/*! The version of LLVM that rust depends on should be equal to or less than
the version of system LLVM. For example, this combination is invalid.

- `rustc v1.56` that relies on `LLVM 13`
- `LLVM 12` installed in the system

But this combination is valid.

- `rustc v1.55` depending on `LLVM 12` or `rustc v1.51` relying on `LLVM 11`
- `LLVM 12` installed in the system

If invalid combination is used, compiling BPF programs results in corrupted ELF
files or compiling process abnormally exits with SIGSEGV, SIGABRT or LLVM
related indigestible errors.

This restriction exists because `cargo-bpf` executes `rustc` to emit bitcode
first and then calls LLVM API directly to parse and optimize the emitted
bitcode second. So LLVM version mismatch incurs problems.
*/
cfg_if::cfg_if! {
    if #[cfg(feature = "llvm-sys-130")] {
        use llvm_sys_130 as llvm_sys;
    } else if #[cfg(feature = "llvm-sys-120")] {
        use llvm_sys_120 as llvm_sys;
        #[rustversion::since(1.56)]
        compile_error!("Can not use LLVM12 with Rust >= 1.56");
    } else if #[cfg(feature = "llvm-sys-110")] {
        use llvm_sys_110 as llvm_sys;
        #[rustversion::since(1.52)]
        compile_error!("Can not use LLVM11 with Rust >= 1.52");
    } else if #[cfg(feature = "llvm-sys-100")] {
        use llvm_sys_100 as llvm_sys;
        #[cfg(not(docsrs))]
        #[rustversion::since(1.47)]
        compile_error!("Can not use LLVM10 with Rust >= 1.47");
    } else {
        compile_error!("At least one of `llvm13`, `llvm12`, `llvm11` and `llvm10` features should be specified");
    }
}

use anyhow::{anyhow, Result};
use llvm_sys::bit_writer::LLVMWriteBitcodeToFile;
use llvm_sys::core::*;
use llvm_sys::ir_reader::LLVMParseIRInContext;
use llvm_sys::prelude::*;
use llvm_sys::support::LLVMParseCommandLineOptions;
use llvm_sys::target::*;
use llvm_sys::target_machine::*;
use llvm_sys::transforms::ipo::LLVMAddAlwaysInlinerPass;
use llvm_sys::transforms::pass_manager_builder::*;
use llvm_sys::{LLVMAttributeFunctionIndex, LLVMInlineAsmDialect::*};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;

pub unsafe fn init() {
    LLVM_InitializeAllTargets();
    LLVM_InitializeAllTargetInfos();
    LLVM_InitializeAllTargetMCs();
    LLVM_InitializeAllAsmPrinters();
    LLVM_InitializeAllAsmParsers();

    let mut args = Vec::new();
    args.push(CString::new("cargo-bpf").unwrap());
    args.push(CString::new(format!("-unroll-threshold={}", std::u32::MAX)).unwrap());
    let args_ptrs = args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    let overview = CString::new("what is this").unwrap();
    LLVMParseCommandLineOptions(args.len() as i32, args_ptrs.as_ptr(), overview.as_ptr());
}

unsafe fn load_module(context: LLVMContextRef, input: &Path) -> Result<LLVMModuleRef> {
    let mut message: *mut c_char = ptr::null_mut();
    let filename = CString::new(input.to_str().unwrap()).unwrap();
    let mut buf: LLVMMemoryBufferRef = ptr::null_mut();
    LLVMCreateMemoryBufferWithContentsOfFile(
        filename.as_ptr(),
        &mut buf as *mut _,
        &mut message as *mut *mut c_char,
    );
    if !message.is_null() {
        return Err(anyhow!(
            "LLVMCreateMemoryBufferWithContentsOfFile failed: {}",
            error_str(message)
        ));
    }

    let mut module: LLVMModuleRef = ptr::null_mut();
    let mut message: *mut c_char = ptr::null_mut();
    LLVMParseIRInContext(
        context,
        buf,
        &mut module as *mut _,
        &mut message as *mut *mut c_char,
    );
    if !message.is_null() {
        return Err(anyhow!(
            "LLVMParseIRInContext failed: {}",
            error_str(message)
        ));
    }

    Ok(module)
}

unsafe fn inject_exit_call(context: LLVMContextRef, func: LLVMValueRef, builder: LLVMBuilderRef) {
    let exit_str = CString::new("exit").unwrap();
    let exit_sig = LLVMFunctionType(LLVMVoidTypeInContext(context), ptr::null_mut(), 0, 0);
    let exit = LLVMGetInlineAsm(
        exit_sig,
        exit_str.as_ptr() as *mut _,
        "exit".len(),
        ptr::null_mut(),
        0,
        0,
        0,
        LLVMInlineAsmDialectATT,
        #[cfg(feature = "llvm-sys-130")]
        0,
    );

    let block = LLVMGetLastBasicBlock(func);
    let last = LLVMGetLastInstruction(block);
    LLVMPositionBuilderBefore(builder, last);
    let c_str = CString::new("").unwrap();
    LLVMBuildCall(builder, exit, ptr::null_mut(), 0, c_str.as_ptr());
}

pub unsafe fn compile(input: &Path, output: &Path, bc_output: Option<&Path>) -> Result<()> {
    let context = LLVMGetGlobalContext();
    let module = load_module(context, input)?;
    process_ir(context, module)?;
    let ret = compile_module(module, output, bc_output);
    LLVMDisposeModule(module);

    ret
}

/// Get section names of functions
///
/// Only functions that do not belong to the default .text section have
/// particular section names. So thd default `.text` won't be included in the
/// result vector.
pub(crate) unsafe fn get_function_section_names(bc: &Path) -> Result<Vec<String>> {
    let mut section_names = vec![];
    let context = LLVMGetGlobalContext();
    let module = load_module(context, bc)?;
    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        let secptr = LLVMGetSection(func);
        if !secptr.is_null() {
            let secname = CStr::from_ptr(secptr).to_string_lossy().into_owned();
            section_names.push(secname);
        }
        func = LLVMGetNextFunction(func);
    }
    LLVMDisposeModule(module);

    Ok(section_names)
}

/// Strip unnecessary sections from resulting ELF relocatable file
///
/// This removes sections of which name start with `.debug` and their
/// associated relocation sections. But .BTF related sections are not stripped.
///
/// cf) `llvm_sys::debuginfo::LLVMStripModuleDebugInfo` removes BTF sections so
/// do not call it.
///
/// .text section is also removed.
///
pub(crate) fn strip_unnecessary(target: &impl AsRef<Path>, delete_btf: bool) -> Result<()> {
    let cmd = [
        "llvm-strip",
        "llvm-strip-13",
        "llvm-strip-12",
        "llvm-strip-11",
    ]
    .iter()
    .find(|cmd| {
        Command::new(cmd)
            .arg("--version")
            .stdout(Stdio::null())
            .status()
            .is_ok()
    })
    .ok_or_else(|| anyhow!("llvm-strip command not found"))?;

    Command::new(cmd)
        .arg("--strip-debug")
        .arg(target.as_ref())
        .status()
        .map(|_| ())
        .or_else(|e| Err(anyhow!("llvm-strip --strip-debug failed: {}", e)))?;

    // Even if there does not exist any function in .text section, .text
    // section is created with zero size as a result of compilation. So it is
    // needed to remove it explictly.
    let mut cmd = Command::new(cmd);
    if delete_btf {
        // The BTF section generated by rustc contains characters that are not
        // permitted by BPF verifier of the Linux kernel. So those characters
        // should be fixed before loading the BTF sections. But some utils that
        // are not aware of rustc generated BTF such as `tc` do not handle
        // this. In this case just remove BTF sections to avoid BPF verifier
        // problem.
        cmd.args("--remove-section .BTF.ext --remove-section .BTF".split(' '));
    }
    cmd.args("--remove-section .text".split(' '))
        .arg("--no-strip-all")
        .arg(target.as_ref())
        .status()
        .map(|_| ())
        .or_else(|e| Err(anyhow!("llvm-strip --remove-section .text failed: {}", e)))
}

pub unsafe fn process_ir(context: LLVMContextRef, module: LLVMModuleRef) -> Result<()> {
    let builder = LLVMCreateBuilderInContext(context);

    let no_inline = CString::new("noinline").unwrap();
    let no_inline_kind = LLVMGetEnumAttributeKindForName(no_inline.as_ptr(), "noinline".len());
    let always_inline = CString::new("alwaysinline").unwrap();
    let always_inline_kind =
        LLVMGetEnumAttributeKindForName(always_inline.as_ptr(), "alwaysinline".len());
    let always_inline_attr = LLVMCreateEnumAttribute(context, always_inline_kind, 0);

    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        let mut size: libc::size_t = 0;
        let name = CStr::from_ptr(LLVMGetValueName2(func, &mut size as *mut _))
            .to_str()
            .unwrap();
        if !name.starts_with("llvm.") {
            // make sure everything gets inlined as BPF can't do calls to
            // things other than helpers
            LLVMRemoveEnumAttributeAtIndex(func, LLVMAttributeFunctionIndex, no_inline_kind);
            LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex, always_inline_attr);

            if name == "rust_begin_unwind" {
                // inject a BPF exit call in the panic handler to make the program terminate
                inject_exit_call(context, func, builder);
            }
        }
        func = LLVMGetNextFunction(func);
    }

    Ok(())
}

unsafe fn create_target_machine() -> Result<LLVMTargetMachineRef> {
    let mut error = ptr::null_mut();
    let triple = CString::new("bpf").unwrap();
    let cpu = CString::new("generic").unwrap(); // see llc -march=bpf -mcpu=help
    let features = CString::new("").unwrap(); // see llc -march=bpf -mcpu=help

    let mut target = ptr::null_mut();
    let ret = LLVMGetTargetFromTriple(triple.as_ptr(), &mut target, &mut error);
    if ret == 1 {
        return Err(anyhow!(
            "LLVMGetTargetFromTriple failed: {}",
            error_str(error)
        ));
    }

    let tm = LLVMCreateTargetMachine(
        target,
        triple.as_ptr(),
        cpu.as_ptr(),
        features.as_ptr(),
        LLVMCodeGenOptLevel::LLVMCodeGenLevelAggressive,
        LLVMRelocMode::LLVMRelocDefault,
        LLVMCodeModel::LLVMCodeModelDefault,
    );
    if tm.is_null() {
        return Err(anyhow!("Couldn't create target machine"));
    }

    Ok(tm)
}

unsafe fn compile_module(
    module: LLVMModuleRef,
    output: &Path,
    bc_output: Option<&Path>,
) -> Result<()> {
    let tm = create_target_machine()?;
    let data_layout = LLVMCreateTargetDataLayout(tm);
    LLVMSetModuleDataLayout(module, data_layout);

    let fpm = LLVMCreateFunctionPassManagerForModule(module);
    let mpm = LLVMCreatePassManager();

    LLVMAddAnalysisPasses(tm, fpm);
    LLVMAddAnalysisPasses(tm, mpm);

    // we annotate all functions as always-inline so that we can force-inline
    // them with the always inliner pass
    LLVMAddAlwaysInlinerPass(mpm);

    // NOTE: we should call LLVMAddTargetLibraryInfo() here but there's no way
    // to retrieve the library info for the BPF target using the C API

    // add all the other passes
    let pmb = LLVMPassManagerBuilderCreate();
    LLVMPassManagerBuilderSetOptLevel(pmb, 3);
    LLVMPassManagerBuilderSetSizeLevel(pmb, 0);

    // We already added the AlwaysInliner pass. Ideally we want to set
    // PMB->Inliner = AlwaysInliner but that's not possible with the C API. So
    // here we add _another_ inliner pass that won't actually inline anything,
    // but will cause the PMB to add extra optimization passes that are only
    // turned on if inlining is configured.
    LLVMPassManagerBuilderUseInlinerWithThreshold(pmb, 275);

    // populate the pass managers
    LLVMPassManagerBuilderPopulateFunctionPassManager(pmb, fpm);
    LLVMPassManagerBuilderPopulateModulePassManager(pmb, mpm);

    // run function passes
    LLVMInitializeFunctionPassManager(fpm);
    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        if LLVMIsDeclaration(func) == 0 {
            LLVMRunFunctionPassManager(fpm, func);
        }
        func = LLVMGetNextFunction(func);
    }
    LLVMFinalizeFunctionPassManager(fpm);

    // run module passes
    LLVMRunPassManager(mpm, module);

    if let Some(output) = bc_output {
        let file_ptr = CString::new(output.to_str().unwrap()).unwrap().into_raw();
        let ret = LLVMWriteBitcodeToFile(module, file_ptr);
        let _ = CString::from_raw(file_ptr);
        if ret == 1 {
            return Err(anyhow!("LLVMWriteBitcodeToFile failed"));
        }
    }

    // emit the code
    let mut error = ptr::null_mut();
    let file_ptr = CString::new(output.to_str().unwrap()).unwrap().into_raw();
    let ret = LLVMTargetMachineEmitToFile(
        tm,
        module,
        file_ptr,
        LLVMCodeGenFileType::LLVMObjectFile,
        &mut error,
    );
    let _ = CString::from_raw(file_ptr);
    if ret == 1 {
        return Err(anyhow!(
            "LLVMTargetMachineEmitToFile failed: {}",
            error_str(error)
        ));
    }

    LLVMPassManagerBuilderDispose(pmb);
    LLVMDisposePassManager(fpm);
    LLVMDisposePassManager(mpm);
    LLVMDisposeTargetMachine(tm);

    Ok(())
}

unsafe fn error_str(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        "unknown error".to_string()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}
