/*! The version of LLVM that rustc depends on should be equal to or less than
the version of system LLVM that cargo-bpf is linked to. For example, this
combination is invalid.

- `rustc v1.56` that relies on `LLVM 13`
- `LLVM 12` installed in the system

But this combination is valid.

- `rustc v1.55` depending on `LLVM 12` or `rustc v1.51` relying on `LLVM 11`
- `LLVM 12` installed in the system

If invalid combination is used, cargo-bpf stops compiling BPF programs and
prints error. If it just proceeds, compiling BPF programs results in corrupted
ELF files or compiling process abnormally exits with SIGSEGV, SIGABRT or LLVM
related indigestible errors.

This problem occurs because `cargo-bpf` executes `rustc` to emit bitcode first
and then calls LLVM API directly to parse and optimize the emitted bitcode
second.
*/
cfg_if::cfg_if! {
    if #[cfg(feature = "llvm-sys-130")] {
        use llvm_sys_130 as llvm_sys;
    } else {
        compile_error!("Specify --features llvm13");
    }
}
use anyhow::{anyhow, Result};
use llvm_sys::bit_writer::LLVMWriteBitcodeToFile;
use llvm_sys::core::*;
use llvm_sys::debuginfo::*;
use llvm_sys::ir_reader::LLVMParseIRInContext;
use llvm_sys::prelude::*;
use llvm_sys::support::LLVMParseCommandLineOptions;
use llvm_sys::target::*;
use llvm_sys::target_machine::*;
use llvm_sys::transforms::ipo::LLVMAddAlwaysInlinerPass;
use llvm_sys::transforms::pass_manager_builder::*;
use llvm_sys::{LLVMAttributeFunctionIndex, LLVMInlineAsmDialect::*};
use llvm_sys::{LLVMOpcode, LLVMTypeKind, LLVMValueKind};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;
use std::slice;

pub(crate) unsafe fn init() {
    LLVM_InitializeAllTargets();
    LLVM_InitializeAllTargetInfos();
    LLVM_InitializeAllTargetMCs();
    LLVM_InitializeAllAsmPrinters();
    LLVM_InitializeAllAsmParsers();
}

/// Force loop unroll
///
/// Normally if loop iteration count is big, loop is intact. Loops with small
/// iteration count are unrolled. But if this function is called, every loop is
/// unrolled.
pub(crate) unsafe fn force_loop_unroll() {
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
        0,
    );

    let block = LLVMGetLastBasicBlock(func);
    let last = LLVMGetLastInstruction(block);
    LLVMPositionBuilderBefore(builder, last);
    let c_str = CString::new("").unwrap();
    LLVMBuildCall(builder, exit, ptr::null_mut(), 0, c_str.as_ptr());
}

/// Find debugger intrinsics handling methods of RedBPF maps. The the type
/// string of methods such as `get`, `get_mut`, `get_val`, `set`, `delete` are
/// returned.
unsafe fn find_redbpf_map_method_type_str(dbg_var_inst: LLVMValueRef) -> Option<String> {
    let called_val = LLVMGetCalledValue(dbg_var_inst);
    if called_val.is_null() {
        return None;
    }
    let mut len: usize = 0;
    let cname = LLVMGetValueName2(called_val, &mut len as *mut _);
    let cv_name = CStr::from_ptr(cname).to_str().unwrap();
    if cv_name != "llvm.dbg.value" {
        return None;
    }
    // llvm.dbg.value requires three arguments
    if LLVMGetNumArgOperands(dbg_var_inst) != 3 {
        return None;
    }

    // The first argument of llvm.dbg.value is new value
    let new_value = LLVMGetArgOperand(dbg_var_inst, 0);
    if LLVMGetNumOperands(new_value) == 0 {
        return None;
    }
    let undef = LLVMGetOperand(new_value, 0);
    match LLVMGetValueKind(undef) {
        LLVMValueKind::LLVMUndefValueValueKind => {}
        _ => {
            return None;
        }
    }
    let undef_type = LLVMTypeOf(undef);
    match LLVMGetTypeKind(undef_type) {
        LLVMTypeKind::LLVMPointerTypeKind => {}
        _ => {
            return None;
        }
    }
    let cname = LLVMPrintTypeToString(undef_type);
    let undef_type_str = CStr::from_ptr(cname).to_str().unwrap();
    if !(undef_type_str.starts_with("%\"redbpf_probes::maps::") && undef_type_str.ends_with("\"*"))
    {
        return None;
    }
    // e.g., `redbpf_probes::maps::HashMap<u64, example_probes::vfsreadlat::VFSEvent>`
    let map_type_str = &undef_type_str[2..undef_type_str.len() - 2];

    // The second argument of llvm.dbg.value is DI local variable.
    let di_local_var = LLVMGetArgOperand(dbg_var_inst, 1);
    let dilocvar_meta = LLVMValueAsMetadata(di_local_var);
    match LLVMGetMetadataKind(dilocvar_meta) {
        LLVMMetadataKind::LLVMDILocalVariableMetadataKind => {}
        _ => {
            return None;
        }
    }
    let method_scope = LLVMDIVariableGetScope(dilocvar_meta);
    match LLVMGetMetadataKind(method_scope) {
        LLVMMetadataKind::LLVMDISubprogramMetadataKind => {}
        _ => {
            return None;
        }
    }
    // e.g., `get_mut<u64, example_probes::vfsreadlat::VFSEvent>`
    let mut len: usize = 0;
    let cname = LLVMDITypeGetName(method_scope, &mut len as *mut _);

    // e.g., `redbpf_probes::maps::HashMap<u64, example_probes::vfsreadlat::VFSEvent>::get_mut<u64, example_probes::vfsreadlat::VFSEvent>`
    Some(format!(
        "{}::{}",
        map_type_str,
        String::from_utf8_lossy(slice::from_raw_parts(cname as *const _, len))
    ))
}

unsafe fn find_map_calling_bpf_map_lookup_elem(call_inst: LLVMValueRef) -> Option<String> {
    let called_val = LLVMGetCalledValue(call_inst);
    if called_val.is_null() {
        return None;
    }
    match LLVMGetValueKind(called_val) {
        LLVMValueKind::LLVMConstantExprValueKind => {}
        _ => {
            return None;
        }
    }
    match LLVMGetTypeKind(LLVMTypeOf(called_val)) {
        LLVMTypeKind::LLVMPointerTypeKind => {}
        _ => {
            return None;
        }
    }
    match LLVMGetConstOpcode(called_val) {
        LLVMOpcode::LLVMIntToPtr => {}
        _ => {
            return None;
        }
    }
    let const_int = LLVMGetOperand(called_val, 0);
    match LLVMGetValueKind(const_int) {
        LLVMValueKind::LLVMConstantIntValueKind => {}
        _ => {
            return None;
        }
    }
    // `bpf_map_lookup_elem` BPF helper is 1
    if LLVMConstIntGetZExtValue(const_int) != 1 {
        return None;
    }
    // `bpf_map_lookup_elem` requires two arguments
    if LLVMGetNumArgOperands(call_inst) != 2 {
        return None;
    }
    // The first argument of `bpf_map_lookup_elem` is a pointer to map def
    let map_def = LLVMGetArgOperand(call_inst, 0);
    match LLVMGetValueKind(map_def) {
        LLVMValueKind::LLVMConstantExprValueKind => {}
        _ => {
            return None;
        }
    }
    match LLVMGetConstOpcode(map_def) {
        LLVMOpcode::LLVMGetElementPtr => {}
        _ => {
            return None;
        }
    }
    // Get a map that is the container of the map definition
    let map = LLVMGetOperand(map_def, 0);
    match LLVMGetValueKind(map) {
        LLVMValueKind::LLVMGlobalVariableValueKind => {}
        _ => {
            return None;
        }
    }
    // Get name of the map
    let mut len: usize = 0;
    let cname = LLVMGetValueName2(map, &mut len as *mut _);
    let map_variable_name =
        String::from_utf8_lossy(slice::from_raw_parts(cname as *const _, len)).to_string();
    Some(map_variable_name)
}

/// Check if the alignment of value of map exceeds 8 bytes and `get` or
/// `get_mut` method is called to create a reference of the possibly misaligned
/// value data.
unsafe fn check_map_value_alignment(_context: LLVMContextRef, module: LLVMModuleRef) -> Result<()> {
    let mut get_called_maps = Vec::<(String, String, String)>::new(); // (map_variable_name, calling_function_name, get_method_name)
    let mut func = LLVMGetFirstFunction(module);
    while !func.is_null() {
        let mut block = LLVMGetFirstBasicBlock(func);
        let mut map_method_type_str = None;
        while !block.is_null() {
            let mut inst = LLVMGetFirstInstruction(block);
            while !inst.is_null() {
                // inspect debugger intrinsics
                if !LLVMIsADbgVariableIntrinsic(inst).is_null() {
                    // find debugger intrinsics of `get` or `get_mut` methods
                    // of RedBPF maps such as
                    // `redbpf_probes::maps::HashMap<u64, example_probes::vfsreadlat::VFSEvent>::get_mut<u64, example_probes::vfsreadlat::VFSEvent>`
                    if let Some(name) = find_redbpf_map_method_type_str(inst) {
                        map_method_type_str = Some(name);
                    }
                    // inspect normal function call
                } else if !LLVMIsACallInst(inst).is_null() && LLVMIsAIntrinsicInst(inst).is_null() {
                    // find the calling instruction to the `bpf_map_lookup_elem` BPF helper function.
                    if let Some(map_var_name) = find_map_calling_bpf_map_lookup_elem(inst) {
                        if let Some(method_name) = map_method_type_str.take() {
                            // Don't care the `get_val` method because it does
                            // not create any reference of misaligned value
                            // data.
                            if method_name.contains("::get<") || method_name.contains("::get_mut<")
                            {
                                let mut len: usize = 0;
                                let cname = LLVMGetValueName2(func, &mut len as *mut _);
                                let calling_func_name = String::from_utf8_lossy(
                                    slice::from_raw_parts(cname as *const _, len),
                                )
                                .to_string();

                                get_called_maps.push((
                                    map_var_name,
                                    calling_func_name,
                                    method_name,
                                ));
                            }
                        }
                    }
                }
                inst = LLVMGetNextInstruction(inst);
            }
            block = LLVMGetNextBasicBlock(block);
        }
        func = LLVMGetNextFunction(func);
    }

    const PROBES_ALIGNMENT_MAX: usize = 8;
    const ALIGN_PREFIX: &str = "MAP_VALUE_ALIGN_";
    let mut global = LLVMGetFirstGlobal(module);
    'next_global: while !global.is_null() {
        let mut size: libc::size_t = 0;
        let c_name = LLVMGetValueName2(global, &mut size as *mut _);
        if c_name.is_null() {
            global = LLVMGetNextGlobal(global);
            continue 'next_global;
        }
        let name = String::from_utf8_lossy(slice::from_raw_parts(c_name as *const _, size));
        if !name.starts_with(ALIGN_PREFIX) {
            global = LLVMGetNextGlobal(global);
            continue 'next_global;
        }
        let align = LLVMGetAlignment(global) as usize;
        if align <= PROBES_ALIGNMENT_MAX {
            global = LLVMGetNextGlobal(global);
            continue 'next_global;
        }
        let map_name = &name[ALIGN_PREFIX.len()..];
        let get_callers = get_called_maps
            .iter()
            .filter_map(|(map_var_name, calling_func_name, get_method_name)| {
                if map_var_name == map_name {
                    Some((calling_func_name, get_method_name))
                } else {
                    None
                }
            })
            .collect::<Vec<(&String, &String)>>();
        if get_callers.len() == 0 {
            global = LLVMGetNextGlobal(global);
            continue 'next_global;
        }
        let mut emsg = "In BPF programs, it is prohibited to call `get` or `get_mut` methods of maps of which value has the alignment greater than 8 bytes.\n".to_string();
        emsg.push_str("Because in kernel context, it is not guaranteed for the values to be stored at the correct alignment if the alignment is greater than 8 bytes.\n");
        emsg.push_str("Since it is undefined behavior in Rust to create references or to dereference pointers of unaligned data, BPF programs should not call `get` or `get_mut` methods that create references of the possibly misaligned data.\n");
        emsg.push_str(&format!(
            "\tmap variable name: {} alignment of value: {} bytes\n",
            map_name, align
        ));
        for (calling_func_name, get_method_name) in get_callers.iter() {
            emsg.push_str(&format!(
                "\tcalling function name: {} called get method type: {}\n",
                calling_func_name, get_method_name
            ));
        }
        return Err(anyhow!(emsg));
    }

    Ok(())
}

pub unsafe fn compile(input: &Path, output: &Path, bc_output: Option<&Path>) -> Result<()> {
    let context = LLVMGetGlobalContext();
    let module = load_module(context, input)?;
    check_map_value_alignment(context, module)?;
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

fn find_available_command<'a>(candidates: &[&'a str]) -> Option<&'a str> {
    candidates.iter().find_map(|cmd| {
        if Command::new(*cmd)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            Some(*cmd)
        } else {
            None
        }
    })
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
    let cmd = find_available_command(&[
        "llvm-strip",
        "llvm-strip-13",
        "llvm-strip-12",
        "llvm-strip-11",
    ])
    .ok_or_else(|| anyhow!("llvm-strip command not found"))?;

    Command::new(cmd)
        .arg("--strip-debug")
        .arg(target.as_ref())
        .status()
        .map(|_| ())
        .or_else(|e| Err(anyhow!("llvm-strip --strip-debug failed: {}", e)))?;

    let mut cmd = Command::new(cmd);
    if delete_btf {
        cmd.args("--remove-section .BTF.ext".split(' '));
    }
    // Even if there does not exist any function in .text section, .text
    // section is created with zero size as a result of compilation. So it is
    // needed to remove it explictly. The .text section can cause a problem if
    // the resulting ELF relocatable file is passed to tc command.
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
