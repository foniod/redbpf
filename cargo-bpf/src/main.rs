use clap::{self, crate_authors, crate_version, App, AppSettings, Arg, SubCommand};
use std::path::PathBuf;

use cargo_bpf;

fn main() {
    let matches =
        App::new("cargo")
            .bin_name("cargo")
            .settings(&[
                AppSettings::ColoredHelp,
                AppSettings::ArgRequiredElseHelp,
                AppSettings::GlobalVersion,
                AppSettings::SubcommandRequiredElseHelp,
            ])
            .subcommand(
                SubCommand::with_name("bpf")
                    .version(crate_version!())
                    .author(crate_authors!("\n"))
                    .about("A cargo subcommand for developing eBPF programs")
                    .settings(&[
                        AppSettings::SubcommandRequiredElseHelp
                    ])
                    .subcommand(
                        SubCommand::with_name("new")
                            .about("Creates a new eBPF package at <PATH>")
                            .arg(Arg::with_name("name").long("name").value_name("NAME").help(
                                "Set the resulting package name, defaults to the directory name",
                            ))
                            .arg(Arg::with_name("PATH").required(true)),
                    )
                    .subcommand(
                        SubCommand::with_name("add")
                            .about("Adds a new eBPF program at src/<NAME>")
                            .arg(Arg::with_name("NAME").required(true).help(
                                "The name of the eBPF program. The code will be created under src/<NAME>",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("bindgen")
                            .about("Generates rust bindings from C headers")
                            .arg(Arg::with_name("HEADER").required(true).help(
                                "The C header file to generate bindings for",
                            ))
                            .arg(Arg::with_name("BINDGEN_ARGS").required(false).multiple(true).help(
                                "Extra arguments passed to bindgen",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("build")
                            .about("Compiles the eBPF programs in the package")
                            .arg(Arg::with_name("NAME").required(false).multiple(true).help(
                                "The names of the programs to compile. When no names are specified, all the programs are built",
                            ))
                    )
                    .subcommand(
                        SubCommand::with_name("load")
                            .about("Loads the specifeid eBPF program")
                            .arg(Arg::with_name("INTERFACE").value_name("INTERFACE").short("i").long("interface").help(
                                "Binds XDP programs to the given interface"
                            ))
                            .arg(Arg::with_name("PROGRAM").required(true).help(
                                "Loads the specified eBPF program and outputs all the events generated",
                            ))
                    ),
            )
            .get_matches();
    let matches = matches.subcommand_matches("bpf").unwrap();
    if let Some(m) = matches.subcommand_matches("new") {
        let path = m.value_of("PATH").map(PathBuf::from).unwrap();

        if let Err(e) = cargo_bpf::new(&path, m.value_of("NAME")) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("add") {
        if let Err(e) = cargo_bpf::new_program(m.value_of("NAME").unwrap()) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("bindgen") {
        let header = m.value_of("HEADER").map(PathBuf::from).unwrap();
        let extra_args = m
            .values_of("BINDGEN_ARGS")
            .map(|i| i.collect())
            .unwrap_or_else(Vec::new);
        if let Err(e) = cargo_bpf::bindgen(&header, &extra_args[..]) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("build") {
        let programs = m
            .values_of("NAME")
            .map(|i| i.map(|s| String::from(s)).collect())
            .unwrap_or_else(Vec::new);
        if let Err(e) = cargo_bpf::cmd_build(programs) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
    if let Some(m) = matches.subcommand_matches("load") {
        let program = m
            .value_of("PROGRAM")
            .map(PathBuf::from)
            .unwrap();
        let interface = m.value_of("INTERFACE");
        if let Err(e) = cargo_bpf::load(&program, interface) {
            clap::Error::with_description(&e.0, clap::ErrorKind::InvalidValue).exit()
        }
    }
}
