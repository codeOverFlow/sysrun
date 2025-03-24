use clap::Parser;
use std::{ffi::OsString, path::PathBuf};

#[derive(Debug, Parser)]
#[command(about, long_about = None)]
pub struct Cli {
    /// Executable to launch.
    pub executable: PathBuf,

    /// Arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<OsString>,
}
