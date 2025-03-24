[![crates.io](https://img.shields.io/crates/v/sysrun)](https://crates.io/crates/sysrun)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue)](LICENSE-MIT)

# Sysrun
Run any executable as local SYSTEM account (no service required).

**It is directly taken from the awesome tools from the one and only (the GOAT) [Pavel Yosifovich](https://github.com/zodiacon/sysrun).**

This project is more or less a one-to-one rust translation of his tools but rust powered.

My primary goal is to learn more about windows internals by reading ~~God~~ Pavel's  code, and then to make it available through `cargo install`.

## Usage
```text
Usage: sysrun.exe <EXECUTABLE> [ARGS]...

Arguments:
  <EXECUTABLE>  Executable to launch
  [ARGS]...     Arguments

Options:
  -h, --help  Print help
```
