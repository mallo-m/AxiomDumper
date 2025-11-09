## AxiomDumper
Dump LSASS under EDR scrutiny. All actions are performed in kernel mode through vulnerable drivers, therefore bypassing RunAsPPL protections and almost all userland detections and telemetry.

## Evasion efficiency
| Solution              | Status         |
|-----------------------|:--------------:|
| Defender AV           |  ✅ - OK       |
| Defender for Endpoint |  ✅ - OK       |
| Symantec EDR          |  ✅ - OK       |
| Kaspersky EDR         |  ✅ - OK       |
| Sophos                |  ✅ - OK       |
| Trend Micro           |  ✅ - OK       |
| HarfangLab            |  ✅ - OK       |
| WithSecure            |  ✅ - OK       |
| Cortex XDR            |  ✅ - OK       |
| Sentinel ONE          |  ✅ - OK       |
| Crowdstrike Falcon    |  ✅ - OK       |


## Supported systems
This tool does NOT work on Windows 11 and Windows Server 2025. Yet. An update is to come.
You've been warned, you are at risk of BSOD on unsupported systems.

## Building the binaries
Install build dependencies:
```bash
$ apt-get update
$ apt-get install make mingw-w64
```

Build the binaries:
```bash
$ make
Precompiling main.o...                            [OK]
[...]

[COMPILATION SUCCESSFUL]

$ ls AxiomDumper.exe unxor
Permissions Size User  Group  Date Modified Name
----------- ---- ----  -----  ------------- ----
.rwxrwx---  1,2M mallo users  9 nov.  15:10  AxiomDumper.exe
.rwxrwx---   16k mallo users  9 nov.  15:04  unxor
```

## Usage
TODO

## Evasion techniques

### Compile-time XOR encryption
Most strings (used in printf for instance) are XOR-encrypted at compile time, using are time-based encryption key. They change at each new compilation.

### Compile-time hashing
Hashes are also pre-computed at compile-time.

### Kernel-mode arbitrary code execution
Using physical memory read/write primitives in vulnerable drivers, the tool achieves arbitrary code execution in kernel mode. Don't worry about userland hooks are permission checking in this state.

### EDR-based profiles
If an EDR solution is detected on the target, the arguments are verified against pre-built profiles in order to avoid mistakingly running the binary in a mode that might get flagged.

### Encrypted dump looting
The generated dump is encrypted before sending over the network or dropping it to the disk.

### Plug-and-play driver framework
The provided drivers are now getting detected ? No matter, just plug your own into the code. As long as you have a physical read/write, you can achieve the same effect.

## Community

Opening issues or pull requests very much welcome.
Suggestions welcome as well.

## License

This software is under GNU GPL 3.0 license (see LICENSE file).
This is a free, copyleft license that allows users to run, study, share, and modify software, provided that all distributed versions and derivatives remain open source under the same license.

