## Overview

This project contains a plugin for Volatility 2.4 that parses the Windows Application Compatibility Database (aka, ShimCache) from memory. Most forensic tools that parse the shim cache rely on the cache stored in the Windows registry. The cache in the registry is only updated when a system is shutdown so this approach has the disadvantage of only parsing cache entries 
since the last shutdown. On systems that are not rebooted regularly (e.g., production servers) an analyst must either use out-of-date shim cache data or request a system reboot.

This plugin parses the shim cache directly from the module or process containing the cache, thereby providing analysts access to the most up-to-date cache. The plugin supports Windows XP SP2 through Windows 2012 R2 on both 32 and 64 bit architectures.

## Installation

> All development and testing was performed using Python 2.7.6 (x64).

Install the following packages:
* [Python 2.7.6 (x64)](https://www.python.org/ftp/python/2.7.5/python-2.7.5.amd64.msi)
* [Volatility 2.4](http://downloads.volatilityfoundation.org/releases/2.4/volatility-2.4.win32.exe)
* Shim Cache Memory Plugin
  * Copy the plugin file "shimcachemem.py" to the Volatility plugins folder located in volatility/plugins

If working with Windows 8+, the following additional Python modules are required:
  * [pycrypto](http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win-amd64-py2.7.exe)
  * [distorm3](https://github.com/gdabah/distorm/releases/download/v3.3.0/py-distorm3-3.3.0.win-amd64.exe)

See [this volatility page](https://github.com/volatilityfoundation/volatility/wiki/Windows-8-2012) for more information on why pycrypto and distorm3 are needed for Windows 8+ analysis.

## Using the plugin

The process is as follows:

1. Run the volatility "imageinfo" plugin to determine the Volatility profile and KDBG offset.
2. For Windows 8+, run the volatility "kdbgscan" plugin to determine the KdCopyDataBlock offset.
3. As a sanity check, use the results of steps 1/2 to list all modules. If this doesn't work, start over.
4. Run the "shimcachemem" plugin using the results of steps 1 and 2.

The plugin supports the following options:

| Option | Long Option           | Description |
|--------|-----------------------|-------------|
| -h     | --help                | List all plugin options |
|        | --output=csv          | Specify the output format. CSV is the only supported format. If the option is ommitted, the plugin outputs the results to the terminal. |
|        | --output-file=out.csv | The name of the CSV output file. |
| -c     | --clean_file_paths    | Strips UNC path prefixes ("\\??\") and replaces SYSVOL with "C:". Intended an a convenience for analysts. |
| -P     | --print_offset        | Prints the virtual and physical offset of each shim cache entry. Intended to facilitate additional forensic analysis of the memory image. |

## Sample Usage

### Pre-windows 8 (XP SP2 - Windows 7/2008 R2)

#### Identify the profile and KDBG offset.

```
> python vol.py -f D:\Projects\Volatility\WinXPSP2x86.bin imageinfo

Volatility Foundation Volatility Framework 2.4
Determining profile based on KDBG search...

          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (D:\Projects\Volatility\WinXPSP2x86.bin)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-11-27 01:57:28 UTC+0000
     Image local date and time : 2012-11-26 19:57:28 -0600
```

#### As a sanity check, run the volatility "modules" plugin.

```
> python vol.py -f D:\Projects\Volatility\WinXPSP2x86.bin --profile=WinXPSP2x86 --kdbg=0x8054cde0 modules

Volatility Foundation Volatility Framework 2.4
Offset(V)  Name                 Base             Size File
---------- -------------------- ---------- ---------- ----
0x823fc3a0 ntoskrnl.exe         0x804d7000   0x216680 \WINDOWS\system32\ntoskrnl.exe
...

(output redacted)
```

#### Run the shimcachemem plugin.

```
> python vol.py -f D:\Projects\Volatility\WinXPSP2x86.bin --profile=WinXPSP2x86 --kdbg=0x8054cde0 shimcachemem

Volatility Foundation Volatility Framework 2.4
INFO    : volatility.plugins.shimcachemem: Shimcache Memory Dump
INFO    : volatility.plugins.shimcachemem: Searching for ShimSharedMemory section handle...
INFO    : volatility.plugins.shimcachemem:      Found ShimSharedMemory handle in winlogon.exe (628)
INFO    : volatility.plugins.shimcachemem:      Shim section object found at (0xe15d0918) 0x068c9918
INFO    : volatility.plugins.shimcachemem:      Shim segment found at (0xe14ef800) 0x038bd800
INFO    : volatility.plugins.shimcachemem: Process 'winlogon.exe' (628) contains shim cache at virtual address 0x008d0000
INFO    : volatility.plugins.shimcachemem: Shim cache magic header found at 0x008d0000 (0x06a8e000)

Order Last Modified         Last Update           Exec  File Size  File Path
----- --------------------- --------------------- ----- ---------- ---------
    1 2012-11-27 01:42:21   2012-11-27 01:57:28              95104 \??\C:\mdd.exe
    2 2008-04-14 11:42:06   2012-11-27 01:56:17            8461312 \??\C:\WINDOWS\system32\SHELL32.dll
    3 2008-04-14 11:42:40   2012-11-27 01:56:17              28672 \??\C:\WINDOWS\system32\verclsid.exe

(output redacted)
```

### Windows 8+

#### Identify the profile

```
> python vol.py -f D:\Projects\Volatility\Win2012R2x64.raw imageinfo

Volatility Foundation Volatility Framework 2.4
Determining profile based on KDBG search...

          Suggested Profile(s) : Win2012R2x64, Win8SP0x64, Win8SP1x64, Win2012x64 (Instantiated with Win8SP1x64)
                     AS Layer1 : AMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (D:\Projects\Volatility\Win2012R2x64.raw)
                      PAE type : No PAE
                           DTB : 0x1a7000L
                          KDBG : 0xf801a191ca30L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff801a1977000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2015-09-19 09:14:05 UTC+0000
     Image local date and time : 2015-09-19 02:14:05 -0700
```

#### Identify the KdCopyDataBlock offset

```
> python vol.py -f D:\Projects\Volatility\Win2012R2x64.raw --profile=Win2012R2x64 kdbgscan

Volatility Foundation Volatility Framework 2.4
**************************************************
Instantiating KDBG using: Unnamed AS Win2012x64 (6.2.9201 64bit)
Offset (V)                    : 0xf801a191ca30
Offset (P)                    : 0x231ca30
KdCopyDataBlock (V)           : 0xf801a185b9b0
Block encoded                 : Yes
Wait never                    : 0xc790fcab400a5f1f
Wait always                   : 0xa5f1a969fdc88
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2012x64
Version64                     : 0xf801a191cd90 (Major: 15, Minor: 9600)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : 9600.16384.amd64fre.winblue_rtm.
PsActiveProcessHead           : 0xfffff801a1933700 (34 processes)
PsLoadedModuleList            : 0xfffff801a194d9b0 (150 modules)
KernelBase                    : 0xfffff801a1686000 (Matches MZ: True)
Major (OptionalHeader)        : 6
Minor (OptionalHeader)        : 3
KPCR                          : 0xfffff801a1977000 (CPU 0)
...

(output redacted)
```

Note that the PsActiveProcessHead and PsLoadedModuleList values above list 34 processes and 150 modules, indicating that the correct KdCopyDataBlock offset has been found. The kdbgscan plugin may produce multiple results, some of which will list 0 processes and modules, indicating that the offset is probably not correct.

#### As a sanity check, run the volatility "modules" plugin.

```
> python vol.py -f D:\Projects\Volatility\Win2012R2x64.raw --profile=Win2012R2x64 --kdbg=0xf801a185b9b0 modules

Volatility Foundation Volatility Framework 2.4
Offset(V)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0xffffe000000555d0 ntoskrnl.exe         0xfffff801a1686000           0x783000 \SystemRoot\system32\ntoskrnl.exe
0xffffe00000f53f30 ahcache.sys          0xfffff8000164c000            0x17000 \SystemRoot\system32\DRIVERS\ahcache.sys
...

(output redacted)
```

#### Run the shimcachemem plugin

```
> python vol.py -f D:\Projects\Volatility\Win2012R2x64.raw --profile=Win2012R2x64 --kdbg=0xf801a185b9b0 shimcachemem

Volatility Foundation Volatility Framework 2.4
INFO    : volatility.plugins.shimcachemem: Shimcache Memory Dump
INFO    : volatility.plugins.shimcachemem: Searching for '.data' section in the following kernel module(s): ahcache.sys
INFO    : volatility.plugins.shimcachemem: Found kernel module 'ahcache.sys' at offset 0xfffff8000164c000
INFO    : volatility.plugins.shimcachemem: Searching for .data section...
INFO    : volatility.plugins.shimcachemem: Found .data section at 0x00003000 with size 0x10c
INFO    : volatility.plugins.shimcachemem: Searching for 'PAGE' section in the following kernel module(s): ahcache.sys
INFO    : volatility.plugins.shimcachemem: Found kernel module 'ahcache.sys' at offset 0xfffff8000164c000
INFO    : volatility.plugins.shimcachemem: Searching for PAGE section...
INFO    : volatility.plugins.shimcachemem: Found PAGE section at 0x00005000 with size 0xe8dd
INFO    : volatility.plugins.shimcachemem: Scanning range 0xfffff8000164f000 - 0xfffff8000164f10c
INFO    : volatility.plugins.shimcachemem: SHIM_CACHE_ENTRY candidate found at 0xffffc0000046e4b8 (v) 0x37c074b8 (p)
INFO    : volatility.plugins.shimcachemem: Shimcache found at 0xffffc0000046e4b8
INFO    : volatility.plugins.shimcachemem:      _RTL_AVL_TABLE:  0xffffc0000046e450 0x37c07450
INFO    : volatility.plugins.shimcachemem:      SHIM_CACHE:      0xffffc0000046e4b8 0x37c074b8
INFO    : volatility.plugins.shimcachemem: Shim handle at 0xfffff8000164f0d0 (0x3b8ff0d0) points to a valid shim cache at 0xffffc0000046e4b8
INFO    : volatility.plugins.shimcachemem: SHIM_CACHE_ENTRY candidate found at 0xffffc00000465ce8 (v) 0x371f2ce8 (p)
INFO    : volatility.plugins.shimcachemem: Shimcache found at 0xffffc00000465ce8
INFO    : volatility.plugins.shimcachemem:      _RTL_AVL_TABLE:  0xffffc00000465c80 0x371f2c80
INFO    : volatility.plugins.shimcachemem:      SHIM_CACHE:      0xffffc00000465ce8 0x371f2ce8
INFO    : volatility.plugins.shimcachemem: Shim handle at 0xfffff8000164f0e0 (0x3b8ff0e0) points to a valid shim cache at 0xffffc00000465ce8
INFO    : volatility.plugins.shimcachemem: Shimcache found at 0xffffc00000465ce8

Order Last Modified         Last Update           Exec  File Size  File Path
----- --------------------- --------------------- ----- ---------- ---------
    1 2015-03-12 16:44:52                         True             SYSVOL\Users\Administrator\Desktop\DumpIt.exe
    2 2013-08-22 11:45:14                         True             SYSVOL\Windows\System32\wbem\WmiPrvSE.exe
    3 2013-08-22 11:44:42                         True             SYSVOL\Windows\System32\wbem\WMIADAP.exe
    4 2013-08-22 11:03:41                         True             SYSVOL\Windows\System32\rundll32.exe
    5 2012-05-01 20:12:56                         True             SYSVOL\Program Files\VMware\VMware Tools\TPAutoConnect.exe
...

(output redacted)
```
