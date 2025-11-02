# Build Instructions

Follow these instructions to build AWeb 3.

## ToolKit

Building AWeb 3 is most easily achieved if your development environment is setup following the ToolKit standard. See ToolKit.md or https://github.com/amigazen/ToolKit

Since ToolKit itself is a work in progress, here's a basic guide to setting up your development tools in the right way:

### ToolKit directories & assigns



- **include:** - assigned to SDK:Include_h/, SDK:Include_i/, NDK:Include_h/, NDK:Include_i/
- **lib:** - assigned to SDK:lib/, NDK:lib/ in that order 


Apart from this, a minimum ToolKit setup requires at least the following items:
- A supported C compiler - one of SAS/C, GCC or VBCC depending on the project. In this case AWeb currently builds only with SAS/C
- An Amiga Native Developer Kit - currently 3.2 Release 4
- Any Third Party SDKs needed , installed into the ToolKit 

### C Compiler

Building AWeb requires the SAS/C C compiler, version 6.58. Although a commercial product long since abandoned by it's publisher, copies can be found on archive.org among other places. It remains probably the best all round C compiler and development system for the classic Amiga platform in terms of the quality of its features and generated code.

ToolKit expects SAS/C to be installed in the default configuration:
- sc: assign set to the SAS/C install directory (SDK:sc/ is recommended but not mandatory)
- sc:c will therefore contain the SAS/C sc compiler and other command line tools, and this should also be added to the Path
- sc:lib will contain the sc.lib variants and other startup, math library and debugging code. Crucially, do NOT put any other .lib files in this folder such as NDK 
- sc:include will contain ONLY the SAS/C Standard C Library headers. Again, do NOT put your NDK headers or other header files here

That's it, nothing else is required to setup SAS/C for use with ToolKit

### Native Developer Kit

The NDK or 'Native Developer Kit' is the standard Amiga SDK for writing 'native' i.e. C API software for the Amiga.

The latest NDK as of the time of writing is version 3.2 release 4 or 'NDK3.2R4.lha' and available from Hyperion. 

Unpack the archive (again, SDK:NDK/ is recommended but not mandatory)



## Prerequisites

AWeb 3 requires:

- SAS/C compiler 6.58
- NDK3.2
- AmiSSL v5 SDK
- P96 SDK integrated into your ToolKit SDK 
- include: assign pointed at NDK headers
- netinclude: assign pointed at Roadshow headers (included in NDK3.2)
- sslinclude: assign pointed at AmiSSL headers

## Compiler 

The current AWeb 3.6 requires SAS/C

| SAS/C | VBCC | GCC |
|-------|------|-----|
| [x]   | [ ]  | [ ] |

Additional compiler options may be added in the future.

## How To Build

```
Assign AWeb: Source/AWebAPL
cd AWeb:
smake
```

This creates a test binary called Python27 in the Source folder.

## How to Clean

```
smake clean
```

## How To Release

The build system is not yet complete and does not include a distribution build. 
