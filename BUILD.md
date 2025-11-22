# Build Instructions

Follow these instructions to build AWeb 3.

## ToolKit

Building AWeb 3 is most easily achieved if your development environment is setup following the ToolKit standard. See ToolKit.md or https://github.com/amigazen/ToolKit

Since ToolKit itself is a work in progress, here's a basic guide to setting up your development tools in the right way:

### ToolKit directories & assigns

ToolKit
- SDK
- Include_h
- Include_i
- emodules
- lib
- C
- Tools
- Libs

- **SDK:** - assigned to the top level directory containing your ToolKit SDK
- **include:** - assigned to SDK:Include_h/, SDK:Include_i/, NDK:Include_h/, NDK:Include_i/
- **netinclude:** - assigned to NDK:SANA+RoadshowTCP-IP/netinclude/
- **sslinclude:** - assigned to wherever the AmiSSL include folder has been installed - SDK:AmiSSL is suggested
- **lib:** - assigned to SDK:lib/, NDK:lib/ in that order 


Apart from this, a minimum ToolKit setup requires at least the following items:
- A supported C compiler - one of SAS/C, GCC or VBCC depending on the project. In this case AWeb currently builds only with SAS/C
- An Amiga Native Developer Kit - currently 3.2 Release 4
- Any Third Party SDKs needed , installed into the 

### C Compiler

Building AWeb requires the SAS/C C compiler, version 6.58. Although a commercial product long since abandoned by it's publisher, copies can be found on archive.org among other places. It remains probably the best all round C compiler and development system for the classic Amiga platform in terms of the quality of its features and generated code.

ToolKit expects SAS/C to be installed in the default configuration:
- sc: assign set to the SAS/C install directory (SDK:sc/ is recommended but not mandatory)
- sc:c will therefore contain the SAS/C sc compiler and other command line tools, and this should also be added to the Path
- sc:lib will contain the sc.lib variants and other startup, math library and debugging code. Crucially, do NOT put any other .lib files in this folder such as NDK .lib files
- sc:include will contain ONLY the SAS/C Standard C Library headers. Again, do NOT put your NDK headers or other header files here, they have their own directories

That's it, nothing else is required to setup SAS/C for use with ToolKit

### Native Developer Kit

The NDK or 'Native Developer Kit' is the standard Amiga SDK for writing 'native' i.e. C API software for the Amiga.

The latest NDK as of the time of writing is version 3.2 release 4 or 'NDK3.2R4.lha' and available from Hyperion. 

Unpack the archive (again, SDK:NDK/ is recommended but not mandatory)

TODO: ... (setup path, copy catcomp)

### Third Party SDKs

AWeb requires the following Third Party SDKs:
- AmiSSL
- P96

## Prerequisites

AWeb 3 requires:

- SAS/C compiler 6.58
- NDK3.2 Release 4
- catcomp from the NDK3.2 somewhere in your Path
- AmiSSL 5.20 SDK or later
- A version of reaction.lib the auto open static library for ReAction - one is available in the ToolKit SDK, or versions from older NDKs will work. This is required because NDK3.2R4 is missing the colorwheel and gradientslider pragmas
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

## How To Build AWeb

```
cd Source/AWebAPL
smake
```

Or to build individual targets one by one

```
smake aweb
smake awebcfg
smake awebjs
smake aweblib/about.aweblib
smake aweblib/ TODO
```

This creates binaries called AWeb, AWebCfg and AWebJS in the AWebAPL folder, as well as all the aweblib plugins

## How To Build AWeb Plugins

To build the individual AWeb Plugins for enhanced GIF, JPEG and PNG support:

```
cd Source/AWebGifAPL
smake
cd /AWebJfifAPL
smake
cd /AWebPngAPL
smake
```

## How to Clean

To delete all build artifacts in the project directory, you can run this command:

```
smake clean
```

However, if you need to make a fresh build, it is recommend simply to run:

```
smake -u all
```

to force a refresh of all targets.

## How To Release

To prepare a release build, run:

```
smake install
```

This will copy the newly created binaries into the correct locations in this project's Internet/AWeb/ directory (deliberately, not your system's Internet directory)

To make a release archive called for example 'target_file.lha' then run:

```
cd Internet
lha -xer target_file.lha AWeb AWeb.info 
```

## How to Run

The AWeb binary will run from whichever directory it's copied into.

AWeb will automatically set it's assign path "AWeb:" to the current directory if it does not already exist (and clean it up on exit, if it created it itself)

Do note however that it will not find its AWebCfg prefs tools, its Docs/ or its aweblib/ and awebplugin/ directories if they are not in the same directory (it will search for them in "PROGDIR:" also), or in the directory to which "AWeb:" is assigned if that is different.