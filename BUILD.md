# Build Instructions

Follow these instructions to build AWeb 3.

## ToolKit

Building AWeb 3 is most easily achieved if your development environment is setup following the ToolKit standard. See ToolKit.md or https://github.com/amigazen/ToolKit

## Prerequisites

AWeb 3 requires:

- SAS/C compiler 6.58
- NDK3.2
- AmiSSL v5 SDK
- include: assign pointed at NDK headers
- netinclude: assign pointed at Roadshow headers (included in NDK3.2)
- sslinclude: assign pointed at AmiSSL headers

## Compiler 

The current AWeb 3.6 requires VBCC

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
