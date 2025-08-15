## ChangeLog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6.0] - 2025-08-15

### Changed
- **UI Framework:** Migrated from ClassAct API calls and headers to ReAction equivalents
- **Graphics System:** Refactored from Cybergraphics to P96
- **SSL Implementation:** Updated to use AmiSSL v5 code
- **Build System:** Updated smakefiles to build against NDK3.2 and ToolKit SDK
- **Executable:** Renamed core executable from 'AWeb-II' to 'AWeb'
- **Assign Path:** Changed all occurences of 'AWebPath:" and "AWeb3:" to simply "AWeb:"
- **URLs:** Updated default search and navigation URLs to websites relevant in 2025
- **English default strings:** Corrected many english grammar issues in default strings
- **Library Base typecasts:** Fixed most Library typecast warnings
- **reaction.lib:** Incorporated reaction.lib into build because this is needed to autoopen gradientslider.gadget since NDK3.2 is missing the protos
- **AWebCfg builds:** The AWebCfg build in the original 3.4 APL release was broken in several ways. Now fixed
- **Documentation:** Partial update of documentation to reflect reality of 2025
- **Refactoring:** Some refactoring of ezlists and image plugins

### Removed
- **Network Support:** Disabled INet225 support
- **SSL Support:** Disabled MiamiSSL support