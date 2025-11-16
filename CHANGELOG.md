## ChangeLog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6alpha2] - 2025-11-16

### Changed
- **UI Framework:** Migrated from ClassAct classes and headers to ReAction equivalents
- **Graphics System:** Refactored to use P96 instead of Cybergraphics
- **SSL Implementation:** Completely rewritten to use AmiSSL v5.2
- **Command Line arguments:** Any URL arguments passed on the command line that are missing the URL protocol are assumed to be local files to open instead using the file:// protocol
- **Build System:** Updated smakefiles to build against NDK3.2 and ToolKit SDK
- **Executable:** Renamed core executable from 'AWeb-II' to 'AWeb'
- **HTTP/HTTPS Code Refactoring:** http module refactored to support HTTP/1.1, gzip and chunked encodings
- **Network Debugging:** Added extensive debugging output for http and amissl modules for developer builds
- **Socket timeouts:** Socket connections will now timeout and close gracefully if no response after 15 seconds
- **Defaults:** Updated default search and navigation URLs to websites relevant in 2025, and optimised default settings
- **English corrections:** Corrected many english grammar issues in default labels and restored buildable catalogs
- **Background color:** Changed default background color to pure white instead of Amiga grey
- **Image links:** No longer adds a border by default to images that have <a> links associated with them
- **Default search engine:** Changed default search engine to BoingSearch.com. Also works with FrogFind.com
- **reaction.lib:** Incorporated reaction.lib into build because this is needed to autoopen gradientslider.gadget since NDK3.2 is missing the protos
- **AWebCfg builds:** The AWebCfg build in the original 3.4 APL release was broken in several ways. Now fixed
- **Documentation:** Partial update of documentation to reflect reality of 2025
- **Refactoring:** Some refactoring of ezlists and image plugins to build correctly
- **Cookies:** Default cookie setting is now to set to Accept without asking user, and they're no longer called 'Netscape Cookies'
- **HTTP client:** Almost completely rewritten to support HTTP 1.1 and added new encodings including chunked and/or gzip and work with Roadshow version of bsdsocket.library headers and AmiSSL 5.2. Includes far more error and bounds checking than original version.
- **zlib:** Statically linked version of zlib included to support gzip encoded http streams. Future plan is to refactor this to use z.library
- **XML entities:** Many new XML character entities such as &bull; and &rsquo; are now supported and mapped to best Latin-1 equivalent
- **UTF-8:** Added a stopgap UTF-8 conversion to prevent common 'spurious glyphs' issues
- **XML and DOCTYPE headers:** Simple addition to parser to ensure HTML documents starting with these headers don't render spurious text
- **JFIF plugin:** Now uses T: for it's temporary working directory location
- **Installer**: No need to run an installer script, AWeb will run from anywhere, though if the plugins are not in the same directory it won't find them unless they are in the AWeb: assign directory
- **Default Fonts:** Changed default fonts from bitmap fonts (times.font, courier.font) to scalable fonts (CGTimes.font, LetterGothic.font) for better rendering quality out of the box, with improved font fallback mechanism to gracefully fall back to bitmap fonts (times.font, courier.font) if scalable fonts are not available, with final fallback to topaz.font

- **Web-Safe Font Support:** Added comprehensive web-safe font aliases mapping common web fonts to Amiga scalable fonts:
  - Serif fonts: Times New Roman, Times, serif, Georgia, Palatino, Garamond, Book Antiqua → CGTimes.font
  - Sans-serif fonts: Arial, Helvetica, sans-serif, Verdana, Trebuchet MS, Tahoma, Lucida Sans Unicode, Comic Sans MS, Impact → CGTriumvirate.font
  - Monospace fonts: Courier New, Courier, monospace, Lucida Console, Consolas → LetterGothic.font

### Fixed
- **Memory Corruption:** Fixed memory corruption in non-chunked gzip processing where buffer was allocated with first block size but subsequent blocks overflowed the buffer
- **Infinite Loop:** Fixed infinite loop in chunked+gzip processing when waiting for more data
- **Gzip Cleanup:** Fixed duplicate gzip processing that could cause corruption or truncation
- **Socket Timeouts:** Re-enabled and fixed socket timeout handling (SO_RCVTIMEO/SO_SNDTIMEO) to prevent SSL_connect() from hanging indefinitely
- **Socket Library Cleanup:** Fixed race condition where socketbase library was closed while SSL operations were still in progress
- **SSL Connection Handshake:** Fixed blocking SSL_connect() implementation to match earlier working version, with fallback to non-blocking I/O only when needed
- **Thread-Safe Logging:** Implemented thread-safe debug logging using semaphore protection to prevent log corruption from concurrent tasks
- **Use-After-Free Bugs:** Fixed critical race conditions where Assl objects were freed while still in use by concurrent tasks
- **Per-Connection Semaphores:** Added per-connection `use_sema` semaphore to protect SSL object access vs cleanup operations
- **SSL Object Lifecycle:** Fixed Assl object lifecycle - Assl_cleanup() no longer frees the struct itself (caller must free after cleanup)
- **SSL Context Creation:** Fixed concurrent SSL context creation race conditions with global `ssl_init_sema` semaphore
- **Per-Task AmiSSL Initialization:** Fixed per-task AmiSSL initialization - each task now correctly calls InitAmiSSL() and OPENSSL_init_ssl()
- **SocketBase Race Conditions:** Fixed race condition with global SocketBase pointer by storing per-connection socketbase in Assl struct
- **Buffer Validation:** Added buffer pointer and length validation in Assl_read() and Assl_write() to prevent overrun
- **SSL Error Handling:** Enhanced SSL error handling with detailed errno reporting for SSL_ERROR_SYSCALL cases
- **SNI (Server Name Indication):** Fixed SNI hostname setting using SSL_set_tlsext_host_name() for proper virtual host support
- **Non-Blocking I/O:** Implemented proper non-blocking SSL handshake with WaitSelect() timeout handling for servers that require it
- **Task Exit Handling:** Added Checktaskbreak() calls to allow graceful exit during blocking SSL operations
- **Opensocket() Validation:** Added socketbase validation throughout Opensocket() to detect and handle cases where library is closed during SSL initialization
- **Build warnings:** Fixed many Library typecast warnings and other build warnings due to type mismatches
- **Locale targets:** Fixed broken locale/cfglocale object targets in smakefile
- **AWeb: Assign:** Set default assign path to simply "AWeb:" and now creates the assign automatically on launch if it does not exist, in which case it also removes it on exit. If assign already exists before launch, it does not remove it.

### Removed
- **INet225 Support:** Disabled INet225 support - removed all support for socket.library, use a bsdsocket.library instead
- **Miami Support:** Disabled MiamiSSL support - although Miami supports bsdsocket.library, miamissl.library and miami.library are no longer supported which probably stops Miami's bsdsocket.library working properly too
