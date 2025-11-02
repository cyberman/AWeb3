## ChangeLog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6.0pre-alpha] - 2025-11-02

### Changed
- **UI Framework:** Migrated from ClassAct classes and headers to ReAction equivalents
- **Graphics System:** Refactored to use P96 instead of Cybergraphics
- **SSL Implementation:** Completely rewritten to use AmiSSL v5.2
- **Build System:** Updated smakefiles to build against NDK3.2 and ToolKit SDK
- **Executable:** Renamed core executable from 'AWeb-II' to 'AWeb'
- **Assign Path:** Changed all occurences of 'AWebPath:" and "AWeb3:" to simply "AWeb:"
- **URLs:** Updated default search and navigation URLs to websites relevant in 2025
- **English default strings:** Corrected many english grammar issues in default strings and restored buildable catalogs
- **Library Base typecasts:** Fixed most Library typecast warnings
- **reaction.lib:** Incorporated reaction.lib into build because this is needed to autoopen gradientslider.gadget since NDK3.2 is missing the protos
- **AWebCfg builds:** The AWebCfg build in the original 3.4 APL release was broken in several ways. Now fixed
- **Documentation:** Partial update of documentation to reflect reality of 2025
- **Refactoring:** Some refactoring of ezlists and image plugins
- **Cookies:** Default cookie setting is now to set to Accept without asking user
- **HTTP code:** Almost completely rewritten to support HTTP 1.1 and added new encodings including chunked and/or gzip and work with Roadshow version of bsdsocket.library headers and AmiSSL 5.2. Includes far more error and bounds checking than original version.
- **zlib:** Statically linked version of zlib included to support gzip encoded http streams. Future plan is to refactor this to use z.library

### Fixed
- **HTTP/HTTPS Code Refactoring:**
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
  - **Buffer Validation:** Added buffer pointer and length validation in Assl_read() and Assl_write() to prevent CHK instruction errors (80000006)
  - **SSL Error Handling:** Enhanced SSL error handling with detailed errno reporting for SSL_ERROR_SYSCALL cases
  - **SNI (Server Name Indication):** Fixed SNI hostname setting using SSL_set_tlsext_host_name() for proper virtual host support
  - **Non-Blocking I/O:** Implemented proper non-blocking SSL handshake with WaitSelect() timeout handling for servers that require it
  - **Task Exit Handling:** Added Checktaskbreak() calls to allow graceful exit during blocking SSL operations
  - **Opensocket() Validation:** Added socketbase validation throughout Opensocket() to detect and handle cases where library is closed during SSL initialization

### Removed
- **INet225 Support:** Disabled INet225 support - removed all support for socket.library, use bsdsocket.library instead
- **Miami Support:** Disabled MiamiSSL support - although MiamiSSL supports bsdsocket.library, miamissl.library and miami.library are no longer support which probably stops Miami's bsdsocket.library working properly too