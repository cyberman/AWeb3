## ChangeLog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6alpha6] - 17-12-2025

### Added
- **Enhanced CSS Support:** More CSS properties now supported including:
  - Layout: padding, margin (with auto support), position (absolute, relative, fixed, static), top, left, right, bottom, border (width, style, color), vertical-align, text-align
  - Display: display: none (elements completely hidden), overflow (hidden/auto/scroll with clipping), clear (left/right/both for float clearing)
  - Sizing: min-width, max-width, min-height, max-height constraints
  - Colors: CSS colors can now be specified in either hex format (#RRGGBB) or by name (brown, black, red, etc.)
  - Combined table cell styles support
- **HTTP Range Support (RFC 7233):** Added Range request support for fast automatic resume of incomplete requests, reducing failed page asset loads
- **CID and Data URL Support:** Added parsing of cid: and data: URL types for inline binary attachments in multipart MIME messages
- **view-source: Protocol:** Added view-source: URL scheme support allowing viewing any URL as plain text (note: does not work correctly with 30x redirects)
- **Mozilla Bookmarks Import:** Mozilla bookmarks.html format files can now be imported into AWeb Hotlist
- **ICO Format Support:** ICO format images (such as favicon.ico) are converted on-the-fly into BMP format and passed to DataTypes for rendering
- **Protoweb.org Integration:** Added ARexx script for easily enabling Protoweb.org proxy to browse the web as if it's 1999
- **Enhanced User-Agent Spoofing:** Default User-Agent strings now reflect a variety of real-world HTML4 browsers found in the wild in 2025
- **Volume Information Display:** When viewing file:/// root directory, shows volume size and filesystem type rather than normal directory listing
- **Mousewheel Scrolling:** Added support for mousewheel events for scrolling document windows on OS4 and OS3.2
- **68020 Optimization:** All AWeb binaries now built with 68020 optimization enabled by default. AWebPlugins are additional built with 68881 FPU optimisation enabled
- **Locale Catalogs:** All locale catalogs from AWeb 3.4 are now included in the distribution. Note that the list of strings has not changed. Strings added in AWeb 3.5 are NOT included. Do NOT use catalogs meant for AWeb 3.5
- **PNG Plugin Update:** PNG AWebPlugin updated to use libpng 1.6.43
- **New MIME Types:** Added default MIME types for files common in 2025, and all MIME types are set to lowercase as per RFC 6838

### Changed
- **Connection Cancellation:** Connections that are still loading for the current page will immediately be terminated when navigating to a new page or reloading. Same improvement applies to Cancel All button in Network Status window and Cancel Load menu item/ARexx commands
- **TLS Cipher Preference:** AWeb now prefers CHACHA20-POLY1305 ciphers over AES-GCM for better performance on Amiga
- **AmiSSL SDK:** Rebuilt with latest AmiSSL 5.25 SDK
- **CSS Selector Matching:** Enhanced CSS selector matching with:
  - Multiple chained CSS classes (e.g., .class1.class2)
  - Descendant selector matching (e.g., "body .item")
  - Child combinator matching (e.g., "div > p")
  - Specificity-based rule sorting (higher specificity wins, last wins for same specificity)
- **CSS Property Application:** Enhanced CSS property application with proper precedence order (external CSS → FONT tag attributes → inline CSS)
- **FOUC on page load:** At last, there is no placeholder square image flashed on screen while a document loads

### Fixed
- **CSS Loading:** Fixed multiple issues preventing external CSS files from loading correctly when cached:
  - Fixed 304 Not Modified response handling for cached CSS
  - Fixed ERROR flag handling when CSS load completed with ERROR but had valid buffer data
  - Fixed infinite loop when loading external CSS/JS files from CDNs
  - Fixed duplicate CSS merging (CSS was being merged twice)
  - Fixed invalid cached buffer returns (checking DOXF_EOF flag and buffer validity)
  - Fixed reload flag preservation for CSS files
- **CSS Parser:** Fixed infinite loop parsing CSS if CSS file was in UTF-8 (UTF-8 BOM handling)
- **CSS Rendering:** Fixed multiple CSS rendering issues:
  - Fixed background images setting incorrectly controlling all color rendering
  - Fixed child element background colors not rendering when body has background image
  - Fixed link color leaking from links to regular text in external stylesheets
  - Fixed class-based link selectors not applying colors
  - Fixed inline CSS color on links not working
  - Fixed text-transform working for external stylesheets but failing for inline styles
  - Fixed whitespace normalization in `<pre>` blocks (preserves non-breaking spaces)
- **SSL/TLS Management:** Refactored SSL_CTX management with shared SSL_CTX and proper reference counting to prevent crashes
- **Redirect Handling:** Fixed redirects for URLs with query strings - they are now marked as volatile to force refresh since query strings change the URL's intent
- **WBStartup Bug:** Fixed long-standing bug from AWeb 3.4 where wrong struct member was used to reply to WBStartup ReplyPort, causing unpredictable crashes on launch or DSI errors on OS4
- **BUTTON Elements:** Fixed BUTTON elements to display their inner text content as their label instead of being blank
- **Connection Reset:** Fixed connection reset error reporting - don't report ECONNRESET as error when all Content-Length data has been received
- **Memory Leaks:** Fixed resource leaks in CSS module and memory corruption in FreeCSSStylesheetInternal
- **Race Conditions:** Fixed critical race condition in amissl.c that caused intermittent crashes when SSL objects were accessed while being freed concurrently
- **Enforcer Hits:** Fixed possible Enforcer (null pointer) hits in Adddefmenu for empty menu item labels and Getmainstr() with NULL name

### Reintegrated from AWeb 3.5
- **HTML Elements:** Reintegrated support for INS and DEL HTML elements
- **Background Alignment:** Reintegrated bgalign (background alignment) mechanism for proper table background image alignment
- **Background Image Optimization:** Reintegrated optimization for background image redraws
- **JavaScript Improvements:**
  - Fixed JavaScript Image onerror handling
  - Fixed long-standing bug with caching of JavaScript source files that would store empty files in cache
  - Fixed problem where onload and onunload would not work when preceded by a script section in the head of the document
  - Added onclick event handler support for `<IMG>` and `<OBJECT>` elements
- **Form Elements:** Some FORM elements like INPUT and BUTTON can now exist outside of forms and be used as document GUI objects that can trigger JavaScript events
- **DefIcons Support:** Saved files will get a DefIcons icon if running on the system, thanks to using GetDiskObjectNew() instead of GetDefDiskObject()
- **Table Bug:** Fixed bug with nested tables having the height tag
- **Redirect Referer:** The referer in redirected pages is now set correctly
- **Printer Support:** AWeb is now aware that printer.device can handle bitmaps greater than 8 bits from version 44, enabling printing from deep screens without requiring Turboprint
- **Event Handlers:** In tolerant mode event handlers such as onclick now allow the form "javascript:code" often used and supported by other browsers
- **Cookie Domain Matching:** Non-RFC cookie mode extended to allow .domain.com to match domain.com, improving the behaviour of some login systems
- **Image Popup Menu:** Added Copy Image Url To Clipboard to default Image Popup menu
- **JavaScript Images:** Fixed bug where JavaScript images could overwrite some document properties
- **GIF Transparency:** Fixed bug where transparent GIF animations did not update their backgrounds
- **Enforcer Fixes:** Integrated fixes for known Enforcer hits in original AWeb 3.4 in body.c, defprefs.c and jcomp.c
- **Mousewheel on OS4:** Added support for mousewheel scrolling on OS4
- **Plugin Memory:** Fixed missing FreeMem call in every AWebPlugin startup.c

## [3.6alpha5] - 25-12-05

### Added
- **CSS Support:** Experimental inline CSS support for a subset of CSS1 and CSS2 properties including:
  - Text properties: font-family, font-size, font-style, font-weight, color, text-align, text-decoration, text-transform, white-space
  - Layout properties: padding, margin (1-4 value syntax), position, top, left
  - Background properties: background-color, background-image
  - Border properties: border-style, border-color (parsing only, rendering limited)
  - List properties: list-style-type for UL and OL elements
  - Line height: line-height property parsing
  - CSS Grid: Basic grid layout properties parsing (display: grid, grid-gap, grid-template-columns, grid positioning)
- **External Stylesheets:** Experimental support for `<link rel="stylesheet">` external CSS stylesheets with CSS selector matching (element, class, ID selectors)
- **XHTML 1.0 Support:** Added XHTML 1.0 parsing and rendering support, enforcing strict parsing mode when XHTML is detected and implementing CDATA sections
- **CDATA Parsing:** Added CDATA parsing in XHTML documents
- **Gemini and Spartan Protocols:** Experimental support for the gemini:// and spartan:// protocols, new gopher-like networks, and the gemtext markup language they use
- **AWebView:** New standalone HTML and Markdown file viewer built using the LOCALONLY build configuration, taking up less RAM by excluding network features
- **Enhanced UTF-8 Support:** UTF-8 support now handles mapping some 3-byte and 4-byte characters to Latin-1
- **Iconify Support:** Added support for intuition.library 46 Iconify gadget on browser windows
- **Right Mouse Button Context Menu:** Changed default input for context menu from middle button to right mouse button
- **Case Insensitive Entities:** Entity names are now case-insensitive (both &auml; and &Auml; work)
- **RSS MIME type parsing:** Added foundational changes for future RSS AWebPlugin
- **CSS Test Pages:** Added comprehensive CSS test pages to documentation (css_test.html, stylesheet_test.html)

### Changed
- **PNG Plugin:** Updated to version 1.0.69 (latest 1.0.x branch) and now uses the same zlib as the main AWeb program instead of the previous ancient version
- **TLS Security:** TLS connections now safely fail immediately instead of prompting the user to allow unsecure fallback if secure socket cannot be established. Removed option for users to allow HTTPS to downgrade to unsecure HTTP connections
- **TLS Cipher Ordering:** Revised TLS cipher ordering so that most performant cipher (CHACHA) goes first before AES
- **HTTP/1.1 Keep-Alive:** Further enhancement to HTTP/1.1 keep-alive support but still disabled in this alpha release build
- **MIME Types:** MIME types are now lowercase by default as per standards, although matching remains case-insensitive
- **XML Entity Lookup:** Changed XML entities lookup to linear search instead of binary search for better case insensitivity support

### Fixed
- **CSS Parser:** Fixed infinite loops in CSS parser by ensuring parser pointer always advances, even on parse errors. Added safeguards to skip malformed properties/selectors
- **CSS Length Values:** Fixed ParseCSSLengthValue to use strtod() to properly parse decimal values (.5em, 1.5em) and percentage values (150%) instead of sscanf with %ld which only handles integers
- **CSS Link Colors:** Fixed CSS rules with pseudo-classes (a:link, a:visited, etc.) being incorrectly applied in ApplyCSSToBody, causing link colors to affect body text
- **Self-Closing Tags:** Fixed parsing self-closing tags on malformed websites (e.g. amigaworld.net)
- **Argument Parsing:** Fixed null pointer access during argument parsing on launch which failed silently except on OS4 where it throws a DSI error
- **CONFIG Directory:** Fixed issue where if using a custom CONFIG argument, AWeb now creates the directory for it if it doesn't already exist before saving into it
- **TLS Cleanup:** Fixed TLS connections are properly cleaned up in all circumstances and AmiSSL libraries are only closed on application exit. Fixed double cleanup in Readdata() where Assl_closessl() was called before Assl_cleanup()
- **Chunked Encoding:** Fixed improvements to chunked encoding handling mean connections to google no longer trigger binary download
- **AmiSSL Validation:** Added AmiSSLBase validation checks ahead of macro calls to prevent DSI errors sometimes seen on OS4
- **Gopher Protocol:** Fixed enhanced Gopher type support from AWeb 3.5 with proper URL scheme handling

### Reintegrated from AWeb 3.5
- **PNG Plugin libpng:** Updated to version 1.0.0 as used in AWeb 3.5
- **JFIF Plugin JPEG Library:** Updated to version 6b as used in AWeb 3.5
- **GIF Plugin:** Incorporates GIF engine changes from AWeb 3.5
- **Gopher Module:** Reintegrated improvements to the gopher:// aweblib module from AWeb 3.5 including:
  - Support for CSO/telephone directory type ('2')
  - Support for telnet links type ('8') with proper telnet:// URLs
  - Support for WWW links type ('w') with proper http:// URLs
  - Support for HTML links type ('h')
  - Support for info messages type ('i')
  - Support for audio types ('s', '<')
  - Support for gopher+ extensions ('+', 'T', ':', ';')
  - Support for error type ('3')
  - Support for tn3270 type ('T')
  - Enhanced link generation with proper URL schemes based on gopher type

## [3.6alpha4] - 25-12-01

### Added
- **about:plugins:** Added about:plugins to about.aweblib module which lists all loaded AWebPlugin and AWebLib modules
- **file:// Protocol Directory Browsing:** The file:// protocol now supports browsing and navigating directories as well as viewing files unless a file "index.html" is present in the directory. Users can view individual files and navigate into subdirectories
- **file:/// Root URL:** Added support for file:/// root URL which displays a list of all mounted volumes
- **NOSTARTUP Command Line Option:** Added new command line option (and corresponding ToolType) "NOSTARTUP/S" to prevent startup.aweblib plugin from running, eliminating the splash screen
- **Documentation Test Pages:** Added test pages for HTML3.2, HTML4.0 and JavaScript 1.1 to documentation to demonstrate how AWeb handles these standards
- **theoldnet.com Integration:** Added theoldnet.com as a default bookmark and tested proxy function with theoldnet.com's http proxy service for browsing old versions of websites
- **Experimental HTTP/1.1 Keep-Alive:** Added experimental HTTP/1.1 keep-alive support to the codebase (not enabled in this build as it requires further testing and appears slower than expected)

### Changed
- **HTTPS Security:** HTTPS connections now deny use of weak ciphers and TLS versions below 1.2, check CN and SAN name matches with wildcard support, chain validation and Server Name Indication (SNI)
- **FONT Tag Font Selection:** FONT tags now search first for the named font if it exists on the system, then for the mapped alternative, then for the fallback font for the requested family
- **about:fonts Page:** Enhanced about:fonts page to illustrate exactly how AWeb will render the defacto standard web safe fonts on your system with the fonts you have installed
- **FORM Element Font Rendering:** FORM elements such as INPUT, TEXTAREA, SELECT and BUTTON now render using the current font of the element they are contained within, rather than the system font

### Fixed
- **Entity Rendering:** Entities are now always rendered as actual characters regardless of the HTML compatibility mode
- **Proxy Settings:** Fixed proxy settings now being saved - this was completely missing in the original AWeb 3.4 source code
- **PNG Plugin ReadBytes:** Fixed broken ReadBytes function in the PNG plugin that could cause an infinite loop loading assets from HTTPS connections, now fixed following the JPEG version pattern

### Reintegrated from AWeb 3.5
- **JavaScript Dynamic Garbage Collection:** JavaScript now employs dynamic garbage collection during script execution instead of only at the end, reducing overall memory usage
- **ETags for Caching:** Implemented ETags for caching
- **Content-Disposition Parsing:** Implemented Content-Disposition parsing used for setting suggested name for file downloads
- **302 and 307 Redirects:** Reintegrated support for 302 and 307 redirects

## [3.6alpha3] - 25-11-22

### Added
- **about: Protocol Support:** Added about.aweblib plugin providing special internal URLs:
  - `about:home` - Default home page with search interface and quick links
  - `about:blank` - Blank page for empty targets
  - `about:fonts` - Comprehensive font test page
  - `about:version` - Version information and open source credits
- **Markdown Rendering:** Markdown documents loaded from files or http(s) URLs are now rendered as HTML on the fly
- **XML Entity Support:** Added support for remaining Latin-1 XML entities:
  - `&euro;` and `&trade;` - Euro and trademark symbols
  - `&brkbar;` (166) - Alternate for `&brvbar;` (broken vertical bar)
  - `&die;` (168) - Alternate for `&uml;` (spacing dieresis or umlaut)
  - `&hibar;` (175) - Alternate for `&macr;` (spacing macron)
  - `&half;` (189) - Alternate for `&frac12;` (fraction 1/2)
- **MIME Type Handling:** Added default mimetypes for common plain text formats (RSS, Atom, Markdown) while still rendering them as plain text
- **Basic RSS/Atom Support:** Added support for recognizing RSS and Atom MIME types and rendering them as plain text
- **Enhanced Content-Type Detection:** Improved handling of files with incorrect Content-Type headers for common image formats and HTML files
- **TLS 1.3 Support:** Added TLS 1.3 cipher suites support for modern servers
- **HTTP Error Reporting:** Improved HTTP error reporting to distinguish timeout, network, and server errors with specific error types (ETIMEDOUT, ECONNRESET, ECONNREFUSED, ENETUNREACH, EHOSTUNREACH)
- **Redirect Loop Protection:** Added redirect loop protection (max 10 redirects per chain)
- **Command Line Option:** Added HAIKU as a valid alternative to VVIIV command line option (5-7-5 haiku easter egg)
- **Default Bookmarks:** Added sensible default bookmarks to bookmarks bar

### Changed
- **Window Sizing:** On larger screen resolutions (above 640x512) new browser windows will default to a more sensible size rather than full screen
- **Mouse Pointers:** AWeb now uses system provided contextual mouse pointers if intuition.library v47 or greater is available, instead of its own custom pointers, for links, text cursors, popup menus and resize handles
- **Quit Requester:** Closing the last browser window from the close gadget will no longer prompt with an 'Are you sure you want to quit?' requester unless there are transfers still in progress
- **HTTP Buffer Size:** Increased INPUTBLOCKSIZE from 8192 to 16384 bytes to accommodate long headers like content security policy common in 2025
- **SSL Security:** Increased minimum accepted TLS version to 1.2 and reviewed SSL security code for adherence to best practice (verify peer certificates, no session resumption on renegotiation, removed weak ciphers)
- **Default Config:** Added default custom config name (AWeb36a3) to the AWeb icon when launching from Workbench to avoid conflict with any preexisting AWeb settings

### Fixed
- **SSL/TLS Hostname Verification:** Fixed AmiSSL code to verify hostname matches certificate according to RFC 6125 standards (check site name matches CN or one of the SANs)
- **Task Userdata Race Condition:** Fixed critical race condition by using SSL_set_ex_data() instead of Settaskuserdata() for per-connection context storage, preventing certificate callbacks from accessing wrong or freed pointers
- **Certificate Callback Memory Safety:** Fixed certificate callback accessing freed memory by clearing ex_data and callback before freeing SSL objects/contexts
- **Buffer Security:** Replaced ERR_error_string() with ERR_error_string_n() for safe buffer handling, preventing buffer overruns
- **Hostname Validation:** Added RFC 1035-compliant length validation for hostnames and certificate names (max 253 chars) with explicit null termination for all string buffers
- **SSL Context Cleanup:** Removed legacy code that modified AmiSSLBase and fixed semaphore release logic to prevent double-release
- **Pointer Validation:** Added enhanced pointer validation before SSL_connect() to prevent crashes from invalid or corrupted SSL objects
- **Content-Length Transfer Truncation:** Fixed Content-Length transfer truncation by removing restrictive loop limits
- **Large File Transfers:** Fixed issue where large file transfers were truncated if more than 500 loops of chunked transfers were needed
- **Gzip Decompression:** Fixed gzip decompression limits for large compressed files
- **Chunked Encoding:** Fixed chunk position advancement bug when copying partial chunks due to buffer. When appending chunk continuation data to the gzip buffer, avail_in was incorrectly set to total buffer size instead of only the new unprocessed data. Improved tracking of gziplength to correctly position new data after any unprocessed data
- **Chunked Encoding Error Handling:** Added chunked encoding error handling with validation and overflow protection
- **Memory Cleanup:** Improved memory cleanup in all error paths
- **AWeb: Assign:** Fixed case where if AWeb: did already exist before launch, it would be unset on exit. Now if AWeb: does not already exist, it will be created and cleaned up, but if it is pre-existing, it will be untouched
- **HTTP Buffer Overflow:** Added bounds checking in Readblock() to clamp received bytes to available buffer space, preventing buffer overflow even if Receive() returns more data than expected. Added validation to ensure blocklength + n doesn't exceed blocksize

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
