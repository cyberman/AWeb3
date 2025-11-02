# AWeb 3

This is AWeb 3 APL open source version, an HTML 3/4 web browser for Amiga.

## [amigazen project](http://www.amigazen.com)

*A web, suddenly*

*Forty years meditation*

*Minds awaken, free*

**amigazen project** is using modern software development tools and methods to update and rerelease classic Amiga open source software. Projects include a new AWeb, a new Amiga Python 2, and the ToolKit project - a universal SDK for Amiga.

Key to the amigazen project approach is ensuring every project can be built with the same common set of development tools and configurations, so the ToolKit project was created to provide a standard configuration for Amiga development. All *amigazen project* releases will be guaranteed to build against the ToolKit standard so that anyone can download and begin contributing straightaway without having to tailor the toolchain for their own setup.

The original authors of the *AWeb* software are not affiliated with the amigazen project. This software is redistributed on terms described in the documentation, particularly the file LICENSE or LICENSE.md

The amigazen project philosophy philosophy is based on openness:

*Open* to anyone and everyone	- *Open* source and free for all	- *Open* your mind and create!

PRs for all projects are gratefully received at [GitHub](https://github.com/amigazen/). While the focus now is on classic 68k software, it is intended that all amigazen project releases can be ported to other Amiga-like systems including AROS and MorphOS where feasible.

## About AWeb 3

AWeb is one of the most sophisticated web browsers (for its time) ever released on the Amiga platform. The original author, Yvon Rozijn, kindly made AWeb open source under the AWeb Public License. 

This project's first aim is to update the code so it builds against the NDK3.2, which largely means replacing the ClassAct UI APIs with the equivalent ReAction versions, as well as updating the networking code to work properly with RoadShow and the latest AmiSSL, and ensuring it can be built easily out of the box against the ToolKit standard by anyone with an Amiga computer.

## HTML Standards Support

AWeb 3 supports HTML standards from the 1990s era web browsing. The browser implements:

- **HTML 2.0**: Full support for the official HTML 2.0 standard
- **HTML 3.2**: Full support (W3C Recommendation from 1996)
- **HTML 4.0**: Many features supported (one major exception: CSS style sheets)

AWeb also supports many browser-specific extensions from Netscape and Microsoft Internet Explorer of the era, as well as some features from the abandoned HTML 3.0 draft.

### HTML Element Support

| Element | Support | Notes |
|---------|---------|-------|
| **Document Structure** | | |
| `HTML`, `HEAD`, `BODY` | ✅ Full | Standard document structure |
| `TITLE`, `BASE`, `ISINDEX` | ✅ Full | Document metadata |
| `META`, `LINK` | ✅ Full | Meta information and links |
| **Text Formatting** | | |
| Headings (`H1`-`H6`) | ✅ Full | Six levels of headings |
| `P`, `BR`, `HR` | ✅ Full | Paragraphs, line breaks, horizontal rules |
| `PRE`, `LISTING`, `XMP` | ✅ Full | Preformatted text |
| `CENTER`, `DIV` | ✅ Full | Text alignment and division |
| `NOBR`, `WBR` | ✅ Partial | Tolerant mode only (Netscape extension) |
| **Text Style** | | |
| `B`, `I`, `U`, `STRIKE` | ✅ Full | Bold, italic, underline, strikethrough |
| `TT`, `CODE`, `SAMP`, `KBD`, `VAR` | ✅ Full | Monospace and code styling |
| `EM`, `STRONG`, `CITE`, `DFN` | ✅ Full | Emphasis and citation |
| `BIG`, `SMALL`, `SUB`, `SUP` | ✅ Full | Size and positioning |
| `FONT`, `BASEFONT` | ✅ Full | Font face, size, color (deprecated in HTML 4) |
| `BLINK` | ✅ Partial | Tolerant mode only (Netscape extension) |
| **Lists** | | |
| `UL`, `OL`, `LI` | ✅ Full | Unordered and ordered lists |
| `DL`, `DT`, `DD` | ✅ Full | Definition lists |
| `DIR`, `MENU` | ✅ Full | Directory and menu lists |
| **Links and Images** | | |
| `A` (anchor) | ✅ Full | Hyperlinks and anchors |
| `IMG` | ✅ Full | Images with all standard attributes |
| `MAP`, `AREA` | ✅ Full | Client-side image maps |
| **Tables** | | |
| `TABLE`, `CAPTION` | ✅ Full | Table structure |
| `TR`, `TD`, `TH` | ✅ Full | Table rows and cells |
| `THEAD`, `TFOOT`, `TBODY` | ✅ Full | Table sections |
| `COLGROUP`, `COL` | ✅ Full | Column grouping |
| **Forms** | | |
| `FORM` | ✅ Full | Form container |
| `INPUT` | ✅ Full | All input types (text, password, checkbox, radio, submit, reset, hidden, etc.) |
| `SELECT`, `OPTION` | ✅ Full | Dropdown and list boxes |
| `TEXTAREA` | ✅ Full | Multi-line text input |
| `BUTTON` | ✅ Full | Button element |
| **Frames** | | |
| `FRAMESET`, `FRAME` | ✅ Full | Frame-based layouts |
| `NOFRAMES`, `IFRAME` | ✅ Full | Fallback and inline frames |
| **Embedded Content** | | |
| `OBJECT`, `PARAM` | ✅ Full | Embedded objects |
| `EMBED` | ✅ Partial | Tolerant mode only (Netscape extension) |
| `BGSOUND` | ✅ Partial | Tolerant mode only (Internet Explorer extension) |
| `SCRIPT`, `NOSCRIPT` | ✅ Full | JavaScript support |
| `STYLE` | ✅ Partial | Style element (limited CSS support) |
| `ICON` | ✅ Full | AWeb-specific icon support |

### HTML Features

| Feature | Support | Notes |
|---------|---------|-------|
| Character Entities | ✅ Full | HTML entities (`&nbsp;`, `&amp;`, etc.) |
| Numeric Entities | ✅ Full | `&#nnn;` and `&#xhhh;` formats |
| XML Entities | ✅ Partial | Many XML character entities mapped to Latin-1 |
| Tables | ✅ Full | Including backgrounds, borders, colspan, rowspan |
| Forms | ✅ Full | GET/POST, all input types, form validation |
| Frames | ✅ Full | Framesets, targeting, frame navigation |
| Client-side Image Maps | ✅ Full | Including maps defined in other documents |
| Background Images | ✅ Full | On `BODY` and table elements |
| Font Colors/Faces/Sizes | ✅ Full | Font styling attributes |
| Meta Refresh | ✅ Full | Client-pull mechanism |
| **Not Supported** | | |
| CSS Style Sheets | ❌ | Major HTML 4.0 feature not implemented |
| XHTML | ❌ | XML-based markup not supported |

### HTML Modes

AWeb offers three HTML parsing modes to handle the wide variety of HTML found on 1990s era websites:

1. **Strict Mode**: Only recognizes official HTML standards
2. **Tolerant Mode**: Recognizes browser-specific extensions and recovers from common HTML errors
3. **Compatible Mode**: Attempts to handle severely malformed HTML by relaxing parsing rules

## JavaScript Support

AWeb implements **JavaScript 1.1**, the version standardized by Netscape in 1996. This provides core JavaScript language features and browser object model support from the 1990s era.

### JavaScript Language Features

| Feature | Support | Notes |
|---------|---------|-------|
| **Data Types** | | |
| Numbers | ✅ Full | Integer and floating-point |
| Strings | ✅ Full | String literals and operations |
| Booleans | ✅ Full | `true` and `false` |
| `null`, `undefined` | ✅ Full | Null and undefined values |
| Objects | ✅ Full | Object literals and constructors |
| Arrays | ✅ Full | Array literals and methods |
| Functions | ✅ Full | Function declarations and expressions |
| **Operators** | | |
| Arithmetic | ✅ Full | `+`, `-`, `*`, `/`, `%`, `++`, `--` |
| Comparison | ✅ Full | `==`, `!=`, `===`, `!==`, `<`, `>`, `<=`, `>=` |
| Logical | ✅ Full | `&&`, `||`, `!` |
| Bitwise | ✅ Full | `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>` |
| Assignment | ✅ Full | `=`, `+=`, `-=`, etc. |
| Ternary | ✅ Full | `? :` conditional operator |
| **Control Flow** | | |
| `if`/`else` | ✅ Full | Conditional statements |
| `while`, `do/while` | ✅ Full | Looping constructs |
| `for`, `for/in` | ✅ Full | Iteration with `for` loops |
| `switch` | ❌ | Multi-way branching not in JavaScript 1.1 |
| `break`, `continue` | ✅ Full | Loop control |
| `return` | ✅ Full | Function return values |
| `try`/`catch` | ❌ | Exception handling not in JavaScript 1.1 |
| **Functions** | | |
| Function declarations | ✅ Full | Named and anonymous functions |
| Arguments object | ✅ Full | Access to function arguments |
| `this` keyword | ✅ Full | Context object reference |
| `new` operator | ✅ Full | Object instantiation |
| `typeof`, `delete` | ✅ Full | Type checking and property deletion |
| `void`, `in` | ✅ Full | Void operator and property checking |
| `with` statement | ✅ Full | Scope manipulation |
| `var` declarations | ✅ Full | Variable declarations |

### Browser Object Model (BOM)

| Object | Support | Notes |
|--------|---------|-------|
| **window** | ✅ Full | Top-level window object |
| `window.open()` | ✅ Full | Open new windows (with banner suppression option) |
| `window.close()` | ✅ Full | Close windows |
| `window.alert()`, `confirm()`, `prompt()` | ✅ Full | Dialog boxes |
| `window.setTimeout()`, `clearTimeout()` | ✅ Full | Timed execution |
| `window.status`, `defaultStatus` | ✅ Full | Status bar text |
| `window.location` | ✅ Full | Current URL and navigation |
| `window.history` | ✅ Full | Browser history navigation |
| `window.navigator` | ✅ Full | Browser information |
| `window.document` | ✅ Full | Document object model |
| `window.frames` | ✅ Full | Frame array access |
| **document** | ✅ Full | Document object |
| `document.write()`, `writeln()` | ✅ Full | Dynamic content generation |
| `document.forms[]` | ✅ Full | Form collection |
| `document.images[]` | ✅ Full | Image collection |
| `document.links[]` | ✅ Full | Link collection |
| `document.anchors[]` | ✅ Full | Anchor collection |
| `document.applets[]` | ✅ Full | Applet collection (Java) |
| `document.embeds[]` | ✅ Full | Embedded object collection |
| `document.cookie` | ✅ Full | Cookie access |
| `document.URL`, `referrer` | ✅ Full | Document location |
| `document.title` | ✅ Full | Document title |
| `document.bgColor`, `fgColor`, `linkColor`, etc. | ✅ Full | Document colors |
| `document.lastModified` | ✅ Full | Document modification date |
| **form** | ✅ Full | Form object |
| `form.elements[]` | ✅ Full | Form field collection |
| `form.submit()`, `reset()` | ✅ Full | Form submission |
| `form.action`, `method`, `target` | ✅ Full | Form attributes |
| **form elements** | ✅ Full | `text`, `textarea`, `select`, `checkbox`, `radio`, `button` objects |
| **location** | ✅ Full | URL location object |
| `location.href`, `protocol`, `host`, `pathname`, etc. | ✅ Full | URL components |
| `location.reload()` | ✅ Full | Reload current page |
| **history** | ✅ Full | Browser history |
| `history.back()`, `forward()`, `go()` | ✅ Full | History navigation |
| **navigator** | ✅ Full | Browser information |
| `navigator.appCodeName` | ✅ Full | Application code name |
| `navigator.appName` | ✅ Full | Application name |
| `navigator.appVersion` | ✅ Full | Application version |
| `navigator.userAgent` | ✅ Full | User agent string |
| `navigator.javaEnabled()` | ✅ Full | Check if Java is enabled (but always returns false) |
| `navigator.taintEnabled()` | ✅ Full | Check if data tainting is enabled |
| `navigator.platform` | ❌ | Not implemented in JavaScript 1.1 |

### JavaScript Built-in Objects

| Object | Support | Notes |
|--------|---------|-------|
| **String** | ✅ Full | String object and methods |
| **Number** | ✅ Full | Number object and methods |
| **Boolean** | ✅ Full | Boolean object |
| **Array** | ✅ Full | Array methods (`join`, `reverse`, `sort`, etc.) |
| **Math** | ✅ Full | Mathematical functions and constants |
| **Date** | ✅ Full | Date and time handling |
| **Object** | ✅ Full | Base object type |
| **Function** | ✅ Full | Function constructor |
| **RegExp** | ❌ | Regular expressions not in JavaScript 1.1 |

### JavaScript Event Handlers

| Event Handler | Support | Notes |
|---------------|---------|-------|
| `onClick` | ✅ Full | Mouse click events |
| `onLoad`, `onUnload` | ✅ Full | Page load/unload events |
| `onSubmit`, `onReset` | ✅ Full | Form events |
| `onChange` | ✅ Full | Form field change events |
| `onFocus`, `onBlur` | ✅ Full | Focus events |
| `onMouseOver`, `onMouseOut` | ✅ Full | Mouse hover events |
| `onSelect` | ✅ Full | Text selection events |

### JavaScript Limitations

Features **not** supported in JavaScript 1.1:

- ❌ `switch` statement (multi-way branching)
- ❌ Regular Expressions (`RegExp` object)
- ❌ Exception handling (`try`/`catch`/`finally`)
- ❌ JSON parsing/stringifying
- ❌ `Array` methods like `forEach`, `map`, `filter` (ES5 features)
- ❌ `let`/`const` variable declarations (ES6 features)
- ❌ Arrow functions (ES6 features)
- ❌ Classes (ES6 features)
- ❌ Modern DOM manipulation methods

### JavaScript Tools

AWeb includes two JavaScript development tools:

- **AWebJS**: Standalone JavaScript interpreter for testing scripts outside the browser
- **JavaScript Debugger**: Built-in step-through debugger with variable inspection and expression evaluation

## Roadmap

The first AWeb APL open source release was version 3.4, in 2003 from the _AWeb Open Source Development Team_.

Since then one further "3.5" beta release was made for both OS4 and classic Amiga, however the source code to the 68k release of 3.5 seem to no longer be available to the public, if it ever was. The OS4 version is available on os4depot. This release incorporated many improvements to JavaScript, image rendering and much more.

Thus, this version 3.6 is derived directly from the 3.4 source code release. 

The roadmap for AWeb 3 under amigazen project is, for now:

### AWeb 3.6

- Stable re-release of AWeb 3.4 functionality built against ReAction, Roadshow (with INet225 support disabled), P96 (replacing no longer supported Cybergraphics libraries), AmiSSL 5 and NDK3.2
- Cherry pick the most important patches from the various 3.5 releases found in the wild, where code is available
- Add HTTP/1.1, chunked encoding and gzip compressed http streams support
- Update to AmiSSL 5.20
- Refresh icons, images and other supporting materials
- Make minor fixesm improvements and change default configuration settings to sensible values

### AWeb 3.7

- Update image libraries to newer versions for JPEG, PNG and GIF
- Explore adding plugin support for WebP
- Cherry pick additional OS4 native build patches and other enhancements from 3.5 release

### Future releases

- Wait and see! 

## About ToolKit

**ToolKit** exists to solve the problem that most Amiga software was written in the 1980s and 90s, by individuals working alone, each with their own preferred setup for where their dev tools are run from, where their include files, static libs and other toolchain artifacts could be found, which versions they used and which custom modifications they made. Open source collaboration did not exist as we know it in 2025. 

**ToolKit** from amigazen project is a work in progress to make a standardised installation of not just the Native Developer Kit, but the compilers, build tools and third party components needed to be able to consistently build projects in collaboration with others, without each contributor having to change build files to work with their particular toolchain configuration. 

All *amigazen project* releases will release in a ready to build configuration according to the ToolKit standard.

Each component of **ToolKit** is open source and will have it's own github repo, while ToolKit itself will eventually be released as an easy to install package containing the redistributable components, as well as scripts to easily install the parts that are not freely redistributable from archive.

## Contact 

- At GitHub https://github.com/amigazen/aweb3/ 
- on the web at http://www.amigazen.com/aweb/ (Amiga browser compatible)
- or email aweb@amigazen.com

## Acknowledgements

*Amiga* is a trademark of **Amiga Inc**. 

Original AWeb by Yvon Rozijn, released as AWeb APL to the open source community