# AWeb 3

This repository is the active development fork of AmiWeb for classic AmigaOS 3.2+ only.

The repository root contains the primary development tree.
A reference snapshot of the AWeb 3.6 upstream codebase is tracked separately under `vendor/amigazen-aweb3/`.

## Project direction

- native AmigaOS 3.2+ APIs only
- plain C89 in core code
- compiler-agnostic source where practical
- small, reviewable maintenance steps
- reproducible build and test discipline

## About this fork

AmiWeb is an HTML 3 /4 era web browser for Amiga. This fork focuses on maintaining and improving the codebase as a native  Amiga application for AmigaOS 3.2, with emphasis on buildability, system integration, and long-term maintainability.

The authors of AWeb are not affiliated with this fork. Redistribution remains subject to the terms described in the project documentation, especially `LICENSE` and `/docs/LICENSE.md`.

## Repository layout

- repository root: active fork development
- `vendor/amigazen-aweb3/`: imported upstream reference snapshot

## About AmiWeb

AmiWeb base one of the most sophisticated web browsers of its era on the Amiga platform, AWeb 3. The original author, Yvon Rozijn, released AWeb as open source under the AWeb Public License.

This fork continues development on a classic Amiga baseline with a focus on native APIs, maintainable source code, and a reproducible development workflow.

## HTML Standards Support

AmiWeb supports HTML standards from the 1990s era web browsing. The browser implements:

- **HTML 2.0**: Full support for the official HTML 2.0 standard
- **HTML 3.2**: Full support (W3C Recommendation from 1996)
- **HTML 4.0**: Many features supported, including experimental CSS1/CSS2 subset via inline styles and external stylesheets
- **XHTML 1.0/1.1**: Support for parsing and rendering XHTML 1.0/1.1 (and XHTML-MP) in strict mode with CDATA and self-closing tags (experimental)

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
| `STYLE` | ✅ Partial | Style element (inline CSS subset support) |
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
| **Advanced Features** | | |
| CSS Style Sheets | ✅ Partial | Experimental inline and external CSS (subset of CSS1/CSS2 properties). Supported areas include text/font properties, colors and backgrounds, basic layout (margin/padding/border/position), list styling, and simple grid layouts; many table/layout properties remain limited|
| XHTML 1.0/1.1 | ✅ Partial | XHTML 1.0/1.1 and XHTML-MP parsing/rendering with DOCTYPE/XML detection, self-closing tags, and CDATA support|
| URL Schemes (data:, cid:) | ✅ Full | `data:` URLs for inline resources and `cid:` URLs for multipart MIME Content-ID references (HTML email) as per RFC 2397 and RFC 2111|

### HTML Modes

AmiWeb offers three HTML parsing modes to handle the wide variety of HTML found on 1990s era websites:

1. **Strict Mode**: Only recognizes official HTML standards
2. **Tolerant Mode**: Recognizes browser-specific extensions and recovers from common HTML errors
3. **Compatible Mode**: Attempts to handle severely malformed HTML by relaxing parsing rules

## JavaScript Support

AmiWeb implements **JavaScript 1.5 (ECMA 262-3)**, providing comprehensive JavaScript language features and browser object model support. This includes all core JavaScript 1.1 features plus significant enhancements from the ECMAScript 3 standard.

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
| `switch` | ✅ Full | Multi-way branching (JavaScript 1.5) |
| `break`, `continue` | ✅ Full | Loop control |
| `return` | ✅ Full | Function return values |
| `try`/`catch` | ✅ Full | Exception handling (JavaScript 1.5) |
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
| **String** | ✅ Full | String object and methods (including `match`, `replace`, `search`, `split` with RegExp support) |
| **Number** | ✅ Full | Number object and methods |
| **Boolean** | ✅ Full | Boolean object |
| **Array** | ✅ Full | Array methods (`join`, `reverse`, `sort`, `concat`, `slice`, `splice`, `push`, `pop`, `shift`, `unshift`) |
| **Math** | ✅ Full | Mathematical functions and constants |
| **Date** | ✅ Full | Date and time handling |
| **Object** | ✅ Full | Base object type with prototype methods |
| **Function** | ✅ Full | Function constructor with `apply()` and `call()` |
| **RegExp** | ✅ Full | Regular expression objects (JavaScript 1.5) |

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
| `onError`, `onAbort` | ✅ Full | Image and object error events |

### JavaScript 1.5 (ECMA 262-3) Features

AmiWeb implements the following JavaScript 1.5 enhancements beyond JavaScript 1.1:

- ✅ `switch` statement - Multi-way branching
- ✅ Regular Expressions (`RegExp` object) - Pattern matching with `test()`, `exec()`, and properties
- ✅ Exception handling (`try`/`catch`) - Error handling with try/catch blocks
- ✅ Enhanced `Array` methods - `concat()`, `slice()`, `splice()`, `push()`, `pop()`, `shift()`, `unshift()`
- ✅ Enhanced `String` methods - `match()`, `replace()`, `search()`, `split()` with RegExp support
- ✅ `Function.prototype.apply()` and `call()` - Function invocation methods
- ✅ `Object.prototype` methods - `hasOwnProperty()`, `propertyIsEnumerable()`, `isPrototypeOf()`, `toLocaleString()`
- ✅ Dynamic garbage collection - Automatic memory management during script execution
- ✅ Fastidious and Omnivorous error modes - Configurable error handling behavior

### JavaScript Limitations

Features **not** currently supported:

- ❌ DOM manipulation methods (`getElementById`, `getElementsByTagName`, `createElement`, etc.)
- ❌ XMLHttpRequest (AJAX) - asynchronous HTTP requests from JavaScript
- ❌ `finally` clause in try/catch blocks

### JavaScript Tools

AmiWeb includes two JavaScript development tools:

- **AWebJS**: Standalone JavaScript interpreter for testing scripts outside the browser
- **JavaScript Debugger**: Built-in step-through debugger with variable inspection and expression evaluation

## Acknowledgements

*Amiga* is a trademark of **Amiga Inc**. 

Original AWeb by Yvon Rozijn, released as AWeb APL to the open source community
