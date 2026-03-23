# AmiWeb JavaScript Support

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
