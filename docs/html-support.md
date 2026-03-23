# AmiWeb HTML Support

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
