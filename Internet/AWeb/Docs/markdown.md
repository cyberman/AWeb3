# AWeb Markdown Support

Since version 3.6, AWeb includes built-in support for rendering Markdown documents directly in the browser. This page, itself written in Markdown, documents the Markdown features supported by AWeb and provides examples of how to use them.

## What is Markdown?

Markdown is a lightweight markup language that allows you to write formatted text using plain text syntax. Instead of using complex HTML tags, you can use simple characters like asterisks, underscores, and hash symbols to create formatted documents.

Markdown files (`.md` or `.markdown` extension) are automatically detected by AWeb and rendered as formatted HTML4, making it easy to create documentation, readme files, and web pages without writing HTML directly.

## Markdown on the Amiga

AWeb brings Markdown rendering to the Amiga platform for the first time, enabling Amiga users to create and view beautifully formatted documentation directly in their AWeb browser. 

### Why Markdown is Perfect for the Amiga

Markdown is particularly well-suited for constrained systems like the Amiga for several important reasons:

**Plain Text Format**
- Markdown files are stored as plain text, requiring minimal storage space
- No complex binary formats or heavy dependencies
- Easy to edit with any text editor, even on low-memory systems
- Files are human-readable without special tools

**Low Resource Requirements**
- The Markdown parser in AWeb is lightweight and efficient
- Minimal memory footprint compared to complex HTML editors
- Fast parsing and rendering, even on classic Amiga hardware
- No external dependencies or additional libraries required

**Simple Syntax**
- Easy to learn and write, even for non-programmers
- Can be created and edited on any Amiga text editor
- No need for WYSIWYG editors or complex authoring tools
- Perfect for creating documentation, readme files, and simple hypertext pages, using Markdown's support for links



# How to use Markdown

A Markdown file is simply a plain text file, that uses certain characters to add semantic meaning to the document

## Headers

Headers are created using hash symbols (`#`). The number of hashes determines the header level:

# Level 1 Header

## Level 2 Header

### Level 3 Header

#### Level 4 Header

##### Level 5 Header

###### Level 6 Header

To create a header in Markdown, use one to six hash symbols followed by a space and your header text. For example:

```
# This is a Level 1 Header
## This is a Level 2 Header
### This is a Level 3 Header
```

## Text Formatting

### Bold Text

You can make text **bold** by surrounding it with two asterisks or two underscores:

- `**bold text**` renders as **bold text**
- `__bold text__` also renders as **bold text**

### Italic Text

You can make text *italic* by surrounding it with one asterisk or one underscore:

- `*italic text*` renders as *italic text*
- `_italic text_` also renders as *italic text*

### Nested Formatting

You can nest formatting within other formatting:

- `**bold with *italic* inside**` renders as **bold with *italic* inside**
- `*italic with **bold** inside*` renders as *italic with **bold** inside**

### Inline Code

You can display code inline by surrounding it with backticks:

The `printf()` function is used to display text in C programs.

To write inline code, use single backticks around your code. For example, a backtick, the word "code", and another backtick will display as inline code.

## Links

Links in Markdown use the format `[link text](URL)`:

- [AWeb Homepage](http://www.amigazen.com/aweb/)

You can also add an optional title attribute: `[link text](URL "title")`.

### Link Examples

Here's how to create links in Markdown:

```
[Link Text](http://example.com)
[Link with Title](http://example.com "This is the title")
```

## Images

Images use a similar syntax to links, but with an exclamation mark at the beginning: `![alt text](image URL)`

![AWeb Logo](aweb.iff "AWeb Logo")

Images can also be referenced without a title:

![Back Arrow](back.gif)

### Image Syntax

```
![Alt Text](image.gif)
![Alt Text](image.gif "Image Title")
```

The alt text is displayed if the image cannot be loaded, and is important for accessibility.

## Lists

### Unordered Lists

Unordered lists use dashes, asterisks, or plus signs:

- First item
- Second item
- Third item
  - Nested item (indented with 2 spaces)
  - Another nested item
- Fourth item

You can also use asterisks or plus signs:

* Item with asterisk
* Another item
+ Item with plus sign

### Ordered Lists

Ordered lists use numbers followed by a period:

1. First numbered item
2. Second numbered item
3. Third numbered item
   1. Nested numbered item (indented with 3 spaces)
   2. Another nested item
4. Fourth numbered item

### List Syntax

```
- Unordered list item
- Another item
  - Nested item (indent with 2 spaces)

1. Ordered list item
2. Another item
   1. Nested item (indent with 3 spaces)
```

### Lists with Formatting

List items can contain formatted text:

- Item with **bold text**
- Item with *italic text*
- Item with `inline code`
- Item with a [link](http://example.com)

## Code Blocks

### Fenced Code Blocks

Fenced code blocks use triple backticks (```) to create preformatted code blocks:

```
#include <stdio.h>

int main(void)
{
    printf("Hello, World!\n");
    return 0;
}
```

### Indented Code Blocks

You can also create code blocks by indenting lines with four spaces or a tab:

    This is a code block
    created with indentation.
    It preserves spacing and formatting.

### Code Block Syntax

To create a fenced code block, use three backticks on a line by itself, then your code, then three backticks again to close it.

Here's an example using an indented code block to show the syntax:

    ```
    Your code here
    ```

To create an indented code block, indent each line with 4 spaces or a tab.

## Blockquotes

Blockquotes are created using the greater-than symbol (`>`) at the beginning of a line:

> This is a blockquote.
> It can span multiple lines.
> 
> And can have multiple paragraphs.

### Blockquote Syntax

```
> This is a blockquote.
> It continues on the next line.
> 
> Empty lines create new paragraphs within the blockquote.
```

## Horizontal Rules

Horizontal rules (dividers) are created using three or more dashes, asterisks, or underscores on a line by themselves:

---

Above is a horizontal rule using dashes.

***

And another using asterisks.

___

And one using underscores.

### Horizontal Rule Syntax

```
---
***
___
```

All three styles create the same visual effect.

## Special Characters and HTML Entities

Markdown automatically escapes HTML special characters:

- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `&` becomes `&amp;`
- `"` becomes `&quot;`

For example, to display `<div>` in your text, you would write it as-is in Markdown, and it will be automatically escaped.

## Escaping Markdown Syntax

If you want to display Markdown syntax literally (without it being interpreted), you can escape special characters with a backslash:

- `\*not italic\*` displays as \*not italic\*
- `\*\*not bold\*\*` displays as \*\*not bold\*\*
- `\[not a link\](url)` displays as \[not a link\](url)

### Showing Backticks

To display backticks in your text, you can use double backticks around single backticks. For example, two backticks, then a space, then a single backtick, the word "code", another single backtick, a space, and two more backticks will display the word "code" with backticks around it.

You can also escape backticks with a backslash to display them literally.

## Mixed Content Examples

Here are some examples combining multiple Markdown features:

### Paragraph with Multiple Formatting

Here's a paragraph with **bold**, *italic*, `code`, and a [link](http://example.com). You can combine all these features in a single paragraph.

### Complex List

AWeb supports:

1. **HTML4** rendering with full table support
2. *Basic JavaScript* 1.1 for interactive pages
3. Multiple protocols including:
   - HTTP and HTTPS
   - FTP for file transfers
   - Gopher protocol
   - Gemini protocol
4. Image formats: GIF, JPEG, and PNG

> **Note:** AWeb is a powerful web browser for AmigaOS 3.2 and AmigaOS 4.1, providing modern web browsing capabilities on classic Amiga hardware.

## File Extensions

AWeb recognizes Markdown files by their extension:

- `.md` - Standard Markdown extension
- `.markdown` - Alternative Markdown extension

When AWeb encounters a file with one of these extensions, it automatically renders it as formatted Markdown instead of plain text.

## MIME Type

Markdown files are served with the `text/markdown` MIME type. AWeb's MIME type detection automatically identifies Markdown files and routes them to the Markdown renderer.

## Getting Started

To create a Markdown document:

1. Create a new file with a `.md` or `.markdown` extension
2. Write your content using Markdown syntax
3. Open the file in AWeb to see it rendered

You can also serve Markdown files from a web server - AWeb will automatically detect and render them correctly.

## Examples in This Document

This entire document is written in Markdown! You can view the source to see how each feature is implemented. All the formatting you see - headers, lists, links, code blocks, and more - is created using simple Markdown syntax.

