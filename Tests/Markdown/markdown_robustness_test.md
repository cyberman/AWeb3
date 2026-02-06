# Markdown robustness test

This document is designed to test safety/robustness of Markdown rendering.

## Inline code escaping
Inline code should NOT be interpreted as HTML:
`<b>bold?</b> & <i>italics?</i> "quotes"`

## Fenced code block escaping
```text
<html>
  <body>
    & should stay as text
    <b>should not become bold</b>
  </body>
</html>
```

## Indented code block escaping
    <div class="x">This must not be treated as HTML</div>
    & and < and > must stay literal

## Stress: many inline markups in one line
This line contains many things: **bold** *italic* [link](http://example.com) `code` ![alt](file:dummy) **morebold** *moreitalic* [x](http://example.com) `y` **z**

