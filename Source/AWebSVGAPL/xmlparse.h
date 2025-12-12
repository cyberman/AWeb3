/**********************************************************************
 * 
 * This file is part of the AWeb distribution
 *
 * Copyright (C) 2025 amigazen project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the AWeb Public License as included in this
 * distribution.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * AWeb Public License for more details.
 *
 **********************************************************************/

/* xmlparse.h - Simple best-effort XML parser for SVG */

#ifndef XMLPARSE_H
#define XMLPARSE_H

#include <exec/types.h>

/* XML parser state */
struct XmlParser
{  UBYTE *data;              /* Current data pointer */
   UBYTE *dataend;           /* End of data */
   UBYTE *tokenstart;        /* Start of current token */
   UBYTE *tokenend;          /* End of current token */
   UBYTE *attrname;          /* Current attribute name */
   UBYTE *attrvalue;         /* Current attribute value */
   LONG attrnamelen;          /* Length of attribute name */
   LONG attrvaluelen;         /* Length of attribute value */
   LONG line;                 /* Current line number */
   LONG column;               /* Current column number */
   USHORT flags;              /* Parser flags */
};

/* Parser flags */
#define XMLPF_IN_TAG         0x0001   /* Inside a tag */
#define XMLPF_IN_ATTR        0x0002   /* Reading attribute */
#define XMLPF_IN_CDATA       0x0004   /* Inside CDATA section */
#define XMLPF_IN_COMMENT     0x0008   /* Inside comment */
#define XMLPF_ERROR          0x0010   /* Parser error */

/* Token types */
#define XMLTOK_NONE          0
#define XMLTOK_START_TAG     1
#define XMLTOK_END_TAG       2
#define XMLTOK_EMPTY_TAG     3
#define XMLTOK_TEXT          4
#define XMLTOK_ATTR          5
#define XMLTOK_EOF           6
#define XMLTOK_ERROR         7

/* Initialize parser */
void XmlInitParser(struct XmlParser *parser, UBYTE *data, LONG length);

/* Get next token */
LONG XmlGetToken(struct XmlParser *parser);

/* Get current token name (element or attribute) */
UBYTE *XmlGetTokenName(struct XmlParser *parser, LONG *length);

/* Get current token text (for text nodes) */
UBYTE *XmlGetTokenText(struct XmlParser *parser, LONG *length);

/* Get current attribute name */
UBYTE *XmlGetAttrName(struct XmlParser *parser, LONG *length);

/* Get current attribute value */
UBYTE *XmlGetAttrValue(struct XmlParser *parser, LONG *length);

/* Skip whitespace */
void XmlSkipWhitespace(struct XmlParser *parser);

/* Check if character is whitespace */
BOOL XmlIsWhitespace(UBYTE c);

/* Unescape XML entities */
void XmlUnescape(UBYTE *str, LONG *length);

#endif

