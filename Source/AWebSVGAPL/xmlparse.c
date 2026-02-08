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

/* xmlparse.c - Simple best-effort XML parser for SVG */

#include "xmlparse.h"
#include <string.h>

/* Initialize parser */
void XmlInitParser(struct XmlParser *parser, UBYTE *data, LONG length)
{  parser->data = data;
   parser->dataend = data + length;
   parser->tokenstart = NULL;
   parser->tokenend = NULL;
   parser->attrname = NULL;
   parser->attrvalue = NULL;
   parser->attrnamelen = 0;
   parser->attrvaluelen = 0;
   parser->line = 1;
   parser->column = 1;
   parser->flags = 0;
}

/* Check if character is whitespace */
BOOL XmlIsWhitespace(UBYTE c)
{  if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
   {  return TRUE;
   }
   return FALSE;
}

/* Skip whitespace */
void XmlSkipWhitespace(struct XmlParser *parser)
{  while (parser->data < parser->dataend && XmlIsWhitespace(*parser->data))
   {  if (*parser->data == '\n')
      {  parser->line++;
         parser->column = 1;
      }
      else
      {  parser->column++;
      }
      parser->data++;
   }
}

/* Unescape XML entities */
void XmlUnescape(UBYTE *str, LONG *length)
{  UBYTE *src = str;
   UBYTE *dst = str;
   UBYTE *end = str + *length;
   LONG newlen = 0;

   while (src < end)
   {  if (*src == '&')
      {  src++;
         if (src + 3 < end && *src == 'l' && *(src+1) == 't' && *(src+2) == ';')
         {  *dst++ = '<';
            src += 3;
            newlen++;
         }
         else if (src + 3 < end && *src == 'g' && *(src+1) == 't' && *(src+2) == ';')
         {  *dst++ = '>';
            src += 3;
            newlen++;
         }
         else if (src + 4 < end && *src == 'a' && *(src+1) == 'm' && *(src+2) == 'p' && *(src+3) == ';')
         {  *dst++ = '&';
            src += 4;
            newlen++;
         }
         else if (src + 5 < end && *src == 'q' && *(src+1) == 'u' && *(src+2) == 'o' && *(src+3) == 't' && *(src+4) == ';')
         {  *dst++ = '"';
            src += 5;
            newlen++;
         }
         else if (src + 5 < end && *src == 'a' && *(src+1) == 'p' && *(src+2) == 'o' && *(src+3) == 's' && *(src+4) == ';')
         {  *dst++ = '\'';
            src += 5;
            newlen++;
         }
         else
         {  /* Unknown entity, keep as-is */
            *dst++ = '&';
            src++;
            newlen++;
         }
      }
      else
      {  *dst++ = *src++;
         newlen++;
      }
   }
   *length = newlen;
}

/* Get current token name */
UBYTE *XmlGetTokenName(struct XmlParser *parser, LONG *length)
{  if (parser->tokenstart && parser->tokenend)
   {  *length = parser->tokenend - parser->tokenstart;
      return parser->tokenstart;
   }
   *length = 0;
   return NULL;
}

/* Get current token text */
UBYTE *XmlGetTokenText(struct XmlParser *parser, LONG *length)
{  return XmlGetTokenName(parser, length);
}

/* Get current attribute name */
UBYTE *XmlGetAttrName(struct XmlParser *parser, LONG *length)
{  if (parser->attrname)
   {  *length = parser->attrnamelen;
      return parser->attrname;
   }
   *length = 0;
   return NULL;
}

/* Get current attribute value */
UBYTE *XmlGetAttrValue(struct XmlParser *parser, LONG *length)
{  if (parser->attrvalue)
   {  *length = parser->attrvaluelen;
      return parser->attrvalue;
   }
   *length = 0;
   return NULL;
}

/* Get next token */
LONG XmlGetToken(struct XmlParser *parser)
{  UBYTE *p;
   UBYTE *start;
   UBYTE quote_char;

   parser->tokenstart = NULL;
   parser->tokenend = NULL;
   parser->attrname = NULL;
   parser->attrvalue = NULL;
   parser->attrnamelen = 0;
   parser->attrvaluelen = 0;

   if (parser->flags & XMLPF_ERROR)
   {  return XMLTOK_ERROR;
   }

   if (parser->data >= parser->dataend)
   {  return XMLTOK_EOF;
   }

   /* Safety check: ensure dataend is valid */
   if (parser->dataend < parser->data)
   {  parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   XmlSkipWhitespace(parser);

   if (parser->data >= parser->dataend)
   {  return XMLTOK_EOF;
   }

   /* If we don't have a '<' at the start, this isn't valid XML - but try to skip to it */
   if (*parser->data != '<')
   {  /* Skip to first '<' */
      while (parser->data < parser->dataend && *parser->data != '<')
      {  parser->data++;
      }
      if (parser->data >= parser->dataend)
      {  return XMLTOK_EOF;
      }
   }

   /* Check for XML declaration <?xml ... ?> */
   if (parser->dataend - parser->data >= 5 && 
       parser->data[0] == '<' && parser->data[1] == '?' && 
       parser->data[2] == 'x' && parser->data[3] == 'm' && parser->data[4] == 'l')
   {  /* Skip XML declaration */
      parser->data += 5;
      while (parser->dataend - parser->data >= 2)
      {  if (parser->data[0] == '?' && parser->data[1] == '>')
         {  parser->data += 2;
            return XmlGetToken(parser); /* Recursively get next token */
         }
         parser->data++;
      }
      parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   /* Check for processing instruction <?...?> */
   if (parser->dataend - parser->data >= 2 && 
       parser->data[0] == '<' && parser->data[1] == '?')
   {  /* Skip processing instruction */
      parser->data += 2;
      while (parser->dataend - parser->data >= 2)
      {  if (parser->data[0] == '?' && parser->data[1] == '>')
         {  parser->data += 2;
            return XmlGetToken(parser); /* Recursively get next token */
         }
         parser->data++;
      }
      parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   /* Check for comment */
   if (parser->data + 3 < parser->dataend && 
       parser->data[0] == '<' && parser->data[1] == '!' && 
       parser->data[2] == '-' && parser->data[3] == '-')
   {  /* Skip comment */
      parser->data += 4;
      while (parser->data + 2 < parser->dataend)
      {  if (parser->data[0] == '-' && parser->data[1] == '-' && parser->data[2] == '>')
         {  parser->data += 3;
            return XmlGetToken(parser); /* Recursively get next token */
         }
         parser->data++;
      }
      parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   /* Check for CDATA */
   if (parser->data + 8 < parser->dataend &&
       parser->data[0] == '<' && parser->data[1] == '!' &&
       parser->data[2] == '[' && parser->data[3] == 'C' &&
       parser->data[4] == 'D' && parser->data[5] == 'A' &&
       parser->data[6] == 'T' && parser->data[7] == 'A' &&
       parser->data[8] == '[')
   {  /* Skip CDATA for now, treat as text */
      parser->data += 9;
      start = parser->data;
      while (parser->data + 2 < parser->dataend)
      {  if (parser->data[0] == ']' && parser->data[1] == ']' && parser->data[2] == '>')
         {  parser->tokenstart = start;
            parser->tokenend = parser->data;
            parser->data += 3;
            return XMLTOK_TEXT;
         }
         parser->data++;
      }
      parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   /* Check for tag */
   if (*parser->data == '<')
   {  parser->data++;
      parser->flags |= XMLPF_IN_TAG;
      XmlSkipWhitespace(parser);

      if (parser->data >= parser->dataend)
      {  parser->flags |= XMLPF_ERROR;
         return XMLTOK_ERROR;
      }

      /* Debug: log what we're about to parse */
      {  UBYTE *debug_start = parser->data;
         UBYTE *debug_end = parser->dataend;
         LONG debug_len = debug_end - debug_start;
         if (debug_len > 20) debug_len = 20;
         /* Note: Can't use Aprintf here as this is in xmlparse.c which doesn't include aweb headers */
      }

      /* Check for end tag */
      if (*parser->data == '/')
      {  parser->data++;
         XmlSkipWhitespace(parser);
         start = parser->data;
         p = parser->data;
         while (p < parser->dataend && *p != '>' && !XmlIsWhitespace(*p))
         {  p++;
         }
         if (p >= parser->dataend || *p != '>')
         {  parser->flags |= XMLPF_ERROR;
            return XMLTOK_ERROR;
         }
         parser->tokenstart = start;
         parser->tokenend = p;
         parser->data = p + 1;
         parser->flags &= ~XMLPF_IN_TAG;
         return XMLTOK_END_TAG;
      }

      /* Start tag or empty tag */
      start = parser->data;
      p = parser->data;
      while (p < parser->dataend && *p != '>' && *p != '/' && !XmlIsWhitespace(*p))
      {  p++;
      }
      if (p >= parser->dataend)
      {  parser->flags |= XMLPF_ERROR;
         return XMLTOK_ERROR;
      }

      parser->tokenstart = start;
      parser->tokenend = p;
      parser->data = p;  /* Update parser->data to point after tag name */

      /* Check if empty tag */
      XmlSkipWhitespace(parser);
      if (parser->data < parser->dataend && *parser->data == '/')
      {  parser->data++;
         XmlSkipWhitespace(parser);
         if (parser->data >= parser->dataend || *parser->data != '>')
         {  parser->flags |= XMLPF_ERROR;
            return XMLTOK_ERROR;
         }
         parser->data++;
         parser->flags &= ~XMLPF_IN_TAG;
         return XMLTOK_EMPTY_TAG;
      }

      /* Check for attributes */
      XmlSkipWhitespace(parser);
      if (parser->data >= parser->dataend || *parser->data == '>')
      {  /* No attributes, end of tag */
         parser->flags &= ~XMLPF_IN_TAG;
         if (parser->data < parser->dataend && *parser->data == '>')
         {  parser->data++;
         }
         return XMLTOK_START_TAG;
      }
      
      /* There are attributes - return START_TAG now, attributes will come on next calls */
      /* Keep XMLPF_IN_TAG set so we know to parse attributes on subsequent calls */
      return XMLTOK_START_TAG;
   }

   /* If we're still in a tag from a previous call, check for more attributes */
   if (parser->flags & XMLPF_IN_TAG)
   {  XmlSkipWhitespace(parser);
      if (parser->data >= parser->dataend)
      {  parser->flags |= XMLPF_ERROR;
         return XMLTOK_ERROR;
      }
      if (*parser->data == '>')
      {  /* End of tag, no more attributes */
         parser->data++;
         parser->flags &= ~XMLPF_IN_TAG;
         parser->flags &= ~XMLPF_IN_ATTR;
         /* Continue to get next token */
      }
      else
      {  /* There's another attribute */
         parser->flags |= XMLPF_IN_ATTR;
         
         /* Read attribute name */
         start = parser->data;
         p = parser->data;
         while (p < parser->dataend && *p != '=' && *p != '>' && !XmlIsWhitespace(*p))
         {  p++;
         }
         if (p >= parser->dataend)
         {  parser->flags |= XMLPF_ERROR;
            return XMLTOK_ERROR;
         }
         if (*p != '=')
         {  parser->flags &= ~XMLPF_IN_ATTR;
            parser->flags &= ~XMLPF_IN_TAG;
            if (*p == '>')
            {  parser->data = p + 1;
            }
            /* Continue to get next token */
         }
         else
         {  /* We found '=', so this is an attribute */
            parser->attrname = start;
            parser->attrnamelen = p - start;
            parser->data = p + 1;
            XmlSkipWhitespace(parser);

            /* Read attribute value */
            if (parser->data >= parser->dataend || (*parser->data != '"' && *parser->data != '\''))
            {  parser->flags |= XMLPF_ERROR;
               return XMLTOK_ERROR;
            }
            quote_char = *parser->data;
            parser->data++;
            start = parser->data;
            while (parser->data < parser->dataend && *parser->data != quote_char)
            {  parser->data++;
            }
            if (parser->data >= parser->dataend)
            {  parser->flags |= XMLPF_ERROR;
               return XMLTOK_ERROR;
            }
            parser->attrvalue = start;
            parser->attrvaluelen = parser->data - start;
            parser->data++;  /* Skip closing quote */

            /* Unescape attribute value */
            XmlUnescape(parser->attrvalue, &parser->attrvaluelen);

            return XMLTOK_ATTR;
         }
      }
   }

      parser->flags |= XMLPF_ERROR;
      return XMLTOK_ERROR;
   }

   /* Text content */
   start = parser->data;
   p = parser->data;
   while (p < parser->dataend && *p != '<')
   {  p++;
   }
   parser->tokenstart = start;
   parser->tokenend = p;
   parser->data = p;

   /* Trim whitespace from text */
   while (parser->tokenend > parser->tokenstart && XmlIsWhitespace(*(parser->tokenend - 1)))
   {  parser->tokenend--;
   }
   while (parser->tokenstart < parser->tokenend && XmlIsWhitespace(*parser->tokenstart))
   {  parser->tokenstart++;
   }

   if (parser->tokenstart >= parser->tokenend)
   {  return XmlGetToken(parser); /* Skip empty text, get next token */
   }

   return XMLTOK_TEXT;
}

