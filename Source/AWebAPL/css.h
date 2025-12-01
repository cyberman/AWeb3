/**********************************************************************
 * 
 * This file is part of the AWeb APL distribution
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

/* css.h - AWeb CSS parsing and application */

#ifndef AWEB_CSS_H
#define AWEB_CSS_H

#include "aweb.h"
#include "docprivate.h"

/* CSS selector types */
#define CSS_SEL_ELEMENT    0x0001
#define CSS_SEL_CLASS      0x0002
#define CSS_SEL_ID         0x0004
#define CSS_SEL_PSEUDO     0x0008

/* CSS selector structure */
struct CSSSelector
{  struct MinNode node;
   USHORT type;              /* Selector type flags */
   UBYTE *name;              /* Element name (NULL = any) */
   UBYTE *class;             /* Class name */
   UBYTE *id;                /* ID name */
   USHORT specificity;      /* Selector specificity for cascade */
};

/* CSS property structure */
struct CSSProperty
{  struct MinNode node;
   UBYTE *name;              /* Property name */
   UBYTE *value;             /* Property value */
};

/* CSS rule structure */
struct CSSRule
{  struct MinNode node;
   struct MinList selectors; /* List of CSSSelector */
   struct MinList properties; /* List of CSSProperty */
};

/* CSS stylesheet structure */
struct CSSStylesheet
{  struct MinList rules;     /* List of CSSRule */
   void *pool;               /* Memory pool */
};

/* Function prototypes */
void ParseCSSStylesheet(struct Document *doc,UBYTE *css);
void ApplyCSSToElement(struct Document *doc,void *element);
void FreeCSSStylesheet(struct Document *doc);
void ApplyInlineCSS(struct Document *doc,void *element,UBYTE *style);
void ApplyInlineCSSToBody(struct Document *doc,void *body,UBYTE *style,UBYTE *tagname);
void ApplyInlineCSSToLink(struct Document *doc,void *link,UBYTE *style);
struct Colorinfo *ExtractBackgroundColorFromStyle(struct Document *doc,UBYTE *style);

#endif /* AWEB_CSS_H */

