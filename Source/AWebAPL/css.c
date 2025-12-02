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

/* css.c - AWeb CSS parsing and application */

#include <proto/exec.h>
#include <proto/utility.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include "aweb.h"
#include "css.h"
#include "docprivate.h"
#include "element.h"
#include "body.h"
#include "html.h"
#include "link.h"
#include "table.h"
#include "copy.h"
#include "colours.h"

/* COLOR macro - extract pen number from Colorinfo */
#define COLOR(ci) ((ci)?((ci)->pen):(-1))

/* Forward declarations */
static struct CSSStylesheet* ParseCSS(struct Document *doc,UBYTE *css);
static struct CSSRule* ParseRule(struct Document *doc,UBYTE **p);
static struct CSSSelector* ParseSelector(struct Document *doc,UBYTE **p);
static struct CSSProperty* ParseProperty(struct Document *doc,UBYTE **p);
static void SkipComment(UBYTE **p);
static UBYTE* ParseIdentifier(UBYTE **p);
static UBYTE* ParseValue(UBYTE **p);
static BOOL MatchSelector(struct CSSSelector *sel,void *element);
static void ApplyProperty(void *element,struct CSSProperty *prop);
static void FreeCSSStylesheetInternal(struct CSSStylesheet *sheet);
void SkipWhitespace(UBYTE **p);
long ParseCSSLengthValue(UBYTE *value,struct Number *num);
ULONG ParseHexColor(UBYTE *pcolor);

/* Simple debug printf */
static void debug_printf(const char *format, ...)
{  va_list args;
   va_start(args, format);
   vprintf(format, args);
   va_end(args);
}

/* Parse a CSS stylesheet */
void ParseCSSStylesheet(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   if(!doc || !css) return;
   
   /* debug_printf("CSS: ParseCSSStylesheet called, css length=%ld\n",strlen((char *)css)); */
   
   /* Free existing stylesheet if any */
   if(doc->cssstylesheet)
   {  FreeCSSStylesheetInternal((struct CSSStylesheet *)doc->cssstylesheet);
      doc->cssstylesheet = NULL;
   }
   
   /* Parse CSS */
   sheet = ParseCSS(doc,css);
   if(sheet)
   {  struct CSSRule *rule;
      long ruleCount = 0;
      doc->cssstylesheet = (void *)sheet;
      /* Count rules */
      for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
          (struct MinNode *)rule->node.mln_Succ;
          rule = (struct CSSRule *)rule->node.mln_Succ)
      {  ruleCount++;
      }
      /* debug_printf("CSS: Stylesheet parsed successfully, %ld rules\n",ruleCount); */
   }
   else
   {  /* debug_printf("CSS: Stylesheet parsing failed\n"); */
   }
}

/* Parse CSS content */
static struct CSSStylesheet* ParseCSS(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   struct CSSRule *rule;
   UBYTE *p;
   
   if(!doc || !css) return NULL;
   
   sheet = ALLOCSTRUCT(CSSStylesheet,1,0);
   if(!sheet) return NULL;
   
   NEWLIST(&sheet->rules);
   sheet->pool = doc->pool;
   
   p = css;
   while(*p)
   {  SkipWhitespace(&p);
      SkipComment(&p);
      if(!*p) break;
      
      rule = ParseRule(doc,&p);
      if(rule)
      {  ADDTAIL(&sheet->rules,rule);
      }
      else
      {  /* Skip to next rule on parse error */
         while(*p && *p != '}')
         {  p++;
         }
         if(*p == '}') p++;
      }
   }
   
   return sheet;
}

/* Parse a CSS rule */
static struct CSSRule* ParseRule(struct Document *doc,UBYTE **p)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   
   if(!doc || !p || !*p) return NULL;
   
   rule = ALLOCSTRUCT(CSSRule,1,0);
   if(!rule) return NULL;
   
   NEWLIST(&rule->selectors);
   NEWLIST(&rule->properties);
   
   /* Parse selectors */
   while(**p)
   {  SkipWhitespace(p);
      SkipComment(p);
      if(**p == '{') break;
      if(**p == ';' || **p == '}') return NULL; /* Invalid */
      
      sel = ParseSelector(doc,p);
      if(sel)
      {  ADDTAIL(&rule->selectors,sel);
      }
      else
      {  /* Parse error in selector */
         FREE(rule);
         return NULL;
      }
      
      SkipWhitespace(p);
      if(**p == ',')
      {  (*p)++;
         continue;
      }
      if(**p == '{') break;
   }
   
   if(**p != '{')
      {  FREE(rule);
         return NULL;
      }
   (*p)++; /* Skip '{' */
   
   /* Parse properties */
   while(**p)
   {  SkipWhitespace(p);
      SkipComment(p);
      if(**p == '}') break;
      
      prop = ParseProperty(doc,p);
      if(prop)
      {  ADDTAIL(&rule->properties,prop);
      }
      
      SkipWhitespace(p);
      if(**p == ';')
      {  (*p)++;
      }
      else if(**p == '}')
      {  break;
      }
   }
   
   if(**p == '}')
   {  (*p)++; /* Skip '}' */
      return rule;
   }
   
   FREE(rule);
   return NULL;
}

/* Parse a CSS selector */
static struct CSSSelector* ParseSelector(struct Document *doc,UBYTE **p)
{  struct CSSSelector *sel;
   UBYTE *name;
   UBYTE *id;
   UBYTE *class;
   UBYTE *pseudoName;
   
   if(!doc || !p || !*p) return NULL;
   
   sel = ALLOCSTRUCT(CSSSelector,1,0);
   if(!sel) return NULL;
   
   SkipWhitespace(p);
   
   /* Parse element name, class, or ID */
   if(**p == '.')
   {  /* Class selector */
      (*p)++;
      class = ParseIdentifier(p);
      if(class)
      {  sel->type = CSS_SEL_CLASS;
         sel->class = Dupstr(class,-1);
         sel->specificity = 10; /* Class specificity */
      }
      else
      {  FREE(sel);
         return NULL;
      }
      
      /* Check for descendant element after class (e.g., ".menubar li") */
      SkipWhitespace(p);
      if(**p && **p != ':' && **p != ',' && **p != '{' && **p != '}')
      {  name = ParseIdentifier(p);
         if(name)
         {  sel->type |= CSS_SEL_ELEMENT;
            sel->name = Dupstr(name,-1);
            sel->specificity += 1; /* Element adds to specificity */
         }
      }
   }
   else if(**p == '#')
   {  /* ID selector */
      (*p)++;
      id = ParseIdentifier(p);
      if(id)
      {  sel->type = CSS_SEL_ID;
         sel->id = Dupstr(id,-1);
         sel->specificity = 100; /* ID specificity */
      }
      else
      {  FREE(sel);
         return NULL;
      }
   }
   else
   {  /* Element name or universal */
      name = ParseIdentifier(p);
      if(name)
      {  sel->type = CSS_SEL_ELEMENT;
         sel->name = Dupstr(name,-1);
         sel->specificity = 1; /* Element specificity */
      }
      else
      {  /* Universal selector */
         sel->type = CSS_SEL_ELEMENT;
         sel->specificity = 0;
      }
      
      /* Check for class or ID after element name */
      SkipWhitespace(p);
      if(**p == '.')
      {  (*p)++;
         class = ParseIdentifier(p);
         if(class)
         {  sel->type |= CSS_SEL_CLASS;
            sel->class = Dupstr(class,-1);
            sel->specificity += 10;
         }
      }
      else if(**p == '#')
      {  (*p)++;
         id = ParseIdentifier(p);
         if(id)
         {  sel->type |= CSS_SEL_ID;
            sel->id = Dupstr(id,-1);
            sel->specificity += 100;
         }
      }
   }
   
   /* Check for pseudo-class (e.g., :link, :visited, :hover) */
   SkipWhitespace(p);
   if(**p == ':')
   {  (*p)++;
      pseudoName = ParseIdentifier(p);
      if(pseudoName)
      {  sel->type |= CSS_SEL_PSEUDO;
         sel->pseudo = Dupstr(pseudoName,-1);
         sel->specificity += 10; /* Pseudo-class adds to specificity */
      }
   }
   
   return sel;
}

/* Parse a CSS property */
static struct CSSProperty* ParseProperty(struct Document *doc,UBYTE **p)
{  struct CSSProperty *prop;
   UBYTE *name;
   UBYTE *value;
   
   if(!doc || !p || !*p) return NULL;
   
   prop = ALLOCSTRUCT(CSSProperty,1,0);
   if(!prop) return NULL;
   
   SkipWhitespace(p);
   
   /* Parse property name */
   name = ParseIdentifier(p);
   if(!name)
   {  FREE(prop);
      return NULL;
   }
   prop->name = Dupstr(name,-1);
   
   SkipWhitespace(p);
   if(**p != ':')
   {  FREE(prop->name);
      FREE(prop);
      return NULL;
   }
   (*p)++; /* Skip ':' */
   
   SkipWhitespace(p);
   
   /* Parse property value */
   value = ParseValue(p);
   if(value)
   {  prop->value = Dupstr(value,-1);
   }
   else
   {  FREE(prop->name);
      FREE(prop);
      return NULL;
   }
   
   return prop;
}

/* Skip whitespace */
void SkipWhitespace(UBYTE **p)
{  if(!p || !*p) return;
   while(**p && (isspace(**p) || **p == '\n' || **p == '\r' || **p == '\t'))
   {  (*p)++;
   }
}

/* Skip CSS comment */
static void SkipComment(UBYTE **p)
{  if(!p || !*p) return;
   if(**p == '/' && (*p)[1] == '*')
   {  (*p) += 2;
      while(**p)
      {  if(**p == '*' && (*p)[1] == '/')
         {  (*p) += 2;
            break;
         }
         (*p)++;
      }
   }
}

/* Parse an identifier */
static UBYTE* ParseIdentifier(UBYTE **p)
{  UBYTE *start;
   long len;
   UBYTE *result;
   
   if(!p || !*p) return NULL;
   
   SkipWhitespace(p);
   start = *p;
   
   /* First character must be letter, underscore, or non-ASCII */
   if(!isalpha(**p) && **p != '_' && (unsigned char)**p >= 128)
   {  return NULL;
   }
   (*p)++;
   
   /* Subsequent characters can be alphanumeric, underscore, or hyphen */
   while(**p && (isalnum(**p) || **p == '_' || **p == '-' || (unsigned char)**p >= 128))
   {  (*p)++;
   }
   
   len = *p - start;
   if(len == 0) return NULL;
   
   result = ALLOCTYPE(UBYTE,len + 1,0);
   if(result)
   {  memmove(result,start,len);
      result[len] = '\0';
   }
   
   return result;
}

/* Parse a property value */
static UBYTE* ParseValue(UBYTE **p)
{  UBYTE *start;
   long len;
   UBYTE *result;
   BOOL inString = FALSE;
   UBYTE quote = 0;
   
   if(!p || !*p) return NULL;
   
   SkipWhitespace(p);
   start = *p;
   
   /* Parse until semicolon, closing brace, or newline */
   /* Handle quoted strings within the value (e.g., font-family: "Open Sans", "Helvetica Neue", ...) */
   while(**p && **p != ';' && **p != '}' && **p != '\n' && **p != '\r')
   {  if((**p == '"' || **p == '\'') && !inString)
      {  quote = **p;
         inString = TRUE;
         (*p)++;
         /* Skip to closing quote */
         while(**p && **p != quote)
         {  if(**p == '\\' && (*p)[1])
            {  (*p) += 2; /* Skip escaped character */
            }
            else
            {  (*p)++;
            }
         }
         if(**p == quote)
         {  (*p)++; /* Skip closing quote */
            inString = FALSE;
         }
      }
      else
      {  (*p)++;
      }
   }
   len = *p - start;
   /* Trim trailing whitespace */
   while(len > 0 && isspace(start[len - 1]))
   {  len--;
   }
   
   if(len == 0) return NULL;
   
   result = ALLOCTYPE(UBYTE,len + 1,0);
   if(result)
   {  memmove(result,start,len);
      result[len] = '\0';
   }
   
   return result;
}

/* Match a selector to an element */
static BOOL MatchSelector(struct CSSSelector *sel,void *element)
{  UBYTE *elemName;
   UBYTE *elemClass;
   UBYTE *elemId;
   UBYTE *classPtr;
   
   if(!sel || !element) return FALSE;
   
   /* Get element attributes */
   elemName = (UBYTE *)Agetattr(element,AOELT_TagName);
   elemClass = (UBYTE *)Agetattr(element,AOELT_Class);
   elemId = (UBYTE *)Agetattr(element,AOELT_Id);
   
   /* Match element name */
   if(sel->type & CSS_SEL_ELEMENT && sel->name)
   {  if(!elemName || stricmp((char *)sel->name,(char *)elemName) != 0)
      {  return FALSE;
      }
   }
   
   /* Match class - class attribute can contain multiple classes separated by spaces */
   if(sel->type & CSS_SEL_CLASS && sel->class)
   {  if(!elemClass)
      {  return FALSE;
      }
      /* Check if class name appears in the class attribute */
      classPtr = (UBYTE *)strstr((char *)elemClass,(char *)sel->class);
      if(!classPtr)
      {  return FALSE;
      }
      /* Make sure it's a complete word match (not part of another class name) */
      if(classPtr != elemClass && !isspace(classPtr[-1]))
      {  return FALSE;
      }
      if(classPtr[strlen((char *)sel->class)] != '\0' && 
         !isspace(classPtr[strlen((char *)sel->class)]))
      {  return FALSE;
      }
   }
   
   /* Match ID */
   if(sel->type & CSS_SEL_ID && sel->id)
   {  if(!elemId || stricmp((char *)sel->id,(char *)elemId) != 0)
      {  return FALSE;
      }
   }
   
   return TRUE;
}

/* Apply a CSS property to an element */
static void ApplyProperty(void *element,struct CSSProperty *prop)
{  UBYTE *name;
   UBYTE *value;
   short align;
   
   if(!element || !prop || !prop->name || !prop->value) return;
   
   name = prop->name;
   value = prop->value;
   
   /* text-align */
   if(stricmp((char *)name,"text-align") == 0)
   {  if(stricmp((char *)value,"center") == 0)
      {  align = HALIGN_CENTER;
      }
      else if(stricmp((char *)value,"left") == 0)
      {  align = HALIGN_LEFT;
      }
      else if(stricmp((char *)value,"right") == 0)
      {  align = HALIGN_RIGHT;
      }
      else if(stricmp((char *)value,"justify") == 0)
      {  align = HALIGN_LEFT; /* Justify not supported, use left */
      }
      else
      {  return;
      }
      Asetattrs(element,AOELT_Halign,align,TAG_END);
   }
   /* font-family */
   else if(stricmp((char *)name,"font-family") == 0)
   {  /* Parse font family list (comma-separated) */
      UBYTE *fontName = value;
      UBYTE *comma;
      
      /* Find first font name (before comma) */
      comma = (UBYTE *)strchr((char *)value,',');
      if(comma)
      {  long len = comma - value;
         fontName = ALLOCTYPE(UBYTE,len + 1,0);
         if(fontName)
         {  memmove(fontName,value,len);
            fontName[len] = '\0';
            /* Trim whitespace */
            while(len > 0 && isspace(fontName[len - 1]))
            {  fontName[--len] = '\0';
            }
         }
      }
      
      /* TODO: Apply font family to element */
      /* This would require font management system */
      
      if(fontName != value) FREE(fontName);
   }
   /* font-size */
   else if(stricmp((char *)name,"font-size") == 0)
   {  /* Handle font size values */
      if(stricmp((char *)value,"xx-small") == 0)
      {  /* TODO: Apply smaller font size */
      }
      else if(stricmp((char *)value,"x-small") == 0)
      {  /* TODO: Apply small font size */
      }
      else if(stricmp((char *)value,"small") == 0)
      {  /* TODO: Apply small font size */
      }
      else if(stricmp((char *)value,"medium") == 0)
      {  /* TODO: Apply medium font size */
      }
      else if(stricmp((char *)value,"large") == 0)
      {  /* TODO: Apply large font size */
      }
      else if(stricmp((char *)value,"x-large") == 0)
      {  /* TODO: Apply larger font size */
      }
      else if(stricmp((char *)value,"xx-large") == 0)
      {  /* TODO: Apply largest font size */
      }
      /* TODO: Handle numeric sizes (px, pt, em, etc.) */
   }
}

/* Apply CSS to an element */
void ApplyCSSToElement(struct Document *doc,void *element)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct MinList matches;
   struct CSSStylesheet *sheet;
   
   if(!doc || !element || !doc->cssstylesheet) return;
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   
   NEWLIST(&matches);
   
   /* Find all matching rules */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  if(MatchSelector(sel,element))
         {  ADDTAIL(&matches,rule);
            break; /* One selector match is enough */
         }
      }
   }
   
   /* Apply properties from matching rules (simple cascade - last wins) */
   for(rule = (struct CSSRule *)matches.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
         (struct MinNode *)prop->node.mln_Succ;
         prop = (struct CSSProperty *)prop->node.mln_Succ)
      {  ApplyProperty(element,prop);
      }
   }
}

/* Free CSS stylesheet for a document */
void FreeCSSStylesheet(struct Document *doc)
{  if(doc && doc->cssstylesheet)
   {  FreeCSSStylesheetInternal((struct CSSStylesheet *)doc->cssstylesheet);
      doc->cssstylesheet = NULL;
   }
}

/* Free CSS stylesheet structure */
static void FreeCSSStylesheetInternal(struct CSSStylesheet *sheet)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   
   if(!sheet) return;
   
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  if(sel->name) FREE(sel->name);
         if(sel->class) FREE(sel->class);
         if(sel->id) FREE(sel->id);
         if(sel->pseudo) FREE(sel->pseudo);
      }
      for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
         (struct MinNode *)prop->node.mln_Succ;
         prop = (struct CSSProperty *)prop->node.mln_Succ)
      {  if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
      }
   }
   
   FREE(sheet);
}

/* Parse and apply inline CSS to an element */
void ApplyInlineCSS(struct Document *doc,void *element,UBYTE *style)
{  struct CSSProperty *prop;
   UBYTE *p;
   
   if(!doc || !element || !style) return;
   
   p = style;
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop)
      {  ApplyProperty(element,prop);
         /* Free the property */
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
}

/* Parse and apply inline CSS to a Body object */
void ApplyInlineCSSToBody(struct Document *doc,void *body,UBYTE *style,UBYTE *tagname)
{  struct CSSProperty *prop;
   struct Number num;
   UBYTE *p;
   ULONG colorrgb;
   struct Colorinfo *ci;
   short align;
   UBYTE *fontFace;
   UBYTE *comma;
   short fontSize;
   BOOL isRelative;
   long paddingValue;
   long marginTop;
   long marginRight;
   long marginBottom;
   long marginLeft;
   UBYTE *marginValue;
   UBYTE *marginTokens[4];
   long marginCount;
   long i;
   float lineHeightValue;
   UBYTE *lineHeightStr;
   UBYTE *displayValue;
   
   /* Initialize margin tokens array */
   for(i = 0; i < 4; i++) marginTokens[i] = NULL;
   
   if(!doc || !body || !style) return;
   
   p = style;
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {           /* Apply padding */
         if(stricmp((char *)prop->name,"padding") == 0)
         {  paddingValue = ParseCSSLengthValue(prop->value,&num);
            if(num.type == NUMBER_NUMBER && paddingValue >= 0)
            {  /* Apply padding to left and top margins */
               Asetattrs(body,AOBDY_Leftmargin,paddingValue,TAG_END);
               Asetattrs(body,AOBDY_Topmargin,paddingValue,TAG_END);
            }
         }
         /* Apply background-color */
         else if(stricmp((char *)prop->name,"background-color") == 0)
         {  /* Parse hex color */
            colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  /* Use Finddoccolor from docprivate.h */
               ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  Asetattrs(body,AOBDY_Bgcolor,COLOR(ci),TAG_END);
               }
            }
         }
         /* Apply background-image */
         else if(stricmp((char *)prop->name,"background-image") == 0)
         {  UBYTE *urlValue;
            UBYTE *url;
            void *bgimg;
            /* Parse url(...) format */
            urlValue = prop->value;
            /* Skip whitespace */
            while(*urlValue && isspace(*urlValue)) urlValue++;
            /* Check for url( */
            if(strnicmp((char *)urlValue,"url(",4) == 0)
            {  UBYTE *start;
               UBYTE *end;
               long len;
               start = urlValue + 4;
               /* Skip whitespace after url( */
               while(*start && isspace(*start)) start++;
               /* Find closing ) */
               end = (UBYTE *)strchr((char *)start,')');
               if(end && end > start)
               {  /* Trim quotes if present */
                  if((*start == '"' || *start == '\'') && end > start + 1)
                  {  start++;
                     if(*(end - 1) == '"' || *(end - 1) == '\'')
                     {  end--;
                     }
                  }
                  len = end - start;
                  if(len > 0)
                  {  url = ALLOCTYPE(UBYTE,len + 1,0);
                     if(url)
                     {  memmove(url,start,len);
                        url[len] = '\0';
                        bgimg = Backgroundimg(doc,url);
                        if(bgimg)
                        {  Asetattrs(body,AOBDY_Bgimage,bgimg,TAG_END);
                        }
                        FREE(url);
                     }
                  }
               }
            }
         }
         /* Apply border - parse width, style, and color from "2px solid #color" or "2px" format */
         else if(stricmp((char *)prop->name,"border") == 0)
         {  /* Parse border shorthand: width style color */
            UBYTE *pval;
            UBYTE *token;
            long borderWidth;
            struct Number num;
            ULONG borderColor;
            
            pval = prop->value;
            borderWidth = -1;
            borderColor = ~0;
            
            /* Parse tokens separated by spaces */
            while(*pval)
            {  SkipWhitespace(&pval);
               if(!*pval) break;
               
               token = pval;
               while(*pval && !isspace(*pval)) pval++;
               
               /* Check if it's a width (starts with digit or has px/em/etc) */
               if(isdigit(*token) || *token == '+' || *token == '-')
               {  UBYTE *end;
                  long len;
                  len = pval - token;
                  end = token + len;
                  if(borderWidth < 0)
                  {  borderWidth = ParseCSSLengthValue(token,&num);
                  }
               }
               /* Check if it's a color (starts with #) */
               else if(*token == '#')
               {  borderColor = ParseHexColor(token);
               }
               /* Otherwise it's probably a style (solid, dashed, dotted, etc.) */
               /* We parse but don't store style yet as rendering isn't implemented */
            }
            
            /* Note: Full border rendering not yet implemented, but we parse it */
         }
         /* Apply border-style */
         else if(stricmp((char *)prop->name,"border-style") == 0)
         {  /* Parse border style: solid, dashed, dotted, double, groove, ridge, inset, outset, none */
            /* We parse but don't store yet as rendering isn't fully implemented */
            /* Values: solid, dashed, dotted, double, groove, ridge, inset, outset, none */
         }
         /* Apply border-color */
         else if(stricmp((char *)prop->name,"border-color") == 0)
         {  ULONG colorrgb;
            struct Colorinfo *ci;
            colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  /* For tables, apply to bordercolor */
                  /* For other elements, we'd need to store it for future rendering */
                  /* For now, we only apply to table cells via ApplyCSSToTableCell */
               }
            }
         }
         /* Apply border-radius (CSS3 - not implemented, but parse to avoid errors) */
         else if(stricmp((char *)prop->name,"border-radius") == 0)
         {  /* CSS3 feature - not implemented */
         }
         /* Apply text-align */
         else if(stricmp((char *)prop->name,"text-align") == 0)
         {  if(stricmp((char *)prop->value,"center") == 0)
            {  align = HALIGN_CENTER;
            }
            else if(stricmp((char *)prop->value,"left") == 0)
            {  align = HALIGN_LEFT;
            }
            else if(stricmp((char *)prop->value,"right") == 0)
            {  align = HALIGN_RIGHT;
            }
            else
            {  align = -1;
            }
            if(align >= 0)
            {  /* Apply text-align to various elements that support align attribute */
               if(tagname && stricmp((char *)tagname,"DIV") == 0)
               {  Asetattrs(body,AOBDY_Divalign,align,TAG_END);
               }
               else if(tagname && stricmp((char *)tagname,"P") == 0)
               {  Asetattrs(body,AOBDY_Align,align,TAG_END);
               }
               else if(tagname && (stricmp((char *)tagname,"TD") == 0 || stricmp((char *)tagname,"TH") == 0))
               {  /* For table cells, alignment is handled via table attributes in ApplyCSSToTableCell */
                  /* But we can also set it on the body */
                  Asetattrs(body,AOBDY_Divalign,align,TAG_END);
               }
               else
               {  /* Default: apply to div align for other block elements */
                  Asetattrs(body,AOBDY_Divalign,align,TAG_END);
               }
            }
         }
         /* Apply font-style */
         else if(stricmp((char *)prop->name,"font-style") == 0)
         {  if(stricmp((char *)prop->value,"italic") == 0)
            {  Asetattrs(body,AOBDY_Sethardstyle,FSF_ITALIC,TAG_END);
            }
            else if(stricmp((char *)prop->value,"normal") == 0)
            {  Asetattrs(body,AOBDY_Unsethardstyle,FSF_ITALIC,TAG_END);
            }
         }
         /* Apply font-weight */
         else if(stricmp((char *)prop->name,"font-weight") == 0)
         {  if(stricmp((char *)prop->value,"bold") == 0 || stricmp((char *)prop->value,"700") == 0 || stricmp((char *)prop->value,"bolder") == 0)
            {  Asetattrs(body,AOBDY_Sethardstyle,FSF_BOLD,TAG_END);
            }
            else if(stricmp((char *)prop->value,"normal") == 0 || stricmp((char *)prop->value,"400") == 0 || stricmp((char *)prop->value,"lighter") == 0)
            {  Asetattrs(body,AOBDY_Unsethardstyle,FSF_BOLD,TAG_END);
            }
            /* Also support numeric values 100-900 */
            else
            {  long weightValue;
               weightValue = ParseCSSLengthValue(prop->value,&num);
               if(weightValue >= 600)
               {  Asetattrs(body,AOBDY_Sethardstyle,FSF_BOLD,TAG_END);
               }
               else if(weightValue >= 0 && weightValue < 600)
               {  Asetattrs(body,AOBDY_Unsethardstyle,FSF_BOLD,TAG_END);
               }
            }
         }
         /* Apply text-decoration */
         else if(stricmp((char *)prop->name,"text-decoration") == 0)
         {  /* text-decoration can have multiple values like "underline line-through" */
            UBYTE *decValue;
            UBYTE *pdec;
            decValue = Dupstr(prop->value,-1);
            if(decValue)
            {  pdec = decValue;
               while(*pdec)
               {  SkipWhitespace(&pdec);
                  if(!*pdec) break;
                  if(stricmp((char *)pdec,"line-through") == 0 || stricmp((char *)pdec,"strikethrough") == 0)
                  {  Asetattrs(body,AOBDY_Sethardstyle,FSF_STRIKE,TAG_END);
                  }
                  else if(stricmp((char *)pdec,"none") == 0)
                  {  /* Remove all text decorations */
                     Asetattrs(body,AOBDY_Unsethardstyle,FSF_STRIKE,TAG_END);
                  }
                  /* Skip to next space or end */
                  while(*pdec && !isspace(*pdec)) pdec++;
               }
               FREE(decValue);
            }
         }
         /* Apply white-space */
         else if(stricmp((char *)prop->name,"white-space") == 0)
         {  if(stricmp((char *)prop->value,"nowrap") == 0)
            {  Asetattrs(body,AOBDY_Nobr,TRUE,TAG_END);
            }
            else if(stricmp((char *)prop->value,"normal") == 0 || stricmp((char *)prop->value,"pre-wrap") == 0 || stricmp((char *)prop->value,"pre-line") == 0)
            {  Asetattrs(body,AOBDY_Nobr,FALSE,TAG_END);
            }
            /* Note: "pre" is handled by STYLE_PRE, not white-space */
         }
         /* Apply text-transform */
         else if(stricmp((char *)prop->name,"text-transform") == 0)
         {  if(stricmp((char *)prop->value,"uppercase") == 0)
            {  doc->texttransform = 1;
            }
            else if(stricmp((char *)prop->value,"lowercase") == 0)
            {  doc->texttransform = 2;
            }
            else if(stricmp((char *)prop->value,"capitalize") == 0)
            {  doc->texttransform = 3;
            }
            else if(stricmp((char *)prop->value,"none") == 0)
            {  doc->texttransform = 0;
            }
         }
         /* Apply font-family */
         else if(stricmp((char *)prop->name,"font-family") == 0)
         {  fontFace = NULL;
            comma = (UBYTE *)strchr((char *)prop->value,',');
            if(comma)
            {  long len = comma - prop->value;
               fontFace = ALLOCTYPE(UBYTE,len + 1,0);
               if(fontFace)
               {  memmove(fontFace,prop->value,len);
                  fontFace[len] = '\0';
                  while(len > 0 && isspace(fontFace[len - 1]))
                  {  fontFace[--len] = '\0';
                  }
               }
            }
            else
            {  fontFace = Dupstr(prop->value,-1);
            }
            if(fontFace)
            {  Asetattrs(body,AOBDY_Fontface,fontFace,TAG_END);
               FREE(fontFace);
            }
         }
         /* Apply font-size */
         else if(stricmp((char *)prop->name,"font-size") == 0)
         {  fontSize = 0;
            isRelative = FALSE;
            if(stricmp((char *)prop->value,"xx-small") == 0)
            {  fontSize = 1;
            }
            else if(stricmp((char *)prop->value,"x-small") == 0)
            {  fontSize = 2;
            }
            else if(stricmp((char *)prop->value,"small") == 0)
            {  fontSize = 3;
            }
            else if(stricmp((char *)prop->value,"medium") == 0)
            {  fontSize = 4;
            }
            else if(stricmp((char *)prop->value,"large") == 0)
            {  fontSize = 5;
            }
            else if(stricmp((char *)prop->value,"x-large") == 0)
            {  fontSize = 6;
            }
            else if(stricmp((char *)prop->value,"xx-large") == 0)
            {  fontSize = 7;
            }
            else if(stricmp((char *)prop->value,"smaller") == 0)
            {  fontSize = -1;
               isRelative = TRUE;
            }
            else if(stricmp((char *)prop->value,"larger") == 0)
            {  fontSize = 1;
               isRelative = TRUE;
            }
            if(fontSize != 0)
            {  if(isRelative)
               {  Asetattrs(body,AOBDY_Fontsizerel,fontSize,TAG_END);
               }
               else
               {  Asetattrs(body,AOBDY_Fontsize,fontSize,TAG_END);
               }
            }
         }
         /* Apply color */
         else if(stricmp((char *)prop->name,"color") == 0)
         {  colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  Asetattrs(body,AOBDY_Fontcolor,ci,TAG_END);
               }
            }
         }
         /* Apply margin shorthand */
         else if(stricmp((char *)prop->name,"margin") == 0)
         {  UBYTE *marginP;
            UBYTE *tokenStart;
            UBYTE *tokenEnd;
            long tokenLen;
            UBYTE *tokenBuf;
            marginValue = prop->value;
            marginCount = 0;
            marginTop = marginRight = marginBottom = marginLeft = 0;
            
            /* Parse margin values - can be 1, 2, 3, or 4 values */
            marginP = marginValue;
            for(i = 0; i < 4 && marginP && *marginP; i++)
            {  /* Skip whitespace */
               while(*marginP && isspace(*marginP)) marginP++;
               if(!*marginP) break;
               tokenStart = marginP;
               /* Find end of token */
               while(*marginP && !isspace(*marginP)) marginP++;
               tokenEnd = marginP;
               tokenLen = tokenEnd - tokenStart;
               if(tokenLen > 0)
               {  /* Copy token to temporary buffer */
                  tokenBuf = ALLOCTYPE(UBYTE,tokenLen + 1,0);
                  if(tokenBuf)
                  {  memmove(tokenBuf,tokenStart,tokenLen);
                     tokenBuf[tokenLen] = '\0';
                     marginTokens[marginCount] = tokenBuf;
                     marginCount++;
                  }
               }
            }
            
            /* Apply margin values based on count */
            if(marginCount >= 1)
            {  marginTop = ParseCSSLengthValue(marginTokens[0],&num);
               if(marginCount == 1)
               {  /* All sides same */
                  marginRight = marginBottom = marginLeft = marginTop;
               }
               else if(marginCount == 2)
               {  /* Top/bottom, left/right */
                  marginBottom = marginTop;
                  marginRight = ParseCSSLengthValue(marginTokens[1],&num);
                  marginLeft = marginRight;
               }
               else if(marginCount == 3)
               {  /* Top, left/right, bottom */
                  marginRight = ParseCSSLengthValue(marginTokens[1],&num);
                  marginLeft = marginRight;
                  marginBottom = ParseCSSLengthValue(marginTokens[2],&num);
               }
               else if(marginCount == 4)
               {  /* Top, right, bottom, left */
                  marginRight = ParseCSSLengthValue(marginTokens[1],&num);
                  marginBottom = ParseCSSLengthValue(marginTokens[2],&num);
                  marginLeft = ParseCSSLengthValue(marginTokens[3],&num);
               }
               
               /* Apply margins */
               if(marginTop >= 0) Asetattrs(body,AOBDY_Topmargin,marginTop,TAG_END);
               if(marginLeft >= 0) Asetattrs(body,AOBDY_Leftmargin,marginLeft,TAG_END);
               /* Note: margin-right and margin-bottom are not directly supported
                * by AWeb's body attributes, but we parse them for future use */
            }
            
            /* Free temporary token buffers */
            for(i = 0; i < marginCount; i++)
            {  if(marginTokens[i]) FREE(marginTokens[i]);
            }
         }
         /* Apply line-height */
         else if(stricmp((char *)prop->name,"line-height") == 0)
         {  lineHeightStr = prop->value;
            /* Skip whitespace */
            while(*lineHeightStr && isspace(*lineHeightStr)) lineHeightStr++;
            /* Parse unitless value (e.g., 1.42857143) or pixel value (e.g., 20px) */
            if(sscanf((char *)lineHeightStr,"%f",&lineHeightValue) == 1)
            {  /* Store line-height in document for potential future use */
               doc->lineheight = lineHeightValue;
               /* Note: AWeb's layout engine doesn't directly support line-height,
                * but we parse and store it for potential future implementation */
            }
         }
         /* Apply display */
         else if(stricmp((char *)prop->name,"display") == 0)
         {  displayValue = prop->value;
            /* Skip whitespace */
            while(*displayValue && isspace(*displayValue)) displayValue++;
            /* Parse display values */
            if(stricmp((char *)displayValue,"none") == 0)
            {  /* Hide element - not directly supported, but parsed */
               /* Note: Would require element visibility control */
            }
            else if(stricmp((char *)displayValue,"inline") == 0)
            {  /* Inline display - default for many elements */
               /* Note: AWeb handles this automatically based on element type */
            }
            else if(stricmp((char *)displayValue,"block") == 0)
            {  /* Block display - default for div, p, etc. */
               /* Note: AWeb handles this automatically based on element type */
            }
            else if(stricmp((char *)displayValue,"grid") == 0)
            {  /* CSS Grid - not yet implemented */
               /* Note: CSS Grid requires major architectural changes */
            }
            /* Other display values (flex, table, etc.) not yet supported */
         }
         /* Apply grid-column-start (for grid layout positioning) */
         else if(stricmp((char *)prop->name,"grid-column-start") == 0)
         {  long gridColStart;
            long leftMargin;
            UBYTE *pval;
            
            /* Parse grid-column-start value - can be a number (e.g., "2") or a length */
            pval = prop->value;
            SkipWhitespace(&pval);
            if(isdigit(*pval))
            {  /* Parse as integer */
               gridColStart = strtol((char *)pval,NULL,10);
            }
            else
            {  /* Try parsing as length value */
               struct Number num;
               gridColStart = ParseCSSLengthValue(prop->value,&num);
               /* If it's a length, convert to column number (approximate) */
               if(gridColStart > 0)
               {  /* Assume each column is at least 100px wide */
                  gridColStart = (gridColStart / 100) + 1;
               }
            }
            
            if(gridColStart >= 2)
            {  /* For grid-column-start >= 2, apply left margin to push to second column */
               /* Use column gap from parent dl element if available */
               if(doc->gridcolgap > 0)
               {  leftMargin = doc->gridcolgap;
               }
               else
               {  /* Default column gap if not specified */
                  leftMargin = 16;
               }
               Asetattrs(body,AOBDY_Leftmargin,leftMargin,TAG_END);
            }
         }
         /* Apply grid-column-end (for grid layout positioning) */
         else if(stricmp((char *)prop->name,"grid-column-end") == 0)
         {  /* Parse but not fully implemented */
         }
         /* Apply grid-row-start (for grid layout positioning) */
         else if(stricmp((char *)prop->name,"grid-row-start") == 0)
         {  /* Parse but not fully implemented */
         }
         /* Apply grid-row-end (for grid layout positioning) */
         else if(stricmp((char *)prop->name,"grid-row-end") == 0)
         {  /* Parse but not fully implemented */
         }
         /* Note: width, height, and vertical-align for table cells are handled
          * separately in ApplyCSSToTableCell() */
         
         /* Free the property */
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
}

/* Parse CSS length value (pixels, percentages, etc.) */
long ParseCSSLengthValue(UBYTE *value,struct Number *num)
{  UBYTE *pval;
   char c = '\0';
   short m;
   BOOL sign = FALSE;
   
   if(!value || !num) return 0;
   
   num->n = 0;
   num->type = NUMBER_NONE;
   
   pval = value;
   while(*pval && isspace(*pval)) pval++;
   
   sign = (*pval == '+' || *pval == '-');
   if(*pval == '*')
   {  num->n = 1;
      c = '*';
      m = 1;
   }
   else
   {  m = sscanf((char *)pval," %ld%c",&num->n,&c);
   }
   if(m)
   {  if(c == '%') num->type = NUMBER_PERCENT;
      else if(c == '*') num->type = NUMBER_RELATIVE;
      else if(sign) num->type = NUMBER_SIGNED;
      else num->type = NUMBER_NUMBER;
   }
   if(num->type != NUMBER_SIGNED && num->n < 0) num->n = 0;
   
   return num->n;
}

/* Parse hex color value */
ULONG ParseHexColor(UBYTE *pcolor)
{  ULONG rgbval = ~0;
   ULONG rgb = 0;
   long len;
   UBYTE *start;
   UBYTE *p;
   
   if(!pcolor) return ~0;
   
   p = pcolor;
   /* Skip whitespace */
   while(*p && isspace(*p)) p++;
   if(!*p) return ~0;
   
   /* Check for # */
   if(*p == '#') p++;
   
   /* Parse hex digits */
   start = p;
   len = 0;
   while(*p && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
   {  p++;
      len++;
   }
   
   if(len == 3)
   {  /* Short format: #RGB -> #RRGGBB */
      rgb = 0;
      if(start[0] >= '0' && start[0] <= '9') rgb |= (start[0] - '0') << 20;
      else if(start[0] >= 'a' && start[0] <= 'f') rgb |= (start[0] - 'a' + 10) << 20;
      else if(start[0] >= 'A' && start[0] <= 'F') rgb |= (start[0] - 'A' + 10) << 20;
      if(start[1] >= '0' && start[1] <= '9') rgb |= (start[1] - '0') << 12;
      else if(start[1] >= 'a' && start[1] <= 'f') rgb |= (start[1] - 'a' + 10) << 12;
      else if(start[1] >= 'A' && start[1] <= 'F') rgb |= (start[1] - 'A' + 10) << 12;
      if(start[2] >= '0' && start[2] <= '9') rgb |= (start[2] - '0') << 4;
      else if(start[2] >= 'a' && start[2] <= 'f') rgb |= (start[2] - 'a' + 10) << 4;
      else if(start[2] >= 'A' && start[2] <= 'F') rgb |= (start[2] - 'A' + 10) << 4;
      /* Expand to full format */
      rgb = (rgb & 0xf00) << 8 | (rgb & 0x0f0) << 4 | (rgb & 0x00f);
      rgb = rgb << 16 | rgb << 8 | rgb;
      rgbval = rgb;
   }
   else if(len == 6)
   {  /* Full format: #RRGGBB */
      rgb = 0;
      if(start[0] >= '0' && start[0] <= '9') rgb |= (start[0] - '0') << 20;
      else if(start[0] >= 'a' && start[0] <= 'f') rgb |= (start[0] - 'a' + 10) << 20;
      else if(start[0] >= 'A' && start[0] <= 'F') rgb |= (start[0] - 'A' + 10) << 20;
      if(start[1] >= '0' && start[1] <= '9') rgb |= (start[1] - '0') << 16;
      else if(start[1] >= 'a' && start[1] <= 'f') rgb |= (start[1] - 'a' + 10) << 16;
      else if(start[1] >= 'A' && start[1] <= 'F') rgb |= (start[1] - 'A' + 10) << 16;
      if(start[2] >= '0' && start[2] <= '9') rgb |= (start[2] - '0') << 12;
      else if(start[2] >= 'a' && start[2] <= 'f') rgb |= (start[2] - 'a' + 10) << 12;
      else if(start[2] >= 'A' && start[2] <= 'F') rgb |= (start[2] - 'A' + 10) << 12;
      if(start[3] >= '0' && start[3] <= '9') rgb |= (start[3] - '0') << 8;
      else if(start[3] >= 'a' && start[3] <= 'f') rgb |= (start[3] - 'a' + 10) << 8;
      else if(start[3] >= 'A' && start[3] <= 'F') rgb |= (start[3] - 'A' + 10) << 8;
      if(start[4] >= '0' && start[4] <= '9') rgb |= (start[4] - '0') << 4;
      else if(start[4] >= 'a' && start[4] <= 'f') rgb |= (start[4] - 'a' + 10) << 4;
      else if(start[4] >= 'A' && start[4] <= 'F') rgb |= (start[4] - 'A' + 10) << 4;
      if(start[5] >= '0' && start[5] <= '9') rgb |= (start[5] - '0');
      else if(start[5] >= 'a' && start[5] <= 'f') rgb |= (start[5] - 'a' + 10);
      else if(start[5] >= 'A' && start[5] <= 'F') rgb |= (start[5] - 'A' + 10);
      rgbval = rgb;
   }
   
   /* If hex parsing failed, try color name lookup */
   if(rgbval == ~0)
   {  UBYTE buf[32];
      UBYTE *q;
      long bufLen;
      short a = 0;
      short b = NR_COLORNAMES - 1;
      short mid;
      long c;
      
      /* Copy color name to buffer, removing whitespace */
      q = pcolor;
      bufLen = 0;
      while(*q && bufLen < 31 && !isspace(*q))
      {  buf[bufLen++] = *q++;
      }
      buf[bufLen] = '\0';
      
      /* Binary search for color name */
      while(a <= b)
      {  mid = (a + b) / 2;
         c = stricmp((char *)colornames[mid].name, (char *)buf);
         if(c == 0)
         {  rgbval = colornames[mid].color;
            break;
         }
         if(c < 0) a = mid + 1;
         else b = mid - 1;
      }
   }
   
   return rgbval;
}

/* Parse and apply inline CSS to a Link object */
void ApplyInlineCSSToLink(struct Document *doc,void *link,void *body,UBYTE *style)
{  struct CSSProperty *prop;
   UBYTE *p;
   ULONG colorrgb;
   struct Colorinfo *ci;
   
   if(!doc || !link || !style) return;
   
   p = style;
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {  /* Apply text-decoration: none */
         if(stricmp((char *)prop->name,"text-decoration") == 0)
         {  if(stricmp((char *)prop->value,"none") == 0)
            {  Asetattrs(link,AOLNK_NoDecoration,TRUE,TAG_END);
            }
         }
         /* Apply color - apply to body's font color */
         else if(stricmp((char *)prop->name,"color") == 0)
         {  colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci && body)
               {  Asetattrs(body,AOBDY_Fontcolor,ci,TAG_END);
               }
            }
         }
      }
      
      /* Free the property */
      if(prop)
      {  if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      
      /* Skip to next semicolon on parse error */
      if(!prop)
      {  while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
}

/* Apply CSS from stylesheet to document link colors (a:link, a:visited) */
void ApplyCSSToLinkColors(struct Document *doc)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct CSSStylesheet *sheet;
   BOOL matches;
   ULONG colorrgb;
   struct Colorinfo *ci;
   BOOL linkColorSet = FALSE;
   BOOL visitedColorSet = FALSE;
   
   if(!doc || !doc->cssstylesheet) return;
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   
   /* Find a:link and a:visited rules to set document link colors */
   /* Process :link and :visited FIRST, then fall back to 'a' without pseudo-class */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  matches = TRUE;
         
         /* Match element name - must be 'a' */
         if(sel->type & CSS_SEL_ELEMENT && sel->name)
         {  if(stricmp((char *)sel->name,"a") != 0)
            {  matches = FALSE;
            }
         }
         
         /* Match pseudo-class - :link and :visited take priority */
         if(matches && (sel->type & CSS_SEL_PSEUDO) && sel->pseudo)
         {  if(stricmp((char *)sel->pseudo,"link") == 0)
            {  /* Apply a:link color to doc->linkcolor */
               for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
                   (struct MinNode *)prop->node.mln_Succ;
                   prop = (struct CSSProperty *)prop->node.mln_Succ)
               {  if(prop->name && prop->value && stricmp((char *)prop->name,"color") == 0)
                  {  colorrgb = ParseHexColor(prop->value);
                     /* debug_printf("CSS: Parsing a:link color='%s', rgb=0x%08lx\n",
                                  prop->value ? (char *)prop->value : "NULL", colorrgb); */
                     if(colorrgb != ~0)
                     {  ci = Finddoccolor(doc,colorrgb);
                        if(ci)
                        {  doc->linkcolor = ci;
                           linkColorSet = TRUE;
                           /* debug_printf("CSS: Set doc->linkcolor from a:link (color=0x%08lx)\n", colorrgb); */
                        }
                        else
                        {  /* debug_printf("CSS: Failed to find/create color for a:link (rgb=0x%08lx)\n", colorrgb); */
                        }
                     }
                     else
                     {  /* debug_printf("CSS: Failed to parse a:link color='%s'\n",
                                      prop->value ? (char *)prop->value : "NULL"); */
                     }
                  }
               }
            }
            else if(stricmp((char *)sel->pseudo,"visited") == 0)
            {  /* Apply a:visited color to doc->vlinkcolor */
               for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
                   (struct MinNode *)prop->node.mln_Succ;
                   prop = (struct CSSProperty *)prop->node.mln_Succ)
               {  if(prop->name && prop->value && stricmp((char *)prop->name,"color") == 0)
                  {  colorrgb = ParseHexColor(prop->value);
                     if(colorrgb != ~0)
                     {  ci = Finddoccolor(doc,colorrgb);
                        if(ci)
                        {  doc->vlinkcolor = ci;
                           visitedColorSet = TRUE;
                           /* debug_printf("CSS: Set doc->vlinkcolor from a:visited\n"); */
                        }
                     }
                  }
               }
            }
         }
      }
   }
   
   /* Second pass: Handle 'a' without pseudo-class as fallback default link color */
   if(!linkColorSet)
   {  for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
          (struct MinNode *)rule->node.mln_Succ;
          rule = (struct CSSRule *)rule->node.mln_Succ)
      {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
            (struct MinNode *)sel->node.mln_Succ;
            sel = (struct CSSSelector *)sel->node.mln_Succ)
         {  matches = TRUE;
            
            /* Match element name - must be 'a' */
            if(sel->type & CSS_SEL_ELEMENT && sel->name)
            {  if(stricmp((char *)sel->name,"a") != 0)
               {  matches = FALSE;
               }
            }
            
            /* Must NOT have pseudo-class */
            if(matches && ((sel->type & CSS_SEL_PSEUDO) && sel->pseudo))
            {  matches = FALSE;
            }
            
            /* Apply 'a' without pseudo-class as default link color */
            if(matches)
            {  for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
                   (struct MinNode *)prop->node.mln_Succ;
                   prop = (struct CSSProperty *)prop->node.mln_Succ)
               {  if(prop->name && prop->value && stricmp((char *)prop->name,"color") == 0)
                  {  colorrgb = ParseHexColor(prop->value);
                     if(colorrgb != ~0)
                     {  ci = Finddoccolor(doc,colorrgb);
                        if(ci)
                        {  doc->linkcolor = ci;
                           linkColorSet = TRUE;
                           /* debug_printf("CSS: Set doc->linkcolor from 'a' (default fallback)\n"); */
                           break;
                        }
                     }
                  }
               }
            }
         }
      }
   }
   
   /* Register colors if they were set */
   if(linkColorSet || visitedColorSet)
   {  /* debug_printf("CSS: Link colors set - linkColorSet=%d visitedColorSet=%d frame=%p\n",
                   linkColorSet, visitedColorSet, doc->frame); */
      if(doc->frame)
      {  Registerdoccolors(doc);
         /* debug_printf("CSS: Registered link colors with frame\n"); */
      }
      else
      {  /* debug_printf("CSS: Frame not ready yet, colors will be registered when frame is created\n"); */
      }
   }
}

/* Apply CSS from stylesheet to a Link object with pseudo-class matching */
void ApplyCSSToLink(struct Document *doc,void *link,void *body)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct CSSStylesheet *sheet;
   BOOL matches;
   BOOL isVisited;
   
   if(!doc || !link || !doc->cssstylesheet)
   {  /* debug_printf("CSS: ApplyCSSToLink skipped - doc=%p link=%p stylesheet=%p\n",
                   doc, link, (doc ? doc->cssstylesheet : NULL)); */
      return;
   }
   
   /* debug_printf("CSS: ApplyCSSToLink called\n"); */
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   isVisited = (BOOL)Agetattr(link,AOLNK_Visited);
   
   /* Find matching rules for 'a' element with pseudo-classes */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  matches = TRUE;
         
         /* Match element name - must be 'a' */
         if(sel->type & CSS_SEL_ELEMENT && sel->name)
         {  if(stricmp((char *)sel->name,"a") != 0)
            {  matches = FALSE;
            }
         }
         
         /* Match pseudo-class */
         if(matches && (sel->type & CSS_SEL_PSEUDO) && sel->pseudo)
         {  if(stricmp((char *)sel->pseudo,"link") == 0)
            {  if(isVisited) matches = FALSE;
            }
            else if(stricmp((char *)sel->pseudo,"visited") == 0)
            {  if(!isVisited) matches = FALSE;
            }
            else if(stricmp((char *)sel->pseudo,"hover") == 0)
            {  /* Hover state - not yet implemented, skip for now */
               matches = FALSE;
            }
         }
         
         /* Apply properties if selector matches */
         if(matches)
         {  /* debug_printf("CSS: Link selector matched! Element=%s pseudo=%s\n",
                         (sel->name ? (char *)sel->name : "any"),
                         (sel->pseudo ? (char *)sel->pseudo : "none")); */
            for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
               (struct MinNode *)prop->node.mln_Succ;
               prop = (struct CSSProperty *)prop->node.mln_Succ)
            {  if(prop->name && prop->value)
               {                    /* Apply text-decoration: none */
                  if(stricmp((char *)prop->name,"text-decoration") == 0)
                  {  /* debug_printf("CSS: Link property text-decoration=%s\n",prop->value); */
                     if(stricmp((char *)prop->value,"none") == 0)
                     {  /* debug_printf("CSS: Setting link NoDecoration=TRUE\n"); */
                        Asetattrs(link,AOLNK_NoDecoration,TRUE,TAG_END);
                     }
                  }
                  /* Note: font-family is inherited from parent elements, not set on links */
                  /* Note: color is handled by ApplyCSSToLinkColors for document-level colors */
               }
            }
         }
      }
   }
}

/* Extract background-color from a style string and return Colorinfo */
struct Colorinfo *ExtractBackgroundColorFromStyle(struct Document *doc,UBYTE *style)
{  struct CSSProperty *prop;
   UBYTE *p;
   ULONG colorrgb;
   struct Colorinfo *ci;
   
   if(!doc || !style) return NULL;
   
   ci = NULL;
   p = style;
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {  if(stricmp((char *)prop->name,"background-color") == 0)
         {  colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
            }
         }
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
   
   return ci;
}

/* Apply CSS properties specific to table cells (width, height, vertical-align) */
void ApplyCSSToTableCell(struct Document *doc,void *table,UBYTE *style)
{  struct CSSProperty *prop;
   struct Number num;
   UBYTE *p;
   long widthValue;
   long heightValue;
   short valign;
   ULONG wtag;
   ULONG htag;
   
   if(!doc || !table || !style) return;
   
   p = style;
   wtag = TAG_IGNORE;
   htag = TAG_IGNORE;
   widthValue = -1;
   heightValue = -1;
   valign = -1;
   
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {  /* Extract width */
         if(stricmp((char *)prop->name,"width") == 0)
         {  widthValue = ParseCSSLengthValue(prop->value,&num);
            if(widthValue >= 0 && num.type != NUMBER_NONE)
            {  if(num.type == NUMBER_PERCENT)
               {  wtag = AOTAB_Percentwidth;
               }
               else
               {  wtag = AOTAB_Pixelwidth;
               }
            }
         }
         /* Extract height */
         else if(stricmp((char *)prop->name,"height") == 0)
         {  heightValue = ParseCSSLengthValue(prop->value,&num);
            if(heightValue >= 0 && num.type != NUMBER_NONE)
            {  if(num.type == NUMBER_PERCENT)
               {  htag = AOTAB_Percentheight;
               }
               else
               {  htag = AOTAB_Pixelheight;
               }
            }
         }
         /* Extract vertical-align */
         else if(stricmp((char *)prop->name,"vertical-align") == 0)
         {  if(stricmp((char *)prop->value,"top") == 0)
            {  valign = VALIGN_TOP;
            }
            else if(stricmp((char *)prop->value,"middle") == 0)
            {  valign = VALIGN_MIDDLE;
            }
            else if(stricmp((char *)prop->value,"bottom") == 0)
            {  valign = VALIGN_BOTTOM;
            }
            else if(stricmp((char *)prop->value,"baseline") == 0)
            {  valign = VALIGN_BASELINE;
            }
         }
         /* Extract text-align for horizontal alignment */
         else if(stricmp((char *)prop->name,"text-align") == 0)
         {  short halign;
            halign = -1;
            if(stricmp((char *)prop->value,"center") == 0)
            {  halign = HALIGN_CENTER;
            }
            else if(stricmp((char *)prop->value,"left") == 0)
            {  halign = HALIGN_LEFT;
            }
            else if(stricmp((char *)prop->value,"right") == 0)
            {  halign = HALIGN_RIGHT;
            }
            if(halign >= 0)
            {  Asetattrs(table,AOTAB_Halign,halign,TAG_END);
            }
         }
         
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
   
   /* Apply extracted values to table cell */
   /* CSS should override HTML attributes, so always apply if found */
   if(wtag != TAG_IGNORE)
   {  if(widthValue > 0)
      {  Asetattrs(table,wtag,widthValue,TAG_END);
      }
      else if(widthValue == 0)
      {  /* Explicit 0 width - clear width */
         Asetattrs(table,AOTAB_Pixelwidth,0,TAG_END);
      }
   }
   if(htag != TAG_IGNORE)
   {  if(heightValue > 0)
      {  Asetattrs(table,htag,heightValue,TAG_END);
      }
      else if(heightValue == 0)
      {  /* Explicit 0 height - clear height */
         Asetattrs(table,AOTAB_Pixelheight,0,TAG_END);
      }
   }
   if(valign >= 0)
   {  Asetattrs(table,AOTAB_Valign,valign,TAG_END);
   }
}

/* Apply CSS properties to an image (IMG tag) */
void ApplyCSSToImage(struct Document *doc,void *copy,UBYTE *style)
{  struct CSSProperty *prop;
   struct Number num;
   UBYTE *p;
   long borderValue;
   long widthValue;
   long heightValue;
   long hspaceValue;
   long vspaceValue;
   ULONG wtag;
   ULONG htag;
   
   if(!doc || !copy || !style) return;
   
   p = style;
   wtag = TAG_IGNORE;
   htag = TAG_IGNORE;
   borderValue = -1;
   widthValue = -1;
   heightValue = -1;
   hspaceValue = -1;
   vspaceValue = -1;
   
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {  /* Extract border */
         if(stricmp((char *)prop->name,"border") == 0)
         {  borderValue = ParseCSSLengthValue(prop->value,&num);
            if(borderValue < 0) borderValue = 0;
         }
         /* Extract width */
         else if(stricmp((char *)prop->name,"width") == 0)
         {  widthValue = ParseCSSLengthValue(prop->value,&num);
            if(widthValue > 0)
            {  if(num.type == NUMBER_PERCENT)
               {  wtag = AOCPY_Percentwidth;
               }
               else
               {  wtag = AOCPY_Width;
               }
            }
         }
         /* Extract height */
         else if(stricmp((char *)prop->name,"height") == 0)
         {  heightValue = ParseCSSLengthValue(prop->value,&num);
            if(heightValue > 0)
            {  if(num.type == NUMBER_PERCENT)
               {  htag = AOCPY_Percentheight;
               }
               else
               {  htag = AOCPY_Height;
               }
            }
         }
         /* Extract hspace via margin-left and margin-right */
         else if(stricmp((char *)prop->name,"margin-left") == 0 || stricmp((char *)prop->name,"margin-right") == 0)
         {  long marginValue;
            marginValue = ParseCSSLengthValue(prop->value,&num);
            if(marginValue > 0 && num.type == NUMBER_NUMBER)
            {  if(hspaceValue < 0) hspaceValue = marginValue;
               else hspaceValue = (hspaceValue + marginValue) / 2; /* Average if both set */
            }
         }
         /* Extract vspace via margin-top and margin-bottom */
         else if(stricmp((char *)prop->name,"margin-top") == 0 || stricmp((char *)prop->name,"margin-bottom") == 0)
         {  long marginValue;
            marginValue = ParseCSSLengthValue(prop->value,&num);
            if(marginValue > 0 && num.type == NUMBER_NUMBER)
            {  if(vspaceValue < 0) vspaceValue = marginValue;
               else vspaceValue = (vspaceValue + marginValue) / 2; /* Average if both set */
            }
         }
         
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
   
   /* Apply extracted values to image */
   if(borderValue >= 0)
   {  Asetattrs(copy,AOCPY_Border,borderValue,TAG_END);
   }
   if(wtag != TAG_IGNORE && widthValue > 0)
   {  Asetattrs(copy,wtag,widthValue,TAG_END);
   }
   if(htag != TAG_IGNORE && heightValue > 0)
   {  Asetattrs(copy,htag,heightValue,TAG_END);
   }
   if(hspaceValue >= 0)
   {  Asetattrs(copy,AOCPY_Hspace,hspaceValue,TAG_END);
   }
   if(vspaceValue >= 0)
   {  Asetattrs(copy,AOCPY_Vspace,vspaceValue,TAG_END);
   }
}

/* Apply CSS properties to a table (TABLE tag) */
void ApplyCSSToTable(struct Document *doc,void *table,UBYTE *style)
{  struct CSSProperty *prop;
   struct Number num;
   UBYTE *p;
   long borderValue;
   long widthValue;
   long cellpaddingValue;
   long cellspacingValue;
   ULONG wtag;
   struct Colorinfo *cssBgcolor;
   
   if(!doc || !table || !style) return;
   
   p = style;
   wtag = TAG_IGNORE;
   borderValue = -1;
   widthValue = -1;
   cellpaddingValue = -1;
   cellspacingValue = -1;
   cssBgcolor = NULL;
   
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {  /* Extract border */
         if(stricmp((char *)prop->name,"border") == 0)
         {  borderValue = ParseCSSLengthValue(prop->value,&num);
            if(borderValue < 0) borderValue = 0;
         }
         /* Extract width */
         else if(stricmp((char *)prop->name,"width") == 0)
         {  widthValue = ParseCSSLengthValue(prop->value,&num);
            if(widthValue > 0)
            {  if(num.type == NUMBER_PERCENT)
               {  wtag = AOTAB_Percentwidth;
               }
               else
               {  wtag = AOTAB_Pixelwidth;
               }
            }
         }
         /* Extract cellpadding via padding */
         else if(stricmp((char *)prop->name,"padding") == 0)
         {  cellpaddingValue = ParseCSSLengthValue(prop->value,&num);
            if(cellpaddingValue < 0) cellpaddingValue = 0;
         }
         /* Extract cellspacing - no direct CSS equivalent, but we can parse it if needed */
         /* Note: CSS border-spacing is CSS2 and not yet supported */
         /* Extract background-color */
         else if(stricmp((char *)prop->name,"background-color") == 0)
         {  ULONG colorrgb;
            colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  cssBgcolor = Finddoccolor(doc,colorrgb);
            }
         }
         /* Extract border-color */
         else if(stricmp((char *)prop->name,"border-color") == 0)
         {  ULONG colorrgb;
            struct Colorinfo *ci;
            colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  Asetattrs(table,AOTAB_Bordercolor,ci,TAG_END);
               }
            }
         }
         
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      else
      {  /* Skip to next semicolon on parse error */
         while(*p && *p != ';')
         {  p++;
         }
      }
      
      /* Skip semicolon */
      if(*p == ';') p++;
   }
   
   /* Apply extracted values to table */
   if(borderValue >= 0)
   {  Asetattrs(table,AOTAB_Border,borderValue,TAG_END);
   }
   if(wtag != TAG_IGNORE && widthValue > 0)
   {  Asetattrs(table,wtag,widthValue,TAG_END);
   }
   if(cellpaddingValue >= 0)
   {  Asetattrs(table,AOTAB_Cellpadding,cellpaddingValue,TAG_END);
   }
   if(cellspacingValue >= 0)
   {  Asetattrs(table,AOTAB_Cellspacing,cellspacingValue,TAG_END);
   }
   if(cssBgcolor)
   {  Asetattrs(table,AOTAB_Bgcolor,cssBgcolor,TAG_END);
   }
}

