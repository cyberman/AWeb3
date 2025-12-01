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
#include "aweb.h"
#include "css.h"
#include "docprivate.h"
#include "element.h"
#include "body.h"
#include "colours.h"
#include "html.h"
#include "link.h"

/* COLOR macro - extract pen number from Colorinfo */
#define COLOR(ci) ((ci)?((ci)->pen):(-1))

/* Forward declarations */
static struct CSSStylesheet* ParseCSS(struct Document *doc,UBYTE *css);
static struct CSSRule* ParseRule(struct Document *doc,UBYTE **p);
static struct CSSSelector* ParseSelector(struct Document *doc,UBYTE **p);
static struct CSSProperty* ParseProperty(struct Document *doc,UBYTE **p);
static void SkipWhitespace(UBYTE **p);
static void SkipComment(UBYTE **p);
static UBYTE* ParseIdentifier(UBYTE **p);
static UBYTE* ParseValue(UBYTE **p);
static BOOL MatchSelector(struct CSSSelector *sel,void *element);
static void ApplyProperty(void *element,struct CSSProperty *prop);
static void FreeCSSStylesheetInternal(struct CSSStylesheet *sheet);
static long ParseCSSLengthValue(UBYTE *value,struct Number *num);
static ULONG ParseHexColor(UBYTE *pcolor);

/* Parse a CSS stylesheet */
void ParseCSSStylesheet(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   if(!doc || !css) return;
   
   /* Free existing stylesheet if any */
   if(doc->cssstylesheet)
   {  FreeCSSStylesheetInternal((struct CSSStylesheet *)doc->cssstylesheet);
      doc->cssstylesheet = NULL;
   }
   
   /* Parse CSS */
   sheet = ParseCSS(doc,css);
   if(sheet)
   {  doc->cssstylesheet = (void *)sheet;
   }
}

/* Parse CSS content */
static struct CSSStylesheet* ParseCSS(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   struct CSSRule *rule;
   UBYTE *p;
   
   if(!doc || !css) return NULL;
   
   sheet = AllocMem(sizeof(struct CSSStylesheet),MEMF_CLEAR);
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
   
   rule = AllocMem(sizeof(struct CSSRule),MEMF_CLEAR);
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
         FreeMem(rule,sizeof(struct CSSRule));
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
   {  FreeMem(rule,sizeof(struct CSSRule));
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
   
   FreeMem(rule,sizeof(struct CSSRule));
   return NULL;
}

/* Parse a CSS selector */
static struct CSSSelector* ParseSelector(struct Document *doc,UBYTE **p)
{  struct CSSSelector *sel;
   UBYTE *name;
   UBYTE *id;
   UBYTE *class;
   
   if(!doc || !p || !*p) return NULL;
   
   sel = AllocMem(sizeof(struct CSSSelector),MEMF_CLEAR);
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
      {  FreeMem(sel,sizeof(struct CSSSelector));
         return NULL;
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
      {  FreeMem(sel,sizeof(struct CSSSelector));
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
   
   return sel;
}

/* Parse a CSS property */
static struct CSSProperty* ParseProperty(struct Document *doc,UBYTE **p)
{  struct CSSProperty *prop;
   UBYTE *name;
   UBYTE *value;
   
   if(!doc || !p || !*p) return NULL;
   
   prop = AllocMem(sizeof(struct CSSProperty),MEMF_CLEAR);
   if(!prop) return NULL;
   
   SkipWhitespace(p);
   
   /* Parse property name */
   name = ParseIdentifier(p);
   if(!name)
   {  FreeMem(prop,sizeof(struct CSSProperty));
      return NULL;
   }
   prop->name = Dupstr(name,-1);
   
   SkipWhitespace(p);
   if(**p != ':')
   {  FREE(prop->name);
      FreeMem(prop,sizeof(struct CSSProperty));
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
      FreeMem(prop,sizeof(struct CSSProperty));
      return NULL;
   }
   
   return prop;
}

/* Skip whitespace */
static void SkipWhitespace(UBYTE **p)
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
   
   result = AllocMem(len + 1,MEMF_CLEAR);
   if(result)
   {  strncpy((char *)result,(char *)start,len);
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
   
   /* Handle quoted strings */
   if(**p == '"' || **p == '\'')
   {  quote = **p;
      inString = TRUE;
      (*p)++;
      start = *p;
      while(**p && **p != quote)
      {  if(**p == '\\' && (*p)[1])
         {  (*p) += 2; /* Skip escaped character */
         }
         else
         {  (*p)++;
         }
      }
      len = *p - start;
      if(**p == quote) (*p)++;
   }
   else
   {  /* Parse until semicolon, closing brace, or newline */
      while(**p && **p != ';' && **p != '}' && **p != '\n' && **p != '\r')
      {  (*p)++;
      }
      len = *p - start;
      /* Trim trailing whitespace */
      while(len > 0 && isspace(start[len - 1]))
      {  len--;
      }
   }
   
   if(len == 0) return NULL;
   
   result = AllocMem(len + 1,MEMF_CLEAR);
   if(result)
   {  strncpy((char *)result,(char *)start,len);
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
         fontName = AllocMem(len + 1,MEMF_CLEAR);
         if(fontName)
         {  strncpy((char *)fontName,(char *)value,len);
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
      }
      for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
         (struct MinNode *)prop->node.mln_Succ;
         prop = (struct CSSProperty *)prop->node.mln_Succ)
      {  if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
      }
   }
   
   FreeMem(sheet,sizeof(struct CSSStylesheet));
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
         FreeMem(prop,sizeof(struct CSSProperty));
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
         /* Apply border (simplified - just width for now) */
         else if(stricmp((char *)prop->name,"border") == 0)
         {  /* Parse "2px solid #E8E0D8" format */
            /* For now, just note that border is set */
            /* TODO: Parse border width, style, and color */
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
            {  if(tagname && stricmp((char *)tagname,"DIV") == 0)
               {  Asetattrs(body,AOBDY_Divalign,align,TAG_END);
               }
               else if(tagname && stricmp((char *)tagname,"P") == 0)
               {  Asetattrs(body,AOBDY_Align,align,TAG_END);
               }
               else if(tagname && (stricmp((char *)tagname,"TD") == 0 || stricmp((char *)tagname,"TH") == 0))
               {  /* For table cells, alignment is handled via table attributes */
                  /* But we can set it on the body */
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
         /* Apply font-family */
         else if(stricmp((char *)prop->name,"font-family") == 0)
         {  fontFace = prop->value;
            comma = (UBYTE *)strchr((char *)prop->value,',');
            if(comma)
            {  long len = comma - prop->value;
               fontFace = AllocMem(len + 1,MEMF_CLEAR);
               if(fontFace)
               {  strncpy((char *)fontFace,(char *)prop->value,len);
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
         
         /* Free the property */
         if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FreeMem(prop,sizeof(struct CSSProperty));
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
static long ParseCSSLengthValue(UBYTE *value,struct Number *num)
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
static ULONG ParseHexColor(UBYTE *pcolor)
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
   
   return rgbval;
}

/* Parse and apply inline CSS to a Link object */
void ApplyInlineCSSToLink(struct Document *doc,void *link,UBYTE *style)
{  struct CSSProperty *prop;
   UBYTE *p;
   ULONG colorrgb;
   struct Colorinfo *ci;
   void *body;
   
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
         /* Apply color - apply to body's font color via link's text buffer */
         else if(stricmp((char *)prop->name,"color") == 0)
         {  colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  /* Apply color to the document body's font color */
                  /* The link text will inherit this color */
                  if(doc->body)
                  {  Asetattrs(doc->body,AOBDY_Fontcolor,ci,TAG_END);
                  }
               }
            }
         }
      }
      
      /* Free the property */
      if(prop)
      {  if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FreeMem(prop,sizeof(struct CSSProperty));
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
         FreeMem(prop,sizeof(struct CSSProperty));
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

