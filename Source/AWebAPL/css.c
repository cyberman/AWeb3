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
#include <stdlib.h>
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
static void ApplyProperty(struct Document *doc,void *element,struct CSSProperty *prop);
static void FreeCSSStylesheetInternal(struct CSSStylesheet *sheet);
void MergeCSSStylesheet(struct Document *doc,UBYTE *css);
void SkipWhitespace(UBYTE **p);
long ParseCSSLengthValue(UBYTE *value,struct Number *num);
ULONG ParseHexColor(UBYTE *pcolor);

/* Simple debug printf - only output if httpdebug is enabled */
extern BOOL httpdebug;

static void css_debug_printf(const char *format, ...)
{  va_list args;
   if(!httpdebug) return;
   va_start(args, format);
   printf("[CSS] ");
   vprintf(format, args);
   va_end(args);
}

/* Parse a CSS stylesheet */
void ParseCSSStylesheet(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   if(!doc || !css) return;
   
   /* debug_printf("CSS: ParseCSSStylesheet called, css length=%ld\n",strlen((char *)css)); */
   
   /* If there's an existing stylesheet, merge instead of replace */
   if(doc->cssstylesheet)
   {  MergeCSSStylesheet(doc,css);
      return;
   }
   
   /* Parse CSS */
   sheet = ParseCSS(doc,css);
   if(sheet)
   {  struct CSSRule *rule;
      struct CSSSelector *sel;
      long ruleCount = 0;
      doc->cssstylesheet = (void *)sheet;
      /* Count rules and log selectors */
      for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
          (struct MinNode *)rule->node.mln_Succ;
          rule = (struct CSSRule *)rule->node.mln_Succ)
      {  ruleCount++;
         /* Log first selector of each rule for debugging */
         sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         if((struct MinNode *)sel->node.mln_Succ)
         {  /* debug_printf("CSS: Rule %ld: selector type=0x%lx name=%s class=%s id=%s\n",
                        ruleCount,
                        (ULONG)sel->type,
                        (sel->name ? (char *)sel->name : "NULL"),
                        (sel->class ? (char *)sel->class : "NULL"),
                        (sel->id ? (char *)sel->id : "NULL")); */
         }
      }
      /* debug_printf("CSS: Stylesheet parsed successfully, %ld rules\n",ruleCount); */
   }
   else
   {  /* debug_printf("CSS: Stylesheet parsing failed\n"); */
   }
}

/* Merge external CSS stylesheet with existing stylesheet */
void MergeCSSStylesheet(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *existingSheet;
   struct CSSStylesheet *newSheet;
   struct CSSRule *rule;
   struct CSSSelector *sel;
   long ruleCount;
   
   if(!doc || !css) return;
   
   css_debug_printf("MergeCSSStylesheet: Starting merge, CSS length=%ld bytes\n", strlen((char *)css));
   
   /* Parse the new CSS */
   newSheet = ParseCSS(doc,css);
   if(!newSheet)
   {  css_debug_printf("MergeCSSStylesheet: ERROR - ParseCSS failed\n");
      return;
   }
   
   css_debug_printf("MergeCSSStylesheet: ParseCSS succeeded, merging into existing stylesheet\n");
   
   /* Count rules in new sheet and log selectors */
   ruleCount = 0;
   for(rule = (struct CSSRule *)newSheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  ruleCount++;
      /* Log first selector of each rule for debugging */
      sel = (struct CSSSelector *)rule->selectors.mlh_Head;
      if((struct MinNode *)sel->node.mln_Succ)
      {  /* debug_printf("MergeCSSStylesheet: New rule %ld: selector type=0x%lx name=%s class=%s id=%s\n",
                     ruleCount,
                     (ULONG)sel->type,
                     (sel->name ? (char *)sel->name : "NULL"),
                     (sel->class ? (char *)sel->class : "NULL"),
                     (sel->id ? (char *)sel->id : "NULL")); */
      }
   }
   /* debug_printf("MergeCSSStylesheet: Parsed %ld rules from new CSS\n",ruleCount); */
   
   /* If no existing stylesheet, just use the new one */
   if(!doc->cssstylesheet)
   {  doc->cssstylesheet = (void *)newSheet;
      /* debug_printf("MergeCSSStylesheet: No existing sheet, using new one\n"); */
      return;
   }
   
   /* Merge: append rules from new sheet to existing sheet */
   existingSheet = (struct CSSStylesheet *)doc->cssstylesheet;
   
   /* Move all rules from newSheet to existingSheet */
   while((rule = (struct CSSRule *)REMHEAD(&newSheet->rules)))
   {  ADDTAIL(&existingSheet->rules,rule);
   }
   
   /* Free the empty newSheet structure */
   FREE(newSheet);
   
   /* Count total rules after merge */
   ruleCount = 0;
   for(rule = (struct CSSRule *)existingSheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  ruleCount++;
   }
   css_debug_printf("MergeCSSStylesheet: Merge completed, total rules=%ld\n", ruleCount);
}

/* Parse CSS content */
static struct CSSStylesheet* ParseCSS(struct Document *doc,UBYTE *css)
{  struct CSSStylesheet *sheet;
   struct CSSRule *rule;
   UBYTE *p;
   long cssLen;
   long ruleCount = 0;
   long iterationCount = 0;
   UBYTE *cssStart;
   
   if(!doc || !css) return NULL;
   
   cssStart = css;
   cssLen = strlen((char *)css);
   css_debug_printf("ParseCSS: Starting, CSS length=%ld bytes\n", cssLen);
   
   sheet = ALLOCSTRUCT(CSSStylesheet,1,MEMF_FAST);
   if(!sheet)
   {  css_debug_printf("ParseCSS: Failed to allocate stylesheet\n");
      return NULL;
   }
   
   NEWLIST(&sheet->rules);
   sheet->pool = doc->pool;
   
   p = css;
   
   /* Skip UTF-8 BOM if present (0xEF 0xBB 0xBF) */
   if(p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
   {  p += 3;
      css_debug_printf("ParseCSS: Skipped UTF-8 BOM\n");
   }
   
   {  long lastPosition = -1;
      long stuckCount = 0;
      
      while(*p)
      {  UBYTE *oldp;
         long position;
         UBYTE *contextStart;
         UBYTE *contextEnd;
         long contextLen;
         UBYTE context[101];
         long j;
         
         iterationCount++;
         
         if(iterationCount % 100 == 0)
         {  position = p - cssStart;
            css_debug_printf("ParseCSS: Iteration %ld, position %ld/%ld (%.1f%%), rules parsed=%ld\n",
                            iterationCount, position, cssLen, 
                            (cssLen > 0 ? (100.0 * position / cssLen) : 0.0), ruleCount);
         }
         
         /* Hard limit: if we've done more than 100000 iterations, something is very wrong */
         if(iterationCount > 100000)
         {  css_debug_printf("ParseCSS: FATAL - Exceeded 100000 iterations, breaking to prevent lockup\n");
            break;
         }
         
         oldp = p;
         SkipWhitespace(&p);
         SkipComment(&p);
         if(!*p) break;
         
         position = p - cssStart;
         
         /* Detect if we're stuck at the same position (after skipping whitespace) */
         if(position == lastPosition)
         {  stuckCount++;
            if(stuckCount > 10)
            {  /* Show context around stuck position */
               contextStart = (position > 50) ? p - 50 : cssStart;
               contextEnd = p + 50;
               contextLen = contextEnd - contextStart;
               if(contextLen > 100) contextLen = 100;
               for(j = 0; j < contextLen && contextStart[j]; j++)
               {  context[j] = (contextStart[j] >= 32 && contextStart[j] < 127) ? contextStart[j] : '.';
               }
               context[j] = '\0';
               css_debug_printf("ParseCSS: STUCK - Same position %ld for %ld iterations!\n",
                              position, stuckCount);
               css_debug_printf("ParseCSS: Context around stuck position: '%.100s'\n", context);
               css_debug_printf("ParseCSS: Breaking to prevent infinite loop\n");
               break;
            }
         }
         else
         {  stuckCount = 0;
            lastPosition = position;
         }
      
         /* Check for @media query - skip it for now (basic support) */
         if(*p == '@' && strnicmp((char *)p, "@media", 6) == 0)
         {  css_debug_printf("ParseCSS: Found @media query at position %ld, skipping\n", p - cssStart);
            p += 6; /* Skip "@media" */
            SkipWhitespace(&p);
            /* Skip media query list until opening brace */
            while(*p && *p != '{')
            {  p++;
            }
            if(*p == '{')
            {  long braceDepth = 1;
               long mediaStart = p - cssStart;
               (*p)++; /* Skip opening brace */
               /* Skip entire @media block */
               while(*p && braceDepth > 0)
               {  if(*p == '{') braceDepth++;
                  else if(*p == '}') braceDepth--;
                  p++;
               }
               css_debug_printf("ParseCSS: Skipped @media block from position %ld to %ld\n",
                              mediaStart, p - cssStart);
            }
            /* Update position after skipping @media block */
            position = p - cssStart;
            lastPosition = position;
            stuckCount = 0;
            continue; /* Skip to next rule */
         }
         
         /* Check for other @ rules (@import, @charset, etc.) - skip them */
         if(*p == '@')
         {  UBYTE *atRuleStart = p;
            UBYTE atRuleName[32];
            long i = 0;
            /* Extract @ rule name for debugging */
            while(*p && i < 31 && (isalpha(*p) || *p == '-' || *p == '_'))
            {  atRuleName[i++] = *p++;
            }
            atRuleName[i] = '\0';
            css_debug_printf("ParseCSS: Found @ rule '%s' at position %ld, skipping\n",
                            atRuleName, atRuleStart - cssStart);
            
            /* Skip to semicolon or opening brace */
            while(*p && *p != ';' && *p != '{')
            {  p++;
            }
            if(*p == ';')
            {  (*p)++;
               /* Update position after skipping @ rule */
               position = p - cssStart;
               lastPosition = position;
               stuckCount = 0;
               continue;
            }
            else if(*p == '{')
            {  long braceDepth = 1;
               (*p)++;
               while(*p && braceDepth > 0)
               {  if(*p == '{') braceDepth++;
                  else if(*p == '}') braceDepth--;
                  p++;
               }
               /* Update position after skipping @ rule block */
               position = p - cssStart;
               lastPosition = position;
               stuckCount = 0;
               continue;
            }
         }
         
         oldp = p;  /* Remember position before parsing */
         rule = ParseRule(doc,&p);
         if(rule)
         {  ruleCount++;
            ADDTAIL(&sheet->rules,rule);
            if(ruleCount % 50 == 0)
            {  css_debug_printf("ParseCSS: Parsed %ld rules so far, position %ld/%ld\n",
                               ruleCount, p - cssStart, cssLen);
            }
         }
         else
         {  /* Parse error - make sure we advance the pointer */
            if(p == oldp)
            {  /* Pointer didn't advance - skip one character to prevent infinite loop */
               {  /* Show context around the problematic character */
                  UBYTE *contextStart2;
                  UBYTE *contextEnd2;
                  long contextLen2;
                  UBYTE context2[41];
                  long j2;
                  
                  contextStart2 = (p - cssStart > 20) ? p - 20 : cssStart;
                  contextEnd2 = p + 20;
                  contextLen2 = contextEnd2 - contextStart2;
                  if(contextLen2 > 40) contextLen2 = 40;
                  for(j2 = 0; j2 < contextLen2 && contextStart2[j2]; j2++)
                  {  context2[j2] = (contextStart2[j2] >= 32 && contextStart2[j2] < 127) ? contextStart2[j2] : '.';
                  }
                  context2[j2] = '\0';
                  css_debug_printf("ParseCSS: WARNING - ParseRule failed and pointer didn't advance at position %ld (char=0x%02x '%c')\n",
                                 p - cssStart, *p, (*p >= 32 && *p < 127) ? *p : '?');
                  css_debug_printf("ParseCSS: Context: '%.40s'\n", context2);
               }
               if(*p) p++;
               else break;  /* End of string */
            }
            else
            {  /* Pointer advanced but rule failed - skip to next rule */
               css_debug_printf("ParseCSS: ParseRule failed but pointer advanced, skipping to next rule (pos %ld->%ld)\n",
                              oldp - cssStart, p - cssStart);
               while(*p && *p != '}')
               {  p++;
               }
               if(*p == '}') p++;
            }
         }
         
         /* Final safety check: if we haven't advanced at all, force advance and break */
         if(p == oldp)
         {  css_debug_printf("ParseCSS: ERROR - Pointer stuck at position %ld, forcing advance\n", p - cssStart);
            if(*p) p++;
            else break;
            /* If we're still at the same position after forcing advance, something is wrong - break */
            if(p == oldp)
            {  css_debug_printf("ParseCSS: FATAL - Pointer still stuck after force advance, breaking\n");
               break;
            }
         }
         
         /* Safety check: if we've been parsing for too long, warn */
         if(iterationCount > 10000)
         {  css_debug_printf("ParseCSS: WARNING - High iteration count (%ld), position %ld/%ld\n",
                            iterationCount, p - cssStart, cssLen);
         }
      }
   }
   
   css_debug_printf("ParseCSS: Completed, parsed %ld rules in %ld iterations, final position %ld/%ld\n",
                   ruleCount, iterationCount, p - cssStart, cssLen);
   return sheet;
}

/* Parse a CSS rule */
static struct CSSRule* ParseRule(struct Document *doc,UBYTE **p)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   UBYTE *ruleStart;
   long selectorCount = 0;
   long propertyCount = 0;
   
   if(!doc || !p || !*p) return NULL;
   
   ruleStart = *p;
   rule = ALLOCSTRUCT(CSSRule,1,MEMF_FAST);
   if(!rule)
   {  css_debug_printf("ParseRule: Failed to allocate rule\n");
      return NULL;
   }
   
   NEWLIST(&rule->selectors);
   NEWLIST(&rule->properties);
   
   /* Parse selectors */
   {  long selIterationCount = 0;
      while(**p)
      {  UBYTE *oldp;
         
         selIterationCount++;
         if(selIterationCount > 1000)
         {  css_debug_printf("ParseRule: WARNING - Selector parsing loop exceeded 1000 iterations, breaking\n");
            break;
         }
         
         SkipWhitespace(p);
         SkipComment(p);
         if(**p == '{') break;
         if(**p == ';' || **p == '}') return NULL; /* Invalid */
         
         oldp = *p;  /* Remember position before parsing */
         sel = ParseSelector(doc,p);
         if(sel)
         {  selectorCount++;
            ADDTAIL(&rule->selectors,sel);
         }
         else
         {  /* Parse error in selector - make sure pointer advanced */
            if(*p == oldp)
            {  /* Pointer didn't advance - skip one character to prevent infinite loop */
               css_debug_printf("ParseRule: WARNING - ParseSelector failed and pointer didn't advance (pos %ld, char=0x%02x)\n",
                              *p - ruleStart, **p);
               (*p)++;
            }
            else
            {  css_debug_printf("ParseRule: ParseSelector failed but pointer advanced (pos %ld->%ld)\n",
                               oldp - ruleStart, *p - ruleStart);
            }
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
   }
   
   if(**p != '{')
   {  css_debug_printf("ParseRule: Expected '{' but found 0x%02x at position %ld\n",
                      **p, *p - ruleStart);
      FREE(rule);
      return NULL;
   }
   (*p)++; /* Skip '{' */
   
   css_debug_printf("ParseRule: Parsed %ld selector(s), starting properties at position %ld\n",
                   selectorCount, *p - ruleStart);
   
   /* Parse properties */
   {  long propIterationCount = 0;
      while(**p)
      {  UBYTE *propOldp;
         
         propIterationCount++;
         if(propIterationCount > 1000)
         {  css_debug_printf("ParseRule: WARNING - Property parsing loop exceeded 1000 iterations, breaking\n");
            break;
         }
         
         SkipWhitespace(p);
         SkipComment(p);
         if(**p == '}') break;
         
         propOldp = *p;  /* Remember position before parsing property */
         prop = ParseProperty(doc,p);
         if(prop)
         {  propertyCount++;
            ADDTAIL(&rule->properties,prop);
         }
         else
         {  /* Parse error - skip to next semicolon or closing brace */
            if(*p == propOldp)
            {  /* Pointer didn't advance - force advance */
               css_debug_printf("ParseRule: WARNING - ParseProperty failed and pointer didn't advance (pos %ld, char=0x%02x)\n",
                              *p - ruleStart, **p);
               if(**p && **p != ';' && **p != '}')
               {  (*p)++;
               }
               else if(**p == ';')
               {  (*p)++;
               }
               else if(**p == '}')
               {  break;
               }
               else
               {  /* End of string or invalid - break */
                  break;
               }
            }
            else
            {  /* Pointer advanced but property failed - skip to next */
               css_debug_printf("ParseRule: ParseProperty failed, skipping to next (pos %ld->%ld)\n",
                              propOldp - ruleStart, *p - ruleStart);
               {  long skipIterationCount = 0;
                  while(**p && **p != ';' && **p != '}')
                  {  skipIterationCount++;
                     if(skipIterationCount > 10000)
                     {  /* Safety: if we can't find semicolon or brace in 10000 chars, break */
                        break;
                     }
                     (*p)++;
                  }
               }
            }
         }
         
         SkipWhitespace(p);
         if(**p == ';')
         {  (*p)++;
         }
         else if(**p == '}')
         {  break;
         }
         
         /* Safety check: if pointer didn't advance at all, force advance and break */
         if(*p == propOldp)
         {  if(**p && **p != '}')
            {  (*p)++;
            }
            else
            {  break;
            }
            /* If still at same position after forcing advance, break */
            if(*p == propOldp)
            {  css_debug_printf("ParseRule: Property pointer stuck, breaking\n");
               break;
            }
         }
      }
   }
   
   css_debug_printf("ParseRule: Completed rule with %ld selector(s) and %ld property(ies), final position %ld\n",
                   selectorCount, propertyCount, *p - ruleStart);
   
   if(**p == '}')
   {  (*p)++; /* Skip '}' */
      return rule;
   }
   
   css_debug_printf("ParseRule: ERROR - Expected '}' but found 0x%02x, freeing rule\n", **p);
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
   
   sel = ALLOCSTRUCT(CSSSelector,1,MEMF_FAST);
   if(!sel) return NULL;
   
   /* Initialize new fields */
   sel->parent = NULL;
   sel->combinator = CSS_COMB_NONE;
   sel->pseudoElement = NULL;
   sel->attr = NULL;
   
   SkipWhitespace(p);
   
   /* Check for :root selector (must be at start) */
   if(**p == ':')
   {  UBYTE *rootCheck = *p + 1;
      UBYTE *rootId = ParseIdentifier(&rootCheck);
      if(rootId && stricmp((char *)rootId, "root") == 0)
      {  /* Check if next char is whitespace, comma, or brace (end of selector) */
         if(!*rootCheck || isspace(*rootCheck) || *rootCheck == ',' || *rootCheck == '{' || *rootCheck == '}')
         {  sel->type = CSS_SEL_ROOT;
            sel->specificity = 1; /* :root has element-level specificity */
            *p = rootCheck;
            SkipWhitespace(p);
            return sel;
         }
      }
   }
   
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
      /* Support multiple chained classes (e.g., .class1.class2) */
      SkipWhitespace(p);
      while(**p == '.' || **p == '#')
      {  if(**p == '.')
         {  (*p)++;
            class = ParseIdentifier(p);
            if(class)
            {  sel->type |= CSS_SEL_CLASS;
               if(sel->class)
               {  /* Append to existing class list (space-separated) */
                  UBYTE *oldClass;
                  long oldLen;
                  long newLen;
                  long classLen;
                  UBYTE *newClass;
                  
                  oldClass = sel->class;
                  oldLen = strlen((char *)oldClass);
                  classLen = strlen((char *)class);
                  newLen = oldLen + 1 + classLen; /* old + space + new */
                  newClass = ALLOCTYPE(UBYTE, newLen + 1, MEMF_FAST);
                  if(newClass)
                  {  memmove(newClass, oldClass, oldLen);
                     newClass[oldLen] = ' ';
                     memmove(newClass + oldLen + 1, class, classLen);
                     newClass[newLen] = '\0';
                     FREE(oldClass);
                     sel->class = newClass;
                  }
               }
               else
               {  sel->class = Dupstr(class,-1);
               }
               sel->specificity += 10; /* Each class adds 10 to specificity */
            }
         }
         else if(**p == '#')
         {  (*p)++;
            id = ParseIdentifier(p);
            if(id)
            {  sel->type |= CSS_SEL_ID;
               sel->id = Dupstr(id,-1);
               sel->specificity += 100;
               break; /* ID can only appear once, stop parsing classes */
            }
         }
         SkipWhitespace(p);
      }
   }
   
   /* Check for pseudo-class (e.g., :link, :visited, :hover) or pseudo-element (::before, ::after) */
   SkipWhitespace(p);
   if(**p == ':')
   {  if((*p)[1] == ':')
      {  /* Pseudo-element (::before, ::after, ::selection, etc.) */
         (*p) += 2; /* Skip '::' */
         pseudoName = ParseIdentifier(p);
         if(pseudoName)
         {  sel->type |= CSS_SEL_PSEUDOEL;
            sel->pseudoElement = Dupstr(pseudoName,-1);
            sel->specificity += 1; /* Pseudo-element adds element-level specificity */
         }
      }
      else
      {  /* Pseudo-class (:link, :visited, :hover, etc.) */
         (*p)++; /* Skip ':' */
         pseudoName = ParseIdentifier(p);
         if(pseudoName)
         {  sel->type |= CSS_SEL_PSEUDO;
            sel->pseudo = Dupstr(pseudoName,-1);
            sel->specificity += 10; /* Pseudo-class adds to specificity */
         }
      }
   }
   
   /* Check for attribute selector [attr], [attr=value], [attr*=value], etc. */
   SkipWhitespace(p);
   if(**p == '[')
   {  struct CSSAttribute *attr;
      UBYTE *attrName;
      UBYTE *attrValue;
      UBYTE *oldp;
      UBYTE quote;
      
      (*p)++; /* Skip '[' */
      SkipWhitespace(p);
      
      attr = ALLOCSTRUCT(CSSAttribute, 1, MEMF_FAST);
      if(attr)
      {  attr->name = NULL;
         attr->value = NULL;
         attr->operator = CSS_ATTR_NONE;
         
         /* Parse attribute name */
         attrName = ParseIdentifier(p);
         if(attrName)
         {  attr->name = Dupstr(attrName,-1);
            SkipWhitespace(p);
            
            /* Check for operator */
            if(**p == '=')
            {  attr->operator = CSS_ATTR_EQUAL;
               (*p)++;
            }
            else if(**p == '*' && (*p)[1] == '=')
            {  attr->operator = CSS_ATTR_CONTAINS;
               (*p) += 2;
            }
            else if(**p == '^' && (*p)[1] == '=')
            {  attr->operator = CSS_ATTR_STARTS;
               (*p) += 2;
            }
            else if(**p == '$' && (*p)[1] == '=')
            {  attr->operator = CSS_ATTR_ENDS;
               (*p) += 2;
            }
            else if(**p == '~' && (*p)[1] == '=')
            {  attr->operator = CSS_ATTR_WORD;
               (*p) += 2;
            }
            
            /* If we have an operator, parse the value */
            if(attr->operator != CSS_ATTR_NONE)
            {  SkipWhitespace(p);
               oldp = *p;
               
               /* Check for quoted value */
               if(**p == '"' || **p == '\'')
               {  quote = **p;
                  (*p)++; /* Skip opening quote */
                  attrValue = *p;
                  while(**p && **p != quote)
                  {  if(**p == '\\' && (*p)[1])
                     {  (*p) += 2; /* Skip escaped character */
                     }
                     else
                     {  (*p)++;
                     }
                  }
                  if(**p == quote)
                  {  long len = *p - attrValue;
                     attr->value = ALLOCTYPE(UBYTE, len + 1, MEMF_FAST);
                     if(attr->value)
                     {  memmove(attr->value, attrValue, len);
                        attr->value[len] = '\0';
                     }
                     (*p)++; /* Skip closing quote */
                  }
               }
               else
               {  /* Unquoted value - parse identifier */
                  attrValue = ParseIdentifier(p);
                  if(attrValue)
                  {  attr->value = Dupstr(attrValue,-1);
                  }
               }
            }
            
            SkipWhitespace(p);
            if(**p == ']')
            {  (*p)++; /* Skip ']' */
               sel->type |= CSS_SEL_ATTRIBUTE;
               sel->attr = attr;
               sel->specificity += 10; /* Attribute selector adds class-level specificity */
            }
            else
            {  /* Invalid attribute selector - free and ignore */
               if(attr->name) FREE(attr->name);
               if(attr->value) FREE(attr->value);
               FREE(attr);
            }
         }
         else
         {  /* Invalid attribute name - free and ignore */
            FREE(attr);
         }
      }
   }
   
   /* Check for descendant selector (whitespace) or child combinator (>) */
   SkipWhitespace(p);
   if(**p && **p != ',' && **p != '{' && **p != '}')
   {  UBYTE *oldp;
      struct CSSSelector *childSel;
      
      /* Check for child combinator */
      if(**p == '>')
      {  (*p)++; /* Skip '>' */
         SkipWhitespace(p);
         oldp = *p;
         childSel = ParseSelector(doc, p);
         if(childSel)
         {  childSel->parent = sel;
            childSel->combinator = CSS_COMB_CHILD;
            /* Update specificity - child selector adds to parent */
            childSel->specificity += sel->specificity;
            return childSel; /* Return the child selector as the head */
         }
         else
         {  /* Parse error - restore position */
            *p = oldp;
         }
      }
      else
      {  /* Check if there's whitespace followed by another selector (descendant) */
         /* We already skipped whitespace, so check if next char starts an identifier */
         if(isalpha(**p) || **p == '.' || **p == '#' || **p == '*')
         {  oldp = *p;
            childSel = ParseSelector(doc, p);
            if(childSel)
            {  childSel->parent = sel;
               childSel->combinator = CSS_COMB_DESCENDANT;
               /* Update specificity - descendant selector adds to parent */
               childSel->specificity += sel->specificity;
               return childSel; /* Return the child selector as the head */
            }
            else
            {  /* Parse error - restore position */
               *p = oldp;
            }
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
   
   prop = ALLOCSTRUCT(CSSProperty,1,MEMF_FAST);
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
   {  /* ParseValue failed - make sure pointer advanced */
      /* ParseValue should have advanced past whitespace, but if it returned NULL
       * without advancing, we need to skip to prevent infinite loop */
      if(*p && **p != ';' && **p != '}')
      {  /* Skip to next semicolon or closing brace */
         while(**p && **p != ';' && **p != '}')
         {  (*p)++;
         }
      }
      FREE(prop->name);
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
   
   result = ALLOCTYPE(UBYTE,len + 1,MEMF_FAST);
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
   
   /* If we're already at a semicolon or closing brace, no value to parse */
   if(**p == ';' || **p == '}')
   {  return NULL;
   }
   
   /* Parse until semicolon or closing brace (allow newlines in values) */
   /* Handle quoted strings within the value (e.g., font-family: "Open Sans", "Helvetica Neue", ...) */
   {  long valueIterationCount = 0;
      while(**p && **p != ';' && **p != '}')
      {  valueIterationCount++;
         if(valueIterationCount > 10000)
         {  /* Safety: if we've parsed more than 10000 characters, something is wrong - break */
            break;
         }
         
         if((**p == '"' || **p == '\'') && !inString)
         {  quote = **p;
            inString = TRUE;
            (*p)++;
            /* Skip to closing quote */
            {  long quoteIterationCount = 0;
               while(**p && **p != quote)
               {  quoteIterationCount++;
                  if(quoteIterationCount > 10000)
                  {  /* Unclosed quote - break out */
                     inString = FALSE;
                     break;
                  }
                  if(**p == '\\' && (*p)[1])
                  {  (*p) += 2; /* Skip escaped character */
                  }
                  else
                  {  (*p)++;
                  }
               }
            }
            if(**p == quote)
            {  (*p)++; /* Skip closing quote */
               inString = FALSE;
            }
            else
            {  /* Unclosed quote - treat as end of value */
               inString = FALSE;
            }
         }
         else
         {  (*p)++;
         }
      }
   }
   len = *p - start;
   /* Trim trailing whitespace */
   while(len > 0 && isspace(start[len - 1]))
   {  len--;
   }
   
   if(len == 0) return NULL;
   
   result = ALLOCTYPE(UBYTE,len + 1,MEMF_FAST);
   if(result)
   {  memmove(result,start,len);
      result[len] = '\0';
   }
   
   return result;
}

/* Match class attribute against selector class (handles space-separated classes) */
/* For multiple classes in selector (e.g., "class1 class2"), element must have ALL classes */
/* Uses proper word-boundary matching to avoid partial matches */
static BOOL MatchClassAttribute(UBYTE *elementClass, UBYTE *selectorClass)
{  UBYTE *start;
   UBYTE *selectorP;
   UBYTE *selectorStart;
   size_t selectorWordLen;
   size_t elementWordLen;
   BOOL foundMatch;
   UBYTE *elementP;
   
   if(!elementClass || !selectorClass || !*selectorClass)
   {  return FALSE;
   }
   
   /* If selector has multiple classes (space-separated), element must have ALL */
   selectorP = selectorClass;
   while(*selectorP)
   {  /* Skip whitespace */
      while(*selectorP && isspace(*selectorP)) selectorP++;
      if(!*selectorP) break;
      
      selectorStart = selectorP;
      /* Find end of current selector class word */
      while(*selectorP && !isspace(*selectorP)) selectorP++;
      selectorWordLen = selectorP - selectorStart;
      
      if(selectorWordLen == 0) break;
      
      /* Check if element has this class */
      foundMatch = FALSE;
      elementP = elementClass;
      /* Skip leading whitespace */
      while(*elementP && isspace(*elementP)) elementP++;
      
      while(*elementP)
      {  start = elementP;
         /* Find end of current element class word */
         while(*elementP && !isspace(*elementP)) elementP++;
         elementWordLen = elementP - start;
         
         /* Check if this word matches selector class (case-insensitive) */
         if(elementWordLen == selectorWordLen)
         {  if(strnicmp((char *)start, (char *)selectorStart, selectorWordLen) == 0)
            {  foundMatch = TRUE;
               break;
            }
         }
         
         /* Skip whitespace to next word */
         while(*elementP && isspace(*elementP)) elementP++;
      }
      
      /* If this selector class wasn't found in element, fail */
      if(!foundMatch)
      {  return FALSE;
      }
   }
   
   return TRUE;
}

/* Case-insensitive string search (stristr equivalent) */
static UBYTE *stristr_case(UBYTE *haystack, UBYTE *needle)
{  UBYTE *p;
   long haystackLen;
   long needleLen;
   long i;
   
   if(!haystack || !needle || !*needle) return NULL;
   
   haystackLen = strlen((char *)haystack);
   needleLen = strlen((char *)needle);
   
   if(needleLen > haystackLen) return NULL;
   
   for(i = 0; i <= haystackLen - needleLen; i++)
   {  if(strnicmp((char *)(haystack + i), (char *)needle, needleLen) == 0)
      {  return haystack + i;
      }
   }
   
   return NULL;
}

/* Match attribute selector */
static BOOL MatchAttributeSelector(struct CSSAttribute *attr, UBYTE *elemAttrValue)
{  UBYTE *attrVal;
   long len;
   
   if(!attr || !attr->name) return FALSE;
   
   if(!elemAttrValue) return (attr->operator == CSS_ATTR_NONE) ? TRUE : FALSE; /* [attr] matches if attribute exists */
   
   attrVal = elemAttrValue;
   
   switch(attr->operator)
   {  case CSS_ATTR_NONE:
         /* [attr] - attribute exists */
         return TRUE;
         
      case CSS_ATTR_EQUAL:
         /* [attr=value] - exact match */
         if(!attr->value) return FALSE;
         return (stricmp((char *)attrVal, (char *)attr->value) == 0) ? TRUE : FALSE;
         
      case CSS_ATTR_CONTAINS:
         /* [attr*=value] - contains substring */
         if(!attr->value) return FALSE;
         return (stristr_case(attrVal, attr->value) != NULL) ? TRUE : FALSE;
         
      case CSS_ATTR_STARTS:
         /* [attr^=value] - starts with */
         if(!attr->value) return FALSE;
         len = strlen((char *)attr->value);
         return (strlen((char *)attrVal) >= len && 
                 strnicmp((char *)attrVal, (char *)attr->value, len) == 0) ? TRUE : FALSE;
         
      case CSS_ATTR_ENDS:
         /* [attr$=value] - ends with */
         if(!attr->value) return FALSE;
         len = strlen((char *)attr->value);
         {  long attrLen = strlen((char *)attrVal);
            if(attrLen < len) return FALSE;
            return (stricmp((char *)(attrVal + attrLen - len), (char *)attr->value) == 0) ? TRUE : FALSE;
         }
         
      case CSS_ATTR_WORD:
         /* [attr~=value] - word match (space-separated) */
         if(!attr->value) return FALSE;
         {  UBYTE *p = attrVal;
            UBYTE *wordStart;
            long wordLen;
            long valueLen = strlen((char *)attr->value);
            
            while(*p)
            {  /* Skip whitespace */
               while(*p && isspace(*p)) p++;
               if(!*p) break;
               
               wordStart = p;
               /* Find end of word */
               while(*p && !isspace(*p)) p++;
               wordLen = p - wordStart;
               
               /* Check if this word matches */
               if(wordLen == valueLen && strnicmp((char *)wordStart, (char *)attr->value, wordLen) == 0)
               {  return TRUE;
               }
            }
            return FALSE;
         }
         
      default:
         return FALSE;
   }
}

/* Match a single selector component to an element (without checking parent) */
static BOOL MatchSelectorComponent(struct CSSSelector *sel, void *element)
{  UBYTE *elemName;
   UBYTE *elemClass;
   UBYTE *elemId;
   UBYTE *attrValue;
   
   if(!sel || !element) return FALSE;
   
   /* Match :root selector - matches HTML element */
   if(sel->type & CSS_SEL_ROOT)
   {  elemName = (UBYTE *)Agetattr(element,AOELT_TagName);
      return (elemName && stricmp((char *)elemName, "html") == 0) ? TRUE : FALSE;
   }
   
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
   
   /* Match class - use proper word-boundary matching */
   if(sel->type & CSS_SEL_CLASS && sel->class)
   {  if(!MatchClassAttribute(elemClass, sel->class))
      {  return FALSE;
      }
   }
   
   /* Match ID */
   if(sel->type & CSS_SEL_ID && sel->id)
   {  if(!elemId || stricmp((char *)sel->id,(char *)elemId) != 0)
      {  return FALSE;
      }
   }
   
   /* Match attribute selector */
   if(sel->type & CSS_SEL_ATTRIBUTE && sel->attr)
   {  /* Get attribute value - for now, we check class and id attributes */
      /* TODO: Support arbitrary attributes via Agetattr with attribute name */
      if(sel->attr->name && stricmp((char *)sel->attr->name, "class") == 0)
      {  attrValue = elemClass;
      }
      else if(sel->attr->name && stricmp((char *)sel->attr->name, "id") == 0)
      {  attrValue = elemId;
      }
      else
      {  /* For other attributes, we'd need to query them by name */
         /* For now, return FALSE for unknown attributes */
         attrValue = NULL;
      }
      
      if(!MatchAttributeSelector(sel->attr, attrValue))
      {  return FALSE;
      }
   }
   
   /* Note: Pseudo-elements (::before, ::after) are not matched here as they
    * don't correspond to actual DOM elements. They would be handled during rendering. */
   
   return TRUE;
}

/* Match a single selector component to a body (for parent matching) */
static BOOL MatchSelectorComponentBody(struct CSSSelector *sel, void *body)
{  UBYTE *bodyName;
   UBYTE *bodyClass;
   UBYTE *bodyId;
   UBYTE *attrValue;
   
   if(!sel || !body) return FALSE;
   
   /* Match :root selector - matches HTML element */
   if(sel->type & CSS_SEL_ROOT)
   {  bodyName = (UBYTE *)Agetattr(body,AOBDY_TagName);
      return (bodyName && stricmp((char *)bodyName, "html") == 0) ? TRUE : FALSE;
   }
   
   /* Get body attributes */
   bodyName = (UBYTE *)Agetattr(body,AOBDY_TagName);
   bodyClass = (UBYTE *)Agetattr(body,AOBDY_Class);
   bodyId = (UBYTE *)Agetattr(body,AOBDY_Id);
   
   /* Match element name */
   if(sel->type & CSS_SEL_ELEMENT && sel->name)
   {  if(!bodyName || stricmp((char *)sel->name,(char *)bodyName) != 0)
      {  return FALSE;
      }
   }
   
   /* Match class - use proper word-boundary matching */
   if(sel->type & CSS_SEL_CLASS && sel->class)
   {  if(!MatchClassAttribute(bodyClass, sel->class))
      {  return FALSE;
      }
   }
   
   /* Match ID */
   if(sel->type & CSS_SEL_ID && sel->id)
   {  if(!bodyId || stricmp((char *)sel->id,(char *)bodyId) != 0)
      {  return FALSE;
      }
   }
   
   /* Match attribute selector */
   if(sel->type & CSS_SEL_ATTRIBUTE && sel->attr)
   {  /* Get attribute value - for now, we check class and id attributes */
      if(sel->attr->name && stricmp((char *)sel->attr->name, "class") == 0)
      {  attrValue = bodyClass;
      }
      else if(sel->attr->name && stricmp((char *)sel->attr->name, "id") == 0)
      {  attrValue = bodyId;
      }
      else
      {  /* For other attributes, we'd need to query them by name */
         attrValue = NULL;
      }
      
      if(!MatchAttributeSelector(sel->attr, attrValue))
      {  return FALSE;
      }
   }
   
   return TRUE;
}

/* Match a selector component to either an element or body */
static BOOL MatchSelectorComponentGeneric(struct CSSSelector *sel, void *obj)
{  struct Aobject *ao;
   short objtype;
   UBYTE *name;
   UBYTE *class;
   UBYTE *id;
   UBYTE *attrValue;
   
   if(!sel || !obj) return FALSE;
   
   /* Match :root selector - matches HTML element */
   if(sel->type & CSS_SEL_ROOT)
   {  ao = (struct Aobject *)obj;
      objtype = ao->objecttype;
      if(objtype == AOTP_BODY)
      {  name = (UBYTE *)Agetattr(obj, AOBDY_TagName);
      }
      else
      {  name = (UBYTE *)Agetattr(obj, AOELT_TagName);
      }
      return (name && stricmp((char *)name, "html") == 0) ? TRUE : FALSE;
   }
   
   /* Check object type to determine which attributes to use */
   ao = (struct Aobject *)obj;
   objtype = ao->objecttype;
   
   if(objtype == AOTP_BODY)
   {  /* It's a body - use body attributes */
      name = (UBYTE *)Agetattr(obj, AOBDY_TagName);
      class = (UBYTE *)Agetattr(obj, AOBDY_Class);
      id = (UBYTE *)Agetattr(obj, AOBDY_Id);
   }
   else
   {  /* Assume it's an element - use element attributes */
      name = (UBYTE *)Agetattr(obj, AOELT_TagName);
      class = (UBYTE *)Agetattr(obj, AOELT_Class);
      id = (UBYTE *)Agetattr(obj, AOELT_Id);
   }
   
   /* Match element name */
   if(sel->type & CSS_SEL_ELEMENT && sel->name)
   {  if(!name || stricmp((char *)sel->name, (char *)name) != 0)
      {  return FALSE;
      }
   }
   
   /* Match class - use proper word-boundary matching */
   if(sel->type & CSS_SEL_CLASS && sel->class)
   {  if(!MatchClassAttribute(class, sel->class))
      {  return FALSE;
      }
   }
   
   /* Match ID */
   if(sel->type & CSS_SEL_ID && sel->id)
   {  if(!id || stricmp((char *)sel->id, (char *)id) != 0)
      {  return FALSE;
      }
   }
   
   /* Match attribute selector */
   if(sel->type & CSS_SEL_ATTRIBUTE && sel->attr)
   {  /* Get attribute value - for now, we check class and id attributes */
      if(sel->attr->name && stricmp((char *)sel->attr->name, "class") == 0)
      {  attrValue = class;
      }
      else if(sel->attr->name && stricmp((char *)sel->attr->name, "id") == 0)
      {  attrValue = id;
      }
      else
      {  /* For other attributes, we'd need to query them by name */
         attrValue = NULL;
      }
      
      if(!MatchAttributeSelector(sel->attr, attrValue))
      {  return FALSE;
      }
   }
   
   return TRUE;
}

/* Match a selector to an element (handles descendant/child selectors) */
/* maxDepth limits recursion depth to prevent infinite loops and performance issues */
static BOOL MatchSelectorInternal(struct CSSSelector *sel,void *element,long maxDepth)
{  void *parentBody;
   void *ancestorBody;
   BOOL foundMatch;
   long depth;
   
   if(!sel || !element || maxDepth <= 0) return FALSE;
   
   /* If selector has a parent (descendant/child selector), we need to match the chain */
   if(sel->parent)
   {  /* Match current element against current selector */
      if(!MatchSelectorComponent(sel, element))
      {  return FALSE;
      }
      
      /* Get parent body */
      parentBody = (void *)Agetattr(element, AOBJ_Layoutparent);
      if(!parentBody)
      {  return FALSE;  /* No parent, can't match parent selector */
      }
      
      /* For child combinator (>), only immediate parent is valid */
      if(sel->combinator == CSS_COMB_CHILD)
      {  /* Check immediate parent only */
         if(!MatchSelectorComponentGeneric(sel->parent, parentBody))
         {  return FALSE;  /* Immediate parent doesn't match */
         }
         /* Matched! Continue up the chain if parent selector has its own parent */
         if(sel->parent->parent)
         {  /* Recursively match parent selector against parent body */
            return MatchSelectorInternal(sel->parent, parentBody, maxDepth - 1);
         }
         return TRUE;  /* Full chain matched */
      }
      /* For descendant combinator (space), traverse up ancestor chain */
      else if(sel->combinator == CSS_COMB_DESCENDANT)
      {  ancestorBody = parentBody;
         foundMatch = FALSE;
         depth = 0;
         
         /* Traverse up ancestor chain until we find a match or reach root */
         /* Limit depth to prevent excessive traversal on deep DOM trees */
         while(ancestorBody && depth < 50)
         {  /* Check if this ancestor matches the parent selector */
            if(MatchSelectorComponentGeneric(sel->parent, ancestorBody))
            {  foundMatch = TRUE;
               break;  /* Found matching ancestor */
            }
            
            /* Move up to next ancestor */
            ancestorBody = (void *)Agetattr(ancestorBody, AOBJ_Layoutparent);
            depth++;
         }
         
         if(!foundMatch)
         {  return FALSE;  /* No matching ancestor found */
         }
         
         /* Matched! Continue up the chain if parent selector has its own parent */
         if(sel->parent->parent)
         {  /* Recursively match parent selector against matching ancestor */
            return MatchSelectorInternal(sel->parent, ancestorBody, maxDepth - 1);
         }
         return TRUE;  /* Full chain matched */
      }
      else
      {  /* Unknown combinator - shouldn't happen, but be safe */
         return FALSE;
      }
   }
   else
   {  /* Simple selector - no parent chain */
      return MatchSelectorComponent(sel, element);
   }
}

/* Match a selector to an element (handles descendant/child selectors) */
/* Public wrapper with default depth limit */
static BOOL MatchSelector(struct CSSSelector *sel,void *element)
{  /* Limit recursion depth to 20 levels to prevent performance issues */
   return MatchSelectorInternal(sel, element, 20);
}

/* Apply a CSS property to an element */
static void ApplyProperty(struct Document *doc,void *element,struct CSSProperty *prop)
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
         fontName = ALLOCTYPE(UBYTE,len + 1,MEMF_FAST);
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
   /* float */
   else if(stricmp((char *)name,"float") == 0)
   {  UBYTE *floatValue;
      short halign;
      
      floatValue = value;
      /* Skip whitespace */
      while(*floatValue && isspace(*floatValue)) floatValue++;
      
      /* Parse float values */
      if(stricmp((char *)floatValue,"left") == 0)
      {  /* Set floating left */
         halign = HALIGN_FLOATLEFT;
         Asetattrs(element,AOELT_Floating,halign,TAG_END);
      }
      else if(stricmp((char *)floatValue,"right") == 0)
      {  /* Set floating right */
         halign = HALIGN_FLOATRIGHT;
         Asetattrs(element,AOELT_Floating,halign,TAG_END);
      }
      else if(stricmp((char *)floatValue,"none") == 0)
      {  /* Clear float */
         Asetattrs(element,AOELT_Floating,0,TAG_END);
      }
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
   /* color */
   else if(stricmp((char *)name,"color") == 0)
   {  ULONG colorrgb;
      struct Colorinfo *ci;
      
      if(doc)
      {  colorrgb = ParseHexColor(value);
         if(colorrgb != ~0)
         {  ci = Finddoccolor(doc, colorrgb);
            if(ci)
            {  Asetattrs(element, AOELT_Color, ci, TAG_END);
            }
         }
      }
   }
   /* font-weight */
   else if(stricmp((char *)name,"font-weight") == 0)
   {  USHORT currentStyle;
      USHORT newStyle;
      
      currentStyle = (USHORT)Agetattr(element, AOELT_Style);
      newStyle = currentStyle;
      
      if(stricmp((char *)value,"bold") == 0 || stricmp((char *)value,"700") == 0 || stricmp((char *)value,"bolder") == 0)
      {  newStyle |= FSF_BOLD;
      }
      else if(stricmp((char *)value,"normal") == 0 || stricmp((char *)value,"400") == 0 || stricmp((char *)value,"lighter") == 0)
      {  newStyle &= ~FSF_BOLD;
      }
      else
      {  /* Try to parse numeric value */
         long weightValue;
         struct Number num;
         weightValue = ParseCSSLengthValue(value, &num);
         if(weightValue >= 600)
         {  newStyle |= FSF_BOLD;
         }
         else if(weightValue >= 0 && weightValue < 600)
         {  newStyle &= ~FSF_BOLD;
         }
      }
      
      if(newStyle != currentStyle)
      {  Asetattrs(element, AOELT_Style, newStyle, TAG_END);
      }
   }
   /* font-style */
   else if(stricmp((char *)name,"font-style") == 0)
   {  USHORT currentStyle;
      USHORT newStyle;
      
      currentStyle = (USHORT)Agetattr(element, AOELT_Style);
      newStyle = currentStyle;
      
      if(stricmp((char *)value,"italic") == 0 || stricmp((char *)value,"oblique") == 0)
      {  newStyle |= FSF_ITALIC;
      }
      else if(stricmp((char *)value,"normal") == 0)
      {  newStyle &= ~FSF_ITALIC;
      }
      
      if(newStyle != currentStyle)
      {  Asetattrs(element, AOELT_Style, newStyle, TAG_END);
      }
   }
   /* text-decoration */
   else if(stricmp((char *)name,"text-decoration") == 0)
   {  USHORT currentStyle;
      USHORT newStyle;
      UBYTE *decValue;
      UBYTE *pdec;
      
      currentStyle = (USHORT)Agetattr(element, AOELT_Style);
      newStyle = currentStyle;
      
      decValue = Dupstr(value, -1);
      if(decValue)
      {  pdec = decValue;
         while(*pdec)
         {  SkipWhitespace(&pdec);
            if(!*pdec) break;
            
            if(stricmp((char *)pdec,"underline") == 0)
            {  newStyle |= FSF_UNDERLINED;
            }
            else if(stricmp((char *)pdec,"line-through") == 0 || stricmp((char *)pdec,"strikethrough") == 0)
            {  newStyle |= FSF_STRIKE;
            }
            else if(stricmp((char *)pdec,"none") == 0)
            {  newStyle &= ~(FSF_UNDERLINED | FSF_STRIKE);
            }
            
            /* Skip to next space or end */
            while(*pdec && !isspace(*pdec)) pdec++;
         }
         FREE(decValue);
      }
      
      if(newStyle != currentStyle)
      {  Asetattrs(element, AOELT_Style, newStyle, TAG_END);
      }
   }
}

/* Helper structure for sorting rules by specificity */
struct RuleWithSpecificity
{  struct MinNode node;
   struct CSSRule *rule;
   USHORT maxSpecificity;  /* Maximum specificity of matching selectors */
};

/* Apply CSS to an element */
void ApplyCSSToElement(struct Document *doc,void *element)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct MinList matches;
   struct RuleWithSpecificity *ruleSpec;
   struct RuleWithSpecificity *current;
   struct RuleWithSpecificity *insertAfter;
   struct CSSStylesheet *sheet;
   USHORT maxSpec;
   
   if(!doc || !element || !doc->cssstylesheet) return;
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   
   NEWLIST(&matches);
   
   /* Find all matching rules and calculate their maximum specificity */
   /* Optimize: Check element attributes once to avoid repeated Agetattr calls */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  maxSpec = 0;
      for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  /* Quick rejection: If selector has an ID and element doesn't match, skip */
         if(sel->type & CSS_SEL_ID && sel->id)
         {  UBYTE *elemId;
            short objtype;
            struct Aobject *ao;
            
            ao = (struct Aobject *)element;
            objtype = ao->objecttype;
            if(objtype == AOTP_BODY)
            {  elemId = (UBYTE *)Agetattr(element, AOBDY_Id);
            }
            else
            {  elemId = (UBYTE *)Agetattr(element, AOELT_Id);
            }
            if(!elemId || stricmp((char *)sel->id, (char *)elemId) != 0)
            {  continue;  /* ID doesn't match, skip this selector */
            }
         }
         
         if(MatchSelector(sel,element))
         {  /* Find maximum specificity among matching selectors */
            if(sel->specificity > maxSpec)
            {  maxSpec = sel->specificity;
            }
            /* Early exit: If we found a match, we can stop checking other selectors in this rule */
            /* (One matching selector is enough to apply the rule) */
            break;
         }
      }
      
      /* If at least one selector matched, add rule with its specificity */
      if(maxSpec > 0)
      {  ruleSpec = ALLOCSTRUCT(RuleWithSpecificity, 1, MEMF_FAST);
         if(ruleSpec)
         {  ruleSpec->rule = rule;
            ruleSpec->maxSpecificity = maxSpec;
            
            /* Insert sorted by specificity (lower first, so higher wins when applied last) */
            /* For same specificity, maintain document order (last in document wins) */
            insertAfter = NULL;
            for(current = (struct RuleWithSpecificity *)matches.mlh_Head;
                (struct MinNode *)current->node.mln_Succ;
                current = (struct RuleWithSpecificity *)current->node.mln_Succ)
            {  if(current->maxSpecificity > maxSpec)
               {  /* Insert before current (after insertAfter, which is the previous node) */
                  break;
               }
               insertAfter = current; /* Continue to maintain document order for same specificity */
            }
            
            if(insertAfter)
            {  /* INSERT inserts after the specified node */
               INSERT(&matches, (struct MinNode *)insertAfter, (struct MinNode *)ruleSpec);
            }
            else
            {  /* No node with lower or equal specificity, add at head */
               ADDHEAD(&matches, (struct MinNode *)ruleSpec);
            }
         }
      }
   }
   
   /* Apply properties from matching rules sorted by specificity */
   /* Rules with same specificity maintain document order (last wins) */
   for(ruleSpec = (struct RuleWithSpecificity *)matches.mlh_Head;
       (struct MinNode *)ruleSpec->node.mln_Succ;
       ruleSpec = (struct RuleWithSpecificity *)ruleSpec->node.mln_Succ)
   {  rule = ruleSpec->rule;
      for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
         (struct MinNode *)prop->node.mln_Succ;
         prop = (struct CSSProperty *)prop->node.mln_Succ)
      {  ApplyProperty(doc,element,prop);
      }
      /* Free the helper structure */
      REMOVE((struct MinNode *)ruleSpec);
      FREE(ruleSpec);
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
   
   /* Remove and free all rules from the list */
   while((rule = (struct CSSRule *)REMHEAD(&sheet->rules)))
   {  /* Remove and free all selectors from the rule's list */
      while((sel = (struct CSSSelector *)REMHEAD(&rule->selectors)))
      {  if(sel->name) FREE(sel->name);
         if(sel->class) FREE(sel->class);
         if(sel->id) FREE(sel->id);
         if(sel->pseudo) FREE(sel->pseudo);
         if(sel->pseudoElement) FREE(sel->pseudoElement);
         if(sel->attr)
         {  if(sel->attr->name) FREE(sel->attr->name);
            if(sel->attr->value) FREE(sel->attr->value);
            FREE(sel->attr);
         }
         FREE(sel);
      }
      /* Remove and free all properties from the rule's list */
      while((prop = (struct CSSProperty *)REMHEAD(&rule->properties)))
      {  if(prop->name) FREE(prop->name);
         if(prop->value) FREE(prop->value);
         FREE(prop);
      }
      FREE(rule);
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
      {  ApplyProperty(doc,element,prop);
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
      {           /* Apply padding shorthand */
         if(stricmp((char *)prop->name,"padding") == 0)
         {  UBYTE *paddingP;
            UBYTE *tokenStart;
            UBYTE *tokenEnd;
            long tokenLen;
            UBYTE *tokenBuf;
            UBYTE *paddingTokens[4];
            long paddingCount;
            long paddingTop;
            long paddingRight;
            long paddingBottom;
            long paddingLeft;
            long j;
            struct Number paddingNum;
            
            paddingP = prop->value;
            paddingCount = 0;
            paddingTop = paddingRight = paddingBottom = paddingLeft = 0;
            for(j = 0; j < 4; j++) paddingTokens[j] = NULL;
            
            /* Parse padding values - can be 1, 2, 3, or 4 values */
            for(j = 0; j < 4 && paddingP && *paddingP; j++)
            {  while(*paddingP && isspace(*paddingP)) paddingP++;
               if(!*paddingP) break;
               tokenStart = paddingP;
               while(*paddingP && !isspace(*paddingP)) paddingP++;
               tokenEnd = paddingP;
               tokenLen = tokenEnd - tokenStart;
               if(tokenLen > 0)
                  {  tokenBuf = ALLOCTYPE(UBYTE,tokenLen + 1,MEMF_FAST);
                  if(tokenBuf)
                  {  memmove(tokenBuf,tokenStart,tokenLen);
                     tokenBuf[tokenLen] = '\0';
                     paddingTokens[paddingCount] = tokenBuf;
                     paddingCount++;
                  }
               }
            }
            
            /* Apply padding values based on count */
            if(paddingCount >= 1)
            {  paddingTop = ParseCSSLengthValue(paddingTokens[0],&paddingNum);
               if(paddingCount == 1)
               {  paddingRight = paddingBottom = paddingLeft = paddingTop;
               }
               else if(paddingCount == 2)
               {  paddingBottom = paddingTop;
                  paddingRight = ParseCSSLengthValue(paddingTokens[1],&paddingNum);
                  paddingLeft = paddingRight;
               }
               else if(paddingCount == 3)
               {  paddingRight = ParseCSSLengthValue(paddingTokens[1],&paddingNum);
                  paddingLeft = paddingRight;
                  paddingBottom = ParseCSSLengthValue(paddingTokens[2],&paddingNum);
               }
               else if(paddingCount == 4)
               {  paddingRight = ParseCSSLengthValue(paddingTokens[1],&paddingNum);
                  paddingBottom = ParseCSSLengthValue(paddingTokens[2],&paddingNum);
                  paddingLeft = ParseCSSLengthValue(paddingTokens[3],&paddingNum);
               }
               
               /* Apply padding values to body */
               if(paddingTop >= 0 && paddingNum.type == NUMBER_NUMBER)
               {  Asetattrs(body,AOBDY_PaddingTop,paddingTop,TAG_END);
               }
               if(paddingRight >= 0 && paddingNum.type == NUMBER_NUMBER)
               {  Asetattrs(body,AOBDY_PaddingRight,paddingRight,TAG_END);
               }
               if(paddingBottom >= 0 && paddingNum.type == NUMBER_NUMBER)
               {  Asetattrs(body,AOBDY_PaddingBottom,paddingBottom,TAG_END);
               }
               if(paddingLeft >= 0 && paddingNum.type == NUMBER_NUMBER)
               {  Asetattrs(body,AOBDY_PaddingLeft,paddingLeft,TAG_END);
               }
            }
            
            /* Free temporary token buffers */
            for(j = 0; j < paddingCount; j++)
            {  if(paddingTokens[j]) FREE(paddingTokens[j]);
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
                     {  url = ALLOCTYPE(UBYTE,len + 1,MEMF_FAST);
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
               else
               {  UBYTE *styleStr;
                  UBYTE *end;
                  long len;
                  len = pval - token;
                  end = token + len;
                  styleStr = ALLOCTYPE(UBYTE, len + 1, MEMF_FAST);
                  if(styleStr)
                  {  memmove(styleStr, token, len);
                     styleStr[len] = '\0';
                     Asetattrs(body, AOBDY_BorderStyle, styleStr, TAG_END);
                  }
               }
            }
            
            /* Store border width and color */
            if(borderWidth >= 0 && num.type == NUMBER_NUMBER)
            {  Asetattrs(body, AOBDY_BorderWidth, borderWidth, TAG_END);
            }
            if(borderColor != ~0)
            {  ci = Finddoccolor(doc, borderColor);
               if(ci)
               {  Asetattrs(body, AOBDY_BorderColor, ci, TAG_END);
               }
            }
         }
         /* Apply border-style */
         else if(stricmp((char *)prop->name,"border-style") == 0)
         {  UBYTE *styleStr;
            styleStr = Dupstr(prop->value, -1);
            if(styleStr)
            {  Asetattrs(body, AOBDY_BorderStyle, styleStr, TAG_END);
            }
         }
         /* Apply border-color */
         else if(stricmp((char *)prop->name,"border-color") == 0)
         {  ULONG colorrgb;
            struct Colorinfo *ci;
            colorrgb = ParseHexColor(prop->value);
            if(colorrgb != ~0)
            {  ci = Finddoccolor(doc,colorrgb);
               if(ci)
               {  Asetattrs(body, AOBDY_BorderColor, ci, TAG_END);
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
         /* Apply cursor */
         else if(stricmp((char *)prop->name,"cursor") == 0)
         {  UBYTE *cursorStr;
            cursorStr = Dupstr(prop->value, -1);
            if(cursorStr)
            {  Asetattrs(body, AOBDY_Cursor, cursorStr, TAG_END);
            }
         }
         /* Apply text-transform */
         else if(stricmp((char *)prop->name,"text-transform") == 0)
         {  UBYTE *transformStr;
            transformStr = Dupstr(prop->value, -1);
            if(transformStr)
            {  Asetattrs(body, AOBDY_TextTransform, transformStr, TAG_END);
            }
         }
         /* Apply white-space */
         else if(stricmp((char *)prop->name,"white-space") == 0)
         {  UBYTE *whitespaceStr;
            whitespaceStr = Dupstr(prop->value, -1);
            if(whitespaceStr)
            {  Asetattrs(body, AOBDY_WhiteSpace, whitespaceStr, TAG_END);
               /* Also apply to AOBDY_Nobr for nowrap */
               if(stricmp((char *)whitespaceStr, "nowrap") == 0)
               {  Asetattrs(body, AOBDY_Nobr, TRUE, TAG_END);
               }
               else if(stricmp((char *)whitespaceStr, "normal") == 0 || 
                       stricmp((char *)whitespaceStr, "pre-wrap") == 0 || 
                       stricmp((char *)whitespaceStr, "pre-line") == 0)
               {  Asetattrs(body, AOBDY_Nobr, FALSE, TAG_END);
               }
               /* Note: "pre" is handled by STYLE_PRE, not white-space */
            }
         }
         /* Apply text-transform */
         else if(stricmp((char *)prop->name,"text-transform") == 0)
         {  UBYTE *transformStr;
            transformStr = Dupstr(prop->value, -1);
            if(transformStr)
            {  Asetattrs(body, AOBDY_TextTransform, transformStr, TAG_END);
               /* Also set document-level text-transform for compatibility */
               if(stricmp((char *)transformStr, "uppercase") == 0)
               {  doc->texttransform = 1;
               }
               else if(stricmp((char *)transformStr, "lowercase") == 0)
               {  doc->texttransform = 2;
               }
               else if(stricmp((char *)transformStr, "capitalize") == 0)
               {  doc->texttransform = 3;
               }
               else if(stricmp((char *)transformStr, "none") == 0)
               {  doc->texttransform = 0;
               }
            }
         }
         /* Apply font-family */
         else if(stricmp((char *)prop->name,"font-family") == 0)
         {  fontFace = NULL;
            comma = (UBYTE *)strchr((char *)prop->value,',');
            if(comma)
            {  long len = comma - prop->value;
               fontFace = ALLOCTYPE(UBYTE,len + 1,MEMF_FAST);
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
         {  /* Don't apply color to body font color for anchor tags.
              * Link colors are handled at the document level via ApplyCSSToLinkColors.
              * Setting color on the body would incorrectly affect all body text, not just the link. */
            if(!tagname || stricmp((char *)tagname,"A") != 0)
            {  colorrgb = ParseHexColor(prop->value);
               if(colorrgb != ~0)
               {  ci = Finddoccolor(doc,colorrgb);
                  if(ci)
                  {  Asetattrs(body,AOBDY_Fontcolor,ci,TAG_END);
                  }
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
                  tokenBuf = ALLOCTYPE(UBYTE,tokenLen + 1,MEMF_FAST);
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
         /* Apply width */
         else if(stricmp((char *)prop->name,"width") == 0)
         {  long widthValue;
            struct Number widthNum;
            
            widthValue = ParseCSSLengthValue(prop->value, &widthNum);
            if(widthValue >= 0 && widthNum.type != NUMBER_NONE)
            {  /* Apply width to body object */
               Asetattrs(body, AOBJ_Width, widthValue, TAG_END);
            }
         }
         /* Apply height */
         else if(stricmp((char *)prop->name,"height") == 0)
         {  long heightValue;
            struct Number heightNum;
            
            heightValue = ParseCSSLengthValue(prop->value, &heightNum);
            if(heightValue >= 0 && heightNum.type != NUMBER_NONE)
            {  /* Apply height to body object */
               Asetattrs(body, AOBJ_Height, heightValue, TAG_END);
            }
         }
         /* Apply position */
         else if(stricmp((char *)prop->name,"position") == 0)
         {  UBYTE *posValue;
            UBYTE *posStr;
            
            posValue = prop->value;
            SkipWhitespace(&posValue);
            
            posStr = Dupstr(posValue, -1);
            if(posStr)
            {  Asetattrs(body, AOBDY_Position, posStr, TAG_END);
            }
         }
         /* Apply top */
         else if(stricmp((char *)prop->name,"top") == 0)
         {  long topValue;
            struct Number topNum;
            
            topValue = ParseCSSLengthValue(prop->value, &topNum);
            if(topValue >= 0 && topNum.type == NUMBER_NUMBER)
            {  /* Apply top position */
               Asetattrs(body, AOBJ_Top, topValue, TAG_END);
            }
         }
         /* Apply left */
         else if(stricmp((char *)prop->name,"left") == 0)
         {  long leftValue;
            struct Number leftNum;
            
            leftValue = ParseCSSLengthValue(prop->value, &leftNum);
            if(leftValue >= 0 && leftNum.type == NUMBER_NUMBER)
            {  /* Apply left position */
               Asetattrs(body, AOBJ_Left, leftValue, TAG_END);
            }
         }
         /* Apply right */
         else if(stricmp((char *)prop->name,"right") == 0)
         {  long rightValue;
            struct Number rightNum;
            
            rightValue = ParseCSSLengthValue(prop->value, &rightNum);
            if(rightValue >= 0 && rightNum.type == NUMBER_NUMBER)
            {  /* Store right position - will be calculated during layout */
               Asetattrs(body, AOBDY_Right, rightValue, TAG_END);
            }
         }
         /* Apply bottom */
         else if(stricmp((char *)prop->name,"bottom") == 0)
         {  long bottomValue;
            struct Number bottomNum;
            
            bottomValue = ParseCSSLengthValue(prop->value, &bottomNum);
            if(bottomValue >= 0 && bottomNum.type == NUMBER_NUMBER)
            {  /* Store bottom position - will be calculated during layout */
               Asetattrs(body, AOBDY_Bottom, bottomValue, TAG_END);
            }
         }
         /* Apply z-index */
         else if(stricmp((char *)prop->name,"z-index") == 0)
         {  long zIndexValue;
            UBYTE *zval;
            
            zval = prop->value;
            SkipWhitespace(&zval);
            
            if(stricmp((char *)zval,"auto") == 0)
            {  /* Auto z-index (default) - store as 0 */
               zIndexValue = 0;
            }
            else
            {  /* Parse numeric z-index value */
               zIndexValue = strtol((char *)zval, NULL, 10);
            }
            Asetattrs(body, AOBDY_ZIndex, zIndexValue, TAG_END);
         }
         /* Apply display */
         else if(stricmp((char *)prop->name,"display") == 0)
         {  UBYTE *dispValue;
            UBYTE *dispStr;
            
            dispValue = prop->value;
            SkipWhitespace(&dispValue);
            
            dispStr = Dupstr(dispValue, -1);
            if(dispStr)
            {  Asetattrs(body, AOBDY_Display, dispStr, TAG_END);
            }
         }
         /* Apply vertical-align */
         else if(stricmp((char *)prop->name,"vertical-align") == 0)
         {  UBYTE *valignValue;
            short valign;
            
            valignValue = prop->value;
            SkipWhitespace(&valignValue);
            
            valign = -1;
            if(stricmp((char *)valignValue,"top") == 0)
            {  valign = VALIGN_TOP;
            }
            else if(stricmp((char *)valignValue,"middle") == 0)
            {  valign = VALIGN_MIDDLE;
            }
            else if(stricmp((char *)valignValue,"bottom") == 0)
            {  valign = VALIGN_BOTTOM;
            }
            else if(stricmp((char *)valignValue,"baseline") == 0)
            {  valign = VALIGN_BASELINE;
            }
            
            if(valign >= 0)
            {  Asetattrs(body, AOBDY_VerticalAlign, valign, TAG_END);
            }
         }
         /* Apply clear */
         else if(stricmp((char *)prop->name,"clear") == 0)
         {  UBYTE *clearValue;
            UBYTE *clearStr;
            
            clearValue = prop->value;
            SkipWhitespace(&clearValue);
            
            clearStr = Dupstr(clearValue, -1);
            if(clearStr)
            {  Asetattrs(body, AOBDY_Clear, clearStr, TAG_END);
            }
         }
         /* Apply overflow */
         else if(stricmp((char *)prop->name,"overflow") == 0)
         {  UBYTE *overflowValue;
            UBYTE *overflowStr;
            
            overflowValue = prop->value;
            SkipWhitespace(&overflowValue);
            
            overflowStr = Dupstr(overflowValue, -1);
            if(overflowStr)
            {  Asetattrs(body, AOBDY_Overflow, overflowStr, TAG_END);
            }
         }
         /* Apply list-style */
         else if(stricmp((char *)prop->name,"list-style") == 0)
         {  UBYTE *listStyleValue;
            UBYTE *listStyleStr;
            
            listStyleValue = prop->value;
            SkipWhitespace(&listStyleValue);
            
            listStyleStr = Dupstr(listStyleValue, -1);
            if(listStyleStr)
            {  Asetattrs(body, AOBDY_ListStyle, listStyleStr, TAG_END);
            }
         }
         /* Apply min-width */
         else if(stricmp((char *)prop->name,"min-width") == 0)
         {  long minWidthValue;
            struct Number minWidthNum;
            
            minWidthValue = ParseCSSLengthValue(prop->value, &minWidthNum);
            if(minWidthValue >= 0 && minWidthNum.type == NUMBER_NUMBER)
            {  Asetattrs(body, AOBDY_MinWidth, minWidthValue, TAG_END);
            }
         }
         /* Apply max-width */
         else if(stricmp((char *)prop->name,"max-width") == 0)
         {  long maxWidthValue;
            struct Number maxWidthNum;
            
            maxWidthValue = ParseCSSLengthValue(prop->value, &maxWidthNum);
            if(maxWidthValue >= 0 && maxWidthNum.type == NUMBER_NUMBER)
            {  Asetattrs(body, AOBDY_MaxWidth, maxWidthValue, TAG_END);
            }
         }
         /* Apply min-height */
         else if(stricmp((char *)prop->name,"min-height") == 0)
         {  long minHeightValue;
            struct Number minHeightNum;
            
            minHeightValue = ParseCSSLengthValue(prop->value, &minHeightNum);
            if(minHeightValue >= 0 && minHeightNum.type == NUMBER_NUMBER)
            {  Asetattrs(body, AOBDY_MinHeight, minHeightValue, TAG_END);
            }
         }
         /* Apply max-height */
         else if(stricmp((char *)prop->name,"max-height") == 0)
         {  long maxHeightValue;
            struct Number maxHeightNum;
            
            maxHeightValue = ParseCSSLengthValue(prop->value, &maxHeightNum);
            if(maxHeightValue >= 0 && maxHeightNum.type == NUMBER_NUMBER)
            {  Asetattrs(body, AOBDY_MaxHeight, maxHeightValue, TAG_END);
            }
         }
         /* Apply float - Note: Body objects don't directly support floating */
         /* But we parse it here for IsDivInline to detect float:left */
         /* The actual floating is handled by preventing line breaks in Dodiv */
         else if(stricmp((char *)prop->name,"float") == 0)
         {  /* Float is parsed but not directly applied to body objects */
            /* IsDivInline will check for float:left and prevent line breaks */
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
   double dval;
   long ival;
   UBYTE *endptr;
   
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
   {  /* Use strtod to parse decimal values (handles .5, 1.5, 0.5, etc.) */
      dval = strtod((char *)pval, (char **)&endptr);
      if(endptr != pval)
      {  /* Successfully parsed a number */
         /* Convert double to long, rounding */
         ival = (long)(dval + (dval >= 0 ? 0.5 : -0.5));
         num->n = ival;
         /* Check what comes after the number */
         if(*endptr)
         {  c = *endptr;
            if(c == '%') num->type = NUMBER_PERCENT;
            else if(c == '*') num->type = NUMBER_RELATIVE;
            else if(sign) num->type = NUMBER_SIGNED;
            else num->type = NUMBER_NUMBER;
            m = 2;
         }
         else
         {  /* No character - just a number */
            if(sign) num->type = NUMBER_SIGNED;
            else num->type = NUMBER_NUMBER;
            m = 1;
         }
      }
      else
      {  /* Fallback: try integer parsing with sscanf */
         m = sscanf((char *)pval," %ld%c",&num->n,&c);
         if(m)
         {  if(c == '%') num->type = NUMBER_PERCENT;
            else if(c == '*') num->type = NUMBER_RELATIVE;
            else if(sign) num->type = NUMBER_SIGNED;
            else num->type = NUMBER_NUMBER;
         }
      }
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
   
   if(!doc || !link || !style) return;
   
   p = style;
   while(*p)
   {  SkipWhitespace(&p);
      if(!*p) break;
      
      /* Parse property */
      prop = ParseProperty(doc,&p);
      if(prop && prop->name && prop->value)
      {           /* Apply text-decoration: none */
         if(stricmp((char *)prop->name,"text-decoration") == 0)
         {  if(stricmp((char *)prop->value,"none") == 0)
            {  Asetattrs(link,AOLNK_NoDecoration,TRUE,TAG_END);
            }
         }
         /* Note: color is not handled here for inline styles on links.
          * Link colors are handled at the document level via ApplyCSSToLinkColors.
          * Setting color on the body would incorrectly affect all body text, not just the link. */
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

/* Extract background-color from external CSS stylesheet rules matching class/ID */
struct Colorinfo *ExtractBackgroundColorFromRules(struct Document *doc,UBYTE *class,UBYTE *id,UBYTE *tagname)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct CSSStylesheet *sheet;
   BOOL matches;
   ULONG colorrgb;
   struct Colorinfo *ci;
   
   if(!doc || !doc->cssstylesheet) return NULL;
   
   ci = NULL;
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   
   /* Find matching CSS rules and extract background-color */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  matches = TRUE;
         
         /* Match element name */
         if(sel->type & CSS_SEL_ELEMENT && sel->name)
         {  if(!tagname || stricmp((char *)sel->name,(char *)tagname) != 0)
            {  matches = FALSE;
            }
         }
         
         /* Match class */
         if(matches && sel->type & CSS_SEL_CLASS && sel->class)
         {  if(!MatchClassAttribute(class, sel->class))
            {  matches = FALSE;
            }
         }
         
         /* Match ID */
         if(matches && sel->type & CSS_SEL_ID && sel->id)
         {  if(!id || stricmp((char *)sel->id,(char *)id) != 0)
            {  matches = FALSE;
            }
         }
         
         /* Skip rules with pseudo-classes */
         if(matches && (sel->type & CSS_SEL_PSEUDO) && sel->pseudo)
         {  matches = FALSE;
         }
         
         /* If selector matches, extract background-color */
         if(matches)
         {  for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
               (struct MinNode *)prop->node.mln_Succ;
               prop = (struct CSSProperty *)prop->node.mln_Succ)
            {  if(prop->name && prop->value && 
                  stricmp((char *)prop->name,"background-color") == 0)
               {  colorrgb = ParseHexColor(prop->value);
                  if(colorrgb != ~0)
                  {  ci = Finddoccolor(doc,colorrgb);
                     /* Return first matching background-color */
                     if(ci) return ci;
                  }
               }
            }
         }
      }
   }
   
   return ci;
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

/* Apply CSS properties specific to table cells from external stylesheet rules */
void ApplyCSSToTableCellFromRules(struct Document *doc,void *table,UBYTE *class,UBYTE *id,UBYTE *tagname)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct CSSStylesheet *sheet;
   BOOL matches;
   long widthValue;
   long heightValue;
   short valign;
   short halign;
   ULONG wtag;
   ULONG htag;
   struct Number num;
   ULONG colorrgb;
   struct Colorinfo *cssBgcolor;
   
   if(!doc || !table || !doc->cssstylesheet) return;
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   wtag = TAG_IGNORE;
   htag = TAG_IGNORE;
   widthValue = -1;
   heightValue = -1;
   valign = -1;
   halign = -1;
   cssBgcolor = NULL;
   
   /* Find matching CSS rules and extract table-cell-specific properties */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  matches = TRUE;
         
         /* Match element name */
         if(sel->type & CSS_SEL_ELEMENT && sel->name)
         {  if(!tagname || stricmp((char *)sel->name,(char *)tagname) != 0)
            {  matches = FALSE;
            }
         }
         
         /* Match class */
         if(matches && sel->type & CSS_SEL_CLASS && sel->class)
         {  if(!MatchClassAttribute(class, sel->class))
            {  matches = FALSE;
            }
         }
         
         /* Match ID */
         if(matches && sel->type & CSS_SEL_ID && sel->id)
         {  if(!id || stricmp((char *)sel->id,(char *)id) != 0)
            {  matches = FALSE;
            }
         }
         
         /* Skip rules with pseudo-classes */
         if(matches && (sel->type & CSS_SEL_PSEUDO) && sel->pseudo)
         {  matches = FALSE;
         }
         
         /* If selector matches, extract table-cell-specific properties */
         if(matches)
         {  for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
               (struct MinNode *)prop->node.mln_Succ;
               prop = (struct CSSProperty *)prop->node.mln_Succ)
            {  if(prop->name && prop->value)
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
                  {  if(stricmp((char *)prop->value,"center") == 0)
                     {  halign = HALIGN_CENTER;
                     }
                     else if(stricmp((char *)prop->value,"left") == 0)
                     {  halign = HALIGN_LEFT;
                     }
                     else if(stricmp((char *)prop->value,"right") == 0)
                     {  halign = HALIGN_RIGHT;
                     }
                  }
                  /* Extract background-color for table cells */
                  else if(stricmp((char *)prop->name,"background-color") == 0)
                  {  colorrgb = ParseHexColor(prop->value);
                     if(colorrgb != ~0)
                     {  cssBgcolor = Finddoccolor(doc,colorrgb);
                     }
                  }
               }
            }
         }
      }
   }
   
   /* Apply extracted values to table cell */
   if(wtag != TAG_IGNORE && widthValue >= 0)
   {  Asetattrs(table,wtag,widthValue,TAG_END);
   }
   if(htag != TAG_IGNORE && heightValue >= 0)
   {  Asetattrs(table,htag,heightValue,TAG_END);
   }
   if(valign >= 0)
   {  Asetattrs(table,AOTAB_Valign,valign,TAG_END);
   }
   if(halign >= 0)
   {  Asetattrs(table,AOTAB_Halign,halign,TAG_END);
   }
   if(cssBgcolor)
   {  Asetattrs(table,AOTAB_Bgcolor,cssBgcolor,TAG_END);
   }
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
   if(wtag != TAG_IGNORE && widthValue >= 0)
   {  /* Apply width value (can be pixel or percentage) */
      Asetattrs(table,wtag,widthValue,TAG_END);
   }
   if(htag != TAG_IGNORE && heightValue >= 0)
   {  /* Apply height value (can be pixel or percentage) */
      Asetattrs(table,htag,heightValue,TAG_END);
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

/* Apply CSS properties to a table from external stylesheet rules */
void ApplyCSSToTableFromRules(struct Document *doc,void *table,UBYTE *class,UBYTE *id)
{  struct CSSRule *rule;
   struct CSSSelector *sel;
   struct CSSProperty *prop;
   struct CSSStylesheet *sheet;
   BOOL matches;
   struct Number num;
   long borderValue;
   long widthValue;
   long cellpaddingValue;
   ULONG wtag;
   struct Colorinfo *cssBgcolor;
   ULONG colorrgb;
   struct Colorinfo *ci;
   
   if(!doc || !table || !doc->cssstylesheet) return;
   
   sheet = (struct CSSStylesheet *)doc->cssstylesheet;
   wtag = TAG_IGNORE;
   borderValue = -1;
   widthValue = -1;
   cellpaddingValue = -1;
   cssBgcolor = NULL;
   
   /* Find matching CSS rules and apply properties */
   for(rule = (struct CSSRule *)sheet->rules.mlh_Head;
       (struct MinNode *)rule->node.mln_Succ;
       rule = (struct CSSRule *)rule->node.mln_Succ)
   {  for(sel = (struct CSSSelector *)rule->selectors.mlh_Head;
         (struct MinNode *)sel->node.mln_Succ;
         sel = (struct CSSSelector *)sel->node.mln_Succ)
      {  matches = TRUE;
         
         /* Match element name (should be "table") */
         if(sel->type & CSS_SEL_ELEMENT && sel->name)
         {  if(stricmp((char *)sel->name,"table") != 0)
            {  matches = FALSE;
            }
         }
         
         /* Match class */
         if(matches && sel->type & CSS_SEL_CLASS && sel->class)
         {  if(!MatchClassAttribute(class, sel->class))
            {  matches = FALSE;
            }
         }
         
         /* Match ID */
         if(matches && sel->type & CSS_SEL_ID && sel->id)
         {  if(!id || stricmp((char *)sel->id,(char *)id) != 0)
            {  matches = FALSE;
            }
         }
         
         /* Skip rules with pseudo-classes */
         if(matches && (sel->type & CSS_SEL_PSEUDO) && sel->pseudo)
         {  matches = FALSE;
         }
         
         /* If selector matches, apply properties */
         if(matches)
         {  for(prop = (struct CSSProperty *)rule->properties.mlh_Head;
               (struct MinNode *)prop->node.mln_Succ;
               prop = (struct CSSProperty *)prop->node.mln_Succ)
            {  if(!prop->name || !prop->value) continue;
               
               /* Extract border */
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
               /* Extract background-color */
               else if(stricmp((char *)prop->name,"background-color") == 0)
               {  colorrgb = ParseHexColor(prop->value);
                  if(colorrgb != ~0)
                  {  cssBgcolor = Finddoccolor(doc,colorrgb);
                  }
               }
               /* Extract border-color */
               else if(stricmp((char *)prop->name,"border-color") == 0)
               {  colorrgb = ParseHexColor(prop->value);
                  if(colorrgb != ~0)
                  {  ci = Finddoccolor(doc,colorrgb);
                     if(ci)
                     {  Asetattrs(table,AOTAB_Bordercolor,ci,TAG_END);
                     }
                  }
               }
            }
         }
      }
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
   if(cssBgcolor)
   {  Asetattrs(table,AOTAB_Bgcolor,cssBgcolor,TAG_END);
   }
}

