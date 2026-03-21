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

/* markdown.c - AWeb markdown parser */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include "aweb.h"
#include "html.h"
#include "application.h"
#include "docprivate.h"

#define MAXATTRS 40
static struct Tagattr tagattr[MAXATTRS];

static LIST(Tagattr) attrs;
static short nextattr;

/* Forward declarations */
static struct Tagattr *Nextattr(struct Document *doc);
static BOOL ProcessMarkdownLine(struct Document *doc, UBYTE *line, long length, USHORT *list_state, BOOL *in_paragraph);
static BOOL ProcessMarkdownText(struct Document *doc, UBYTE *text, long length);
static void EscapeHtmlEntities(struct Document *doc, UBYTE *text, long length);

/* Get next attribute structure */
static struct Tagattr *Nextattr(struct Document *doc)
{  struct Tagattr *ta;
   if(nextattr==MAXATTRS) REMOVE(&tagattr[--nextattr]);
   ta=&tagattr[nextattr++];
   ADDTAIL(&attrs,ta);
   ta->attr=0;
   ta->valuepos=doc->args.length;
   ta->length=0;
   return ta;
}

/* Escape HTML entities in text */
static void EscapeHtmlEntities(struct Document *doc, UBYTE *text, long length)
{  UBYTE *p, *end;
   UBYTE ch;
   p=text;
   end=text+length;
   while(p<end)
   {  ch=*p;
      if(ch=='<')
      {  if(!Addtobuffer(&doc->args,"&lt;",4)) return;
      }
      else if(ch=='>')
      {  if(!Addtobuffer(&doc->args,"&gt;",4)) return;
      }
      else if(ch=='&')
      {  if(!Addtobuffer(&doc->args,"&amp;",5)) return;
      }
      else if(ch=='"')
      {  if(!Addtobuffer(&doc->args,"&quot;",6)) return;
      }
      else
      {  if(!Addtobuffer(&doc->args,&ch,1)) return;
      }
      p++;
   }
}

/* Process markdown text with emphasis, inline code, links, and images */
static BOOL ProcessMarkdownText(struct Document *doc, UBYTE *text, long length)
{  UBYTE *p, *end, *start;
   UBYTE *italic_start, *italic_end;
   UBYTE *code_start, *code_end;
   UBYTE *link_text_start, *link_text_end;
   UBYTE *link_url_start, *link_url_end;
   UBYTE *img_alt_start, *img_alt_end;
   UBYTE *img_url_start, *img_url_end;
   struct Tagattr *ta;
   BOOL in_code;
   
   p=text;
   end=text+length;
   start=p;
   in_code=FALSE;
   
   while(p<end)
   {  /* Check for images (![alt](url)) */
      if(p<end && *p=='!' && p+1<end && p[1]=='[')
      {  UBYTE *img_start=p;
         p+=2;  /* Skip ![ */
         img_alt_start=p;
         while(p<end && *p!=']') p++;
         if(p<end && *p==']')
         {  img_alt_end=p;
            p++;
            if(p<end && *p=='(')
            {  p++;
               img_url_start=p;
               /* Find URL end - URL ends at space, quote, or closing paren */
               while(p<end && *p!=')' && *p!=' ' && *p!='"' && *p!='\'') p++;
               img_url_end=p;
               /* Check for optional title in quotes */
               while(p<end && isspace(*p)) p++;
               if(p<end && (*p=='"' || *p=='\''))
               {  UBYTE quote_char=*p;
                  p++;
                  /* Skip title content */
                  while(p<end && *p!=quote_char) p++;
                  if(p<end) p++;  /* Skip closing quote */
                  while(p<end && isspace(*p)) p++;
               }
               if(p<end && *p==')')
               {  p++;
                  /* Output text before image */
                  if(img_start>start)
                  {  ta=Nextattr(doc);
                     ta->attr=TAGATTR_TEXT;
                     EscapeHtmlEntities(doc,start,img_start-start);
                     ta->length=doc->args.length-ta->valuepos;
                     if(!Addtobuffer(&doc->args,"",1)) return FALSE;
                     Processhtml(doc,MARKUP_TEXT,attrs.first);
                     NEWLIST(&attrs);
                     nextattr=0;
                     doc->args.length=0;
                  }
                  /* Output image */
                  ta=Nextattr(doc);
                  ta->attr=TAGATTR_ALT;
                  if(!Addtobuffer(&doc->args,img_alt_start,img_alt_end-img_alt_start)) return FALSE;
                  ta->length=img_alt_end-img_alt_start;
                  if(!Addtobuffer(&doc->args,"",1)) return FALSE;
                  ta=Nextattr(doc);
                  ta->attr=TAGATTR_SRC;
                  if(!Addtobuffer(&doc->args,img_url_start,img_url_end-img_url_start)) return FALSE;
                  ta->length=img_url_end-img_url_start;
                  if(!Addtobuffer(&doc->args,"",1)) return FALSE;
                  Processhtml(doc,MARKUP_IMG,attrs.first);
                  NEWLIST(&attrs);
                  nextattr=0;
                  doc->args.length=0;
                  start=p;
                  continue;
               }
            }
         }
         p=img_start+1;  /* Advance past ! to avoid infinite loop */
      }
      /* Check for links ([text](url)) */
      if(p<end && *p=='[')
      {  UBYTE *link_start=p;
         p++;
         link_text_start=p;
         while(p<end && *p!=']') p++;
         if(p<end && *p==']')
         {  link_text_end=p;
            p++;
            if(p<end && *p=='(')
            {  p++;
               link_url_start=p;
               /* Find URL end - URL ends at space, quote, or closing paren */
               while(p<end && *p!=')' && *p!=' ' && *p!='"' && *p!='\'') p++;
               link_url_end=p;
               /* Check for optional title in quotes */
               while(p<end && isspace(*p)) p++;
               if(p<end && (*p=='"' || *p=='\''))
               {  UBYTE quote_char=*p;
                  p++;
                  /* Skip title content */
                  while(p<end && *p!=quote_char) p++;
                  if(p<end) p++;  /* Skip closing quote */
                  while(p<end && isspace(*p)) p++;
               }
               if(p<end && *p==')')
               {  p++;
                  /* Output text before link */
                  if(link_start>start)
                  {  ta=Nextattr(doc);
                     ta->attr=TAGATTR_TEXT;
                     EscapeHtmlEntities(doc,start,link_start-start);
                     ta->length=doc->args.length-ta->valuepos;
                     if(!Addtobuffer(&doc->args,"",1)) return FALSE;
                     Processhtml(doc,MARKUP_TEXT,attrs.first);
                     NEWLIST(&attrs);
                     nextattr=0;
                     doc->args.length=0;
                  }
                  /* Output link */
                  ta=Nextattr(doc);
                  ta->attr=TAGATTR_HREF;
                  if(!Addtobuffer(&doc->args,link_url_start,link_url_end-link_url_start)) return FALSE;
                  ta->length=link_url_end-link_url_start;
                  if(!Addtobuffer(&doc->args,"",1)) return FALSE;
                  /* Open link tag */
                  Processhtml(doc,MARKUP_A,attrs.first);
                  /* Recursively process link text (may contain formatting) */
                  NEWLIST(&attrs);
                  nextattr=0;
                  doc->args.length=0;
                  if(!ProcessMarkdownText(doc,link_text_start,link_text_end-link_text_start)) return FALSE;
                  /* Close link tag */
                  NEWLIST(&attrs);
                  nextattr=0;
                  Processhtml(doc,MARKUP_A|MARKUP_END,attrs.first);
                  NEWLIST(&attrs);
                  nextattr=0;
                  doc->args.length=0;
                  start=p;
                  continue;
               }
            }
         }
         p=link_start+1;  /* Advance past [ to avoid infinite loop */
      }
      /* Check for inline code (backticks) */
      if(p<end-1 && *p=='`' && !in_code)
      {  /* Output text before code */
         if(p>start)
         {  ta=Nextattr(doc);
            ta->attr=TAGATTR_TEXT;
            EscapeHtmlEntities(doc,start,p-start);
            ta->length=doc->args.length-ta->valuepos;
            if(!Addtobuffer(&doc->args,"",1)) return FALSE;
            Processhtml(doc,MARKUP_TEXT,attrs.first);
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
         }
         code_start=++p;
         while(p<end && *p!='`') p++;
         if(p<end)
         {  code_end=p;
            p++;
            /* Open code tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_CODE,attrs.first);
            /* Output code text */
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            ta=Nextattr(doc);
            ta->attr=TAGATTR_TEXT;
            if(!Addtobuffer(&doc->args,code_start,code_end-code_start)) return FALSE;
            ta->length=code_end-code_start;
            if(!Addtobuffer(&doc->args,"",1)) return FALSE;
            Processhtml(doc,MARKUP_TEXT,attrs.first);
            /* Close code tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_CODE|MARKUP_END,attrs.first);
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            start=p;
         }
         else
         {  /* Unmatched backtick - treat as regular text */
            p=code_start-1;
            start=p;
            p++;  /* Advance to avoid infinite loop */
         }
      }
      /* Check for bold (**text** or __text__) - must be two consecutive same characters */
      else if(p<end-2 && ((p[0]=='*' && p[1]=='*') || (p[0]=='_' && p[1]=='_')) && !in_code)
      {  UBYTE match_char1=p[0];
         UBYTE match_char2=p[1];
         UBYTE *bold_start;
         UBYTE *bold_end;
         /* Output text before bold */
         if(p>start)
         {  ta=Nextattr(doc);
            ta->attr=TAGATTR_TEXT;
            EscapeHtmlEntities(doc,start,p-start);
            ta->length=doc->args.length-ta->valuepos;
            if(!Addtobuffer(&doc->args,"",1)) return FALSE;
            Processhtml(doc,MARKUP_TEXT,attrs.first);
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
         }
         bold_start=p+2;
         p+=2;
         /* Find matching closing delimiter */
         while(p<end-1 && !(p[0]==match_char1 && p[1]==match_char2)) p++;
         if(p<end-1 && p>bold_start)
         {  bold_end=p;
            p+=2;
            /* Open bold tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_STRONG,attrs.first);
            /* Recursively process bold text content (may contain italic, links, etc.) */
            if(!ProcessMarkdownText(doc,bold_start,bold_end-bold_start)) return FALSE;
            /* Close bold tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_STRONG|MARKUP_END,attrs.first);
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            start=p;
         }
         else
         {  /* Unmatched bold - treat as regular text */
            p=bold_start-2;
            start=p;
            p++;  /* Advance to avoid infinite loop */
         }
      }
      /* Check for italic (*text* or _text_) - single asterisk/underscore, not part of bold */
      else if(p<end && (*p=='*' || *p=='_') && p+1<end && 
              !(p+1<end && (p[1]=='*' || p[1]=='_')) && !in_code)
      {  UBYTE *next;
         UBYTE match_char=*p;
         next=p+1;
         /* Find matching closing delimiter */
         while(next<end && *next!=match_char && *next!='\n' && *next!='\r') next++;
         if(next<end && *next==match_char && next>p+1)
         {  /* Found matching italic delimiter */
            /* Output text before italic */
            if(p>start)
            {  ta=Nextattr(doc);
               ta->attr=TAGATTR_TEXT;
               EscapeHtmlEntities(doc,start,p-start);
               ta->length=doc->args.length-ta->valuepos;
               if(!Addtobuffer(&doc->args,"",1)) return FALSE;
               Processhtml(doc,MARKUP_TEXT,attrs.first);
               NEWLIST(&attrs);
               nextattr=0;
               doc->args.length=0;
            }
            italic_start=p+1;
            italic_end=next;
            p=next+1;
            /* Open italic tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_EM,attrs.first);
            /* Recursively process italic text content (may contain bold, links, etc.) */
            if(!ProcessMarkdownText(doc,italic_start,italic_end-italic_start)) return FALSE;
            /* Close italic tag */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_EM|MARKUP_END,attrs.first);
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            start=p;
         }
         else
         {  /* No match - treat as regular text */
            p++;
         }
      }
      else
      {  p++;
      }
   }
   
   /* Output remaining text */
   if(p>start)
   {  ta=Nextattr(doc);
      ta->attr=TAGATTR_TEXT;
      EscapeHtmlEntities(doc,start,p-start);
      ta->length=doc->args.length-ta->valuepos;
      if(!Addtobuffer(&doc->args,"",1)) return FALSE;
      Processhtml(doc,MARKUP_TEXT,attrs.first);
      NEWLIST(&attrs);
      nextattr=0;
      doc->args.length=0;
   }
   
   return TRUE;
}

/* Process a single markdown line */
static BOOL ProcessMarkdownLine(struct Document *doc, UBYTE *line, long length, USHORT *list_state, BOOL *in_paragraph)
{  UBYTE *p, *end, *start;
   struct Tagattr *ta;
   USHORT header_level;
   BOOL is_list_item=FALSE;
   USHORT list_type=0;  /* 0=none, 1=unordered, 2=ordered */
   
   if(!line || length<=0) return TRUE;
   
   p=line;
   end=line+length;
   
   /* Skip leading whitespace */
   while(p<end && isspace(*p)) p++;
   if(p>=end) return TRUE;  /* Empty line */
   
   start=p;
   
   /* Check for headers (# through ######) */
   if(*p=='#')
   {  header_level=0;
      while(p<end && *p=='#' && header_level<6)
      {  header_level++;
         p++;
      }
      if(p<end && isspace(*p))
      {  /* Valid header */
         /* Close any open paragraph */
         if(*in_paragraph)
         {  NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
            *in_paragraph=FALSE;
         }
         p++;
         while(p<end && isspace(*p)) p++;
         if(p<end)
         {  /* Process header text */
            UBYTE *header_text=p;
            UBYTE *header_end=end;
            while(header_end>header_text && isspace(header_end[-1])) header_end--;
            
            /* Open header tag */
            NEWLIST(&attrs);
            nextattr=0;
            switch(header_level)
            {  case 1: Processhtml(doc,MARKUP_H1,attrs.first); break;
               case 2: Processhtml(doc,MARKUP_H2,attrs.first); break;
               case 3: Processhtml(doc,MARKUP_H3,attrs.first); break;
               case 4: Processhtml(doc,MARKUP_H4,attrs.first); break;
               case 5: Processhtml(doc,MARKUP_H5,attrs.first); break;
               case 6: Processhtml(doc,MARKUP_H6,attrs.first); break;
            }
            /* Recursively process header text (may contain formatting) */
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            if(!ProcessMarkdownText(doc,header_text,header_end-header_text)) return FALSE;
            /* Close header tag */
            NEWLIST(&attrs);
            nextattr=0;
            switch(header_level)
            {  case 1: Processhtml(doc,MARKUP_H1|MARKUP_END,attrs.first); break;
               case 2: Processhtml(doc,MARKUP_H2|MARKUP_END,attrs.first); break;
               case 3: Processhtml(doc,MARKUP_H3|MARKUP_END,attrs.first); break;
               case 4: Processhtml(doc,MARKUP_H4|MARKUP_END,attrs.first); break;
               case 5: Processhtml(doc,MARKUP_H5|MARKUP_END,attrs.first); break;
               case 6: Processhtml(doc,MARKUP_H6|MARKUP_END,attrs.first); break;
            }
            return TRUE;
         }
      }
      /* Not a valid header, treat as regular text */
      p=start;
   }
   
   /* Check for horizontal rule (---, ***, or ___) */
   if((p<end-2 && p[0]=='-' && p[1]=='-' && p[2]=='-') ||
      (p<end-2 && p[0]=='*' && p[1]=='*' && p[2]=='*') ||
      (p<end-2 && p[0]=='_' && p[1]=='_' && p[2]=='_'))
   {  UBYTE *hr_check=p+3;
      BOOL is_hr=TRUE;
      while(hr_check<end && is_hr)
      {  if(*hr_check!=p[0] && !isspace(*hr_check)) is_hr=FALSE;
         hr_check++;
      }
      if(is_hr)
      {  /* Close any open paragraph */
         if(*in_paragraph)
         {  NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
            *in_paragraph=FALSE;
         }
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_HR,attrs.first);
         return TRUE;
      }
   }
   
   /* Check for blockquote (>) */
   if(*p=='>')
   {  /* Close any open paragraph */
      if(*in_paragraph)
      {  NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
         *in_paragraph=FALSE;
      }
      p++;
      while(p<end && isspace(*p)) p++;
      if(p<end)
      {  /* Open blockquote tag */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_BLOCKQUOTE,attrs.first);
         /* Recursively process blockquote text */
         NEWLIST(&attrs);
         nextattr=0;
         doc->args.length=0;
         if(!ProcessMarkdownText(doc,p,end-p)) return FALSE;
         /* Close blockquote tag */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_BLOCKQUOTE|MARKUP_END,attrs.first);
         return TRUE;
      }
   }
   
   /* Check for unordered list (-, *, +) */
   if((*p=='-' || *p=='*' || *p=='+') && p+1<end && isspace(p[1]))
   {  is_list_item=TRUE;
      list_type=1;
      p+=2;
      while(p<end && isspace(*p)) p++;
      if(p<end)
      {  /* Open list if not already open */
         if(*list_state!=1)
         {  if(*list_state!=0)
            {  /* Close previous list */
               NEWLIST(&attrs);
               nextattr=0;
               Processhtml(doc,MARKUP_UL|MARKUP_END,attrs.first);
            }
            /* Open unordered list */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_UL,attrs.first);
            *list_state=1;
         }
         /* Open list item */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_LI,attrs.first);
         /* Process list item content */
         NEWLIST(&attrs);
         nextattr=0;
         doc->args.length=0;
         if(!ProcessMarkdownText(doc,p,end-p)) return FALSE;
         /* Close list item */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_LI|MARKUP_END,attrs.first);
         return TRUE;
      }
   }
   
   /* Check for ordered list (1., 2., etc.) */
   if(isdigit(*p))
   {  UBYTE *num_start=p;
      while(p<end && isdigit(*p)) p++;
      if(p<end && *p=='.' && p+1<end && isspace(p[1]))
      {  is_list_item=TRUE;
         list_type=2;
         p+=2;
         while(p<end && isspace(*p)) p++;
         if(p<end)
         {  /* Open list if not already open */
            if(*list_state!=2)
            {  if(*list_state!=0)
               {  /* Close previous list */
                  NEWLIST(&attrs);
                  nextattr=0;
                  if(*list_state==1)
                  {  Processhtml(doc,MARKUP_UL|MARKUP_END,attrs.first);
                  }
                  else if(*list_state==2)
                  {  Processhtml(doc,MARKUP_OL|MARKUP_END,attrs.first);
                  }
               }
            /* Open ordered list */
            NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_OL,attrs.first);
            *list_state=2;
         }
         /* Open list item */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_LI,attrs.first);
         /* Process list item content */
         NEWLIST(&attrs);
         nextattr=0;
         doc->args.length=0;
         if(!ProcessMarkdownText(doc,p,end-p)) return FALSE;
         /* Close list item */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_LI|MARKUP_END,attrs.first);
         return TRUE;
         }
      }
      p=num_start;
   }
   
   /* Not a list item - close list if open */
   if(*list_state!=0 && !is_list_item)
   {  NEWLIST(&attrs);
      nextattr=0;
      if(*list_state==1)
      {  Processhtml(doc,MARKUP_UL|MARKUP_END,attrs.first);
      }
      else if(*list_state==2)
      {  Processhtml(doc,MARKUP_OL|MARKUP_END,attrs.first);
      }
      *list_state=0;
   }
   
   /* If we processed a list item, we're not in a paragraph */
   if(is_list_item)
   {  *in_paragraph=FALSE;
   }
   
   /* Check for code block (indented with 4 spaces or tab) */
   if((p<end-3 && p[0]==' ' && p[1]==' ' && p[2]==' ' && p[3]==' ') || *p=='\t')
   {  UBYTE *code_start;
      /* Close any open paragraph */
      if(*in_paragraph)
      {  NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
         *in_paragraph=FALSE;
      }
      if(*p=='\t')
      {  code_start=p+1;
      }
      else
      {  code_start=p+4;
      }
      while(code_start<end && isspace(*code_start)) code_start++;
      if(code_start<end)
      {  /* Open pre tag for code block */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_PRE,attrs.first);
         /* Output code block text */
         NEWLIST(&attrs);
         nextattr=0;
         doc->args.length=0;
         ta=Nextattr(doc);
         ta->attr=TAGATTR_TEXT;
         if(!Addtobuffer(&doc->args,code_start,end-code_start)) return FALSE;
         ta->length=end-code_start;
         if(!Addtobuffer(&doc->args,"",1)) return FALSE;
         Processhtml(doc,MARKUP_TEXT,attrs.first);
         /* Close pre tag */
         NEWLIST(&attrs);
         nextattr=0;
         Processhtml(doc,MARKUP_PRE|MARKUP_END,attrs.first);
         return TRUE;
      }
   }
   
   /* Regular paragraph text */
   /* Open paragraph tag if not already open */
   if(!*in_paragraph)
   {  NEWLIST(&attrs);
      nextattr=0;
      Processhtml(doc,MARKUP_P,attrs.first);
      *in_paragraph=TRUE;
   }
   /* Recursively process paragraph text */
   NEWLIST(&attrs);
   nextattr=0;
   doc->args.length=0;
   if(!ProcessMarkdownText(doc,start,end-start)) return FALSE;
   /* Note: Don't close paragraph here - it will be closed on empty line or block element */
   
   return TRUE;
}

/* Main markdown parser function */
BOOL Parsemarkdown(struct Document *doc,struct Buffer *src,BOOL eof,long *srcpos)
{  UBYTE *p=src->buffer+(*srcpos);
   UBYTE *end=src->buffer+src->length;
   UBYTE *line_start;
   USHORT list_state=0;  /* 0=none, 1=unordered, 2=ordered */
   static BOOL in_fenced_code=FALSE;  /* Track fenced code block state */
   static BOOL in_paragraph=FALSE;  /* Track if we're inside a paragraph */
   struct Tagattr *ta;
   
   if((*srcpos)==0)
   {  while(p<end && !*p) p++;
      *srcpos=p-src->buffer;
      NEWLIST(&attrs);
      nextattr=0;
      in_fenced_code=FALSE;  /* Reset on new document */
      in_paragraph=FALSE;  /* Reset on new document */
   }
   
   while(p<end || eof)
   {  line_start=p;
      
      /* Find end of line */
      while(p<end && *p!='\r' && *p!='\n') p++;
      
      if(p>line_start || (p<end && (*p=='\r' || *p=='\n')))
      {  long line_length=p-line_start;
         UBYTE *line=line_start;
         BOOL is_empty_line=FALSE;
         
         /* Check if line is empty (after whitespace) */
         {  UBYTE *check=line;
            UBYTE *check_end=line+line_length;
            while(check<check_end && isspace(*check)) check++;
            if(check>=check_end) is_empty_line=TRUE;
         }
         
         /* If empty line, close any open paragraph */
         if(is_empty_line && in_paragraph)
         {  NEWLIST(&attrs);
            nextattr=0;
            Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
            in_paragraph=FALSE;
         }
         
         /* Check for fenced code block (```) - must be exactly 3 backticks (or 3+ with only backticks/whitespace) */
         if(!is_empty_line && line_length>=3 && line[0]=='`' && line[1]=='`' && line[2]=='`')
         {  UBYTE *check=line+3;
            BOOL is_fenced=TRUE;
            /* Check that rest of line is only backticks or whitespace */
            while(check<line+line_length && is_fenced)
            {  if(*check!='`' && !isspace(*check)) is_fenced=FALSE;
               check++;
            }
            if(is_fenced)
            {  if(in_fenced_code)
            {  /* Close fenced code block */
               NEWLIST(&attrs);
               nextattr=0;
               Processhtml(doc,MARKUP_PRE|MARKUP_END,attrs.first);
               in_fenced_code=FALSE;
            }
            else
            {  /* Open fenced code block */
               /* Close any open paragraph */
               if(in_paragraph)
               {  NEWLIST(&attrs);
                  nextattr=0;
                  Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
                  in_paragraph=FALSE;
               }
               /* Close any open list first */
               if(list_state!=0)
               {  NEWLIST(&attrs);
                  nextattr=0;
                  if(list_state==1)
                  {  Processhtml(doc,MARKUP_UL|MARKUP_END,attrs.first);
                  }
                  else if(list_state==2)
                  {  Processhtml(doc,MARKUP_OL|MARKUP_END,attrs.first);
                  }
                  list_state=0;
               }
               NEWLIST(&attrs);
               nextattr=0;
               Processhtml(doc,MARKUP_PRE,attrs.first);
               in_fenced_code=TRUE;
            }
            }
         }
         else if(in_fenced_code)
         {  /* Inside fenced code block - output line as-is */
            NEWLIST(&attrs);
            nextattr=0;
            doc->args.length=0;
            ta=Nextattr(doc);
            ta->attr=TAGATTR_TEXT;
            if(!Addtobuffer(&doc->args,line,line_length)) return FALSE;
            ta->length=line_length;
            if(!Addtobuffer(&doc->args,"\n",1)) return FALSE;
            ta->length++;
            Processhtml(doc,MARKUP_TEXT,attrs.first);
         }
         else if(!is_empty_line)
         {  /* Process the line normally */
            if(!ProcessMarkdownLine(doc,line_start,line_length,&list_state,&in_paragraph))
            {  return FALSE;
            }
         }
      }
      
      if(p>=end && !eof) break;
      
      /* Skip line ending */
      if(p<end && *p=='\r')
      {  if(p+1<end && p[1]=='\n')
         {  p+=2;
         }
         else if(eof)
         {  p++;
         }
         else
         {  break;
         }
      }
      else if(p<end && *p=='\n')
      {  p++;
      }
      else if(eof)
      {  break;
      }
      else
      {  break;
      }
      
      (*srcpos)=p-src->buffer;
   }
   
   /* Close any open list at EOF */
   if(eof && list_state!=0)
   {  NEWLIST(&attrs);
      nextattr=0;
      if(list_state==1)
      {  Processhtml(doc,MARKUP_UL|MARKUP_END,attrs.first);
      }
      else if(list_state==2)
      {  Processhtml(doc,MARKUP_OL|MARKUP_END,attrs.first);
      }
   }
   
   /* Close any open paragraph at EOF */
   if(eof && in_paragraph)
   {  NEWLIST(&attrs);
      nextattr=0;
      Processhtml(doc,MARKUP_P|MARKUP_END,attrs.first);
      in_paragraph=FALSE;
   }
   
   return TRUE;
}

