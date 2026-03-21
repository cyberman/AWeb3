/**********************************************************************
 * 
 * This file is part of the AWebZen distribution
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

/* rssparse.c - RSS/Atom XML parser */

#include "rss.h"
#include <exec/memory.h>
#include <exec/types.h>
#include <string.h>
#include <ctype.h>
#include <proto/exec.h>
#include <proto/utility.h>

/* Allocate and initialize parser */
void InitRssParser(struct RssParser *parser)
{  struct FeedChannel *channel;
   
   if(!parser) return;
   
   parser->buffer = NULL;
   parser->bufsize = 0;
   parser->buflen = 0;
   parser->current = NULL;
   parser->end = NULL;
   parser->currenttag = NULL;
   parser->currenttaglen = 0;
   parser->currentdata = NULL;
   parser->currentdatalen = 0;
   parser->initem = FALSE;
   parser->incontent = FALSE;
   parser->detectedtype = FEED_UNKNOWN;
   
   channel = (struct FeedChannel *)AllocVec(sizeof(struct FeedChannel), MEMF_CLEAR);
   if(channel)
   {  channel->items = NULL;
      channel->lastitem = NULL;
      channel->itemcount = 0;
      channel->feedtype = FEED_UNKNOWN;
   }
   parser->channel = channel;
   parser->currentitem = NULL;
}

/* Helper: Find end of tag name */
static UBYTE *FindTagEnd(UBYTE *p, UBYTE *end)
{  while(p < end && *p != '>' && *p != ' ' && *p != '\t' && *p != '/')
   {  p++;
   }
   return p;
}

/* Helper: Find closing tag */
static UBYTE *FindClosingTag(UBYTE *p, UBYTE *end, UBYTE *tagname, long tagnamelen)
{  UBYTE *tagstart;
   UBYTE *tagend;
   
   while(p < end)
   {  if(*p == '<')
      {  tagstart = p + 1;
         if(tagstart < end && *tagstart == '/')
         {  tagstart++;
            tagend = FindTagEnd(tagstart, end);
            if(tagend - tagstart == tagnamelen)
            {  if(strnicmp(tagstart, tagname, tagnamelen) == 0)
               {  return tagstart - 1;
               }
            }
         }
      }
      p++;
   }
   return NULL;
}

/* Helper: Extract text content from tag */
static UBYTE *ExtractText(UBYTE *start, UBYTE *end, long *len)
{  UBYTE *textstart;
   UBYTE *textend;
   UBYTE *p;
   
   textstart = start;
   while(textstart < end && (*textstart == ' ' || *textstart == '\t' || 
         *textstart == '\n' || *textstart == '\r' || *textstart == '<' || *textstart == '>'))
   {  textstart++;
   }
   
   textend = end;
   while(textend > textstart && (textend[-1] == ' ' || textend[-1] == '\t' || 
         textend[-1] == '\n' || textend[-1] == '\r' || textend[-1] == '<' || textend[-1] == '>'))
   {  textend--;
   }
   
   /* Decode HTML entities */
   p = textstart;
   while(p < textend)
   {  if(*p == '&')
      {  if(p + 3 < textend && strnicmp(p, "&lt;", 4) == 0)
         {  *p = '<';
            memmove(p + 1, p + 4, textend - p - 4);
            textend -= 3;
         }
         else if(p + 3 < textend && strnicmp(p, "&gt;", 4) == 0)
         {  *p = '>';
            memmove(p + 1, p + 4, textend - p - 4);
            textend -= 3;
         }
         else if(p + 4 < textend && strnicmp(p, "&amp;", 5) == 0)
         {  *p = '&';
            memmove(p + 1, p + 5, textend - p - 5);
            textend -= 4;
         }
         else if(p + 5 < textend && strnicmp(p, "&quot;", 6) == 0)
         {  *p = '"';
            memmove(p + 1, p + 6, textend - p - 6);
            textend -= 5;
         }
         else if(p + 5 < textend && strnicmp(p, "&apos;", 6) == 0)
         {  *p = '\'';
            memmove(p + 1, p + 6, textend - p - 6);
            textend -= 5;
         }
      }
      p++;
   }
   
   if(len) *len = textend - textstart;
   return textstart;
}

/* Helper: Duplicate string */
static UBYTE *DupString(UBYTE *start, long len)
{  UBYTE *result;
   
   if(!start || len <= 0) return NULL;
   
   result = (UBYTE *)AllocVec(len + 1, MEMF_CLEAR);
   if(result)
   {  memcpy(result, start, len);
      result[len] = '\0';
   }
   return result;
}

/* Process a tag */
static void ProcessTag(struct RssParser *parser, UBYTE *tagstart, UBYTE *tagend, BOOL isclosing)
{  UBYTE *tagname;
   long tagnamelen;
   struct FeedItem *item;
   struct FeedChannel *channel;
   
   if(!parser || !tagstart || !tagend) return;
   
   channel = parser->channel;
   if(!channel) return;
   
   tagname = tagstart;
   tagnamelen = tagend - tagstart;
   
   if(isclosing)
   {  /* Closing tag */
      if(parser->initem && parser->currentitem)
      {  if(parser->currenttag && parser->currenttaglen == tagnamelen)
         {  if(strnicmp(parser->currenttag, tagname, tagnamelen) == 0)
            {  parser->incontent = FALSE;
               parser->currenttag = NULL;
               parser->currenttaglen = 0;
            }
         }
      }
      
      if(tagnamelen == 4 && strnicmp(tagname, "item", 4) == 0)
      {  parser->initem = FALSE;
         parser->currentitem = NULL;
      }
      else if(tagnamelen == 5 && strnicmp(tagname, "entry", 5) == 0)
      {  parser->initem = FALSE;
         parser->currentitem = NULL;
      }
      return;
   }
   
   /* Opening tag - detect feed type */
   if(parser->detectedtype == FEED_UNKNOWN)
   {  if(tagnamelen == 3 && strnicmp(tagname, "rss", 3) == 0)
      {  parser->detectedtype = FEED_RSS;
         channel->feedtype = FEED_RSS;
      }
      else if(tagnamelen == 4 && strnicmp(tagname, "feed", 4) == 0)
      {  parser->detectedtype = FEED_ATOM;
         channel->feedtype = FEED_ATOM;
      }
   }
   
   /* RSS channel tags */
   if(!parser->initem)
   {  if(tagnamelen == 5 && strnicmp(tagname, "title", 5) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 5;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 4 && strnicmp(tagname, "link", 4) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 4;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 11 && strnicmp(tagname, "description", 11) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 11;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 8 && strnicmp(tagname, "language", 8) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 8;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 9 && strnicmp(tagname, "copyright", 9) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 9;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 4 && strnicmp(tagname, "item", 4) == 0)
      {  parser->initem = TRUE;
         item = (struct FeedItem *)AllocVec(sizeof(struct FeedItem), MEMF_CLEAR);
         if(item)
         {  if(channel->lastitem)
            {  channel->lastitem->next = item;
            }
            else
            {  channel->items = item;
            }
            channel->lastitem = item;
            channel->itemcount++;
            parser->currentitem = item;
         }
      }
      else if(tagnamelen == 5 && strnicmp(tagname, "entry", 5) == 0)
      {  parser->initem = TRUE;
         item = (struct FeedItem *)AllocVec(sizeof(struct FeedItem), MEMF_CLEAR);
         if(item)
         {  if(channel->lastitem)
            {  channel->lastitem->next = item;
            }
            else
            {  channel->items = item;
            }
            channel->lastitem = item;
            channel->itemcount++;
            parser->currentitem = item;
         }
      }
   }
   else
   {  /* Item/entry tags */
      item = parser->currentitem;
      if(!item) return;
      
      if(tagnamelen == 5 && strnicmp(tagname, "title", 5) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 5;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 4 && strnicmp(tagname, "link", 4) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 4;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 11 && strnicmp(tagname, "description", 11) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 11;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 7 && strnicmp(tagname, "content", 7) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 7;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 7 && strnicmp(tagname, "summary", 7) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 7;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 7 && strnicmp(tagname, "pubDate", 7) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 7;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 7 && strnicmp(tagname, "updated", 7) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 7;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 6 && strnicmp(tagname, "author", 6) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 6;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 4 && strnicmp(tagname, "guid", 4) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 4;
         parser->incontent = TRUE;
      }
      else if(tagnamelen == 2 && strnicmp(tagname, "id", 2) == 0)
      {  parser->currenttag = tagname;
         parser->currenttaglen = 2;
         parser->incontent = TRUE;
      }
   }
}

/* Process text content */
static void ProcessContent(struct RssParser *parser, UBYTE *start, UBYTE *end)
{  UBYTE *text;
   long textlen;
   struct FeedItem *item;
   struct FeedChannel *channel;
   
   if(!parser || !start || !end || !parser->incontent) return;
   
   channel = parser->channel;
   if(!channel) return;
   
   text = ExtractText(start, end, &textlen);
   if(!text || textlen <= 0) return;
   
   if(parser->initem && parser->currentitem)
   {  item = parser->currentitem;
      
      if(parser->currenttag)
      {  if(parser->currenttaglen == 5 && strnicmp(parser->currenttag, "title", 5) == 0)
         {  if(!item->title)
            {  item->title = DupString(text, textlen);
               item->titlelen = textlen;
            }
         }
         else if(parser->currenttaglen == 4 && strnicmp(parser->currenttag, "link", 4) == 0)
         {  if(!item->link)
            {  item->link = DupString(text, textlen);
               item->linklen = textlen;
            }
         }
         else if(parser->currenttaglen == 11 && strnicmp(parser->currenttag, "description", 11) == 0)
         {  if(!item->description)
            {  item->description = DupString(text, textlen);
               item->desclen = textlen;
            }
         }
         else if(parser->currenttaglen == 7 && strnicmp(parser->currenttag, "content", 7) == 0)
         {  if(!item->description)
            {  item->description = DupString(text, textlen);
               item->desclen = textlen;
            }
         }
         else if(parser->currenttaglen == 7 && strnicmp(parser->currenttag, "summary", 7) == 0)
         {  if(!item->description)
            {  item->description = DupString(text, textlen);
               item->desclen = textlen;
            }
         }
         else if(parser->currenttaglen == 7 && strnicmp(parser->currenttag, "pubDate", 7) == 0)
         {  if(!item->pubdate)
            {  item->pubdate = DupString(text, textlen);
               item->pubdatelen = textlen;
            }
         }
         else if(parser->currenttaglen == 7 && strnicmp(parser->currenttag, "updated", 7) == 0)
         {  if(!item->pubdate)
            {  item->pubdate = DupString(text, textlen);
               item->pubdatelen = textlen;
            }
         }
         else if(parser->currenttaglen == 6 && strnicmp(parser->currenttag, "author", 6) == 0)
         {  if(!item->author)
            {  item->author = DupString(text, textlen);
               item->authorlen = textlen;
            }
         }
         else if(parser->currenttaglen == 4 && strnicmp(parser->currenttag, "guid", 4) == 0)
         {  if(!item->guid)
            {  item->guid = DupString(text, textlen);
               item->guidlen = textlen;
            }
         }
         else if(parser->currenttaglen == 2 && strnicmp(parser->currenttag, "id", 2) == 0)
         {  if(!item->guid)
            {  item->guid = DupString(text, textlen);
               item->guidlen = textlen;
            }
         }
      }
   }
   else
   {  /* Channel/feed metadata */
      if(parser->currenttag)
      {  if(parser->currenttaglen == 5 && strnicmp(parser->currenttag, "title", 5) == 0)
         {  if(!channel->title)
            {  channel->title = DupString(text, textlen);
               channel->titlelen = textlen;
            }
         }
         else if(parser->currenttaglen == 4 && strnicmp(parser->currenttag, "link", 4) == 0)
         {  if(!channel->link)
            {  channel->link = DupString(text, textlen);
               channel->linklen = textlen;
            }
         }
         else if(parser->currenttaglen == 11 && strnicmp(parser->currenttag, "description", 11) == 0)
         {  if(!channel->description)
            {  channel->description = DupString(text, textlen);
               channel->desclen = textlen;
            }
         }
         else if(parser->currenttaglen == 8 && strnicmp(parser->currenttag, "language", 8) == 0)
         {  if(!channel->language)
            {  channel->language = DupString(text, textlen);
               channel->languagelen = textlen;
            }
         }
         else if(parser->currenttaglen == 9 && strnicmp(parser->currenttag, "copyright", 9) == 0)
         {  if(!channel->copyright)
            {  channel->copyright = DupString(text, textlen);
               channel->copyrightlen = textlen;
            }
         }
      }
   }
}

/* Parse a chunk of XML data */
void ParseRssChunk(struct RssParser *parser, UBYTE *data, long length)
{  UBYTE *p;
   UBYTE *end;
   UBYTE *tagstart;
   UBYTE *tagend;
   UBYTE *contentstart;
   UBYTE *closingtag;
   BOOL isclosing;
   UBYTE *newbuffer;
   long newlen;
   
   if(!parser || !data || length <= 0) return;
   
   /* Append to buffer */
   newlen = parser->buflen + length;
   if(newlen > parser->bufsize)
   {  newbuffer = (UBYTE *)AllocVec(newlen + 4096, MEMF_CLEAR);
      if(newbuffer)
      {  if(parser->buffer)
         {  memcpy(newbuffer, parser->buffer, parser->buflen);
            FreeVec(parser->buffer);
         }
         parser->buffer = newbuffer;
         parser->bufsize = newlen + 4096;
      }
      else
      {  return;
      }
   }
   
   memcpy(parser->buffer + parser->buflen, data, length);
   parser->buflen += length;
   
   p = parser->buffer;
   end = parser->buffer + parser->buflen;
   
   /* Simple XML parsing - find tags */
   while(p < end)
   {  if(*p == '<')
      {  tagstart = p + 1;
         if(tagstart >= end) break;
         
         isclosing = FALSE;
         if(*tagstart == '/')
         {  isclosing = TRUE;
            tagstart++;
         }
         
         tagend = FindTagEnd(tagstart, end);
         if(tagend >= end) break;
         
         /* Check for self-closing tag (ends with />) */
         {  UBYTE *check = tagend;
            BOOL selfclosing = FALSE;
            while(check > tagstart && (*check == ' ' || *check == '\t'))
            {  check--;
            }
            if(check > tagstart && *check == '/')
            {  selfclosing = TRUE;
            }
            
            if(*tagend == '>' || selfclosing)
            {  /* Simple tag like <title> or self-closing like <author /> */
               ProcessTag(parser, tagstart, tagend, isclosing);
               
               if(!isclosing && !selfclosing)
               {  contentstart = tagend + 1;
                  closingtag = FindClosingTag(contentstart, end, tagstart, tagend - tagstart);
                  if(closingtag)
                  {  ProcessContent(parser, contentstart, closingtag);
                  }
               }
               else if(selfclosing)
               {  /* Self-closing tag - reset content state */
                  parser->incontent = FALSE;
                  parser->currenttag = NULL;
                  parser->currenttaglen = 0;
               }
               
               /* Find the actual closing > */
               while(p < end && *p != '>')
               {  p++;
               }
               if(p < end) p++;
            }
            else
            {  /* Tag with attributes - skip to > */
               while(p < end && *p != '>')
               {  p++;
               }
               if(p < end)
               {  ProcessTag(parser, tagstart, tagend, isclosing);
                  p++;
               }
            }
         }
      }
      else
      {  p++;
      }
   }
}

/* Cleanup parser */
void CleanupRssParser(struct RssParser *parser)
{  if(!parser) return;
   
   if(parser->buffer)
   {  FreeVec(parser->buffer);
      parser->buffer = NULL;
   }
   
   if(parser->channel)
   {  FreeFeedChannel(parser->channel);
      parser->channel = NULL;
   }
   
   parser->bufsize = 0;
   parser->buflen = 0;
}

/* Free feed channel and items */
void FreeFeedChannel(struct FeedChannel *channel)
{  struct FeedItem *item;
   struct FeedItem *next;
   
   if(!channel) return;
   
   if(channel->title) FreeVec(channel->title);
   if(channel->link) FreeVec(channel->link);
   if(channel->description) FreeVec(channel->description);
   if(channel->language) FreeVec(channel->language);
   if(channel->copyright) FreeVec(channel->copyright);
   if(channel->managingeditor) FreeVec(channel->managingeditor);
   if(channel->webmaster) FreeVec(channel->webmaster);
   
   item = channel->items;
   while(item)
   {  next = item->next;
      if(item->title) FreeVec(item->title);
      if(item->link) FreeVec(item->link);
      if(item->description) FreeVec(item->description);
      if(item->pubdate) FreeVec(item->pubdate);
      if(item->author) FreeVec(item->author);
      if(item->guid) FreeVec(item->guid);
      FreeVec(item);
      item = next;
   }
   
   FreeVec(channel);
}

