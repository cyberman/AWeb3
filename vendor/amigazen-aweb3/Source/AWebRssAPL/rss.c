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

/* rss.c - RSS/Atom filter plugin main file */

#include "pluginlib.h"
#include "rss.h"
#include <libraries/awebplugin.h>
#include <exec/memory.h>
#include <clib/awebplugin_protos.h>
#include <clib/exec_protos.h>
#include <pragmas/awebplugin_pragmas.h>
#include <pragmas/exec_sysbase_pragmas.h>
#include <string.h>

/* Library bases we use */
extern struct ExecBase *SysBase;
struct Library *AwebPluginBase;

/* Stub function for _XCEXIT to avoid stdio dependency */
void __stdargs _XCEXIT(long x)
{
   /* No-op stub - we don't use stdio */
}

ULONG Initpluginlib(struct RssBase *base)
{  AwebPluginBase=OpenLibrary("awebplugin.library",2);
   return (ULONG)(AwebPluginBase);
}

void Expungepluginlib(struct RssBase *base)
{  if(AwebPluginBase) CloseLibrary(AwebPluginBase);
}

__asm __saveds ULONG Initplugin(register __a0 struct Plugininfo *pi)
{  pi->sourcedriver=0;
   pi->copydriver=0;
   return 1;
}

/* Query function. Handle in a safe way. */
#define ISSAFE(s,f) (s->structsize>=((long)&s->f-(long)s+sizeof(s->f)))

__asm __saveds void Queryplugin(register __a0 struct Pluginquery *pq)
{
#ifdef PLUGIN_COMMANDPLUGIN
   if(ISSAFE(pq,command)) pq->command=TRUE;
#endif
#ifdef PLUGIN_FILTERPLUGIN
   if(ISSAFE(pq,filter)) pq->filter=TRUE;
#endif
}

/* Check if content type indicates RSS/Atom feed */
static BOOL IsFeedContentType(UBYTE *contenttype)
{  if(!contenttype) return FALSE;
   
   if(!strnicmp(contenttype, "application/rss+xml", 20)) return TRUE;
   if(!strnicmp(contenttype, "application/atom+xml", 21)) return TRUE;
   /* Note: application/xml and text/xml are too generic - we'll do content sniffing for these */
   
   return FALSE;
}

/* Check if URL extension suggests RSS/Atom feed */
static BOOL IsFeedUrl(UBYTE *url)
{  UBYTE *ext;
   long len;
   
   if(!url) return FALSE;
   
   len = strlen(url);
   if(len < 4) return FALSE;
   
   /* Check for feed-related keywords in URL path */
   if(strstr(url, "/feed") || strstr(url, "/rss") || strstr(url, "/atom") ||
      strstr(url, "?feed") || strstr(url, "?rss") || strstr(url, "?atom"))
   {  return TRUE;
   }
   
   ext = url + len - 4;
   if(!strnicmp(ext, ".rss", 4)) return TRUE;
   if(len >= 5)
   {  ext = url + len - 5;
      if(!strnicmp(ext, ".atom", 5)) return TRUE;
   }
   if(!strnicmp(ext, ".xml", 4))
   {  /* Could be RSS/Atom, check for feed-like patterns in URL */
      if(strstr(url, "feed") || strstr(url, "rss") || strstr(url, "atom"))
      {  return TRUE;
      }
   }
   
   return FALSE;
}

/* Check if data contains RSS/Atom signatures */
static BOOL IsFeedContent(UBYTE *data, long length)
{  UBYTE *p;
   UBYTE *end;
   long i;
   
   if(!data || length < 10) return FALSE;
   
   end = data + length;
   if(end - data > 512) end = data + 512;
   
   p = data;
   while(p < end - 10)
   {        if(*p == '<')
      {  if(!strnicmp(p, "<rss", 4)) return TRUE;
         if(!strnicmp(p, "<feed", 5)) return TRUE;
         if(!strnicmp(p, "<?xml", 5))
         {  /* Check further for RSS/Atom */
            for(i = 0; i < 200 && p + i < end; i++)
            {  if(!strnicmp(p + i, "<rss", 4)) return TRUE;
               if(!strnicmp(p + i, "<feed", 5)) return TRUE;
            }
         }
      }
      p++;
   }
   
   return FALSE;
}

/* The filter function */
__asm __saveds void Filterplugin(register __a0 struct Pluginfilter *pf)
{
   struct RssFilterData *fd;
   BOOL should_filter;
   
   /* See if there is already a userdata for us.
    * If not, allocate and initialize. */
   fd = pf->userdata;
   if(!fd)
   {
      fd = (struct RssFilterData *)AllocVec(sizeof(struct RssFilterData), MEMF_CLEAR);
      if(!fd) return;
      pf->userdata = fd;
      fd->first = TRUE;
      fd->is_feed = FALSE;
      fd->parser = NULL;
      fd->html_buffer = NULL;
      fd->html_bufsize = 0;
      fd->html_buflen = 0;
      fd->header_written = FALSE;
      fd->footer_written = FALSE;
      
      /* Determine if this is an RSS/Atom feed */
      should_filter = FALSE;
      
      /* Check content type first - specific RSS/Atom types */
      if(IsFeedContentType(pf->contenttype))
      {  should_filter = TRUE;
      }
      
      /* Check URL extension as fallback - but verify content on first chunk */
      if(!should_filter && IsFeedUrl(pf->url))
      {  /* URL suggests feed, but verify with content sniffing on first data chunk */
         should_filter = FALSE; /* Will verify on first data chunk */
      }
      
      /* For generic XML types, we'll do content sniffing on first data chunk */
      if(!should_filter && pf->contenttype)
      {  if(!strnicmp(pf->contenttype, "application/xml", 15) ||
            !strnicmp(pf->contenttype, "text/xml", 8))
         {  /* Will check content on first data chunk */
            should_filter = FALSE; /* Not confirmed yet, will check in data processing */
         }
      }
      
      fd->is_feed = should_filter;
      
      /* Only initialize parser if we're certain it's a feed (specific content type) */
      if(should_filter)
      {  /* Initialize parser */
         fd->parser = (struct RssParser *)AllocVec(sizeof(struct RssParser), MEMF_CLEAR);
         if(fd->parser)
         {  InitRssParser(fd->parser);
         }
         else
         {  fd->is_feed = FALSE;
         }
      }
   }
   
   if(pf->data)
   {
      /* Content sniffing on first chunk if not already confirmed as feed */
      if(fd->first && !fd->is_feed)
      {  BOOL url_suggests_feed = IsFeedUrl(pf->url);
         BOOL content_type_suggests_xml = FALSE;
         
         if(pf->contenttype)
         {  if(!strnicmp(pf->contenttype, "application/xml", 15) ||
               !strnicmp(pf->contenttype, "text/xml", 8) ||
               !strnicmp(pf->contenttype, "application/rss+xml", 20) ||
               !strnicmp(pf->contenttype, "application/atom+xml", 21))
            {  content_type_suggests_xml = TRUE;
            }
         }
         
         /* Do content sniffing if URL suggests feed OR content type suggests XML */
         if(url_suggests_feed || content_type_suggests_xml)
         {  if(IsFeedContent(pf->data, pf->length))
            {  fd->is_feed = TRUE;
               if(!fd->parser)
               {  fd->parser = (struct RssParser *)AllocVec(sizeof(struct RssParser), MEMF_CLEAR);
                  if(fd->parser)
                  {  InitRssParser(fd->parser);
                  }
                  else
                  {  fd->is_feed = FALSE;
                  }
               }
            }
         }
      }
      
      if(fd->is_feed && fd->parser)
      {
         /* Before the first data, change the content type
          * and write a proper HTML header */
         if(fd->first)
         {
            Setfiltertype(pf->handle, "text/html");
            fd->first = FALSE;
         }
         
         /* Parse RSS/Atom XML */
         ParseRssChunk(fd->parser, pf->data, pf->length);
         
         /* Render to HTML if we have complete feed or on EOF */
         if(pf->eof || (fd->parser->channel && fd->parser->channel->itemcount > 0))
         {  RenderFeedToHtml(fd, pf->handle);
         }
      }
      else
      {  /* Not a feed after all, pass through unchanged */
         Writefilter(pf->handle, pf->data, pf->length);
      }
   }
   
   /* Cleanup on EOF */
   if(pf->eof)
   {
      if(fd->parser)
      {  CleanupRssParser(fd->parser);
         FreeVec(fd->parser);
         fd->parser = NULL;
      }
      
      if(fd->html_buffer)
      {  FreeVec(fd->html_buffer);
         fd->html_buffer = NULL;
      }
      
      FreeVec(fd);
      pf->userdata = NULL;
   }
}

