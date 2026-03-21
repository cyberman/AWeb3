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

/* awebeml.c - EML email filter plugin main file */

#include "pluginlib.h"
#include "eml.h"
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

ULONG Initpluginlib(struct EmlBase *base)
{  AwebPluginBase=OpenLibrary("awebplugin.library",2);
   return (ULONG)(AwebPluginBase);
}

void Expungepluginlib(struct EmlBase *base)
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

/* Check if content type indicates email */
static BOOL IsEmailContentType(UBYTE *contenttype)
{  if(!contenttype) return FALSE;
   
   if(!strnicmp(contenttype, "message/rfc822", 14)) return TRUE;
   if(!strnicmp(contenttype, "message/rfc822;", 15)) return TRUE;
   
   return FALSE;
}

/* Check if URL extension suggests email */
static BOOL IsEmailUrl(UBYTE *url)
{  UBYTE *ext;
   long len;
   
   if(!url) return FALSE;
   
   len = strlen(url);
   if(len < 4) return FALSE;
   
   ext = url + len - 4;
   if(!strnicmp(ext, ".eml", 4)) return TRUE;
   
   return FALSE;
}

/* Check if data contains email signatures */
static BOOL IsEmailContent(UBYTE *data, long length)
{  UBYTE *p;
   UBYTE *end;
   long i;
   
   if(!data || length < 10) return FALSE;
   
   end = data + length;
   if(end - data > 512) end = data + 512;
   
   p = data;
   while(p < end - 10)
   {  if(*p == 'F' || *p == 'f')
      {  if(!strnicmp(p, "From:", 5)) return TRUE;
      }
      if(*p == 'T' || *p == 't')
      {  if(!strnicmp(p, "To:", 3)) return TRUE;
         if(!strnicmp(p, "Subject:", 8)) return TRUE;
      }
      if(*p == 'D' || *p == 'd')
      {  if(!strnicmp(p, "Date:", 5)) return TRUE;
      }
      p++;
   }
   
   return FALSE;
}

/* The filter function */
__asm __saveds void Filterplugin(register __a0 struct Pluginfilter *pf)
{
   struct EmlFilterData *fd;
   BOOL should_filter;
   
   /* See if there is already a userdata for us.
    * If not, allocate and initialize. */
   fd = pf->userdata;
   if(!fd)
   {
      fd = (struct EmlFilterData *)AllocVec(sizeof(struct EmlFilterData), MEMF_CLEAR);
      if(!fd) return;
      pf->userdata = fd;
      fd->first = TRUE;
      fd->is_email = FALSE;
      fd->parser = NULL;
      fd->html_buffer = NULL;
      fd->html_bufsize = 0;
      fd->html_buflen = 0;
      fd->header_written = FALSE;
      fd->footer_written = FALSE;
      fd->eml_url = NULL;
      
      /* Store the EML URL for CID registry */
      if(pf->url)
      {  fd->eml_url = Dupstr(pf->url, -1);
      }
      
      /* Determine if this is an email */
      should_filter = FALSE;
      
      /* Check content type first - specific email types */
      if(IsEmailContentType(pf->contenttype))
      {  should_filter = TRUE;
      }
      
      /* Check URL extension as fallback - but verify content on first chunk */
      if(!should_filter && IsEmailUrl(pf->url))
      {  /* URL suggests email, but verify with content sniffing on first data chunk */
         should_filter = FALSE; /* Will verify on first data chunk */
      }
      
      fd->is_email = should_filter;
      
      /* Only initialize parser if we're certain it's an email (specific content type) */
      if(should_filter)
      {  /* Initialize parser */
         fd->parser = (struct EmlParser *)AllocVec(sizeof(struct EmlParser), MEMF_CLEAR);
         if(fd->parser)
         {  InitEmlParser(fd->parser);
         }
         else
         {  fd->is_email = FALSE;
         }
      }
   }
   
   if(pf->data)
   {
      /* Content sniffing on first chunk if not already confirmed as email */
      if(fd->first && !fd->is_email)
      {  BOOL url_suggests_email = IsEmailUrl(pf->url);
         BOOL content_type_suggests_email = FALSE;
         
         if(pf->contenttype)
         {  if(!strnicmp(pf->contenttype, "message/rfc822", 14) ||
               !strnicmp(pf->contenttype, "text/plain", 10))
            {  content_type_suggests_email = TRUE;
            }
         }
         
         /* Do content sniffing if URL suggests email OR content type suggests email */
         if(url_suggests_email || content_type_suggests_email)
         {  if(IsEmailContent(pf->data, pf->length))
            {  fd->is_email = TRUE;
               if(!fd->parser)
               {  fd->parser = (struct EmlParser *)AllocVec(sizeof(struct EmlParser), MEMF_CLEAR);
                  if(fd->parser)
                  {  InitEmlParser(fd->parser);
                  }
                  else
                  {  fd->is_email = FALSE;
                  }
               }
            }
         }
      }
      
      if(fd->is_email && fd->parser)
      {
         /* Before the first data, change the content type
          * and write a proper HTML header */
         if(fd->first)
         {
            Setfiltertype(pf->handle, "text/html");
            fd->first = FALSE;
         }
         
         /* Parse email MIME */
         ParseEmlChunk(fd->parser, pf->data, pf->length);
         
         /* Render to HTML if we have complete email or on EOF */
         if(pf->eof || (fd->parser->message && fd->parser->headers_complete))
         {  RenderEmailToHtml(fd, pf->handle);
         }
      }
      else
      {  /* Not an email after all, pass through unchanged */
         Writefilter(pf->handle, pf->data, pf->length);
      }
   }
   
   /* Cleanup on EOF */
   if(pf->eof)
   {
      Aprintf("EML: EOF - cleaning up\n");
      /* Unregister all CID parts for this EML */
      if(fd->eml_url)
      {  Aprintf("EML: Unregistering CID parts for %s\n", fd->eml_url);
         Unregistercidparts(fd->eml_url);
         Aprintf("EML: Freeing eml_url\n");
         FreeVec(fd->eml_url);
         fd->eml_url = NULL;
      }
      
      if(fd->parser)
      {  CleanupEmlParser(fd->parser);
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

