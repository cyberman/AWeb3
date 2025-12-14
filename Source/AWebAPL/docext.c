/**********************************************************************
 * 
 * This file is part of the AWeb APL distribution
 *
 * Copyright (C) 2002 Yvon Rozijn
 * Changes Copyright (C) 2025 amigazen project
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

/* docext.c - AWeb HTML document extension (script, style) object */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include "aweb.h"
#include "source.h"
#include "sourcedriver.h"
#include "copy.h"
#include "url.h"
#include "docprivate.h"

static LIST(Docext) docexts;

/*------------------------------------------------------------------------*/

/* Reference to a waiting document */
struct Docref
{  NODE(Docref);
   struct Document *doc;
   void *url;
};

static LIST(Docref) docrefs;

/* Signal all waiting documents */
static void Signaldocs(struct Docext *dox)
{  struct Docref *dr,*drnext;
   void *url,*durl;
   durl=(void *)Agetattr(dox->url,AOURL_Finalurlptr);
/*
printf("Signal for url %08x=%s\n"
       "             ->%08x=%s\n",
       dox->url,Agetattr(dox->url,AOURL_Url),
       durl,Agetattr(durl,AOURL_Url));
*/
   for(dr=docrefs.first;dr->next;dr=drnext)
   {  drnext=dr->next;
      url=(void *)Agetattr(dr->url,AOURL_Finalurlptr);
/*
printf("       ref url %08x=%s\n"
       "             ->%08x=%s\n",
       dr->url,Agetattr(dr->url,AOURL_Url),
       url,Agetattr(url,AOURL_Url));
*/
      if(url==durl)
      {  REMOVE(dr);
         Asetattrs(dr->doc,AODOC_Docextready,dr->url,TAG_END);
         FREE(dr);
      }
   }
}

static void Addwaitingdoc(struct Document *doc,void *url)
{  struct Docref *dr;
   if(dr=ALLOCSTRUCT(Docref,1,0))
   {  dr->doc=doc;
      dr->url=url;
      ADDTAIL(&docrefs,dr);
   }
}

void Remwaitingdoc(struct Document *doc)
{  struct Docref *dr,*drnext;
   for(dr=docrefs.first;dr->next;dr=drnext)
   {  drnext=dr->next;
      if(dr->doc==doc)
      {  REMOVE(dr);
         FREE(dr);
      }
   }
}

/*------------------------------------------------------------------------*/

static long Setdocext(struct Docext *dox,struct Amset *ams)
{  struct TagItem *tag,*tstate=ams->tags;
   while(tag=NextTagItem(&tstate))
   {  switch(tag->ti_Tag)
      {  case AOSDV_Source:
            dox->source=(void *)tag->ti_Data;
            break;
      }
   }
   return 0;
}

static struct Docext *Newdocext(struct Amset *ams)
{  struct Docext *dox;
   if(dox=Allocobject(AOTP_DOCEXT,sizeof(struct Docext),ams))
   {  Setdocext(dox,ams);
      dox->url=(void *)Agetattr(dox->source,AOSRC_Url);
      ADDTAIL(&docexts,dox);
   }
   return dox;
}

static long Getdocext(struct Docext *dox,struct Amset *ams)
{  struct TagItem *tag,*tstate=ams->tags;
   while(tag=NextTagItem(&tstate))
   {  switch(tag->ti_Tag)
      {  case AOSDV_Source:
            PUTATTR(tag,dox->source);
            break;
      }
   }
   return 0;
}

static long Srcupdatedocext(struct Docext *dox,struct Amsrcupdate *ams)
{  struct TagItem *tag,*tstate=ams->tags;
   long length=0;
   UBYTE *data=NULL;
   BOOL eof=FALSE;
   while(tag=NextTagItem(&tstate))
   {  switch(tag->ti_Tag)
      {  case AOURL_Contentlength:
            Expandbuffer(&dox->buf,tag->ti_Data-dox->buf.length);
            break;
         case AOURL_Data:
            data=(UBYTE *)tag->ti_Data;
            break;
         case AOURL_Datalength:
            length=tag->ti_Data;
            break;
         case AOURL_Reload:
            Freebuffer(&dox->buf);
            /* Clear both EOF and ERROR flags on reload to allow retry */
            dox->flags&=~(DOXF_EOF|DOXF_ERROR|DOXF_LOADING);
            break;
         case AOURL_Eof:
            if(tag->ti_Data)
            {  dox->flags|=DOXF_EOF;
               dox->flags&=~DOXF_LOADING;  /* Load completed successfully */
               eof=TRUE;
            }
            break;
         case AOURL_Error:
            if(tag->ti_Data)
            {  dox->flags|=DOXF_EOF|DOXF_ERROR;
               dox->flags&=~DOXF_LOADING;  /* Load completed with error */
               eof=TRUE;
            }
            break;
      }
   }
   if(data)
   {  Addtobuffer(&dox->buf,data,length);
      Asetattrs(dox->source,AOSRC_Memory,dox->buf.size,TAG_END);
   }
   if(eof)
   {  Addtobuffer(&dox->buf,"",1);
      Signaldocs(dox);
   }
   return 0;
}

/* A new child was added; send it an initial update msg */
static long Addchilddocext(struct Docext *dox,struct Amadd *ama)
{  Asetattrs(ama->child,AODOC_Srcupdate,TRUE,TAG_END);
   return 0;
}

static void Disposedocext(struct Docext *dox)
{  REMOVE(dox);
   Freebuffer(&dox->buf);
   Asetattrs(dox->source,AOSRC_Memory,0,TAG_END);
   Amethodas(AOTP_OBJECT,dox,AOM_DISPOSE);
}

static void Deinstalldocext(void)
{  struct Docref *p;
   while(p=REMHEAD(&docrefs)) FREE(p);
}

static long Dispatch(struct Docext *dox,struct Amessage *amsg)
{  long result=0;
   switch(amsg->method)
   {  case AOM_NEW:
         result=(long)Newdocext((struct Amset *)amsg);
         break;
      case AOM_SET:
         result=Setdocext(dox,(struct Amset *)amsg);
         break;
      case AOM_GET:
         result=Getdocext(dox,(struct Amset *)amsg);
         break;
      case AOM_SRCUPDATE:
         result=Srcupdatedocext(dox,(struct Amsrcupdate *)amsg);
         break;
      case AOM_ADDCHILD:
         result=Addchilddocext(dox,(struct Amadd *)amsg);
         break;
      case AOM_DISPOSE:
         Disposedocext(dox);
         break;
      case AOM_DEINSTALL:
         Deinstalldocext();
         break;
   }
   return result;
}

/*------------------------------------------------------------------------*/

BOOL Installdocext(void)
{  NEWLIST(&docexts);
   NEWLIST(&docrefs);
   if(!Amethod(NULL,AOM_INSTALL,AOTP_DOCEXT,Dispatch)) return FALSE;
   return TRUE;
}

/* Return the source for this document extension. If NULL return, a
 * load for that file was started and the document was added to the
 * wait list.
 * If (UBYTE *)~0 return, the extension is in error. */
UBYTE *Finddocext(struct Document *doc,void *url,BOOL reload)
{  struct Docext *dox;
   ULONG loadflags=AUMLF_DOCEXT;
   void *durl;
   void *furl=(void *)Agetattr(url,AOURL_Finalurlptr);
   UBYTE *urlstr;
   extern BOOL httpdebug;
   urlstr = (UBYTE *)Agetattr(url,AOURL_Url);
   if(httpdebug)
   {  printf("[FETCH] Finddocext: URL=%s, reload=%d\n", urlstr ? (char *)urlstr : "NULL", reload ? 1 : 0);
   }
   if(reload)
   {  loadflags|=AUMLF_RELOAD;
      if(httpdebug)
      {  printf("[FETCH] Finddocext: Reload requested, forcing fresh load\n");
      }
   }
   else
   {  struct Docext *found_dox=NULL;
      for(dox=docexts.first;dox->next;dox=dox->next)
      {  durl=(void *)Agetattr(dox->url,AOURL_Finalurlptr);
         if(durl==furl)
         {  found_dox=dox;
            if(dox->flags&DOXF_ERROR)
            {  if(httpdebug)
               {  printf("[FETCH] Finddocext: Cached entry found but in ERROR state, clearing error and retrying\n");
               }
               /* Clear ERROR flag and retry loading - the error might have been transient
                * or from a previous page load. This allows CSS to load on new page navigations. */
               dox->flags&=~DOXF_ERROR;
               dox->flags&=~DOXF_EOF;
               dox->flags&=~DOXF_LOADING;
               Freebuffer(&dox->buf);
               /* Set LOADING flag immediately to prevent race conditions */
               dox->flags|=DOXF_LOADING;
               /* Break out to start loading - don't fall through */
               break;
            }
            /* Only return cached buffer if it's complete (EOF reached) and valid.
             * After a reload, the buffer is freed and DOXF_EOF is cleared, so
             * we need to reload it instead of returning an invalid buffer.
             * Also check that buffer has meaningful content (more than just null terminator). */
            if((dox->flags&DOXF_EOF) && !(dox->flags&DOXF_ERROR) && dox->buf.buffer && dox->buf.length > 1)
            {  if(httpdebug)
               {  printf("[FETCH] Finddocext: Cache HIT - returning cached buffer, length=%ld bytes\n", dox->buf.length);
               }
               return dox->buf.buffer;
            }
            /* If a load is already in progress, don't start another one - just wait for it to complete */
            if(dox->flags&DOXF_LOADING)
            {  if(httpdebug)
               {  printf("[FETCH] Finddocext: Cached entry found but load already in progress, waiting for completion\n");
               }
               /* Add this document to the wait list and return NULL - the existing load will signal when done */
               Addwaitingdoc(doc,url);
               return NULL;
            }
            if(httpdebug)
            {  printf("[FETCH] Finddocext: Cached entry found but buffer not ready (EOF=%d, buffer=%p, length=%ld), loading fresh\n",
                      (dox->flags&DOXF_EOF) ? 1 : 0, dox->buf.buffer, dox->buf.length);
            }
            /* Buffer not ready yet, break out to start loading */
            break;
         }
      }
      if(httpdebug && !found_dox)
      {  printf("[FETCH] Finddocext: Cache MISS - starting async load\n");
      }
      /* If we found an entry that needs loading and LOADING flag isn't already set,
       * set it before starting the load. (It may already be set if we cleared ERROR above) */
      if(found_dox && !(found_dox->flags&DOXF_LOADING))
      {  found_dox->flags|=DOXF_LOADING;
      }
   }
   Addwaitingdoc(doc,url);
   Auload(url,loadflags,NULL,NULL,NULL);
   return NULL;
}

