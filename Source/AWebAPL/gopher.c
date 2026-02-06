/**********************************************************************
 * 
 * This file is part of the AWeb-II distribution
 *
 * Copyright (C) 2002 Yvon Rozijn
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

/* gopher.c - AWeb gopher client */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <clib/exec_protos.h>
#include "aweblib.h"
#include "tcperr.h"
#include "fetchdriver.h"
#include "task.h"
#include "awebtcp.h"
#include <exec/resident.h>
#include <proto/utility.h>
#include <stdarg.h>

struct BoundedFmt
{
   UBYTE *buf;
   long size;
   long len;
};

static void PutChBounded(UBYTE ch, APTR data)
{
   struct BoundedFmt *bf = (struct BoundedFmt *)data;
   if(!bf || !bf->buf || bf->size <= 0) return;

   /* Leave room for NUL */
   if(bf->len < bf->size - 1)
   {
      bf->buf[bf->len++] = ch;
      bf->buf[bf->len] = '\0';
   }
}

static long BVSNPrintf(UBYTE *dst, long dstsize, const UBYTE *fmt, va_list ap)
{
   struct BoundedFmt bf;

   if(!dst || dstsize <= 0) return 0;
   dst[0] = '\0';

   bf.buf  = dst;
   bf.size = dstsize;
   bf.len  = 0;

   VNewRawDoFmt((STRPTR)fmt, PutChBounded, (APTR)&bf, ap);

   return bf.len;
}

static long BSNPrintf(UBYTE *dst, long dstsize, const UBYTE *fmt, ...)
{
   va_list ap;
   long n;

   va_start(ap, fmt);
   n = BVSNPrintf(dst, dstsize, fmt, ap);
   va_end(ap);

   return n;
}

#ifndef LOCALONLY

struct Gopheraddr
{  UBYTE *buf;
   UBYTE *hostname;
   long port;
   UBYTE *selector;
   UBYTE type;
   BOOL query;
};

struct Library *AwebTcpBase;
void *AwebPluginBase;

/*-----------------------------------------------------------------------*/
/* AWebLib module startup */

__asm __saveds struct Library *Initlib(
   register __a6 struct ExecBase *sysbase,
   register __a0 struct SegList *seglist,
   register __d0 struct Library *libbase);

__asm __saveds struct Library *Openlib(
   register __a6 struct Library *libbase);

__asm __saveds struct SegList *Closelib(
   register __a6 struct Library *libbase);

__asm __saveds struct SegList *Expungelib(
   register __a6 struct Library *libbase);

__asm __saveds ULONG Extfunclib(void);

__asm __saveds void Fetchdrivertask(
   register __a0 struct Fetchdriver *fd);

/* Function declarations for project dependent hook functions */
static ULONG Initaweblib(struct Library *libbase);
static void Expungeaweblib(struct Library *libbase);

struct Library *GopherBase;

static APTR libseglist;

struct ExecBase *SysBase;

LONG __saveds __asm Libstart(void)
{  return -1;
}

static APTR functable[]=
{  Openlib,
   Closelib,
   Expungelib,
   Extfunclib,
   Fetchdrivertask,
   (APTR)-1
};

/* Init table used in library initialization. */
static ULONG inittab[]=
{  sizeof(struct Library),
   (ULONG) functable,
   0,
   (ULONG) Initlib
};

static char __aligned libname[]="gopher.aweblib";
static char __aligned libid[]="gopher.aweblib " AWEBLIBVSTRING " " __AMIGADATE__;

/* The ROM tag */
struct Resident __aligned romtag=
{  RTC_MATCHWORD,
   &romtag,
   &romtag+1,
   RTF_AUTOINIT,
   AWEBLIBVERSION,
   NT_LIBRARY,
   0,
   libname,
   libid,
   inittab
};

__asm __saveds struct Library *Initlib(
   register __a6 struct ExecBase *sysbase,
   register __a0 struct SegList *seglist,
   register __d0 struct Library *libbase)
{  SysBase=sysbase;
   GopherBase=libbase;
   libbase->lib_Revision=AWEBLIBREVISION;
   libseglist=seglist;
   if(!Initaweblib(libbase))
   {  Expungeaweblib(libbase);
      libbase=NULL;
   }
   return libbase;
}

__asm __saveds struct Library *Openlib(
   register __a6 struct Library *libbase)
{  libbase->lib_OpenCnt++;
   libbase->lib_Flags&=~LIBF_DELEXP;
   if(libbase->lib_OpenCnt==1)
   {  AwebPluginBase=OpenLibrary("awebplugin.library",0);
   }
#ifndef DEMOVERSION
   if(!Fullversion())
   {  Closelib(libbase);
      return NULL;
   }
#endif
   return libbase;
}

__asm __saveds struct SegList *Closelib(
   register __a6 struct Library *libbase)
{  libbase->lib_OpenCnt--;
   if(libbase->lib_OpenCnt==0)
   {  if(AwebPluginBase)
      {  CloseLibrary(AwebPluginBase);
         AwebPluginBase=NULL;
      }
      if(libbase->lib_Flags&LIBF_DELEXP)
      {  return Expungelib(libbase);
      }
   }
   return NULL;
}

__asm __saveds struct SegList *Expungelib(
   register __a6 struct Library *libbase)
{  if(libbase->lib_OpenCnt==0)
   {  ULONG size=libbase->lib_NegSize+libbase->lib_PosSize;
      UBYTE *ptr=(UBYTE *)libbase-libbase->lib_NegSize;
      Remove((struct Node *)libbase);
      Expungeaweblib(libbase);
      FreeMem(ptr,size);
      return libseglist;
   }
   libbase->lib_Flags|=LIBF_DELEXP;
   return NULL;
}

__asm __saveds ULONG Extfunclib(void)
{  return 0;
}

/*-----------------------------------------------------------------------*/

/* Decode %AA url encoding */
static void Urldecode(UBYTE *string)
{  UBYTE *p,*q,*end;
   UBYTE c;
   short i;
   p=q=string;
   end=string+strlen(string);
   while(p<end)
   {  if(*p=='%' && p<end-3)
      {  c=0;
         for(i=0;i<2;i++)
         {  c<<=4;
            p++;
            if(*p>='0' && *p<='9')
            {  c+=*p-'0';
            }
            else if(*p>='A' && *p<='F')
            {  c+=*p-'A'+10;
            }
            else if(*p>='a' && *p<='f')
            {  c+=*p-'a'+10;
            }
         }
         *q=c;
      }
      else if(q!=p)
      {  *q=*p;
      }
      p++;
      q++;
   }
   *q='\0';
}

static BOOL Makegopheraddr(struct Gopheraddr *ha,UBYTE *name)
{  long len=strlen(name);
   UBYTE *p,*q;
   ha->buf=ALLOCTYPE(UBYTE,len+2,0);
   if(!ha->buf) return FALSE;
   p=name;
   ha->hostname=q=ha->buf;
   while(*p && *p!='/' && *p!=':') *q++=*p++;
   *q++='\0';
   if(*p==':')
   {  ha->port=0;
      p++;
      while(isdigit(*p))
      {  ha->port=10*ha->port+(*p-'0');
         p++;
      }
   }
   else ha->port=70;
   while(*p && *p!='/') p++;
   if(*p) p++; /* skip / */
   if(*p)
   {  ha->type=*p++;
      strcpy(q,p);
   }
   else
   {  ha->type='1';
      *q='\0';
   }
   ha->selector=q;
   if(ha->type=='7' && (p=strchr(ha->selector,'?')))
   {  ha->query=TRUE;
      *p='\t';
   }
   Urldecode(ha->hostname);
   Urldecode(ha->selector);
   return TRUE;
}

/*-----------------------------------------------------------------------*/

struct GResponse
{  struct Buffer buf;
   BOOL headerdone;
};

static UBYTE *Findtab(UBYTE *p,UBYTE *end)
{  while(p<end && *p!='\t' && *p!='\r' && *p!='\n') p++;
   if(p<end) return p;
   else return NULL;
}

static UBYTE *Findeol(UBYTE *p,UBYTE *end)
{  while(p<end && *p!='\r' && *p!='\n') p++;
   if(p<end) return p;
   else return NULL;
}

static void Builddir(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  UBYTE *p,*end,*descr,*selector,*host,*hport;
   UBYTE type;
   UBYTE *icon;
   long length=0;
   if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   if(!resp->headerdone)
   {  length = BSNPrintf(fd->block, fd->blocksize,
        "<html><h1>%s</h1>", AWEBSTR(MSG_AWEB_GOPHERMENU));
      resp->headerdone=TRUE;
   }
   for(;;)
   {  p=resp->buf.buffer;
      end=p+resp->buf.length;
      while(p<end && (*p=='\n' || *p=='\r')) p++;
      if(p>=end) break;
      type=*p;
      descr=++p;
      if(!(p=Findtab(p,end))) break;
      *p='\0';
      selector=++p;
      if(!(p=Findtab(p,end))) break;
      *p='\0';
      host=++p;
      if(!(p=Findtab(p,end))) break;
      *p='\0';
      hport=++p;
      if(!(p=Findtab(p,end))) break;
      if(*p=='\r' || *p=='\n') *p='\0';
      else
      {  *p='\0';
         if(!(p=Findeol(p,end))) break;
      }
      switch(type)
      {  case '0':icon="&text.document;";break;
         case '1':icon="&folder;";break;
         case '4':icon="&binhex.document;";break;
         case '5':icon="&archive;";break;
         case '6':icon="&uuencoded.document;";break;
         case '7':icon="&index;";break;
         case '9':icon="&binary.document;";break;
         case 'g':icon="&image;";break;
         case 'I':icon="&image;";break;
         default: icon=NULL;
      }
      if(icon)
      {
         /* Flush BEFORE appending, so we never write past fd->blocksize */
         if(length > fd->blocksize - 1000)
         {  Updatetaskattrs(
              AOURL_Data,fd->block,
              AOURL_Datalength,length,
              TAG_END);
            length = 0;
            fd->block[0] = '\0';
         }

         /* Bounded append */
         if(length < fd->blocksize)
         {  length += BSNPrintf(fd->block + length, fd->blocksize - length,
              "<BR>%s <A HREF=\"gopher://%s:%s/%c%s\">%s</A>",
              icon,host,hport,type,selector,descr);
         }
      }
      p++;
      Deleteinbuffer(&resp->buf,0,p-resp->buf.buffer);
   }
   if(length)
   {  Updatetaskattrs(
         AOURL_Data,fd->block,
         AOURL_Datalength,length,
         TAG_END);
   }
}

static void Deleteperiods(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  UBYTE *p,*end,*begin;
   long length=0;
   if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   for(;;)
   {  p=resp->buf.buffer;
      end=p+resp->buf.length;
      if(p>=end) break;
      if(*p=='.') p++;
      begin=p;
      if(!(p=Findeol(p,end))) break;
      p++;
      {
          long chunk = p - begin;

          /* Flush BEFORE copying */
          if(length > fd->blocksize - 1000)
          {  Updatetaskattrs(
                AOURL_Data,fd->block,
                AOURL_Datalength,length,
                TAG_END);
             length = 0;
          }

          /* Bounded copy */
          if(length < fd->blocksize)
          {  long space = fd->blocksize - length;
                if(chunk > space) chunk = space;
                if(chunk > 0)
                {  memmove(fd->block + length, begin, chunk);
                   length += chunk;
                }
          }
      }
      Deleteinbuffer(&resp->buf,0,p-resp->buf.buffer);
   }
   if(length)
   {  Updatetaskattrs(
         AOURL_Data,fd->block,
         AOURL_Datalength,length,
         TAG_END);
   }
}

static void Makeindex(struct Fetchdriver *fd)
{  long length;
   length = BSNPrintf(fd->block, fd->blocksize,
      "<html><h1>%s</h1><isindex>", AWEBSTR(MSG_AWEB_GOPHERINDEX));
   Updatetaskattrs(
      AOURL_Data,fd->block,
      AOURL_Datalength,length,
      TAG_END);
}

__saveds __asm void Fetchdrivertask(register __a0 struct Fetchdriver *fd)
{  struct Library *SocketBase;
   struct Gopheraddr ha={0};
   struct hostent *hent;
   struct GResponse resp={0};
   BOOL error=FALSE;
   long sock;
   long result,length;
   AwebTcpBase=Opentcp(&SocketBase,fd,!fd->validate);
   if(SocketBase)
   {  if(Makegopheraddr(&ha,fd->name))
      {  if(ha.type=='7' && !ha.query)
         {  Makeindex(fd);
         }
         else
         {  Updatetaskattrs(AOURL_Netstatus,NWS_LOOKUP,TAG_END);
            Tcpmessage(fd,TCPMSG_LOOKUP,ha.hostname);
            if(hent=Lookup(ha.hostname,SocketBase))
            {  if((sock=a_socket(hent->h_addrtype,SOCK_STREAM,0,SocketBase))>=0)
               {  Updatetaskattrs(AOURL_Netstatus,NWS_CONNECT,TAG_END);
                  Tcpmessage(fd,TCPMSG_CONNECT,"Gopher",hent->h_name);
                  if(!a_connect(sock,hent,ha.port,SocketBase))
                  {  length = BSNPrintf(fd->block, fd->blocksize, "%s\r\n", ha.selector);
                     result=(a_send(sock,fd->block,length,0,SocketBase)==length);
                     if(result)
                     {  Updatetaskattrs(AOURL_Netstatus,NWS_WAIT,TAG_END);
                        Tcpmessage(fd,TCPMSG_WAITING,"Gopher");
                        for(;;)
                        {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                           if(length<0 || Checktaskbreak())
                           {  error=TRUE;
                              break;
                           }
                           if(ha.type=='1' || ha.type=='7')
                           {  Builddir(fd,&resp,length);
                           }
                           else if(ha.type=='0')
                           {  Deleteperiods(fd,&resp,length);
                           }
                           else
                           {  Updatetaskattrs(
                                 AOURL_Data,fd->block,
                                 AOURL_Datalength,length,
                                 TAG_END);
                           }
                           if(length==0) break;
                        }
                        a_shutdown(sock,2,SocketBase);
                     }
                     else error=TRUE;
                  }
                  else
                  {  Tcperror(fd,TCPERR_NOCONNECT,hent->h_name);
                  }
                  a_close(sock,SocketBase);
               }
               else error=TRUE;
            }
            else
            {  Tcperror(fd,TCPERR_NOHOST,ha.hostname);
            }
         }
         FREE(ha.buf);
      }
      else error=TRUE;
      a_cleanup(SocketBase);
      CloseLibrary(SocketBase);
   }
   else
   {  Tcperror(fd,TCPERR_NOLIB);
   }
   Freebuffer(&resp.buf);
   Updatetaskattrs(AOTSK_Async,TRUE,
      AOURL_Error,error,
      AOURL_Eof,TRUE,
      AOURL_Terminate,TRUE,
      TAG_END);
}

/*-----------------------------------------------------------------------*/

static ULONG Initaweblib(struct Library *libbase)
{  return TRUE;
}

static void Expungeaweblib(struct Library *libbase)
{
}

#endif /* LOCALONLY */
