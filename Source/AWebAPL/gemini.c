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

/* gemini.c - AWeb Gemini protocol client */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <proto/exec.h>
#include <proto/socket.h>
#include "aweblib.h"
#include "tcperr.h"
#include "fetchdriver.h"
#include "task.h"
#include "awebtcp.h"
#include "awebssl.h"
#include <exec/resident.h>

#ifndef LOCALONLY

struct Geminaddr
{  UBYTE *buf;
   UBYTE *hostname;
   long port;
   UBYTE *path;
   UBYTE *query;
};

struct Library *AwebTcpBase;
struct Library *AwebSslBase;
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

struct Library *GeminiBase;

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

static char __aligned libname[]="gemini.aweblib";
static char __aligned libid[]="gemini.aweblib " AWEBLIBVSTRING " " __AMIGADATE__;

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
   GeminiBase=libbase;
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

/* Parse gemini://host:port/path?query URL */
/* Note: name should NOT include gemini:// prefix (it's stripped in fetch.c) */
static BOOL Makegeminaddr(struct Geminaddr *ha,UBYTE *name)
{  long len=strlen(name);
   UBYTE *p,*q,*query_start;
   ha->buf=ALLOCTYPE(UBYTE,len+2,0);
   if(!ha->buf) return FALSE;
   p=name;
   /* CRITICAL: Ensure name doesn't contain gemini:// prefix */
   /* This should never happen, but check to prevent error 53 */
   if(!strnicmp(p,"gemini://",9))
   {  /* Skip gemini:// prefix if present (shouldn't happen) */
      p+=9;
   }
   ha->hostname=q=ha->buf;
   /* Extract hostname */
   while(*p && *p!='/' && *p!=':') *q++=*p++;
   *q++='\0';
   /* Extract port */
   if(*p==':')
   {  ha->port=0;
      p++;
      while(isdigit(*p))
      {  ha->port=10*ha->port+(*p-'0');
         p++;
      }
   }
   else ha->port=1965;  /* Default Gemini port */
   /* Extract path - p now points to either /, ?, or \0 */
   /* Skip to the path part (after the /) */
   if(*p=='/') p++;  /* skip leading / */
   else if(*p && *p!='?')
   {  /* No / found, but there's more data - this shouldn't happen with gemini:// URLs */
      /* Skip any remaining characters until / or ? */
      while(*p && *p!='/' && *p!='?') p++;
      if(*p=='/') p++;  /* skip / if found */
   }
   query_start=strchr(p,'?');
   if(query_start)
   {  /* Has query string */
      ha->path=q;
      while(p<query_start) *q++=*p++;
      *q++='\0';
      ha->query=q;
      p++;  /* skip ? */
      strcpy(q,p);
   }
   else
   {  /* No query string */
      ha->path=q;
      if(*p)
      {  strcpy(q,p);
      }
      else
      {  *q='\0';
      }
      ha->query=NULL;
   }
   Urldecode(ha->hostname);
   Urldecode(ha->path);
   if(ha->query) Urldecode(ha->query);
   /* Validate hostname is not empty */
   if(!ha->hostname || !*ha->hostname)
   {  FREE(ha->buf);
      ha->buf=NULL;
      return FALSE;
   }
   return TRUE;
}

/*-----------------------------------------------------------------------*/

struct GResponse
{  struct Buffer buf;
   BOOL headerdone;
   int status_code;
   UBYTE *mime_type;
   BOOL status_parsed;
};

/* Find end of line */
static UBYTE *Findeol(UBYTE *p,UBYTE *end)
{  while(p<end && *p!='\r' && *p!='\n') p++;
   if(p<end) return p;
   else return NULL;
}

/* Parse status line: STATUS<SPACE>META<CR><LF> */
static BOOL Parsestatusline(struct GResponse *resp,UBYTE *line,long len)
{  UBYTE *p,*end,*meta_start;
   int status;
   long metalen=0;
   UBYTE temp_mime[256];
   if(len<3) return FALSE;  /* Minimum: "20 " */
   p=line;
   end=line+len;
   /* Parse status code (2 digits) */
   if(!isdigit(*p) || !isdigit(*(p+1))) return FALSE;
   status=(*p-'0')*10+(*(p+1)-'0');
   p+=2;
   /* Skip space */
   if(p>=end || *p!=' ') return FALSE;
   p++;
   /* META field starts here */
   meta_start=p;
   /* Find end of META (CR or LF) */
   while(p<end && *p!='\r' && *p!='\n') p++;
   if(p>meta_start)
   {  metalen=p-meta_start;
      if(metalen>=sizeof(temp_mime)) metalen=sizeof(temp_mime)-1;
      memmove(temp_mime,meta_start,metalen);
      temp_mime[metalen]='\0';
      resp->status_code=status;
      if(Addtobuffer(&resp->buf,temp_mime,metalen+1))
      {  long mime_offset;
         mime_offset=metalen+1;
         resp->mime_type=resp->buf.buffer+resp->buf.length-mime_offset;
         resp->status_parsed=TRUE;
         return TRUE;
      }
   }
   return FALSE;
}

/* Convert text/gemini markup to HTML */
static void Convertgeminitohtml(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  UBYTE *p,*end,*line_start;
   UBYTE *out;
   long outlen=0;
   UBYTE in_pre=0;  /* Flag for preformatted blocks */
   if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   if(!resp->headerdone)
   {  sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body>");
      outlen=strlen(fd->block);
      resp->headerdone=TRUE;
   }
   out=fd->block+outlen;
   p=resp->buf.buffer;
   end=p+resp->buf.length;
   while(p<end)
   {  line_start=p;
      /* Find end of line */
      while(p<end && *p!='\r' && *p!='\n') p++;
      if(p>line_start)
      {  long linelen=p-line_start;
         UBYTE *line=line_start;
         /* Check for preformatted toggle */
         if(linelen>=3 && line[0]=='`' && line[1]=='`' && line[2]=='`')
         {  if(in_pre)
            {  outlen+=sprintf(out+outlen,"</pre>");
               in_pre=0;
            }
            else
            {  outlen+=sprintf(out+outlen,"<pre>");
               in_pre=1;
            }
         }
         else if(in_pre)
         {  /* In preformatted block - pass through */
            if(outlen+linelen+1>INPUTBLOCKSIZE-1000)
            {  Updatetaskattrs(
                  AOURL_Data,fd->block,
                  AOURL_Datalength,outlen,
                  TAG_END);
               outlen=0;
               out=fd->block;
            }
            memmove(out+outlen,line,linelen);
            outlen+=linelen;
            out[outlen++]='\n';
         }
         else
         {  /* Regular line - check for Gemini markup */
            if(linelen>=2 && line[0]=='=' && line[1]=='=')
            {  /* Heading: ==text== */
               UBYTE *text=line+2;
               long textlen=linelen-2;
               while(textlen>0 && text[textlen-1]=='=') textlen--;
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<h1>%.*s</h1>",textlen,text);
               }
            }
            else if(linelen>=1 && line[0]=='=')
            {  /* Heading: =text= */
               UBYTE *text=line+1;
               long textlen=linelen-1;
               while(textlen>0 && text[textlen-1]=='=') textlen--;
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<h2>%.*s</h2>",textlen,text);
               }
            }
            else if(linelen>=2 && line[0]=='=' && line[1]==' ')
            {  /* Link: => URL Description */
               UBYTE *url_start=line+2;
               UBYTE *desc_start=NULL;
               long urllen=0;
               long desclen=0;
               UBYTE *q;
               /* Find space separating URL and description */
               for(q=url_start;q<line+linelen;q++)
               {  if(*q==' ')
                  {  urllen=q-url_start;
                     desc_start=q+1;
                     desclen=(line+linelen)-desc_start;
                     break;
                  }
               }
               if(!desc_start)
               {  /* No description, URL is entire rest of line */
                  urllen=linelen-2;
                  desc_start=url_start+urllen;
                  desclen=0;
               }
               if(urllen>0)
               {  if(desclen>0)
                  {  outlen+=sprintf(out+outlen,"<p><a href=\"%.*s\">%.*s</a></p>",
                        urllen,url_start,desclen,desc_start);
                  }
                  else
                  {  outlen+=sprintf(out+outlen,"<p><a href=\"%.*s\">%.*s</a></p>",
                        urllen,url_start,urllen,url_start);
                  }
               }
            }
            else if(linelen>=1 && line[0]=='*' && line[1]==' ')
            {  /* List item: * text */
               UBYTE *text=line+2;
               long textlen=linelen-2;
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<li>%.*s</li>",textlen,text);
               }
            }
            else if(linelen>=1 && line[0]=='>')
            {  /* Quote: >text */
               UBYTE *text=line+1;
               long textlen=linelen-1;
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<blockquote>%.*s</blockquote>",textlen,text);
               }
            }
            else if(linelen>0)
            {  /* Regular paragraph */
               outlen+=sprintf(out+outlen,"<p>%.*s</p>",linelen,line);
            }
         }
      }
      /* Skip line ending */
      if(p<end && *p=='\r') p++;
      if(p<end && *p=='\n') p++;
      if(outlen>INPUTBLOCKSIZE-1000)
      {  Updatetaskattrs(
            AOURL_Data,fd->block,
            AOURL_Datalength,outlen,
            TAG_END);
         outlen=0;
         out=fd->block;
      }
      /* Delete processed line from buffer */
      if(p>resp->buf.buffer)
      {  Deleteinbuffer(&resp->buf,0,p-resp->buf.buffer);
         p=resp->buf.buffer;
         end=p+resp->buf.length;
      }
   }
   if(outlen)
   {  Updatetaskattrs(
         AOURL_Data,fd->block,
         AOURL_Datalength,outlen,
         TAG_END);
   }
}

/* Handle text/html content - pass through */
static void Handlehtml(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   if(!resp->headerdone)
   {  resp->headerdone=TRUE;
   }
   /* Pass through HTML content */
   Updatetaskattrs(
      AOURL_Data,resp->buf.buffer,
      AOURL_Datalength,resp->buf.length,
      TAG_END);
   Deleteinbuffer(&resp->buf,0,resp->buf.length);
}

/* Handle text/plain content */
static void Handleplaintext(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  UBYTE *p,*end,*begin;
   long length=0;
   if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   if(!resp->headerdone)
   {  sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body><pre>");
      length=strlen(fd->block);
      resp->headerdone=TRUE;
   }
   for(;;)
   {  p=resp->buf.buffer;
      end=p+resp->buf.length;
      if(p>=end) break;
      begin=p;
      if(!(p=Findeol(p,end))) break;
      p++;
      memmove(fd->block+length,begin,p-begin);
      length+=p-begin;
      if(length>INPUTBLOCKSIZE-1000)
      {  Updatetaskattrs(
            AOURL_Data,fd->block,
            AOURL_Datalength,length,
            TAG_END);
         length=0;
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

/* Handle other content types - pass through as binary */
static void Handleother(struct Fetchdriver *fd,struct GResponse *resp,long read)
{  if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   Updatetaskattrs(
      AOURL_Data,resp->buf.buffer,
      AOURL_Datalength,resp->buf.length,
      TAG_END);
   Deleteinbuffer(&resp->buf,0,resp->buf.length);
}


/* Follow redirect - extract URL from META and return new URL */
static UBYTE *Extractredirecturl(struct Geminaddr *ha,UBYTE *meta)
{  UBYTE *url;
   long len;
   /* META contains the redirect URL */
   len=strlen(meta);
   url=ALLOCTYPE(UBYTE,len+1,0);
   if(url)
   {  strcpy(url,meta);
   }
   return url;
}

/* Resolve relative URL against base URL */
static BOOL Resolverelativeurl(struct Geminaddr *base,UBYTE *relative,struct Geminaddr *result)
{  UBYTE *fullurl;
   long len;
   UBYTE *p;
   /* Check if absolute URL (starts with gemini://) */
   if(!strnicmp(relative,"gemini://",9))
   {  /* Skip gemini:// prefix */
      p=relative+9;
      return Makegeminaddr(result,p);
   }
   /* Simple implementation: if relative starts with /, it's relative to host */
   if(relative[0]=='/')
   {  len=strlen(base->hostname)+strlen(relative)+20;
      fullurl=ALLOCTYPE(UBYTE,len,0);
      if(fullurl)
      {  sprintf(fullurl,"%s:%ld%s",
            base->hostname,base->port,relative);
         return Makegeminaddr(result,fullurl);
      }
   }
   else
   {  /* Assume absolute URL without scheme */
      return Makegeminaddr(result,relative);
   }
   return FALSE;
}

/* Main fetch driver task */
__saveds __asm void Fetchdrivertask(register __a0 struct Fetchdriver *fd)
{  struct Library *SocketBase;
   struct Geminaddr ha={0};
   struct hostent *hent;
   struct GResponse resp={0};
   BOOL error=FALSE;
   long sock=-1;
   long result,length;
   int redirect_count=0;
   UBYTE *request_path;
   long request_len;
   long status_line_len;
   UBYTE *redirect_url=NULL;
   
   AwebTcpBase=Opentcp(&SocketBase,fd,!fd->validate);
   if(SocketBase && AwebTcpBase)
   {  if(Makegeminaddr(&ha,fd->name))
      {  /* Follow redirects up to 5 times */
            while(redirect_count<5 && !error)
            {  if(Checktaskbreak())
               {  error=TRUE;
                  break;
               }
               /* Validate hostname before lookup */
               if(!ha.hostname || !*ha.hostname)
               {  Tcperror(fd,TCPERR_NOHOST,"");
                  error=TRUE;
                  break;
               }
               Updatetaskattrs(AOURL_Netstatus,NWS_LOOKUP,TAG_END);
               Tcpmessage(fd,TCPMSG_LOOKUP,ha.hostname);
               if(hent=Lookup(ha.hostname,SocketBase))
               {  /* Validate hostent structure before use */
                  if(hent->h_name && hent->h_addr_list && hent->h_addr_list[0])
                  {  if((sock=a_socket(hent->h_addrtype,SOCK_STREAM,0,SocketBase))>=0)
                     {  if(Checktaskbreak())
                        {  error=TRUE;
                           a_close(sock,SocketBase);
                           sock=-1;
                           break;
                        }
                        Updatetaskattrs(AOURL_Netstatus,NWS_CONNECT,TAG_END);
                        Tcpmessage(fd,TCPMSG_CONNECT,"Gemini",hent->h_name);
                        if(!a_connect(sock,hent,ha.port,SocketBase))
                        {  if(Checktaskbreak())
                           {  error=TRUE;
                              a_close(sock,SocketBase);
                              sock=-1;
                              break;
                           }
                           /* Build request: path?query<CR><LF> */
                              request_len=0;
                              if(ha.path && *ha.path)
                              {  request_len+=strlen(ha.path);
                              }
                              else
                              {  request_len+=1;  /* "/" */
                              }
                              if(ha.query && *ha.query)
                              {  request_len+=1+strlen(ha.query);  /* "?" + query */
                              }
                              request_len+=2;  /* <CR><LF> */
                              request_path=fd->block;
                              /* Gemini protocol requires absolute path starting with / */
                              /* CRITICAL: Never send full URL or hostname - only send the path */
                              /* Format must be: /path?query<CR><LF> */
                              if(ha.path && *ha.path)
                              {  /* Path exists - ensure it starts with / and doesn't contain hostname */
                                 /* Check if path accidentally contains hostname (should never happen) */
                                 if(strstr(ha.path,"://") || strstr(ha.path,"gemini://"))
                                 {  /* ERROR: Path contains URL - this should never happen */
                                    /* Fall back to root path */
                                    sprintf(request_path,"/");
                                 }
                                 else if(ha.path[0]=='/')
                                 {  /* Already has leading / */
                                    sprintf(request_path,"%s",ha.path);
                                 }
                                 else
                                 {  /* Missing leading / - add it */
                                    sprintf(request_path,"/%s",ha.path);
                                 }
                              }
                              else
                              {  /* No path - send root */
                                 sprintf(request_path,"/");
                              }
                              if(ha.query && *ha.query)
                              {  sprintf(request_path+strlen(request_path),"?%s",ha.query);
                              }
                              sprintf(request_path+strlen(request_path),"\r\n");
                              /* Verify request format is correct before sending */
                              /* Request should be: /path?query<CR><LF> or just /<CR><LF> */
                              /* Must NOT contain hostname or gemini:// prefix */
                              if(request_path[0]!='/')
                              {  /* ERROR: Request doesn't start with / - fix it */
                                 request_path[0]='/';
                                 request_path[1]='\0';
                                 sprintf(request_path+1,"\r\n");
                              }
                              /* Send request - format: /path?query<CR><LF> */
                              result=(a_send(sock,request_path,request_len,0,SocketBase)==request_len);
                              if(result)
                              {  Updatetaskattrs(AOURL_Netstatus,NWS_WAIT,TAG_END);
                                 Tcpmessage(fd,TCPMSG_WAITING,"Gemini");
                                 /* Read status line (max 1024 bytes) */
                                 /* Use response buffer to store status line */
                                 status_line_len=0;
                                 resp.status_parsed=FALSE;
                                 resp.headerdone=FALSE;
                                 while(status_line_len<1024 && !resp.status_parsed)
                                 {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                    if(length<0 || Checktaskbreak())
                                    {  error=TRUE;
                                       break;
                                    }
                                    if(length==0) break;
                                    if(!Addtobuffer(&resp.buf,fd->block,length)) break;
                                    status_line_len+=length;
                                    /* Check for CRLF */
                                    if(status_line_len>=2)
                                    {  UBYTE *eol;
                                       eol=Findeol(resp.buf.buffer,resp.buf.buffer+resp.buf.length);
                                       if(eol)
                                       {  /* Found end of status line */
                                          if(Parsestatusline(&resp,resp.buf.buffer,eol-resp.buf.buffer))
                                          {  /* Status parsed successfully */
                                             /* Skip status line from buffer */
                                             eol++;
                                             if(eol<resp.buf.buffer+resp.buf.length && *eol=='\n') eol++;
                                             Deleteinbuffer(&resp.buf,0,eol-resp.buf.buffer);
                                             break;
                                          }
                                       }
                                    }
                                 }
                                 if(!error && resp.status_parsed)
                                 {  /* Handle based on status code */
                                    if(resp.status_code>=20 && resp.status_code<30)
                                    {  /* Success - process body based on MIME type */
                                       if(resp.mime_type && !strncmp(resp.mime_type,"text/gemini",11))
                                       {  /* text/gemini - convert to HTML */
                                          for(;;)
                                          {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                             if(length<0 || Checktaskbreak())
                                             {  error=TRUE;
                                                break;
                                             }
                                             if(length==0) break;
                                             Convertgeminitohtml(fd,&resp,length);
                                          }
                                          /* Close HTML */
                                          sprintf(fd->block,"</body></html>");
                                          Updatetaskattrs(
                                             AOURL_Data,fd->block,
                                             AOURL_Datalength,strlen(fd->block),
                                             TAG_END);
                                       }
                                       else if(resp.mime_type && !strncmp(resp.mime_type,"text/html",9))
                                       {  /* text/html - pass through */
                                          for(;;)
                                          {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                             if(length<0 || Checktaskbreak())
                                             {  error=TRUE;
                                                break;
                                             }
                                             if(length==0) break;
                                             Handlehtml(fd,&resp,length);
                                          }
                                       }
                                       else if(resp.mime_type && !strncmp(resp.mime_type,"text/plain",10))
                                       {  /* text/plain - display as preformatted */
                                          for(;;)
                                          {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                             if(length<0 || Checktaskbreak())
                                             {  error=TRUE;
                                                break;
                                             }
                                             if(length==0) break;
                                             Handleplaintext(fd,&resp,length);
                                          }
                                          /* Close pre tag */
                                          sprintf(fd->block,"</pre></body></html>");
                                          Updatetaskattrs(
                                             AOURL_Data,fd->block,
                                             AOURL_Datalength,strlen(fd->block),
                                             TAG_END);
                                       }
                                       else
                                       {  /* Other content types - pass through */
                                          for(;;)
                                          {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                             if(length<0 || Checktaskbreak())
                                             {  error=TRUE;
                                                break;
                                             }
                                             if(length==0) break;
                                             Handleother(fd,&resp,length);
                                          }
                                       }
                                    }
                                    else if(resp.status_code>=30 && resp.status_code<40)
                                    {  /* Redirect */
                                       if(resp.mime_type && *resp.mime_type)
                                       {  redirect_url=Extractredirecturl(&ha,resp.mime_type);
                                          if(redirect_url)
                                          {  /* Close current connection - this will clean up SSL objects */
                                             a_close(sock,SocketBase);
                                             sock=-1;
                                             /* Free old address */
                                             FREE(ha.buf);
                                             /* Resolve redirect URL */
                                             if(Resolverelativeurl(&ha,redirect_url,&ha))
                                             {  redirect_count++;
                                                  FREE(redirect_url);
                                                  redirect_url=NULL;
                                                  /* Continue loop to follow redirect */
                                                  /* SSL objects were cleaned up by a_close() above */
                                                  /* amitcp_connect() will call Assl_closessl() again before creating new SSL objects */
                                                  continue;
                                             }
                                             else
                                             {  error=TRUE;
                                                FREE(redirect_url);
                                                redirect_url=NULL;
                                             }
                                          }
                                          else
                                          {  error=TRUE;
                                          }
                                       }
                                       else
                                       {  error=TRUE;
                                       }
                                    }
                                    else if(resp.status_code>=40 && resp.status_code<60)
                                    {  /* Error - display error message */
                                       sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body><h1>Gemini Error %d</h1><p>%s</p></body></html>",
                                          resp.status_code,resp.mime_type ? (char *)resp.mime_type : "Unknown error");
                                       Updatetaskattrs(
                                          AOURL_Data,fd->block,
                                          AOURL_Datalength,strlen(fd->block),
                                          TAG_END);
                                    }
                                    else if(resp.status_code>=60 && resp.status_code<70)
                                    {  /* Client certificate required - not implemented */
                                       sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body><h1>Client Certificate Required</h1><p>This Gemini server requires a client certificate, which is not yet supported.</p></body></html>");
                                       Updatetaskattrs(
                                          AOURL_Data,fd->block,
                                          AOURL_Datalength,strlen(fd->block),
                                          TAG_END);
                                    }
                                 }
                                 else if(!error)
                                 {  /* Failed to parse status line */
                                    error=TRUE;
                                 }
                              }
                              else error=TRUE;
                        }
                        else
                        {  Tcperror(fd,TCPERR_NOCONNECT,hent->h_name ? hent->h_name : ha.hostname);
                           error=TRUE;
                        }
                        if(sock>=0)
                        {  a_close(sock,SocketBase);
                           sock=-1;
                        }
                     }
                     else error=TRUE;
                  }
                  else
                  {  /* Invalid hostent structure */
                     Tcperror(fd,TCPERR_NOHOST,ha.hostname);
                     error=TRUE;
                  }
               }
               else
               {  Tcperror(fd,TCPERR_NOHOST,ha.hostname);
                  error=TRUE;
               }
               if(error || redirect_count>=5) break;
            }
            if(redirect_url) FREE(redirect_url);
            if(ha.buf) FREE(ha.buf);
         }
         else
         {  /* Makegeminaddr failed */
            error=TRUE;
         }
      if(SocketBase)
      {  a_cleanup(SocketBase);
         CloseLibrary(SocketBase);
      }
   }
   else
   {  Tcperror(fd,TCPERR_NOLIB);
   }
   Freebuffer(&resp.buf);
   if(!Checktaskbreak())
   {  Updatetaskattrs(AOTSK_Async,TRUE,
         AOURL_Error,error,
         AOURL_Eof,TRUE,
         AOURL_Terminate,TRUE,
         TAG_END);
   }
}

/*-----------------------------------------------------------------------*/

static ULONG Initaweblib(struct Library *libbase)
{  return TRUE;
}

static void Expungeaweblib(struct Library *libbase)
{
}

#endif /* LOCALONLY */

