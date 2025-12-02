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

/* Parse gemini://host:port/path?query or spartan://host:port/path?query URL */
/* Note: name should NOT include gemini:// or spartan:// prefix (it's stripped in fetch.c) */
/* Returns TRUE if successful, FALSE on error */
/* Sets default port based on protocol: 1965 for Gemini, 300 for Spartan */
static BOOL Makegeminaddr(struct Geminaddr *ha,UBYTE *name,BOOL is_spartan)
{  long len=strlen(name);
   UBYTE *p,*q,*query_start;
   ha->buf=ALLOCTYPE(UBYTE,len+2,0);
   if(!ha->buf) return FALSE;
   p=name;
   /* CRITICAL: Ensure name doesn't contain gemini:// or spartan:// prefix */
   /* This should never happen, but check to prevent error 53 */
   if(!strnicmp(p,"gemini://",9))
   {  /* Skip gemini:// prefix if present (shouldn't happen) */
      p+=9;
   }
   else if(!strnicmp(p,"spartan://",10))
   {  /* Skip spartan:// prefix if present (shouldn't happen) */
      p+=10;
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
   else
   {  /* Default port based on protocol */
      if(is_spartan)
      {  ha->port=300;  /* Default Spartan port */
      }
      else
      {  ha->port=1965;  /* Default Gemini port */
      }
   }
   /* Extract path - p now points to either /, ?, or \0 */

   query_start=strchr(p,'?');
   if(query_start)
   {  /* Has query string */
      ha->path=q;
      while(p<=query_start) *q++=*p++;
      *q++='\0';
      ha->query=q;
      p++;  /* skip ? */
      strcpy(q,p);
   }
   else
   {  /* No query string */
      ha->path=q;
      if(*p=='/')
      {  /* Path starts with / - include it */
         strcpy(q,p);
      }
      else if(*p)
      {  /* No leading / but has path - shouldn't happen, but add / */
         *q++='/';
         strcpy(q,p);
      }
      else
      {  /* No path - use root / */
         *q++='/';
         *q='\0';
      }
      ha->query=NULL;
   }
   /* Decode hostname (needed for DNS lookup) */
   Urldecode(ha->hostname);
   /* CRITICAL: Do NOT decode path or query - they must remain percent-encoded */
   /* Decoding breaks URLs with encoded characters like spaces, special chars, etc. */
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
   UBYTE in_pre;  /* Flag for preformatted blocks - persists during page processing */
   UBYTE *base_hostname;  /* Base hostname for resolving relative URLs */
   long base_port;  /* Base port for resolving relative URLs */
   UBYTE *base_path;  /* Base path for resolving relative URLs */
   BOOL is_spartan;  /* TRUE if this is a Spartan page (affects link URL generation) */
};

/* Forward declarations */
static BOOL Resolverelativeurl(struct Geminaddr *base,UBYTE *relative,struct Geminaddr *result,BOOL is_spartan);
static void Removedotsegments(UBYTE *path);

/* Remove dot segments from path (RFC 3986 section 5.2.4) */
static void Removedotsegments(UBYTE *path)
{  UBYTE output[1024];
   UBYTE *in,*out;
   long seglen;
   long inlen;
   UBYTE *slash_pos;
   if(!path || !*path) return;
   output[0]='\0';
   in=path;
   out=output;
   while(*in)
   {  /* A: Remove "../" and "./" at start */
      if(!strncmp((char *)in,"../",3))
      {  in+=3;
      }
      else if(!strncmp((char *)in,"./",2))
      {  in+=2;
      }
      /* C: Remove "/../" and "/.." - go up one directory */
      else if(!strncmp((char *)in,"/../",4))
      {  in+=3;
         /* Remove last segment from output */
         {  UBYTE *last_slash;
            last_slash=(UBYTE *)strrchr((char *)output,'/');
            if(last_slash)
            {  *last_slash='\0';
               out=last_slash;
            }
         }
      }
      else if(!strncmp((char *)in,"/..",3) && (in[3]=='\0' || in[3]=='?'))
      {  in+=2;
         if(*in=='?') *in='/';
         /* Remove last segment from output */
         {  UBYTE *last_slash;
            last_slash=(UBYTE *)strrchr((char *)output,'/');
            if(last_slash)
            {  *last_slash='\0';
               out=last_slash;
            }
         }
      }
      /* B: Remove "/./" and "/." */
      else if(!strncmp((char *)in,"/./",3))
      {  in+=2;
      }
      else if(!strncmp((char *)in,"/.",2) && (in[2]=='\0' || in[2]=='?'))
      {  in++;
         if(*in=='?') *in='/';
      }
      /* D: Remove "." and ".." at end */
      else if(in[0]=='.' && (in[1]=='\0' || in[1]=='?'))
      {  in++;
      }
      else if(!strncmp((char *)in,"..",2) && (in[2]=='\0' || in[2]=='?'))
      {  in+=2;
      }
      /* E: Copy normal segment */
      else
      {  inlen=strlen((char *)in);
         /* Find slash marking end of first segment */
         if(inlen>1)
         {  slash_pos=(UBYTE *)strchr((char *)(in+1),'/');
            if(slash_pos)
            {  seglen=slash_pos-in+1;
            }
            else
            {  /* Check for query string */
               slash_pos=(UBYTE *)strchr((char *)(in+1),'?');
               if(slash_pos)
               {  seglen=slash_pos-in;
               }
               else
               {  seglen=inlen;
               }
            }
         }
         else
         {  seglen=inlen;
         }
         /* Copy segment to output */
         if(out-output+seglen<sizeof(output)-1)
         {  memcpy(out,in,seglen);
            out[seglen]='\0';
            in+=seglen;
            out+=seglen;
         }
         else
         {  /* Buffer overflow - stop processing */
            break;
         }
      }
   }
   /* Copy result back to path */
   strcpy((char *)path,(char *)output);
}

/* Find end of line */
static UBYTE *Findeol(UBYTE *p,UBYTE *end)
{  while(p<end && *p!='\r' && *p!='\n') p++;
   if(p<end) return p;
   else return NULL;
}

/* Parse status line: STATUS<SPACE>META<CR><LF> */
/* Supports both Gemini (2-digit status: "20 ", "30 ", etc.) and Spartan (1-digit status: "2 ", "3 ", etc.) */
static BOOL Parsestatusline(struct GResponse *resp,UBYTE *line,long len,BOOL is_spartan)
{  UBYTE *p,*end,*meta_start;
   int status;
   long metalen=0;
   UBYTE temp_mime[256];
   if(is_spartan)
   {  /* Spartan format: single digit status code (e.g., "2 ", "3 ", "4 ", "5 ") */
      if(len<2) return FALSE;  /* Minimum: "2 " */
      p=line;
      end=line+len;
      /* Parse status code (1 digit) */
      if(!isdigit(*p)) return FALSE;
      status=*p-'0';
      p++;
   }
   else
   {  /* Gemini format: two digit status code (e.g., "20 ", "30 ", "40 ", "50 ") */
      if(len<3) return FALSE;  /* Minimum: "20 " */
      p=line;
      end=line+len;
      /* Parse status code (2 digits) */
      if(!isdigit(*p) || !isdigit(*(p+1))) return FALSE;
      status=(*p-'0')*10+(*(p+1)-'0');
      p+=2;
   }
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
      /* Normalize Spartan status codes to Gemini format for unified handling */
      /* Spartan: 2=success, 3=redirect, 4=client error, 5=server error */
      /* Gemini: 20-29=success, 30-39=redirect, 40-59=client/server error */
      if(is_spartan)
      {  /* Convert single-digit Spartan codes to two-digit Gemini format */
         if(status==2) status=20;  /* Success */
         else if(status==3) status=30;  /* Redirect */
         else if(status==4) status=40;  /* Client error */
         else if(status==5) status=50;  /* Server error */
      }
      resp->status_code=status;
      /* Store MIME type in a separate buffer, not in resp->buf */
      /* resp->buf is for content only, not status line data */
      resp->mime_type=ALLOCTYPE(UBYTE,metalen+1,0);
      if(resp->mime_type)
      {  memmove(resp->mime_type,temp_mime,metalen);
         resp->mime_type[metalen]='\0';
         resp->status_parsed=TRUE;
         return TRUE;
      }
   }
   return FALSE;
}

/* Convert text/gemini or text/spartan markup to HTML */
/* is_spartan: TRUE if this is a Spartan page (affects link URL generation) */
static void Convertgeminitohtml(struct Fetchdriver *fd,struct GResponse *resp,long read,BOOL is_spartan)
{  UBYTE *p,*end,*line_start;
   UBYTE *out;
   long outlen=0;
   /* Add new data to buffer if provided */
   if(read>0)
   {  if(!Addtobuffer(&resp->buf,fd->block,read)) return;
   }
   /* If read==0, just process existing buffer (for EOF case) */
   if(!resp->headerdone)
   {  /* Send HTML header as separate chunk */
      sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body>");
      Updatetaskattrs(
         AOURL_Data,fd->block,
         AOURL_Datalength,strlen(fd->block),
         TAG_END);
      resp->headerdone=TRUE;
   }
   /* Start output at beginning of buffer for content */
   out=fd->block;
   outlen=0;
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
         {  if(resp->in_pre)
            {  outlen+=sprintf(out+outlen,"</pre>");
               resp->in_pre=0;
            }
            else
            {  outlen+=sprintf(out+outlen,"<pre>");
               resp->in_pre=1;
            }
         }
         else if(resp->in_pre)
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
            /* Gemini headings: # H1, ## H2, ### H3 */
            if(linelen>=2 && line[0]=='#' && line[1]=='#')
            {  /* Check for H3: ### */
               if(linelen>=3 && line[2]=='#')
               {  UBYTE *text=line+3;
                  long textlen=linelen-3;
                  /* Skip leading space if present */
                  if(textlen>0 && *text==' ') { text++; textlen--; }
                  /* Trim trailing spaces */
                  while(textlen>0 && text[textlen-1]==' ') textlen--;
                  if(textlen>0)
                  {  outlen+=sprintf(out+outlen,"<h3>%.*s</h3>",textlen,text);
                  }
               }
               else
               {  /* H2: ## */
                  UBYTE *text=line+2;
                  long textlen=linelen-2;
                  /* Skip leading space if present */
                  if(textlen>0 && *text==' ') { text++; textlen--; }
                  /* Trim trailing spaces */
                  while(textlen>0 && text[textlen-1]==' ') textlen--;
                  if(textlen>0)
                  {  outlen+=sprintf(out+outlen,"<h2>%.*s</h2>",textlen,text);
                  }
               }
            }
            else if(linelen>=1 && line[0]=='#')
            {  /* H1: # */
               UBYTE *text=line+1;
               long textlen=linelen-1;
               /* Skip leading space if present */
               if(textlen>0 && *text==' ') { text++; textlen--; }
               /* Trim trailing spaces */
               while(textlen>0 && text[textlen-1]==' ') textlen--;
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<h1>%.*s</h1>",textlen,text);
               }
            }
            else if(linelen>=2 && line[0]=='=' && line[1]=='>')
            {  /* Link: => URL Description */
               UBYTE *url_start=line+2;
               UBYTE *desc_start=NULL;
               long urllen=0;
               long desclen=0;
               UBYTE *q;
               /* Skip whitespace after => */
               while(url_start<line+linelen && (*url_start==' ' || *url_start=='\t'))
               {  url_start++;
               }
               /* Find space separating URL and description */
               for(q=url_start;q<line+linelen;q++)
               {  if(*q==' ' || *q=='\t')
                  {  urllen=q-url_start;
                     /* Skip whitespace before description */
                     desc_start=q+1;
                     while(desc_start<line+linelen && (*desc_start==' ' || *desc_start=='\t'))
                     {  desc_start++;
                     }
                     desclen=(line+linelen)-desc_start;
                     break;
                  }
               }
               if(!desc_start || desclen<=0)
               {  /* No description, URL is entire rest of line */
                  urllen=(line+linelen)-url_start;
                  /* Trim trailing whitespace from URL */
                  while(urllen>0 && (url_start[urllen-1]==' ' || url_start[urllen-1]=='\t'))
                  {  urllen--;
                  }
                  desc_start=NULL;
                  desclen=0;
               }
               if(urllen>0)
               {  /* Resolve relative URLs to absolute URLs */
                  UBYTE link_url[512];
                  UBYTE *final_url;
                  long final_urllen;
                  /* Check if URL is already absolute with a protocol */
                  if(urllen>=7 && (!strnicmp(url_start,"http://",7) || !strnicmp(url_start,"https://",8) || 
                     !strnicmp(url_start,"ftp://",6) || !strnicmp(url_start,"gopher://",9) ||
                     !strnicmp(url_start,"gemini://",9) || !strnicmp(url_start,"spartan://",10)))
                  {  /* Already absolute with protocol - use as-is */
                     final_url=url_start;
                     final_urllen=urllen;
                  }
                  else if(urllen>=9 && (!strnicmp(url_start,"gemini://",9) || !strnicmp(url_start,"spartan://",10)))
                  {  /* Already absolute gemini:// or spartan:// URL */
                     final_url=url_start;
                     final_urllen=urllen;
                  }
                  else
                  {  /* Relative URL - resolve against base */
                     struct Geminaddr resolved;
                     struct Geminaddr base;
                     UBYTE rel_buf[256];
                     if(urllen>=sizeof(rel_buf)) urllen=sizeof(rel_buf)-1;
                     memmove(rel_buf,url_start,urllen);
                     rel_buf[urllen]='\0';
                     /* Build base address structure for resolution */
                     base.hostname=resp->base_hostname;
                     base.port=resp->base_port;
                     base.path=resp->base_path;
                     base.buf=NULL;
                     if(resp->base_hostname && Resolverelativeurl(&base,rel_buf,&resolved,resp->is_spartan))
                     {  /* Always use full gemini:// or spartan:// URL so AWeb recognizes the protocol */
                        /* AWeb's Hasprotocol() function requires protocol prefix to route to plugin */
                        /* CRITICAL: resolved.path does NOT include leading / (it's stripped in Makegeminaddr line 247) */
                        /* So we must always add / before the path when building the URL */
                        if(resp->is_spartan)
                        {  /* Generate spartan:// URLs for Spartan pages */
                           if(resolved.port==300)
                           {  /* Default port - omit port number */
                              if(resolved.path && *resolved.path)
                              {  final_urllen=sprintf(link_url,"spartan://%s%s",
                                    resolved.hostname,resolved.path);
                              }
                              else
                              {  final_urllen=sprintf(link_url,"spartan://%s/",
                                    resolved.hostname);
                              }
                           }
                           else
                           {  /* Non-default port - include port number */
                              if(resolved.path && *resolved.path)
                              {  final_urllen=sprintf(link_url,"spartan://%s:%ld%s",
                                    resolved.hostname,resolved.port,resolved.path);
                              }
                              else
                              {  final_urllen=sprintf(link_url,"spartan://%s:%ld/",
                                    resolved.hostname,resolved.port);
                              }
                           }
                        }
                        else
                        {  /* Generate gemini:// URLs for Gemini pages */
                           if(resolved.port==1965)
                           {  /* Default port - omit port number */
                              if(resolved.path && *resolved.path)
                              {  final_urllen=sprintf(link_url,"gemini://%s%s",
                                    resolved.hostname,resolved.path);
                              }
                              else
                              {  final_urllen=sprintf(link_url,"gemini://%s/",
                                    resolved.hostname);
                              }
                           }
                           else
                           {  /* Non-default port - include port number */
                              if(resolved.path && *resolved.path)
                              {  final_urllen=sprintf(link_url,"gemini://%s:%ld%s",
                                    resolved.hostname,resolved.port,resolved.path);
                              }
                              else
                              {  final_urllen=sprintf(link_url,"gemini://%s:%ld/",
                                    resolved.hostname,resolved.port);
                              }
                           }
                        }
                        final_url=link_url;
                        if(resolved.buf) FREE(resolved.buf);
                     }
                     else
                     {  /* Resolution failed - use original */
                        final_url=url_start;
                        final_urllen=urllen;
                     }
                  }
                  /* Format link - use proper HTML anchor tags */
                  if(desclen>0 && desc_start)
                  {  outlen+=sprintf(out+outlen,"<p><a href=\"%.*s\">%.*s</a></p>",
                        final_urllen,final_url,desclen,desc_start);
                  }
                  else
                  {  /* No description - use URL as link text */
                     outlen+=sprintf(out+outlen,"<p><a href=\"%.*s\">%.*s</a></p>",
                        final_urllen,final_url,final_urllen,final_url);
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
            {  /* Quote: >text (skip space after > if present) */
               UBYTE *text=line+1;
               long textlen=linelen-1;
               /* Skip leading space if present */
               if(textlen>0 && *text==' ') { text++; textlen--; }
               if(textlen>0)
               {  outlen+=sprintf(out+outlen,"<blockquote><p>%.*s</p></blockquote>",textlen,text);
               }
            }
            else if(linelen>0)
            {  /* Regular paragraph text */
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
   /* If read==0 (EOF) and there's remaining incomplete data, process it as a line */
   if(read==0 && resp->buf.length>0 && p<end)
   {  /* Process incomplete line at EOF */
      long linelen=end-p;
      if(linelen>0)
      {  if(resp->in_pre)
         {  /* In preformatted block - pass through */
            if(outlen+linelen+1>INPUTBLOCKSIZE-1000)
            {  Updatetaskattrs(
                  AOURL_Data,fd->block,
                  AOURL_Datalength,outlen,
                  TAG_END);
               outlen=0;
               out=fd->block;
            }
            memmove(out+outlen,p,linelen);
            outlen+=linelen;
            out[outlen++]='\n';
         }
         else
         {  /* Regular line - treat as paragraph */
            outlen+=sprintf(out+outlen,"<p>%.*s</p>",linelen,p);
         }
         /* Clear buffer since we've processed everything */
         Deleteinbuffer(&resp->buf,0,resp->buf.length);
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
   /* Pass through HTML content - only output the NEW data we just added */
   /* Don't output entire buffer each time (would cause infinite loop) */
   Updatetaskattrs(
      AOURL_Data,fd->block,
      AOURL_Datalength,read,
      TAG_END);
   /* Don't delete from buffer - we're just passing through, buffer will be cleared at end */
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
   /* Pass through content - only output the NEW data we just added */
   /* Don't output entire buffer each time (would cause infinite loop) */
   Updatetaskattrs(
      AOURL_Data,fd->block,
      AOURL_Datalength,read,
      TAG_END);
   /* Don't delete from buffer - we're just passing through, buffer will be cleared at end */
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
static BOOL Resolverelativeurl(struct Geminaddr *base,UBYTE *relative,struct Geminaddr *result,BOOL is_spartan)
{  UBYTE *p;
   UBYTE *base_path;
   long base_path_len;
   long combined_len;
   UBYTE *combined_path;
   UBYTE *query_start;
   /* Check if absolute URL (starts with gemini:// or spartan://) */
   if(!strnicmp(relative,"gemini://",9))
   {  /* Skip gemini:// prefix */
      p=relative+9;
      return Makegeminaddr(result,p,FALSE);  /* FALSE = not spartan */
   }
   else if(!strnicmp(relative,"spartan://",10))
   {  /* Skip spartan:// prefix */
      p=relative+10;
      return Makegeminaddr(result,p,TRUE);  /* TRUE = spartan */
   }
   /* CRITICAL: base->hostname should be just the hostname (no protocol, no port) */
   /* Validate base->hostname doesn't contain ':' or '/' (would indicate it already has port/path) */
   if(!base->hostname || !*base->hostname || strchr(base->hostname,':') || strchr(base->hostname,'/'))
   {  /* Invalid base hostname - cannot resolve relative URL */
      return FALSE;
   }
   /* Allocate buffer for hostname, path, and query */
   combined_len=strlen(base->hostname)+strlen(relative)+256;  /* Extra space for path and query */
   result->buf=ALLOCTYPE(UBYTE,combined_len,0);
   if(!result->buf) return FALSE;
   /* Copy hostname directly from base (no parsing needed) */
   result->hostname=result->buf;
   strcpy((char *)result->hostname,(char *)base->hostname);
   /* Use base port */
   result->port=base->port;
   /* Extract query string from relative URL before processing path (RFC 3986) */
   query_start=strchr(relative,'?');
   if(relative[0]=='/')
   {  /* Absolute path - relative to host root */
      /* Path is just the relative path (without query) */
      result->path=result->buf+strlen((char *)result->hostname)+1;
      if(query_start)
      {  /* Copy path part only (before ?) */
         long path_len=query_start-relative;
         memcpy(result->path,relative,path_len);
         result->path[path_len]='\0';
      }
      else
      {  strcpy((char *)result->path,(char *)relative);
      }
      /* RFC 3986: remove dot segments from absolute path */
      Removedotsegments(result->path);
   }
   else
   {  /* Relative path - combine with base path directory */
      base_path_len=0;
      if(base->path && *base->path)
      {  UBYTE *last_slash;
         last_slash=strrchr(base->path,'/');
         if(last_slash)
         {  base_path_len=last_slash-base->path+1;  /* Include the / */
         }
         else
         {  /* No / found - use root */
            base_path_len=1;
         }
      }
      else
      {  /* No base path - use root */
         base_path_len=1;
      }
      /* Build combined path: base directory + relative path (without query) */
      result->path=result->buf+strlen((char *)result->hostname)+1;
      if(base_path_len>0 && base->path)
      {  /* Copy base path directory (up to last /) + relative path (without query) */
         if(query_start)
         {  long rel_path_len=query_start-relative;
            sprintf((char *)result->path,"%.*s%.*s",(int)base_path_len,base->path,(int)rel_path_len,relative);
         }
         else
         {  sprintf((char *)result->path,"%.*s%s",(int)base_path_len,base->path,relative);
         }
      }
      else
      {  /* No base path - relative path becomes the path (without query) */
         if(query_start)
         {  long rel_path_len=query_start-relative;
            memcpy(result->path,relative,rel_path_len);
            result->path[rel_path_len]='\0';
         }
         else
         {  strcpy((char *)result->path,(char *)relative);
         }
      }
      /* RFC 3986: remove dot segments from merged path */
      Removedotsegments(result->path);
   }
   /* Store query string if present */
   if(query_start)
   {  result->query=result->buf+strlen((char *)result->hostname)+1+strlen((char *)result->path)+1;
      strcpy((char *)result->query,query_start+1);
   }
   else
   {  /* No query string */
      result->query=NULL;
   }
   /* Validate result */
   if(!result->hostname || !*result->hostname || !result->path)
   {  FREE(result->buf);
      result->buf=NULL;
      return FALSE;
   }
   return TRUE;
}

/* Main fetch driver task */
__saveds __asm void Fetchdrivertask(register __a0 struct Fetchdriver *fd)
{  struct Library *SocketBase;
   struct Geminaddr ha={0};
   struct hostent *hent;
   struct GResponse resp={0};
   BOOL error=FALSE;
   BOOL is_spartan;  /* C89: Declare at start of block */
   long sock=-1;
   long result,length;
   int redirect_count=0;
   UBYTE *request_path;
   long request_len;
   long status_line_len;
   UBYTE *redirect_url=NULL;
   
   /* Initialize preformatted flag - must be after all declarations (C89 requirement) */
   resp.in_pre=0;
   
   /* Detect protocol: Spartan if FDVF_SSL is NOT set, Gemini if it is set */
   /* fetch.c sets FDVF_SSL for Gemini but not for Spartan */
   is_spartan=(fd->flags&FDVF_SSL)?FALSE:TRUE;
   resp.is_spartan=is_spartan;  /* Store in response structure for use in link generation */
   
   AwebTcpBase=Opentcp(&SocketBase,fd,!fd->validate);
   if(SocketBase && AwebTcpBase)
   {  if(Makegeminaddr(&ha,fd->name,is_spartan))
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
                        if(is_spartan)
                        {  Tcpmessage(fd,TCPMSG_CONNECT,"Spartan",hent->h_name);
                        }
                        else
                        {  Tcpmessage(fd,TCPMSG_CONNECT,"Gemini",hent->h_name);
                        }
                        if(!a_connect(sock,hent,ha.port,SocketBase))
                        {  if(Checktaskbreak())
                           {  error=TRUE;
                              a_close(sock,SocketBase);
                              sock=-1;
                              break;
                           }
                           /* Build request based on protocol */
                           request_path=fd->block;
                           if(is_spartan)
                           {  /* Spartan request format: host path length\r\n */
                              /* If port is not 300, use: host:port path length\r\n */
                              /* length is 0 for normal requests (no input data) */
                              /* ha.path includes leading / */
                              /* For Spartan, query parameters are NOT included in path */
                              /* They are sent separately in the spartanData structure */
                              UBYTE *path_str;
                              long input_length=0;  /* No input data for normal requests */
                              if(!ha.path || !*ha.path)
                              {  path_str=(UBYTE *)"/";
                              }
                              else
                              {  path_str=ha.path;  /* Already includes leading / */
                              }
                              if(ha.port==300)
                              {  /* Default port - omit port number */
                                 sprintf(request_path,"%s %s %ld\r\n",
                                    ha.hostname,path_str,input_length);
                              }
                              else
                              {  /* Non-default port - include port number */
                                 sprintf(request_path,"%s:%ld %s %ld\r\n",
                                    ha.hostname,ha.port,path_str,input_length);
                              }
                           }
                           else
                           {  /* Gemini request format: gemini://host:port/path?query<CR><LF> */
                              /* According to Gemini protocol spec, request must be full URL */
                              if(ha.port==1965)
                              {  /* Default port - omit port number */
                                 if(ha.path && *ha.path)
                                 {  if(ha.query && *ha.query)
                                    {  sprintf(request_path,"gemini://%s%s?%s\r\n",
                                          ha.hostname,ha.path,ha.query);
                                    }
                                    else
                                    {  sprintf(request_path,"gemini://%s%s\r\n",
                                          ha.hostname,ha.path);
                                    }
                                 }
                                 else
                                 {  /* No path - send root */
                                    if(ha.query && *ha.query)
                                    {  sprintf(request_path,"gemini://%s/?%s\r\n",
                                          ha.hostname,ha.query);
                                    }
                                    else
                                    {  sprintf(request_path,"gemini://%s/\r\n",
                                          ha.hostname);
                                    }
                                 }
                              }
                              else
                              {  /* Non-default port - include port number */
                                 if(ha.path && *ha.path)
                                 {  if(ha.query && *ha.query)
                                    {  sprintf(request_path,"gemini://%s:%ld%s?%s\r\n",
                                          ha.hostname,ha.port,ha.path,ha.query);
                                    }
                                    else
                                    {  sprintf(request_path,"gemini://%s:%ld%s\r\n",
                                          ha.hostname,ha.port,ha.path);
                                    }
                                 }
                                 else
                                 {  /* No path - send root */
                                    if(ha.query && *ha.query)
                                    {  sprintf(request_path,"gemini://%s:%ld/?%s\r\n",
                                          ha.hostname,ha.port,ha.query);
                                    }
                                    else
                                    {  sprintf(request_path,"gemini://%s:%ld/\r\n",
                                          ha.hostname,ha.port);
                                    }
                                 }
                              }
                           }
                           request_len=strlen(request_path);
                           /* Send request - validate socket is still open */
                           if(sock>=0)
                           {  result=(a_send(sock,request_path,request_len,0,SocketBase)==request_len);
                           }
                           else
                           {  /* Socket was closed - cannot send request */
                              error=TRUE;
                              result=FALSE;
                           }
                              if(result)
                              {  Updatetaskattrs(AOURL_Netstatus,NWS_WAIT,TAG_END);
                                 if(is_spartan)
                                 {  Tcpmessage(fd,TCPMSG_WAITING,"Spartan");
                                 }
                                 else
                                 {  Tcpmessage(fd,TCPMSG_WAITING,"Gemini");
                                 }
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
                                          if(Parsestatusline(&resp,resp.buf.buffer,eol-resp.buf.buffer,is_spartan))
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
                                 {  /* Store base URL for resolving relative links */
                                    resp.base_hostname=ha.hostname;
                                    resp.base_port=ha.port;
                                    resp.base_path=ha.path;
                                    /* Set content type based on MIME type from server */
                                    /* Both Gemini and Spartan use text/gemini or text/ MIME types */
                                    if(resp.mime_type && (!strncmp(resp.mime_type,"text/gemini",11) || 
                                       (resp.is_spartan && !strncmp(resp.mime_type,"text/",5))))
                                    {  /* Convert to HTML */
                                       Updatetaskattrs(AOURL_Contenttype,"text/html",TAG_END);
                                    }
                                    else if(resp.mime_type)
                                    {  /* Use server's MIME type */
                                       Updatetaskattrs(AOURL_Contenttype,resp.mime_type,TAG_END);
                                    }
                                    /* Handle based on status code */
                                    if(resp.status_code>=20 && resp.status_code<30)
                                    {  /* Success - process body based on MIME type */
                                       /* Check if there's any body data already in buffer (after status line) */
                                       /* This can happen if status line and body came in same recv() packet */
                                       if(resp.buf.length>0)
                                       {  /* Copy remaining data from buffer to fd->block for processing */
                                          /* Handler functions expect data in fd->block and will add it to buffer */
                                          /* So we need to extract it from buffer first, then let handler add it back */
                                          long remaining=resp.buf.length;
                                          if(remaining>INPUTBLOCKSIZE) remaining=INPUTBLOCKSIZE;
                                          memmove(fd->block,resp.buf.buffer,remaining);
                                          /* Remove from buffer before calling handler (handler will add it back) */
                                          Deleteinbuffer(&resp.buf,0,remaining);
                                          /* Process the remaining data - handler will add it to buffer and process it */
                                          /* Both Gemini and Spartan use text/gemini or text/ MIME types */
                                          if(resp.mime_type && (!strncmp(resp.mime_type,"text/gemini",11) || 
                                             (resp.is_spartan && !strncmp(resp.mime_type,"text/",5))))
                                          {  Convertgeminitohtml(fd,&resp,remaining,resp.is_spartan);
                                          }
                                          else if(resp.mime_type && !strncmp(resp.mime_type,"text/html",9))
                                          {  Handlehtml(fd,&resp,remaining);
                                          }
                                          else if(resp.mime_type && !strncmp(resp.mime_type,"text/plain",10))
                                          {  Handleplaintext(fd,&resp,remaining);
                                          }
                                          else
                                          {  Handleother(fd,&resp,remaining);
                                          }
                                       }
                                       /* Both Gemini and Spartan use text/gemini or text/ MIME types */
                                       if(resp.mime_type && (!strncmp(resp.mime_type,"text/gemini",11) || 
                                          (resp.is_spartan && !strncmp(resp.mime_type,"text/",5))))
                                       {  /* text/gemini or text/anything - convert to HTML */
                                          BOOL eof_received=FALSE;
                                          for(;;)
                                          {  length=a_recv(sock,fd->block,INPUTBLOCKSIZE,0,SocketBase);
                                             if(length<0 || Checktaskbreak())
                                             {  error=TRUE;
                                                break;
                                             }
                                             if(length==0)
                                             {  /* EOF received - process any remaining data in buffer */
                                                eof_received=TRUE;
                                                /* Process any remaining incomplete line in buffer */
                                                if(resp.buf.length>0)
                                                {  /* Force process remaining buffer data */
                                                   Convertgeminitohtml(fd,&resp,0,resp.is_spartan);  /* 0 means process buffer only */
                                                }
                                                break;
                                             }
                                             /* Process this chunk of data */
                                             Convertgeminitohtml(fd,&resp,length,resp.is_spartan);
                                          }
                                          /* Close HTML */
                                          if(!error)
                                          {  sprintf(fd->block,"</body></html>");
                                             Updatetaskattrs(
                                                AOURL_Data,fd->block,
                                                AOURL_Datalength,strlen(fd->block),
                                                TAG_END);
                                          }
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
                                       /* Successfully processed response - exit redirect loop */
                                       /* Close socket immediately to prevent reuse after EOF */
                                       if(sock>=0)
                                       {  a_close(sock,SocketBase);
                                          sock=-1;
                                       }
                                       break;
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
                                             if(Resolverelativeurl(&ha,redirect_url,&ha,is_spartan))
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
                                       /* META field contains the error message */
                                       UBYTE *error_msg;
                                       if(resp.mime_type && *resp.mime_type)
                                       {  error_msg=resp.mime_type;
                                       }
                                       else
                                       {  error_msg=(UBYTE *)"Unknown error";
                                       }
                                       /* Set content type for error page */
                                       Updatetaskattrs(AOURL_Contenttype,"text/html",TAG_END);
                                       sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body><h1>Gemini Error %d</h1><p>%s</p></body></html>",
                                          resp.status_code,error_msg);
                                       Updatetaskattrs(
                                          AOURL_Data,fd->block,
                                          AOURL_Datalength,strlen(fd->block),
                                          TAG_END);
                                       /* Error responses may have a body, but we've displayed the error - break loop */
                                       break;
                                    }
                                    else if(resp.status_code>=60 && resp.status_code<70)
                                    {  /* Client certificate required - not implemented */
                                       /* Set content type for error page */
                                       Updatetaskattrs(AOURL_Contenttype,"text/html",TAG_END);
                                       sprintf(fd->block,"<html><head><meta charset=\"utf-8\"></head><body><h1>Client Certificate Required</h1><p>This Gemini server requires a client certificate, which is not yet supported.</p></body></html>");
                                       Updatetaskattrs(
                                          AOURL_Data,fd->block,
                                          AOURL_Datalength,strlen(fd->block),
                                          TAG_END);
                                       /* Break loop - can't proceed without client certificate */
                                       break;
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
            if(resp.mime_type) FREE(resp.mime_type);
         }
         else
         {  /* Makegeminaddr failed */
            error=TRUE;
         }
      /* Cleanup sequence - a_cleanup() automatically calls ClearTaskSSLContext() */
      /* This matches HTTP pattern: a_cleanup() -> ClearTaskSSLContext() -> CloseLibrary() */
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

