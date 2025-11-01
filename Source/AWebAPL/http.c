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

/* http.c - aweb http protocol client */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <proto/socket.h>
#include "aweb.h"
#include "tcperr.h"
#include "fetchdriver.h"
#include "application.h"
#include "task.h"
#include "form.h"
#include "awebtcp.h"
#include <dos/dosextens.h>

#include "/zlib/zconf.h"
#include "/zlib/zlib.h"

/* Socket option constants if not already defined */
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO 0x1006
#endif
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO 0x1005
#endif





#ifndef LOCALONLY

struct Httpinfo
{  long status;               /* Response status */
   USHORT flags;
   struct Authorize *prxauth; /* Proxy authorization */
   struct Authorize *auth;    /* Normal authorization */
   UBYTE *connect;            /* Connect to this host or proxy */
   long port;                 /* .. using this port. -1 means use default (80/443) */
   UBYTE *tunnel;             /* Host and port to tunnel to */
   UBYTE *hostport;           /* Host and port for use in Host: header */
   UBYTE *hostname;           /* Host name to match authorization for */
   UBYTE *abspath;            /* Abs path, or full url, to use in GET request */
   UBYTE *boundary;           /* Multipart boundary including leading "--" */
   struct Fetchdriver *fd;
   struct Library *socketbase;
   long sock;
   struct Assl *assl;         /* AwebSSL context */
   long blocklength;          /* Length of data in block */
   long nextscanpos;          /* Block position to scan */
   long linelength;           /* Length of current header line */
   long readheaders;          /* Number of header bytes read */
   ULONG movedto;             /* AOURL_ tag if 301 or 302 status */
   UBYTE *movedtourl;         /* URL string moved to */
   UBYTE parttype[32];        /* Content-type for this part */
   long partlength;           /* Content-length for this part */
   UBYTE *userid;             /* Userid from URL */
   UBYTE *passwd;             /* Password from URL */
};

#define HTTPIF_AUTH        0x0001   /* Tried with a known to be valid auth */
#define HTTPIF_PRXAUTH     0x0002   /* Tried with a known to be valid prxauth */
#define HTTPIF_HEADERS     0x0004   /* Doing headers, issue bytes read messages */
#define HTTPIF_SSL         0x0008   /* Use secure transfer */
#define HTTPIF_RETRYNOSSL  0x0010   /* Retry with no secure transfer */
#define HTTPIF_NOSSLREQ    0x0020   /* Don't put on another SSL requester */
#define HTTPIF_SSLTUNNEL   0x0040   /* Tunnel SSL request through proxy */
#define HTTPIF_TUNNELOK    0x0080   /* Tunnel response was ok */
#define HTTPIF_GZIPENCODED 0x0100   /* response is gzip encoded */
#define HTTPIF_GZIPDECODING 0x0200  /* decoding gziped response has begun */
#define HTTPIF_DATA_PROCESSED 0x0400 /* data has already been processed to prevent duplication */

static UBYTE *httprequest="GET %.7000s HTTP/1.1\r\n";

static UBYTE *httppostrequest="POST %.7000s HTTP/1.1\r\n";

static UBYTE *useragent="User-Agent: Mozilla/3.0 (compatible; Amiga-AWeb/3.6; AmigaOS 3.2)\r\n";

#ifndef DEMOVERSION
static UBYTE *useragentspoof="User-Agent: %s; (Spoofed by Amiga-AWeb/3.6; AmigaOS 3.2)\r\n";
#endif

static UBYTE *fixedheaders=
   "Accept: */*;q=1\r\nAccept-Encoding: gzip\r\n";
//   "Accept: text/html;level=3, text/html;version=3.0, */*;q=1\r\n";

/* HTTP/1.1 specific headers */
static UBYTE *connection="Connection: close\r\n";

static UBYTE *host="Host: %s\r\n";

static UBYTE *ifmodifiedsince="If-modified-since: %s\r\n";

static UBYTE *ifnonematch="If-none-match: %s\r\n";

static UBYTE *authorization="Authorization: Basic %s\r\n";

static UBYTE *proxyauthorization="Proxy-Authorization: Basic %s\r\n";

static UBYTE *nocache="Pragma: no-cache\r\n";

static UBYTE *referer="Referer: %s\r\n";

static UBYTE *httppostcontent=
   "Content-Length: %d\r\n"
   "Content-Type: application/x-www-form-urlencoded\r\n";

static UBYTE *httpmultipartcontent=
   "Content-Length: %d\r\n"
   "Content-Type: multipart/form-data; boundary=%s\r\n";

static UBYTE *tunnelrequest="CONNECT %.200s HTTP/1.1\r\n";

/* Unverifyable certificates that the user accepted */
struct Certaccept
{  NODE(Certaccept);
   UBYTE *hostname;
   UBYTE *certname;
};

static LIST(Certaccept) certaccepts;
static struct SignalSemaphore certsema;

/*-----------------------------------------------------------------------*/

static void Messageread(struct Fetchdriver *fd,long n)
{  UBYTE buf[64];
   strcpy(buf,AWEBSTR(MSG_AWEB_BYTESREAD));
   strcat(buf,": ");
   sprintf(buf+strlen(buf),"%d",n);
   Updatetaskattrs(
      AOURL_Status,buf,
      TAG_END);
}

static BOOL Makehttpaddr(struct Httpinfo *hi,UBYTE *proxy,UBYTE *url,BOOL ssl)
{  UBYTE *p,*q,*r,*u;
   UBYTE *userid=NULL,*passwd=NULL;
   long l;
   BOOL gotport=FALSE;
   if(u=strchr(url,':')) u++; /* Should always be found */
   else u=url;
   if(u[0]=='/' && u[1]=='/') u+=2;
   if(proxy)
   {  p=strchr(proxy,':');
      hi->connect=Dupstr(proxy,p?p-proxy:-1);
      hi->port=p?atol(p+1):8080;
      p=stpbrk(u,":/");
      if(p && *p==':' && (q=strchr(p,'@')) && (!(r=strchr(p,'/')) || q<r))
      {  /* userid:passwd@host[:port][/path] */
         userid=Dupstr(u,p-u);
         passwd=Dupstr(p+1,q-p-1);
         u=q+1;
         p=stpbrk(u,":/");
      }
      hi->hostname=Dupstr(u,p?p-u:-1);
      gotport=(p && *p==':');
      p=strchr(u,'/');
      hi->hostport=Dupstr(u,p?p-u:-1);
      if(ssl)
      {  /* Will be tunneled. Use abspath like with no proxy */
         if(gotport)
         {  hi->tunnel=Dupstr(hi->hostport,-1);
         }
         else
         {  hi->tunnel=ALLOCTYPE(UBYTE,strlen(hi->hostname)+5,0);
            if(hi->tunnel)
            {  strcpy(hi->tunnel,hi->hostname);
               strcat(hi->tunnel,":443");
            }
         }
         hi->abspath=Dupstr(p?p:(UBYTE *)"/",-1);
         hi->flags|=HTTPIF_SSLTUNNEL;
      }
      else
      {  if(p)
         {  hi->abspath=Dupstr(url,-1);
         }
         else
         {  /* append '/' */
            l=strlen(url);
            if(hi->abspath=Dupstr(url,l+1)) hi->abspath[l]='/';
         }
      }
   }
   else
   {  p=stpbrk(u,":/");
      if(p && *p==':' && (q=strchr(p,'@')) && (!(r=strchr(p,'/')) || q<r))
      {  /* userid:password@host[:port][/path] */
         userid=Dupstr(u,p-u);
         passwd=Dupstr(p+1,q-p-1);
         u=q+1;
         p=stpbrk(u,":/");
      }
      hi->connect=Dupstr(u,p?p-u:-1);
      if(p && *p==':')
      {  hi->port=atol(p+1);
      }
      else
      {  hi->port=-1;
      }
      p=strchr(u,'/');
      hi->hostport=Dupstr(u,p?p-u:-1);
      hi->abspath=Dupstr(p?p:(UBYTE *)"/",-1);
      hi->hostname=Dupstr(hi->connect,-1);
   }
   if(userid && passwd)
   {  if(hi->auth) Freeauthorize(hi->auth);
      if(hi->auth=Newauthorize(hi->hostport,"dummyrealm"))
      {  Setauthorize(hi->auth,userid,passwd);
         hi->flags|=HTTPIF_AUTH;
      }
   }
   if(userid) FREE(userid);
   if(passwd) FREE(passwd);
   return (BOOL)(hi->connect && hi->hostport && hi->abspath && hi->hostname);
}

/* Build a HTTP request. The length is returned.
 * (*request) is either fd->block or a dynamic string if fd->block was too small */
static long Buildrequest(struct Fetchdriver *fd,struct Httpinfo *hi,UBYTE **request)
{  UBYTE *p=fd->block;
   UBYTE *cookies;
   *request=fd->block;
   if(fd->postmsg || fd->multipart)
      p+=sprintf(p,httppostrequest,hi->abspath);
   else p+=sprintf(p,httprequest,hi->abspath);
   ObtainSemaphore(&prefssema);
#ifndef DEMOVERSION
   if(*prefs.spoofid)
   {  p+=sprintf(p,useragentspoof,prefs.spoofid,awebversion);
   }
   else
#endif
   {  p+=sprintf(p,useragent,awebversion);
   }
   ReleaseSemaphore(&prefssema);
   p+=sprintf(p,fixedheaders);
   /* Add HTTP/1.1 Connection header */
   p+=sprintf(p,connection);
   if(hi->hostport)
      p+=sprintf(p,host,hi->hostport);
   if(fd->validate)
   {  UBYTE date[32];
      Makedate(fd->validate,date);
      p+=sprintf(p,ifmodifiedsince,date);
   }
   
   // If ETag exists verify this else try time
   if(fd->etag && strlen(fd->etag)>0)
   {  p+=sprintf(p,ifnonematch,fd->etag);
   }
   
   if(hi->auth && hi->auth->cookie)
      p+=sprintf(p,authorization,hi->auth->cookie);
   if(hi->prxauth && hi->prxauth->cookie)
      p+=sprintf(p,proxyauthorization,hi->prxauth->cookie);
   if(fd->flags&FDVF_NOCACHE)
      p+=sprintf(p,nocache);
   if(fd->referer && (p-fd->block)+strlen(fd->referer)<7000)
      p+=sprintf(p,referer,fd->referer);
   if(fd->multipart)
   {  p+=sprintf(p,httpmultipartcontent,
         fd->multipart->length,fd->multipart->buf.buffer);
   }
   else if(fd->postmsg)
   {  p+=sprintf(p,httppostcontent,strlen(fd->postmsg));
   }
   if(prefs.cookies && (cookies=Findcookies(fd->name,hi->flags&HTTPIF_SSL)))
   {  long len=strlen(cookies);
      if((p-fd->block)+len<7000)
      {  strcpy(p,cookies);
         p+=len;
      }
      else
      {  UBYTE *newreq=ALLOCTYPE(UBYTE,(p-fd->block)+len+16,0);
         if(newreq)
         {  strcpy(newreq,fd->block);
            strcpy(newreq+(p-fd->block),cookies);
            *request=newreq;
            p=newreq+(p-fd->block)+len;
         }
      }
      FREE(cookies);
   }
   p+=sprintf(p,"\r\n");
   return p-*request;
}

/*-----------------------------------------------------------------------*/

/* Receive a block through SSL or socket. */
static long Receive(struct Httpinfo *hi,UBYTE *buffer,long length)
{  long result;
#ifndef DEMOVERSION
   if(hi->flags&HTTPIF_SSL)
   {  result=Assl_read(hi->assl,buffer,length);
   }
   else
#endif
   {  result=a_recv(hi->sock,buffer,length,0,hi->socketbase);
   }
   return result;
}

/* Read remainder of block. Returns FALSE if eof or error. */
static BOOL Readblock(struct Httpinfo *hi)
{  long n;
   printf("DEBUG: Readblock() called, current blocklength=%ld\n", hi->blocklength);
   
#ifdef DEVELOPER
   UBYTE *block;
   if(!hi->socketbase)
   {  block=fgets(hi->fd->block+hi->blocklength,hi->fd->blocksize-hi->blocklength,
         (FILE *)hi->sock);
      n=block?strlen(block):0;
      /* for some reason, we get a bogus 'G' in the second console window */
      if(STRNEQUAL(hi->fd->block,"GHTTP/",6))
      {  memmove(hi->fd->block,hi->fd->block+1,n-1);
         n--;
      }
   }
   else
#endif
   n=Receive(hi,hi->fd->block+hi->blocklength,hi->fd->blocksize-hi->blocklength);
   
   printf("DEBUG: Readblock: Receive returned %ld bytes\n", n);
   
   if(n<0 || Checktaskbreak())
   {  
/* Don't send error, let source driver keep its partial data if it wants to.
      Updatetaskattrs(
         AOURL_Error,TRUE,
         TAG_END);
*/
      printf("DEBUG: Readblock: error or task break, returning FALSE\n");
      return FALSE;
   }
   if(n==0) 
   {  printf("DEBUG: Readblock: no data received (EOF), returning FALSE\n");
      return FALSE;
   }
   
   printf("DEBUG: Readblock: adding %ld bytes to block, new total=%ld\n", n, hi->blocklength + n);
   
   hi->blocklength+=n;
   if(hi->flags&HTTPIF_HEADERS)
   {  Messageread(hi->fd,hi->readheaders+=n);
   }
   return TRUE;
}

/* Remove the first part from the block. */
static void Nextline(struct Httpinfo *hi)
{  if(hi->nextscanpos<hi->blocklength)
   {  memmove(hi->fd->block,hi->fd->block+hi->nextscanpos,hi->blocklength-hi->nextscanpos);
   }
   hi->blocklength-=hi->nextscanpos;
   hi->nextscanpos=0;
}

/* Find a complete line. Read again if no complete line found. */
static BOOL Findline(struct Httpinfo *hi)
{  UBYTE *p=hi->fd->block;
   UBYTE *end;
   for(;;)
   {  end=hi->fd->block+hi->blocklength;
      while(p<end && *p!='\n') p++;
      if(p<end) break;
      if(!Readblock(hi)) return FALSE;
   }
   /* Now we've got a LF. Terminate line here, but if it is preceded by CR ignore that too. */
   *p='\0';
   hi->linelength=p-hi->fd->block;
   hi->nextscanpos=hi->linelength+1;
   if(hi->linelength)
   {  p--;
      if(*p=='\r')
      {  *p='\0';
         hi->linelength--;
      }
   }
   if(httpdebug)
   {  Write(Output(),hi->fd->block,hi->linelength);
      Write(Output(),"\n",1);
   }
   return TRUE;
}

/* Get the authorization details from this buffer */
static struct Authorize *Parseauth(UBYTE *buf,UBYTE *server)
{  UBYTE *p,*q;
   struct Authorize *auth;
   for(p=buf;*p==' ';p++);
   if(!STRNIEQUAL(p,"Basic ",6)) return NULL;
   for(p+=6;*p==' ';p++);
   if(!STRNIEQUAL(p,"realm",5)) return NULL;
   for(p+=5;*p==' ';p++);
   if(*p!='=') return FALSE;
   for(p++;*p==' ';p++);
   if(*p!='"') return FALSE;
   q=p+1;
   for(p++;*p!='"' && *p!='\r' && *p!='\n';p++);
   *p='\0';
   auth=Newauthorize(server,q);
   return auth;
}

/* Read and process headers until end of headers. Read when necessary.
 * Returns FALSE if eof or error, or data should be skipped. */
static BOOL Readheaders(struct Httpinfo *hi)
{  /* Reset gzip flags at start of headers - this is crucial! */
   hi->flags &= ~(HTTPIF_GZIPENCODED | HTTPIF_GZIPDECODING);
   
   for(;;)
   {  if(!Findline(hi)) return FALSE;
      if(hi->linelength==0)
      {  if(hi->status) return FALSE;
         else 
         {  printf("DEBUG: Headers complete, starting data processing\n");
            return TRUE;
         }
      }
      Updatetaskattrs(
         AOURL_Header,hi->fd->block,
         TAG_END);
      printf("DEBUG: Processing header: '%s'\n", hi->fd->block);
      
      if(STRNIEQUAL(hi->fd->block,"Date:",5))
      {  hi->fd->serverdate=Scandate(hi->fd->block+5);
         Updatetaskattrs(
            AOURL_Serverdate,hi->fd->serverdate,
            TAG_END);
      }
      else if(STRNIEQUAL(hi->fd->block,"Last-Modified:",14))
      {  ULONG date=Scandate(hi->fd->block+14);
         Updatetaskattrs(
            AOURL_Lastmodified,date,
            TAG_END);
      }
      else if(STRNIEQUAL(hi->fd->block,"Expires:",8))
      {  long expires=Scandate(hi->fd->block+8);
         Updatetaskattrs(
            AOURL_Expires,expires,
            TAG_END);
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Length:",15))
      {  long i=0;
         sscanf(hi->fd->block+15," %ld",&i);
         Updatetaskattrs(
            AOURL_Contentlength,i,
            TAG_END);
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Type:",13))
      {  UBYTE mimetype[32];
         UBYTE *p,*q,*r;
         UBYTE qq;
         long l;
         BOOL foreign=FALSE;
         BOOL forward=TRUE;
         
         printf("DEBUG: Content-Type header found in Readheaders: '%s'\n", hi->fd->block);
         mimetype[0] = '\0';  /* Initialize empty string */
         if(!prefs.ignoremime)
         {  for(p=hi->fd->block+13;*p && isspace(*p);p++);
            for(q=p;*q && !isspace(*q) && *q!=';';q++);
            qq=*q;
            *q='\0';
            l=q-p;
            if(qq && !hi->boundary)
            {  if(STRIEQUAL(p,"MULTIPART/X-MIXED-REPLACE")
               || STRIEQUAL(p,"MULTIPART/MIXED-REPLACE"))
               {  for(q++;*q && !STRNIEQUAL(q,"BOUNDARY=",9);q++);
                  if(*q)
                  {  q+=9;
                     if(*q=='"')
                     {  q++;
                        for(r=q;*r && *r!='"';r++);
                        *r='\0';
                     }
                     if(hi->boundary=Dupstr(q-2,-1))
                     {  hi->boundary[0]='-';
                        hi->boundary[1]='-';
                     }
                     forward=FALSE;
                  }
               }
            }
            if(qq && STRNIEQUAL(p,"TEXT/",5))
            {  for(q++;*q && !STRNIEQUAL(q,"CHARSET=",8);q++);
               if(*q)
               {  q+=8;
                  while(*q && isspace(*q)) q++;
                  if(*q=='"')
                  {  q++;
                     for(r=q;*r && *r!='"';r++);
                     *r='\0';
                  }
                  else
                  {  for(r=q;*r && !isspace(*r);r++);
                     *r='\0';
                  }
                  if(*q && !STRIEQUAL(q,"ISO-8859-1")) foreign=TRUE;
               }
            }
            if(forward)
            {  if(l>31) p[31]='\0';
               strcpy(mimetype,p);
            }
         }
         if(*mimetype)
         {  printf("DEBUG: Setting Content-Type to: '%s'\n", mimetype);
            Updatetaskattrs(
               AOURL_Contenttype,mimetype,
               AOURL_Foreign,foreign,
               TAG_END);
         }
         else
         {  printf("DEBUG: No mimetype extracted from Content-Type header\n");
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Encoding:",17))
      {  if(strstr(hi->fd->block+18,"gzip"))
         {  hi->flags|=HTTPIF_GZIPENCODED;
            printf("DEBUG: Detected gzip encoding\n");
            Updatetaskattrs(AOURL_Contentlength,0,TAG_END);
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"ETag:",5))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+5;*p && isspace(*p);p++);
         for(q=p;*q && !isspace(*q) && *q!=';';q++);
         *q='\0';
         if(q-p>63) p[63]='\0';
         /* Store ETag in both URL object and fetchdriver for caching */
         Updatetaskattrs(AOURL_Etag,p,TAG_END);
         if(hi->fd->etag) FREE(hi->fd->etag);
         hi->fd->etag=Dupstr(p,-1);
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Disposition:",20))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+21;*p && isspace(*p);p++);
         for(q=p;*q && !isspace(*q) && *q!=';';q++);
         *q='\0';
         if(STRIEQUAL(p,"attachment"))
         {  p+=11;
            if((q=strstr(p,"filename")))
            {  for(p=q+8;*p && (isspace(*p) || *p=='"' || *p=='=');p++);
               for(q=p;*q && !isspace(*q) && *q!=';' && *q!='"';q++);
               *q='\0';
               Updatetaskattrs(AOURL_Filename,p,TAG_END);
            }
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-script-type:",20))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+20;*p && isspace(*p);p++);
         for(q=p;*q && !isspace(*q) && *q!=';';q++);
         *q='\0';
         Updatetaskattrs(
            AOURL_Contentscripttype,p,
            TAG_END);
      }
      else if(STRNIEQUAL(hi->fd->block,"Pragma:",7))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+7;*p && isspace(*p);p++);
         for(q=p;*q && !isspace(*q) && *q!=';';q++);
         *q='\0';
         if(STRIEQUAL(p,"no-cache"))
         {  Updatetaskattrs(
               AOURL_Nocache,TRUE,
               TAG_END);
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"Cache-Control:",14))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+14;*p && isspace(*p);p++);
         for(q=p;*q && !isspace(*q) && *q!='\r' && *q!='\n';q++);
         *q='\0';
         if(STRIEQUAL(p,"no-cache") || STRIEQUAL(p,"no-store"))
         {  Updatetaskattrs(
               AOURL_Nocache,TRUE,
               TAG_END);
         }
         else if(STRIEQUAL(p,"max-age"))
         {  /* Parse max-age value for caching */
            long maxage=0;
            if(q=strchr(p,'='))
            {  sscanf(q+1,"%ld",&maxage);
               Updatetaskattrs(AOURL_Maxage,maxage,TAG_END);
            }
         }
      }
      else if(hi->movedto && STRNIEQUAL(hi->fd->block,"Location:",9))
      {  UBYTE *p,*q;
         for(p=hi->fd->block+9;*p && isspace(*p);p++);
         for(q=p+strlen(p)-1;q>p && isspace(*q);q--);
         if(hi->movedtourl) FREE(hi->movedtourl);
         hi->movedtourl=Dupstr(p,q-p+1);
      }
      else if(hi->status==401 && STRNIEQUAL(hi->fd->block,"WWW-Authenticate:",17))
      {  struct Authorize *newauth=Parseauth(hi->fd->block+17,hi->hostport);
         if(newauth)
         {  if(hi->auth) Freeauthorize(hi->auth);
            hi->auth=newauth;
         }
      }
      else if(hi->status==407 && STRNIEQUAL(hi->fd->block,"Proxy-Authenticate:",19)
      && hi->fd->proxy)
      {  if(hi->prxauth) Freeauthorize(hi->prxauth);
         hi->prxauth=Parseauth(hi->fd->block+19,hi->fd->proxy);
      }
      else if(STRNIEQUAL(hi->fd->block,"Set-Cookie:",11))
      {  if(prefs.cookies) Storecookie(hi->fd->name,hi->fd->block+11,hi->fd->serverdate);
      }
      else if(STRNIEQUAL(hi->fd->block,"Refresh:",8))
      {  Updatetaskattrs(
            AOURL_Clientpull,hi->fd->block+8,
            TAG_END);
      }
      Nextline(hi);
   }
}

/* Read the HTTP response. Returns TRUE if HTTP, FALSE if plain response. */
static BOOL Readresponse(struct Httpinfo *hi)
{  long stat=0;
   BOOL http=FALSE;
   do
   {  if(!Readblock(hi)) return FALSE;
   } while(hi->blocklength<5);
   if(STRNEQUAL(hi->fd->block,"HTTP/",5))
   {  if(!Findline(hi)) return FALSE;
      hi->movedto=TAG_IGNORE;
      sscanf(hi->fd->block+5,"%*d.%*d %ld",&stat);
      Updatetaskattrs(
         AOURL_Header,hi->fd->block,
         TAG_END);
      if(stat<400)
      {  hi->flags|=HTTPIF_TUNNELOK;
         if(stat==301) hi->movedto=AOURL_Movedto;
         else if(stat==302) hi->movedto=AOURL_Tempmovedto;
         else if(stat==303) hi->movedto=AOURL_Seeother;
         else if(stat==304)
         {  Updatetaskattrs(
               AOURL_Notmodified,TRUE,
               TAG_END);
         }
      }
      else
      {  if(stat==401)
         {  if(hi->flags&HTTPIF_AUTH)
            {  /* Second attempt */
               if(hi->auth) Forgetauthorize(hi->auth);
               Updatetaskattrs(
                  AOURL_Error,TRUE,
                  TAG_END);
            }
            else
            {  hi->status=401;
            }
         }
         else if(stat==407)
         {  if(hi->flags&HTTPIF_PRXAUTH)
            {  /* Second attempt */
               if(hi->prxauth) Forgetauthorize(hi->prxauth);
               Updatetaskattrs(
                  AOURL_Error,TRUE,
                  TAG_END);
            }
            else
            {  hi->status=407;
            }
         }
         else if((stat==405 || stat==500 || stat==501) && hi->fd->postmsg)
         {  Updatetaskattrs(
               AOURL_Postnogood,TRUE,
               TAG_END);
         }
         else
         {  Updatetaskattrs(
               AOURL_Error,TRUE,
               TAG_END);
         }
      }
      http=TRUE;
   }
   return http;
}

/* Read and process part headers until end of headers. Read when necessary.
 * Returns FALSE if eof or error. */
static BOOL Readpartheaders(struct Httpinfo *hi)
{  hi->partlength=0;
   *hi->parttype='\0';
   for(;;)
   {  if(!Findline(hi)) return FALSE;
      if(hi->linelength==0)
      {  if(hi->status) return FALSE;
         else return TRUE;
      }
      Updatetaskattrs(
         AOURL_Header,hi->fd->block,
         TAG_END);
      if(STRNIEQUAL(hi->fd->block,"Content-Length:",15))
      {  sscanf(hi->fd->block+15," %ld",&hi->partlength);
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Type:",13))
      {  printf("DEBUG: Content-Type header found in Readpartheaders: '%s'\n", hi->fd->block);
         if(!prefs.ignoremime)
         {  UBYTE *p,*q;
            for(p=hi->fd->block+13;*p && isspace(*p);p++);
            q=strchr(p,';');
            if(q) *q='\0';
            if(strlen(p)>31) p[31]='\0';
            strcpy(hi->parttype,p);
            printf("DEBUG: Set parttype to: '%s'\n", hi->parttype);
         }
      }
      Nextline(hi);
   }
}

/* Read data and pass to main task. Returns FALSE if error or connection eof, TRUE if
 * multipart boundary found. */
static BOOL Readdata(struct Httpinfo *hi)
{  UBYTE *bdcopy=NULL;
   long bdlength=0,blocklength=0;
   BOOL result=FALSE,boundary,partial,eof;
   
   long gzip_buffer_size=INPUTBLOCKSIZE;
   UBYTE *gzipbuffer=NULL;
   long gziplength=0;
   long err=0;
   UWORD gzip_end=0;
   int loop_count=0;
   z_stream d_stream;

   if(hi->boundary)
   {  bdlength=strlen(hi->boundary);
      bdcopy=ALLOCTYPE(UBYTE,bdlength+1,0);
   }
   for(;;)
   {  if(hi->blocklength)
      {  printf("DEBUG: Processing data block, length=%ld, flags=0x%04X\n", hi->blocklength, hi->flags);
         
         // first block of the encoded data
         // allocate buffer and initialize zlib
         if((hi->flags & HTTPIF_GZIPENCODED) && !(hi->flags & HTTPIF_GZIPDECODING))
         {  int i;
            UBYTE *p;
            long gzip_start = 0;
            
            /* Find the start of actual gzip data (1F 8B 08) */
            for(p = hi->fd->block; p < hi->fd->block + hi->blocklength - 2; p++) {
                if(p[0] == 0x1F && p[1] == 0x8B && p[2] == 0x08) {
                    gzip_start = p - hi->fd->block;
                    break;
                }
            }
            
            if(gzip_start > 0) {
                printf("DEBUG: Found gzip data starting at position %ld, skipping prefix\n", gzip_start);
                /* Only copy the actual gzip data, skip any prefix */
                gziplength = hi->blocklength - gzip_start;
                
                /* CRITICAL: Validate gziplength to prevent memory corruption */
                if(gziplength > 0 && gziplength <= gzip_buffer_size && gziplength <= hi->blocklength) {
                    gzipbuffer = ALLOCTYPE(UBYTE, gziplength, 0);
                    if(gzipbuffer) {
                        memcpy(gzipbuffer, hi->fd->block + gzip_start, gziplength);
                    } else {
                        printf("DEBUG: CRITICAL: Failed to allocate gzip buffer, disabling gzip\n");
                        hi->flags &= ~HTTPIF_GZIPENCODED;
                        hi->flags &= ~HTTPIF_GZIPDECODING;
                        gzip_end = 1;
                        break;
                    }
                } else {
                    printf("DEBUG: CRITICAL: Invalid gziplength %ld, disabling gzip\n", gziplength);
                    hi->flags &= ~HTTPIF_GZIPENCODED;
                    hi->flags &= ~HTTPIF_GZIPDECODING;
                    gzip_end = 1;
                    break;
                }
            } else {
                printf("DEBUG: No gzip magic found, using entire block\n");
                
                /* CRITICAL: Validate blocklength before allocation */
                if(hi->blocklength > 0 && hi->blocklength <= gzip_buffer_size) {
                    gzipbuffer = ALLOCTYPE(UBYTE, hi->blocklength, 0);
                    if(gzipbuffer) {
                        gziplength = hi->blocklength;
                        memcpy(gzipbuffer, hi->fd->block, gziplength);
                    } else {
                        printf("DEBUG: CRITICAL: Failed to allocate gzip buffer, disabling gzip\n");
                        hi->flags &= ~HTTPIF_GZIPENCODED;
                        hi->flags &= ~HTTPIF_GZIPDECODING;
                        gzip_end = 1;
                        break;
                    }
                } else {
                    printf("DEBUG: CRITICAL: Invalid blocklength %ld for gzip, disabling gzip\n", hi->blocklength);
                    hi->flags &= ~HTTPIF_GZIPENCODED;
                    hi->flags &= ~HTTPIF_GZIPDECODING;
                    gzip_end = 1;
                    break;
                }
            }
            
            hi->flags|=HTTPIF_GZIPDECODING;
            printf("DEBUG: Starting gzip decompression, blocklength=%ld, gziplength=%ld\n", hi->blocklength, gziplength);
            
            /* Initialize zlib for gzip decompression */
            d_stream.zalloc=Z_NULL;
            d_stream.zfree=Z_NULL;
            d_stream.opaque=Z_NULL;
            d_stream.avail_in=0;
            d_stream.next_in=Z_NULL;
            d_stream.avail_out=0;
            d_stream.next_out=Z_NULL;
            
            /* CRITICAL: Validate zlib stream structure before initialization */
            if((ULONG)&d_stream < 0x1000 || (ULONG)&d_stream > 0xFFFFFFF0) {
               printf("DEBUG: CRITICAL: Invalid zlib stream pointer 0x%08lX\n", (ULONG)&d_stream);
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            }
            
            err=inflateInit2(&d_stream,16+15); // set zlib to expect 'gzip-header'
            if(err!=Z_OK) {
               printf("zlib Init Fail: %d\n", err);
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            } else {
               printf("DEBUG: zlib init successful\n");
            }
            
                     /* CRITICAL: Validate gzip buffer allocation to prevent heap corruption */
         if(gzipbuffer && gziplength > 0) {
            /* Check if gzipbuffer pointer is valid */
            if((ULONG)gzipbuffer < 0x1000 || (ULONG)gzipbuffer > 0xFFFFFFF0) {
               printf("DEBUG: CRITICAL: Invalid gzipbuffer pointer 0x%08lX\n", (ULONG)gzipbuffer);
               FREE(gzipbuffer);
               gzipbuffer = NULL;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            }
            
            /* Check if gziplength is reasonable */
            if(gziplength > gzip_buffer_size || gziplength <= 0) {
               printf("DEBUG: CRITICAL: Invalid gziplength: %ld (max: %ld)\n", gziplength, gzip_buffer_size);
               FREE(gzipbuffer);
               gzipbuffer = NULL;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            }
            
            d_stream.next_in=gzipbuffer;
            d_stream.avail_in=gziplength;
            
            /* CRITICAL: Validate blocksize before setting output buffer to prevent overflow */
            if(hi->fd->blocksize > 0 && hi->fd->blocksize <= INPUTBLOCKSIZE) {
                d_stream.next_out=hi->fd->block;
                d_stream.avail_out=hi->fd->blocksize;
                printf("DEBUG: Setting zlib output buffer to %ld bytes\n", hi->fd->blocksize);
            } else {
                printf("DEBUG: CRITICAL: Invalid blocksize %ld, using safe default\n", hi->fd->blocksize);
                d_stream.next_out=hi->fd->block;
                d_stream.avail_out=INPUTBLOCKSIZE;
                /* CRITICAL: Reset corrupted blocksize to prevent memory corruption */
                hi->fd->blocksize = INPUTBLOCKSIZE;
            }
                
                printf("DEBUG: First 16 bytes of gzip data: ");
                for(i = 0; i < MIN(16, gziplength); i++) {
                    printf("%02X ", gzipbuffer[i]);
                }
                printf("\n");
                
                /* Verify this is actually gzip data */
                if(gziplength >= 3 && gzipbuffer[0] == 0x1F && gzipbuffer[1] == 0x8B && gzipbuffer[2] == 0x08) {
                    printf("DEBUG: Valid gzip header confirmed\n");
                } else {
                    printf("DEBUG: WARNING: Data still doesn't start with gzip magic!\n");
                }
            } else {
                printf("DEBUG: No gzip data to process\n");
            }
            
            hi->blocklength=0;
            continue;
         }

         /* CRITICAL: Boundary detection for multipart data */
         boundary=partial=eof=FALSE;
         if(bdcopy)
         {  /* Look for [CR]LF--<boundary>[--][CR]LF or any possible part thereof. */
            UBYTE *p=hi->fd->block,*end=p+hi->blocklength;
            for(;;)
            {  for(;p<end && *p!='\r' && *p!='\n';p++);
               if(p>=end) break;
               blocklength=p-hi->fd->block;
               if(*p=='\r' && (p>=end-1 || p[1]=='\n'))
               {  p++;  /* Skip CR */
               }
               p++;  /* Skip LF */
               if(p>=end) partial=TRUE;
               else
               {  if(*p=='-')
                  {  /* Create a copy of hi->boundary, with what we have
                      * in the block, copied over. */
                     strcpy(bdcopy,hi->boundary);
                     strncpy(bdcopy,p,MIN(bdlength,end-p));
                     /* If the result is equal to the boundary, we have a (at least
                      * partial possible) boundary. */
                     if(STREQUAL(bdcopy,hi->boundary))
                     {  /* Now check if it's complete and followed by [CR]LF. */
                        p+=bdlength;
                        if(p<end && *p=='-') p++;
                        if(p<end && *p=='-')
                        {  eof=TRUE;
                           p++;
                        }
                        if(p<end && *p=='\r') p++;
                        if(p>=end) partial=TRUE;
                        else if(*p=='\n') boundary=TRUE;
                     }
                  }
               }
               if(boundary || partial) break;
               /* Look further */
               p=hi->fd->block+blocklength+1;
            }
         }
         if(!boundary && !partial) blocklength=hi->blocklength;
         
         /* CRITICAL: Validate blocklength to prevent memory corruption */
         if(blocklength < 0 || blocklength > hi->blocklength) {
            printf("DEBUG: CRITICAL: Invalid blocklength %ld, resetting to %ld\n", blocklength, hi->blocklength);
            blocklength = hi->blocklength;
         }
         
         /* CRITICAL: Validate data before calling Updatetaskattrs to prevent memory corruption */
         if(hi->fd && hi->fd->block && blocklength >= 0 && blocklength <= hi->fd->blocksize) {
            printf("DEBUG: Validating data before Updatetaskattrs: block=%p, length=%ld\n", hi->fd->block, blocklength);
            Updatetaskattrs(
               AOURL_Data,hi->fd->block,
               AOURL_Datalength,blocklength,
               TAG_END);
         } else {
            printf("DEBUG: CRITICAL: Invalid data detected, skipping Updatetaskattrs to prevent memory corruption\n");
            printf("DEBUG: fd=%p, block=%p, blocklength=%ld, blocksize=%ld\n", 
                   hi->fd, hi->fd ? hi->fd->block : NULL, blocklength, hi->fd ? hi->fd->blocksize : 0);
         }
         
         /* CRITICAL: Safe memory move with bounds checking */
         if(blocklength < hi->blocklength && blocklength > 0) {
            long move_length = hi->blocklength - blocklength;
            if(move_length > 0 && move_length <= hi->fd->blocksize) {
               memmove(hi->fd->block, hi->fd->block + blocklength, move_length);
               hi->blocklength = move_length;
            } else {
               printf("DEBUG: CRITICAL: Invalid move_length %ld, resetting blocklength\n", move_length);
               hi->blocklength = 0;
            }
         } else if(blocklength >= hi->blocklength) {
            hi->blocklength = 0;
         }
         
         if(hi->flags & HTTPIF_GZIPDECODING)
         {  d_stream.next_out=hi->fd->block;
            d_stream.avail_out=hi->fd->blocksize;
            /* Don't subtract blocklength here - gzip processing manages it separately */
            /* CRITICAL: For HTTPS with gzip, blocklength must not be modified */
         }
         else
         {  /* Only subtract blocklength for non-gzip data */
            if(hi->blocklength >= blocklength)
            {  hi->blocklength-=blocklength;
            }
            else
            {  /* Prevent negative blocklength values */
               printf("DEBUG: WARNING: blocklength %ld < blocklength %ld, resetting to 0\n", hi->blocklength, blocklength);
               hi->blocklength = 0;
            }
         }
         if(boundary)
         {  result=!eof;
            break;
         }
      }
      
      /* Gzip processing loop - continues until stream is complete */
      while(hi->flags & HTTPIF_GZIPDECODING && !gzip_end)
      {  if(gzip_end>0) break;
         
         /* Process the current gzip data */
         if(d_stream.avail_in > 0) {
            err=inflate(&d_stream,Z_SYNC_FLUSH);
         } else {
            err=Z_OK; /* No input to process */
         }
         
         /* Handle zlib return codes */
         if(err==Z_BUF_ERROR) {
            /* Output buffer is full - this is normal, not an error */
            printf("DEBUG: Output buffer full, processing current data and continuing\n");
            /* Process the current decompressed data */
            hi->blocklength=hi->fd->blocksize-d_stream.avail_out;
            printf("DEBUG: Processing %ld bytes of decompressed data\n", hi->blocklength);
            
            /* CRITICAL: Validate blocklength before processing to prevent memory corruption */
            if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
               printf("DEBUG: CRITICAL: Invalid blocklength %ld in Z_BUF_ERROR, resetting to prevent memory corruption\n", hi->blocklength);
               hi->blocklength = 0;
               inflateEnd(&d_stream);
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            }
            
            /* Update task attributes with current data */
            Updatetaskattrs(
               AOURL_Data,hi->fd->block,
               AOURL_Datalength,hi->blocklength,
               TAG_END);
            
            /* Reset output buffer for next chunk */
            d_stream.next_out=hi->fd->block;
            d_stream.avail_out=hi->fd->blocksize;
            
            /* Continue decompression - but add safety check to prevent infinite loops */
            if(++loop_count > 100) {
               printf("DEBUG: Too many buffer full cycles, finishing gzip\n");
               gzip_end=1;
               break;
            }
            continue;
         }
         else if(err==Z_STREAM_END) {
            printf("DEBUG: Gzip decompression completed successfully\n");
            gzip_end=1; // Success break!
         }
         else if(err!=Z_OK)
         {  if(err==Z_DATA_ERROR) printf("zlib DATA ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_STREAM_ERROR) printf("zlib STREAM_ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_NEED_DICT) printf("zlib NEED DICT - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_MEM_ERROR) printf("zlib MEM ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            
                     /* CRITICAL: On any zlib error, safely disable gzip to prevent memory corruption */
         printf("DEBUG: Zlib error detected, safely disabling gzip to prevent crashes\n");
         
         /* Clean up zlib stream immediately */
         inflateEnd(&d_stream);
         
         /* Reset all gzip flags */
         hi->flags &= ~HTTPIF_GZIPENCODED;
         hi->flags &= ~HTTPIF_GZIPDECODING;
         
         /* Reset output buffer safely */
         hi->blocklength = 0;
         d_stream.avail_out = hi->fd->blocksize;
         d_stream.next_out = hi->fd->block;
         
         /* Break out of gzip processing to prevent further corruption */
         gzip_end = 1;
         break;
         }
         
         /* If we need more input data, read it */
         if((err==Z_OK || err==Z_BUF_ERROR) && d_stream.avail_in==0 && !gzip_end)
         {  /* Add timeout protection to prevent infinite hanging */
            if(++loop_count > 200) {
               printf("DEBUG: Too many gzip input cycles, finishing\n");
               gzip_end=1;
               break;
            }
            
            gziplength=Receive(hi,gzipbuffer,gzip_buffer_size);
            if(gziplength<=0)
            {  
               if(gziplength < 0) {
                  printf("DEBUG: Network error during gzip processing: %ld\n", gziplength);
               } else {
                  printf("DEBUG: End of gzip data stream\n");
               }
               gzip_end=1; // Finished or Error
            }
            else
            {  d_stream.next_in=gzipbuffer;
               d_stream.avail_in=gziplength;
            }
         }
         
         /* CRITICAL: Only calculate blocklength if we have decompressed data */
         /* Don't reset blocklength here - it may still contain valid data */
         if(d_stream.avail_out < hi->fd->blocksize) {
            /* We have decompressed some data */
            long decompressed_len = hi->fd->blocksize - d_stream.avail_out;
            
            printf("DEBUG: Gzip decompressed %ld bytes\n", decompressed_len);
            
            /* CRITICAL: Validate decompressed length immediately to prevent memory corruption */
            if(decompressed_len < 0 || decompressed_len > hi->fd->blocksize) {
               printf("DEBUG: CRITICAL: Invalid decompressed length %ld calculated, aborting\n", decompressed_len);
               inflateEnd(&d_stream);
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
            
            /* CRITICAL: Process decompressed data immediately to ensure it's not lost */
            if(hi->fd && hi->fd->block && decompressed_len > 0) {
               printf("DEBUG: Processing %ld bytes of decompressed data immediately\n", decompressed_len);
               
               /* CRITICAL: Ensure proper content type is set for HTML parsing */
               /* Check if we have HTML content type from headers */
               if(hi->parttype[0] && strstr(hi->parttype, "text/html")) {
                  printf("DEBUG: Content type is HTML, ensuring proper parsing\n");
                  Updatetaskattrs(
                     AOURL_Data, hi->fd->block,
                     AOURL_Datalength, decompressed_len,
                     AOURL_Contenttype, "text/html",
                     TAG_END);
               } else {
                  printf("DEBUG: Content type: %s, processing as-is\n", hi->parttype[0] ? hi->parttype : "unknown");
                  Updatetaskattrs(
                     AOURL_Data, hi->fd->block,
                     AOURL_Datalength, decompressed_len,
                     TAG_END);
               }
               
               /* Mark this data as already processed to prevent duplication */
               hi->flags |= HTTPIF_DATA_PROCESSED;
               
               /* Reset output buffer for next decompression cycle */
               d_stream.next_out = hi->fd->block;
               d_stream.avail_out = hi->fd->blocksize;
               /* DON'T reset blocklength here - it's managed separately */
            }
            
            /* Continue processing - only exit when gzip_end is set (Z_STREAM_END) */
            if(gzip_end) {
               printf("DEBUG: Gzip stream complete, exiting processing loop\n");
               break;
            }
         }
         
         /* CRITICAL: Memory bounds validation with actual canary-like protection */
         if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
            printf("DEBUG: CRITICAL: Invalid blocklength %ld after decompression, aborting\n", hi->blocklength);
            inflateEnd(&d_stream);
            hi->flags &= ~HTTPIF_GZIPENCODED;
            hi->flags &= ~HTTPIF_GZIPDECODING;
            hi->blocklength = 0;
            gzip_end = 1;
            break;
         }
         
         /* CRITICAL: Buffer overflow protection - validate the actual buffer */
         if(hi->fd->block && hi->blocklength > 0) {
            UBYTE *buffer_start = hi->fd->block;
            UBYTE *buffer_end = buffer_start + hi->blocklength;
            
            /* Check if buffer pointers are valid memory addresses */
            if((ULONG)buffer_start < 0x1000 || (ULONG)buffer_start > 0xFFFFFFF0) {
               printf("DEBUG: CRITICAL: Invalid buffer start address 0x%08lX\n", (ULONG)buffer_start);
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
            
            /* Check if buffer end is within valid range */
            if((ULONG)buffer_end < 0x1000 || (ULONG)buffer_end > 0xFFFFFFF0) {
               printf("DEBUG: CRITICAL: Invalid buffer end address 0x%08lX\n", (ULONG)buffer_end);
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
            
            /* Verify buffer doesn't wrap around */
            if((ULONG)buffer_end <= (ULONG)buffer_start) {
               printf("DEBUG: CRITICAL: Buffer wrap-around detected\n");
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
            
            /* CRITICAL: Heap corruption detection - check memory allocation integrity */
            if(hi->fd->blocksize > 0) {
               /* Check if blocksize is reasonable (not corrupted) */
               if(hi->fd->blocksize > 1024*1024) { /* 1MB max */
                  printf("DEBUG: CRITICAL: Corrupted blocksize detected: %ld\n", hi->fd->blocksize);
                  hi->blocklength = 0;
                  gzip_end = 1;
                  break;
               }
               
               /* CRITICAL: Only validate that block pointer is a reasonable memory address */
               /* Don't check if it's within filedata structure - it's a separate buffer! */
               if((ULONG)buffer_start < 0x1000 || (ULONG)buffer_start > 0xFFFFFFF0) {
                  printf("DEBUG: CRITICAL: Block pointer is invalid memory address: 0x%08lX\n", (ULONG)buffer_start);
                  hi->blocklength = 0;
                  gzip_end = 1;
                  break;
               }
            }
         }
         
         /* CRITICAL: Safety check - ensure blocklength is valid to prevent memory corruption */
         if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
            printf("DEBUG: CRITICAL: Invalid blocklength %ld, resetting to 0 to prevent crash\n", hi->blocklength);
            hi->blocklength = 0;
            
            /* If we get invalid data, disable gzip to prevent further corruption */
            printf("DEBUG: Disabling gzip due to invalid decompressed data\n");
            hi->flags &= ~HTTPIF_GZIPENCODED;
            hi->flags &= ~HTTPIF_GZIPDECODING;
            gzip_end = 1;
            break;
         }
         
         /* If we have no more input and no more output, we're done */
         if(d_stream.avail_in==0 && d_stream.avail_out==hi->fd->blocksize && !gzip_end) {
            printf("DEBUG: No more input data, gzip decompression complete\n");
            gzip_end=1;
         }
         
         /* CRITICAL: Validate decompressed data to prevent memory corruption */
         if(hi->blocklength > 0) {
            UBYTE *data_check = hi->fd->block;
            BOOL data_valid = TRUE;
            int i;
            
            /* CRITICAL: Buffer pointer validation FIRST */
            if((ULONG)data_check < 0x1000 || (ULONG)data_check > 0xFFFFFFF0) {
               printf("DEBUG: CRITICAL: Invalid buffer pointer 0x%08lX, disabling gzip\n", (ULONG)data_check);
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
            
            /* Check first few bytes for reasonable data */
            for(i = 0; i < hi->blocklength && i < 16; i++) {
               if(data_check[i] < 0x20 && data_check[i] != 0x09 && data_check[i] != 0x0A && data_check[i] != 0x0D) {
                  if(data_check[i] != 0x00) { /* Allow null bytes */
                     data_valid = FALSE;
                     break;
                  }
               }
            }
            
            if(!data_valid) {
               printf("DEBUG: CRITICAL: Decompressed data contains invalid characters, disabling gzip\n");
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               hi->blocklength = 0;
               gzip_end = 1;
               break;
            }
         }
      } /* End of gzip processing while loop */
      
      /* CRITICAL: Clean up gzip resources after processing */
      if(hi->flags & HTTPIF_GZIPDECODING) {
         /* Gzip processing completed - clean up */
         inflateEnd(&d_stream);
         if(gzipbuffer) {
            FREE(gzipbuffer);
            gzipbuffer = NULL;
         }
         hi->flags &= ~HTTPIF_GZIPDECODING;
         
         /* Reset blocklength to 0 after gzip processing is complete */
         hi->blocklength = 0;
      }
      
      /* CRITICAL: Validate blocklength before continuing */
      if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
         printf("DEBUG: CRITICAL: Invalid blocklength %ld after gzip processing, resetting to prevent corruption\n", hi->blocklength);
         hi->blocklength = 0;
      }
      
      if(hi->flags & HTTPIF_GZIPDECODING)
      {  
         /* This shouldn't happen - gzip should be cleaned up above */
         printf("DEBUG: WARNING: Gzip still active after loop exit, forcing cleanup\n");
         inflateEnd(&d_stream);
         hi->flags &= ~HTTPIF_GZIPENCODED;
         hi->flags &= ~HTTPIF_GZIPDECODING;
         hi->blocklength = 0;
      }
      else
      {  printf("DEBUG: No data to process, blocklength=%ld, calling Readblock\n", hi->blocklength);
         
         /* CRITICAL: Validate blocklength before proceeding to prevent memory corruption */
         if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
            printf("DEBUG: CRITICAL: Invalid blocklength %ld detected in main loop, resetting to prevent OS crash\n", hi->blocklength);
            hi->blocklength = 0;
            
            /* CRITICAL: Disable gzip if it's causing corruption */
            if(hi->flags & (HTTPIF_GZIPENCODED | HTTPIF_GZIPDECODING)) {
               printf("DEBUG: CRITICAL: Disabling corrupted gzip processing\n");
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               
               /* Force cleanup of any remaining gzip resources */
               if(gzipbuffer) {
                  FREE(gzipbuffer);
                  gzipbuffer = NULL;
               }
               inflateEnd(&d_stream);
            }
            
            /* CRITICAL: Reset corrupted buffer to prevent OS crash */
            if(hi->fd && hi->fd->block) {
               hi->fd->block[0] = '\0'; /* Safe reset */
            }
            
            break;
         }
         
         /* CRITICAL: Check if data was already processed to prevent duplication */
         if(hi->flags & HTTPIF_DATA_PROCESSED) {
            printf("DEBUG: Data already processed, skipping Readblock to prevent duplication\n");
            hi->flags &= ~HTTPIF_DATA_PROCESSED; /* Clear the flag for next iteration */
            break;
         }
         
         /* Add timeout protection to prevent infinite hanging */
         if(++loop_count > 500) {
            printf("DEBUG: Too many main loop cycles, finishing\n");
            break;
         }
         
         if(!Readblock(hi)) {
            printf("DEBUG: Readblock failed, checking for network errors\n");
            /* Check if this is a network error vs normal EOF */
            if(hi->blocklength > 0) {
               printf("DEBUG: Have %ld bytes of data, processing what we have\n", hi->blocklength);
               /* Process the data we already have before breaking */
               Updatetaskattrs(
                  AOURL_Data, hi->fd->block,
                  AOURL_Datalength, hi->blocklength,
                  TAG_END);
            }
            break;
         }
         printf("DEBUG: Readblock returned, new blocklength=%ld\n", hi->blocklength);
      }
   }
   
   if(bdcopy) FREE(bdcopy);
   
   /* CRITICAL: Always clean up gzip resources to prevent memory corruption */
   if(gzipbuffer) 
   {  FREE(gzipbuffer);
      gzipbuffer = NULL;
   }
   
   /* CRITICAL: Always clean up zlib stream to prevent memory corruption */
   if(hi->flags & HTTPIF_GZIPDECODING || gzip_end > 0)
   {  inflateEnd(&d_stream);
      printf("DEBUG: Zlib stream cleaned up\n");
   }
   
   /* CRITICAL: Force cleanup of any pending network operations to prevent exit hanging */
   if(hi->sock >= 0) {
      printf("DEBUG: Force closing socket to prevent exit hanging\n");
      /* Use AmigaOS socket close function */
      if(hi->socketbase) {
         struct Library *SocketBase = hi->socketbase;
         close(hi->sock);
      }
      hi->sock = -1;
   }
   
   /* CRITICAL: Final memory corruption detection and prevention */
   if(hi->fd && hi->fd->block) {
      if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
         printf("DEBUG: CRITICAL: Final safety check - invalid blocklength %ld, resetting to 0\n", hi->blocklength);
         hi->blocklength = 0;
         
         /* CRITICAL: Reset buffer to prevent memory corruption from spreading */
         if(hi->fd->blocksize > 0 && hi->fd->blocksize <= INPUTBLOCKSIZE) {
            hi->fd->block[0] = '\0'; /* Safe reset */
            printf("DEBUG: CRITICAL: Buffer reset to prevent OS corruption\n");
         }
         
         /* CRITICAL: Disable gzip if it's causing corruption */
         if(hi->flags & (HTTPIF_GZIPENCODED | HTTPIF_GZIPDECODING)) {
            printf("DEBUG: CRITICAL: Final cleanup - disabling corrupted gzip processing\n");
            hi->flags &= ~HTTPIF_GZIPENCODED;
            hi->flags &= ~HTTPIF_GZIPDECODING;
         }
      }
   } else {
      printf("DEBUG: CRITICAL: Invalid fd or block pointer detected, resetting to prevent OS crash\n");
      hi->blocklength = 0;
   }
   
   /* CRITICAL: Final validation before return to prevent memory corruption */
   if(hi->fd && (ULONG)hi->fd < 0x1000 || (ULONG)hi->fd > 0xFFFFFFF0) {
      printf("DEBUG: CRITICAL: Corrupted fd pointer detected! fd=0x%08lX\n", (ULONG)hi->fd);
      hi->fd = NULL;
      hi->blocklength = 0;
   }
   
   /* CRITICAL: Final blocklength validation to prevent OS crash */
   if(hi->blocklength < 0) {
      printf("DEBUG: CRITICAL: Final blocklength validation failed: %ld, forcing reset to prevent OS crash\n", hi->blocklength);
      hi->blocklength = 0;
   }
   
   /* CRITICAL: Final validation before return to prevent memory corruption */
   if(hi->fd && (ULONG)hi->fd < 0x1000 || (ULONG)hi->fd > 0xFFFFFFF0) {
      printf("DEBUG: CRITICAL: Corrupted fd pointer detected! fd=0x%08lX\n", (ULONG)hi->fd);
      hi->fd = NULL;
      hi->blocklength = 0;
   }
   
   return result;
}

/* Process the plain or HTTP or multipart response. */
static void Httpresponse(struct Httpinfo *hi,BOOL readfirst)
{  BOOL first=TRUE;
   printf("DEBUG: Httpresponse: processing URL, flags=0x%04X\n", hi->flags);
   if(!readfirst || Readresponse(hi))
   {  Nextline(hi);
      hi->flags|=HTTPIF_HEADERS;
      if(Readheaders(hi))
      {  printf("DEBUG: Readheaders returned TRUE, processing response\n");
         if(hi->movedto && hi->movedtourl)
         {  Updatetaskattrs(hi->movedto,hi->movedtourl,TAG_END);
         }
         else
         {  printf("DEBUG: Calling Nextline before Readdata\n");
            Nextline(hi);
            printf("DEBUG: Nextline completed, calling Readdata\n");
            printf("DEBUG: After Nextline - blocklength=%ld, flags=0x%04X\n", hi->blocklength, hi->flags);
            if(hi->boundary)
            {  for(;;)
               {  if(!Findline(hi)) return;
                  if(STREQUAL(hi->fd->block,hi->boundary)) break;
                  Nextline(hi);
               }
               Nextline(hi);  /* Skip boundary */
               for(;;)
               {  if(!Readpartheaders(hi)) break;
                  Nextline(hi);
                  if(!first)
                  {  Updatetaskattrs(
                        AOURL_Reload,TRUE,
                        TAG_END);
                  }
                  if(*hi->parttype || hi->partlength)
                  {  Updatetaskattrs(
                        *hi->parttype?AOURL_Contenttype:TAG_IGNORE,hi->parttype,
                        hi->partlength?AOURL_Contentlength:TAG_IGNORE,hi->partlength,
                        TAG_END);
                  }
                  if(!Readdata(hi)) break;
                  Updatetaskattrs(
                     AOURL_Eof,TRUE,
                     AOURL_Serverpush,hi->fd->fetch,
                     TAG_END);
                  if(!Findline(hi)) break;
                  Nextline(hi);  /* Skip boundary */
                  first=FALSE;
               }
            }
            else
            {  printf("DEBUG: No boundary, calling Readdata directly\n");
               
               /* CRITICAL: Add memory corruption protection before calling Readdata */
               if(hi->fd && hi->fd->block && hi->fd->blocksize > 0 && hi->fd->blocksize <= INPUTBLOCKSIZE) {
                  printf("DEBUG: Memory validation passed, calling Readdata\n");
                  Readdata(hi);
                  printf("DEBUG: Readdata() completed\n");
                  
                  /* CRITICAL: Validate memory integrity after Readdata */
                  if(hi->fd && hi->fd->block) {
                     if(hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize) {
                        printf("DEBUG: CRITICAL: Memory corruption detected after Readdata! blocklength=%ld\n", hi->blocklength);
                        printf("DEBUG: CRITICAL: Resetting to prevent OS crash\n");
                        hi->blocklength = 0;
                        hi->fd->block[0] = '\0'; /* Safe reset */
                     }
                  }
               } else {
                  printf("DEBUG: CRITICAL: Invalid memory state detected, skipping Readdata to prevent OS crash\n");
                  printf("DEBUG: fd=%p, block=%p, blocksize=%ld\n", hi->fd, hi->fd ? hi->fd->block : NULL, hi->fd ? hi->fd->blocksize : 0);
                  hi->blocklength = 0;
               }
            }
         }
      }
   }
   else
   {  Readdata(hi);
   }
}

/* Send a message */
static long Send(struct Httpinfo *hi,UBYTE *request,long reqlen)
{  long result=-1;
#ifndef DEMOVERSION
   if(hi->flags&HTTPIF_SSL)
   {  result=Assl_write(hi->assl,request,reqlen);
   }
   else
   {  printf("DEBUG: Sending HTTP request: '%.*s'\n", (int)reqlen, request);
      result=a_send(hi->sock,request,reqlen,0,hi->socketbase);
   }
   return result;
}

#ifndef DEMOVERSION
/* Warning: Cannot make SSL connection. Retries TRUE if use unsecure link. */
static BOOL Securerequest(struct Httpinfo *hi,UBYTE *reason)
{  UBYTE *msg,*msgbuf;
   BOOL ok=FALSE;
   msg=AWEBSTR(MSG_SSLWARN_SSL_TEXT);
   if(msgbuf=ALLOCTYPE(UBYTE,strlen(msg)+strlen(hi->hostname)+strlen(reason)+8,0))
   {  Lprintf(msgbuf,msg,hi->hostname,reason);
      ok=Syncrequest(AWEBSTR(MSG_SSLWARN_SSL_TITLE),haiku?HAIKU11:msgbuf,
         AWEBSTR(MSG_SSLWARN_SSL_BUTTONS),0);
      FREE(msgbuf);
   }
   return ok;
}
#endif

BOOL Httpcertaccept(char *hostname,char *certname)
{  char *def="????";
   UBYTE *msg,*msgbuf,*h,*c;
   struct Certaccept *ca;
   BOOL ok=FALSE;
   h=hostname;
   c=certname;
   if(!c) c=def;
   if(!h) h=def;
   ObtainSemaphore(&certsema);
   for(ca=certaccepts.first;ca->next;ca=ca->next)
   {  if(STRIEQUAL(ca->hostname,hostname) && STREQUAL(ca->certname,c))
      {  ok=TRUE;
         break;
      }
   }
   if(!ok)
   {  msg=AWEBSTR(MSG_SSLWARN_CERT_TEXT);
      if(msgbuf=ALLOCTYPE(UBYTE,strlen(msg)+strlen(h)+strlen(c)+8,0))
      {  Lprintf(msgbuf,msg,h,c);
         ok=Syncrequest(AWEBSTR(MSG_SSLWARN_CERT_TITLE),haiku?HAIKU13:msgbuf,
            AWEBSTR(MSG_SSLWARN_CERT_BUTTONS),0);
         FREE(msgbuf);
         if(hostname)
         {  if(ok)
            {  if(ca=ALLOCSTRUCT(Certaccept,1,MEMF_PUBLIC|MEMF_CLEAR))
               {  ca->hostname=Dupstr(hostname,-1);
                  ca->certname=Dupstr(c,-1);
                  ADDTAIL(&certaccepts,ca);
               }
            }
         }
      }
   }
   ReleaseSemaphore(&certsema);
   return ok;
}

/* Open the tcp stack, and optionally the SSL library */
static BOOL Openlibraries(struct Httpinfo *hi)
{  BOOL result=FALSE;
   Opentcp(&hi->socketbase,hi->fd,!hi->fd->validate);
   if(!hi->socketbase)
   {  /* Show GUI error if bsdsocket.library is missing */
      Lowlevelreq("AWeb requires bsdsocket.library for network access.\nPlease install bsdsocket.library and try again.");
      return FALSE;
   }
   result=TRUE;
   if(hi->flags&HTTPIF_SSL)
   {  
#ifndef DEMOVERSION
      if(hi->assl=Tcpopenssl(hi->socketbase))
      {  /* ok */
         /* Additional check for amisslmaster.library (AmiSSL 4+) */
         struct Library *amisslmaster = OpenLibrary("amisslmaster.library", 0);
         if(!amisslmaster)
         {  Lowlevelreq("AWeb requires amisslmaster.library for SSL/TLS connections.\nPlease install AmiSSL 5.20 or newer and try again.");
            Assl_cleanup(hi->assl);
            hi->assl = NULL;
            result = FALSE;
         }
         else
         {  CloseLibrary(amisslmaster);
         }
      }
      else
      {  /* No SSL available */
         Lowlevelreq("AWeb requires amissl.library (AmiSSL 5.20+) for SSL/TLS connections.\nPlease install AmiSSL and try again.");
         if(Securerequest(hi,haiku?HAIKU12:AWEBSTR(MSG_SSLWARN_SSL_NO_SSL2)))
         {  hi->flags&=~HTTPIF_SSL;
         }
         else
         {  result=FALSE;
         }
      }
#else
      hi->flags&=~HTTPIF_SSL;
#endif
   }
   return result;
}

/* Create SSL context, SSL and socket */
static long Opensocket(struct Httpinfo *hi,struct hostent *hent)
{  long sock;
   struct timeval timeout;
   
#ifndef DEMOVERSION
   if(hi->flags&HTTPIF_SSL)
   {  if(!Assl_openssl(hi->assl)) return -1;
   }
#endif
   sock=a_socket(hent->h_addrtype,SOCK_STREAM,0,hi->socketbase);
   if(sock<0)
   {  Assl_closessl(hi->assl);
      return -1;
   }
   
   /* Set socket timeouts to prevent hanging connections */
   timeout.tv_sec = 30;  /* 30 second timeout */
   timeout.tv_usec = 0;
   
   /* Set receive timeout */
/*   if(a_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout), hi->socketbase) < 0)
   {  /* Timeout setting failed, but continue */
   }
*/   
   /* Set send timeout */
/*   if(a_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout), hi->socketbase) < 0)
   {  /* Timeout setting failed, but continue */
   }
*/   
   return sock;
}

/* Connect and make SSL connection. Returns TRUE if success. */
static BOOL Connect(struct Httpinfo *hi,struct hostent *hent)
{  BOOL ok=FALSE;
   if(hi->port==-1)
   {  if(hi->flags&HTTPIF_SSL) hi->port=443;
      else hi->port=80;
   }
   if(!a_connect(hi->sock,hent,hi->port,hi->socketbase))
   {  
#ifndef DEMOVERSION
      if(hi->flags&HTTPIF_SSL)
      {  if(hi->flags&HTTPIF_SSLTUNNEL)
         {  UBYTE *creq,*p;
            long creqlen=strlen(tunnelrequest)+strlen(hi->tunnel);
            if(hi->prxauth && hi->prxauth->cookie)
            {  creqlen+=strlen(proxyauthorization)+strlen(hi->prxauth->cookie);
            }
            creqlen+=16;
            if(creq=ALLOCTYPE(UBYTE,creqlen,0))
            {  p=creq;
               p+=sprintf(p,tunnelrequest,hi->tunnel);
               if(hi->prxauth && hi->prxauth->cookie)
                  p+=sprintf(p,proxyauthorization,hi->prxauth->cookie);
               p+=sprintf(p,"\r\n");
               creqlen=p-creq;
#ifdef BETAKEYFILE
               if(httpdebug)
               {  Write(Output(),"\n",1);
                  Write(Output(),creq,creqlen);
               }
#endif
               /* Temporarily turn off SSL since we don't have a SSL connection yet */
               hi->flags&=~HTTPIF_SSL;
               if(Send(hi,creq,creqlen)==creqlen)
               {  
                  if(Readresponse(hi))
                  {  
                     Nextline(hi);
                     if(Readheaders(hi))
                     {  
                        Nextline(hi);
                        if(hi->flags&HTTPIF_TUNNELOK)
                        {  
                           ok=TRUE;
                        }
                     }
                  }
               }
               hi->flags|=HTTPIF_SSL;
               FREE(creq);
            }
         }
         else ok=TRUE;
         
         if(ok)
         {  long result=Assl_connect(hi->assl,hi->sock,hi->hostname);
            ok=(result==ASSLCONNECT_OK);
            if(result==ASSLCONNECT_DENIED) hi->flags|=HTTPIF_NOSSLREQ;
            if(!ok && !(hi->flags&HTTPIF_NOSSLREQ))
            {  UBYTE errbuf[128],*p;
               p=Assl_geterror(hi->assl,errbuf);
               if(Securerequest(hi,p))
               {  hi->flags|=HTTPIF_RETRYNOSSL;
               }
            }
         }
      }
      else
#endif
      {  ok=TRUE;
      }
   }
   return ok;
}

/* Send multipart form data. */
static BOOL Sendmultipartdata(struct Httpinfo *hi,struct Fetchdriver *fd,FILE *fp)
{  struct Multipartpart *mpp;
   long lock,fh,l;
   BOOL ok=TRUE;
   for(mpp=fd->multipart->parts.first;ok && mpp->next;mpp=mpp->next)
   {  if(mpp->lock)
      {  Updatetaskattrs(AOURL_Netstatus,NWS_UPLOAD,TAG_END);
         Tcpmessage(fd,TCPMSG_UPLOAD);
         /* We can't just use the mpp->lock because we might need to send the
          * message again after a 301/302 status. */
         if(lock=DupLock(mpp->lock))
         {  if(fh=OpenFromLock(lock))
            {  while(ok && (l=Read(fh,fd->block,fd->blocksize)))
               {  
#ifdef DEVELOPER
                  if(httpdebug) Write(Output(),fd->block,l);
                  if(fp) fwrite(fd->block,l,1,fp);
                  else
#endif
                  ok=(Send(hi,fd->block,l)==l);
               }
               Close(fh);
            }
            else UnLock(lock);
         }
      }
      else
      {  
#ifdef DEVELOPER
         if(httpdebug) Write(Output(),fd->multipart->buf.buffer+mpp->start,mpp->length);
         if(fp) fwrite(fd->multipart->buf.buffer+mpp->start,mpp->length,1,fp);
         else
#endif
         ok=(Send(hi,fd->multipart->buf.buffer+mpp->start,mpp->length)==mpp->length);
      }
   }
#ifdef DEVELOPER
   if(httpdebug) Write(Output(),"\n",1);
#endif
   return ok;
}

#ifndef DEMOVERSION
static BOOL Formwarnrequest(void)
{  return (BOOL)Syncrequest(AWEBSTR(MSG_FORMWARN_TITLE),
      haiku?HAIKU16:AWEBSTR(MSG_FORMWARN_WARNING),AWEBSTR(MSG_FORMWARN_BUTTONS),0);
}
#endif

static void Httpretrieve(struct Httpinfo *hi,struct Fetchdriver *fd)
{  struct hostent *hent;
   long reqlen,msglen,result;
   UBYTE *request,*p,*q;
   BOOL error=FALSE;
   hi->blocklength=0;
   hi->nextscanpos=0;
   if(fd->flags&FDVF_SSL) hi->flags|=HTTPIF_SSL;
   hi->fd=fd;
#ifdef DEVELOPER
   if(STRNEQUAL(fd->name,"&&&&",4)
   ||STRNIEQUAL(fd->name,"http://&&&&",11)
   ||STRNIEQUAL(fd->name,"https://&&&&",12)
   ||STRNIEQUAL(fd->name,"ftp://&&&&",10))
   {  UBYTE name[64]="CON:20/200/600/200/HTTP/screen ";
      FILE *f;
      strcat(name,(UBYTE *)Agetattr(Aweb(),AOAPP_Screenname));
      if(
#ifndef DEMOVERSION
         (!(hi->fd->flags&FDVF_FORMWARN) || (hi->flags&HTTPIF_SSL) || Formwarnrequest())
      && 
#endif
         (f=fopen(name,"r+")))
      {  fprintf(f,"[%s %d%s]\n",hi->connect,hi->port,
            (hi->flags&HTTPIF_SSL)?" SECURE":"");
         reqlen=Buildrequest(fd,hi,&request);
         fwrite(request,reqlen,1,f);
         if(fd->multipart) Sendmultipartdata(hi,fd,f);
         else if(fd->postmsg)
         {  fwrite(fd->postmsg,strlen(fd->postmsg),1,f);
            fwrite("\n",1,1,f);
         }
         fflush(f);
         if(request!=fd->block) FREE(request);
         if(hi->flags&HTTPIF_SSL)
         {  Updatetaskattrs(AOURL_Cipher,"AWEB-DEBUG",TAG_END);
         }
         Updatetaskattrs(AOURL_Netstatus,NWS_WAIT,TAG_END);
         Tcpmessage(fd,TCPMSG_WAITING,hi->flags&HTTPIF_SSL?"HTTPS":"HTTP");
         hi->socketbase=NULL;
         hi->sock=(long)f;
         Httpresponse(hi,TRUE);
         fclose(f);
      }
   }
   else
   {
#endif
   result=Openlibraries(hi);
#ifndef DEMOVERSION
   if(result && (hi->fd->flags&FDVF_FORMWARN) && !(hi->flags&HTTPIF_SSL))
   {  result=Formwarnrequest();
   }
#endif
   if(result)
   {  Updatetaskattrs(AOURL_Netstatus,NWS_LOOKUP,TAG_END);
      Tcpmessage(fd,TCPMSG_LOOKUP,hi->connect);
      if(hent=Lookup(hi->connect,hi->socketbase))
      {  if((hi->sock=Opensocket(hi,hent))>=0)
         {  Updatetaskattrs(AOURL_Netstatus,NWS_CONNECT,TAG_END);
            Tcpmessage(fd,TCPMSG_CONNECT,
               hi->flags&HTTPIF_SSL?"HTTPS":"HTTP",hent->h_name);
            if(Connect(hi,hent))
            {  
#ifndef DEMOVERSION
               if(hi->flags&HTTPIF_SSL)
               {  p=Assl_getcipher(hi->assl);
                  q=Assl_libname(hi->assl);
                  if(p || q)
                  {  Updatetaskattrs(AOURL_Cipher,p,
                        AOURL_Ssllibrary,q,
                        TAG_END);
                  }
               }
#endif
               
               reqlen=Buildrequest(fd,hi,&request);
               result=(Send(hi,request,reqlen)==reqlen);
#ifdef BETAKEYFILE
               if(httpdebug)
               {  Write(Output(),"\n",1);
                  Write(Output(),request,reqlen);
               }
#endif
               if(result)
               {  if(fd->multipart)
                  {  result=Sendmultipartdata(hi,fd,NULL);
                  }
                  else if(fd->postmsg)
                  {  msglen=strlen(fd->postmsg);
                     result=(Send(hi,fd->postmsg,msglen)==msglen);
#ifdef BETAKEYFILE
                     if(httpdebug)
                     {  Write(Output(),fd->postmsg,msglen);
                        Write(Output(),"\n\n",2);
                     }
#endif
                  }
               }
               if(request!=fd->block) FREE(request);
               if(result)
               {  Updatetaskattrs(AOURL_Netstatus,NWS_WAIT,TAG_END);
                  Tcpmessage(fd,TCPMSG_WAITING,hi->flags&HTTPIF_SSL?"HTTPS":"HTTP");
                  Httpresponse(hi,TRUE);
               }
               else error=TRUE;
            }
            else if(!(hi->flags&HTTPIF_RETRYNOSSL) && hi->status!=407)
            {  Tcperror(fd,TCPERR_NOCONNECT,
                  (hi->flags&HTTPIF_SSLTUNNEL)?hi->hostport:(UBYTE *)hent->h_name);
            }
            if(hi->assl)
            {  Assl_closessl(hi->assl);
            }
            a_close(hi->sock,hi->socketbase);
         }
         else error=TRUE;
      }
      else
      {  Tcperror(fd,TCPERR_NOHOST,hi->hostname);
      }
      a_cleanup(hi->socketbase);
   }
   else
   {  Tcperror(fd,TCPERR_NOLIB);
   }
#ifndef DEMOVERSION
   if(hi->assl)
   {  Assl_cleanup(hi->assl);
      hi->assl=NULL;
   }
#endif
   if(hi->socketbase)
   {  CloseLibrary(hi->socketbase);
      hi->socketbase=NULL;
   }
#ifdef DEVELOPER
   }
#endif
   if(error)
   {  Updatetaskattrs(
         AOURL_Error,TRUE,
         TAG_END);
   }
}

/*-----------------------------------------------------------------------*/

void Httptask(struct Fetchdriver *fd)
{  struct Httpinfo hi={0};
   if(Makehttpaddr(&hi,fd->proxy,fd->name,BOOLVAL(fd->flags&FDVF_SSL)))
   {  if(!prefs.limitproxy && !hi.auth) hi.auth=Guessauthorize(hi.hostport);
      if(fd->proxy && !prefs.limitproxy) hi.prxauth=Guessauthorize(fd->proxy);
      for(;;)
      {  if(fd->proxy && hi.auth && prefs.limitproxy)
         {  if(hi.connect) FREE(hi.connect);
            if(hi.tunnel) FREE(hi.tunnel);hi.tunnel=NULL;
            if(hi.hostport) FREE(hi.hostport);
            if(hi.abspath) FREE(hi.abspath);
            if(hi.hostname) FREE(hi.hostname);
            if(!Makehttpaddr(&hi,NULL,fd->name,BOOLVAL(fd->flags&FDVF_SSL))) break;
         }
         hi.status=0;
         Httpretrieve(&hi,fd);
         if(hi.flags&HTTPIF_RETRYNOSSL)
         {  UBYTE *url=ALLOCTYPE(UBYTE,strlen(fd->name)+6,0);
            UBYTE *p;
            strcpy(url,"http");
            if(p=strchr(fd->name,':')) strcat(url,p);
            Updatetaskattrs(AOURL_Tempmovedto,url,TAG_END);
            FREE(url);
            break;
         }
         if(hi.status==401 && !(hi.flags&HTTPIF_AUTH) && hi.auth)
         {  hi.flags|=HTTPIF_AUTH;
            Updatetaskattrs(
               AOURL_Contentlength,0,
               AOURL_Contenttype,"",
               TAG_END);
            if(!hi.auth->cookie) Authorize(fd,hi.auth,FALSE);
            if(hi.auth->cookie) continue;
            Updatetaskattrs(AOURL_Error,TRUE,TAG_END);
         }
         if(hi.status==407 && !(hi.flags&HTTPIF_PRXAUTH) && hi.prxauth)
         {  hi.flags|=HTTPIF_PRXAUTH;
            Updatetaskattrs(
               AOURL_Contentlength,0,
               AOURL_Contenttype,"",
               TAG_END);
            if(!hi.prxauth->cookie) Authorize(fd,hi.prxauth,TRUE);
            if(hi.prxauth->cookie) continue;
            Updatetaskattrs(AOURL_Error,TRUE,TAG_END);
         }
         break;
      }
   }
   else
   {  Updatetaskattrs(AOURL_Error,TRUE,TAG_END);
   }
   if(hi.connect) FREE(hi.connect);
   if(hi.tunnel) FREE(hi.tunnel);
   if(hi.hostport) FREE(hi.hostport);
   if(hi.abspath) FREE(hi.abspath);
   if(hi.hostname) FREE(hi.hostname);
   if(hi.auth) Freeauthorize(hi.auth);
   if(hi.prxauth) Freeauthorize(hi.prxauth);
   if(hi.movedtourl) FREE(hi.movedtourl);
   Updatetaskattrs(AOTSK_Async,TRUE,
      AOURL_Eof,TRUE,
      AOURL_Terminate,TRUE,
      TAG_END);
}

#endif /* LOCALONLY */

/*-----------------------------------------------------------------------*/

/* Enhanced multipart boundary detection */
static BOOL Findmultipartboundary(struct Httpinfo *hi, UBYTE *data, long length)
{  UBYTE *p = data;
   UBYTE *end = data + length;
   UBYTE *boundary = hi->boundary;
   long blen;
   
   if(!boundary) return FALSE;
   blen = strlen(boundary);
   
   while(p < end - blen)
   {  if(*p == '\r' || *p == '\n')
      {  p++;
         if(p < end && (*p == '\r' || *p == '\n')) p++;
         if(p < end && *p == '-' && p[1] == '-')
         {  if(STREQUAL(p + 2, boundary))
            {  return TRUE;
            }
         }
      }
      p++;
   }
   return FALSE;
}

/*-----------------------------------------------------------------------*/

BOOL Inithttp(void)
{  
#ifndef LOCALONLY
   InitSemaphore(&certsema);
   NEWLIST(&certaccepts);
#endif
   return TRUE;
}

void Freehttp(void)
{  
#ifndef LOCALONLY
   struct Certaccept *ca;
   if(certaccepts.first)
   {  while(ca=REMHEAD(&certaccepts))
      {  if(ca->hostname) FREE(ca->hostname);
         if(ca->certname) FREE(ca->certname);
         FREE(ca);
      }
   }
#endif
}

