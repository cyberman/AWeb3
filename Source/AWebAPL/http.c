/**********************************************************************
 * 
 * This file is part of the AWeb APL distribution
 *
 * Original Copyright (C) 2002 Yvon Rozijn
 * Rewrite Copyright (C) 2025 amigazen project
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
#define HTTPIF_CHUNKED 0x0800        /* response uses chunked transfer encoding */

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
{  long old_blocklength = hi->blocklength;
   if(hi->nextscanpos<hi->blocklength)
   {  memmove(hi->fd->block,hi->fd->block+hi->nextscanpos,hi->blocklength-hi->nextscanpos);
   }
   hi->blocklength-=hi->nextscanpos;
   hi->nextscanpos=0;
   printf("DEBUG: Nextline: consumed %ld bytes, remaining blocklength=%ld\n", 
          old_blocklength - hi->blocklength, hi->blocklength);
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
{  /* Reset encoding flags at start of headers - this is crucial! */
   hi->flags &= ~(HTTPIF_GZIPENCODED | HTTPIF_GZIPDECODING | HTTPIF_CHUNKED);
   
   for(;;)
   {  if(!Findline(hi)) return FALSE;
      if(hi->linelength==0)
      {  if(hi->status) return FALSE;
         else 
         {  printf("DEBUG: Headers complete, starting data processing\n");
            /* Allow gzip with chunked encoding - we now handle it properly */
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
         hi->partlength = i; /* Store for use in Readdata to track compressed data consumption */
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
            /* Store content type in parttype for later use (e.g., gzip processing) */
            strncpy(hi->parttype, mimetype, sizeof(hi->parttype) - 1);
            hi->parttype[sizeof(hi->parttype) - 1] = '\0';
            printf("DEBUG: Stored parttype='%s' (length=%ld)\n", hi->parttype, strlen(hi->parttype));
            Updatetaskattrs(
               AOURL_Contenttype,mimetype,
               AOURL_Foreign,foreign,
               TAG_END);
         }
         else
         {  printf("DEBUG: No mimetype extracted from Content-Type header (forward=%d, prefs.ignoremime=%d)\n", forward, prefs.ignoremime);
            /* Clear parttype if no mimetype */
            hi->parttype[0] = '\0';
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"Content-Encoding:",17))
      {  if(strstr(hi->fd->block+18,"gzip"))
         {  hi->flags|=HTTPIF_GZIPENCODED;
            printf("DEBUG: Detected gzip encoding\n");
            Updatetaskattrs(AOURL_Contentlength,0,TAG_END);
         }
      }
      else if(STRNIEQUAL(hi->fd->block,"Transfer-Encoding:",18))
      {  if(strstr(hi->fd->block+18,"chunked"))
         {  hi->flags|=HTTPIF_CHUNKED;
            printf("DEBUG: Detected chunked transfer encoding\n");
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
            long maxage;
            maxage = 0;
            if(q=strchr(p,'='))
            {  sscanf(q+1,"%ld",&maxage);
               Updatetaskattrs(AOURL_Maxage,maxage,TAG_END);
            }
         }
      }
      else if(hi->movedto && STRNIEQUAL(hi->fd->block,"Location:",9))
      {  UBYTE *p;
         UBYTE *q;
         for(p=hi->fd->block+9;*p && isspace(*p);p++);
         for(q=p+strlen(p)-1;q>p && isspace(*q);q--);
         if(hi->movedtourl) FREE(hi->movedtourl);
         hi->movedtourl=Dupstr(p,q-p+1);
         printf("DEBUG: Set movedtourl to: %s\n", hi->movedtourl ? (char *)hi->movedtourl : "(NULL)");
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
      printf("DEBUG: HTTP status code: %ld\n", stat);
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
   long move_length;
   z_stream d_stream;
   BOOL d_stream_initialized=FALSE; /* Track if d_stream has been initialized */
   BOOL exit_main_loop=FALSE; /* Flag to exit main loop for gzip processing */
   long compressed_bytes_consumed=0; /* Track how much compressed data we've consumed for Content-Length validation */
   long total_compressed_read=0; /* Track total compressed bytes READ from network (before copying to gzipbuffer) */

   if(hi->boundary)
   {  bdlength=strlen(hi->boundary);
      bdcopy=ALLOCTYPE(UBYTE,bdlength+1,0);
   }
   for(;;)
   {  if(hi->blocklength)
      {  printf("DEBUG: Readdata loop: Processing data block, length=%ld, flags=0x%04X, parttype='%s'\n", 
                hi->blocklength, hi->flags, hi->parttype[0] ? (char *)hi->parttype : "(none)");
         
         // first block of the encoded data
         // allocate buffer and initialize zlib
         if((hi->flags & HTTPIF_GZIPENCODED) && !(hi->flags & HTTPIF_GZIPDECODING))
         {  int i;
            UBYTE *p;
            long gzip_start;
            long search_start;
            long data_after_chunk;
            
            gzip_start = 0;
            search_start = 0;
            
            /* CRITICAL: Handle chunked encoding + gzip combination */
            /* When chunked encoding is present, skip chunk headers before looking for gzip magic */
            if(hi->flags & HTTPIF_CHUNKED)
            {  /* Skip chunk size line (e.g., "3259\r\n") */
               p = hi->fd->block;
               while(search_start < hi->blocklength - 1)
               {  if(p[search_start] == '\r' && search_start + 1 < hi->blocklength && p[search_start + 1] == '\n')
                  {  search_start += 2; /* Skip CRLF */
                     break;
                  }
                  search_start++;
               }
               printf("DEBUG: Chunked encoding detected, skipping %ld bytes of chunk header\n", search_start);
            }
            
            /* Find the start of actual gzip data (1F 8B 08) */
            gzip_start = -1; /* Use -1 to indicate not found */
            for(p = hi->fd->block + search_start; p < hi->fd->block + hi->blocklength - 2; p++) {
                if(p[0] == 0x1F && p[1] == 0x8B && p[2] == 0x08) {
                    gzip_start = p - hi->fd->block;
                    break;
                }
            }
            
            /* CRITICAL: Don't start gzip if we haven't found gzip magic and we have chunked encoding */
            /* With chunked encoding, we need to wait until we have actual gzip data */
            if(gzip_start < 0 && (hi->flags & HTTPIF_CHUNKED))
            {  /* Check if we have enough data after chunk header to potentially contain gzip magic */
               data_after_chunk = hi->blocklength - search_start;
               if(data_after_chunk < 10)
               {  printf("DEBUG: Chunked+gzip: Not enough data yet (only %ld bytes after chunk header), waiting for more chunks\n", data_after_chunk);
                  /* Don't start gzip yet - wait for more data */
                  continue;
               }
               else
               {  printf("DEBUG: Chunked+gzip: Have %ld bytes after chunk header but no gzip magic, disabling gzip\n", data_after_chunk);
                  hi->flags &= ~HTTPIF_GZIPENCODED;
                  hi->flags &= ~HTTPIF_GZIPDECODING;
                  continue;
               }
            }
            
            /* If we found gzip magic (at any position, including 0), use it */
            if(gzip_start >= 0)
            {  printf("DEBUG: Found gzip data starting at position %ld, skipping prefix\n", gzip_start);
               
               /* For chunked encoding, extract all chunks and accumulate them */
               if(hi->flags & HTTPIF_CHUNKED)
               {                 /* Extract all chunks from the block and accumulate in gzipbuffer */
                  long chunk_pos;
                  long chunk_size;
                  long total_chunk_data;
                  long initial_gzip_size;
                  
                  /* CRITICAL: Start parsing from beginning of block, not from search_start */
                  /* search_start is after the first chunk header, but we need to parse from the start */
                  chunk_pos = 0;
                  total_chunk_data = 0;
                  
                  /* Calculate total size of chunk data from gzip_start onwards */
                  while(chunk_pos < hi->blocklength)
                  {  long chunk_data_start;
                     
                     /* Skip whitespace before chunk size */
                     while(chunk_pos < hi->blocklength && 
                           (hi->fd->block[chunk_pos] == ' ' || hi->fd->block[chunk_pos] == '\t'))
                     {  chunk_pos++;
                     }
                     
                     /* Parse chunk size (hex number) */
                     chunk_size = 0;
                     while(chunk_pos < hi->blocklength)
                     {  UBYTE c;
                        long digit;
                        
                        c = hi->fd->block[chunk_pos];
                        if(c >= '0' && c <= '9')
                        {  digit = c - '0';
                        }
                        else if(c >= 'A' && c <= 'F')
                        {  digit = c - 'A' + 10;
                        }
                        else if(c >= 'a' && c <= 'f')
                        {  digit = c - 'a' + 10;
                        }
                        else
                        {  break;
                        }
                        chunk_size = chunk_size * 16 + digit;
                        chunk_pos++;
                     }
                     
                     if(chunk_size == 0)
                     {  /* Last chunk */
                        break;
                     }
                     
                     /* Skip chunk extension (semicolon and anything after) */
                     while(chunk_pos < hi->blocklength && 
                           hi->fd->block[chunk_pos] != '\r' && hi->fd->block[chunk_pos] != '\n')
                     {  chunk_pos++;
                     }
                     
                     /* Skip CRLF after chunk header */
                     if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                     {  chunk_pos++;
                     }
                     if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                     {  chunk_pos++;
                     }
                     
                     /* Store where chunk data starts */
                     chunk_data_start = chunk_pos;
                     
                     /* Only count chunk data that is at or after gzip_start */
                     if(chunk_data_start <= gzip_start && chunk_data_start + chunk_size > gzip_start)
                     {  /* This chunk contains gzip_start - count from gzip_start */
                        total_chunk_data += (chunk_data_start + chunk_size) - gzip_start;
                     }
                     else if(chunk_data_start > gzip_start)
                     {  /* This chunk is entirely after gzip_start - count all of it */
                        total_chunk_data += chunk_size;
                     }
                     /* Otherwise, this chunk is before gzip_start, skip it */
                     
                     /* Move past chunk data */
                     if(chunk_pos + chunk_size <= hi->blocklength)
                     {  chunk_pos += chunk_size;
                        
                        /* Skip CRLF after chunk data */
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                     }
                     else
                     {  /* Chunk extends beyond current block - estimate remaining */
                        if(chunk_data_start <= gzip_start)
                        {  /* This chunk contains gzip_start and extends beyond block */
                           total_chunk_data += (hi->blocklength - gzip_start);
                        }
                        else
                        {  /* This chunk is after gzip_start */
                           total_chunk_data += (hi->blocklength - chunk_pos);
                        }
                        break;
                     }
                  }
                  
                  printf("DEBUG: Chunked+gzip: Calculated total_chunk_data=%ld bytes from gzip_start=%ld\n", total_chunk_data, gzip_start);
                  
                  /* Find where gzip data starts in the chunk data */
                  initial_gzip_size = hi->blocklength - gzip_start;
                  if(initial_gzip_size > total_chunk_data)
                  {  initial_gzip_size = total_chunk_data;
                  }
                  
                  /* Allocate buffer for gzip data (use total_chunk_data, but we may need to grow it) */
                  if(total_chunk_data > 0 && total_chunk_data <= gzip_buffer_size)
                  {  gzipbuffer = ALLOCTYPE(UBYTE, total_chunk_data, 0);
                     if(!gzipbuffer)
                     {  printf("DEBUG: Chunked+gzip: Failed to allocate buffer of size %ld\n", total_chunk_data);
                        total_chunk_data = 0;
                     }
                  }
                  else if(total_chunk_data > gzip_buffer_size)
                  {  /* Chunked data is larger than buffer - allocate max buffer size */
                     gzipbuffer = ALLOCTYPE(UBYTE, gzip_buffer_size, 0);
                     if(!gzipbuffer)
                     {  printf("DEBUG: Chunked+gzip: Failed to allocate max buffer of size %ld\n", gzip_buffer_size);
                        total_chunk_data = 0;
                     }
                     else
                     {  total_chunk_data = gzip_buffer_size;
                     }
                  }
                  else
                  {  /* Fallback to initial size */
                     if(initial_gzip_size > 0 && initial_gzip_size <= gzip_buffer_size)
                     {  gzipbuffer = ALLOCTYPE(UBYTE, initial_gzip_size, 0);
                        if(!gzipbuffer)
                        {  printf("DEBUG: Chunked+gzip: Failed to allocate initial buffer of size %ld\n", initial_gzip_size);
                           total_chunk_data = 0;
                        }
                        else
                        {  total_chunk_data = initial_gzip_size;
                        }
                     }
                     else if(initial_gzip_size > 0)
                     {  long fallback_size;
                        fallback_size = MIN(initial_gzip_size, gzip_buffer_size);
                        gzipbuffer = ALLOCTYPE(UBYTE, fallback_size, 0);
                        if(!gzipbuffer)
                        {  printf("DEBUG: Chunked+gzip: Failed to allocate fallback buffer of size %ld\n", fallback_size);
                           total_chunk_data = 0;
                        }
                        else
                        {  total_chunk_data = fallback_size;
                        }
                     }
                     else
                     {  printf("DEBUG: Chunked+gzip: No valid size for buffer allocation (total=%ld, initial=%ld)\n", 
                               total_chunk_data, initial_gzip_size);
                        total_chunk_data = 0;
                     }
                  }
                  
                  if(gzipbuffer && total_chunk_data > 0)
                  {  printf("DEBUG: Chunked+gzip: Successfully allocated buffer of size %ld\n", total_chunk_data);
                  }
                  
                  if(gzipbuffer)
                  {  /* Extract chunk data starting from where gzip magic was found */
                     /* Start from beginning of block and parse chunks until we reach gzip_start */
                     chunk_pos = 0;
                     gziplength = 0;
                     
                     printf("DEBUG: Chunked+gzip: Starting extraction, gzipbuffer=%p, total_chunk_data=%ld, gzip_start=%ld\n", 
                            gzipbuffer, total_chunk_data, gzip_start);
                     
                     /* First, find the chunk that contains gzip_start */
                     while(chunk_pos < gzip_start && chunk_pos < hi->blocklength)
                     {  /* Skip whitespace before chunk size */
                        while(chunk_pos < hi->blocklength && 
                              (hi->fd->block[chunk_pos] == ' ' || hi->fd->block[chunk_pos] == '\t'))
                        {  chunk_pos++;
                        }
                        
                        /* Parse chunk size */
                        chunk_size = 0;
                        while(chunk_pos < hi->blocklength)
                        {  UBYTE c;
                           long digit;
                           
                           c = hi->fd->block[chunk_pos];
                           if(c >= '0' && c <= '9')
                           {  digit = c - '0';
                           }
                           else if(c >= 'A' && c <= 'F')
                           {  digit = c - 'A' + 10;
                           }
                           else if(c >= 'a' && c <= 'f')
                           {  digit = c - 'a' + 10;
                           }
                           else
                           {  break;
                           }
                           chunk_size = chunk_size * 16 + digit;
                           chunk_pos++;
                        }
                        
                        if(chunk_size == 0)
                        {  /* Last chunk - shouldn't happen before gzip_start */
                           break;
                        }
                        
                        /* Skip chunk extension */
                        while(chunk_pos < hi->blocklength && 
                              hi->fd->block[chunk_pos] != '\r' && hi->fd->block[chunk_pos] != '\n')
                        {  chunk_pos++;
                        }
                        
                        /* Skip CRLF after chunk header */
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                        
                        /* Check if gzip_start is in this chunk's data */
                        if(chunk_pos <= gzip_start && chunk_pos + chunk_size > gzip_start)
                        {  /* Gzip starts in this chunk - copy from gzip_start to end of chunk */
                           long copy_start;
                           long copy_len;
                           long max_copy;
                           long chunk_data_end;
                           long actual_copy;
                           long bytes_in_block;
                           long expected_bytes;
                           
                           copy_start = gzip_start;
                           /* Calculate where this chunk's data ends (before CRLF) */
                           chunk_data_end = chunk_pos + chunk_size;
                           copy_len = chunk_data_end - gzip_start;
                           expected_bytes = chunk_data_end - copy_start;
                           
                           /* Calculate how much we can actually copy (limited by buffer space) */
                           max_copy = total_chunk_data - gziplength;
                           if(copy_len > max_copy)
                           {  copy_len = max_copy;
                           }
                           
                           actual_copy = 0;
                           if(copy_len > 0 && gzipbuffer)
                           {  /* How much of this chunk's data is actually in the current block */
                              bytes_in_block = MIN(chunk_data_end, hi->blocklength) - copy_start;
                              actual_copy = MIN(copy_len, bytes_in_block);
                              
                              if(actual_copy > 0 && gziplength + actual_copy <= total_chunk_data && gzipbuffer)
                              {  memcpy(gzipbuffer + gziplength, hi->fd->block + copy_start, actual_copy);
                                 gziplength += actual_copy;
                                 compressed_bytes_consumed += actual_copy; /* Track compressed data consumed */
                                 printf("DEBUG: Chunked+gzip: Copied %ld bytes from first chunk starting at gzip_start=%ld (chunk_size=%ld, bytes_in_block=%ld, expected=%ld, gziplength now=%ld, max=%ld)\n", 
                                        actual_copy, gzip_start, chunk_size, bytes_in_block, expected_bytes, gziplength, total_chunk_data);
                                 
                                 /* CRITICAL: If chunk extends beyond block, we need to continue it in next block */
                                 /* Don't advance past chunk boundary if chunk wasn't fully copied */
                                 if(bytes_in_block < expected_bytes)
                                 {  /* Chunk continues in next block - leave block position at end of data we copied */
                                    printf("DEBUG: Chunked+gzip: First chunk extends beyond block (%ld of %ld bytes), will continue in next block\n",
                                           bytes_in_block, expected_bytes);
                                    /* Break out - the remaining chunk data will be handled when we read more blocks */
                                    break;
                                 }
                              }
                              else
                              {  printf("DEBUG: Chunked+gzip: WARNING - Failed to copy first chunk: actual_copy=%ld, bytes_in_block=%ld, gziplength=%ld, total=%ld, gzipbuffer=%p\n",
                                        actual_copy, bytes_in_block, gziplength, total_chunk_data, gzipbuffer);
                              }
                           }
                           else
                           {  printf("DEBUG: Chunked+gzip: WARNING - First chunk copy conditions failed: copy_len=%ld, gziplength=%ld, total=%ld, gzipbuffer=%p\n",
                                     copy_len, gziplength, total_chunk_data, gzipbuffer);
                           }
                           
                           /* Move to next chunk only if we copied all data from this chunk */
                           if(actual_copy >= expected_bytes)
                           {  chunk_pos = chunk_data_end;
                              
                              /* Skip CRLF after chunk data */
                              if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                              {  chunk_pos++;
                              }
                              if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                              {  chunk_pos++;
                              }
                              
                              /* Now extract all remaining chunks */
                              break;
                           }
                           else
                           {  /* Chunk continues in next block - stop extraction for now */
                              break;
                           }
                        }
                        else if(chunk_pos + chunk_size <= gzip_start)
                        {  /* This chunk is before gzip_start - skip it */
                           chunk_pos += chunk_size;
                           
                           /* Skip CRLF after chunk data */
                           if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                           {  chunk_pos++;
                           }
                           if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                           {  chunk_pos++;
                           }
                        }
                        else
                        {  /* Should not happen */
                           break;
                        }
                     }
                     
                     /* Now extract all remaining chunks */
                     while(chunk_pos < hi->blocklength && gziplength < total_chunk_data)
                     {  /* Skip whitespace before chunk size */
                        while(chunk_pos < hi->blocklength && 
                              (hi->fd->block[chunk_pos] == ' ' || hi->fd->block[chunk_pos] == '\t'))
                        {  chunk_pos++;
                        }
                        
                        /* Parse chunk size */
                        chunk_size = 0;
                        while(chunk_pos < hi->blocklength)
                        {  UBYTE c;
                           long digit;
                           
                           c = hi->fd->block[chunk_pos];
                           if(c >= '0' && c <= '9')
                           {  digit = c - '0';
                           }
                           else if(c >= 'A' && c <= 'F')
                           {  digit = c - 'A' + 10;
                           }
                           else if(c >= 'a' && c <= 'f')
                           {  digit = c - 'a' + 10;
                           }
                           else
                           {  break;
                           }
                           chunk_size = chunk_size * 16 + digit;
                           chunk_pos++;
                        }
                        
                        if(chunk_size == 0)
                        {  /* Last chunk */
                           break;
                        }
                        
                        /* Skip chunk extension */
                        while(chunk_pos < hi->blocklength && 
                              hi->fd->block[chunk_pos] != '\r' && hi->fd->block[chunk_pos] != '\n')
                        {  chunk_pos++;
                        }
                        
                        /* Skip CRLF after chunk header */
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                        
                        /* Copy chunk data (may be partial if chunk is larger than buffer) */
                        if(chunk_size > 0 && gzipbuffer)
                        {  long max_copy;
                           long actual_copy;
                           
                           /* Calculate how much we can copy (limited by remaining buffer space) */
                           max_copy = total_chunk_data - gziplength;
                           if(max_copy <= 0)
                           {  /* Buffer is full */
                              printf("DEBUG: Chunked+gzip: Buffer full (gziplength=%ld >= total=%ld), stopping extraction\n", 
                                     gziplength, total_chunk_data);
                              break;
                           }
                           
                           if(chunk_size > max_copy)
                           {  /* Chunk is larger than remaining buffer - copy what we can */
                              actual_copy = MIN(max_copy, hi->blocklength - chunk_pos);
                              if(actual_copy > 0)
                              {  memcpy(gzipbuffer + gziplength, hi->fd->block + chunk_pos, actual_copy);
                                 gziplength += actual_copy;
                                 compressed_bytes_consumed += actual_copy; /* Track compressed data consumed */
                                 printf("DEBUG: Chunked+gzip: Copied %ld bytes from chunk (size=%ld, partial copy, total=%ld, pos=%ld)\n", 
                                        actual_copy, chunk_size, gziplength, chunk_pos);
                              }
                              /* Buffer is now full - stop extraction */
                              break;
                           }
                           else
                           {  /* Chunk fits in remaining buffer */
                              actual_copy = MIN(chunk_size, hi->blocklength - chunk_pos);
                              if(actual_copy > 0 && gziplength + actual_copy <= total_chunk_data && gzipbuffer)
                              {  memcpy(gzipbuffer + gziplength, hi->fd->block + chunk_pos, actual_copy);
                                 gziplength += actual_copy;
                                 compressed_bytes_consumed += actual_copy; /* Track compressed data consumed */
                                 printf("DEBUG: Chunked+gzip: Copied %ld bytes from chunk (size=%ld, total=%ld, pos=%ld)\n", 
                                        actual_copy, chunk_size, gziplength, chunk_pos);
                              }
                              else if(actual_copy < chunk_size)
                              {  /* Chunk extends beyond block - copy what we have */
                                 if(actual_copy > 0 && gziplength + actual_copy <= total_chunk_data && gzipbuffer)
                                 {  memcpy(gzipbuffer + gziplength, hi->fd->block + chunk_pos, actual_copy);
                                    gziplength += actual_copy;
                                    compressed_bytes_consumed += actual_copy; /* Track compressed data consumed */
                                    printf("DEBUG: Chunked+gzip: Copied partial chunk %ld bytes (extends beyond block, size=%ld, total=%ld)\n", 
                                           actual_copy, chunk_size, gziplength);
                                 }
                                 /* Chunk extends beyond block - we'll read more later */
                              }
                           }
                           
                           /* Check if we've filled the buffer */
                           if(gziplength >= total_chunk_data)
                           {  printf("DEBUG: Chunked+gzip: Buffer full (gziplength=%ld >= total=%ld), stopping extraction\n", 
                                     gziplength, total_chunk_data);
                              break;
                           }
                        }
                        else if(chunk_size > 0)
                        {  printf("DEBUG: Chunked+gzip: WARNING - Skipping chunk copy: chunk_size=%ld, gziplength=%ld, total=%ld, gzipbuffer=%p\n",
                                  chunk_size, gziplength, total_chunk_data, gzipbuffer);
                        }
                        
                        /* Move past chunk data */
                        chunk_pos += chunk_size;
                        
                        /* Skip CRLF after chunk data */
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                     }
                     
                     printf("DEBUG: Chunked+gzip: Extracted %ld bytes of chunk data (gzip_start=%ld, total_chunk_data=%ld)\n", gziplength, gzip_start, total_chunk_data);
                  }
                  else
                  {  printf("DEBUG: CRITICAL: Failed to allocate gzip buffer for chunked data\n");
                     hi->flags &= ~HTTPIF_GZIPENCODED;
                     hi->flags &= ~HTTPIF_GZIPDECODING;
                     gzip_end = 1;
                     break;
                  }
               }
               else
               {  /* Non-chunked: Only copy the actual gzip data, skip any prefix */
                  gziplength = hi->blocklength - gzip_start;
                  
                  /* CRITICAL: Track total compressed bytes read from network */
                  /* For non-chunked, all data in blocklength after headers is compressed */
                  total_compressed_read = hi->blocklength;
                  
                  /* CRITICAL: For non-chunked gzip, allocate full buffer size since we don't know total size */
                  /* This prevents buffer overflow when appending more data later */
                  if(gziplength > 0 && gziplength <= hi->blocklength) {
                      gzipbuffer = ALLOCTYPE(UBYTE, gzip_buffer_size, 0);
                      if(gzipbuffer) {
                          memcpy(gzipbuffer, hi->fd->block + gzip_start, gziplength);
                          compressed_bytes_consumed += gziplength; /* Track compressed data consumed */
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
               }
            }
            else if(gzip_start < 0)
            {  /* No gzip magic found at all - check if data might be gzip anyway */
               /* For non-chunked, check if it starts with gzip magic */
               if(hi->blocklength >= 3 && hi->fd->block[0] == 0x1F && hi->fd->block[1] == 0x8B && hi->fd->block[2] == 0x08)
               {  /* Gzip magic at start - treat as gzip_start=0 */
                  gzip_start = 0;
                  printf("DEBUG: Found gzip magic at start of block\n");
                  gziplength = hi->blocklength;
                  
                  /* CRITICAL: Track total compressed bytes read from network */
                  total_compressed_read = hi->blocklength;
                  
                  /* CRITICAL: For non-chunked gzip, allocate full buffer size since we don't know total size */
                  /* This prevents buffer overflow when appending more data later */
                  if(gziplength > 0 && gziplength <= gzip_buffer_size) {
                      gzipbuffer = ALLOCTYPE(UBYTE, gzip_buffer_size, 0);
                      if(gzipbuffer) {
                          memcpy(gzipbuffer, hi->fd->block, gziplength);
                          compressed_bytes_consumed += gziplength; /* Track compressed data consumed */
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
               }
               else
               {  /* No gzip magic found anywhere */
                  printf("DEBUG: No gzip magic found in block, disabling gzip\n");
                  hi->flags &= ~HTTPIF_GZIPENCODED;
                  hi->flags &= ~HTTPIF_GZIPDECODING;
                  continue;
               }
            }
            
            /* CRITICAL: Verify we have valid gzip magic before starting */
            if(!gzipbuffer || gziplength < 3 || gzipbuffer[0] != 0x1F || gzipbuffer[1] != 0x8B || gzipbuffer[2] != 0x08)
            {  printf("DEBUG: CRITICAL: No valid gzip magic found (first 3 bytes: %02X %02X %02X), disabling gzip\n",
                      gzipbuffer && gziplength >= 1 ? gzipbuffer[0] : 0,
                      gzipbuffer && gziplength >= 2 ? gzipbuffer[1] : 0,
                      gzipbuffer && gziplength >= 3 ? gzipbuffer[2] : 0);
               if(gzipbuffer) FREE(gzipbuffer);
               gzipbuffer = NULL;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               continue;
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
               if(gzipbuffer) FREE(gzipbuffer);
               gzipbuffer = NULL;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               break;
            }
            
            err=inflateInit2(&d_stream,16+15); // set zlib to expect 'gzip-header'
            if(err!=Z_OK) {
               printf("zlib Init Fail: %d\n", err);
               if(gzipbuffer) FREE(gzipbuffer);
               gzipbuffer = NULL;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end = 1;
               d_stream_initialized = FALSE;
               break;
            } else {
               printf("DEBUG: zlib init successful\n");
               d_stream_initialized = TRUE; /* Mark d_stream as initialized */
            }
            
            /* CRITICAL: Validate gzip buffer allocation to prevent heap corruption */
            if(gzipbuffer && gziplength > 0) {
               /* Check if gzipbuffer pointer is valid */
               if((ULONG)gzipbuffer < 0x1000 || (ULONG)gzipbuffer > 0xFFFFFFF0) {
                  printf("DEBUG: CRITICAL: Invalid gzipbuffer pointer 0x%08lX\n", (ULONG)gzipbuffer);
                  FREE(gzipbuffer);
                  gzipbuffer = NULL;
                  inflateEnd(&d_stream);
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
                  inflateEnd(&d_stream);
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
                   printf("DEBUG: Valid gzip header confirmed, gziplength=%ld, avail_in=%lu\n", 
                          gziplength, d_stream.avail_in);
               } else {
                   printf("DEBUG: WARNING: Data still doesn't start with gzip magic! Disabling gzip.\n");
                   FREE(gzipbuffer);
                   gzipbuffer = NULL;
                   inflateEnd(&d_stream);
                   hi->flags &= ~HTTPIF_GZIPENCODED;
                   hi->flags &= ~HTTPIF_GZIPDECODING;
                   gzip_end = 1;
                   break;
               }
            } else {
                printf("DEBUG: No gzip data to process\n");
                hi->flags &= ~HTTPIF_GZIPENCODED;
                hi->flags &= ~HTTPIF_GZIPDECODING;
                continue;
            }
            
            /* CRITICAL: After copying data to gzipbuffer, clear block to prevent reprocessing */
            /* For chunked encoding, we've already extracted and copied the gzip data */
            /* For non-chunked, we've copied all data to gzipbuffer */
            /* Either way, we don't want to process this block again as regular data */
            hi->blocklength = 0;
            
            /* CRITICAL: Set the decoding flag so we can process gzip */
            hi->flags |= HTTPIF_GZIPDECODING;
            printf("DEBUG: Set HTTPIF_GZIPDECODING flag (0x%04X), gzipbuffer=%p, gziplength=%ld, avail_in=%lu, d_stream_initialized=%d\n", 
                   hi->flags, gzipbuffer, gziplength, d_stream.avail_in, d_stream_initialized);
            
            /* Now process the gzip data immediately */
         }

         /* CRITICAL: Process gzip data if flag is set */
         if(hi->flags & HTTPIF_GZIPDECODING && gzipbuffer != NULL && d_stream_initialized)
         {  /* Process gzip data immediately */
            printf("DEBUG: Processing gzip data inside main loop, avail_in=%lu\n", d_stream.avail_in);
            
            /* CRITICAL: Process ALL gzip data in this loop to avoid duplicate processing */
            /* Process gzip completely in the main loop - this prevents the second loop from running */
            while(!gzip_end && hi->flags & HTTPIF_GZIPDECODING && gzipbuffer != NULL && d_stream_initialized)
            {  long decompressed_len;
               
               /* Only call inflate if we have input */
               if(d_stream.avail_in > 0)
               {  err=inflate(&d_stream,Z_SYNC_FLUSH);
               }
               else
               {  /* No input - need to read more data */
                  err=Z_OK; /* Signal that we need more input */
               }
               
               if(err==Z_BUF_ERROR || err==Z_OK)
               {  /* Output buffer full or OK - process decompressed data */
                  decompressed_len=hi->fd->blocksize-d_stream.avail_out;
                  if(decompressed_len > 0 && decompressed_len <= hi->fd->blocksize)
                  {  printf("DEBUG: Processing %ld bytes of decompressed data\n", decompressed_len);
                     if(hi->parttype[0] && strlen(hi->parttype) > 0) {
                        Updatetaskattrs(
                           AOURL_Data,hi->fd->block,
                           AOURL_Datalength,decompressed_len,
                           AOURL_Contenttype,hi->parttype,
                           TAG_END);
                     } else {
                        Updatetaskattrs(
                           AOURL_Data,hi->fd->block,
                           AOURL_Datalength,decompressed_len,
                           TAG_END);
                     }
                     d_stream.next_out=hi->fd->block;
                     d_stream.avail_out=hi->fd->blocksize;
                  }
                  if(err==Z_OK && d_stream.avail_in==0)
                  {  /* Need more input - read next block */
                     if(!Readblock(hi))
                     {  printf("DEBUG: No more data for gzip, ending\n");
                        gzip_end=1;
                        break;
                     }
                     /* Update total compressed bytes read from network */
                     total_compressed_read += hi->blocklength;
                     
                     /* CRITICAL: Continue loop to process the newly read data */
                     /* For non-chunked, append new block data to gzipbuffer */
                     /* For chunked, we need to extract chunk data and add to gzipbuffer */
                     if(!(hi->flags & HTTPIF_CHUNKED))
                     {  /* Non-chunked: Append all new block data to gzipbuffer */
                        long remaining_space;
                        long bytes_to_append;
                        long used_space;
                        
                        /* Calculate space used in buffer (from start to next_in + remaining) */
                        used_space = (d_stream.next_in - gzipbuffer) + d_stream.avail_in;
                        remaining_space = gzip_buffer_size - used_space;
                        
                        if(remaining_space <= 0 || hi->blocklength > remaining_space)
                        {  printf("DEBUG: Non-chunked gzip: Buffer full or block too large (remaining=%ld, block=%ld), cannot continue\n",
                                  remaining_space, hi->blocklength);
                           gzip_end = 1;
                           break;
                        }
                        
                        bytes_to_append = MIN(hi->blocklength, remaining_space);
                        if(bytes_to_append > 0 && gziplength + bytes_to_append <= gzip_buffer_size)
                        {  /* Move unprocessed data to start if needed */
                           if(d_stream.next_in != gzipbuffer && d_stream.avail_in > 0)
                           {  memmove(gzipbuffer, d_stream.next_in, d_stream.avail_in);
                              gziplength = d_stream.avail_in;
                           }
                           else if(d_stream.avail_in == 0)
                           {  gziplength = 0;
                           }
                           
                           /* Append new data */
                           memcpy(gzipbuffer + gziplength, hi->fd->block, bytes_to_append);
                           gziplength += bytes_to_append;
                           compressed_bytes_consumed += bytes_to_append;
                           
                           /* Update zlib stream */
                           d_stream.next_in = gzipbuffer;
                           d_stream.avail_in = gziplength;
                           
                           printf("DEBUG: Non-chunked gzip: Added %ld bytes from new block (total in buffer=%ld)\n",
                                  bytes_to_append, gziplength);
                           
                           /* Clear block for next read */
                           hi->blocklength = 0;
                           
                           /* CRITICAL: Continue loop to process the newly added data */
                           continue;
                        }
                     }
                     else if(hi->flags & HTTPIF_CHUNKED)
                     {  /* Extract chunk data from new block and append to gzipbuffer */
                        UBYTE *chunk_p;
                        long chunk_pos;
                        long chunk_size;
                        long new_data_start;
                        long remaining_space;
                        long available_space;
                        long remaining_unprocessed;
                        long used_space;
                        long bytes_to_move;
                        UBYTE first_char;
                        BOOL is_continuation;
                        
                        chunk_p = hi->fd->block;
                        chunk_pos = 0;
                        new_data_start = 0;
                        
                        /* CRITICAL: Check if this block is continuing a chunk from previous block */
                        /* If block doesn't start with hex digits (chunk header), it's continuation of previous chunk */
                        is_continuation = FALSE;
                        if(hi->blocklength > 0)
                        {  first_char = hi->fd->block[0];
                           /* Chunk headers start with hex digits (0-9, A-F, a-f) */
                           /* If first char is not hex digit, this is continuation of previous chunk data */
                           if(!((first_char >= '0' && first_char <= '9') ||
                                (first_char >= 'A' && first_char <= 'F') ||
                                (first_char >= 'a' && first_char <= 'f')))
                           {  is_continuation = TRUE;
                              printf("DEBUG: Chunked+gzip: Block starts with non-hex char (0x%02X), treating as continuation of previous chunk\n", first_char);
                           }
                        }
                        
                        if(is_continuation)
                        {  /* This block continues the previous chunk - copy directly to gzipbuffer */
                           /* Calculate available space and copy what we can */
                           remaining_unprocessed = d_stream.avail_in;
                           
                           /* CRITICAL: Validate remaining_unprocessed is reasonable */
                           if(remaining_unprocessed < 0 || remaining_unprocessed > gzip_buffer_size)
                           {  printf("DEBUG: CRITICAL: Invalid remaining_unprocessed (%ld) in continuation, resetting to 0\n", remaining_unprocessed);
                              remaining_unprocessed = 0;
                           }
                           
                           if(remaining_unprocessed > 0)
                           {  /* CRITICAL: Validate next_in pointer before pointer arithmetic */
                              if(gzipbuffer && d_stream.next_in >= gzipbuffer && 
                                 d_stream.next_in < gzipbuffer + gzip_buffer_size)
                              {  used_space = (d_stream.next_in - gzipbuffer) + remaining_unprocessed;
                                 /* CRITICAL: Validate used_space is reasonable */
                                 if(used_space < 0 || used_space > gzip_buffer_size)
                                 {  printf("DEBUG: CRITICAL: Invalid used_space (%ld) in continuation, resetting\n", used_space);
                                    used_space = remaining_unprocessed; /* Fallback */
                                    if(used_space > gzip_buffer_size) used_space = gzip_buffer_size;
                                 }
                              }
                              else
                              {  printf("DEBUG: CRITICAL: Invalid d_stream.next_in pointer (%p) in continuation, resetting\n", d_stream.next_in);
                                 used_space = remaining_unprocessed; /* Fallback */
                                 if(used_space > gzip_buffer_size) used_space = gzip_buffer_size;
                              }
                           }
                           else
                           {  used_space = 0;
                           }
                           
                           remaining_space = gzip_buffer_size - used_space;
                           if(remaining_space <= 0)
                           {  printf("DEBUG: Chunked+gzip: Buffer full, cannot add continuation data\n");
                              gzip_end = 1;
                              break;
                           }
                           
                           /* Move unprocessed data to start if needed */
                           if(remaining_unprocessed > 0 && d_stream.next_in != gzipbuffer)
                           {  bytes_to_move = remaining_unprocessed;
                              /* CRITICAL: Validate all pointers and sizes before memmove */
                              if(bytes_to_move > gzip_buffer_size)
                              {  printf("DEBUG: CRITICAL: bytes_to_move (%ld) exceeds buffer size (%ld) in continuation, resetting\n",
                                        bytes_to_move, gzip_buffer_size);
                                 gziplength = 0;
                                 remaining_unprocessed = 0;
                              }
                              else if(bytes_to_move > 0 && gzipbuffer && d_stream.next_in >= gzipbuffer && 
                                      d_stream.next_in < gzipbuffer + gzip_buffer_size &&
                                      (d_stream.next_in + bytes_to_move) <= gzipbuffer + gzip_buffer_size &&
                                      bytes_to_move <= remaining_unprocessed)
                              {  memmove(gzipbuffer, d_stream.next_in, bytes_to_move);
                                 gziplength = bytes_to_move;
                              }
                              else
                              {  printf("DEBUG: CRITICAL: Invalid pointer state for memmove in continuation (next_in=%p, gzipbuffer=%p, bytes=%ld, buffer_size=%ld), resetting\n",
                                        d_stream.next_in, gzipbuffer, bytes_to_move, gzip_buffer_size);
                                 gziplength = 0;
                                 remaining_unprocessed = 0;
                              }
                           }
                           else if(remaining_unprocessed == 0)
                           {  gziplength = 0;
                           }
                           
                           /* Copy continuation data to buffer */
                           available_space = MIN(hi->blocklength, remaining_space);
                           if(gziplength + available_space <= gzip_buffer_size)
                           {  /* CRITICAL: Validate pointers before memcpy */
                              if(gzipbuffer && hi->fd && hi->fd->block &&
                                 gziplength >= 0 && gziplength < gzip_buffer_size &&
                                 available_space > 0 && available_space <= (gzip_buffer_size - gziplength) &&
                                 hi->blocklength > 0 && available_space <= hi->blocklength)
                              {  memcpy(gzipbuffer + gziplength, hi->fd->block, available_space);
                                 gziplength += available_space;
                                 compressed_bytes_consumed += available_space; /* Track compressed data consumed */
                              }
                              else
                              {  printf("DEBUG: CRITICAL: Invalid pointers for memcpy in continuation (gzipbuffer=%p, block=%p, gziplength=%ld, available_space=%ld, blocklength=%ld), aborting\n",
                                        gzipbuffer, hi->fd ? hi->fd->block : NULL, gziplength, available_space, hi->blocklength);
                                 gzip_end = 1;
                                 break;
                              }
                              
                              d_stream.next_in = gzipbuffer;
                              d_stream.avail_in = gziplength;
                              
                              printf("DEBUG: Chunked+gzip: Added %ld bytes of chunk continuation (total=%ld, avail_in=%lu)\n",
                                     available_space, gziplength, d_stream.avail_in);
                              
                              /* Clear block - we've used all continuation data */
                              hi->blocklength = 0;
                              
                              /* Continue decompression */
                              continue;
                           }
                           else
                           {  printf("DEBUG: Chunked+gzip: Not enough space for continuation (%ld bytes)\n", hi->blocklength);
                              gzip_end = 1;
                              break;
                           }
                        }
                        
                        /* Find start of next chunk data (new chunk header) */
                        while(chunk_pos < hi->blocklength)
                        {  /* Skip whitespace */
                           while(chunk_pos < hi->blocklength && 
                                 (hi->fd->block[chunk_pos] == ' ' || hi->fd->block[chunk_pos] == '\t'))
                           {  chunk_pos++;
                           }
                           
                           /* Parse chunk size */
                           chunk_size = 0;
                           while(chunk_pos < hi->blocklength)
                           {  UBYTE c;
                              long digit;
                              
                              c = hi->fd->block[chunk_pos];
                              if(c >= '0' && c <= '9')
                              {  digit = c - '0';
                              }
                              else if(c >= 'A' && c <= 'F')
                              {  digit = c - 'A' + 10;
                              }
                              else if(c >= 'a' && c <= 'f')
                              {  digit = c - 'a' + 10;
                              }
                              else
                              {  break;
                              }
                              chunk_size = chunk_size * 16 + digit;
                              chunk_pos++;
                           }
                           
                           if(chunk_size == 0)
                           {  /* Last chunk */
                              gzip_end = 1;
                              break;
                           }
                           
                           /* Skip chunk extension */
                           while(chunk_pos < hi->blocklength && 
                                 hi->fd->block[chunk_pos] != '\r' && hi->fd->block[chunk_pos] != '\n')
                           {  chunk_pos++;
                           }
                           
                           /* Skip CRLF after chunk header */
                           if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                           {  chunk_pos++;
                           }
                           if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                           {  chunk_pos++;
                           }
                           
                           /* CRITICAL: Calculate remaining unprocessed data and available space */
                           /* If avail_in > 0, we have unprocessed data starting at next_in */
                           /* If avail_in == 0, we've consumed all data and can reuse buffer */
                           
                           remaining_unprocessed = d_stream.avail_in;
                           
                           /* CRITICAL: Validate remaining_unprocessed is reasonable */
                           if(remaining_unprocessed < 0 || remaining_unprocessed > gzip_buffer_size)
                           {  printf("DEBUG: CRITICAL: Invalid remaining_unprocessed (%ld) in chunk extraction, resetting to 0\n", remaining_unprocessed);
                              remaining_unprocessed = 0;
                           }
                           
                           if(remaining_unprocessed > 0)
                           {  /* We have unprocessed data - calculate how much buffer is used */
                              /* CRITICAL: Validate next_in pointer before pointer arithmetic */
                              if(gzipbuffer && d_stream.next_in >= gzipbuffer && 
                                 d_stream.next_in < gzipbuffer + gzip_buffer_size)
                              {  /* Used space = data from start to next_in + remaining unprocessed */
                                 used_space = (d_stream.next_in - gzipbuffer) + remaining_unprocessed;
                                 /* CRITICAL: Validate used_space is reasonable */
                                 if(used_space < 0 || used_space > gzip_buffer_size)
                                 {  printf("DEBUG: CRITICAL: Invalid used_space (%ld) calculated from next_in=%p, gzipbuffer=%p, remaining=%ld\n",
                                           used_space, d_stream.next_in, gzipbuffer, remaining_unprocessed);
                                    used_space = remaining_unprocessed; /* Fallback to just remaining */
                                    if(used_space > gzip_buffer_size) used_space = gzip_buffer_size;
                                 }
                              }
                              else
                              {  printf("DEBUG: CRITICAL: Invalid d_stream.next_in pointer (%p) for gzipbuffer (%p), resetting\n",
                                        d_stream.next_in, gzipbuffer);
                                 used_space = remaining_unprocessed; /* Fallback */
                                 if(used_space > gzip_buffer_size) used_space = gzip_buffer_size;
                              }
                           }
                           else
                           {  /* All data consumed - buffer can be reused from start */
                              used_space = 0;
                           }
                           
                           remaining_space = gzip_buffer_size - used_space;
                           if(remaining_space <= 0)
                           {  printf("DEBUG: Chunked+gzip: Gzip buffer full (used=%ld, remaining=%ld), cannot add more chunks\n",
                                     used_space, remaining_space);
                              gzip_end = 1;
                              break;
                           }
                           
                           /* Determine how much chunk data we can copy */
                           available_space = MIN(chunk_size, remaining_space);
                           if(chunk_pos + available_space <= hi->blocklength)
                           {  /* We have the full chunk or space for it */
                              /* If we have unprocessed data, move it to start of buffer first */
                              if(remaining_unprocessed > 0 && d_stream.next_in != gzipbuffer)
                              {  bytes_to_move = remaining_unprocessed;
                                 /* CRITICAL: Validate all pointers and sizes before memmove */
                                 if(bytes_to_move > gzip_buffer_size)
                                 {  printf("DEBUG: CRITICAL: bytes_to_move (%ld) exceeds buffer size (%ld), resetting\n",
                                           bytes_to_move, gzip_buffer_size);
                                    gziplength = 0;
                                    remaining_unprocessed = 0;
                                 }
                                 else if(bytes_to_move > 0 && gzipbuffer && d_stream.next_in >= gzipbuffer && 
                                         d_stream.next_in < gzipbuffer + gzip_buffer_size &&
                                         (d_stream.next_in + bytes_to_move) <= gzipbuffer + gzip_buffer_size &&
                                         bytes_to_move <= remaining_unprocessed)
                                 {  memmove(gzipbuffer, d_stream.next_in, bytes_to_move);
                                    gziplength = bytes_to_move;
                                    printf("DEBUG: Chunked+gzip: Moved %ld bytes of unprocessed data to start\n", bytes_to_move);
                                 }
                                 else
                                 {  /* Invalid state - reset */
                                    printf("DEBUG: Chunked+gzip: CRITICAL - Invalid buffer state (next_in=%p, gzipbuffer=%p, bytes=%ld, buffer_size=%ld), resetting\n",
                                           d_stream.next_in, gzipbuffer, bytes_to_move, gzip_buffer_size);
                                    gziplength = 0;
                                    remaining_unprocessed = 0;
                                 }
                              }
                              else
                              {  /* No unprocessed data or already at start - start fresh */
                                 if(remaining_unprocessed == 0)
                                 {  gziplength = 0;
                                 }
                                 /* else gziplength already set correctly */
                              }
                              
                              /* Append new chunk data to buffer */
                              if(gziplength + available_space <= gzip_buffer_size)
                              {  /* CRITICAL: Validate pointers before memcpy */
                                 if(gzipbuffer && hi->fd && hi->fd->block &&
                                    gziplength >= 0 && gziplength < gzip_buffer_size &&
                                    available_space > 0 && available_space <= (gzip_buffer_size - gziplength) &&
                                    chunk_pos >= 0 && chunk_pos < hi->blocklength &&
                                    (chunk_pos + available_space) <= hi->blocklength)
                                 {  memcpy(gzipbuffer + gziplength, hi->fd->block + chunk_pos, available_space);
                                    gziplength += available_space;
                                    compressed_bytes_consumed += available_space; /* Track compressed data consumed */
                                 }
                                 else
                                 {  printf("DEBUG: CRITICAL: Invalid pointers for memcpy in chunk extraction (gzipbuffer=%p, block=%p, gziplength=%ld, available_space=%ld, chunk_pos=%ld, blocklength=%ld), aborting\n",
                                           gzipbuffer, hi->fd ? hi->fd->block : NULL, gziplength, available_space, chunk_pos, hi->blocklength);
                                    gzip_end = 1;
                                    break;
                                 }
                                 
                                 /* Update zlib stream to point to start of all unprocessed data */
                                 d_stream.next_in = gzipbuffer;
                                 d_stream.avail_in = gziplength;
                                 
                                 printf("DEBUG: Chunked+gzip: Added %ld bytes from chunk (unprocessed was=%ld, total=%ld, avail_in=%lu)\n", 
                                        available_space, remaining_unprocessed, gziplength, d_stream.avail_in);
                                 
                                 /* Move past chunk data and CRLF */
                                 chunk_pos += chunk_size;
                                 if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\r')
                                 {  chunk_pos++;
                                 }
                                 if(chunk_pos < hi->blocklength && hi->fd->block[chunk_pos] == '\n')
                                 {  chunk_pos++;
                                 }
                                 
                                 /* Remove processed chunk from block */
                                 if(chunk_pos < hi->blocklength)
                                 {  long remaining;
                                    remaining = hi->blocklength - chunk_pos;
                                    memmove(hi->fd->block, hi->fd->block + chunk_pos, remaining);
                                    hi->blocklength = remaining;
                                 }
                                 else
                                 {  hi->blocklength = 0;
                                 }
                                 
                                 /* Continue decompression */
                                 continue;
                              }
                              else
                              {  printf("DEBUG: Chunked+gzip: Not enough space in buffer (gziplength=%ld, available_space=%ld, buffer_size=%ld)\n",
                                       gziplength, available_space, gzip_buffer_size);
                                 gzip_end = 1;
                                 break;
                              }
                           }
                           else
                           {  /* Need more data for this chunk */
                              printf("DEBUG: Chunked+gzip: Chunk extends beyond block, need more data\n");
                              /* Keep the block and wait for more data */
                              break;
                           }
                        }
                     }
                     else
                     {  /* Non-chunked - all data already in gzipbuffer */
                        gzip_end=1;
                        break;
                     }
                  }
               }
               else if(err==Z_STREAM_END)
               {  /* Stream complete */
                  decompressed_len=hi->fd->blocksize-d_stream.avail_out;
                  if(decompressed_len > 0 && decompressed_len <= hi->fd->blocksize)
                  {  printf("DEBUG: Processing final %ld bytes of decompressed data\n", decompressed_len);
                     if(hi->parttype[0] && strlen(hi->parttype) > 0) {
                        Updatetaskattrs(
                           AOURL_Data,hi->fd->block,
                           AOURL_Datalength,decompressed_len,
                           AOURL_Contenttype,hi->parttype,
                           TAG_END);
                     } else {
                        Updatetaskattrs(
                           AOURL_Data,hi->fd->block,
                           AOURL_Datalength,decompressed_len,
                           TAG_END);
                     }
                  }
                  
                  /* CRITICAL: For chunked encoding, zlib may finish before all chunks are processed */
                  /* If there's still data in blocklength, it might be more chunks or chunk continuation */
                  /* We need to continue processing chunks until we get the final "0\r\n\r\n" chunk */
                  if(hi->flags & HTTPIF_CHUNKED && hi->blocklength > 0)
                  {  printf("DEBUG: Z_STREAM_END but %ld bytes remain in block for chunked encoding, continuing chunk processing\n", hi->blocklength);
                     /* Don't exit yet - continue processing chunks */
                     /* The remaining data will be processed in the next iteration */
                  }
                  else
                  {  /* Non-chunked or no remaining data - gzip is complete */
                     gzip_end=1;
                     break;
                  }
               }
               else
               {  printf("DEBUG: Gzip error: %d, ending\n", err);
                  gzip_end=1;
                  break;
               }
            }
            
            /* Clean up gzip after processing */
            if(gzip_end)
            {  inflateEnd(&d_stream);
               if(gzipbuffer) FREE(gzipbuffer);
               gzipbuffer = NULL;
               d_stream_initialized = FALSE;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               hi->flags &= ~HTTPIF_GZIPENCODED;
               printf("DEBUG: Gzip processing complete\n");
               
               /* CRITICAL: For chunked+gzip, we need to continue processing remaining chunks */
               /* even after gzip finishes, until we reach the final "0\r\n\r\n" chunk */
               if(hi->flags & HTTPIF_CHUNKED)
               {  printf("DEBUG: Chunked+gzip: Gzip complete, discarding remaining chunks until final chunk\n");
                  /* Process remaining data in blocklength, then continue reading chunks */
                  /* until we find the final "0\r\n\r\n" chunk */
                  /* Note: remaining data might be chunk continuation (not starting with hex digits) */
                  while(hi->blocklength > 0 || Readblock(hi))
                  {  UBYTE *chunk_p;
                     long chunk_pos;
                     long chunk_size;
                     long chunk_data_end;
                     BOOL final_chunk_found;
                     UBYTE first_char;
                     BOOL is_chunk_header;
                     
                     if(hi->blocklength <= 0) break;
                     
                     chunk_p = hi->fd->block;
                     chunk_pos = 0;
                     final_chunk_found = FALSE;
                     
                     /* Parse chunks in current block until we find final chunk or run out of data */
                     while(chunk_pos < hi->blocklength)
                     {  /* Check if this looks like a chunk header (starts with hex digit) */
                        /* or continuation data (starts with non-hex) */
                        first_char = chunk_p[chunk_pos];
                        is_chunk_header = FALSE;
                        if((first_char >= '0' && first_char <= '9') ||
                           (first_char >= 'A' && first_char <= 'F') ||
                           (first_char >= 'a' && first_char <= 'f'))
                        {  is_chunk_header = TRUE;
                        }
                        
                        if(!is_chunk_header)
                        {  /* This is continuation data from a previous chunk - skip until we find CRLF */
                           /* which indicates end of chunk data, then we'll see next chunk header */
                           printf("DEBUG: Chunked+gzip: Found continuation data (starts with 0x%02X), skipping to next chunk boundary\n", first_char);
                           /* Skip until we find CRLF (end of chunk data) */
                           while(chunk_pos < hi->blocklength - 1)
                           {  if(chunk_p[chunk_pos] == '\r' && chunk_p[chunk_pos + 1] == '\n')
                              {  chunk_pos += 2; /* Skip CRLF */
                                 break; /* Now we should see next chunk header */
                              }
                              chunk_pos++;
                           }
                           if(chunk_pos >= hi->blocklength - 1)
                           {  /* CRLF not found in this block - need more data */
                              /* Move remaining data to start */
                              if(chunk_pos < hi->blocklength)
                              {  long remaining;
                                 remaining = hi->blocklength - chunk_pos;
                                 memmove(hi->fd->block, chunk_p + chunk_pos, remaining);
                                 hi->blocklength = remaining;
                              }
                              break; /* Exit inner loop to read more */
                           }
                           /* Continue to parse next chunk header */
                           continue;
                        }
                        
                        /* Skip whitespace */
                        while(chunk_pos < hi->blocklength && 
                              (chunk_p[chunk_pos] == ' ' || chunk_p[chunk_pos] == '\t'))
                        {  chunk_pos++;
                        }
                        
                        if(chunk_pos >= hi->blocklength) break;
                        
                        /* Parse chunk size */
                        chunk_size = 0;
                        while(chunk_pos < hi->blocklength)
                        {  UBYTE c;
                           long digit;
                           c = chunk_p[chunk_pos];
                           if(c >= '0' && c <= '9')
                           {  digit = c - '0';
                           }
                           else if(c >= 'A' && c <= 'F')
                           {  digit = c - 'A' + 10;
                           }
                           else if(c >= 'a' && c <= 'f')
                           {  digit = c - 'a' + 10;
                           }
                           else
                           {  break;
                           }
                           chunk_size = chunk_size * 16 + digit;
                           chunk_pos++;
                        }
                        
                        /* Skip chunk extension and CRLF */
                        while(chunk_pos < hi->blocklength && 
                              chunk_p[chunk_pos] != '\r' && chunk_p[chunk_pos] != '\n')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                        
                        if(chunk_size == 0)
                        {  /* Final chunk found */
                           printf("DEBUG: Chunked+gzip: Final chunk (0) found, all chunks processed\n");
                           final_chunk_found = TRUE;
                           /* Skip final CRLF if present */
                           if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\r')
                           {  chunk_pos++;
                           }
                           if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\n')
                           {  chunk_pos++;
                           }
                           break;
                        }
                        
                        /* Skip chunk data and trailing CRLF */
                        chunk_data_end = chunk_pos + chunk_size;
                        if(chunk_data_end > hi->blocklength)
                        {  /* Chunk extends beyond current block - need more data */
                           printf("DEBUG: Chunked+gzip: Chunk size %ld extends beyond block, need more data\n", chunk_size);
                           /* Move remaining data to start of block */
                           if(chunk_pos < hi->blocklength)
                           {  long remaining;
                              remaining = hi->blocklength - chunk_pos;
                              memmove(hi->fd->block, chunk_p + chunk_pos, remaining);
                              hi->blocklength = remaining;
                           }
                           break; /* Exit inner loop to read more */
                        }
                        
                        chunk_pos = chunk_data_end;
                        /* Skip trailing CRLF after chunk data */
                        if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\r')
                        {  chunk_pos++;
                        }
                        if(chunk_pos < hi->blocklength && chunk_p[chunk_pos] == '\n')
                        {  chunk_pos++;
                        }
                        
                        printf("DEBUG: Chunked+gzip: Discarded chunk of size %ld\n", chunk_size);
                     }
                     
                     if(final_chunk_found)
                     {  /* Final chunk found - we're done */
                        hi->blocklength = 0;
                        break;
                     }
                     
                     /* Move any remaining data to start of block for next iteration */
                     if(chunk_pos < hi->blocklength)
                     {  long remaining;
                        remaining = hi->blocklength - chunk_pos;
                        memmove(hi->fd->block, chunk_p + chunk_pos, remaining);
                        hi->blocklength = remaining;
                     }
                     else
                     {  hi->blocklength = 0;
                     }
                  }
                  
                  printf("DEBUG: Chunked+gzip: Finished discarding remaining chunks\n");
                  result = !eof;
                  break;
               }
               
               /* CRITICAL: For non-chunked gzip streams, all data has been decompressed */
               /* Account for any remaining compressed data in current block */
               if(hi->blocklength > 0)
               {  total_compressed_read += hi->blocklength;
                  printf("DEBUG: Accounting for %ld bytes remaining in block after gzip completion\n", hi->blocklength);
               }
               
               /* Clear blocklength to prevent processing remaining compressed data as uncompressed */
               hi->blocklength = 0;
               
               /* CRITICAL: For non-chunked responses with Content-Length, we need to read */
               /* exactly that much compressed data from network before exiting */
               if(hi->partlength > 0)
               {  /* We have a Content-Length - need to read that much compressed data total from network */
                  printf("DEBUG: Gzip decompression complete, read %ld/%ld compressed bytes from network so far\n", 
                         total_compressed_read, hi->partlength);
                  while(total_compressed_read < hi->partlength && Readblock(hi))
                  {  long compressed_in_block;
                     compressed_in_block = hi->blocklength;
                     total_compressed_read += compressed_in_block;
                     hi->blocklength = 0; /* Discard consumed compressed data */
                     printf("DEBUG: Read %ld bytes of compressed data from network, total=%ld/%ld\n", 
                            compressed_in_block, total_compressed_read, hi->partlength);
                  }
                  printf("DEBUG: Finished reading compressed data from network: %ld/%ld bytes\n", 
                         total_compressed_read, hi->partlength);
               }
               else
               {  /* No Content-Length - read until EOF to consume remaining compressed data */
                  printf("DEBUG: No Content-Length, reading until EOF to consume remaining compressed data\n");
                  while(Readblock(hi))
                  {  /* Discard remaining compressed data - it's already been decompressed */
                     total_compressed_read += hi->blocklength;
                     hi->blocklength = 0;
                  }
               }
               
               /* Exit Readdata - gzip response is complete */
               result = !eof;
               break;
            }
            continue; /* Skip regular data processing */
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
            printf("DEBUG: Validating data before Updatetaskattrs: block=%p, length=%ld, parttype='%s' (strlen=%ld)\n", 
                   hi->fd->block, blocklength, 
                   hi->parttype[0] ? (char *)hi->parttype : "(none)",
                   hi->parttype[0] ? strlen(hi->parttype) : 0);
            /* CRITICAL: Include content type if available to prevent defaulting to octet-stream */
            /* Check if parttype is valid by checking first character and length */
            if(hi->parttype[0] != '\0' && hi->parttype[0] != 0 && strlen(hi->parttype) > 0) {
               printf("DEBUG: Sending data with content type: '%s' (length=%ld)\n", hi->parttype, strlen(hi->parttype));
               Updatetaskattrs(
                  AOURL_Data,hi->fd->block,
                  AOURL_Datalength,blocklength,
                  AOURL_Contenttype,hi->parttype,
                  TAG_END);
            } else {
               printf("DEBUG: WARNING: parttype is empty or invalid! Sending data without content type (will default to octet-stream)\n");
               printf("DEBUG: parttype[0]=0x%02X, parttype='%.31s'\n", (unsigned char)hi->parttype[0], hi->parttype);
               Updatetaskattrs(
                  AOURL_Data,hi->fd->block,
                  AOURL_Datalength,blocklength,
                  TAG_END);
            }
         } else {
            printf("DEBUG: CRITICAL: Invalid data detected, skipping Updatetaskattrs to prevent memory corruption\n");
            printf("DEBUG: fd=%p, block=%p, blocklength=%ld, blocksize=%ld\n", 
                   hi->fd, hi->fd ? hi->fd->block : NULL, blocklength, hi->fd ? hi->fd->blocksize : 0);
         }
         
         /* CRITICAL: Safe memory move with bounds checking */
         if(blocklength < hi->blocklength && blocklength > 0) {
            move_length = hi->blocklength - blocklength;
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
         
         /* CRITICAL: Handle blocklength differently for gzip vs non-gzip data */
         /* CRITICAL: This code should NEVER run if gzip decoding is active because we break out earlier */
         if(hi->flags & HTTPIF_GZIPDECODING)
         {  /* This should not happen - we should have broken out earlier */
            printf("DEBUG: ERROR: Regular data processing with gzip flag set! This is a bug.\n");
            /* The gzip loop handles blocklength separately via decompressed_len */
            d_stream.next_out=hi->fd->block;
            d_stream.avail_out=hi->fd->blocksize;
            /* Don't process this data - let gzip loop handle it */
            break;
         }
         else
         {  /* Only subtract blocklength for non-gzip data */
            /* CRITICAL: Only subtract if blocklength is valid and >= blocklength */
            if(hi->blocklength > 0 && hi->blocklength >= blocklength)
            {  hi->blocklength-=blocklength;
            }
            else if(hi->blocklength > 0 && hi->blocklength < blocklength)
            {  /* This should not happen, but handle it safely */
               printf("DEBUG: WARNING: blocklength %ld < processed %ld, resetting\n", hi->blocklength, blocklength);
               hi->blocklength = 0;
            }
            /* If blocklength is already 0 (e.g., after gzip cleanup), don't try to subtract */
         }
         if(boundary)
         {  result=!eof;
            break;
         }
      }
      
      printf("DEBUG: Exited main for(;;) loop, now checking gzip processing\n");
      
      /* Gzip processing loop - continues until stream is complete */
      /* CRITICAL: This loop should NOT run if gzip was already processed in the main loop */
      /* The inline loop above processes ALL gzip data, so this should only handle edge cases */
      
      /* CRITICAL: Clean up flags if resources are already cleaned up BEFORE checking loop condition */
      /* This prevents the loop from trying to run with invalid resources */
      /* CRITICAL: Also check if gzip_end was set, meaning gzip processing completed */
      if(hi->flags & HTTPIF_GZIPDECODING && (gzipbuffer == NULL || !d_stream_initialized || gzip_end)) {
         if(gzipbuffer == NULL || !d_stream_initialized) {
            printf("DEBUG: Flag is set but resources cleaned up - clearing flags to prevent crash\n");
         }
         if(gzip_end) {
            printf("DEBUG: Flag is set but gzip_end is set - clearing flags as gzip processing is complete\n");
         }
         hi->flags &= ~HTTPIF_GZIPDECODING;
         hi->flags &= ~HTTPIF_GZIPENCODED;
      }
      
      if(d_stream_initialized) {
         printf("DEBUG: Checking gzip loop condition: flags=0x%04X, HTTPIF_GZIPDECODING=0x%04X, gzip_end=%u, gzipbuffer=%p, d_stream.avail_in=%lu\n",
                hi->flags, HTTPIF_GZIPDECODING, gzip_end, gzipbuffer, d_stream.avail_in);
      } else {
         printf("DEBUG: Checking gzip loop condition: flags=0x%04X, HTTPIF_GZIPDECODING=0x%04X, gzip_end=%u, gzipbuffer=%p, d_stream NOT initialized\n",
                hi->flags, HTTPIF_GZIPDECODING, gzip_end, gzipbuffer);
      }
      if(hi->flags & HTTPIF_GZIPDECODING && !gzip_end && gzipbuffer != NULL && d_stream_initialized) {
         if(d_stream_initialized) {
            printf("DEBUG: Entering gzip processing loop, flags=0x%04X, gzipbuffer=%p, gzip_end=%u, avail_in=%lu\n", 
                   hi->flags, gzipbuffer, gzip_end, d_stream.avail_in);
         } else {
            printf("DEBUG: Entering gzip processing loop, flags=0x%04X, gzipbuffer=%p, gzip_end=%u\n", 
                   hi->flags, gzipbuffer, gzip_end);
         }
      } else {
         printf("DEBUG: NOT entering gzip loop - flags check: %d, gzip_end check: %d, gzipbuffer check: %d, d_stream_initialized: %d\n",
                (hi->flags & HTTPIF_GZIPDECODING) != 0, gzip_end == 0, gzipbuffer != NULL, d_stream_initialized);
         /* Clean up if flag is still set but we're not entering the loop */
         if(hi->flags & HTTPIF_GZIPDECODING) {
            printf("DEBUG: Flag is set but loop not running - cleaning up\n");
            if(gzipbuffer) {
               FREE(gzipbuffer);
               gzipbuffer = NULL;
            }
            if(d_stream_initialized) {
               inflateEnd(&d_stream);
               d_stream_initialized = FALSE;
            }
            hi->flags &= ~HTTPIF_GZIPDECODING;
            hi->flags &= ~HTTPIF_GZIPENCODED;
         }
      }
      while(hi->flags & HTTPIF_GZIPDECODING && !gzip_end && gzipbuffer != NULL && d_stream_initialized)
      {  /* Declare all variables at start of loop for C89 compliance */
         long final_len;
         long error_len;
         long decompressed_len;
         UBYTE *buffer_start;
         UBYTE *buffer_end;
         UBYTE *data_check;
         BOOL data_valid;
         int i;
         
         /* CRITICAL: Re-validate all conditions inside loop to prevent crashes */
         if(gzip_end>0 || gzipbuffer == NULL || !d_stream_initialized) {
            printf("DEBUG: Gzip loop: Invalid state detected, exiting (gzip_end=%d, gzipbuffer=%p, d_stream_initialized=%d)\n",
                   gzip_end, gzipbuffer, d_stream_initialized);
            break;
         }
         
         /* CRITICAL: Validate d_stream.next_in points to valid memory before using it */
         if(d_stream.next_in != NULL && d_stream.next_in != gzipbuffer && 
            (d_stream.next_in < gzipbuffer || d_stream.next_in >= gzipbuffer + gzip_buffer_size)) {
            printf("DEBUG: CRITICAL: d_stream.next_in (%p) is invalid, clearing flags\n", d_stream.next_in);
            hi->flags &= ~HTTPIF_GZIPDECODING;
            hi->flags &= ~HTTPIF_GZIPENCODED;
            break;
         }
         
         /* Process the current gzip data */
         if(d_stream.avail_in > 0 && d_stream.next_in != NULL) {
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
            if(hi->parttype[0] && strstr(hi->parttype, "text/html")) {
               Updatetaskattrs(
                  AOURL_Data,hi->fd->block,
                  AOURL_Datalength,hi->blocklength,
                  AOURL_Contenttype, "text/html",
                  TAG_END);
            } else {
               Updatetaskattrs(
                  AOURL_Data,hi->fd->block,
                  AOURL_Datalength,hi->blocklength,
                  TAG_END);
            }
            
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
            /* Process any remaining decompressed data before exiting */
            if(d_stream.avail_out < hi->fd->blocksize) {
               final_len = hi->fd->blocksize - d_stream.avail_out;
               if(final_len > 0 && final_len <= hi->fd->blocksize) {
                  printf("DEBUG: Processing final %ld bytes from gzip stream\n", final_len);
                  if(hi->parttype[0] && strstr(hi->parttype, "text/html")) {
                     Updatetaskattrs(
                        AOURL_Data, hi->fd->block,
                        AOURL_Datalength, final_len,
                        AOURL_Contenttype, "text/html",
                        TAG_END);
                  } else {
                     Updatetaskattrs(
                        AOURL_Data, hi->fd->block,
                        AOURL_Datalength, final_len,
                        TAG_END);
                  }
                  hi->flags |= HTTPIF_DATA_PROCESSED;
               }
            }
            
            /* CRITICAL: When Z_STREAM_END is returned, zlib has finished decompressing */
            /* compressed_bytes_consumed tracks data we've copied to gzipbuffer and processed */
            /* For Content-Length tracking, we need to account for any remaining unprocessed data in the buffer */
            /* Note: d_stream.avail_in at Z_STREAM_END should typically be 0 for a valid gzip stream */
            if(!(hi->flags & HTTPIF_CHUNKED) && hi->partlength > 0)
            {  long remaining_in_buffer;
               remaining_in_buffer = d_stream.avail_in;
               if(remaining_in_buffer > 0)
               {  printf("DEBUG: Z_STREAM_END: %ld bytes remain unprocessed in buffer (this is unusual for gzip)\n", remaining_in_buffer);
                  /* This data is part of what was read from network, but not processed by zlib */
                  /* For Content-Length tracking, we should count it, but it's already counted in compressed_bytes_consumed */
                  /* since we copied it to gzipbuffer. The issue is zlib didn't consume it all. */
               }
               printf("DEBUG: Z_STREAM_END: compressed_bytes_consumed=%ld, Content-Length=%ld, remaining_in_buffer=%ld\n",
                      compressed_bytes_consumed, hi->partlength, remaining_in_buffer);
            }
            
            /* CRITICAL: Clean up immediately when stream ends */
            if(d_stream_initialized) {
               inflateEnd(&d_stream);
               d_stream_initialized = FALSE;
            }
            if(gzipbuffer) {
               FREE(gzipbuffer);
               gzipbuffer = NULL;
            }
            hi->flags &= ~HTTPIF_GZIPENCODED;
            hi->flags &= ~HTTPIF_GZIPDECODING;
            gzip_end=1; // Success break!
         }
         else if(err!=Z_OK)
         {  if(err==Z_DATA_ERROR) printf("zlib DATA ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_STREAM_ERROR) printf("zlib STREAM_ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_NEED_DICT) printf("zlib NEED DICT - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            if(err==Z_MEM_ERROR) printf("zlib MEM ERROR - avail_in=%lu, avail_out=%lu\n", d_stream.avail_in, d_stream.avail_out);
            
            /* CRITICAL: On any zlib error, process any valid decompressed data first */
            /* Then safely disable gzip to prevent memory corruption */
            if(d_stream.avail_out < hi->fd->blocksize) {
               /* We might have some valid decompressed data before the error */
               error_len = hi->fd->blocksize - d_stream.avail_out;
               if(error_len > 0 && error_len <= hi->fd->blocksize) {
                  printf("DEBUG: Processing %ld bytes before zlib error\n", error_len);
                  if(hi->parttype[0] && strstr(hi->parttype, "text/html")) {
                     Updatetaskattrs(
                        AOURL_Data, hi->fd->block,
                        AOURL_Datalength, error_len,
                        AOURL_Contenttype, "text/html",
                        TAG_END);
                  } else {
                     Updatetaskattrs(
                        AOURL_Data, hi->fd->block,
                        AOURL_Datalength, error_len,
                        TAG_END);
                  }
                  hi->flags |= HTTPIF_DATA_PROCESSED;
               }
            }
            
            printf("DEBUG: Zlib error detected, safely disabling gzip to prevent crashes\n");
            
            /* Clean up zlib stream immediately */
            if(d_stream_initialized) {
               inflateEnd(&d_stream);
               d_stream_initialized = FALSE;
            }
            
            /* Free gzip buffer */
            if(gzipbuffer) {
               FREE(gzipbuffer);
               gzipbuffer = NULL;
            }
            
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
         {  /* Read more compressed data from network */
            if(!Readblock(hi))
            {  printf("DEBUG: No more data for gzip, ending\n");
               gzip_end = 1;
               break;
            }
            /* Update total compressed bytes read from network */
            total_compressed_read += hi->blocklength;
            
            /* For non-chunked, append new block data to gzipbuffer */
            if(!(hi->flags & HTTPIF_CHUNKED))
            {  /* Non-chunked: Append all new block data to gzipbuffer */
               long remaining_space;
               long bytes_to_append;
               long used_space;
               
               /* Calculate space used in buffer */
               used_space = (d_stream.next_in - gzipbuffer) + d_stream.avail_in;
               remaining_space = gzip_buffer_size - used_space;
               
               if(remaining_space <= 0 || hi->blocklength > remaining_space)
               {  printf("DEBUG: Non-chunked gzip: Buffer full (remaining=%ld, block=%ld), ending\n",
                         remaining_space, hi->blocklength);
                  gzip_end = 1;
                  break;
               }
               
               bytes_to_append = MIN(hi->blocklength, remaining_space);
               if(bytes_to_append > 0)
               {  /* Move unprocessed data to start if needed */
                  if(d_stream.next_in != gzipbuffer && d_stream.avail_in > 0)
                  {  memmove(gzipbuffer, d_stream.next_in, d_stream.avail_in);
                     gziplength = d_stream.avail_in;
                  }
                  else if(d_stream.avail_in == 0)
                  {  gziplength = 0;
                  }
                  
                  /* Append new data */
                  if(gziplength + bytes_to_append <= gzip_buffer_size)
                  {  memcpy(gzipbuffer + gziplength, hi->fd->block, bytes_to_append);
                     gziplength += bytes_to_append;
                     compressed_bytes_consumed += bytes_to_append;
                     
                     /* Update zlib stream */
                     d_stream.next_in = gzipbuffer;
                     d_stream.avail_in = gziplength;
                     
                     printf("DEBUG: Non-chunked gzip: Added %ld bytes from new block (total in buffer=%ld)\n",
                            bytes_to_append, gziplength);
                     
                     /* Clear block */
                     hi->blocklength = 0;
                  }
               }
            }
            /* For chunked encoding, we need to extract chunks - this is handled in the chunked+gzip section above */
            
            /* Add timeout protection to prevent infinite hanging */
            if(++loop_count > 200) {
               printf("DEBUG: Too many gzip input cycles, finishing\n");
               /* CRITICAL: Clean up when loop limit reached */
               if(d_stream_initialized) {
                  inflateEnd(&d_stream);
                  d_stream_initialized = FALSE;
               }
               if(gzipbuffer) {
                  FREE(gzipbuffer);
                  gzipbuffer = NULL;
               }
               hi->flags &= ~HTTPIF_GZIPENCODED;
               hi->flags &= ~HTTPIF_GZIPDECODING;
               gzip_end=1;
               break;
            }
            
            /* CRITICAL: For chunked encoding, read into block first, then extract chunk data */
            if(hi->flags & HTTPIF_CHUNKED)
            {  /* Declare all variables at start of block for C89 compliance */
               long chunk_data_start;
               long gzip_data_start;
               long search_pos;
               long chunk_data_len;
               long remaining_unprocessed;
               long available_space;
               UBYTE *p;
               
               /* Read chunk data into block buffer first */
               if(!Readblock(hi))
               {  printf("DEBUG: End of chunked gzip stream\n");
                  /* CRITICAL: Clean up when we reach end of stream */
                  if(d_stream_initialized) {
                     inflateEnd(&d_stream);
                     d_stream_initialized = FALSE;
                  }
                  if(gzipbuffer) {
                     FREE(gzipbuffer);
                     gzipbuffer = NULL;
                  }
                  hi->flags &= ~HTTPIF_GZIPENCODED;
                  hi->flags &= ~HTTPIF_GZIPDECODING;
                  gzip_end=1;
                  break;
               }
               
               /* Extract chunk data (skip chunk header) */
               chunk_data_start = 0;
               p = hi->fd->block;
               
               /* Find end of chunk size line */
               while(chunk_data_start < hi->blocklength - 1)
               {  if(p[chunk_data_start] == '\r' && chunk_data_start + 1 < hi->blocklength && p[chunk_data_start + 1] == '\n')
                  {  chunk_data_start += 2; /* Skip CRLF */
                     break;
                  }
                  chunk_data_start++;
               }
               
               if(chunk_data_start >= hi->blocklength)
               {  printf("DEBUG: No chunk data found, waiting for more\n");
                  /* Not enough data yet - wait */
                  continue;
               }
               
               /* Find actual gzip data start (should be immediately after chunk header) */
               gzip_data_start = chunk_data_start;
               if(hi->blocklength - gzip_data_start >= 3)
               {  /* Check if it starts with gzip magic */
                  if(p[gzip_data_start] != 0x1F || p[gzip_data_start + 1] != 0x8B || p[gzip_data_start + 2] != 0x08)
                  {  /* Look for gzip magic in this chunk */
                     search_pos = gzip_data_start;
                     for(; search_pos < hi->blocklength - 2; search_pos++)
                     {  if(p[search_pos] == 0x1F && p[search_pos + 1] == 0x8B && p[search_pos + 2] == 0x08)
                        {  gzip_data_start = search_pos;
                           break;
                        }
                     }
                  }
               }
               
               chunk_data_len = hi->blocklength - gzip_data_start;
               if(chunk_data_len > 0)
               {  /* CRITICAL: For chunked encoding, accumulate chunks into a larger buffer */
                  /* Calculate remaining unprocessed data */
                  remaining_unprocessed = d_stream.avail_in;
                  
                  /* CRITICAL: Validate remaining_unprocessed is reasonable */
                  if(remaining_unprocessed < 0 || remaining_unprocessed > gzip_buffer_size)
                  {  printf("DEBUG: CRITICAL: Invalid remaining_unprocessed (%ld), resetting to 0\n", remaining_unprocessed);
                     remaining_unprocessed = 0;
                  }
                  
                  /* Move remaining unprocessed data to start of buffer to make room */
                  if(d_stream.next_in != gzipbuffer && remaining_unprocessed > 0)
                  {  /* CRITICAL: Validate pointers and sizes before memmove to prevent corruption */
                     if(remaining_unprocessed > gzip_buffer_size)
                     {  printf("DEBUG: CRITICAL: remaining_unprocessed (%ld) exceeds buffer size (%ld), resetting\n",
                               remaining_unprocessed, gzip_buffer_size);
                        remaining_unprocessed = 0;
                        gziplength = 0;
                     }
                     else if(d_stream.next_in >= gzipbuffer && 
                             d_stream.next_in < gzipbuffer + gzip_buffer_size &&
                             (d_stream.next_in + remaining_unprocessed) <= gzipbuffer + gzip_buffer_size &&
                             remaining_unprocessed > 0)
                     {  memmove(gzipbuffer, d_stream.next_in, remaining_unprocessed);
                        d_stream.next_in = gzipbuffer;
                        d_stream.avail_in = remaining_unprocessed;
                        gziplength = remaining_unprocessed;
                     }
                     else
                     {  printf("DEBUG: CRITICAL: Invalid pointer state for memmove (next_in=%p, gzipbuffer=%p, remaining=%ld, buffer_size=%ld), resetting\n",
                               d_stream.next_in, gzipbuffer, remaining_unprocessed, gzip_buffer_size);
                        remaining_unprocessed = 0;
                        gziplength = 0;
                     }
                  }
                  else if(remaining_unprocessed > 0)
                  {  /* Already at start - ensure gziplength is set correctly */
                     gziplength = remaining_unprocessed;
                  }
                  else
                  {  /* All data consumed - reset gziplength for new data */
                     gziplength = 0;
                  }
                  
                  /* Check if we have space for new chunk */
                  available_space = gzip_buffer_size - gziplength;
                  if(chunk_data_len > available_space)
                  {  printf("DEBUG: WARNING: Chunk data (%ld) exceeds available space (%ld), truncating\n", 
                            chunk_data_len, available_space);
                     chunk_data_len = available_space > 0 ? available_space : 0;
                     if(chunk_data_len <= 0)
                     {  printf("DEBUG: CRITICAL: No space in gzipbuffer for chunk data\n");
                        gzip_end = 1;
                        break;
                     }
                  }
                  
                  /* Append chunk data to end of gzipbuffer */
                  if(gziplength + chunk_data_len > gzip_buffer_size)
                  {  printf("DEBUG: CRITICAL: Buffer overflow! gziplength=%ld, chunk_data_len=%ld, buffer_size=%ld\n",
                            gziplength, chunk_data_len, gzip_buffer_size);
                     gzip_end = 1;
                     break;
                  }
                  
                  /* CRITICAL: Validate source and destination pointers before memcpy */
                  if(gzipbuffer && hi->fd->block && 
                     gziplength >= 0 && gziplength < gzip_buffer_size &&
                     chunk_data_len > 0 && chunk_data_len <= available_space &&
                     gzip_data_start >= 0 && gzip_data_start < hi->blocklength &&
                     (gzip_data_start + chunk_data_len) <= hi->blocklength)
                  {  memcpy(gzipbuffer + gziplength, hi->fd->block + gzip_data_start, chunk_data_len);
                     compressed_bytes_consumed += chunk_data_len; /* Track compressed data consumed */
                  }
                  else
                  {  printf("DEBUG: CRITICAL: Invalid pointers for memcpy (gzipbuffer=%p, block=%p, gziplength=%ld, chunk_data_len=%ld, gzip_data_start=%ld, blocklength=%ld), aborting\n",
                            gzipbuffer, hi->fd ? hi->fd->block : NULL, gziplength, chunk_data_len, gzip_data_start, hi->blocklength);
                     gzip_end = 1;
                     break;
                  }
                  
                  /* Update zlib stream to include new data */
                  d_stream.next_in = gzipbuffer; /* Point to start */
                  
                  /* Update total gziplength first, then set avail_in to match */
                  gziplength += chunk_data_len;
                  d_stream.avail_in = gziplength; /* Total available now */
                  
                  /* Clear processed chunk data from block */
                  hi->blocklength = 0;
                  
                  printf("DEBUG: Read %ld bytes of chunked gzip data (unprocessed was=%ld), total in buffer: %ld, avail_in: %lu\n", 
                         chunk_data_len, remaining_unprocessed, gziplength, d_stream.avail_in);
               }
               else
               {  /* No data in this chunk - might be end chunk */
                  printf("DEBUG: Empty chunk, checking for end\n");
                  gzip_end=1;
                  break;
               }
            }
            else
            {  /* Non-chunked: read directly into gzipbuffer */
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
         }
         
         /* CRITICAL: Only calculate blocklength if we have decompressed data */
         /* Don't reset blocklength here - it may still contain valid data */
         if(d_stream.avail_out < hi->fd->blocksize) {
            /* We have decompressed some data */
            decompressed_len = hi->fd->blocksize - d_stream.avail_out;
            
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
                  printf("DEBUG: Content type: %s, processing as-is\n", hi->parttype[0] ? (char *)hi->parttype : "unknown");
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
            buffer_start = hi->fd->block;
            buffer_end = buffer_start + hi->blocklength;
            
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
            data_check = hi->fd->block;
            data_valid = TRUE;
            i = 0;
            
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
         printf("DEBUG: Cleaning up gzip resources, flags before cleanup=0x%04X, d_stream_initialized=%d\n", 
                hi->flags, d_stream_initialized);
         /* Gzip processing completed - clean up */
         if(d_stream_initialized) {
            inflateEnd(&d_stream);
            d_stream_initialized = FALSE;
         }
         if(gzipbuffer) {
            FREE(gzipbuffer);
            gzipbuffer = NULL;
         }
         hi->flags &= ~HTTPIF_GZIPDECODING;
         hi->flags &= ~HTTPIF_GZIPENCODED;
         printf("DEBUG: Gzip cleanup complete, flags after cleanup=0x%04X\n", hi->flags);
         
         /* CRITICAL: Account for any remaining compressed data in current block */
         if(hi->blocklength > 0)
         {  total_compressed_read += hi->blocklength;
            printf("DEBUG: Accounting for %ld bytes remaining in block after gzip cleanup\n", hi->blocklength);
         }
         
         /* CRITICAL: Reset blocklength to 0 after gzip processing is complete */
         /* This is safe because all gzip data has been processed and sent via Updatetaskattrs */
         hi->blocklength = 0;
         
         /* CRITICAL: For non-chunked gzip streams, all data has been decompressed */
         /* For Content-Length responses, read exactly that much compressed data from network */
         if(!(hi->flags & HTTPIF_CHUNKED))
         {  if(hi->partlength > 0)
            {  printf("DEBUG: Non-chunked gzip complete, read %ld/%ld compressed bytes from network, reading remaining\n", 
                      total_compressed_read, hi->partlength);
               while(total_compressed_read < hi->partlength && Readblock(hi))
               {  long compressed_in_block;
                  compressed_in_block = hi->blocklength;
                  total_compressed_read += compressed_in_block;
                  hi->blocklength = 0; /* Discard consumed compressed data */
                  printf("DEBUG: Read %ld bytes from network, total=%ld/%ld\n", 
                         compressed_in_block, total_compressed_read, hi->partlength);
               }
               printf("DEBUG: Finished reading compressed data from network: %ld/%ld bytes\n", 
                      total_compressed_read, hi->partlength);
            }
            else
            {  printf("DEBUG: Non-chunked gzip complete, no Content-Length, reading until EOF\n");
               while(Readblock(hi))
               {  /* Discard remaining compressed data - it's already been decompressed */
                  total_compressed_read += hi->blocklength;
                  hi->blocklength = 0;
               }
            }
            /* Exit Readdata - gzip response is complete */
            result = !eof;
            if(bdcopy) FREE(bdcopy);
            return result;
         }
      } else if(gzipbuffer != NULL) {
         printf("DEBUG: WARNING: gzipbuffer not NULL but flag not set - possible memory leak!\n");
         FREE(gzipbuffer);
         gzipbuffer = NULL;
      }
      /* Clean up d_stream if it was initialized but flag is not set */
      if(d_stream_initialized && !(hi->flags & HTTPIF_GZIPDECODING)) {
         printf("DEBUG: Cleaning up orphaned d_stream\n");
         inflateEnd(&d_stream);
         d_stream_initialized = FALSE;
      }
      
      /* CRITICAL: Validate blocklength before continuing */
      /* Only validate if we're not in a gzip state transition */
      if(!(hi->flags & HTTPIF_GZIPDECODING) && (hi->blocklength < 0 || hi->blocklength > hi->fd->blocksize)) {
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
               /* CRITICAL: Include content type if available */
               if(hi->parttype[0] != '\0' && hi->parttype[0] != 0 && strlen(hi->parttype) > 0) {
                  printf("DEBUG: Sending final data with content type: '%s' (length=%ld)\n", hi->parttype, strlen(hi->parttype));
                  Updatetaskattrs(
                     AOURL_Data, hi->fd->block,
                     AOURL_Datalength, hi->blocklength,
                     AOURL_Contenttype, hi->parttype,
                     TAG_END);
               } else {
                  printf("DEBUG: WARNING: parttype empty for final data, sending without content type\n");
                  Updatetaskattrs(
                     AOURL_Data, hi->fd->block,
                     AOURL_Datalength, hi->blocklength,
                     TAG_END);
               }
            }
            break;
         }
         printf("DEBUG: Readblock returned, new blocklength=%ld\n", hi->blocklength);
      }
      
      /* Check if we should exit main loop for gzip processing */
      if(exit_main_loop) {
         printf("DEBUG: Exit flag set, breaking out of main loop for gzip processing\n");
         break;
      }
   }
   
   printf("DEBUG: Main loop ended, flags=0x%04X, gzipbuffer=%p, d_stream_initialized=%d, exit_main_loop=%d\n", 
          hi->flags, gzipbuffer, d_stream_initialized, exit_main_loop);
   
   if(bdcopy) FREE(bdcopy);
   
   /* CRITICAL: Always clean up gzip resources to prevent memory corruption */
   if(gzipbuffer) 
   {  FREE(gzipbuffer);
      gzipbuffer = NULL;
   }
   
   /* CRITICAL: Always clean up zlib stream to prevent memory corruption */
   if(d_stream_initialized)
   {  inflateEnd(&d_stream);
      d_stream_initialized = FALSE;
      printf("DEBUG: Zlib stream cleaned up\n");
   }
   
   /* CRITICAL: Force cleanup of any pending network operations to prevent exit hanging */
   /* CRITICAL: For SSL connections, must close SSL BEFORE closing socket */
   if(hi->sock >= 0) {
      printf("DEBUG: Force closing socket to prevent exit hanging\n");
      /* CRITICAL: If this is an SSL connection, close SSL first */
#ifndef DEMOVERSION
      if(hi->flags & HTTPIF_SSL && hi->assl)
      {  printf("DEBUG: Force closing SSL connection before socket\n");
         Assl_closessl(hi->assl);
      }
#endif
      /* Use AmigaOS socket close function */
      if(hi->socketbase) {
         a_close(hi->sock, hi->socketbase);
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
         printf("DEBUG: movedto=%lu, movedtourl=%p\n", hi->movedto, hi->movedtourl);
         if(hi->movedto && hi->movedtourl)
         {  printf("DEBUG: Processing redirect to: %s\n", hi->movedtourl);
            /* For redirects, consume any remaining body data before processing redirect */
            Nextline(hi);
            printf("DEBUG: Nextline called for redirect body consumption, blocklength=%ld\n", hi->blocklength);
            /* If there's body data, we should read it, but for redirects we can skip */
            Updatetaskattrs(hi->movedto,hi->movedtourl,TAG_END);
            printf("DEBUG: Updatetaskattrs for redirect completed\n");
            return; /* Exit after redirect */
         }
         else
         {  printf("DEBUG: No redirect, calling Nextline before Readdata\n");
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
      /* CRITICAL: Each HTTPS connection must have its own dedicated Assl object */
      /* If hi->assl already exists, clean it up first to prevent reuse */
      if(hi->assl)
      {  Assl_closessl(hi->assl);
         Assl_cleanup(hi->assl);
         hi->assl = NULL;
      }
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
   {  printf("DEBUG: Opensocket: Calling Assl_openssl() before creating socket\n");
      if(!Assl_openssl(hi->assl))
      {  printf("DEBUG: Opensocket: Assl_openssl() failed, returning -1\n");
         return -1;
      }
      printf("DEBUG: Opensocket: Assl_openssl() succeeded\n");
   }
#endif
   sock=a_socket(hent->h_addrtype,SOCK_STREAM,0,hi->socketbase);
   printf("DEBUG: Opensocket: Created socket %ld\n", sock);
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
   long result;
   UBYTE *hostname_str;
   
   if(hi->port==-1)
   {  if(hi->flags&HTTPIF_SSL) hi->port=443;
      else hi->port=80;
   }
   printf("DEBUG: Attempting to connect to %s:%ld (SSL=%s)\n", 
          hent->h_name, hi->port, (hi->flags&HTTPIF_SSL) ? "YES" : "NO");
   if(!a_connect(hi->sock,hent,hi->port,hi->socketbase))
   {  /* TCP connect succeeded - a_connect returns 0 on success */
      printf("DEBUG: TCP connect succeeded\n");
      ok=TRUE;
#ifndef DEMOVERSION
      /* For SSL connections, proceed with SSL handshake */
      if(hi->flags&HTTPIF_SSL)
      {  hostname_str = hi->hostname ? hi->hostname : (UBYTE *)"(NULL)";
         printf("DEBUG: Starting SSL connection to '%s'\n", hostname_str);
         
         /* CRITICAL: Ensure SSL resources are valid before attempting connection */
         if(hi->assl && hi->sock >= 0)
         {  result=Assl_connect(hi->assl,hi->sock,hi->hostname);
            printf("DEBUG: SSL connect result: %ld (ASSLCONNECT_OK=%d)\n", result, ASSLCONNECT_OK);
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
         else
         {  printf("DEBUG: SSL connection aborted - invalid SSL resources (assl=%p, sock=%ld)\n",
                   hi->assl, hi->sock);
            ok=FALSE;
            hi->flags|=HTTPIF_NOSSLREQ;
         }
      }
#endif
   }
   else
   {  /* TCP connect failed - a_connect returns non-zero on failure */
      printf("DEBUG: TCP connect failed\n");
      /* CRITICAL: TCP connect failed - cannot proceed with SSL or HTTP */
      /* Set ok=FALSE to indicate connection failure */
      ok=FALSE;
#ifndef DEMOVERSION
      if(hi->flags&HTTPIF_SSL)
      {  /* Only proceed if this is an SSL tunnel - tunnel setup uses separate connection */
         if(hi->flags&HTTPIF_SSLTUNNEL)
         {  UBYTE *creq;
            UBYTE *p;
            long creqlen;
            
            creqlen = strlen(tunnelrequest) + strlen(hi->tunnel);
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
            
            /* If tunnel setup succeeded, proceed with SSL connection */
            if(ok)
            {  hostname_str = hi->hostname ? hi->hostname : (UBYTE *)"(NULL)";
               printf("DEBUG: Starting SSL connection to '%s'\n", hostname_str);
               
               /* CRITICAL: Ensure SSL resources are valid before attempting connection */
               if(hi->assl && hi->sock >= 0)
               {  result=Assl_connect(hi->assl,hi->sock,hi->hostname);
                  printf("DEBUG: SSL connect result: %ld (ASSLCONNECT_OK=%d)\n", result, ASSLCONNECT_OK);
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
               else
               {  printf("DEBUG: SSL connection aborted - invalid SSL resources (assl=%p, sock=%ld)\n",
                         hi->assl, hi->sock);
                  ok=FALSE;
                  hi->flags|=HTTPIF_NOSSLREQ;
               }
            }
         }
         else
         {  /* CRITICAL: For direct SSL connections, TCP connect MUST succeed first */
            /* Cannot proceed with SSL if TCP connection failed */
            printf("DEBUG: TCP connect failed for SSL connection - cannot proceed with SSL handshake\n");
            ok=FALSE;
         }
      }
      else
#endif
      {  /* For non-SSL connections, TCP connect failure means connection failed */
         ok=FALSE;
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
            /* CRITICAL: Close SSL connection BEFORE closing socket */
            /* SSL shutdown needs the socket to still be open */
            if(hi->assl)
            {  Assl_closessl(hi->assl);
               /* CRITICAL: DON'T set hi->assl to NULL here - Assl_cleanup() will handle it */
               /* Assl_closessl() only closes the connection, doesn't free the Assl structure */
            }
            /* Now safe to close socket - SSL has been properly shut down */
            if(hi->sock >= 0)
            {  a_close(hi->sock,hi->socketbase);
               hi->sock = -1;
            }
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
   /* CRITICAL: Clean up Assl structure - this frees the structure itself */
   /* Assl_closessl() already freed SSL resources, so Assl_cleanup() should only free the structure */
   if(hi->assl)
   {  /* CRITICAL: Assl_cleanup() will free SSL resources again if they still exist */
      /* But Assl_closessl() should have already freed them, so this should just free the struct */
      Assl_cleanup(hi->assl);
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

