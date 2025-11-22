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

/* awebamitcp.c - AWeb AmiTCP function library. Compile this with AmiTCP SDK */

#include "awebtcp.h"
#include <proto/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <exec/libraries.h>
#include <sys/socket.h>  /* For socklen_t */

/* Forward declarations for SSL functions */
extern struct Assl *GetTaskSSLContext(void);
extern struct Library *GetTaskSSLSocketBase(void);
extern void Setsslsocket(long sock,struct Assl *assl,struct Library *socketbase,UBYTE *hostname);
extern struct Assl *Getsslsocket(long sock);
extern void Clrsslsocket(long sock);
extern BOOL Assl_openssl(struct Assl *assl);
extern void Assl_closessl(struct Assl *assl);
extern long Assl_connect(struct Assl *assl,long sock,UBYTE *hostname);
extern long Assl_read(struct Assl *assl,char *buffer,int length);
extern long Assl_write(struct Assl *assl,char *buffer,int length);

__asm int amitcp_recv(register __d0 int a,
   register __a0 char *b,
   register __d1 int c,
   register __d2 int d,
   register __a1 struct Library *SocketBase)
{  struct Assl *assl;
   long result;
   /* Check if SSL is enabled for this socket */
   assl=Getsslsocket(a);
   if(assl)
   {  /* Use SSL read */
      result=Assl_read(assl,b,c);
      if(result<0) result=-1;
   }
   else
   {  /* Use plain TCP recv */
      result=recv(a,b,c,d);
   }
   return (int)result;
}

__asm int amitcp_send(register __d0 int a,
   register __a0 char *b,
   register __d1 int c,
   register __d2 int d,
   register __a1 struct Library *SocketBase)
{  struct Assl *assl;
   long result;
   /* Check if SSL is enabled for this socket */
   assl=Getsslsocket(a);
   if(assl)
   {  /* Use SSL write */
      result=Assl_write(assl,b,c);
      if(result<0) result=-1;
   }
   else
   {  /* Use plain TCP send */
      result=send(a,b,c,d);
   }
   return (int)result;
}

__asm int amitcp_socket(register __d0 int a,
   register __d1 int b,
   register __d2 int c,
   register __a0 struct Library *SocketBase)
{  /* Just create socket - SSL objects will be created in amitcp_connect() */
   return socket(a,b,c);
}

__asm struct hostent *amitcp_gethostbyname (register __a0 char *a,
   register __a1 struct Library *SocketBase)
{  return gethostbyname(a);
}

__asm int amitcp_connect(register __d0 int a,
   register __a0 struct hostent *hent,
   register __d1 int port,
   register __a1 struct Library *SocketBase)
{  struct sockaddr_in sad = {0};
   int result;
   struct Assl *assl;
   struct Library *ssl_socketbase;
   UBYTE *hostname;
   long connect_result;
   sad.sin_len=sizeof(sad);
   sad.sin_family=hent->h_addrtype;
   sad.sin_port=port;
   sad.sin_addr.s_addr=*(u_long *)(*hent->h_addr_list);
   result=connect(a, (struct sockaddr *)&sad, sizeof(sad));
   if(!result)
   {  /* TCP connect succeeded - check if SSL is needed */
      assl=GetTaskSSLContext();
      ssl_socketbase=GetTaskSSLSocketBase();
      if(assl && ssl_socketbase==SocketBase)
      {  /* SSL is enabled for this task */
         /* Route based on port: port 443 = HTTPS (http.c manages SSL), other ports = automatic SSL */
         /* http.c calls Assl_openssl() in Opensocket() before a_connect() for HTTPS */
         /* For Gemini (port 1965) and other protocols, SSL objects don't exist yet */
         /* So we do automatic SSL for non-443 ports */
         if(port != 443)
         {  /* Not HTTPS - do automatic SSL (e.g., Gemini on port 1965) */
            hostname=hent->h_name ? (UBYTE *)hent->h_name : NULL;
            /* Clean up any existing SSL objects before creating new ones */
            /* This ensures we start with a clean state for each connection */
            Assl_closessl(assl);
            /* Create SSL objects for this connection */
            if(Assl_openssl(assl))
            {  connect_result=Assl_connect(assl,a,hostname);
               if(connect_result==ASSLCONNECT_OK)
               {  /* SSL handshake successful - store SSL context for this socket */
                  Setsslsocket(a,assl,ssl_socketbase,hostname);
               }
               else if(connect_result==ASSLCONNECT_DENIED)
               {  /* User denied certificate - close SSL and return error */
                  Assl_closessl(assl);
                  result=-1;  /* Return error */
               }
               else
               {  /* SSL handshake failed - close SSL and return error */
                  Assl_closessl(assl);
                  result=-1;  /* Return error */
               }
            }
            else
            {  /* SSL init failed */
               result=-1;  /* Return error */
            }
         }
         /* For port 443 (HTTPS), http.c manages SSL - don't touch it here */
         /* http.c calls Assl_openssl() in Opensocket(), then Assl_connect() in Connect() */
      }
   }
   return result;
}

__asm int amitcp_connect2(register __d0 int a,
   register __d1 int addrtype,
   register __d2 u_long addr,
   register __d3 int port,
   register __a0 struct Library *SocketBase)
{  struct sockaddr_in sad = {0};
   sad.sin_len=sizeof(sad);
   sad.sin_family=addrtype;
   sad.sin_port=port;
   sad.sin_addr.s_addr=addr;
   return connect(a, (struct sockaddr *)&sad, sizeof(sad));
}

__asm int amitcp_getsockname(register __d0 int a,
   register __a0 struct sockaddr *b,
   register __a1 int *c,
   register __a2 struct Library *SocketBase)
{
   socklen_t len;
   int result;
   if(c)
   {  len=*c;
      result=getsockname(a,b,&len);
      if(result==0 && c) *c=len;
   }
   else
   {  result=getsockname(a,b,NULL);
   }
   return result;
}

__asm int amitcp_bind(register __d0 int a,
   register __a0 struct sockaddr *b,
   register __d1 int c,
   register __a1 struct Library *SocketBase)
{
   return bind(a, b, c);
}

__asm int amitcp_listen(register __d0 int a,
   register __d1 int b,
   register __a0 struct Library *SocketBase)
{
   return listen(a, b);
}

__asm int amitcp_accept(register __d0 int a,
   register __a0 struct sockaddr *b,
   register __a1 int *c,
   register __a2 struct Library *SocketBase)
{
   socklen_t len;
   int result;
   if(c)
   {  len=*c;
      result=accept(a,b,&len);
      if(result>=0 && c) *c=len;
   }
   else
   {  result=accept(a,b,NULL);
   }
   return result;
}

__asm int amitcp_shutdown(register __d0 int a,
   register __d1 int b,
   register __a0 struct Library *SocketBase)
{  return shutdown(a, b);
}

__asm int amitcp_close(register __d0 int a,
   register __a0 struct Library *SocketBase)
{  struct Assl *assl;
   int result;
   /* Check if SSL is enabled for this socket */
   assl=Getsslsocket(a);
   if(assl)
   {  /* Close SSL first - but don't free the Assl struct itself */
      /* The Assl struct is managed per-task, not per-socket */
      Assl_closessl(assl);
      Clrsslsocket(a);
   }
   /* Close TCP socket */
   result=CloseSocket(a);
   return result;
}

__asm int amitcp_setup(register __a0 struct Library *SocketBase)
{  /* Initialize AmiTCP library - return 0 for success */
   return 0;
}

__asm void amitcp_cleanup(register __a0 struct Library *SocketBase)
{  /* Cleanup AmiTCP library */
   return;
}

__asm void amitcp_dummy(void)
{  return;
}

static UBYTE version[]="AwebAmiTcp.library";

struct Jumptab
{  UWORD jmp;
   void *function;
};
#define JMP 0x4ef9

static struct Jumptab jumptab[]=
{
   JMP,amitcp_getsockname,
   JMP,amitcp_recv,
   JMP,amitcp_send,
   JMP,amitcp_shutdown,
   JMP,amitcp_accept,
   JMP,amitcp_listen,
   JMP,amitcp_bind,
   JMP,amitcp_connect2,
   JMP,amitcp_connect,
   JMP,amitcp_close,
   JMP,amitcp_socket,
   JMP,amitcp_gethostbyname,
   JMP,amitcp_cleanup, /* cleanup */
   JMP,amitcp_setup,   /* setup */
   JMP,amitcp_dummy,   /* Extfunc */
   JMP,amitcp_dummy,   /* Expunge */
   JMP,amitcp_dummy,   /* Close */
   JMP,amitcp_dummy,   /* Open */
};
static struct Library awebamitcplib=
{  {  NULL,NULL,NT_LIBRARY,0,version },
   0,0,
   sizeof(jumptab),
   sizeof(struct Library),
   1,0,
   version,
   0,0
};

struct Library *AwebAmiTcpBase=&awebamitcplib;
   
