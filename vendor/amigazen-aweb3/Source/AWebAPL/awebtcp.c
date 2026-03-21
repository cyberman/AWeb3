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

/* awebtcp.c - AWeb tcp and ssl switch engine */

#include <proto/exec.h>
#include <proto/socket.h>
#include "aweb.h"
#include "awebtcp.h"
#include "fetchdriver.h"

extern struct Library *AwebAmiTcpBase;
/* extern struct Library *AwebInet225Base; */

extern struct Library *AwebAmisslBase;
/* extern struct Library *AwebMiamisslBase; */

struct Library *AwebTcpBase;
struct Library *AwebSslBase;

/* Global errno variable for bsdsocket.library */
int errno;

/* SSL context per socket - simple array indexed by socket fd */
#define MAX_SSL_SOCKETS 256
static struct Assl *ssl_sockets[MAX_SSL_SOCKETS];
static struct Library *ssl_socketbases[MAX_SSL_SOCKETS];
static UBYTE *ssl_hostnames[MAX_SSL_SOCKETS];
static struct SignalSemaphore ssl_socket_sema;
static BOOL ssl_socket_sema_init = FALSE;

/* Forward declarations */
static void Initsslsockets(void);

/*-----------------------------------------------------------------------*/

struct Library *Tcpopenlib(void)
{  struct Library *base=NULL;
   if(base=OpenLibrary("bsdsocket.library",0))
   {  AwebTcpBase=AwebAmiTcpBase;
      a_setup(base);
      Initsslsockets();  /* Initialize SSL socket tracking */
   }
   /* else if(base=OpenLibrary("inet:libs/socket.library",4))
   {  AwebTcpBase=AwebInet225Base;
      a_setup(base);
      Initsslsockets();
   } */
   return base;
}

struct Assl *Tcpopenssl(struct Library *socketbase)
{  struct Assl *assl=NULL;
   if(assl=Assl_initamissl(socketbase))
   {  AwebSslBase=AwebAmisslBase;
   }
   /* else if(assl=Assl_initmiamissl())
   {  AwebSslBase=AwebMiamisslBase;
   } */
   return assl;
}

/* Initialize SSL socket tracking */
static void Initsslsockets(void)
{  if(!ssl_socket_sema_init)
   {  InitSemaphore(&ssl_socket_sema);
      ssl_socket_sema_init=TRUE;
   }
}

/* Store SSL context for a socket - exported for awebamitcp.c */
void Setsslsocket(long sock,struct Assl *assl,struct Library *socketbase,UBYTE *hostname)
{  if(sock>=0 && sock<MAX_SSL_SOCKETS)
   {  ObtainSemaphore(&ssl_socket_sema);
      ssl_sockets[sock]=assl;
      ssl_socketbases[sock]=socketbase;
      if(hostname)
      {  ssl_hostnames[sock]=Dupstr(hostname,-1);
      }
      else
      {  ssl_hostnames[sock]=NULL;
      }
      ReleaseSemaphore(&ssl_socket_sema);
   }
}

/* Get SSL context for a socket - exported for awebamitcp.c */
struct Assl *Getsslsocket(long sock)
{  struct Assl *assl=NULL;
   if(sock>=0 && sock<MAX_SSL_SOCKETS)
   {  ObtainSemaphore(&ssl_socket_sema);
      assl=ssl_sockets[sock];
      ReleaseSemaphore(&ssl_socket_sema);
   }
   return assl;
}

/* Clear SSL context for a socket - exported for awebamitcp.c */
void Clrsslsocket(long sock)
{  if(sock>=0 && sock<MAX_SSL_SOCKETS)
   {  ObtainSemaphore(&ssl_socket_sema);
      if(ssl_hostnames[sock])
      {  FREE(ssl_hostnames[sock]);
         ssl_hostnames[sock]=NULL;
      }
      ssl_sockets[sock]=NULL;
      ssl_socketbases[sock]=NULL;
      ReleaseSemaphore(&ssl_socket_sema);
   }
}

/* Get task SSL context - exported from tcp.c */
extern struct Assl *GetTaskSSLContext(void);
extern struct Library *GetTaskSSLSocketBase(void);
extern void SetTaskSSLContext(struct Assl *assl,struct Library *socketbase);
extern void ClearTaskSSLContext(void);

