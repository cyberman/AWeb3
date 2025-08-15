/**********************************************************************
 * 
 * This file is part of the AWeb-II distribution
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

#include <proto/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <exec/libraries.h>
#include <sys/socket.h>
#include <sys/types.h>

extern int errno;

__asm int amitcp_recv(register __d0 int a,
   register __a0 char *b,
   register __d1 int c,
   register __d2 int d,
   register __a1 struct Library *SocketBase)
{  return recv(a, b, c, d);
}

__asm int amitcp_send(register __d0 int a,
   register __a0 char *b,
   register __d1 int c,
   register __d2 int d,
   register __a1 struct Library *SocketBase)
{  return send(a, b, c, d);
}

__asm int amitcp_socket(register __d0 int a,
   register __d1 int b,
   register __d2 int c,
   register __a0 struct Library *SocketBase)
{  return socket(a, b, c);
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
   sad.sin_len=sizeof(sad);
   sad.sin_family=hent->h_addrtype;
   sad.sin_port=port;
   sad.sin_addr.s_addr=*(unsigned long *)(*hent->h_addr_list);
   return connect(a, (struct sockaddr *)&sad, sizeof(sad));
}

__asm int amitcp_connect2(register __d0 int a,
   register __d1 int addrtype,
   register __d2 unsigned long addr,
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
   register __a1 socklen_t *c,
   register __a2 struct Library *SocketBase)
{
   return getsockname(a, b, c);
}

__asm int amitcp_setsockopt(register __d0 int a,
   register __d1 int b,
   register __d2 int c,
   register __a0 const void *d,
   register __d3 int e,
   register __a1 struct Library *SocketBase)
{
   return setsockopt(a, b, c, d, e);
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
   register __a1 socklen_t *c,
   register __a2 struct Library *SocketBase)
{
   return accept(a, b, c);
}

__asm int amitcp_shutdown(register __d0 int a,
   register __d1 int b,
   register __a0 struct Library *SocketBase)
{  return shutdown(a, b);
}

__asm int amitcp_close(register __d0 int a,
   register __a0 struct Library *SocketBase)
{  return CloseSocket(a);
}

/* Proper socket system initialization with error handling */
__asm int amitcp_setup(register __a0 struct Library *SocketBase)
{  /* Initialize socket system - AmiTCP/Roadshow handle this automatically */
   return 0; /* Success */
}

/* Proper socket system cleanup */
__asm void amitcp_cleanup(register __a0 struct Library *SocketBase)
{  /* AmiTCP/Roadshow handle cleanup automatically */
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

/* Library jump table - referenced by awebamitcplib structure */
static struct Jumptab jumptab[]=
{
   JMP,amitcp_setsockopt,
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
   JMP,amitcp_cleanup,
   JMP,amitcp_setup,
   JMP,amitcp_dummy, /* Extfunc */
   JMP,amitcp_dummy, /* Expunge */
   JMP,amitcp_dummy, /* Close */
   JMP,amitcp_dummy, /* Open */
};
/* Library structure - references jumptab for function dispatch */
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
   
