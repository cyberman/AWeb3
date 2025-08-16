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

extern struct Library *AwebAmiTcpBase;
/* extern struct Library *AwebInet225Base; */

extern struct Library *AwebAmisslBase;
/* extern struct Library *AwebMiamisslBase; */

struct Library *AwebTcpBase;
struct Library *AwebSslBase;

/* Global errno variable for bsdsocket.library */
int errno;

/*-----------------------------------------------------------------------*/

struct Library *Tcpopenlib(void)
{  struct Library *base=NULL;
   if(base=OpenLibrary("bsdsocket.library",0))
   {  AwebTcpBase=AwebAmiTcpBase;
      a_setup(base);
   }
   /* else if(base=OpenLibrary("inet:libs/socket.library",4))
   {  AwebTcpBase=AwebInet225Base;
      a_setup(base);
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
