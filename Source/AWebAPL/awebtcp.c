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

/* awebtcp.c - AWeb tcp and ssl switch engine */

#include <proto/exec.h>
#include <proto/socket.h>
#include "aweb.h"
#include "awebtcp.h"

extern struct Library *AwebAmiTcpBase;

extern struct Library *AwebAmisslBase;

struct Library *AwebTcpBase;
struct Library *AwebSslBase;
struct Library *SocketBase;

/* Global errno variable for bsdsocket.library */
int errno;

/*-----------------------------------------------------------------------*/

struct Library *Tcpopenlib(void)
{  struct Library *base=NULL;
   
   /* Use bsdsocket.library (Roadshow/AmiTCP) */
   if(base=OpenLibrary("bsdsocket.library",0))
   {  AwebTcpBase=AwebAmiTcpBase;
      
      /* Set errno pointer for proper error handling */
      SetErrnoPtr(&errno, 0);
      
      /* Initialize socket system with proper error handling */
      if(a_setup(base) < 0)
      {  /* Socket initialization failed */
         CloseLibrary(base);
         base = NULL;
      }
   }
   else
   {  /* Show GUI error if bsdsocket.library is missing */
      Lowlevelreq("AWeb requires bsdsocket.library for network access.\nPlease install bsdsocket.library and try again.");
   }
   
   return base;
}

struct Assl *Tcpopenssl(struct Library *socketbase)
{  struct Assl *assl=NULL;
   if(assl=Assl_initamissl(socketbase))
   {  AwebSslBase=AwebAmisslBase;
   }
   return assl;
}
