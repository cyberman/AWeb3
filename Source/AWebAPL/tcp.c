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

/* tcp.c - AWeb TCP interface */

#ifndef LOCALONLY

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include "aweb.h"
#include "tcperr.h"
#include "application.h"
#include "awebtcp.h"
#include "fetchdriver.h"
#include <dos/dostags.h>


/* Forward declarations */
extern struct Assl *Tcpopenssl(struct Library *socketbase);
extern void Assl_cleanup(struct Assl *assl);
extern void Assl_closessl(struct Assl *assl);

/* Forward declarations for SSL task context functions */
struct Assl *GetTaskSSLContext(void);
struct Library *GetTaskSSLSocketBase(void);
void SetTaskSSLContext(struct Assl *assl,struct Library *socketbase);
void ClearTaskSSLContext(void);

struct SignalSemaphore tcpsema;
BOOL startedtcp=FALSE;

/* SSL context per task - store SSL context for current task when FDVF_SSL is set */
struct Assl *task_ssl_context = NULL;
struct Library *task_ssl_socketbase = NULL;
struct Task *task_ssl_task = NULL;
struct SignalSemaphore task_ssl_sema;
BOOL task_ssl_sema_init = FALSE;

/*-----------------------------------------------------------------------*/

#ifndef DEMOVERSION
static long Spawnsync(UBYTE *cmd,UBYTE *args)
{  UBYTE *scrname,*cmdbuf;
   long result=100;
   long out;
   UBYTE conbuf[64];
   long pl=Copypathlist();
   scrname=(UBYTE *)Agetattr(Aweb(),AOAPP_Screenname);
   if(!args) args="";
   if(!scrname) scrname="";
   if(cmdbuf=ALLOCTYPE(UBYTE,strlen(cmd)+Pformatlength(args,"n",&scrname)+32,0))
   {  sprintf(cmdbuf,"%s ",cmd);
      Pformat(cmdbuf+strlen(cmdbuf),args,"n",&scrname,TRUE);
      strcpy(conbuf,"CON:////");
      strcat(conbuf,AWEBSTR(MSG_AWEB_EXTWINTITLE));
      strcat(conbuf,"/AUTO/CLOSE");
      out=Open(conbuf,MODE_NEWFILE);
      if(out)
      {  result=(0<=SystemTags(cmdbuf,
            SYS_Input,out,
            SYS_Output,NULL,
            NP_Path,pl,
            TAG_END));
         if(!result) Freepathlist(pl);
         Close(out);
      }
      FREE(cmdbuf);
   }
   return result;
}
#endif

/*-----------------------------------------------------------------------*/

BOOL Inittcp(void)
{  InitSemaphore(&tcpsema);
   if(!task_ssl_sema_init)
   {  InitSemaphore(&task_ssl_sema);
      task_ssl_sema_init=TRUE;
   }
   return TRUE;
}

void Freetcp(void)
{  
#ifndef DEMOVERSION
   if(startedtcp && prefs.endtcpcmd)
   {  if(Syncrequest(AWEBSTR(MSG_REQUEST_TITLE),haiku?HAIKU21:AWEBSTR(MSG_TCP_ENDTCP),
         AWEBSTR(MSG_TCP_BUTTONS),0))
      {  Spawnsync(prefs.endtcpcmd,prefs.endtcpargs);
      }
   }
#endif
   /* Cleanup all task SSL contexts at application shutdown */
   /* This ensures proper cleanup of SSL resources for all tasks */
   ClearTaskSSLContext();
}

struct Library *Opentcp(struct Library **base,struct Fetchdriver *fd,BOOL autocon)
{  BOOL started=FALSE;
   UBYTE *cmd=NULL,*args=NULL;
   struct Process *proc=(struct Process *)FindTask(NULL);
   APTR windowptr=proc->pr_WindowPtr;
   proc->pr_WindowPtr=(APTR)-1;
#ifdef DEMOVERSION
   if(*base=Tcpopenlib())
#else
   if(!AttemptSemaphore(&tcpsema))
   {  if(autocon) Tcpmessage(fd,TCPMSG_TCPSTART);
      ObtainSemaphore(&tcpsema);
   }
   for(;;)
   {  if(*base=Tcpopenlib())
      if(*base) break;
      if(started) break;
      if(!autocon) break;
      ObtainSemaphore(&prefssema);
      if(prefs.starttcpcmd && *prefs.starttcpcmd)
      {  cmd=Dupstr(prefs.starttcpcmd,-1);
         args=Dupstr(prefs.starttcpargs,-1);
      }
      ReleaseSemaphore(&prefssema);
      if(!cmd) break;
      Tcpmessage(fd,TCPMSG_TCPSTART);
      Spawnsync(cmd,args);
      started=startedtcp=TRUE;
   }
   ReleaseSemaphore(&tcpsema);
   if(cmd) FREE(cmd);
   if(args) FREE(args);
#endif
   proc->pr_WindowPtr=windowptr;
   /* Initialize SSL for protocols that need it (e.g., Gemini, HTTPS) */
   /* HTTP/HTTPS also initializes SSL separately in Openlibraries() and stores it in hi->assl */
   /* The task SSL context initialized here is used by awebamitcp.c:amitcp_connect() for */
   /* automatic SSL on non-443 ports (e.g., Gemini on port 1965) */
   /* HTTP on port 443 uses its own hi->assl and ignores the task SSL context, so no conflict */
   if(*base && fd && (fd->flags&FDVF_SSL))
   {  struct Assl *assl=Tcpopenssl(*base);
      if(assl)
      {  SetTaskSSLContext(assl,*base);
      }
   }
   return ((*base)?AwebTcpBase:NULL);
}

/* Get task SSL context - exported for awebtcp.c and awebamitcp.c */
struct Assl *GetTaskSSLContext(void)
{  struct Task *task=FindTask(NULL);
   struct Assl *assl=NULL;
   if(task && task_ssl_sema_init)
   {  ObtainSemaphore(&task_ssl_sema);
      if(task_ssl_task==task)
      {  assl=task_ssl_context;
      }
      ReleaseSemaphore(&task_ssl_sema);
   }
   return assl;
}

struct Library *GetTaskSSLSocketBase(void)
{  struct Task *task=FindTask(NULL);
   struct Library *base=NULL;
   if(task && task_ssl_sema_init)
   {  ObtainSemaphore(&task_ssl_sema);
      if(task_ssl_task==task)
      {  base=task_ssl_socketbase;
      }
      ReleaseSemaphore(&task_ssl_sema);
   }
   return base;
}

void SetTaskSSLContext(struct Assl *assl,struct Library *socketbase)
{  struct Task *task=FindTask(NULL);
   if(task)
   {  if(!task_ssl_sema_init)
      {  InitSemaphore(&task_ssl_sema);
         task_ssl_sema_init=TRUE;
      }
      ObtainSemaphore(&task_ssl_sema);
      task_ssl_context=assl;
      task_ssl_socketbase=socketbase;
      task_ssl_task=task;
      ReleaseSemaphore(&task_ssl_sema);
   }
}

void ClearTaskSSLContext(void)
{  struct Task *task=FindTask(NULL);
   struct Assl *assl_to_cleanup=NULL;
   if(task && task_ssl_sema_init)
   {  ObtainSemaphore(&task_ssl_sema);
      if(task_ssl_task==task)
      {  if(task_ssl_context)
         {  /* Save pointer before clearing - we'll cleanup after releasing semaphore */
            assl_to_cleanup=task_ssl_context;
            task_ssl_context=NULL;
         }
         task_ssl_socketbase=NULL;
         task_ssl_task=NULL;
      }
      ReleaseSemaphore(&task_ssl_sema);
   }
   /* Cleanup SSL outside of semaphore to prevent deadlock */
   /* Follow same pattern as http.c: Assl_cleanup() then FREE() */
   /* Note: Assl_cleanup() internally calls Assl_closessl(), so we don't call it separately */
   /* This matches the HTTP pattern where Assl_closessl() is called before socket close, */
   /* and Assl_cleanup() is called after a_cleanup() but before CloseLibrary() */
   if(assl_to_cleanup)
   {  /* 1. Cleanup Assl struct (calls Assl_closessl() internally, decrements task ref count, calls CleanupAmiSSL for subprocesses) */
      Assl_cleanup(assl_to_cleanup);
      /* 2. Free the Assl struct itself - must happen after Assl_cleanup() */
      /* Assl_cleanup() no longer frees the struct to prevent use-after-free crashes */
      FREE(assl_to_cleanup);
   }
}

#else /* LOCALONLY */

#include <proto/exec.h>
#include "aweb.h"
#include "fetchdriver.h"

/* Stub functions for LOCALONLY build */
struct Library *Opentcp(struct Library **base,struct Fetchdriver *fd,BOOL autocon)
{  if(base) *base=0;
   return 0;
}

BOOL Inittcp(void)
{  return 1;
}

void Freetcp(void)
{
}

struct Assl *GetTaskSSLContext(void)
{  return 0;
}

struct Library *GetTaskSSLSocketBase(void)
{  return 0;
}

void SetTaskSSLContext(struct Assl *assl,struct Library *socketbase)
{
}

void ClearTaskSSLContext(void)
{
}

#endif /* LOCALONLY */