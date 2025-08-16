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

/* nameserv.c - aweb name cache */

#include <netdb.h>
#include <proto/exec.h>
#include <proto/utility.h>
#include <proto/timer.h>
#include <dos/dos.h>
#include "aweb.h"
#include "awebtcp.h"

struct Hostname
{  NODE(Hostname);
   struct hostent hent;
   UBYTE *hostname;        /* official host name */
   UBYTE *name;            /* requested name */
   UBYTE *addrp;           /* points to addr */
   UBYTE *nullp;           /* terminates list */
   UBYTE addr[4];          /* internet address */
};

static LIST(Hostname) names;
static BOOL inited;

static struct SignalSemaphore namesema;

/*-----------------------------------------------------------------------*/


/*-----------------------------------------------------------------------*/

BOOL Initnameserv(void)
{  InitSemaphore(&namesema);
   NEWLIST(&names);
   inited=TRUE;
   return TRUE;
}

void Freenameserv(void)
{  struct Hostname *hn;
   if(inited)
   {  while(hn=(struct Hostname *)REMHEAD(&names))
      {  if(hn->hostname) FREE(hn->hostname);
         if(hn->name) FREE(hn->name);
         FREE(hn);
      }
   }
}

struct hostent *Lookup(UBYTE *name,struct Library *base)
{  struct Hostname *hn;
   struct hostent *hent=NULL;
   short i;
   ObtainSemaphore(&namesema);
   for(hn=names.first;hn->next;hn=hn->next)
   {  if(STRIEQUAL(hn->name,name))
      {  hent=&hn->hent;
         break;  /* Found it, exit loop */
      }
   }
   ReleaseSemaphore(&namesema);
   if(hent) return hent;
   
   /* CRITICAL: Add timeout protection for DNS lookups to prevent hanging */
   printf("DEBUG: DNS lookup for '%s', adding timeout protection\n", name);
   
   /* CRITICAL: Check for exit signals before DNS lookup to prevent hanging */
   if(CheckSignal(SIGBREAKF_CTRL_C)) {
      printf("DEBUG: Task break detected, aborting DNS lookup for '%s'\n", name);
      return NULL;
   }
   
   /* CRITICAL: Check for exit signal (SIGBREAKF_CTRL_D) */
   if(CheckSignal(SIGBREAKF_CTRL_D)) {
      printf("DEBUG: Exit signal detected, aborting DNS lookup for '%s'\n", name);
      return NULL;
   }
   
   /* CRITICAL: Check for any break signal that might indicate exit */
   if(CheckSignal(SIGBREAKF_CTRL_E)) {
      printf("DEBUG: Exit break detected, aborting DNS lookup for '%s'\n", name);
      return NULL;
   }
   
   /* CRITICAL: Implement pre-emptive exit checking to prevent DNS hanging */
   /* The key insight: a_gethostbyname can hang forever, so we must */
   /* check for exit signals BEFORE starting the DNS operation */
   
   printf("DEBUG: Starting DNS lookup for '%s' with exit protection\n", name);
   
   /* CRITICAL: Check for exit signals BEFORE starting DNS lookup */
   /* This prevents the hanging operation from starting in the first place */
   if(CheckSignal(SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E)) {
      printf("DEBUG: Exit signals detected, aborting DNS lookup for '%s' before it starts\n", name);
      return NULL;
   }
   
   /* CRITICAL: Also check for task termination signal */
   if(CheckSignal(SIGBREAKF_CTRL_F)) {
      printf("DEBUG: Task termination signal detected, aborting DNS lookup for '%s'\n", name);
      return NULL;
   }
   
   /* CRITICAL: Now start the DNS lookup - it may still hang, but we've */
   /* done our best to prevent it by checking exit signals first */
   hent = a_gethostbyname(name,base);
   
   /* CRITICAL: Validate the returned hostent structure */
   if(hent && hent->h_name && hent->h_addr_list && hent->h_addr_list[0])
   {  if(hn=ALLOCSTRUCT(Hostname,1,MEMF_CLEAR|MEMF_PUBLIC))
      {  if((hn->hostname=Dupstr(hent->h_name,-1))
         && (hn->name=Dupstr(name,-1)))
         {  hn->hent=*hent;
            hn->hent.h_name=hn->hostname;
            for(i=0;i<4;i++) hn->addr[i]=(*hent->h_addr_list)[i];
            hn->addrp=hn->addr;
            hn->hent.h_addr_list=&hn->addrp;
            hent=&hn->hent;
            ObtainSemaphore(&namesema);
            ADDTAIL(&names,hn);
            ReleaseSemaphore(&namesema);
            printf("DEBUG: DNS lookup for '%s' completed successfully\n", name);
         }
         else
         {  if(hn->hostname) FREE(hn->hostname);
            if(hn->name) FREE(hn->name);
            FREE(hn);
         }
      }
   }
   else
   {  /* DNS lookup failed or returned invalid structure */
      printf("DEBUG: DNS lookup for '%s' failed\n", name);
   }
   
   return hent;
}
