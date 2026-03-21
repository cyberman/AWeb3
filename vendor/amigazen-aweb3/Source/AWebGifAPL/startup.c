/**********************************************************************
 * 
 * This file is part of the AWeb distribution
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

/* startup.c
 *
 * General startup file for AWeb plugin modules
 *
 * Loosely based on the "demo library in pure C" code
 * by Andreas R. Kleinert.
 *
 * Use this file unchanged as startup file in your own
 * AWeb plugin module project.
 *
 */

#include "pluginlib.h"
#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/resident.h>
#include <proto/exec.h>
#include <proto/awebplugin.h>

/* External library base for debug output */
extern struct Library *AwebPluginBase;

/* Function declarations for the library entry points */
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

extern __asm __saveds ULONG Initplugin(register __a0 struct Plugininfo *pi);

extern __asm __saveds void Queryplugin(
   register __a0 struct Pluginquery *pq);

extern __asm __saveds void Commandplugin(
   register __a0 struct Plugincommand *pc);

/* Function declarations for project dependent hook functions */
extern ULONG Initpluginlib(struct Library *libbase);
extern void Expungepluginlib(struct Library *libbase);

/* Our library base. Probably not really a struct Library but a
 * derived structure. */
struct Library *PluginBase;

/* Our seglist, to be returned when expunged. */
static APTR libseglist;

struct ExecBase *SysBase;

/* Return error when run as a program */
LONG __saveds __asm Libstart(void)
{  return -1;
}

/* Library function table. The library vectors will be
 * generated from these. */
static APTR functable[]=
{  Openlib,
   Closelib,
   Expungelib,
   Extfunclib,
   Initplugin,
   Queryplugin,
   Commandplugin,
   (APTR)-1
};

/* Init table used in library initialization. */
static ULONG inittab[]=
{  PLUGIN_SIZE,         /* Size of library base structure */
   (ULONG) functable,   /* Library function table */
   0,                   /* Library base structure initialization */
   (ULONG) Initlib      /* Initial entry point */
};

static char __aligned libname[]=PLUGIN_LIBNAME;
static char __aligned libid[]=PLUGIN_LIBID;

/* The ROM tag */
struct Resident __aligned romtag=
{  RTC_MATCHWORD,
   &romtag,
   &romtag+1,
   RTF_AUTOINIT,
   PLUGIN_VERSION,
   NT_LIBRARY,
   0,
   libname,
   libid,
   inittab
};

/* Initialization of the library after loading. Most of the library
 * node is already initialized from the data in the ROM tag, except
 * for the revision.
 * Store vital pointers, and call the Initpluginlib hook function. */
__asm __saveds struct Library *Initlib(
   register __a6 struct ExecBase *sysbase,
   register __a0 struct SegList *seglist,
   register __d0 struct Library *libbase)
{  SysBase=sysbase;
   PluginBase=libbase;
   libbase->lib_Revision=PLUGIN_REVISION;
   libseglist=seglist;
#ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Initlib called, sysbase=0x%08lx, seglist=0x%08lx, libbase=0x%08lx\n", (ULONG)sysbase, (ULONG)seglist, (ULONG)libbase);
   }
#endif
   if(!Initpluginlib(libbase))
      {  #ifdef DEBUG_PLUGINS
         if(AwebPluginBase)
      {  Aprintf("GIF: Initlib: Initpluginlib failed, expunging\n");
      }
         #endif
      Expungepluginlib(libbase);
      /* olsen: the following line was missing. */
      FreeMem ((APTR)((ULONG)(libbase) - (ULONG)(libbase->lib_NegSize)), libbase->lib_NegSize + libbase->lib_PosSize);
      libbase=NULL;
   }
#ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Initlib returning 0x%08lx\n", (ULONG)libbase);
   }
#endif
   return libbase;
}

__asm __saveds struct Library *Openlib(
   register __a6 struct Library *libbase)
{  #ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Openlib called, libbase=0x%08lx, OpenCnt=%ld\n", (ULONG)libbase, libbase->lib_OpenCnt);
   }
#endif
   libbase->lib_OpenCnt++;
   libbase->lib_Flags&=~LIBF_DELEXP;
#ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Openlib returning, OpenCnt=%ld\n", libbase->lib_OpenCnt);
   }
#endif
   return libbase;
}

__asm __saveds struct SegList *Closelib(
   register __a6 struct Library *libbase)
{  #ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Closelib called, libbase=0x%08lx, OpenCnt=%ld\n", (ULONG)libbase, libbase->lib_OpenCnt);
   }
#endif
   libbase->lib_OpenCnt--;
   if(libbase->lib_OpenCnt==0 && (libbase->lib_Flags&LIBF_DELEXP))
      {  #ifdef DEBUG_PLUGINS
         if(AwebPluginBase)
      {  Aprintf("GIF: Closelib: Expunging library\n");
      }
         #endif
      return Expungelib(libbase);
   }
#ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Closelib returning NULL, OpenCnt=%ld\n", libbase->lib_OpenCnt);
   }
#endif
   return NULL;
}

__asm __saveds struct SegList *Expungelib(
   register __a6 struct Library *libbase)
{  #ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Expungelib called, libbase=0x%08lx, OpenCnt=%ld\n", (ULONG)libbase, libbase->lib_OpenCnt);
   }
#endif
   if(libbase->lib_OpenCnt==0)
   {  ULONG size=libbase->lib_NegSize+libbase->lib_PosSize;
      UBYTE *ptr=(UBYTE *)libbase-libbase->lib_NegSize;
      #ifdef DEBUG_PLUGINS
      if(AwebPluginBase)
      {  Aprintf("GIF: Expungelib: Removing library, size=%ld\n", size);
      }
      #endif
      Remove((struct Node *)libbase);
      Expungepluginlib(libbase);
      FreeMem(ptr,size);
      #ifdef DEBUG_PLUGINS
      if(AwebPluginBase)
      {  Aprintf("GIF: Expungelib: Done, returning seglist\n");
      }
      #endif
      return libseglist;
   }
   libbase->lib_Flags|=LIBF_DELEXP;
#ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Expungelib: Marked for deletion, returning NULL\n");
   }
#endif
   return NULL;
}

__asm __saveds ULONG Extfunclib(void)
{  #ifdef DEBUG_PLUGINS
   if(AwebPluginBase)
   {  Aprintf("GIF: Extfunclib called\n");
   }
#endif
   return 0;
}

