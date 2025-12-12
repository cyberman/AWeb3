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

/* awebsvg.c - AWeb SVG plugin main */

#include "pluginlib.h"
#include "awebsvg.h"
#include <string.h>
#include <libraries/awebplugin.h>

#include <proto/awebplugin.h>
#include <proto/exec.h>
#include <proto/utility.h>

/* Library base variables */
struct Library *GfxBase;
struct Library *IntuitionBase;
struct Library *UtilityBase;
struct Library *AwebPluginBase;
struct Library *DOSBase;

ULONG Initpluginlib(struct AwebSvgBase *base)
{  GfxBase=OpenLibrary("graphics.library",39);
   IntuitionBase=OpenLibrary("intuition.library",39);
   UtilityBase=OpenLibrary("utility.library",39);
   AwebPluginBase=OpenLibrary("awebplugin.library",0);
   /* olsen: I need StrToLong() in the library. */
   DOSBase=OpenLibrary("dos.library",37);
   return (ULONG)(GfxBase && IntuitionBase && UtilityBase && AwebPluginBase && DOSBase != NULL);
}

void Expungepluginlib(struct AwebSvgBase *base)
{  if(base->sourcedriver) Amethod(NULL,AOM_INSTALL,base->sourcedriver,NULL);
   if(base->copydriver) Amethod(NULL,AOM_INSTALL,base->copydriver,NULL);
   if(AwebPluginBase) CloseLibrary(AwebPluginBase);
   if(UtilityBase) CloseLibrary(UtilityBase);
   if(IntuitionBase) CloseLibrary(IntuitionBase);
   if(GfxBase) CloseLibrary(GfxBase);
   if(DOSBase != NULL) CloseLibrary(DOSBase);
}

__asm ULONG Initplugin(register __a0 struct Plugininfo *pi)
{  if(!PluginBase->sourcedriver)
   {  PluginBase->sourcedriver=Amethod(NULL,AOM_INSTALL,0,Dispatchsource);
   }
   if(!PluginBase->copydriver)
   {  PluginBase->copydriver=Amethod(NULL,AOM_INSTALL,0,Dispatchcopy);
   }
   pi->sourcedriver=PluginBase->sourcedriver;
   pi->copydriver=PluginBase->copydriver;
   return (ULONG)(PluginBase->sourcedriver && PluginBase->copydriver);
}

#define ISSAFE(s,f) (s->structsize>=((long)&s->f-(long)s+sizeof(s->f)))

__asm void Queryplugin(register __a0 struct Pluginquery *pq)
{
   if(ISSAFE(pq,command)) pq->command=FALSE;
}   

__asm void Commandplugin(register __a0 struct Plugincommand *pc)
{  if(pc->structsize<sizeof(struct Plugincommand)) return;
   /* olsen: use utility.library instead of the compiler runtime library. */
   pc->rc=10;
}

