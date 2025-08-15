/**********************************************************************
 * 
 * This file is part of the AWeb-II distribution
 *
 * Copyright (C) 2002 Yvon Rozijn
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

/* awebpng.c - AWeb png plugin main */

#include "pluginlib.h"
#include "awebpng.h"
#include <libraries/awebplugin.h>
#include <proto/awebplugin.h>
#include <proto/exec.h>
#include <proto/graphics.h>
#include <proto/utility.h>
#include <proto/Picasso96.h>


/* Library bases */
struct Library *P96Base;
struct Library *AwebPluginBase;

ULONG Initpluginlib(struct AwebPngBase *base)
{  GfxBase=(struct GfxBase *)OpenLibrary("graphics.library",39);
   UtilityBase=OpenLibrary("utility.library",39);
   P96Base=OpenLibrary("Picasso96.library",0);
   AwebPluginBase=OpenLibrary("awebplugin.library",0);
   return (ULONG)(GfxBase && UtilityBase && AwebPluginBase);
}

void Expungepluginlib(struct AwebPngBase *base)
{  if(base->sourcedriver) Amethod(NULL,AOM_INSTALL,base->sourcedriver,NULL);
   if(base->copydriver) Amethod(NULL,AOM_INSTALL,base->copydriver,NULL);
   if(P96Base) CloseLibrary(P96Base);
   if(AwebPluginBase) CloseLibrary(AwebPluginBase);
   if(UtilityBase) CloseLibrary(UtilityBase);
   if(GfxBase) CloseLibrary(GfxBase);
}

__asm __saveds ULONG Initplugin(register __a0 struct Plugininfo *pi)
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
