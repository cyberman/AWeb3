/**********************************************************************
 * 
 * This file is part of the AWeb distribution
 *
 * Copyright (C) 2025 amigazen project
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

/* svgcopy.c - AWeb SVG plugin copydriver */

#include "pluginlib.h"
#include "awebsvg.h"
#include "vrastport.h"
#include <libraries/awebplugin.h>
#include <exec/memory.h>
#include <graphics/gfx.h>
#include <proto/awebplugin.h>
#include <proto/exec.h>
#include <proto/graphics.h>
#include <proto/utility.h>

struct Svgcopy
{  struct Copydriver copydriver;
   struct Aobject *copy;
   struct BitMap *bitmap;
   UBYTE *mask;
   long width,height;
   USHORT flags;
};

/* Svgcopy flags: */
#define SVGCF_DISPLAYED    0x0001
#define SVGCF_READY        0x0002
#define SVGCF_OURBITMAP    0x0004
#define SVGCF_JSREADY      0x0008

/* Limit coordinate (x), offset (dx), width (w) to a region (minx,maxx) */
static void Clipcopy(long *x,long *dx,long *w,long minx,long maxx)
{  if(minx>*x)
   {  (*dx)+=minx-*x;
      (*w)-=minx-*x;
      *x=minx;
   }
   if(maxx<*x+*w)
   {  *w=maxx-*x+1;
   }
}

/* Render these rows of our bitmap. */
static void Renderrows(struct Svgcopy *sc,struct Coords *coo,
   long minx,long miny,long maxx,long maxy,long minrow,long maxrow)
{  long x,y;
   long dx,dy;
   long w,h;
   if(coo && coo->rp)
   {  x=sc->copydriver.aox+coo->dx;
      y=sc->copydriver.aoy+coo->dy+minrow;
      dx=0;
      dy=minrow;
      w=sc->width;
      h=maxrow-minrow+1;
      Clipcopy(&x,&dx,&w,coo->minx,coo->maxx);
      Clipcopy(&y,&dy,&h,coo->miny,coo->maxy);
      Clipcopy(&x,&dx,&w,minx+coo->dx,maxx+coo->dx);
      Clipcopy(&y,&dy,&h,miny+coo->dy,maxy+coo->dy);
      if(w>0 && h>0)
      {  if(sc->mask)
         {  BltMaskBitMapRastPort(sc->bitmap,dx,dy,coo->rp,x,y,w,h,0xe0,sc->mask);
         }
         else
         {  BltBitMapRastPort(sc->bitmap,dx,dy,coo->rp,x,y,w,h,0xc0);
         }
      }
   }

   if(sc->flags&SVGCF_JSREADY)
   {  Asetattrs(sc->copy,AOCPY_Onimgload,TRUE,TAG_END);
   }
}

/* Copy driver dispatcher */
static struct Svgcopy *Newcopy(struct Amset *amset)
{  struct Svgcopy *sc;
   if(sc=(struct Svgcopy *)Allocobject(PluginBase->copydriver,sizeof(struct Svgcopy),amset))
   {  sc->bitmap=NULL;
      sc->mask=NULL;
      sc->width=0;
      sc->height=0;
      sc->flags=0;
   }
   return sc;
}

static void Disposecopy(struct Svgcopy *sc)
{  if(sc->flags&SVGCF_OURBITMAP)
   {  if(sc->bitmap) FreeBitMap(sc->bitmap);
      if(sc->mask) FreeMem(sc->mask,sc->width*sc->height);
   }
   AmethodasA(AOTP_COPYDRIVER,(struct Aobject *)sc,AOM_DISPOSE);
}

static ULONG Getcopy(struct Svgcopy *sc,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   AmethodasA(AOTP_COPYDRIVER,(struct Aobject *)sc,(struct Amessage *)amset);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {           case AOCDV_Imagewidth:
            PUTATTR(tag,(sc->bitmap && (sc->flags&SVGCF_READY))?sc->width:0);
            break;
         case AOCDV_Imageheight:
            PUTATTR(tag,(sc->bitmap && (sc->flags&SVGCF_READY))?sc->height:0);
            break;
      }
   }
   return 0;
}

static ULONG Setcopy(struct Svgcopy *sc,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   Amethodas(AOTP_COPYDRIVER,(struct Aobject *)sc,AOM_SET,amset->tags);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOCDV_Sourcedriver:
            {  struct Aobject *sd=(struct Aobject *)tag->ti_Data;
               long width,height;
               struct BitMap *bitmap;
               UBYTE *mask;
               if(Agetattrs(sd,AOSVG_Width,(ULONG)&width,
                            AOSVG_Height,(ULONG)&height,
                            AOSVG_Bitmap,(ULONG)&bitmap,
                            AOSVG_Mask,(ULONG)&mask,
                            TAG_END))
               {  sc->width=width;
                  sc->height=height;
                  sc->bitmap=bitmap;
                  sc->mask=mask;
                  sc->flags|=SVGCF_READY;
               }
            }
            break;
      }
   }
   return 0;
}

static ULONG Rendercopy(struct Svgcopy *sc,struct Amrender *amrender)
{  struct Coords *coo;
   coo=amrender->coords;
   coo=Clipcoords(sc->copydriver.cframe,coo);
   if(sc->bitmap && (sc->flags&SVGCF_READY) && coo)
   {  Renderrows(sc,coo,0,0,sc->width-1,sc->height-1,0,sc->height-1);
   }
   if(coo && coo!=amrender->coords) Unclipcoords(coo);
   return 0;
}

__asm __saveds ULONG Dispatchcopy(register __a0 struct Aobject *obj,register __a1 struct Amessage *amsg)
{  struct Svgcopy *sc=(struct Svgcopy *)obj;
   ULONG result=0;
   switch(amsg->method)
   {  case AOM_NEW:
         result=(ULONG)Newcopy((struct Amset *)amsg);
         break;
      case AOM_DISPOSE:
         Disposecopy(sc);
         break;
      case AOM_GET:
         result=Getcopy(sc,(struct Amset *)amsg);
         break;
      case AOM_SET:
         result=Setcopy(sc,(struct Amset *)amsg);
         break;
      case AOM_RENDER:
         result=Rendercopy(sc,(struct Amrender *)amsg);
         break;
      default:
         result=AmethodasA(AOTP_COPYDRIVER,(struct Aobject *)sc,amsg);
         break;
   }
   return result;
}

