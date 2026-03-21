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

/* Forward declarations */
static ULONG Setcopy(struct Svgcopy *sc,struct Amset *amset);

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
   Aprintf("SVG: Renderrows called: minrow=%ld, maxrow=%ld\n", minrow, maxrow);
   coo=Clipcoords(sc->copydriver.cframe,coo);
   if(coo && coo->rp && sc->bitmap)
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
      {  Aprintf("SVG: Blitting bitmap: src=(%ld,%ld), dst=(%ld,%ld), size=%ldx%ld\n", dx, dy, x, y, w, h);
         if(sc->mask)
         {  BltMaskBitMapRastPort(sc->bitmap,dx,dy,coo->rp,x,y,w,h,0xe0,sc->mask);
         }
         else
         {  BltBitMapRastPort(sc->bitmap,dx,dy,coo->rp,x,y,w,h,0xc0);
         }
         Aprintf("SVG: Blit completed\n");
      }
      else
      {  Aprintf("SVG: Blit skipped: w=%ld, h=%ld\n", w, h);
      }
   }
   Unclipcoords(coo);

   if(sc->flags&SVGCF_JSREADY)
   {  Asetattrs(sc->copy,AOCPY_Onimgload,TRUE,TAG_END);
   }
}

/* Copy driver dispatcher */
static struct Svgcopy *Newcopy(struct Amset *amset)
{  struct Svgcopy *sc;
   Aprintf("SVG: Newcopy called\n");
   if(sc=Allocobject(PluginBase->copydriver,sizeof(struct Svgcopy),amset))
   {  Aprintf("SVG: Newcopy: Allocated Svgcopy=%p\n", sc);
      sc->bitmap=NULL;
      sc->mask=NULL;
      sc->width=0;
      sc->height=0;
      sc->flags=0;
      Setcopy(sc,amset);
      Aprintf("SVG: Newcopy: Returning sc=%p\n", sc);
   }
   else
   {  Aprintf("SVG: Newcopy: Failed to allocate Svgcopy\n");
   }
   return sc;
}

static void Disposecopy(struct Svgcopy *sc)
{  Aprintf("SVG: Disposecopy called\n");
   if(sc->flags&SVGCF_OURBITMAP)
   {  Aprintf("SVG: Disposecopy: Freeing our bitmap and mask\n");
      if(sc->bitmap) FreeBitMap(sc->bitmap);
      if(sc->mask) FreeVec(sc->mask);
   }
   Amethodas(AOTP_COPYDRIVER,(struct Aobject *)sc,AOM_DISPOSE);
   Aprintf("SVG: Disposecopy: Complete\n");
}

static ULONG Measurecopy(struct Svgcopy *sc,struct Ammeasure *ammeasure)
{  Aprintf("SVG: Measurecopy called, bitmap=%p, ready=%d\n", 
           sc->bitmap, (sc->flags&SVGCF_READY)?1:0);
   if(sc->bitmap && (sc->flags&SVGCF_READY))
   {  sc->copydriver.aow=sc->width;
      sc->copydriver.aoh=sc->height;
      Aprintf("SVG: Measurecopy: Setting dimensions %ldx%ld\n", sc->width, sc->height);
      if(ammeasure->ammr)
      {  ammeasure->ammr->width=sc->copydriver.aow;
         ammeasure->ammr->minwidth=sc->copydriver.aow;
      }
   }
   return 0;
}

static ULONG Layoutcopy(struct Svgcopy *sc,struct Amlayout *amlayout)
{  Aprintf("SVG: Layoutcopy called, bitmap=%p, ready=%d\n",
           sc->bitmap, (sc->flags&SVGCF_READY)?1:0);
   if(sc->bitmap && (sc->flags&SVGCF_READY))
   {  sc->copydriver.aow=sc->width;
      sc->copydriver.aoh=sc->height;
      Aprintf("SVG: Layoutcopy: Setting dimensions %ldx%ld\n", sc->width, sc->height);
   }
   return 0;
}

static ULONG Getcopy(struct Svgcopy *sc,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   Aprintf("SVG: Getcopy called\n");
   AmethodasA(AOTP_COPYDRIVER,(struct Aobject *)sc,(struct Amessage *)amset);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOCDV_Ready:
            Aprintf("SVG: Getcopy: AOCDV_Ready, bitmap=%p\n", sc->bitmap);
            PUTATTR(tag,sc->bitmap?TRUE:FALSE);
            break;
         case AOCDV_Imagebitmap:
            Aprintf("SVG: Getcopy: AOCDV_Imagebitmap, ready=%d, bitmap=%p\n", 
                    (sc->flags&SVGCF_READY)?1:0, sc->bitmap);
            PUTATTR(tag,(sc->flags&SVGCF_READY)?sc->bitmap:NULL);
            break;
         case AOCDV_Imagemask:
            Aprintf("SVG: Getcopy: AOCDV_Imagemask, ready=%d, mask=%p\n",
                    (sc->flags&SVGCF_READY)?1:0, sc->mask);
            PUTATTR(tag,(sc->flags&SVGCF_READY)?sc->mask:NULL);
            break;
         case AOCDV_Imagewidth:
            Aprintf("SVG: Getcopy: AOCDV_Imagewidth, ready=%d, width=%ld\n",
                    (sc->flags&SVGCF_READY)?1:0, sc->width);
            PUTATTR(tag,(sc->bitmap && (sc->flags&SVGCF_READY))?sc->width:0);
            break;
         case AOCDV_Imageheight:
            Aprintf("SVG: Getcopy: AOCDV_Imageheight, ready=%d, height=%ld\n",
                    (sc->flags&SVGCF_READY)?1:0, sc->height);
            PUTATTR(tag,(sc->bitmap && (sc->flags&SVGCF_READY))?sc->height:0);
            break;
         default:
            Aprintf("SVG: Getcopy: Unknown tag 0x%08lx\n", tag->ti_Tag);
            break;
      }
   }
   return 0;
}

static ULONG Setcopy(struct Svgcopy *sc,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   BOOL newbitmap=FALSE;
   BOOL chgbitmap=FALSE;
   BOOL dimchanged=FALSE;
   Aprintf("SVG: Setcopy called\n");
   Amethodas(AOTP_COPYDRIVER,(struct Aobject *)sc,AOM_SET,amset->tags);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOCDV_Copy:
            sc->copy=(struct Aobject *)tag->ti_Data;
            break;
         case AOCDV_Sourcedriver:
            break;
         case AOCDV_Displayed:
            if(tag->ti_Data)
            {  Aprintf("SVG: Copy displayed=TRUE\n");
               sc->flags|=SVGCF_DISPLAYED;
               if(sc->bitmap && (sc->flags&SVGCF_READY) && sc->copydriver.cframe)
               {  chgbitmap=TRUE;
               }
            }
            else
            {  Aprintf("SVG: Copy displayed=FALSE\n");
               sc->flags&=~SVGCF_DISPLAYED;
            }
            break;
         case AOSVG_Bitmap:
            Aprintf("SVG: Copy received bitmap=%p\n", tag->ti_Data);
            sc->bitmap=(struct BitMap *)tag->ti_Data;
            newbitmap=TRUE;
            if(sc->bitmap && (sc->flags&SVGCF_READY))
            {  chgbitmap=TRUE;
            }
            if(!sc->bitmap)
            {  sc->width=0;
               sc->height=0;
               sc->flags&=~SVGCF_READY;
               dimchanged=TRUE;
            }
            break;
         case AOSVG_Mask:
            sc->mask=(UBYTE *)tag->ti_Data;
            break;
         case AOSVG_Width:
            if(tag->ti_Data!=sc->width) dimchanged=TRUE;
            sc->width=tag->ti_Data;
            Aprintf("SVG: Copy width=%ld\n", sc->width);
            break;
         case AOSVG_Height:
            if(tag->ti_Data!=sc->height) dimchanged=TRUE;
            sc->height=tag->ti_Data;
            Aprintf("SVG: Copy height=%ld\n", sc->height);
            break;
         case AOSVG_Imgready:
            if(tag->ti_Data)
            {  Aprintf("SVG: Copy imgready=TRUE\n");
               sc->flags|=SVGCF_READY;
               chgbitmap=TRUE;
            }
            else
            {  sc->flags&=~SVGCF_READY;
            }
            break;
         case AOSVG_Jsready:
            if(tag->ti_Data)
            {  sc->flags|=SVGCF_JSREADY;
            }
            else
            {  sc->flags&=~SVGCF_JSREADY;
            }
            break;
      }
   }
   /* If dimensions changed, notify parent */
   if(dimchanged)
   {  Aprintf("SVG: Setcopy: Dimensions changed, notifying parent\n");
      Asetattrs(sc->copy,AOBJ_Changedchild,sc,TAG_END);
   }
   /* If the bitmap was changed and we are allowed to render ourselves,
    * render the new row(s) now. */
   if(chgbitmap && (sc->flags&SVGCF_DISPLAYED) && sc->copydriver.cframe && sc->bitmap && sc->width>0 && sc->height>0)
   {  Aprintf("SVG: Copy triggering render: bitmap=%p, %ldx%ld, cframe=%p\n", sc->bitmap, sc->width, sc->height, sc->copydriver.cframe);
      Renderrows(sc,NULL,0,0,AMRMAX,AMRMAX,0,sc->height-1);
      Aprintf("SVG: Copy render completed\n");
   }
   else if(chgbitmap)
   {  Aprintf("SVG: Copy would render but: displayed=%d, cframe=%p, bitmap=%p, width=%ld, height=%ld\n",
              (sc->flags&SVGCF_DISPLAYED)?1:0, sc->copydriver.cframe, sc->bitmap, sc->width, sc->height);
   }
   /* If we are not allowed to render ourselves, let our AOTP_COPY object
    * know when the bitmap is complete. */
   else if(chgbitmap && !(sc->flags&SVGCF_DISPLAYED) && (sc->flags&SVGCF_READY))
   {  Aprintf("SVG: Setcopy: Bitmap ready but not displayed, notifying parent\n");
      Asetattrs(sc->copy,AOBJ_Changedchild,sc,TAG_END);
   }
   if(newbitmap && (sc->flags&SVGCF_READY))
   {  Aprintf("SVG: Setcopy: New bitmap ready, setting AOCPY_Onimgload\n");
      Asetattrs(sc->copy,AOCPY_Onimgload,TRUE,TAG_END);
   }
   Aprintf("SVG: Setcopy returning, flags=0x%04x\n", sc->flags);
   return 0;
}

static ULONG Rendercopy(struct Svgcopy *sc,struct Amrender *amrender)
{  struct Coords *coo;
   Aprintf("SVG: Rendercopy called\n");
   coo=amrender->coords;
   coo=Clipcoords(sc->copydriver.cframe,coo);
   Aprintf("SVG: Rendercopy: bitmap=%p, ready=%d, coo=%p\n", 
           sc->bitmap, (sc->flags&SVGCF_READY)?1:0, coo);
   if(sc->bitmap && (sc->flags&SVGCF_READY) && coo)
   {  Aprintf("SVG: Rendercopy: Calling Renderrows\n");
      Renderrows(sc,coo,0,0,sc->width-1,sc->height-1,0,sc->height-1);
      Aprintf("SVG: Rendercopy: Renderrows completed\n");
   }
   else
   {  Aprintf("SVG: Rendercopy: Not rendering: bitmap=%p, ready=%d, coo=%p\n",
              sc->bitmap, (sc->flags&SVGCF_READY)?1:0, coo);
   }
   if(coo && coo!=amrender->coords) Unclipcoords(coo);
   return 0;
}

__asm __saveds ULONG Dispatchcopy(register __a0 struct Aobject *obj,register __a1 struct Amessage *amsg)
{  struct Svgcopy *sc=(struct Svgcopy *)obj;
   ULONG result=0;
   Aprintf("SVG: Dispatchcopy: method=%ld\n", amsg->method);
   switch(amsg->method)
   {  case AOM_NEW:
         Aprintf("SVG: Dispatchcopy: AOM_NEW\n");
         result=(ULONG)Newcopy((struct Amset *)amsg);
         break;
      case AOM_DISPOSE:
         Aprintf("SVG: Dispatchcopy: AOM_DISPOSE\n");
         Disposecopy(sc);
         break;
      case AOM_GET:
         Aprintf("SVG: Dispatchcopy: AOM_GET\n");
         result=Getcopy(sc,(struct Amset *)amsg);
         break;
      case AOM_SET:
         Aprintf("SVG: Dispatchcopy: AOM_SET\n");
         result=Setcopy(sc,(struct Amset *)amsg);
         break;
      case AOM_MEASURE:
         Aprintf("SVG: Dispatchcopy: AOM_MEASURE\n");
         result=Measurecopy(sc,(struct Ammeasure *)amsg);
         break;
      case AOM_LAYOUT:
         Aprintf("SVG: Dispatchcopy: AOM_LAYOUT\n");
         result=Layoutcopy(sc,(struct Amlayout *)amsg);
         break;
      case AOM_RENDER:
         Aprintf("SVG: Dispatchcopy: AOM_RENDER\n");
         result=Rendercopy(sc,(struct Amrender *)amsg);
         break;
      default:
         Aprintf("SVG: Dispatchcopy: Unknown method %ld, calling superclass\n", amsg->method);
         result=AmethodasA(AOTP_COPYDRIVER,(struct Aobject *)sc,amsg);
         break;
   }
   Aprintf("SVG: Dispatchcopy: Returning result=%ld\n", result);
   return result;
}

