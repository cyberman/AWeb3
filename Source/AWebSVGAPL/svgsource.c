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

/* svgsource.c - AWeb SVG plugin sourcedriver */

#include "pluginlib.h"
#include "awebsvg.h"
#include "xmlparse.h"
#include "ezlists.h"
#include "vrastport.h"
#include <libraries/awebplugin.h>
#include <exec/memory.h>
#include <graphics/gfx.h>
#include <intuition/intuitionbase.h>
#include <proto/awebplugin.h>
#include <proto/exec.h>
#include <proto/graphics.h>
#include <proto/utility.h>
#include <proto/dos.h>
#include <proto/intuition.h>

/* A struct Datablock holds one block of data. */
struct Datablock
{  NODE(Datablock);
   UBYTE *data;
   long length;
};

/* The object instance data for the source driver */
struct Svgsource
{  struct Sourcedriver sourcedriver;
   struct Aobject *source;
   struct Aobject *task;
   LIST(Datablock) data;
   long width,height;
   struct BitMap *bitmap;
   UBYTE *mask;
   long memory;
   struct SignalSemaphore sema;
   USHORT flags;
};

/* Svgsource flags: */
#define SVGSF_EOF          0x0001
#define SVGSF_DISPLAYED    0x0002
#define SVGSF_MEMORY       0x0004
#define SVGSF_IMAGEREADY   0x0010

/* Forward declaration */
static void Parsertask(struct Svgsource *ss);

/* Start the parser task */
static void Startparser(struct Svgsource *ss)
{  struct Screen *screen=NULL;
   if(Agetattr(Aweb(),AOAPP_Screenvalid))
   {  Agetattrs(Aweb(),AOAPP_Screen,&screen,TAG_END);
      if(screen && !ss->task)
      {  if(ss->task=Anewobject(AOTP_TASK,
            AOTSK_Entry,Parsertask,
            AOTSK_Name,"AWebSvg parser",
            AOTSK_Userdata,ss,
            AOBJ_Target,ss,
            TAG_END))
         {  Asetattrs(ss->task,AOTSK_Start,TRUE,TAG_END);
         }
      }
   }
}

/* Read the next byte from data blocks */
/* Note: Reserved for future streaming parser implementation */
#if 0
UBYTE Readbyte(struct Parser *parser)
{  struct Datablock *db;
   BOOL wait;
   UBYTE retval=0;
   for(;;)
   {  wait=FALSE;
      if(parser->current)
      {  if(++parser->currentbyte>=parser->current->length)
         {  ObtainSemaphore(&parser->source->sema);
            db=parser->current->next;
            if(db->next)
            {  parser->current=db;
               parser->currentbyte=0;
            }
            else if(parser->source->flags&SVGSF_EOF)
            {  parser->flags|=PARF_EOF;
            }
            else
            {  wait=TRUE;
            }
            ReleaseSemaphore(&parser->source->sema);
         }
      }
      else
      {  ObtainSemaphore(&parser->source->sema);
         db=parser->source->data.first;
         if(db->next)
         {  parser->current=db;
            parser->currentbyte=0;
         }
         else if(parser->source->flags&SVGSF_EOF)
         {  parser->flags|=PARF_EOF;
         }
         else
         {  wait=TRUE;
         }
         ReleaseSemaphore(&parser->source->sema);
      }
      if(!wait)
      {  if(!(parser->flags&PARF_EOF))
         {  retval=parser->current->data[parser->currentbyte];
         }
         break;
      }
      Waittask(0);
   }
   return retval;
}
#endif

/* Parser task - parses SVG and creates bitmap */
static void Parsertask(struct Svgsource *ss)
{  struct Datablock *db;
   UBYTE *buffer;
   long buflen;
   LONG token;
   UBYTE *name;
   LONG namelen;
   struct Screen *screen=NULL;
   struct BitMap *bitmap=NULL;
   struct RastPort rp;
   struct VRastPort *vrp=NULL;
   LONG width=100,height=100;
   LONG svgwidth=0,svgheight=0;
   LONG x,y,w,h,cx,cy,r,rx,ry,x1,y1,x2,y2;
   UBYTE fillpen=1,strokepen=0;

   /* Collect all data into a buffer for XML parsing */
   ObtainSemaphore(&ss->sema);
   buflen=0;
   for(db=ss->data.first;db->next;db=db->next)
   {  buflen+=db->length;
   }
   ReleaseSemaphore(&ss->sema);

   if(buflen==0) goto cleanup;

   buffer=(UBYTE *)AllocMem(buflen+1,MEMF_ANY);
   if(!buffer) goto cleanup;
   buffer[buflen]=0;

   ObtainSemaphore(&ss->sema);
   buflen=0;
   for(db=ss->data.first;db->next;db=db->next)
   {  CopyMem(db->data,buffer+buflen,db->length);
      buflen+=db->length;
   }
   ReleaseSemaphore(&ss->sema);

   /* Get screen for bitmap creation */
   if(Agetattr(Aweb(),AOAPP_Screenvalid))
   {  Agetattrs(Aweb(),AOAPP_Screen,&screen,TAG_END);
   }
   if(!screen) goto cleanup;

   /* Initialize XML parser */
   {  struct XmlParser xml;
      XmlInitParser(&xml,buffer,buflen);

      /* Parse SVG root element to get dimensions */
      token=XmlGetToken(&xml);
      while(token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
      {  if(token==XMLTOK_START_TAG)
         {  name=XmlGetTokenName(&xml,&namelen);
            if(namelen==3 && Strnicmp(name,"svg",3)==0)
            {  /* Parse SVG attributes */
               while((token=XmlGetToken(&xml))==XMLTOK_ATTR)
               {  UBYTE *attrname=XmlGetAttrName(&xml,&namelen);
                  LONG attrnamelen=namelen;
                  UBYTE *attrvalue=XmlGetAttrValue(&xml,&namelen);
                  LONG attrvaluelen=namelen;
                  LONG tempval;
                  if(attrnamelen==5 && Strnicmp(attrname,"width",5)==0 && attrvaluelen>0)
                  {  if(StrToLong(attrvalue,&tempval)>0) svgwidth=tempval;
                  }
                  else if(attrnamelen==6 && Strnicmp(attrname,"height",6)==0 && attrvaluelen>0)
                  {  if(StrToLong(attrvalue,&tempval)>0) svgheight=tempval;
                  }
               }
               if(svgwidth>0) width=svgwidth;
               if(svgheight>0) height=svgheight;
               break;
            }
         }
         token=XmlGetToken(&xml);
      }

      /* Create bitmap */
      if(width<=0) width=100;
      if(height<=0) height=100;
      bitmap=AllocBitMap(width,height,8,BMF_CLEAR,screen->RastPort.BitMap);
      if(!bitmap) goto cleanup;

      InitRastPort(&rp);
      rp.BitMap=bitmap;
      SetAPen(&rp,0);
      RectFill(&rp,0,0,width-1,height-1);

      /* Create VRastPort for vector rendering */
      vrp=MakeVRastPortTags(VRP_RastPort,&rp,
                            VRP_XScale,0x10000,
                            VRP_YScale,0x10000,
                            VRP_LeftBound,0,
                            VRP_TopBound,0,
                            VRP_RightBound,width-1,
                            VRP_BottomBound,height-1,
                            TAG_END);
      if(!vrp) goto cleanup;

      /* Reinitialize parser for element parsing */
      XmlInitParser(&xml,buffer,buflen);
      SetAPen(&rp,fillpen);

      /* Parse SVG elements */
      while((token=XmlGetToken(&xml))!=XMLTOK_EOF && token!=XMLTOK_ERROR)
      {  if(token==XMLTOK_START_TAG || token==XMLTOK_EMPTY_TAG)
         {  name=XmlGetTokenName(&xml,&namelen);
            x=y=w=h=cx=cy=r=rx=ry=x1=y1=x2=y2=0;
            fillpen=1;
            strokepen=0;

            /* Parse attributes */
            while((token=XmlGetToken(&xml))==XMLTOK_ATTR)
            {  UBYTE *attrname=XmlGetAttrName(&xml,&namelen);
               LONG attrnamelen=namelen;
               UBYTE *attrvalue=XmlGetAttrValue(&xml,&namelen);
               LONG attrvaluelen=namelen;
               LONG tempval;
               if(attrnamelen>0 && attrvaluelen>0)
               {  if(attrnamelen==1 && attrname[0]=='x')
                  {  if(StrToLong(attrvalue,&tempval)>0) x=tempval;
                  }
                  else if(attrnamelen==1 && attrname[0]=='y')
                  {  if(StrToLong(attrvalue,&tempval)>0) y=tempval;
                  }
                  else if(attrnamelen==1 && attrname[0]=='r')
                  {  if(StrToLong(attrvalue,&tempval)>0) r=tempval;
                  }
                  else if(attrnamelen==5 && Strnicmp(attrname,"width",5)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) w=tempval;
                  }
                  else if(attrnamelen==6 && Strnicmp(attrname,"height",6)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) h=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"cx",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) cx=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"cy",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) cy=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"rx",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) rx=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"ry",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) ry=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"x1",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) x1=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"y1",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) y1=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"x2",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) x2=tempval;
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"y2",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) y2=tempval;
                  }
               }
            }

            /* Render based on element type */
            if(namelen==4 && Strnicmp(name,"rect",4)==0 && w>0 && h>0)
            {  SetAPen(&rp,fillpen);
               VAreaBox(vrp,x,y,x+w-1,y+h-1);
            }
            else if(namelen==6 && Strnicmp(name,"circle",6)==0 && r>0)
            {  SetAPen(&rp,fillpen);
               VAreaEllipse(vrp,cx,cy,r,r);
            }
            else if(namelen==7 && Strnicmp(name,"ellipse",7)==0 && rx>0 && ry>0)
            {  SetAPen(&rp,fillpen);
               VAreaEllipse(vrp,cx,cy,rx,ry);
            }
            else if(namelen==4 && Strnicmp(name,"line",4)==0)
            {  SetAPen(&rp,strokepen);
               VDrawLine(vrp,x1,y1,x2,y2);
            }
         }
      }

      /* Save bitmap to source */
      ObtainSemaphore(&ss->sema);
      ss->width=width;
      ss->height=height;
      ss->bitmap=bitmap;
      bitmap=NULL;
      ss->flags|=SVGSF_IMAGEREADY;
      ReleaseSemaphore(&ss->sema);

      /* Notify that bitmap is ready */
      Anotifyset(ss->source,
                 AOSVG_Width,width,
                 AOSVG_Height,height,
                 AOSVG_Bitmap,ss->bitmap,
                 AOSVG_Imgready,TRUE,
                 TAG_END);
   }

cleanup:
   if(vrp) FreeVRastPort(vrp);
   if(bitmap) FreeBitMap(bitmap);
   if(buffer) FreeMem(buffer,buflen+1);
   Asetattrs(ss->source,AOSVG_Parseready,TRUE,AOSVG_Jsready,TRUE,TAG_END);
}

/* Source driver dispatcher */
static ULONG Setsource(struct Svgsource *ss,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   Amethodas(AOTP_SOURCEDRIVER,(struct Aobject *)ss,AOM_SET,amset->tags);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOSDV_Source:
            ss->source=(struct Aobject *)tag->ti_Data;
            break;
      }
   }
   return 0;
}

static struct Svgsource *Newsource(struct Amset *amset)
{  struct Svgsource *ss;
   if(ss=(struct Svgsource *)Allocobject(PluginBase->sourcedriver,sizeof(struct Svgsource),amset))
   {  NEWLIST(&ss->data);
      InitSemaphore(&ss->sema);
      ss->width=0;
      ss->height=0;
      ss->bitmap=NULL;
      ss->mask=NULL;
      ss->memory=0;
      ss->flags=0;
      ss->source=NULL;
      ss->task=NULL;
      Setsource(ss,amset);
   }
   return ss;
}

static void Disposesource(struct Svgsource *ss)
{  struct Datablock *db;
   if(ss->bitmap) FreeBitMap(ss->bitmap);
   if(ss->mask) FreeMem(ss->mask,ss->width*ss->height);
   while((db=REMHEAD(&ss->data)))
   {  FreeMem(db->data,db->length);
      FreeMem(db,sizeof(struct Datablock));
   }
   AmethodasA(AOTP_SOURCEDRIVER,(struct Aobject *)ss,AOM_DISPOSE);
}

static ULONG Addchildsource(struct Svgsource *ss,struct Amadd *amadd)
{  if(amadd->relation==AOREL_SRC_COPY)
   {  ObtainSemaphore(&ss->sema);
      if(ss->bitmap && (ss->flags&SVGSF_IMAGEREADY))
      {  Asetattrs(amadd->child,
            AOSVG_Bitmap,ss->bitmap,
            AOSVG_Mask,ss->mask,
            AOSVG_Width,ss->width,
            AOSVG_Height,ss->height,
            AOSVG_Imgready,TRUE,
            TAG_END);
      }
      ReleaseSemaphore(&ss->sema);
   }
   return 0;
}

static ULONG Srcupdatesource(struct Svgsource *ss,struct Amsrcupdate *amsrcupdate)
{  struct TagItem *tag,*tstate;
   UBYTE *data=NULL;
   long datalength=0;
   struct Datablock *db;
   BOOL eof_received=FALSE;

   tstate=amsrcupdate->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOURL_Data:
            data=(UBYTE *)tag->ti_Data;
            break;
         case AOURL_Datalength:
            datalength=tag->ti_Data;
            break;
         case AOURL_Eof:
            if(tag->ti_Data)
            {  ss->flags|=SVGSF_EOF;
               eof_received=TRUE;
            }
            break;
      }
   }
   if(data && datalength>0)
   {  db=(struct Datablock *)AllocMem(sizeof(struct Datablock),MEMF_ANY);
      if(db)
      {  db->data=(UBYTE *)AllocMem(datalength,MEMF_ANY);
         if(db->data)
         {  CopyMem(data,db->data,datalength);
            db->length=datalength;
            ObtainSemaphore(&ss->sema);
            ADDTAIL(&ss->data,db);
            ReleaseSemaphore(&ss->sema);
         }
         else
         {  FreeMem(db,sizeof(struct Datablock));
         }
      }
   }
   /* Start parser when EOF is received */
   if(eof_received && !ss->task)
   {  Startparser(ss);
   }
   return 0;
}

__asm __saveds ULONG Dispatchsource(register __a0 struct Aobject *obj,register __a1 struct Amessage *amsg)
{  struct Svgsource *ss=(struct Svgsource *)obj;
   ULONG result=0;
   switch(amsg->method)
   {  case AOM_NEW:
         result=(ULONG)Newsource((struct Amset *)amsg);
         break;
      case AOM_SET:
         result=Setsource(ss,(struct Amset *)amsg);
         break;
      case AOM_DISPOSE:
         Disposesource(ss);
         break;
      case AOM_SRCUPDATE:
         result=Srcupdatesource(ss,(struct Amsrcupdate *)amsg);
         break;
      case AOM_ADDCHILD:
         result=Addchildsource(ss,(struct Amadd *)amsg);
         break;
      default:
         result=AmethodasA(AOTP_SOURCEDRIVER,(struct Aobject *)ss,amsg);
         break;
   }
   return result;
}

