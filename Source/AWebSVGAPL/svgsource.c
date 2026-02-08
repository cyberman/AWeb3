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

/* Forward declarations for task functions - available through awebplugin.library */
/* struct Taskmsg is defined in <libraries/awebplugin.h> */
extern struct Taskmsg *Gettaskmsg(void);
extern void Replytaskmsg(struct Taskmsg *msg);
extern BOOL Checktaskbreak(void);
extern ULONG Waittask(ULONG signals);
extern long Updatetaskattrs(ULONG tag,...);

/* Workaround for missing AOSDV_Displayed, not part of plugin API */
#define AOSRC_Displayed    (AOSRC_Dummy+2)

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
static void Parsertask(void *userdata);

/* Start the parser task */
static void Startparser(struct Svgsource *ss)
{  struct Screen *screen=NULL;
   Aprintf("SVG: Startparser called\n");
   if(Agetattr(Aweb(),AOAPP_Screenvalid))
   {  Agetattrs(Aweb(),AOAPP_Screen,&screen,TAG_END);
      if(screen && !ss->task)
      {  Aprintf("SVG: Creating parser task\n");
         if(ss->task=Anewobject(AOTP_TASK,
            AOTSK_Entry,Parsertask,
            AOTSK_Name,"AWebSvg parser",
            AOTSK_Userdata,ss,
            AOBJ_Target,ss,
            TAG_END))
         {  void *check_userdata;
            Aprintf("SVG: Parser task created, starting\n");
            /* Verify userdata was set correctly */
            check_userdata=(void *)Agetattr(ss->task,AOTSK_Userdata);
            Aprintf("SVG: Task userdata verification: ss=%p, task->userdata=%p\n", ss, check_userdata);
            if(check_userdata!=ss)
            {  Aprintf("SVG: WARNING - userdata mismatch! Setting it again\n");
               Asetattrs(ss->task,AOTSK_Userdata,ss,TAG_END);
               check_userdata=(void *)Agetattr(ss->task,AOTSK_Userdata);
               Aprintf("SVG: After reset, task->userdata=%p\n", check_userdata);
            }
            Asetattrs(ss->task,AOTSK_Start,TRUE,TAG_END);
         }
         else
         {  Aprintf("SVG: Failed to create parser task\n");
         }
      }
      else
      {  Aprintf("SVG: No screen or task already exists\n");
      }
   }
   else
   {  Aprintf("SVG: Screen not valid\n");
   }
}

/* Parser task - parses SVG and creates bitmap */
static void Parsertask(void *userdata)
{  struct Svgsource *ss;
   struct Datablock *db;
   UBYTE *buffer=NULL;
   long buflen=0;
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
   UBYTE fillpen=1;
   struct Task *task;
   struct Aobject *taskobj;
   
   Aprintf("SVG: Parsertask started, userdata=%p\n", userdata);
   
   /* If userdata is NULL, try to get it from the task object */
   if(!userdata)
   {  Aprintf("SVG: Parsertask: userdata is NULL, trying to get from task object\n");
      task=FindTask(NULL);
      if(task && task->tc_UserData)
      {  taskobj=(struct Aobject *)task->tc_UserData;
         userdata=(void *)Agetattr(taskobj,AOTSK_Userdata);
         Aprintf("SVG: Parsertask: Retrieved userdata from task object: %p\n", userdata);
      }
      else
      {  Aprintf("SVG: Parsertask: ERROR - Cannot get task object!\n");
         return;
      }
   }
   
   ss=(struct Svgsource *)userdata;
   
   /* Safety check - ensure we have a valid source object */
   if(!ss)
   {  Aprintf("SVG: Parsertask: ERROR - ss is NULL after retrieval!\n");
      return;
   }
   
   Aprintf("SVG: Parsertask: ss=%p\n", ss);
   
   /* Get current task for debugging */
   task=FindTask(NULL);
   Aprintf("SVG: Parsertask: Running in task %p\n", task);

   /* Wait for EOF before parsing - we need complete XML */
   /* Process task messages while waiting (like GIF plugin does) */
   {  ULONG initial_flags;
      ObtainSemaphore(&ss->sema);
      initial_flags=ss->flags;
      ReleaseSemaphore(&ss->sema);
      Aprintf("SVG: Waiting for EOF, initial flags=0x%04x (SVGSF_EOF=0x%04x)\n", 
              initial_flags, SVGSF_EOF);
   }
   while(1)
   {  ULONG current_flags;
      struct Taskmsg *tm;
      struct TagItem *tag,*tstate;
      
      /* Read flags with semaphore protection */
      ObtainSemaphore(&ss->sema);
      current_flags=ss->flags;
      ReleaseSemaphore(&ss->sema);
      
      Aprintf("SVG: Wait loop iteration, flags=0x%04x, EOF=%d\n", 
              current_flags, (current_flags&SVGSF_EOF)?1:0);
      
      if(current_flags&SVGSF_EOF)
      {  Aprintf("SVG: EOF flag detected, breaking wait loop\n");
         break;
      }
      
      /* Process any waiting task messages */
      while((tm=Gettaskmsg()))
      {  Aprintf("SVG: Processing task message\n");
         if(tm->amsg && tm->amsg->method==AOM_SET)
         {  tstate=((struct Amset *)tm->amsg)->tags;
            while((tag=NextTagItem(&tstate)))
            {  switch(tag->ti_Tag)
               {  case AOTSK_Stop:
                     if(tag->ti_Data) 
                     {  Aprintf("SVG: Task stop requested\n");
                        goto cleanup;
                     }
                     break;
                  case AOSVG_Data:
                     /* Data notification - check if EOF is set now */
                     {  ULONG data_flags;
                        ObtainSemaphore(&ss->sema);
                        data_flags=ss->flags;
                        ReleaseSemaphore(&ss->sema);
                        Aprintf("SVG: Data notification received, flags=0x%04x, EOF=%d\n", 
                                data_flags, (data_flags&SVGSF_EOF)?1:0);
                     }
                     break;
               }
            }
         }
         Replytaskmsg(tm);
      }
      /* Wait for messages or signals - Waittask(0) waits for task messages */
      /* Add a small delay to prevent CPU spinning if no messages arrive */
      Waittask(0);
      /* Check for stop condition after wait */
      {  ULONG check_flags;
         ObtainSemaphore(&ss->sema);
         check_flags=ss->flags;
         ReleaseSemaphore(&ss->sema);
         if(check_flags&SVGSF_EOF)
         {  Aprintf("SVG: EOF detected after Waittask, breaking\n");
            break;
         }
      }
   }
   {  ULONG final_flags;
      ObtainSemaphore(&ss->sema);
      final_flags=ss->flags;
      ReleaseSemaphore(&ss->sema);
      Aprintf("SVG: Exited wait loop, final flags=0x%04x\n", final_flags);
   }

   /* Collect all data into a buffer for XML parsing */
   ObtainSemaphore(&ss->sema);
   buflen=0;
   for(db=ss->data.first;db->next;db=db->next)
   {  buflen+=db->length;
   }
   ReleaseSemaphore(&ss->sema);

   Aprintf("SVG: Collected data, buflen=%ld\n", buflen);
   if(buflen==0) { Aprintf("SVG: No data, exiting\n"); goto cleanup; }

   /* Limit buffer size to prevent memory exhaustion - 64KB should be enough for SVG */
   if(buflen>65536) { Aprintf("SVG: Clamping buflen from %ld to 65536\n", buflen); buflen=65536; }

   buffer=(UBYTE *)AllocMem(buflen+1,MEMF_ANY);
   if(!buffer) { Aprintf("SVG: Failed to allocate buffer\n"); goto cleanup; }
   Aprintf("SVG: Buffer allocated, size=%ld\n", buflen);
   buffer[buflen]=0;

   {  long buflen2=0;
      ObtainSemaphore(&ss->sema);
      for(db=ss->data.first;db->next;db=db->next)
      {  CopyMem(db->data,buffer+buflen2,db->length);
         buflen2+=db->length;
      }
      ReleaseSemaphore(&ss->sema);
   }

   /* Get screen for bitmap creation */
   if(Agetattr(Aweb(),AOAPP_Screenvalid))
   {  Agetattrs(Aweb(),AOAPP_Screen,&screen,TAG_END);
   }
   if(!screen) { Aprintf("SVG: No screen available\n"); goto cleanup; }
   Aprintf("SVG: Screen available, %ldx%ld\n", screen->Width, screen->Height);

   /* Initialize XML parser */
   {  struct XmlParser xml;
      XmlInitParser(&xml,buffer,buflen);

      /* Parse SVG root element to get dimensions */
      Aprintf("SVG: Starting XML parsing to get dimensions\n");
      Aprintf("SVG: Buffer length=%ld, first 50 chars: ", buflen);
      {  LONG i;
         for(i=0; i<50 && i<buflen; i++)
         {  if(buffer[i]>=32 && buffer[i]<127) Aprintf("%c", buffer[i]);
            else Aprintf(".");
         }
      }
      Aprintf("\n");
      token=XmlGetToken(&xml);
      Aprintf("SVG: First token=%ld (1=START_TAG, 3=EMPTY_TAG, 6=EOF, 7=ERROR)\n", token);
      if(token==XMLTOK_ERROR)
      {  Aprintf("SVG: Parser error! flags=0x%04x, data offset=%ld\n", xml.flags, (LONG)(xml.data-buffer));
      }
      while(token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
      {  if(token==XMLTOK_START_TAG)
         {  name=XmlGetTokenName(&xml,&namelen);
            Aprintf("SVG: Found START_TAG, name='%.*s' (len=%ld)\n", namelen, name, namelen);
            if(namelen==3 && Strnicmp(name,"svg",3)==0)
            {  Aprintf("SVG: Found <svg> tag, parsing attributes\n");
               /* Parse SVG attributes */
               while((token=XmlGetToken(&xml))==XMLTOK_ATTR)
               {  UBYTE *attrname=XmlGetAttrName(&xml,&namelen);
                  LONG attrnamelen=namelen;
                  UBYTE *attrvalue=XmlGetAttrValue(&xml,&namelen);
                  LONG attrvaluelen=namelen;
                  LONG tempval;
                  Aprintf("SVG: Found attribute '%.*s'='%.*s'\n", attrnamelen, attrname, attrvaluelen, attrvalue);
                  if(attrnamelen==5 && Strnicmp(attrname,"width",5)==0 && attrvaluelen>0)
                  {  if(StrToLong(attrvalue,&tempval)>0) 
                     {  svgwidth=tempval;
                        Aprintf("SVG: Parsed width=%ld\n", svgwidth);
                     }
                  }
                  else if(attrnamelen==6 && Strnicmp(attrname,"height",6)==0 && attrvaluelen>0)
                  {  if(StrToLong(attrvalue,&tempval)>0) 
                     {  svgheight=tempval;
                        Aprintf("SVG: Parsed height=%ld\n", svgheight);
                     }
                  }
               }
               if(svgwidth>0) width=svgwidth;
               if(svgheight>0) height=svgheight;
               Aprintf("SVG: Final dimensions: width=%ld, height=%ld\n", width, height);
               break;
            }
         }
         token=XmlGetToken(&xml);
         Aprintf("SVG: Next token=%ld\n", token);
      }

      /* Create bitmap - clamp to screen dimensions to avoid memory issues */
      if(width<=0) width=100;
      if(height<=0) height=100;
      /* Limit to screen dimensions - classic Amiga has limited chip memory */
      {  LONG maxwidth=screen->Width;
         LONG maxheight=screen->Height;
         if(maxwidth<=0) maxwidth=320;
         if(maxheight<=0) maxheight=256;
         if(width>maxwidth) { Aprintf("SVG: Clamping width from %ld to %ld\n", width, maxwidth); width=maxwidth; }
         if(height>maxheight) { Aprintf("SVG: Clamping height from %ld to %ld\n", height, maxheight); height=maxheight; }
      }
      Aprintf("SVG: Creating bitmap %ldx%ld\n", width, height);
      bitmap=AllocBitMap(width,height,8,BMF_CLEAR,screen->RastPort.BitMap);
      if(!bitmap) { Aprintf("SVG: Failed to allocate bitmap\n"); goto cleanup; }
      Aprintf("SVG: Bitmap allocated successfully\n");

      InitRastPort(&rp);
      rp.BitMap=bitmap;
      SetAPen(&rp,0);
      RectFill(&rp,0,0,width-1,height-1);

      /* Create VRastPort for vector rendering */
      /* Scale: 0x80000000 means 2^32 base units = 2^31 pixels, so 1 base unit = 0.5 pixels */
      /* We'll multiply SVG pixel coordinates by 2 to convert to base units */
      Aprintf("SVG: Creating VRastPort\n");
      vrp=MakeVRastPortTags(VRP_RastPort,&rp,
                            VRP_XScale,0x80000000L,
                            VRP_YScale,0x80000000L,
                            VRP_LeftBound,0,
                            VRP_TopBound,0,
                            VRP_RightBound,width-1,
                            VRP_BottomBound,height-1,
                            TAG_END);
      if(!vrp) { Aprintf("SVG: Failed to create VRastPort\n"); goto cleanup; }
      Aprintf("SVG: VRastPort created\n");

      /* Reinitialize parser for element parsing */
      Aprintf("SVG: Reinitializing parser for element parsing\n");
      Aprintf("SVG: Buffer at reinit: length=%ld, first 100 chars: ", buflen);
      {  LONG i;
         for(i=0; i<100 && i<buflen; i++)
         {  if(buffer[i]>=32 && buffer[i]<127) Aprintf("%c", buffer[i]);
            else if(buffer[i]==0) Aprintf("\\0");
            else Aprintf(".");
         }
      }
      Aprintf("\n");
      XmlInitParser(&xml,buffer,buflen);
      Aprintf("SVG: Parser initialized: data=%p, dataend=%p, flags=0x%04x\n", xml.data, xml.dataend, xml.flags);
      SetAPen(&rp,fillpen);

      /* Skip to first element inside <svg> */
      Aprintf("SVG: Skipping to first element inside <svg>\n");
      token=XmlGetToken(&xml);
      Aprintf("SVG: Token after reinit=%ld (1=START_TAG, 3=EMPTY_TAG, 6=EOF, 7=ERROR)\n", token);
      if(token==XMLTOK_ERROR)
      {  Aprintf("SVG: Parser error after reinit! flags=0x%04x, data offset=%ld, dataend offset=%ld\n", 
                 xml.flags, (LONG)(xml.data-buffer), (LONG)(xml.dataend-buffer));
      }
      while(token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
      {  if(token==XMLTOK_START_TAG)
         {  name=XmlGetTokenName(&xml,&namelen);
            Aprintf("SVG: Found START_TAG '%.*s' while skipping\n", namelen, name);
            if(namelen==3 && Strnicmp(name,"svg",3)==0)
            {  Aprintf("SVG: Skipping <svg> tag attributes\n");
               /* Skip <svg> tag and its attributes */
               while((token=XmlGetToken(&xml))==XMLTOK_ATTR);
               /* Now we should be at the content or end tag */
               token=XmlGetToken(&xml);
               Aprintf("SVG: After skipping <svg>, token=%ld\n", token);
               break;
            }
            else
            {  Aprintf("SVG: Found non-svg element, processing\n");
               /* Found a non-svg element, process it */
               break;
            }
         }
         else if(token==XMLTOK_EMPTY_TAG)
         {  Aprintf("SVG: Found empty tag, processing\n");
            /* Found an empty element, process it */
            break;
         }
         else
         {  token=XmlGetToken(&xml);
         }
      }

      /* Parse SVG elements */
      Aprintf("SVG: Starting element parsing, token=%ld\n", token);
      while(token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
      {  if(token==XMLTOK_START_TAG || token==XMLTOK_EMPTY_TAG)
         {  name=XmlGetTokenName(&xml,&namelen);
            x=y=w=h=cx=cy=r=rx=ry=x1=y1=x2=y2=0;
            fillpen=1;
            if(name && namelen>0)
            {  Aprintf("SVG: Found element '%.*s' (token=%ld)\n", namelen, name, token);
            }
            else
            {  Aprintf("SVG: Found element with no name (token=%ld)\n", token);
               token=XmlGetToken(&xml);
               continue;
            }

            /* Skip <svg> and <g> elements - they're containers */
            if((namelen==3 && Strnicmp(name,"svg",3)==0) || (namelen==1 && name[0]=='g'))
            {  Aprintf("SVG: Skipping container element '%.*s'\n", namelen, name);
               if(token==XMLTOK_EMPTY_TAG)
               {  token=XmlGetToken(&xml);
                  continue;
               }
               /* For START_TAG, skip attributes and content until matching END_TAG */
               while((token=XmlGetToken(&xml))==XMLTOK_ATTR);
               /* Skip nested content until we find the matching end tag */
               {  LONG depth=1;
                  while(depth>0 && token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
                  {  token=XmlGetToken(&xml);
                     if(token==XMLTOK_START_TAG || token==XMLTOK_EMPTY_TAG)
                     {  if(token==XMLTOK_START_TAG) depth++;
                        /* Skip attributes */
                        while((token=XmlGetToken(&xml))==XMLTOK_ATTR);
                     }
                     else if(token==XMLTOK_END_TAG)
                     {  depth--;
                     }
                  }
               }
               continue;
            }

            /* Parse attributes */
            Aprintf("SVG: Parsing attributes for element '%.*s'\n", namelen, name);
            while((token=XmlGetToken(&xml))==XMLTOK_ATTR)
            {  UBYTE *attrname=XmlGetAttrName(&xml,&namelen);
               LONG attrnamelen=namelen;
               UBYTE *attrvalue=XmlGetAttrValue(&xml,&namelen);
               LONG attrvaluelen=namelen;
               LONG tempval;
               if(attrnamelen>0 && attrvaluelen>0)
               {  Aprintf("SVG: Attribute '%.*s'='%.*s'\n", attrnamelen, attrname, attrvaluelen, attrvalue);
                  if(attrnamelen==1 && attrname[0]=='x')
                  {  if(StrToLong(attrvalue,&tempval)>0) { x=tempval; Aprintf("SVG: x=%ld\n", x); }
                  }
                  else if(attrnamelen==1 && attrname[0]=='y')
                  {  if(StrToLong(attrvalue,&tempval)>0) { y=tempval; Aprintf("SVG: y=%ld\n", y); }
                  }
                  else if(attrnamelen==1 && attrname[0]=='r')
                  {  if(StrToLong(attrvalue,&tempval)>0) { r=tempval; Aprintf("SVG: r=%ld\n", r); }
                  }
                  else if(attrnamelen==5 && Strnicmp(attrname,"width",5)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { w=tempval; Aprintf("SVG: w=%ld\n", w); }
                  }
                  else if(attrnamelen==6 && Strnicmp(attrname,"height",6)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { h=tempval; Aprintf("SVG: h=%ld\n", h); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"cx",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { cx=tempval; Aprintf("SVG: cx=%ld\n", cx); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"cy",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { cy=tempval; Aprintf("SVG: cy=%ld\n", cy); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"rx",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { rx=tempval; Aprintf("SVG: rx=%ld\n", rx); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"ry",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { ry=tempval; Aprintf("SVG: ry=%ld\n", ry); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"x1",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { x1=tempval; Aprintf("SVG: x1=%ld\n", x1); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"y1",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { y1=tempval; Aprintf("SVG: y1=%ld\n", y1); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"x2",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { x2=tempval; Aprintf("SVG: x2=%ld\n", x2); }
                  }
                  else if(attrnamelen==2 && Strnicmp(attrname,"y2",2)==0)
                  {  if(StrToLong(attrvalue,&tempval)>0) { y2=tempval; Aprintf("SVG: y2=%ld\n", y2); }
                  }
               }
            }

            /* Render based on element type */
            /* Convert pixel coordinates to VRastPort base units (multiply by 2) */
            if(namelen==4 && Strnicmp(name,"rect",4)==0 && w>0 && h>0)
            {  Aprintf("SVG: Rendering rect at %ld,%ld size %ldx%ld\n", x, y, w, h);
               SetAPen(&rp,fillpen);
               VAreaBox(vrp,x*2,y*2,(x+w-1)*2,(y+h-1)*2);
            }
            else if(namelen==6 && Strnicmp(name,"circle",6)==0 && r>0)
            {  Aprintf("SVG: Rendering circle at %ld,%ld radius %ld\n", cx, cy, r);
               SetAPen(&rp,fillpen);
               VAreaEllipse(vrp,cx*2,cy*2,r*2,r*2);
            }
            else if(namelen==7 && Strnicmp(name,"ellipse",7)==0 && rx>0 && ry>0)
            {  Aprintf("SVG: Rendering ellipse at %ld,%ld radii %ldx%ld\n", cx, cy, rx, ry);
               SetAPen(&rp,fillpen);
               VAreaEllipse(vrp,cx*2,cy*2,rx*2,ry*2);
            }
            else if(namelen==4 && Strnicmp(name,"line",4)==0)
            {  Aprintf("SVG: Rendering line from %ld,%ld to %ld,%ld\n", x1, y1, x2, y2);
               SetAPen(&rp,1);
               VDrawLine(vrp,x1*2,y1*2,x2*2,y2*2);
            }
            else
            {  Aprintf("SVG: Unknown or invalid element '%.*s' (namelen=%ld)\n", namelen, name, namelen);
            }

            /* For START_TAG (not EMPTY_TAG), skip to matching END_TAG */
            if(token==XMLTOK_START_TAG)
            {  LONG depth=1;
               while(depth>0 && token!=XMLTOK_EOF && token!=XMLTOK_ERROR)
               {  token=XmlGetToken(&xml);
                  if(token==XMLTOK_START_TAG || token==XMLTOK_EMPTY_TAG)
                  {  if(token==XMLTOK_START_TAG) depth++;
                     /* Skip attributes */
                     while((token=XmlGetToken(&xml))==XMLTOK_ATTR);
                  }
                  else if(token==XMLTOK_END_TAG)
                  {  depth--;
                  }
               }
            }
         }
         else if(token==XMLTOK_END_TAG)
         {  /* Skip end tags we're not tracking */
            Aprintf("SVG: Skipping END_TAG\n");
            token=XmlGetToken(&xml);
         }
         else if(token==XMLTOK_TEXT)
         {  /* Skip text content */
            Aprintf("SVG: Skipping TEXT token\n");
            token=XmlGetToken(&xml);
         }
         else
         {  Aprintf("SVG: Unexpected token type %ld\n", token);
            token=XmlGetToken(&xml);
         }
      }

      /* Save bitmap to source - MUST be set before Updatetaskattrs */
      ObtainSemaphore(&ss->sema);
      ss->width=width;
      ss->height=height;
      ss->bitmap=bitmap;
      bitmap=NULL;  /* Don't free it, it's now owned by ss */
      ss->flags|=SVGSF_IMAGEREADY;
      ReleaseSemaphore(&ss->sema);

      Aprintf("SVG: Bitmap ready, notifying main task: %ldx%ld\n", width, height);
      /* Notify that bitmap is ready via task update - send all attributes together */
      /* Note: Updatesource will use ss->bitmap which is already set above */
      Updatetaskattrs(
         AOSVG_Width,width,
         AOSVG_Height,height,
         AOSVG_Imgready,TRUE,
         AOSVG_Parseready,TRUE,
         TAG_END);
      Aprintf("SVG: Notification sent\n");
   }

cleanup:
   Aprintf("SVG: Parsertask cleanup\n");
   if(vrp) { FreeVRastPort(vrp); Aprintf("SVG: VRastPort freed\n"); }
   if(bitmap) { FreeBitMap(bitmap); Aprintf("SVG: Bitmap freed\n"); }
   if(buffer && buflen>0) { FreeMem(buffer,buflen+1); Aprintf("SVG: Buffer freed\n"); }
   if(!ss->bitmap)
   {  Aprintf("SVG: No bitmap created, sending error notification\n");
      Updatetaskattrs(AOSVG_Error,TRUE,TAG_END);
   }
   Aprintf("SVG: Parsertask exiting\n");
   return;
}

/* Source driver dispatcher */
static ULONG Getsource(struct Svgsource *ss,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   Aprintf("SVG: Getsource called\n");
   AmethodasA(AOTP_SOURCEDRIVER,(struct Aobject *)ss,(struct Amessage *)amset);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOSDV_Source:
            Aprintf("SVG: Getsource: AOSDV_Source\n");
            PUTATTR(tag,ss->source);
            break;
         case AOSDV_Saveable:
            Aprintf("SVG: Getsource: AOSDV_Saveable, EOF=%d\n", (ss->flags&SVGSF_EOF)?1:0);
            PUTATTR(tag,(ss->flags&SVGSF_EOF)?TRUE:FALSE);
            break;
         default:
            Aprintf("SVG: Getsource: Unknown tag 0x%08lx\n", tag->ti_Tag);
            break;
      }
   }
   return 0;
}

static ULONG Setsource(struct Svgsource *ss,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   Aprintf("SVG: Setsource called\n");
   Amethodas(AOTP_SOURCEDRIVER,(struct Aobject *)ss,AOM_SET,amset->tags);
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOSDV_Source:
            Aprintf("SVG: Setsource: AOSDV_Source=%p\n", tag->ti_Data);
            ss->source=(struct Aobject *)tag->ti_Data;
            break;
         case AOSDV_Displayed:
            Aprintf("SVG: Setsource: AOSDV_Displayed=%ld\n", tag->ti_Data);
            if(tag->ti_Data)
            {  ss->flags|=SVGSF_DISPLAYED;
               /* Check if we have data blocks - need to check with semaphore */
               {  struct Datablock *firstblock;
                  ObtainSemaphore(&ss->sema);
                  firstblock=ss->data.first->next;
                  ReleaseSemaphore(&ss->sema);
                  Aprintf("SVG: Setsource: Displayed=TRUE, data.first->next=%p, bitmap=%p, task=%p\n", 
                          firstblock, ss->bitmap, ss->task);
                  if(firstblock && !ss->bitmap && !ss->task)
                  {  Aprintf("SVG: Setsource: Starting parser\n");
                     Startparser(ss);
                  }
                  else if(!firstblock)
                  {  Aprintf("SVG: Setsource: No data yet, will start parser when data arrives\n");
                  }
               }
            }
            else
            {  Aprintf("SVG: Setsource: Displayed=FALSE\n");
               ss->flags&=~SVGSF_DISPLAYED;
            }
            break;
         case AOAPP_Screenvalid:
            Aprintf("SVG: Setsource: AOAPP_Screenvalid=%ld\n", tag->ti_Data);
            if(tag->ti_Data)
            {  /* Check if we have data blocks - need to check with semaphore */
               struct Datablock *firstblock;
               ObtainSemaphore(&ss->sema);
               firstblock=ss->data.first->next;
               ReleaseSemaphore(&ss->sema);
               Aprintf("SVG: Setsource: Screen valid, data.first->next=%p, displayed=%d, task=%p\n",
                       firstblock, (ss->flags&SVGSF_DISPLAYED)?1:0, ss->task);
               if(firstblock && (ss->flags&SVGSF_DISPLAYED) && !ss->task)
               {  Aprintf("SVG: Setsource: Starting parser (screen valid)\n");
                  Startparser(ss);
               }
            }
            else
            {  Aprintf("SVG: Setsource: Screen invalid, cleaning up\n");
               if(ss->task)
               {  Aprintf("SVG: Setsource: Disposing task\n");
                  Adisposeobject(ss->task);
                  ss->task=NULL;
               }
               if(ss->bitmap)
               {  Aprintf("SVG: Setsource: Freeing bitmap\n");
                  FreeBitMap(ss->bitmap);
                  ss->bitmap=NULL;
               }
               if(ss->mask)
               {  Aprintf("SVG: Setsource: Freeing mask\n");
                  FreeVec(ss->mask);
                  ss->mask=NULL;
               }
               ss->width=0;
               ss->height=0;
               ss->flags&=~(SVGSF_IMAGEREADY);
               ss->memory=0;
               Asetattrs(ss->source,AOSRC_Memory,0,TAG_END);
            }
            break;
         default:
            Aprintf("SVG: Setsource: Unknown tag 0x%08lx\n", tag->ti_Tag);
            break;
      }
   }
   Aprintf("SVG: Setsource returning, flags=0x%04x\n", ss->flags);
   return 0;
}

static ULONG Updatesource(struct Svgsource *ss,struct Amset *amset)
{  struct TagItem *tag,*tstate;
   BOOL notify=FALSE;
   BOOL parseready=FALSE;
   Aprintf("SVG: Updatesource called\n");
   tstate=amset->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOSVG_Width:
            ss->width=tag->ti_Data;
            notify=TRUE;
            break;
         case AOSVG_Height:
            ss->height=tag->ti_Data;
            notify=TRUE;
            break;
         case AOSVG_Bitmap:
            /* Bitmap is already set in Parsertask, but handle it if sent */
            ObtainSemaphore(&ss->sema);
            if(tag->ti_Data) ss->bitmap=(struct BitMap *)tag->ti_Data;
            notify=TRUE;
            ReleaseSemaphore(&ss->sema);
            break;
         case AOSVG_Mask:
            ss->mask=(UBYTE *)tag->ti_Data;
            notify=TRUE;
            break;
         case AOSVG_Imgready:
            if(tag->ti_Data)
            {  ss->flags|=SVGSF_IMAGEREADY;
               notify=TRUE;
            }
            else
            {  ss->flags&=~SVGSF_IMAGEREADY;
            }
            break;
         case AOSVG_Parseready:
            Aprintf("SVG: Parseready notification received\n");
            if(tag->ti_Data)
            {  ss->flags|=SVGSF_IMAGEREADY;
               parseready=TRUE;
               notify=TRUE;
            }
            break;
         case AOSVG_Error:
            Aprintf("SVG: Error notification received\n");
            break;
         case AOSVG_Memory:
            ss->memory+=tag->ti_Data;
            Asetattrs(ss->source,
               AOSRC_Memory,ss->memory,
               TAG_END);
            break;
      }
   }
   /* After processing all tags, notify copy drivers if we have a complete image */
   /* This matches the PNG plugin pattern - use the bitmap already stored in ss */
   if(notify && ss->bitmap)
   {  Aprintf("SVG: Notifying copy drivers: bitmap=%p, width=%ld, height=%ld\n", ss->bitmap, ss->width, ss->height);
      Anotifyset(ss->source,
         AOSVG_Bitmap,ss->bitmap,
         AOSVG_Mask,ss->mask,
         AOSVG_Width,ss->width,
         AOSVG_Height,ss->height,
         AOSVG_Imgready,(ss->flags&SVGSF_IMAGEREADY)?TRUE:FALSE,
         AOSVG_Jsready,parseready?TRUE:FALSE,
         TAG_END);
      Aprintf("SVG: Copy drivers notified\n");
   }
   else if(notify && !ss->bitmap)
   {  Aprintf("SVG: Parseready but no bitmap!\n");
   }
   return 0;
}

static struct Svgsource *Newsource(struct Amset *amset)
{  struct Svgsource *ss;
   Aprintf("SVG: Newsource called\n");
   if(ss=Allocobject(PluginBase->sourcedriver,sizeof(struct Svgsource),amset))
   {  Aprintf("SVG: Newsource: Allocated Svgsource=%p\n", ss);
      InitSemaphore(&ss->sema);
      NEWLIST(&ss->data);
      Aaddchild(Aweb(),(struct Aobject *)ss,AOREL_APP_USE_SCREEN);
      Aprintf("SVG: Newsource: Registered for screen notifications\n");
      ss->width=0;
      ss->height=0;
      ss->bitmap=NULL;
      ss->mask=NULL;
      ss->memory=0;
      ss->flags=0;
      ss->source=NULL;
      ss->task=NULL;
      Setsource(ss,amset);
      /* Workaround for missing AOSDV_Displayed in pre-0.132 */
      if(!(ss->flags&SVGSF_DISPLAYED))
      {  Aprintf("SVG: Newsource: Checking AOSRC_Displayed workaround\n");
         if(Agetattr(ss->source,AOSRC_Displayed))
         {  Aprintf("SVG: Newsource: Setting AOSDV_Displayed via workaround\n");
            Asetattrs((struct Aobject *)ss,AOSDV_Displayed,TRUE,TAG_END);
         }
      }
      Aprintf("SVG: Newsource: Returning ss=%p, flags=0x%04x\n", ss, ss->flags);
   }
   else
   {  Aprintf("SVG: Newsource: Failed to allocate Svgsource\n");
   }
   return ss;
}

static void Releasedata(struct Svgsource *ss)
{  struct Datablock *db;
   while((db=REMHEAD(&ss->data)))
   {  if(db->data) FreeVec(db->data);
      FreeVec(db);
   }
}

static void Disposesource(struct Svgsource *ss)
{  Aprintf("SVG: Disposesource called\n");
   if(ss->task)
   {  Aprintf("SVG: Disposesource: Disposing task\n");
      Adisposeobject(ss->task);
      ss->task=NULL;
   }
   if(ss->bitmap) 
   {  Aprintf("SVG: Disposesource: Freeing bitmap\n");
      FreeBitMap(ss->bitmap);
   }
   if(ss->mask) 
   {  Aprintf("SVG: Disposesource: Freeing mask\n");
      FreeVec(ss->mask);
   }
   ss->bitmap=NULL;
   ss->mask=NULL;
   ss->width=0;
   ss->height=0;
   ss->flags&=~(SVGSF_IMAGEREADY);
   ss->memory=0;
   Asetattrs(ss->source,AOSRC_Memory,0,TAG_END);
   Releasedata(ss);
   Aremchild(Aweb(),(struct Aobject *)ss,AOREL_APP_USE_SCREEN);
   Aprintf("SVG: Disposesource: Unregistered from screen notifications\n");
   Amethodas(AOTP_SOURCEDRIVER,(struct Aobject *)ss,AOM_DISPOSE);
   Aprintf("SVG: Disposesource: Complete\n");
}

static ULONG Addchildsource(struct Svgsource *ss,struct Amadd *amadd)
{  Aprintf("SVG: Addchildsource called, relation=0x%08lx\n", amadd->relation);
   if(amadd->relation==AOREL_SRC_COPY)
   {  Aprintf("SVG: Addchildsource: AOREL_SRC_COPY, bitmap=%p\n", ss->bitmap);
      if(ss->bitmap)
      {  Aprintf("SVG: Addchildsource: Setting attributes on child: bitmap=%p, %ldx%ld\n", 
                 ss->bitmap, ss->width, ss->height);
         Asetattrs(amadd->child,
            AOSVG_Bitmap,ss->bitmap,
            AOSVG_Mask,ss->mask,
            AOSVG_Width,ss->width,
            AOSVG_Height,ss->height,
            AOSVG_Imgready,ss->flags&SVGSF_IMAGEREADY,
            AOSVG_Jsready,ss->flags&SVGSF_IMAGEREADY,
            TAG_END);
         Aprintf("SVG: Addchildsource: Attributes set\n");
      }
      else
      {  Aprintf("SVG: Addchildsource: No bitmap available yet\n");
      }
   }
   return 0;
}

static ULONG Srcupdatesource(struct Svgsource *ss,struct Amsrcupdate *amsrcupdate)
{  struct TagItem *tag,*tstate;
   UBYTE *data=NULL;
   long datalength=0;
   struct Datablock *db;
   BOOL eof=FALSE;
   Aprintf("SVG: Srcupdatesource called\n");
   AmethodasA(AOTP_SOURCEDRIVER,(struct Aobject *)ss,(struct Amessage *)amsrcupdate);
   tstate=amsrcupdate->tags;
   while((tag=NextTagItem(&tstate)))
   {  switch(tag->ti_Tag)
      {  case AOURL_Data:
            data=(UBYTE *)tag->ti_Data;
            Aprintf("SVG: Srcupdatesource: AOURL_Data=%p\n", data);
            break;
         case AOURL_Datalength:
            datalength=tag->ti_Data;
            Aprintf("SVG: Srcupdatesource: AOURL_Datalength=%ld\n", datalength);
            break;
         case AOURL_Eof:
            Aprintf("SVG: Srcupdatesource: AOURL_Eof=%ld\n", tag->ti_Data);
            if(tag->ti_Data)
            {  eof=TRUE;
               ObtainSemaphore(&ss->sema);
               ss->flags|=SVGSF_EOF;
               Aprintf("SVG: Srcupdatesource: EOF flag set, flags=0x%04x\n", ss->flags);
               ReleaseSemaphore(&ss->sema);
            }
            break;
         default:
            Aprintf("SVG: Srcupdatesource: Unknown tag 0x%08lx\n", tag->ti_Tag);
            break;
      }
   }
   if(data && datalength)
   {  Aprintf("SVG: Received data block, length=%ld\n", datalength);
      /* Limit individual data block size to prevent memory exhaustion */
      if(datalength>65536) { Aprintf("SVG: Clamping data block from %ld to 65536\n", datalength); datalength=65536; }
      if(db=AllocVec(sizeof(struct Datablock),MEMF_PUBLIC|MEMF_CLEAR))
      {  if(db->data=AllocVec(datalength,MEMF_PUBLIC))
         {  memmove(db->data,data,datalength);
            db->length=datalength;
            ObtainSemaphore(&ss->sema);
            ADDTAIL(&ss->data,db);
            ReleaseSemaphore(&ss->sema);
            Aprintf("SVG: Data block added to list\n");
         }
         else
         {  Aprintf("SVG: Failed to allocate data block buffer\n");
            FreeVec(db);
         }
      }
      else
      {  Aprintf("SVG: Failed to allocate Datablock structure\n");
      }
      if(!ss->task)
      {  Aprintf("SVG: No parser task, starting it\n");
         Startparser(ss);
      }
   }
   if((data && datalength) || eof)
   {  if(ss->task)
      {  Aprintf("SVG: Notifying parser task of new data, task=%p\n", ss->task);
         Asetattrsasync(ss->task,AOSVG_Data,TRUE,TAG_END);
      }
      else
      {  Aprintf("SVG: No task to notify (task=%p)\n", ss->task);
      }
   }
   if(eof)
   {  Aprintf("SVG: EOF received in Srcupdatesource, flags=0x%04x\n", ss->flags);
   }
   Aprintf("SVG: Srcupdatesource returning\n");
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
      case AOM_GET:
         result=Getsource(ss,(struct Amset *)amsg);
         break;
      case AOM_DISPOSE:
         Disposesource(ss);
         break;
      case AOM_SRCUPDATE:
         result=Srcupdatesource(ss,(struct Amsrcupdate *)amsg);
         break;
      case AOM_UPDATE:
         result=Updatesource(ss,(struct Amset *)amsg);
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


