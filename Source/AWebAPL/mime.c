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

/* mime.c aweb mime types */

#include "aweb.h"
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>

struct Mime
{  NODE(Mime);
   UBYTE mimetype[32];
   USHORT driver;
   UBYTE *cmd;
   UBYTE *args;
   LIST(Mimextens) extensions;
};

struct Mimextens
{  NODE(Mimextens);
   UBYTE ext[16];
};

static LIST(Mime) mimes;
static BOOL inited;

/*-----------------------------------------------------------------------*/

static void Freemimetype(struct Mime *m)
{  struct Mimextens *me;
   while(me=REMHEAD(&m->extensions)) FREE(me);
   if(m->cmd) FREE(m->cmd);
   if(m->args) FREE(m->args);
   FREE(m);
}

static UBYTE *Getextension(UBYTE *url)
{  static UBYTE extbuf[16];
   UBYTE *path,*ext,*end;
   if(!url) return NULL;
   path=url;
   end=path;
   while(*end && *end!=';' && *end!='?' && *end!='#') end++;
   ext=end-1;
   while(ext>path && *ext!='.') ext--;
   if(end-ext>15) return NULL;
   memmove(extbuf,ext+1,end-ext-1);
   extbuf[end-ext-1]='\0';
   return extbuf;
}

static void Defaultmimes(void)
{  UBYTE exts[16];
   strcpy(exts,"htm html");
   Addmimetype("TEXT/HTML",exts,MDRIVER_INTERNAL,NULL,NULL);
   strcpy(exts,"txt");
   Addmimetype("TEXT/PLAIN",exts,MDRIVER_INTERNAL,NULL,NULL);
   strcpy(exts,"xml");
   Addmimetype("TEXT/XML",exts,MDRIVER_INTERNAL,NULL,NULL);
   strcpy(exts,"rss");
   Addmimetype("APPLICATION/RSS+XML",exts,MDRIVER_INTERNAL,NULL,NULL);
   strcpy(exts,"atom");
   Addmimetype("APPLICATION/ATOM+XML",exts,MDRIVER_INTERNAL,NULL,NULL);
}

/*-----------------------------------------------------------------------*/

BOOL Initmime(void)
{  NEWLIST(&mimes);
   inited=TRUE;
   Defaultmimes();
   return TRUE;
}

void Freemime(void)
{  struct Mime *m;
   if(inited)
   {  while(m=REMHEAD(&mimes)) Freemimetype(m);
   }
}

void Reinitmime(void)
{  struct Mime *m;
   while(m=REMHEAD(&mimes)) Freemimetype(m);
   Defaultmimes();
}

void Addmimetype(UBYTE *type,UBYTE *exts,USHORT driver,UBYTE *cmd,UBYTE *args)
{  struct Mime *m;
   struct Mimextens *me;
   UBYTE *p,*q;
   BOOL ok=TRUE;
   for(m=mimes.first;m->next;m=m->next)
   {  if(STRIEQUAL(m->mimetype,type))
      {  REMOVE(m);
         Freemimetype(m);
         break;
      }
   }
   if(m=ALLOCSTRUCT(Mime,1,MEMF_PUBLIC|MEMF_CLEAR))
   {  NEWLIST(&m->extensions);
      strncpy(m->mimetype,type,31);
      for(p=m->mimetype;*p;p++) *p=toupper(*p);
      if(cmd && *cmd && !(m->cmd=Dupstr(cmd,-1))) ok=FALSE;
      if(args && *args && !(m->args=Dupstr(args,-1))) ok=FALSE;
      m->driver=driver;
      p=exts;
      while(ok && *p)
      {  if(*p==' ' || *p==',') p++;
         else
         {  for(q=p;*q && *q!=' ' && *q!=',';q++);
            if(me=ALLOCSTRUCT(Mimextens,1,MEMF_PUBLIC|MEMF_CLEAR))
            {  strncpy(me->ext,p,MIN(15,q-p));
               ADDTAIL(&m->extensions,me);
            }
            else ok=FALSE;
            if(*q) *q++;      /* skip q to next, or leave at eol */
            p=q;
         }
      }
      if(ok) ADDTAIL(&mimes,m);
      else Freemimetype(m);
   }
}

UBYTE *Mimetypefromext(UBYTE *name)
{  UBYTE *ext;
   if(ext=Getextension(name))
   {  struct Mime *m;
      struct Mimextens *me;
      for(m=mimes.first;m->next;m=m->next)
      {  for(me=m->extensions.first;me->next;me=me->next)
         {  if(STRIEQUAL(me->ext,ext))
            {  return m->mimetype;
            }
         }
      }
   }
   return NULL;
}

BOOL Checkmimetype(UBYTE *data,long length,UBYTE *type)
{  UBYTE *p,*end;
   BOOL ok=TRUE;
   if(STRNIEQUAL(type,"TEXT/",5))
   {  p=data;
      end=p+length;
      /* Ignore leading nullbytes */
      while(p<end && !*p) p++;
      while(p<end && (Isprint(*p) || Isspace(*p))) p++;
      if(p<end) ok=FALSE;
   }
   else if(length>0 && STRNIEQUAL(type,"IMAGE/",6))
   {  static UBYTE gif87asig[]={ 'G','I','F','8','7','a' };
      static UBYTE gif89asig[]={ 'G','I','F','8','9','a' };
      static UBYTE pngsig[]={ 0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a };
      static UBYTE jpegsig[]={ 0xff,0xd8 };
      short l;
      if(STRIEQUAL(type+6,"GIF"))
      {  l=MIN(length,sizeof(gif87asig));
         ok=!memcmp(data,gif87asig,l) || !memcmp(data,gif89asig,l);
      }
      else if(STRIEQUAL(type+6,"JPEG"))
      {  l=MIN(length,sizeof(jpegsig));
         ok=!memcmp(data,jpegsig,l);
      }
      else if(STRIEQUAL(type+6,"PNG") || STRIEQUAL(type+6,"X-PNG"))
      {  l=MIN(length,sizeof(pngsig));
         ok=!memcmp(data,pngsig,l);
      }
   }
   return ok;
}

UBYTE *Mimetypefromdata(UBYTE *data,long length,UBYTE *deftype)
{  UBYTE *p,*end;
   UBYTE *type=deftype?deftype:(UBYTE *)"X-UNKNOWN/X-UNKNOWN";
   if(data && length)
   {  /* Handle XML-based formats (RSS, Atom, generic XML) */
      if(STRNIEQUAL(deftype,"APPLICATION/RSS",15) ||
         STRNIEQUAL(deftype,"APPLICATION/ATOM",16) ||
         STRNIEQUAL(deftype,"APPLICATION/XML",15) ||
         STRNIEQUAL(deftype,"TEXT/XML",8))
      {  /* XML formats should be treated as text - verify content is XML-like */
         p=data;
         end=data+length;
         while(p<end && !*p) p++;
         while(p<end-3 && isspace(*p)) p++;
         if(p<=end-5 && STRNIEQUAL(p,"<?xml",5))
         {  /* XML declaration found - keep original type or detect RSS/Atom */
            UBYTE *q;
            q=p+5;
            while(q<end && *q!='>' && *q!='\n' && *q!='\r') q++;
            while(q<end && (*q==' ' || *q=='\t' || *q=='\n' || *q=='\r' || *q=='>')) q++;
            if(q<=end-4 && STRNIEQUAL(q,"<rss",4))
            {  type="APPLICATION/RSS+XML";
            }
            else if(q<=end-5 && STRNIEQUAL(q,"<feed",5))
            {  type="APPLICATION/ATOM+XML";
            }
            else if(STRNIEQUAL(deftype,"APPLICATION/RSS",15))
            {  type="APPLICATION/RSS+XML";
            }
            else if(STRNIEQUAL(deftype,"APPLICATION/ATOM",16))
            {  type="APPLICATION/ATOM+XML";
            }
            else
            {  type="TEXT/XML";
            }
         }
         else if(p<=end-4 && STRNIEQUAL(p,"<rss",4))
         {  /* RSS without XML declaration */
            type="APPLICATION/RSS+XML";
         }
         else if(p<=end-5 && STRNIEQUAL(p,"<feed",5))
         {  /* Atom without XML declaration */
            type="APPLICATION/ATOM+XML";
         }
         else if(Checkmimetype(data,length,"TEXT/PLAIN"))
         {  /* Valid text content - keep as XML type */
            if(STRNIEQUAL(deftype,"APPLICATION/RSS",15))
            {  type="APPLICATION/RSS+XML";
            }
            else if(STRNIEQUAL(deftype,"APPLICATION/ATOM",16))
            {  type="APPLICATION/ATOM+XML";
            }
            else
            {  type="TEXT/XML";
            }
         }
         else
         {  /* Not valid text - fall back to octet-stream */
            type="APPLICATION/OCTET-STREAM";
         }
      }
      else if(STRNIEQUAL(deftype,"TEXT/",5))
      {  p=data;
         end=data+length;
         while(p<end && !*p) p++;
         while(p<end-3 && isspace(*p)) p++;
         if(p<=end-4 && STRNIEQUAL(p,"<!--",4))
         {  type="TEXT/HTML";
         }
         else if(p<=end-6 && STRNIEQUAL(p,"<HTML>",6))
         {  type="TEXT/HTML";
         }
         else if(p<=end-10 && STRNIEQUAL(p,"<!DOCTYPE",9) && isspace(p[9]))
         {  p+=10;
            while(p<end && isspace(*p)) p++;
            if(p<=end-5 && STRNIEQUAL(p,"HTML ",5))
            {  type="TEXT/HTML";
            }
         }
         else if(p<=end-5 && STRNIEQUAL(p,"<?xml",5))
         {  /* XML declaration found - check for RSS or Atom */
            UBYTE *q;
            q=p+5;
            while(q<end && *q!='>' && *q!='\n' && *q!='\r') q++;
            /* Look for RSS or Atom root element after XML declaration */
            while(q<end && (*q==' ' || *q=='\t' || *q=='\n' || *q=='\r' || *q=='>')) q++;
            if(q<=end-4 && STRNIEQUAL(q,"<rss",4))
            {  type="APPLICATION/RSS+XML";
            }
            else if(q<=end-5 && STRNIEQUAL(q,"<feed",5))
            {  type="APPLICATION/ATOM+XML";
            }
            else
            {  /* Generic XML - treat as plain text */
               type="TEXT/XML";
            }
         }
         else if(Checkmimetype(data,length,"TEXT/PLAIN"))
         {  type="TEXT/PLAIN";
         }
         else
         {  type="APPLICATION/OCTET-STREAM";
         }
      }
      else if(!deftype || STRIEQUAL(deftype,"APPLICATION/OCTET-STREAM") 
               || STRIEQUAL(deftype,"X-UNKNOWN/X-UNKNOWN"))
      {  /* Try to detect content type from data when default is unknown/octet-stream */
         p=data;
         end=data+length;
         /* Check for images first (binary signatures) */
         if(length >= 2)
         {  static UBYTE gif87asig[]={ 'G','I','F','8','7','a' };
            static UBYTE gif89asig[]={ 'G','I','F','8','9','a' };
            static UBYTE pngsig[]={ 0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a };
            static UBYTE jpegsig[]={ 0xff,0xd8 };
            BOOL found_image=FALSE;
            long i;
            if(length >= sizeof(gif87asig) 
               && (!memcmp(data,gif87asig,sizeof(gif87asig)) 
                   || !memcmp(data,gif89asig,sizeof(gif89asig))))
            {  type="IMAGE/GIF";
               found_image=TRUE;
            }
            else if(length >= sizeof(jpegsig) && !memcmp(data,jpegsig,sizeof(jpegsig)))
            {  type="IMAGE/JPEG";
               found_image=TRUE;
            }
            else if(length >= sizeof(pngsig) && !memcmp(data,pngsig,sizeof(pngsig)))
            {  type="IMAGE/PNG";
               found_image=TRUE;
            }
            else
            {  /* Scan for JPEG markers (ff d8, ff e0-ff ef are JPEG APP markers) */
               for(i=0;i<length-1 && i<1024;i++)
               {  if(data[i]==0xff && (data[i+1]==0xd8 || (data[i+1]>=0xe0 && data[i+1]<=0xef)))
                  {  type="IMAGE/JPEG";
                     found_image=TRUE;
                     break;
                  }
               }
            }
            if(!found_image)
            {  /* Check for text/HTML/XML content */
               while(p<end && !*p) p++;
               while(p<end-3 && isspace(*p)) p++;
               if(p<=end-4 && STRNIEQUAL(p,"<!--",4))
               {  type="TEXT/HTML";
               }
               else if(p<=end-6 && STRNIEQUAL(p,"<HTML>",6))
               {  type="TEXT/HTML";
               }
               else if(p<=end-10 && STRNIEQUAL(p,"<!DOCTYPE",9) && isspace(p[9]))
               {  p+=10;
                  while(p<end && isspace(*p)) p++;
                  if(p<=end-5 && STRNIEQUAL(p,"HTML ",5))
                  {  type="TEXT/HTML";
                  }
               }
               else if(p<=end-5 && STRNIEQUAL(p,"<?xml",5))
               {  /* XML declaration found - check for RSS or Atom */
                  UBYTE *q;
                  q=p+5;
                  while(q<end && *q!='>' && *q!='\n' && *q!='\r') q++;
                  /* Look for RSS or Atom root element after XML declaration */
                  while(q<end && (*q==' ' || *q=='\t' || *q=='\n' || *q=='\r' || *q=='>')) q++;
                  if(q<=end-4 && STRNIEQUAL(q,"<rss",4))
                  {  type="APPLICATION/RSS+XML";
                  }
                  else if(q<=end-5 && STRNIEQUAL(q,"<feed",5))
                  {  type="APPLICATION/ATOM+XML";
                  }
                  else
                  {  /* Generic XML - treat as plain text */
                     type="TEXT/XML";
                  }
               }
               else if(p<=end-4 && STRNIEQUAL(p,"<rss",4))
               {  /* RSS without XML declaration */
                  type="APPLICATION/RSS+XML";
               }
               else if(p<=end-5 && STRNIEQUAL(p,"<feed",5))
               {  /* Atom without XML declaration */
                  type="APPLICATION/ATOM+XML";
               }
               else if(Checkmimetype(data,length,"TEXT/PLAIN"))
               {  type="TEXT/PLAIN";
               }
            }
         }
      }
   }
   return type;
}

ULONG Getmimedriver(UBYTE *mimetype,UBYTE **name,UBYTE **args)
{  struct Mime *m,*mvw=NULL;
   UBYTE wildtype[32],noxtype[32];
   UBYTE *p;
   ULONG mime=MIMEDRV_NONE;
   if(mimetype)
   {  strcpy(wildtype,mimetype);
      strcpy(noxtype,mimetype);
      if(p=strchr(mimetype,'/')) strcpy(wildtype+(p+1-mimetype),"*");
      if(p && STRNIEQUAL(p,"/X-",3))
      {  strcpy(noxtype+(p+1-mimetype),p+3);
      }
      /* search for mime type, or remember matching wild subtype */
      for(m=mimes.first;m->next;m=m->next)
      {  if((STRIEQUAL(m->mimetype,mimetype) || STRIEQUAL(m->mimetype,noxtype))
         && m->driver!=MDRIVER_NONE)
         {  mvw=m;
            break;
         }
         if(STRIEQUAL(m->mimetype,wildtype)) mvw=m;
      }
      if(mvw && mvw->driver==MDRIVER_EXTERNAL && mvw->cmd && mvw->args)
      {  mime=MIMEDRV_EXTPROG;
         *name=mvw->cmd;
         *args=mvw->args;
      }
      else if(mvw && mvw->driver==MDRIVER_EXTPIPE && mvw->cmd && mvw->args)
      {  mime=MIMEDRV_EXTPROGPIPE;
         *name=mvw->cmd;
         *args=mvw->args;
      }
      else if(mvw && mvw->driver==MDRIVER_PLUGIN && mvw->cmd)
      {  mime=MIMEDRV_PLUGIN;
         *name=mvw->cmd;
         *args=mvw->args;
      }
      else if(mvw && mvw->driver==MDRIVER_INTERNAL)
      {  if(STRNIEQUAL("TEXT/",mimetype,5)) mime=MIMEDRV_DOCUMENT;
         else if(STRNIEQUAL("IMAGE/",mimetype,6)) mime=MIMEDRV_IMAGE;
         else if(STRNIEQUAL("AUDIO/",mimetype,6)) mime=MIMEDRV_SOUND;
      }
      else if(mvw && mvw->driver==MDRIVER_SAVELOCAL)
      {  mime=MIMEDRV_SAVELOCAL;
      }
   }
   return mime;
}

BOOL Isxbm(UBYTE *mimetype)
{  return (BOOL)
      (STRIEQUAL(mimetype,"IMAGE/X-XBITMAP") || STRIEQUAL(mimetype,"IMAGE/XBITMAP"));
}

