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

/* about.c - AWeb about: protocol plugin */

#include "aweblib.h"
#include "fetchdriver.h"
#include "task.h"
#include <exec/resident.h>

struct Library *AboutBase;
void *AwebPluginBase;

/*-----------------------------------------------------------------------*/
/* AWebLib module startup */

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

__asm __saveds void Fetchdrivertask(
   register __a0 struct Fetchdriver *fd);

/* Function declarations for project dependent hook functions */
static ULONG Initaweblib(struct Library *libbase);
static void Expungeaweblib(struct Library *libbase);

static APTR libseglist;

struct ExecBase *SysBase;

LONG __saveds __asm Libstart(void)
{  return -1;
}

static APTR functable[]=
{  Openlib,
   Closelib,
   Expungelib,
   Extfunclib,
   Fetchdrivertask,
   (APTR)-1
};

/* Init table used in library initialization. */
static ULONG inittab[]=
{  sizeof(struct Library),
   (ULONG) functable,
   0,
   (ULONG) Initlib
};

static char __aligned libname[]="about.aweblib";
static char __aligned libid[]="about.aweblib " AWEBLIBVSTRING " " __AMIGADATE__;

/* The ROM tag */
struct Resident __aligned romtag=
{  RTC_MATCHWORD,
   &romtag,
   &romtag+1,
   RTF_AUTOINIT,
   AWEBLIBVERSION,
   NT_LIBRARY,
   0,
   libname,
   libid,
   inittab
};

__asm __saveds struct Library *Initlib(
   register __a6 struct ExecBase *sysbase,
   register __a0 struct SegList *seglist,
   register __d0 struct Library *libbase)
{  SysBase=sysbase;
   AboutBase=libbase;
   libbase->lib_Revision=AWEBLIBREVISION;
   libseglist=seglist;
   if(!Initaweblib(libbase))
   {  Expungeaweblib(libbase);
      libbase=NULL;
   }
   return libbase;
}

__asm __saveds struct Library *Openlib(
   register __a6 struct Library *libbase)
{  libbase->lib_OpenCnt++;
   libbase->lib_Flags&=~LIBF_DELEXP;
   if(libbase->lib_OpenCnt==1)
   {  AwebPluginBase=OpenLibrary("awebplugin.library",0);
   }
#ifndef DEMOVERSION
   if(!Fullversion())
   {  Closelib(libbase);
      return NULL;
   }
#endif
   return libbase;
}

__asm __saveds struct SegList *Closelib(
   register __a6 struct Library *libbase)
{  libbase->lib_OpenCnt--;
   if(libbase->lib_OpenCnt==0)
   {  if(AwebPluginBase)
      {  CloseLibrary(AwebPluginBase);
         AwebPluginBase=NULL;
      }
      if(libbase->lib_Flags&LIBF_DELEXP)
      {  return Expungelib(libbase);
      }
   }
   return NULL;
}

__asm __saveds struct SegList *Expungelib(
   register __a6 struct Library *libbase)
{  if(libbase->lib_OpenCnt==0)
   {  ULONG size=libbase->lib_NegSize+libbase->lib_PosSize;
      UBYTE *ptr=(UBYTE *)libbase-libbase->lib_NegSize;
      Remove((struct Node *)libbase);
      Expungeaweblib(libbase);
      FreeMem(ptr,size);
      return libseglist;
   }
   libbase->lib_Flags|=LIBF_DELEXP;
   return NULL;
}

__asm __saveds ULONG Extfunclib(void)
{  return 0;
}

/*-----------------------------------------------------------------------*/

/* Generate HTML content for about: pages */
static UBYTE *GenerateAboutPage(UBYTE *url)
{  UBYTE *html = NULL;
   UBYTE *page = NULL;
   long len;
   UBYTE *version_str;
   UBYTE *about_str;
   long html_len;
   
   /* Extract page name from about: URL (e.g., "about:blank" -> "blank") */
   if(url && STRNIEQUAL(url,"ABOUT:",6))
   {  page = url + 6;
      if(!*page) page = (UBYTE *)"about";
   }
   else
   {  page = (UBYTE *)"about";
   }
   
   /* Get version strings - use Awebversion() function from plugin interface */
   version_str = Awebversion();
   if(!version_str) version_str = (UBYTE *)"Unknown";
   about_str = (UBYTE *)"AWeb";
   
   /* Check for about:blank - must match exactly "blank" or be empty after "blank" */
   if(STRNIEQUAL(page,"blank",5) && (page[5]=='\0' || page[5]==' ' || page[5]=='\t'))
   {  /* about:blank - empty page */
      len = 100;
      html = ALLOCTYPE(UBYTE,len,MEMF_PUBLIC);
      if(html)
      {  strcpy(html,"<html><head><title>about:blank</title></head><body></body></html>");
      }
      return html;
   }
   
   /* Default about page with version info and license acknowledgements */
   /* Calculate required buffer size */
   len = 8192;  /* Large buffer for license text */
   html = ALLOCTYPE(UBYTE,len,MEMF_PUBLIC);
   if(html)
   {  html_len = sprintf(html,
            "<html><head><title>About AWeb</title></head>"
            "<body>"
            "<h1>About AWeb</h1>"
            "<p><strong>%s</strong></p>"
            "<p>Version: %s</p>"
            "<hr>"
            "<h2>About Pages</h2>"
            "<ul>"
            "<li><a href=\"about:blank\">about:blank</a> - Blank page</li>"
            "<li><a href=\"about:\">about:</a> - This page</li>"
            "</ul>"
            "<hr>"
            "<h2>License</h2>"
            "<p>AWeb is distributed under the <strong>AWeb Public License Version 1.0</strong>.</p>"
            "<p>Copyright (C) 2002 YPR Software<br>"
            "Changes Copyright (C) 2025 amigazen project</p>"
            "<p>This program is free software; you can redistribute it and/or modify "
            "it under the terms of the AWeb Public License as included in this distribution.</p>"
            "<p>This program is distributed in the hope that it will be useful, "
            "but WITHOUT ANY WARRANTY; without even the implied warranty of "
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.</p>"
            "<hr>"
            "<h2>Third-Party Components</h2>"
            "<h3>zlib</h3>"
            "<p>zlib compression library is used for HTTP content compression.</p>"
            "<p>Copyright (C) 1995-2023 Jean-loup Gailly and Mark Adler</p>"
            "<p>This software is provided 'as-is', without any express or implied warranty. "
            "In no event will the authors be held liable for any damages arising from "
            "the use of this software.</p>"
            "<p>Permission is granted to anyone to use this software for any purpose, "
            "including commercial applications, and to alter it and redistribute it freely, "
            "subject to the following restrictions:</p>"
            "<ol>"
            "<li>The origin of this software must not be misrepresented; you must not "
            "claim that you wrote the original software. If you use this software in "
            "a product, an acknowledgment in the product documentation would be "
            "appreciated but is not required.</li>"
            "<li>Altered source versions must be plainly marked as such, and must not be "
            "misrepresented as being the original software.</li>"
            "<li>This notice may not be removed or altered from any source distribution.</li>"
            "</ol>"
            "<hr>"
            "<h2>Acknowledgments</h2>"
            "<p>AWeb was originally developed by Yvon Rozijn.</p>"
            "<p>This version is maintained by the amigazen project.</p>"
            "<p>AWeb uses the following AmigaOS components:</p>"
            "<ul>"
            "<li>AmigaOS Exec and Intuition libraries</li>"
            "<li>AmigaOS networking (bsdsocket.library)</li>"
            "<li>AmigaOS graphics and rendering libraries</li>"
            "<li>AmigaOS locale and internationalization support</li>"
            "</ul>"
            "<hr>"
            "<p><small>AWeb is the Amiga web browser.</small></p>"
            "</body></html>",
            about_str,version_str);
      
      /* Ensure null termination */
      if(html_len >= len) html[len-1] = '\0';
   }
   return html;
}

/*-----------------------------------------------------------------------*/

__saveds __asm void Fetchdrivertask(register __a0 struct Fetchdriver *fd)
{  UBYTE *html;
   long html_len;
   BOOL error = FALSE;
   
   if(!fd || !fd->name)
   {  error = TRUE;
   }
   else
   {  /* Generate HTML content */
      html = GenerateAboutPage(fd->name);
      if(html)
      {  html_len = strlen(html);
         Updatetaskattrs(
            AOURL_Contenttype,"text/html",
            AOURL_Data,html,
            AOURL_Datalength,html_len,
            TAG_END);
         /* Free the HTML buffer - it will be copied by the task system */
         FREE(html);
      }
      else
      {  error = TRUE;
      }
   }
   
   Updatetaskattrs(AOTSK_Async,TRUE,
      AOURL_Error,error,
      AOURL_Eof,TRUE,
      AOURL_Terminate,TRUE,
      TAG_END);
}

/*-----------------------------------------------------------------------*/

static ULONG Initaweblib(struct Library *libbase)
{  return TRUE;
}

static void Expungeaweblib(struct Library *libbase)
{
}

