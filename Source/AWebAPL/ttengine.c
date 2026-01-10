/**********************************************************************
 * 
 * This file is part of the AWeb APL distribution
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

/* ttengine.c - Optional ttengine.library support for font rendering */

#include "aweb.h"
#include "ttengine.h"
#include "application.h"
#include "awebprefs.h"
#include <proto/exec.h>
#include <proto/graphics.h>
#include <proto/utility.h>
#include <graphics/text.h>
#include <graphics/rastport.h>
#include <utility/tagitem.h>
#include <stdio.h>

/* Include ttengine library headers */
#include <libraries/ttengine.h>
#include <clib/ttengine_protos.h>
#include <pragma/ttengine_lib.h>

/* Library base pointer */
static struct Library *TTEngineBase = NULL;

/* Flag to track if ttengine is available */
static BOOL ttengine_available = FALSE;

/*------------------------------------------------------------------------*/

/* Initialize ttengine.library support */
BOOL InitTTEngine(void)
{
   
   /* Try to open ttengine.library */
   printf("[TTEngine] Attempting to open ttengine.library (min version %d)\n", TTENGINEMINVERSION);
   TTEngineBase = OpenLibrary("ttengine.library", TTENGINEMINVERSION);
   if(!TTEngineBase)
   {
      printf("[TTEngine] Failed to open ttengine.library - using standard fonts\n");
      ttengine_available = FALSE;
      return FALSE;
   }
   
   /* Check version */
   printf("[TTEngine] Opened ttengine.library, version %d\n", TTEngineBase->lib_Version);
   if(TTEngineBase->lib_Version < TTENGINEMINVERSION)
   {
      printf("[TTEngine] Version too old (%d < %d) - closing library\n", 
             TTEngineBase->lib_Version, TTENGINEMINVERSION);
      CloseLibrary(TTEngineBase);
      TTEngineBase = NULL;
      ttengine_available = FALSE;
      return FALSE;
   }
   
   printf("[TTEngine] Successfully initialized ttengine.library\n");
   ttengine_available = TRUE;
   return TRUE;
}

/*------------------------------------------------------------------------*/

/* Cleanup ttengine.library support */
void FreeTTEngine(void)
{
   if(TTEngineBase)
   {
      printf("[TTEngine] Closing ttengine.library\n");
      CloseLibrary(TTEngineBase);
      TTEngineBase = NULL;
   }
   ttengine_available = FALSE;
}

/*------------------------------------------------------------------------*/

/* Check if ttengine is available */
BOOL TTEngineAvailable(void)
{
   return ttengine_available;
}

/*------------------------------------------------------------------------*/

/* Convert Amiga font name to TrueType family name */
/* Removes .font extension and maps common Amiga font names to TrueType equivalents */
static UBYTE *GetTTFamilyName(UBYTE *fontname, UBYTE *buffer, ULONG bufsize)
{
   UBYTE *p;
   ULONG len;
   
   if(!fontname || !buffer || bufsize == 0)
   {
      return NULL;
   }
   
   /* Copy font name to buffer */
   len = strlen(fontname);
   if(len >= bufsize) len = bufsize - 1;
   Strncpy(buffer, fontname, len);
   buffer[len] = '\0';
   
   /* Remove .font extension if present */
   p = buffer + len;
   while(p > buffer && *p != '.') p--;
   if(*p == '.')
   {
      *p = '\0';
   }
   
   /* Map common Amiga font names to TrueType family names */
   /* Try exact match first, then common mappings */
   if(STRIEQUAL(buffer, "CGTimes") || STRIEQUAL(buffer, "times") || STRIEQUAL(buffer, "Times"))
   {
      Strncpy(buffer, "Times New Roman", bufsize - 1);
      buffer[bufsize - 1] = '\0';
   }
   else if(STRIEQUAL(buffer, "CGHelvetica") || STRIEQUAL(buffer, "helvetica") || STRIEQUAL(buffer, "Helvetica"))
   {
      Strncpy(buffer, "Arial", bufsize - 1);
      buffer[bufsize - 1] = '\0';
   }
   else if(STRIEQUAL(buffer, "Courier") || STRIEQUAL(buffer, "courier"))
   {
      Strncpy(buffer, "Courier New", bufsize - 1);
      buffer[bufsize - 1] = '\0';
   }
   else if(STRIEQUAL(buffer, "Topaz") || STRIEQUAL(buffer, "topaz"))
   {
      Strncpy(buffer, "Courier New", bufsize - 1);
      buffer[bufsize - 1] = '\0';
   }
   /* If no mapping found, use the name as-is (might match a family in database) */
   /* The database might have the font registered with the same name */
   
   return buffer;
}

/*------------------------------------------------------------------------*/

/* Look up the fontsize from Fontprefs for a given TextFont */
/* Returns the fontsize if found, or tf_YSize as fallback */
static LONG GetFontSizeFromPrefs(struct TextFont *font)
{
   struct Fontalias *fa;
   short i;
   LONG fontsize;
   
   /* Default to tf_YSize */
   fontsize = (LONG)font->tf_YSize;
   
   /* Search through font alias list to find matching TextFont */
   for(fa = prefs.aliaslist.first; fa->next; fa = fa->next)
   {
      for(i = 0; i < NRFONTS; i++)
      {
         if(fa->fp[i].font == font)
         {
            /* Found matching TextFont - use the fontsize from Fontprefs */
            return (LONG)fa->fp[i].fontsize;
         }
      }
   }
   
   /* Also check default font preferences */
   for(i = 0; i < NRFONTS; i++)
   {
      if(prefs.font[0][i].font == font || prefs.font[1][i].font == font)
      {
         /* Found in default fonts - use the fontsize from Fontprefs */
         return (LONG)prefs.font[0][i].fontsize;
      }
   }
   
   /* Not found in Fontprefs - use tf_YSize as fallback */
   return fontsize;
}

/*------------------------------------------------------------------------*/

/* Convert TextFont to ttengine font handle */
APTR TTEngineOpenFont(struct TextFont *font)
{
   struct TagItem tags[6];
   UBYTE *fontname;
   UBYTE familyname[256];
   UBYTE *familytable[4];
   LONG fontsize;
   LONG fontweight;
   LONG fontstyle;
   APTR ttfont;
   
   if(!ttengine_available || !font || !TTEngineBase)
   {
      return NULL;
   }
   
   fontname = font->tf_Message.mn_Node.ln_Name;
   /* Get the actual fontsize from Fontprefs if available */
   /* This ensures we use the exact size that was requested when opening the font */
   /* Falls back to tf_YSize if not found in Fontprefs */
   fontsize = GetFontSizeFromPrefs(font);
   
   /* Convert Amiga font name to TrueType family name */
   if(!GetTTFamilyName(fontname, familyname, sizeof(familyname)))
   {
      return NULL;
   }
   
   /* Build family table - try specific name first, then generic fallbacks */
   familytable[0] = familyname;
   /* Add appropriate generic fallback based on font type */
   if(STRIEQUAL(familyname, "Times New Roman") || STRIEQUAL(familyname, "Georgia") || 
      STRIEQUAL(familyname, "Palatino") || STRIEQUAL(familyname, "Garamond"))
   {
      familytable[1] = "serif";
      familytable[2] = "default";
   }
   else if(STRIEQUAL(familyname, "Arial") || STRIEQUAL(familyname, "Helvetica"))
   {
      familytable[1] = "sans-serif";
      familytable[2] = "default";
   }
   else if(STRIEQUAL(familyname, "Courier New") || STRIEQUAL(familyname, "Courier"))
   {
      familytable[1] = "monospaced";
      familytable[2] = "default";
   }
   else
   {
      /* Try the name as-is, then generic fallback */
      familytable[1] = "default";
      familytable[2] = NULL;
   }
   /* Ensure table is NULL-terminated */
   if(familytable[2] != NULL)
   {
      familytable[3] = NULL;
   }
   else
   {
      familytable[2] = NULL;
   }
   
   /* Determine font weight from flags */
   if(font->tf_Style & FSF_BOLD)
   {
      fontweight = TT_FontWeight_Bold;
   }
   else
   {
      fontweight = TT_FontWeight_Normal;
   }
   
   /* Determine font style from flags */
   if(font->tf_Style & FSF_ITALIC)
   {
      fontstyle = TT_FontStyle_Italic;
   }
   else
   {
      fontstyle = TT_FontStyle_Regular;
   }
   
   /* Build tag list - use FamilyTable to search database */
   tags[0].ti_Tag = TT_FamilyTable;
   tags[0].ti_Data = (ULONG)familytable;
   tags[1].ti_Tag = TT_FontSize;
   tags[1].ti_Data = (ULONG)fontsize;
   tags[2].ti_Tag = TT_FontWeight;
   tags[2].ti_Data = fontweight;
   tags[3].ti_Tag = TT_FontStyle;
   tags[3].ti_Data = fontstyle;
   tags[4].ti_Tag = TAG_END;
   
   /* Open font using ttengine */
   ttfont = TT_OpenFontA(tags);
   
   return ttfont;
}

/*------------------------------------------------------------------------*/

/* Close ttengine font handle */
void TTEngineCloseFont(APTR ttfont)
{
   if(ttengine_available && ttfont && TTEngineBase)
   {
      TT_CloseFont(ttfont);
   }
}

/*------------------------------------------------------------------------*/

/* Parse comma-separated font family list into NULL-terminated table */
/* Note: This function creates a working copy of the fontface string and modifies it */
/* The familytable points into this working copy, so it must remain valid */
static void ParseFontFamilyList(UBYTE *fontface, UBYTE *workbuf, ULONG workbufsize, 
                                 UBYTE **familytable, ULONG maxfamilies)
{
   UBYTE *p, *q, *start;
   ULONG count;
   BOOL inQuotes;
   UBYTE quote;
   
   if(!fontface || !workbuf || !familytable || maxfamilies == 0 || workbufsize == 0)
   {
      if(familytable) familytable[0] = NULL;
      return;
   }
   
   /* Copy fontface to work buffer */
   Strncpy(workbuf, fontface, workbufsize - 1);
   workbuf[workbufsize - 1] = '\0';
   
   count = 0;
   p = workbuf;
   inQuotes = FALSE;
   quote = 0;
   
   while(*p && count < maxfamilies - 1)
   {
      /* Skip whitespace */
      while(*p == ' ' || *p == '\t') p++;
      if(!*p) break;
      
      start = p;
      
      /* Check for quoted name */
      if(*p == '"' || *p == '\'')
      {
         quote = *p;
         inQuotes = TRUE;
         start = ++p; /* Skip opening quote */
      }
      
      /* Find end of family name */
      q = p;
      while(*q)
      {
         if(inQuotes)
         {
            if(*q == quote)
            {
               /* End of quoted name */
               break;
            }
         }
         else
         {
            if(*q == ',')
            {
               break;
            }
         }
         q++;
      }
      
      /* Store family name */
      if(q > start)
      {
         /* Null-terminate this family name */
         if(*q) *q++ = '\0';
         familytable[count++] = start;
      }
      
      p = q;
      if(*p == ',') p++;
      inQuotes = FALSE;
      quote = 0;
   }
   
   /* Add generic fallbacks if not already present */
   if(count < maxfamilies - 2)
   {
      ULONG i;
      BOOL hasSerif = FALSE, hasSansSerif = FALSE, hasMonospaced = FALSE, hasDefault = FALSE;
      
      /* Check what generic families are already in the list */
      for(i = 0; i < count; i++)
      {
         if(STRIEQUAL(familytable[i], "serif")) hasSerif = TRUE;
         else if(STRIEQUAL(familytable[i], "sans-serif")) hasSansSerif = TRUE;
         else if(STRIEQUAL(familytable[i], "monospaced")) hasMonospaced = TRUE;
         else if(STRIEQUAL(familytable[i], "default")) hasDefault = TRUE;
      }
      
      /* Add appropriate generic fallback based on first family */
      if(count > 0 && !hasSerif && !hasSansSerif && !hasMonospaced)
      {
         UBYTE *first = familytable[0];
         if(STRIEQUAL(first, "Times New Roman") || STRIEQUAL(first, "Georgia") || 
            STRIEQUAL(first, "Palatino") || STRIEQUAL(first, "Garamond"))
         {
            if(!hasSerif) familytable[count++] = "serif";
         }
         else if(STRIEQUAL(first, "Arial") || STRIEQUAL(first, "Helvetica") ||
                 STRIEQUAL(first, "Verdana"))
         {
            if(!hasSansSerif) familytable[count++] = "sans-serif";
         }
         else if(STRIEQUAL(first, "Courier New") || STRIEQUAL(first, "Courier"))
         {
            if(!hasMonospaced) familytable[count++] = "monospaced";
         }
      }
      
      /* Always add default as final fallback */
      if(!hasDefault) familytable[count++] = "default";
   }
   
   familytable[count] = NULL;
}

/* Get font name from Fontprefs for a given TextFont */
/* Returns the font name if found, or NULL if not found */
static UBYTE *GetFontNameFromPrefs(struct TextFont *font)
{
   struct Fontalias *fa;
   short i;
   
   if(!font)
   {
      printf("[TTEngine] GetFontNameFromPrefs: font is NULL\n");
      return NULL;
   }
   
   printf("[TTEngine] GetFontNameFromPrefs: Looking up font name for TextFont %p (name: %s, size: %d)\n", 
          font, font->tf_Message.mn_Node.ln_Name, font->tf_YSize);
   
   /* Search through font alias list to find matching TextFont */
   for(fa = prefs.aliaslist.first; fa->next; fa = fa->next)
   {
      for(i = 0; i < NRFONTS; i++)
      {
         if(fa->fp[i].font == font)
         {
            /* Found matching TextFont - return the font name from Fontprefs */
         printf("[TTEngine] GetFontNameFromPrefs: Found in alias list: %s (size: %d)\n", 
                fa->fp[i].fontname ? (char *)fa->fp[i].fontname : "(null)", fa->fp[i].fontsize);
            return fa->fp[i].fontname;
         }
      }
   }
   
   /* Also check default font preferences */
   for(i = 0; i < NRFONTS; i++)
   {
      if(prefs.font[0][i].font == font || prefs.font[1][i].font == font)
      {
         /* Found in default fonts - return the font name from Fontprefs */
         printf("[TTEngine] GetFontNameFromPrefs: Found in default fonts: %s (size: %d)\n", 
                prefs.font[0][i].fontname ? (char *)prefs.font[0][i].fontname : "(null)", prefs.font[0][i].fontsize);
         return prefs.font[0][i].fontname;
      }
   }
   
   /* Not found in Fontprefs - return NULL */
   printf("[TTEngine] GetFontNameFromPrefs: Not found in Fontprefs\n");
   return NULL;
}

/* Set font on rastport (uses ttengine if available, else standard SetFont) */
/* fontface can be from CSS font-family or HTML FONT face attribute */
/* If fontface is NULL, font name will be looked up from Fontprefs */
/* style is the text element's style flags (FSF_BOLD, FSF_ITALIC) - use this instead of font->tf_Style */
void TTEngineSetFont(struct RastPort *rp, struct TextFont *font, UBYTE *fontface, USHORT style)
{
   APTR ttfont;
   struct TagItem tags[6];
   struct TagItem attrtags[4];
   UBYTE *familytable[8];
   UBYTE workbuf[512];
   UBYTE *fontname;
   LONG fontsize;
   LONG fontweight;
   LONG fontstyle;
   struct Window *window = NULL;
   struct Screen *screen = NULL;
   ULONG i;
   BOOL was_ttengine_active = FALSE;
   
   if(!rp || !font)
   {
      printf("[TTEngine] TTEngineSetFont: Invalid parameters (rp=%p, font=%p)\n", rp, font);
      return;
   }
   
   printf("[TTEngine] TTEngineSetFont: rp=%p, font=%p (name: %s, size: %d), fontface=%s, style=0x%04x\n", 
          rp, font, font->tf_Message.mn_Node.ln_Name, font->tf_YSize, 
          fontface ? (char *)fontface : "(null)", style);
   
   /* Always use normal SetFont first - let AWeb handle font sizing and selection */
   SetFont(rp, font);
   
   /* Check if a ttengine font is currently active - we'll need to clear it */
   /* if we can't set a new one for this element */
   if(ttengine_available && TTEngineBase)
   {
      was_ttengine_active = IsTTEngineFontActive(rp);
   }
   
   /* Only use ttengine if available */
   if(ttengine_available && TTEngineBase)
   {
      printf("[TTEngine] TTEngineSetFont: ttengine is available\n");
      
      /* Get font name from fontface (CSS or HTML face attribute) or from Fontprefs */
      if(fontface && *fontface)
      {
         /* Use fontface directly (CSS font-family or HTML FONT face attribute) */
         /* CSS font-family strings are already in the correct format for ttengine */
         fontname = fontface;
         printf("[TTEngine] TTEngineSetFont: Using fontface: %s\n", fontname);
      }
      else
      {
         /* No fontface - try to get font name from TextFont name */
         /* Convert TextFont name to TrueType family name */
         printf("[TTEngine] TTEngineSetFont: No fontface, converting TextFont name: %s\n", 
                font->tf_Message.mn_Node.ln_Name);
         if(GetTTFamilyName(font->tf_Message.mn_Node.ln_Name, workbuf, sizeof(workbuf)))
         {
            printf("[TTEngine] TTEngineSetFont: Converted TextFont name to TrueType family: %s\n", workbuf);
            fontname = workbuf;
         }
         else
         {
            printf("[TTEngine] TTEngineSetFont: Failed to convert TextFont name, using as-is\n");
            fontname = font->tf_Message.mn_Node.ln_Name;
         }
      }
      
      /* If we have a font name, try to use ttengine */
      if(fontname && *fontname)
      {
         /* Use the exact same size as the TextFont that AWeb opened */
         fontsize = (LONG)font->tf_YSize;
         
         /* Determine font weight from text element style flags (not font->tf_Style) */
         /* The text element's style flags indicate bold/italic, not the TextFont's style */
         if(style & FSF_BOLD)
         {
            fontweight = TT_FontWeight_Bold;
         }
         else
         {
            fontweight = TT_FontWeight_Normal;
         }
         
         /* Determine font style from text element style flags */
         if(style & FSF_ITALIC)
         {
            fontstyle = TT_FontStyle_Italic;
         }
         else
         {
            fontstyle = TT_FontStyle_Regular;
         }
         
         printf("[TTEngine] TTEngineSetFont: Opening font - name: %s, size: %ld, weight: %ld, style: %ld\n", 
                fontname, fontsize, fontweight, fontstyle);
         
         /* Parse comma-separated font family list (from CSS or HTML face attribute) */
         /* Or use single font name (already converted to TrueType family name if from Fontprefs) */
         ParseFontFamilyList(fontname, workbuf, sizeof(workbuf), 
                            familytable, sizeof(familytable)/sizeof(familytable[0]));
         
         /* Debug: print family table */
         printf("[TTEngine] TTEngineSetFont: Family table: ");
         for(i = 0; i < sizeof(familytable)/sizeof(familytable[0]) && familytable[i]; i++)
         {
            printf("%s", familytable[i]);
            if(familytable[i+1]) printf(", ");
         }
         printf("\n");
         
         /* Build tag list using font name with same size as TextFont */
         tags[0].ti_Tag = TT_FamilyTable;
         tags[0].ti_Data = (ULONG)familytable;
         tags[1].ti_Tag = TT_FontSize;
         tags[1].ti_Data = (ULONG)fontsize;
         tags[2].ti_Tag = TT_FontWeight;
         tags[2].ti_Data = (ULONG)fontweight;
         tags[3].ti_Tag = TT_FontStyle;
         tags[3].ti_Data = (ULONG)fontstyle;
         tags[4].ti_Tag = TAG_END;
         
         /* Try to open font using ttengine */
         printf("[TTEngine] TTEngineSetFont: Calling TT_OpenFontA()\n");
         ttfont = TT_OpenFontA(tags);
         
         if(ttfont)
         {
            printf("[TTEngine] TTEngineSetFont: Successfully opened ttengine font %p\n", ttfont);
            
            /* Set up ttengine rendering environment */
            /* Try to get window from layer */
            if(rp->Layer && rp->Layer->Window)
            {
               window = rp->Layer->Window;
            }
            
            /* If we have a window, use it for color mapping */
            if(window)
            {
               printf("[TTEngine] TTEngineSetFont: Setting TT_Window for color mapping\n");
               attrtags[0].ti_Tag = TT_Window;
               attrtags[0].ti_Data = (ULONG)window;
               attrtags[1].ti_Tag = TT_Antialias;
               attrtags[1].ti_Data = TT_Antialias_Auto;
               attrtags[2].ti_Tag = TT_DiskFontMetrics;
               attrtags[2].ti_Data = TRUE;
               attrtags[3].ti_Tag = TAG_END;
               TT_SetAttrsA(rp, attrtags);
            }
            else
            {
               /* Try to get screen - check if we can get it from the application */
               screen = (struct Screen *)Agetattr(Aweb(), AOAPP_Screen);
               if(screen)
               {
                  printf("[TTEngine] TTEngineSetFont: Setting TT_Screen for color mapping\n");
                  attrtags[0].ti_Tag = TT_Screen;
                  attrtags[0].ti_Data = (ULONG)screen;
                  attrtags[1].ti_Tag = TT_Antialias;
                  attrtags[1].ti_Data = TT_Antialias_Auto;
                  attrtags[2].ti_Tag = TT_DiskFontMetrics;
                  attrtags[2].ti_Data = TRUE;
                  attrtags[3].ti_Tag = TAG_END;
                  TT_SetAttrsA(rp, attrtags);
               }
               else
               {
                  printf("[TTEngine] TTEngineSetFont: Setting TT_Antialias and TT_DiskFontMetrics only\n");
                  /* Set antialiasing and disk font metrics */
                  attrtags[0].ti_Tag = TT_Antialias;
                  attrtags[0].ti_Data = TT_Antialias_Auto;
                  attrtags[1].ti_Tag = TT_DiskFontMetrics;
                  attrtags[1].ti_Data = TRUE;
                  attrtags[2].ti_Tag = TAG_END;
                  TT_SetAttrsA(rp, attrtags);
               }
            }
            
            /* Set ttengine font on rastport */
            /* TT_SetFont returns TRUE on success */
            printf("[TTEngine] TTEngineSetFont: Calling TT_SetFont()\n");
            if(TT_SetFont(rp, ttfont))
            {
               printf("[TTEngine] TTEngineSetFont: Successfully set ttengine font on rastport\n");
               /* Success - ttengine font is now active on rastport */
               /* Use TT_Text() for rendering instead of Text() */
               return;
            }
            else
            {
               printf("[TTEngine] TTEngineSetFont: TT_SetFont() failed, closing font and falling back\n");
               /* Failed to set, close and fall through to standard font */
               TT_CloseFont(ttfont);
            }
         }
         else
         {
            printf("[TTEngine] TTEngineSetFont: TT_OpenFontA() returned NULL - font not found in ttengine database\n");
         }
         /* If ttengine font not found, fall through to use standard TextFont */
      }
      else
      {
         printf("[TTEngine] TTEngineSetFont: No font name available\n");
      }
   }
   
   /* If we reach here, we're not using ttengine for this font */
   /* If a ttengine font was previously active but we couldn't set a new one, */
   /* we need to clear it to prevent font inheritance */
   if(was_ttengine_active && ttengine_available && TTEngineBase)
   {
      /* Check if ttengine font is still active (it shouldn't be if we failed to set a new one) */
      if(IsTTEngineFontActive(rp))
      {
         printf("[TTEngine] TTEngineSetFont: Previous ttengine font still active, clearing it\n");
         /* Clear ttengine state on rastport - this will reset it to use standard fonts */
         TT_DoneRastPort(rp);
      }
   }
   
   printf("[TTEngine] TTEngineSetFont: Using standard SetFont (normal AWeb font)\n");
   /* If ttengine not available or font not found, normal SetFont was already called above */
}

/*------------------------------------------------------------------------*/

/* Check if ttengine font is currently active on a rastport */
BOOL IsTTEngineFontActive(struct RastPort *rp)
{
   UBYTE *fontname;
   struct TagItem tags[2];
   BOOL result;
   
   if(!ttengine_available || !TTEngineBase || !rp)
   {
      return FALSE;
   }
   
   /* Try to get font name - if we can get it, a ttengine font is active */
   /* TT_GetAttrsA writes the font name pointer to ti_Data */
   fontname = NULL;
   tags[0].ti_Tag = TT_FontName;
   tags[0].ti_Data = (ULONG)&fontname;
   tags[1].ti_Tag = TAG_END;
   TT_GetAttrsA(rp, tags);
   
   /* If fontname is non-NULL, a ttengine font is active */
   result = (BOOL)(fontname != NULL);
   return result;
}

/*------------------------------------------------------------------------*/

/* Text rendering wrapper (uses ttengine if available) */
/* Uses TT_Text() if ttengine font is active, otherwise uses standard Text() */
void TTEngineText(struct RastPort *rp, UBYTE *string, ULONG count)
{
   if(!rp || !string || count == 0)
   {
      return;
   }
   
   /* Check if ttengine font is active on this rastport */
   if(IsTTEngineFontActive(rp))
   {
      /* Use TT_Text() - ttengine font is active */
      TT_Text(rp, string, count);
   }
   else
   {
      /* Use standard Text() - no ttengine font active */
      Text(rp, string, count);
   }
}

/*------------------------------------------------------------------------*/

/* Text length wrapper (uses ttengine if available) */
ULONG TTEngineTextLength(struct RastPort *rp, UBYTE *string, ULONG count)
{
   if(!rp || !string || count == 0)
   {
      return 0;
   }
   
   /* Check if ttengine font is active on this rastport */
   if(IsTTEngineFontActive(rp))
   {
      /* Use TT_TextLength() - ttengine font is active */
      return TT_TextLength(rp, string, count);
   }
   else
   {
      /* Use standard TextLength() - no ttengine font active */
      return TextLength(rp, string, count);
   }
}

/*------------------------------------------------------------------------*/

/* Text extent wrapper (uses ttengine if available) */
void TTEngineTextExtent(struct RastPort *rp, UBYTE *string, WORD count, struct TextExtent *te)
{
   if(!rp || !string || count == 0 || !te)
   {
      return;
   }
   
   /* Check if ttengine font is active on this rastport */
   if(IsTTEngineFontActive(rp))
   {
      /* Use TT_TextExtent() - ttengine font is active */
      TT_TextExtent(rp, string, count, te);
   }
   else
   {
      /* Use standard TextExtent() - no ttengine font active */
      TextExtent(rp, string, count, te);
   }
}

/*------------------------------------------------------------------------*/

/* Text fit wrapper (uses ttengine if available) */
ULONG TTEngineTextFit(struct RastPort *rp, UBYTE *string, UWORD count, struct TextExtent *te,
   struct TextExtent *tec, WORD dir, UWORD cwidth, UWORD cheight)
{
   if(!rp || !string || count == 0)
   {
      return 0;
   }
   
   /* Check if ttengine font is active on this rastport */
   if(IsTTEngineFontActive(rp))
   {
      /* Use TT_TextFit() - ttengine font is active */
      return TT_TextFit(rp, string, count, te, tec, dir, cwidth, cheight);
   }
   else
   {
      /* Use standard TextFit() - no ttengine font active */
      return TextFit(rp, string, count, te, tec, dir, cwidth, cheight);
   }
}
