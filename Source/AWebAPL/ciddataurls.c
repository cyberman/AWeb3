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

/* ciddataurls.c - cid: and data: URL scheme handlers */

#include "aweb.h"
#include "fetchdriver.h"
#include "cidregistry.h"
#include "tcperr.h"
#include "task.h"
#include <proto/exec.h>
#include <proto/utility.h>
#include <proto/dos.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>

/* Debug printf for data: URL handler */
static void debug_printf(const char *format, ...)
{  va_list args;
   va_start(args, format);
   vprintf(format, args);
   va_end(args);
}

/* Base64 character to value conversion */
static UBYTE Base64Char(UBYTE c)
{  if(c >= 'A' && c <= 'Z') return (UBYTE)(c - 'A');
   if(c >= 'a' && c <= 'z') return (UBYTE)(c - 'a' + 26);
   if(c >= '0' && c <= '9') return (UBYTE)(c - '0' + 52);
   if(c == '+') return (UBYTE)62;
   if(c == '/') return (UBYTE)63;
   return (UBYTE)64; /* Invalid */
}

/* Decode base64 encoded data (for data: URLs) */
static UBYTE *DecodeBase64Data(UBYTE *input, long inputlen, long *outputlen)
{  UBYTE *output;
   UBYTE *out;
   UBYTE *in;
   UBYTE *end;
   UBYTE c1, c2, c3, c4;
   long len;
   
   if(!input || inputlen <= 0)
   {  if(outputlen) *outputlen = 0;
      return NULL;
   }
   
   /* Calculate output length (approximately 3/4 of input) */
   len = (inputlen * 3) / 4 + 1;
   output = (UBYTE *)Allocmem(len, 0);
   if(!output)
   {  if(outputlen) *outputlen = 0;
      return NULL;
   }
   
   out = output;
   in = input;
   end = input + inputlen;
   
   while(in < end - 3)
   {  /* Skip whitespace */
      while(in < end && (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n'))
      {  in++;
      }
      if(in >= end - 3) break;
      
      c1 = Base64Char(in[0]);
      c2 = Base64Char(in[1]);
      c3 = Base64Char(in[2]);
      c4 = Base64Char(in[3]);
      
      if(c1 >= 64 || c2 >= 64) break;
      
      /* Bounds check before writing */
      if(out >= output + len) break;
      *out++ = (c1 << 2) | (c2 >> 4);
      
      if(c3 >= 64)
      {  /* Padding found */
         break;
      }
      
      /* Bounds check before writing */
      if(out >= output + len) break;
      *out++ = ((c2 & 0x0F) << 4) | (c3 >> 2);
      
      if(c4 >= 64)
      {  /* Padding found */
         break;
      }
      
      /* Bounds check before writing */
      if(out >= output + len) break;
      *out++ = ((c3 & 0x03) << 6) | c4;
      
      in += 4;
   }
   
   if(outputlen) *outputlen = out - output;
   return output;
}

/* URL decode %XX sequences (simple version for data: URLs) */
static void Urldecode(UBYTE *str)
{  UBYTE *p, *q;
   UBYTE hex[3];
   long val;
   
   if(!str) return;
   
   p = q = str;
   while(*p)
   {  if(*p == '%' && p[1] && p[2])
      {  hex[0] = p[1];
         hex[1] = p[2];
         hex[2] = '\0';
         sscanf(hex, "%lx", &val);
         *q++ = (UBYTE)val;
         p += 3;
      }
      else if(*p == '+')
      {  *q++ = ' ';
         p++;
      }
      else
      {  *q++ = *p++;
      }
   }
   *q = '\0';
}

/*------------------------------------------------------------------------*/

/* Content-ID URL handler (cid: scheme) */
void Cidurltask(struct Fetchdriver *fd)
{  UBYTE *content_id;
   UBYTE *referer;
   UBYTE *content_type = NULL;
   UBYTE *data = NULL;
   long datalen = 0;
   BOOL error = FALSE;
   BOOL eof = TRUE;
   
   /* Extract Content-ID from URL (skip "cid:" prefix) */
   content_id = fd->name;
   
   /* Get referer URL to find the source document */
   referer = fd->referer;
   
   if(!content_id || !*content_id)
   {  error = TRUE;
   }
   else if(!referer || !*referer)
   {  /* No referer - can't look up part */
      error = TRUE;
   }
   else
   {  /* Look up part data by Content-ID and referer */
      if(!Findcidpart(referer, content_id, &content_type, &data, &datalen))
      {  error = TRUE;
      }
   }
   
   if(error)
   {  Tcperror(fd, TCPERR_XAWEB, fd->name);
   }
   else
   {  /* Set content type */
      if(content_type)
      {  Updatetaskattrs(AOURL_Contenttype, content_type, TAG_END);
      }
      
      /* Send data directly from RAM (no copy needed)
       * The CID registry keeps the original data in memory for the document lifetime.
       * imgsource will use RAM mode (DTST_MEMORY) to render directly from this buffer,
       * avoiding disk I/O. The registry copy persists in RAM until Unregistercidparts()
       * is called when the document is closed. */
      if(data && datalen > 0)
      {  Updatetaskattrs(
            AOURL_Data, data,
            AOURL_Datalength, datalen,
            TAG_END);
         /* NOTE: Do NOT free data here - it's owned by the CID registry and will remain
          * valid for the document lifetime. imgsource will use it directly via RAM mode. */
      }
   }
   
   Updatetaskattrs(AOTSK_Async, TRUE,
      AOURL_Error, error,
      AOURL_Eof, eof,
      AOURL_Terminate, TRUE,
      TAG_END);
}

/*------------------------------------------------------------------------*/

/* Data URI handler (data: scheme) */
void Dataurltask(struct Fetchdriver *fd)
{     UBYTE *data_uri;
   UBYTE *comma;
   UBYTE *content_type = "text/plain";
   UBYTE *content_type_allocated = NULL;
   UBYTE *data = NULL;
   long datalen = 0;
   BOOL base64 = FALSE;
   BOOL error = FALSE;
   BOOL eof = TRUE;
   UBYTE *mediatype_copy = NULL;
   UBYTE *semicolon;
   UBYTE *data_str;
   UBYTE *decoded_data = NULL;
   long mediatype_len;
   
   debug_printf("DATA: Dataurltask called, fd->name=%s\n", fd->name ? (char *)fd->name : "(null)");
   /* fd->name contains the data: URL without the "data:" prefix (stripped in fetch.c)
    * We need to reconstruct the full data: URL string for the registry key */
   data_uri = fd->name;
   
   if(!data_uri || !*data_uri)
   {  debug_printf("DATA: ERROR - data_uri is null or empty\n");
      error = TRUE;
   }
   else
   {  /* Parse data URI: data:[<mediatype>][;base64],<data> */
      debug_printf("DATA: Parsing data URI, len=%ld\n", strlen(data_uri));
      comma = strchr(data_uri, ',');
      if(!comma)
      {  debug_printf("DATA: ERROR - No comma found in data URI\n");
         error = TRUE;
      }
      else
      {  /* Make a copy of mediatype part for parsing */
         mediatype_len = comma - data_uri;
         if(mediatype_len > 0)
         {  mediatype_copy = (UBYTE *)Allocmem(mediatype_len + 1, 0);
            if(mediatype_copy)
            {  memcpy(mediatype_copy, data_uri, mediatype_len);
               mediatype_copy[mediatype_len] = '\0';
            }
         }
         data_str = comma + 1;  /* Point to data */
         debug_printf("DATA: Found comma, mediatype_len=%ld, data_str len=%ld\n", mediatype_len, strlen(data_str));
         
         if(mediatype_copy)
         {  /* Check for base64 encoding */
            if(strstr(mediatype_copy, ";base64"))
            {  base64 = TRUE;
               debug_printf("DATA: base64 encoding detected\n");
            }
            
            /* Extract content type */
            semicolon = strchr(mediatype_copy, ';');
            if(semicolon)
            {  *semicolon = '\0';
            }
            
            debug_printf("DATA: Mediatype: %s\n", mediatype_copy);
            if(*mediatype_copy)
            {  /* Allocate separate copy for content_type */
               content_type_allocated = Dupstr(mediatype_copy, -1);
               if(content_type_allocated)
               {  content_type = content_type_allocated;
                  debug_printf("DATA: Content type allocated: %s\n", content_type);
               }
               else
               {  debug_printf("DATA: ERROR - Failed to allocate content_type\n");
               }
            }
         }
         
         /* Decode data */
         debug_printf("DATA: Decoding data, base64=%ld, data_str len=%ld\n", (ULONG)base64, strlen(data_str));
         if(base64)
         {  decoded_data = DecodeBase64Data((UBYTE *)data_str, strlen(data_str), &datalen);
            debug_printf("DATA: Base64 decode result: decoded_data=%lx, datalen=%ld\n", (ULONG)decoded_data, datalen);
            if(!decoded_data || datalen <= 0)
            {  debug_printf("DATA: ERROR - Base64 decode failed\n");
               error = TRUE;
            }
            else
            {  data = decoded_data;
               debug_printf("DATA: Base64 decode successful, datalen=%ld\n", datalen);
            }
         }
         else
         {  /* URL decode */
            data = (UBYTE *)Dupstr((UBYTE *)data_str, -1);
            if(data)
            {  Urldecode(data);
               datalen = strlen(data);
            }
            else
            {  error = TRUE;
            }
         }
      }
   }
   
   if(error)
   {  /* Free allocated data on error only */
      if(decoded_data) FREE(decoded_data);
      else if(data && data != content_type_allocated) FREE(data);
      if(content_type_allocated) FREE(content_type_allocated);
      if(mediatype_copy) FREE(mediatype_copy);
      Tcperror(fd, TCPERR_XAWEB, fd->name);
   }
   else
   {  debug_printf("DATA: Setting content type and sending data\n");
      /* Set content type first */
      Updatetaskattrs(AOURL_Contenttype, content_type, TAG_END);
      debug_printf("DATA: Content type set\n");
      
      /* Register decoded data in unified registry for persistence
       * This keeps the data in RAM for the document lifetime
       * For data: URLs, referer_url is NULL and part_id is the full data: URL string (with "data:" prefix) */
      if(data && datalen > 0 && data_uri)
      {  UBYTE *full_data_url;
         long full_url_len;
         
         /* Reconstruct full data: URL string (fd->name has "data:" prefix stripped) */
         full_url_len = 5 + strlen(data_uri) + 1; /* "data:" + data_uri + null */
         full_data_url = (UBYTE *)Allocmem(full_url_len, 0);
         if(full_data_url)
         {  strcpy(full_data_url, "data:");
            strcat(full_data_url, data_uri);
            Registercidpart(NULL, full_data_url, content_type, data, datalen);
            FREE(full_data_url); /* Registry owns the data, not the URL string */
            debug_printf("DATA: Registered data: URL in registry for persistence\n");
         }
         else
         {  debug_printf("DATA: WARNING - Failed to allocate full data: URL string for registry\n");
         }
      }
      
      /* Send data directly from RAM (no copy needed)
       * imgsource will use RAM mode (DTST_MEMORY) to render directly from this buffer,
       * avoiding disk I/O. The registry keeps the original data in RAM for the document lifetime. */
      if(data && datalen > 0)
      {  debug_printf("DATA: Sending RAM data to Updatetaskattrs, data=%lx, datalen=%ld\n", (ULONG)data, datalen);
         Updatetaskattrs(
            AOURL_Data, data,
            AOURL_Datalength, datalen,
            TAG_END);
         debug_printf("DATA: RAM data sent to Updatetaskattrs\n");
         /* NOTE: Do NOT free data here - it's owned by the CID registry and will remain
          * valid for the document lifetime. imgsource will use it directly via RAM mode. */
      }
      else
      {  debug_printf("DATA: WARNING - No data to send\n");
      }
      
      /* Send EOF separately (imgsource processes this after data) */
      debug_printf("DATA: Sending EOF\n");
      Updatetaskattrs(AOTSK_Async, TRUE,
         AOURL_Error, error,
         AOURL_Eof, eof,
         AOURL_Terminate, TRUE,
         TAG_END);
      debug_printf("DATA: EOF sent\n");
      
      /* Free allocated strings (but NOT the data - registry owns it now) */
      if(content_type_allocated) FREE(content_type_allocated);
      if(mediatype_copy) FREE(mediatype_copy);
      debug_printf("DATA: Cleanup complete\n");
      
      /* NOTE: We don't free 'data' here because it's now owned by the registry.
       * The registry keeps it in RAM for the document lifetime and will free it
       * when Unregistercidparts() or Cleanupcidregistry() is called. */
   }
   
   debug_printf("DATA: Dataurltask complete\n");
}

