/**********************************************************************
 * 
 * This file is part of the AWebZen distribution
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

/* rssrender.c - RSS/Atom HTML4 renderer */

#include "rss.h"
#include <exec/memory.h>
#include <exec/types.h>
#include <string.h>
#include <stdio.h>
#include <clib/awebplugin_protos.h>
#include <pragmas/awebplugin_pragmas.h>
#include <proto/exec.h>

/* Helper: Escape HTML special characters */
static void EscapeHtml(UBYTE *dest, UBYTE *src, long len, long maxlen)
{  UBYTE *p;
   UBYTE *d;
   long remaining;
   
   if(!dest || !src || len <= 0 || maxlen <= 0) return;
   
   d = dest;
   remaining = maxlen - 1;
   p = src;
   
   while(p < src + len && remaining > 0)
   {  if(*p == '<')
      {  if(remaining >= 4)
         {  strcpy(d, "&lt;");
            d += 4;
            remaining -= 4;
         }
         else
         {  break;
         }
      }
      else if(*p == '>')
      {  if(remaining >= 4)
         {  strcpy(d, "&gt;");
            d += 4;
            remaining -= 4;
         }
         else
         {  break;
         }
      }
      else if(*p == '&')
      {  if(remaining >= 5)
         {  strcpy(d, "&amp;");
            d += 5;
            remaining -= 5;
         }
         else
         {  break;
         }
      }
      else if(*p == '"')
      {  if(remaining >= 6)
         {  strcpy(d, "&quot;");
            d += 6;
            remaining -= 6;
         }
         else
         {  break;
         }
      }
      else
      {  *d++ = *p;
         remaining--;
      }
      p++;
   }
   
   *d = '\0';
}

/* Helper: Append to HTML buffer */
static void AppendHtml(struct RssFilterData *fd, UBYTE *html, long len)
{  UBYTE *newbuffer;
   long newlen;
   
   if(!fd || !html || len <= 0) return;
   
   newlen = fd->html_buflen + len;
   if(newlen >= fd->html_bufsize)
   {  newbuffer = (UBYTE *)AllocVec(newlen + 4096, MEMF_CLEAR);
      if(newbuffer)
      {  if(fd->html_buffer)
         {  memcpy(newbuffer, fd->html_buffer, fd->html_buflen);
            FreeVec(fd->html_buffer);
         }
         fd->html_buffer = newbuffer;
         fd->html_bufsize = newlen + 4096;
      }
      else
      {  return;
      }
   }
   
   memcpy(fd->html_buffer + fd->html_buflen, html, len);
   fd->html_buflen += len;
}

/* Render feed to HTML with NetNewsWire-style layout */
void RenderFeedToHtml(struct RssFilterData *fd, void *handle)
{  struct FeedChannel *channel;
   struct FeedItem *item;
   UBYTE html[8192];
   UBYTE escaped[2048];
   long len;
   long itemnum;
   
   if(!fd || !fd->parser || !fd->parser->channel) return;
   
   channel = fd->parser->channel;
   
   /* Write HTML header with JavaScript if not already written */
   if(!fd->header_written)
   {  len = sprintf(html, 
         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n"
         "<HTML>\n<HEAD>\n<TITLE>");
      
      if(channel->title && channel->titlelen > 0)
      {  EscapeHtml(escaped, channel->title, channel->titlelen, sizeof(escaped));
         len += sprintf(html + len, "%s", escaped);
      }
      else
      {  len += sprintf(html + len, "RSS Feed");
      }
      
      len += sprintf(html + len, 
         "</TITLE>\n"
         "<SCRIPT LANGUAGE=\"JavaScript1.1\">\n"
         "<!--\n"
         "function showArticle(id) {\n"
         "  var i;\n"
         "  for(i = 1; i <= %ld; i++) {\n"
         "    var elem = document.getElementById('article' + i);\n"
         "    if(elem) {\n"
         "      if(i == id) {\n"
         "        elem.style.display = 'block';\n"
         "      } else {\n"
         "        elem.style.display = 'none';\n"
         "      }\n"
         "    }\n"
         "  }\n"
         "  var link = document.getElementById('link' + id);\n"
         "  if(link) link.style.fontWeight = 'bold';\n"
         "  for(i = 1; i <= %ld; i++) {\n"
         "    if(i != id) {\n"
         "      var otherLink = document.getElementById('link' + i);\n"
         "      if(otherLink) otherLink.style.fontWeight = 'normal';\n"
         "    }\n"
         "  }\n"
         "}\n"
         "//-->\n"
         "</SCRIPT>\n"
         "<STYLE TYPE=\"text/css\">\n"
         "<!--\n"
         "BODY { font-family: Arial, Helvetica, sans-serif; margin: 0; padding: 0; background: #F5F5F5; }\n"
         ".sidebar { background: #FFFFFF; border-right: 1px solid #CCCCCC; padding: 10px; width: 300px; }\n"
         ".sidebar H1 { font-size: 18px; margin: 0 0 10px 0; color: #333333; border-bottom: 2px solid #0066CC; padding-bottom: 5px; }\n"
         ".sidebar H2 { font-size: 14px; margin: 10px 0 5px 0; color: #666666; }\n"
         ".itemlist { list-style: none; padding: 0; margin: 0; }\n"
         ".itemlist LI { margin: 0 0 8px 0; padding: 8px; background: #F9F9F9; border-left: 3px solid #CCCCCC; cursor: pointer; }\n"
         ".itemlist LI:hover { background: #EEEEEE; border-left-color: #0066CC; }\n"
         ".itemlist A { text-decoration: none; color: #333333; display: block; font-size: 12px; line-height: 1.4; }\n"
         ".itemlist A:visited { color: #666666; }\n"
         ".maincontent { padding: 20px; background: #FFFFFF; }\n"
         ".article { display: none; margin-bottom: 30px; padding: 20px; background: #FAFAFA; border: 1px solid #DDDDDD; }\n"
         ".article H2 { margin: 0 0 10px 0; color: #0066CC; font-size: 20px; }\n"
         ".article .meta { color: #666666; font-size: 12px; margin: 0 0 15px 0; padding-bottom: 10px; border-bottom: 1px solid #EEEEEE; }\n"
         ".article .content { line-height: 1.6; color: #333333; margin: 15px 0; }\n"
         ".article .content P { margin: 10px 0; }\n"
         ".article .link { margin-top: 15px; padding-top: 15px; border-top: 1px solid #EEEEEE; }\n"
         ".article .link A { color: #0066CC; text-decoration: none; font-weight: bold; }\n"
         ".article .link A:hover { text-decoration: underline; }\n"
         "//-->\n"
         "</STYLE>\n"
         "</HEAD>\n"
         "<BODY>\n"
         "<TABLE WIDTH=\"100%%\" HEIGHT=\"100%%\" BORDER=\"0\" CELLPADDING=\"0\" CELLSPACING=\"0\">\n"
         "<TR>\n"
         "<TD CLASS=\"sidebar\" VALIGN=\"TOP\" WIDTH=\"300\">\n",
         channel->itemcount, channel->itemcount);
      
      /* Feed title and description */
      if(channel->title && channel->titlelen > 0)
      {  EscapeHtml(escaped, channel->title, channel->titlelen, sizeof(escaped));
         len += sprintf(html + len, "<H1>%s</H1>\n", escaped);
      }
      else
      {  len += sprintf(html + len, "<H1>RSS Feed</H1>\n");
      }
      
      if(channel->description && channel->desclen > 0)
      {  EscapeHtml(escaped, channel->description, channel->desclen, sizeof(escaped));
         len += sprintf(html + len, "<P STYLE=\"font-size: 11px; color: #666666; margin: 0 0 15px 0;\">%s</P>\n", escaped);
      }
      
      if(channel->link && channel->linklen > 0)
      {  /* URLs should not be HTML-escaped, but we need to escape quotes for attribute */
         long i, j;
         j = 0;
         for(i = 0; i < channel->linklen && j < sizeof(escaped) - 1; i++)
         {  if(channel->link[i] == '"')
            {  if(j + 6 < sizeof(escaped))
               {  strcpy(escaped + j, "&quot;");
                  j += 6;
               }
            }
            else if(channel->link[i] == '<' || channel->link[i] == '>')
            {  /* Skip invalid characters in URLs */
            }
            else
            {  escaped[j++] = channel->link[i];
            }
         }
         escaped[j] = '\0';
         len += sprintf(html + len, "<P STYLE=\"font-size: 11px; margin: 0 0 15px 0;\"><A HREF=\"%s\" TARGET=\"_blank\" STYLE=\"color: #0066CC;\">Visit Website</A></P>\n", escaped);
      }
      
      len += sprintf(html + len, 
         "<HR STYLE=\"border: none; border-top: 1px solid #EEEEEE; margin: 15px 0;\">\n"
         "<H2>Articles</H2>\n"
         "<UL CLASS=\"itemlist\">\n");
      
      /* Generate item list in sidebar */
      itemnum = 0;
      item = channel->items;
      while(item)
      {  itemnum++;
         len += sprintf(html + len, "<LI><A ID=\"link%d\" HREF=\"javascript:showArticle(%ld);\"", itemnum, itemnum);
         if(itemnum == 1) len += sprintf(html + len, " STYLE=\"font-weight: bold;\"");
         len += sprintf(html + len, ">");
         
         if(item->title && item->titlelen > 0)
         {  EscapeHtml(escaped, item->title, item->titlelen, sizeof(escaped));
            len += sprintf(html + len, "%s", escaped);
         }
         else
         {  len += sprintf(html + len, "Item %ld", itemnum);
         }
         
         len += sprintf(html + len, "</A></LI>\n");
         item = item->next;
      }
      
      len += sprintf(html + len, 
         "</UL>\n"
         "</TD>\n"
         "<TD CLASS=\"maincontent\" VALIGN=\"TOP\">\n");
      
      AppendHtml(fd, html, len);
      Writefilter(handle, fd->html_buffer, fd->html_buflen);
      fd->html_buflen = 0;
      fd->header_written = TRUE;
   }
   
   /* Render articles in main content area */
   itemnum = 0;
   item = channel->items;
   while(item)
   {  itemnum++;
      
      len = sprintf(html, "<DIV ID=\"article%ld\" CLASS=\"article\"", itemnum);
      if(itemnum == 1) len += sprintf(html + len, " STYLE=\"display: block;\"");
      len += sprintf(html + len, ">\n");
      
      /* Article title */
      len += sprintf(html + len, "<H2>");
      if(item->title && item->titlelen > 0)
      {  EscapeHtml(escaped, item->title, item->titlelen, sizeof(escaped));
         len += sprintf(html + len, "%s", escaped);
      }
      else
      {  len += sprintf(html + len, "Item %ld", itemnum);
      }
      len += sprintf(html + len, "</H2>\n");
      
      /* Article metadata */
      len += sprintf(html + len, "<DIV CLASS=\"meta\">");
      if(item->pubdate && item->pubdatelen > 0)
      {  EscapeHtml(escaped, item->pubdate, item->pubdatelen, sizeof(escaped));
         len += sprintf(html + len, "<STRONG>Date:</STRONG> %s", escaped);
         if(item->author && item->authorlen > 0) len += sprintf(html + len, " | ");
      }
      if(item->author && item->authorlen > 0)
      {  EscapeHtml(escaped, item->author, item->authorlen, sizeof(escaped));
         len += sprintf(html + len, "<STRONG>Author:</STRONG> %s", escaped);
      }
      len += sprintf(html + len, "</DIV>\n");
      
      /* Article content */
      len += sprintf(html + len, "<DIV CLASS=\"content\">\n");
      if(item->description && item->desclen > 0)
      {  EscapeHtml(escaped, item->description, item->desclen, sizeof(escaped));
         /* Convert newlines to <BR> for better formatting */
         {  UBYTE *p, *q;
            UBYTE formatted[2048];
            p = escaped;
            q = formatted;
            while(*p && q < formatted + sizeof(formatted) - 10)
            {  if(*p == '\n' || (*p == '\r' && p[1] == '\n'))
               {  strcpy(q, "<BR>");
                  q += 4;
                  if(*p == '\r') p++;
                  p++;
               }
               else
               {  *q++ = *p++;
               }
            }
            *q = '\0';
            len += sprintf(html + len, "<P>%s</P>", formatted);
         }
      }
      else
      {  len += sprintf(html + len, "<P>No content available.</P>");
      }
      len += sprintf(html + len, "</DIV>\n");
      
      /* Article link */
      if(item->link && item->linklen > 0)
      {  /* URLs should not be HTML-escaped, but we need to escape quotes for attribute */
         long i, j;
         j = 0;
         for(i = 0; i < item->linklen && j < sizeof(escaped) - 1; i++)
         {  if(item->link[i] == '"')
            {  if(j + 6 < sizeof(escaped))
               {  strcpy(escaped + j, "&quot;");
                  j += 6;
               }
            }
            else if(item->link[i] == '<' || item->link[i] == '>')
            {  /* Skip invalid characters in URLs */
            }
            else
            {  escaped[j++] = item->link[i];
            }
         }
         escaped[j] = '\0';
         len += sprintf(html + len, "<DIV CLASS=\"link\"><A HREF=\"%s\" TARGET=\"_blank\">Read Full Article</A></DIV>\n", escaped);
      }
      
      len += sprintf(html + len, "</DIV>\n");
      
      AppendHtml(fd, html, len);
      
      if(fd->html_buflen > 4096)
      {  Writefilter(handle, fd->html_buffer, fd->html_buflen);
         fd->html_buflen = 0;
      }
      
      item = item->next;
   }
   
   /* Write footer if EOF */
   if(!fd->footer_written)
   {  len = sprintf(html, 
         "</TD>\n</TR>\n</TABLE>\n"
         "<SCRIPT LANGUAGE=\"JavaScript1.1\">\n"
         "<!--\n"
         "if(document.getElementById('article1')) showArticle(1);\n"
         "//-->\n"
         "</SCRIPT>\n"
         "</BODY>\n</HTML>\n");
      
      AppendHtml(fd, html, len);
      Writefilter(handle, fd->html_buffer, fd->html_buflen);
      fd->html_buflen = 0;
      fd->footer_written = TRUE;
   }
}
