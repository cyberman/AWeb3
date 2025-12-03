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

/* rss.h - RSS/Atom plugin header file */

#ifndef RSS_H
#define RSS_H

#include <libraries/awebplugin.h>
#include <exec/types.h>

/* Base pointers of libraries needed */
extern struct Library *AwebPluginBase;

/* Feed type enumeration */
enum FeedType
{  FEED_UNKNOWN = 0,
   FEED_RSS,
   FEED_ATOM
};

/* RSS/Atom item structure */
struct FeedItem
{  struct FeedItem *next;
   UBYTE *title;
   UBYTE *link;
   UBYTE *description;
   UBYTE *pubdate;
   UBYTE *author;
   UBYTE *guid;
   long titlelen;
   long linklen;
   long desclen;
   long pubdatelen;
   long authorlen;
   long guidlen;
};

/* Feed channel/feed metadata */
struct FeedChannel
{  UBYTE *title;
   UBYTE *link;
   UBYTE *description;
   UBYTE *language;
   UBYTE *copyright;
   UBYTE *managingeditor;
   UBYTE *webmaster;
   long titlelen;
   long linklen;
   long desclen;
   long languagelen;
   long copyrightlen;
   long managingeditorlen;
   long webmasterlen;
   struct FeedItem *items;
   struct FeedItem *lastitem;
   long itemcount;
   enum FeedType feedtype;
};

/* Parser state structure */
struct RssParser
{  UBYTE *buffer;
   long bufsize;
   long buflen;
   UBYTE *current;
   UBYTE *end;
   struct FeedChannel *channel;
   struct FeedItem *currentitem;
   BOOL initem;
   BOOL incontent;
   UBYTE *currenttag;
   long currenttaglen;
   UBYTE *currentdata;
   long currentdatalen;
   enum FeedType detectedtype;
};

/* Filter user data structure */
struct RssFilterData
{  BOOL first;
   BOOL is_feed;
   struct RssParser *parser;
   UBYTE *html_buffer;
   long html_bufsize;
   long html_buflen;
   BOOL header_written;
   BOOL footer_written;
};

/* Function declarations */
void InitRssParser(struct RssParser *parser);
void ParseRssChunk(struct RssParser *parser, UBYTE *data, long length);
void CleanupRssParser(struct RssParser *parser);
void RenderFeedToHtml(struct RssFilterData *fd, void *handle);
void FreeFeedChannel(struct FeedChannel *channel);

#endif /* RSS_H */

