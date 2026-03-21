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

/* version.c - AWeb version info */

#include "aweb.h"

static UBYTE *versionstring=
#ifdef LOCALONLY
   "$VER: AWebView " AWEBVERSION RELEASECLASS " " __AMIGADATE__;
#else
   "$VER: AWeb " AWEBVERSION RELEASECLASS " " __AMIGADATE__;
#endif
static UBYTE *internalstring=
#ifdef LOCALONLY
   "AWebView " BETARELEASE;
#else
   "AWeb " BETARELEASE;
#endif

UBYTE *aboutversion;

UBYTE *awebversion=
#ifdef BETAKEYFILE
   FULLRELEASE " (" BETARELEASE " beta)";
#else
   AWEBVERSION RELEASECLASS;
#endif

/*-----------------------------------------------------------------------*/

BOOL Initversion(void)
{  aboutversion=versionstring+6;
   return TRUE;
}

void Initialrequester(void (*about)(UBYTE *),UBYTE *p)
{
#ifdef POPABOUT
   about(p);
#endif
}
