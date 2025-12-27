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

/* rexxmsgext.h - ARexx message extension structures */

#ifndef RXMSGEXT_H
#define RXMSGEXT_H

#include <utility/hooks.h>

struct RexxMsgExt {
	struct Hook *rme_SetVarHook;
	struct Hook *rme_GetVarHook;
	APTR         rme_UserData;
};

struct SetVarHookData {
	STRPTR name;
	STRPTR value;
};

struct GetVarHookData {
	STRPTR name;
	STRPTR buffer;           /* ARexx assumes a 255 bytes buffer here */
};

typedef ULONG (*SetVarHookFunc)(struct Hook *, APTR unused1, struct RexxMsg *rm);
typedef ULONG (*GetVarHookFunc)(struct Hook *, APTR unused1, struct RexxMsg *rm);

#endif /* RXMSGEXT_H */

