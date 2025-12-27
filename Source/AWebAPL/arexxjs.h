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

/* arexxjs.h - AWeb js arexx support header */

#ifndef AREXXJS_H
#define AREXXJS_H

#include "jslib.h"

BOOL initarexx(struct Jcontext *jc);
void freearexx(struct Jcontext *jc);
/* SendCommand is a JavaScript function, implementation uses __saveds __asm */
void SendCommand(struct Jcontext *jc);

#endif /* AREXXJS_H */

