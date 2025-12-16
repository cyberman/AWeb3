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

/* ciddataurls.h - cid: and data: URL scheme handlers */

#ifndef AWEB_CIDDATAURLS_H
#define AWEB_CIDDATAURLS_H

#include "fetchdriver.h"

/* Content-ID URL handler (cid: scheme) */
extern void Cidurltask(struct Fetchdriver *fd);

/* Data URI handler (data: scheme) */
extern void Dataurltask(struct Fetchdriver *fd);

#endif /* AWEB_CIDDATAURLS_H */


