/**********************************************************************
 * 
 * This file is part of the AWeb-II distribution
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

/* awebssl.h - AWeb common definitions for amissl function library */

#ifndef AWEBSSL_H
#define AWEBSSL_H

/* SAS/C 64-bit integer workaround for OPENSSL_init_ssl() */
/* For 64-bit parameters, high 32-bits go in D0, low 32-bits in D1 */
#define OPENSSL_init_ssl_32(opts, settings) \
	(putreg(REG_D1,opts), OPENSSL_init_ssl(0, settings))

struct Assl *Assl_initamissl(struct Library *socketbase);

/* SSL certificate acceptance function */
BOOL Httpcertaccept(char *hostname, char *certname);

/* SSL connection result codes */
#define ASSLCONNECT_OK     0  /* connection ok */
#define ASSLCONNECT_FAIL   1  /* connection failed */
#define ASSLCONNECT_DENIED 2  /* connection denied by user */

#endif