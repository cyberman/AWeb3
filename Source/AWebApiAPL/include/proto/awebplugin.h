#ifndef PROTO_AWEBPLUGIN_H
#define PROTO_AWEBPLUGIN_H

/*
**	$VER: awebplugin.h 1.0 (6.12.2024)
**
**	Lattice 'C' style prototype/pragma header file combo
**
**	Copyright (C) 2024 AWebZen Project.
**	    Developed for AmigaOS 3.2 and 4.1 compatibility.
*/

/****************************************************************************/

#ifdef _NO_INLINE

#include <clib/awebplugin_protos.h>

#else

/****************************************************************************/

#ifndef __NOLIBBASE__

#ifndef AWEBPLUGIN_AWEBPLUGIN_H
#include <awebplugin/awebplugin.h>
#endif /* AWEBPLUGIN_AWEBPLUGIN_H */

extern struct Library * AwebPluginBase;

#endif /* __NOLIBBASE__ */

/****************************************************************************/

#if defined(LATTICE) || defined(__SASC) || defined(_DCC)

#ifndef PRAGMAS_AWEBPLUGIN_PRAGMAS_H
#include <pragmas/awebplugin_pragmas.h>
#endif /* PRAGMAS_AWEBPLUGIN_PRAGMAS_H */

/****************************************************************************/

#elif defined(AZTEC_C) || defined(__MAXON__) || defined(__STORM__)

#ifndef PRAGMA_AWEBPLUGIN_LIB_H
#include <pragma/awebplugin_lib.h>
#endif /* PRAGMA_AWEBPLUGIN_LIB_H */

/****************************************************************************/

#elif defined(__VBCC__)

#include <clib/awebplugin_protos.h>

#ifndef _VBCCINLINE_AWEBPLUGIN_H
#include <inline/awebplugin_protos.h>
#endif /* _VBCCINLINE_AWEBPLUGIN_H */

/****************************************************************************/

#elif defined(__GNUC__)

#if defined(mc68000)
#ifndef _INLINE_AWEBPLUGIN_H
#include <inline/awebplugin.h>
#endif /* _INLINE_AWEBPLUGIN_H */
#else
#include <clib/awebplugin_protos.h>
#endif /* mc68000 */

/****************************************************************************/

/* Any other compiler */
#else

#include <clib/awebplugin_protos.h>

/****************************************************************************/

#endif /* __GNUC__ */

/****************************************************************************/

#endif /* _NO_INLINE */

/****************************************************************************/

#endif /* PROTO_AWEBPLUGIN_H */ 