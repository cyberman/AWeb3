/* $VER: vrastport 2.1 (6.11.98) */

#include <proto/graphics.h>
#include <proto/utility.h>

/* VRastPort structure */
/* NOTE: Please do not change it by hand, use SetVRPAttrs() instead. */
/* You sholud use it as read-only. */

struct VRastPort
	{
		struct RastPort *rp;
		struct Rectangle box;
		LONG xscale;
		LONG yscale;
		LONG xoffset;
		LONG yoffset;
		struct AreaInfo ainfo;
		struct TmpRas tmpras;
		APTR raster;
		APTR aitable;
		LONG aisize;
	};

struct Point32
	{
		LONG x, y;
	};

/* Public functions prototypes */

struct VRastPort *MakeVRastPortTagList (struct TagItem *taglist);
struct VRastPort *MakeVRastPortTags (ULONG tag1, ...);
void FreeVRastPort (struct VRastPort *vrp);
void SetVRPAttrsA (struct VRastPort *vrp, struct TagItem *taglist);
void SetVRPAttrs (struct VRastPort *vrp, ULONG tag1, ...);
void GetVRPAttrsA (struct VRastPort *vrp, struct TagItem *taglist);
void GetVRPAttrs (struct VRastPort *vrp, ULONG tag1, ...);
LONG RealToRastX (struct VRastPort *vrp, LONG xcoord);
LONG RealToRastY (struct VRastPort *vrp, LONG ycoord);
LONG RastToRealX (struct VRastPort *vrp, LONG xcoord);
LONG RastToRealY (struct VRastPort *vrp, LONG ycoord);
LONG VWritePixel (struct VRastPort *vrp, LONG x, LONG y);
void VSetRast (struct VRastPort *vrp, UBYTE pen);
LONG VDrawLine (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1);
void VDrawEllipse (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b);
void VAreaEllipse (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b);
LONG VDrawPolygon (struct VRastPort *vrp, struct Point32* polygon, WORD vertices);
LONG VAreaPolygon (struct VRastPort *vrp, struct Point32* polygon, WORD vertices);
void VDrawBox (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1);
void VAreaBox (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1);

/* tags */

#define VRP_RastPort     0x86525000  /* [ISG] RastPort pointer */
#define VRP_XScale       0x86525001  /* [ISG] horizontal scale */
#define VRP_YScale       0x86525002  /* [ISG] vertical scale */
#define VRP_LeftBound    0x86525003  /* [ISG] clip rectangle bounds */
#define VRP_RightBound   0x86525004  /* [ISG]                       */
#define VRP_TopBound     0x86525005  /* [ISG]                       */
#define VRP_BottomBound  0x86525006  /* [ISG]                       */
#define VRP_XOffset      0x86525007  /* [ISG] position of cliprect on */
#define VRP_YOffset      0x86525008  /* [ISG] VRastPort               */

