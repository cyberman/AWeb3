/* vrastport.c */
/* written by Grzegorz Kraszewski (Krashan/BlaBla) */
/* BlaBla Corp. 1998 */
/* $VER: vrastport 2.1 (6.11.98) */

#include <proto/exec.h>
#include <exec/memory.h>
#include <proto/graphics.h>
#include <proto/dos.h>
#include <dos.h>

#include "vrastport.h"
#include "math64.h"


/**** INTERNAL STUFF ****/

static Tag VRPTags [] = {VRP_RastPort, VRP_XScale, VRP_YScale, VRP_LeftBound, VRP_RightBound, 
	VRP_TopBound, VRP_BottomBound, VRP_XOffset, VRP_YOffset, TAG_END};

struct Line
	{
		struct Point32 s, e;
	};

/* special search_best_x() and search_best_y() results */

#define BOTH_POSITIVE		0x80000000
#define BOTH_NEGATIVE		0x80000001

/* ellipse drawing modes in ellipse_internal() */

#define ELLIPSE_MODE_PLOT		7
#define ELLIPSE_MODE_FILL		19

/* internal functions prototypes */

static LONG clip (struct Line *line, struct Rectangle *box);
static LONG clip_any (struct Line *line, struct Rectangle *box);
static LONG clip_horiz (struct Line *line, struct Rectangle *box);
static LONG clip_vert (struct Line *line, struct Rectangle *box);
static LONG search_best_y (LONG min, LONG max, struct Point32 *s, struct Point32 *e,
                           LONG x);
static LONG search_best_x (LONG min, LONG max, struct Point32 *s, struct Point32 *e,
                           LONG y);
static void calc_deviation (struct Point32 *s, struct Point32 *e, struct Point32 *p, 
                            Extended *dev);
static LONG check_section (struct Line *line, struct Rectangle *box);
static void ellipse_internal (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b,
                              WORD mode);
static void fbox_internal (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1);
static LONG pixel_internal (struct VRastPort *vrp, LONG x, LONG y);
static LONG prepare_filled_polygon (struct VRastPort *vrp, struct Point32 *polygon,
                                    struct Point32 *cliptable, WORD vertices);
static LONG clip_polygon (struct VRastPort *vrp, struct Point32 *polygon,
                          struct Point32 *cliptable, WORD vertices);
static LONG setup_tmpras (struct VRastPort *vrp);
static void free_tmpras (struct VRastPort *vrp);
static LONG setup_ainfo (struct VRastPort *vrp, LONG vertices);
static void free_ainfo (struct VRastPort *vrp);

/****** vrastport.lib/--background-- ***************************************
*
*   NAME   
*       vrastport.lib
*
*   PURPOSE
*       vrastport.lib is a set of functions used for 2D vector graphics
*       rendering in Amiga RastPorts. It automatically performs
*       clipping (even on a non-layered rastports) and low-level stuff
*       handling like temporary rasters and AreaInfo.
*
*       Clipping
*
*       All drawing functions performs clipping before rendering to
*       a RastPort. It has two advantages:
*       - functions are significantly faster than OS ones,
*         especially if part of a figure is clipped out.
*       - clipping works on non-layered RastPorts (used e.g. for
*         printing).
*       - no need to call MUI_AddClipping() in MUI custom classes.
*
*       Temporary Raster management
*
*       vrastport.lib uses temporary rasters for filled polygons and
*       ellipses. TmpRas buffer is as small as possible to reduce
*       chip memory usage. It is created by first call to a function
*       needing it. TmpRas size is calculated from clipping
*       rectangle size. When the size changes, TmpRas is disposed,
*       and again created by a first call to filling function. So it
*       always uses only really needed amount of chip-ram.
*
*       AreaInfo management
*
*       AreaInfo is created in VRastPort creation time. It has
*       a size for triangle by default. If You try to draw a polygon
*       with more vertices old AreaInfo buffer gets disposed and new
*       one is allocated and initialized. It is used as long as You
*       draw polygons with no more vertices than previously. And
*       again if AreaInfo is too small, a new one is allocated, and
*       old one is disposed. This scheme reduces memory usage. E.g.
*       if You draw in Your application only tetragons, AreaInfo
*       buffer will be never bigger than 25 bytes.
*
*       Virtual RastPort concept
*
*       vrastport.lib creates for You a new coordinate system called
*       VRastPort. Imagine that VRastPort is a big plane, and
*       clipping rectangle is a window. You can see a part of
*       VRastPort through the window. You can move the window, and
*       change zoom level independently in X and Y dimension.
*       VRastPort coordinates system is Carthesian one (X grows
*       right, Y grows up). All needed calculations are done
*       automatically. All You have to do is:
*       - create a RastPort (e.g. by opening an Intuition window).
*       - create a VRastPort.
*       - set a clipping rectangle bounds on the created RastPort.
*       - decide which part of the VRastPort You want to "see"
*         through the clipping rect. (using VRastPort attributes)
*       - draw some figures in VRastPort.
*
*       VRastPort base unit
*
*       Coordinates in VRastPorts are not in pixels. These are in an
*       abstract base unit. You can set base unit adequate to Your needs.
*       The size of a VRastPort is 2^31x2^31 base units. Eg. if You make
*       vector grahics editor You can choose base unit equal to 0.001 mm (1
*       um!). It gives You maximal page size about 2.14km x 2.14km. I hope
*       it's enough:-). Or if You prefer Imperial measure system - let's
*       base unit be 0.000001 inch. The page size in this case can be up to
*       58 x 58 yards. So VRastPort combines accuracy and big work
*       area size. When You choose base unit You can easily make VRastPort
*       to display objects at given dpi. Let's assume that base unit
*       = 0.001 mm, and You want 360 dpi in both axes. You can
*       calculate VRP_XScale and VRP_Yscale from the formula:
*
*                    dpi * 2^32        360 * 4294967296
*       scale = -------------------- = ---------------- = 60873552
*               1 inch in base units         25400
*
*       rounding error doesn't exceed 0.5 pixel in the whole
*       VRastPort area.
*
*       Overriding graphics.library limitations
*
*       Filled ellipse procedure has no chip-ram, and blitter
*       limitations. So filled ellipses can have both radii up to
*       32767 pixels.
*
*       VRastPort limitations
*
*       Coordinates range: -2^30+1 to +2^30-1 base unit in both axes.
*       Scale range: from 2 to 2^32 base units per pixel.
*       Number of polygon vertices - 16384 outline, 16380 filled.
*       Size of ellipse: radius up to 2^30-1 base units, but
*       rendered only if radius < 32767 pixels on RastPort (so if
*       You set scale to 4 base units per pixel only ellipses
*       smaller than 131068 base units will be drawn). This limit can
*       be removed in the future.
*
*       Speed
*
*       vrastport.lib uses no floating point math. It gives good
*       speed no matter if You have FPU or not. Effective clipping
*       makes it possible to render only visible parts of figures.
*       It speeds the rendering up especially on slower gfx devices
*       (eg. native Amiga chipsets).
*
* EXAMPLE
*       See example code in the archive.
*
****************************************************************************
*/

/*##########################################################################
##########  PUBLIC FUNCTIONS  ##############################################
##########################################################################*/


/****** vrastport.lib/MakeVRastPortTagList *********************************
*
*   NAME
*       MakeVRastPortTagList -- Creates a VRastPort with attributes from
*       given tag list (V1).
*
*   SYNOPSIS
*       vrastport = MakeVRastPortTagList (taglist)
*
*       struct VRastPort *MakeVRastPortTagList (struct TagItem*);
*       struct VRastPort *MakeVRastPortTags (ULONG,...);
*
*   FUNCTION
*       Creates a new VRastPort and set its attributes according to given
*       tag list. For possible tags see SetVRPAttrsA() docs. You can also
*       include to list RastPort attributes as described in
*       graphics.library/SetRPAttrsA(). If VRP_RastPort is set, RastPort
*       attributes will be passed to it.
*
*   INPUTS
*       taglist  - list of created VRastPort attributes.
*
*   RESULT
*       Initialized VRastPort address or NULL if falied.
*
*   NOTES
*       Don't put unknown tags (I mean tags other than VRP_xxxx or
*       RPTAG_xxxx) in the list! SetRPAttrsA() hangs up if it finds any.
*
*       Putting RPTAG_xxx tags is senseless if VRP_RastPort is not present
*       in the list.
*
*       You must not draw anything until You set VRP_RastPort.
*
*   SEE ALSO
*       SetVRPAttrsA(), graphics.library/SetRPAttrsA(), FreeVRastPort()
*
*****************************************************************************
*
*/


struct VRastPort *MakeVRastPortTagList (struct TagItem *taglist)
	{
		struct VRastPort *new;

		if (new = (struct VRastPort*)AllocVec (sizeof (struct VRastPort), MEMF_ANY))
			{
				new->rp = (struct RastPort*)GetTagData (VRP_RastPort, NULL, taglist);
				new->box.MinX = GetTagData (VRP_LeftBound, -32767, taglist);
				new->box.MinY = GetTagData (VRP_TopBound, -32767, taglist);
				new->box.MaxX = GetTagData (VRP_RightBound, 32767, taglist);
				new->box.MaxY = GetTagData (VRP_BottomBound, 32767, taglist);
				new->xscale = GetTagData (VRP_XScale, 322123, taglist);
				new->yscale = GetTagData (VRP_YScale, 322123, taglist);
				new->xoffset = GetTagData (VRP_XOffset, 0, taglist);
				new->yoffset = GetTagData (VRP_YOffset, 0, taglist);
				new->raster = NULL;
				new->aitable = NULL;
				if (new->rp)
					{
						FilterTagItems (taglist, VRPTags, TAGFILTER_NOT);
						SetRPAttrsA (new->rp, taglist);
					}
				return (new);
			}	
		return (0);
	}

/** STACK ARGS VERSION **/

struct VRastPort *MakeVRastPortTags (ULONG tag1, ...)
	{
		return (MakeVRastPortTagList ((struct TagItem*)&tag1));
	}


/****** vrastport.lib/FreeVRastPort ******************************************
*
*   NAME	
*       FreeVRastPort -- Free VRastPort structure and all allocated
*       resources (V1).
*
*   SYNOPSIS
*       FreeVRastPort (vrastport)
*
*       void FreeVRastPort (struct VRastPort*);
*
*   FUNCTION
*       Frees memory allocated for VRastPort structure and all resources
*       allocated by VRastPort itself.
*
*   INPUTS
*       vrastport - VRastPort to free (must be valid VRastPort address).
*
*   SEE ALSO
*       MakeVRastPortTagList()
*
******************************************************************************
*
*/


void FreeVRastPort (struct VRastPort *vrp)
	{
		free_tmpras (vrp);
		free_ainfo (vrp);
		FreeVec (vrp);
		return;
	}


/****** vrastport.lib/SetVRPAttrsA ***************************************
*
*   NAME
*       SetVRPAttrsA -- Sets a list of attributes for VRastPort (V1).
*
*   SYNOPSIS
*       SetVRPAttrsA (vrastport, taglist)
*
*       void SetVRPAttrsA (struct VRastPort*, struct TagItem*);
*       void SetVRPAttrs (struct VRastPort*, ULONG,...);
*
*   FUNCTION
*       Sets attributes from taglist for given VRastPort. Possible
*       attributes are:
*       VRP_RastPort    - RastPort associated with VRastPort. It must be set
*                         before any rendering.
*       VRP_XScale      - X axis scale coefficient. It says how many pixels
*                         in the RastPort equates 2^32 VRastPort base units.
*       VRP_YScale      - Y axis scale coefficient. It says how many pixels
*                         in the RastPort equates 2^32 VRastPort base units.
*       VRP_LeftBound   - Left edge of clipping rectangle on RastPort in 
*                         pixels.
*       VRP_RightBound  - Right edge of clipping rectangle on RastPort in 
*                         pixels.
*       VRP_TopBound    - Top edge of clipping rectangle on RastPort in 
*                         pixels.
*       VRP_BottomBound - Bottom edge of clipping rectangle on RastPort in 
*                         pixels.
*       VRP_XOffsett    - X coordinate of left lower cliprect corner in
*                         VRastPort base units.
*       VRP_YOffsett    - Y coordinate of left lower cliprect corner in
*                         VRastPort base units.
*       You can also use any of RPTAG_xxxx tags, they will be passed to
*       associated RastPort via SetRPAttrsA().
*
*   INPUTS
*       vrastport - VRastPort to set attrs for.
*       taglist   - list of VRastPort attributes.
*
*
*   NOTES
*       Don't put unknown tags (I mean tags other than VRP_xxxx or
*       RPTAG_xxxx) in the list! SetRPAttrsA() hangs up if it finds any.
*
*       Seting RPTAG_xxx attributes is senseless if there is no RastPort
*       associated with the VRastPort.
*
*       You must not draw anything until You set VRP_RastPort.
*
*   SEE ALSO
*       MakeVRastPortTagList(), graphics.library/SetRPAttrsA(),
*
*****************************************************************************
*
*/


void SetVRPAttrsA (struct VRastPort *vrp, struct TagItem *taglist)
	{
		struct TagItem *tag, *tagptr = taglist;

		while (tag = NextTagItem (&tagptr))
			{
				switch (tag->ti_Tag)
					{
						case VRP_RastPort:
							vrp->rp = (struct RastPort*)tag->ti_Data;
							break;
						case VRP_XScale:			vrp->xscale = tag->ti_Data;			break;
						case VRP_YScale:			vrp->yscale = tag->ti_Data;			break;
						case VRP_LeftBound:
							vrp->box.MinX = tag->ti_Data;
							free_tmpras (vrp);
							break;
						case VRP_RightBound:
							vrp->box.MaxX = tag->ti_Data;
							free_tmpras (vrp);
							break;
						case VRP_TopBound:
							vrp->box.MinY = tag->ti_Data;
							free_tmpras (vrp);
							break;
						case VRP_BottomBound:
							vrp->box.MaxY = tag->ti_Data;
							free_tmpras (vrp);
							break;
						case VRP_XOffset:			vrp->xoffset = tag->ti_Data;			break;
						case VRP_YOffset:			vrp->yoffset = tag->ti_Data;			break;
					}
			}
		if (vrp->rp)
			{
				FilterTagItems (taglist, VRPTags, TAGFILTER_NOT);
				SetRPAttrsA (vrp->rp, taglist);
			}
	}

/** STACK ARGS VERSION **/

void SetVRPAttrs (struct VRastPort *vrp, ULONG tag1, ...)
	{
		SetVRPAttrsA (vrp, (struct TagItem*)&tag1);
	}


/****** vrastport.lib/GetVRPAttrsA ***************************************
*
*   NAME
*       GetVRPAttrsA -- Gets a list of attributes from VRastPort (V1).
*
*   SYNOPSIS
*       GetVRPAttrsA (vrastport, taglist)
*
*       void GetVRPAttrsA (struct VRastPort*, struct TagItem*);
*       void GetVRPAttrs (struct VRastPort*, ULONG,...);
*
*   FUNCTION
*       Gets attributes from taglist for given VRastPort. ti_Data of every
*       struct TagItem in the list points to a longword, where attribute
*       value will be stored. Possible attributes are the same as for 
*       SetVRPAttrsA().
*
*       You can also use any of RPTAG_xxxx tags, they will be passed to
*       associated RastPort via GetRPAttrsA().
*
*   INPUTS
*       vrastport - VRastPort to get attrs from.
*       taglist   - list of VRastPort attributes.
*
*
*   NOTES
*       Don't put unknown tags (I mean tags other than VRP_xxxx or
*       RPTAG_xxxx) in the list! GetRPAttrsA() hangs up if it finds any.
*
*       Getting RPTAG_xxx attributes is senseless if there is no RastPort
*       associated with the VRastPort.
*
*   SEE ALSO
*       SetVRPAttrsA(), graphics.library/SetRPAttrsA(),
*
*****************************************************************************
*
*/


void GetVRPAttrsA (struct VRastPort *vrp, struct TagItem *taglist)
	{
		struct TagItem *tag, *tagptr = taglist;

		while (tag = NextTagItem (&tagptr))
			{
				switch (tag->ti_Tag)
					{
						case VRP_RastPort:		*(ULONG*)tag->ti_Data = (ULONG)vrp->rp;	break;
						case VRP_XScale:			*(ULONG*)tag->ti_Data = vrp->xscale;		break;
						case VRP_YScale:			*(ULONG*)tag->ti_Data = vrp->yscale;		break;
						case VRP_LeftBound:		*(ULONG*)tag->ti_Data = vrp->box.MinX;	break;
						case VRP_RightBound:	*(ULONG*)tag->ti_Data = vrp->box.MaxX;	break;
						case VRP_TopBound:		*(ULONG*)tag->ti_Data = vrp->box.MinY;	break;
						case VRP_BottomBound:	*(ULONG*)tag->ti_Data = vrp->box.MaxY;	break;
						case VRP_XOffset:			*(ULONG*)tag->ti_Data = vrp->xoffset;		break;
						case VRP_YOffset:			*(ULONG*)tag->ti_Data = vrp->yoffset;		break;
					}
			}
		if (vrp->rp)
			{
				FilterTagItems (taglist, (Tag*)&VRPTags, TAGFILTER_NOT);
				GetRPAttrsA (vrp->rp, taglist);
			}
	}

/** STACK ARGS VERSION **/

void GetVRPAttrs (struct VRastPort *vrp, ULONG tag1, ...)
	{
		GetVRPAttrsA (vrp, (struct TagItem*)&tag1);
	}


/****** vrastport.lib/RealToRastX ******************************************
*
*   NAME	
*       RealToRastX -- Converts real X coordinate to RastPort X coordinate
*       (V1).
*
*   SYNOPSIS
*       rastX = RealToRastX (vrastport, realX)
*
*       LONG RealToRastX (struct VRastPort*, LONG);
*
*   FUNCTION
*       Converts X coordinate from VRastPort coordinates system to RastPort
*       system according to X axis scaling factor, X offset and coodrinates
*       of clipping rectangle on the RastPort.
*
*   INPUTS
*       vrastport - VRastPort to convert from.
*       realX     - X coordinate in VRastPort base units. Range from
*                   -2^30+1 to +2^30-1.
*
*   RESULT
*       rastX     - X coordinate in pixels. Range from -2^30+1 to +2^30-1.
*
*   NOTES
*       Since one RastPort pixel represents at least two VRastPort base
*       units, returned value is always valid.
*
*       It is guarranted that RealToRastX (RastToRealX (a)) = a, if
*       RastToRealX() gives proper result.
*
*   SEE ALSO
*       RealToRastX(), RastToRealY(), RealToRastY(), SetVRPAttrsA()
*
******************************************************************************
*
*/


LONG RealToRastX (struct VRastPort *vrp, LONG xcoord)
	{
		Extended x;

		mul64 (xcoord - vrp->xoffset, vrp->xscale, &x);
		return (x.high + vrp->box.MinX);
	}


/****** vrastport.lib/RealToRastY ******************************************
*
*   NAME	
*       RealToRastY -- Converts real Y coordinate to RastPort Y coordinate
*       (V1).
*
*   SYNOPSIS
*       rastY = RealToRastY (vrastport, realY)
*
*       LONG RealToRastY (struct VRastPort*, LONG);
*
*   FUNCTION
*       Converts Y coordinate from VRastPort coordinates system to RastPort
*       system according to Y axis scaling factor, Y offset and coodrinates
*       of clipping rectangle on the RastPort.
*
*   INPUTS
*       vrastport - VRastPort to convert from.
*       realY     - Y coordinate in VRastPort base units. Range from -2^30+1
*                   to +2^30-1.
*
*   RESULT
*       rastY     - Y coordinate in pixels. Range from -2^30+1 to +2^30-1.
*
*   NOTES
*       Since one RastPort pixel represents at least two VRastPort base
*       units, returned value is always valid.
*
*       It is guarranted that RealToRastY (RastToRealY (a)) = a, if
*       RastToRealY() gives proper result.
*
*   SEE ALSO
*       RastToRealY(), RealToRastX(), RastToRealX(), SetVRPAttrsA()
*
******************************************************************************
*
*/


LONG RealToRastY (struct VRastPort *vrp, LONG ycoord)
	{
		Extended y;

		mul64 (ycoord - vrp->yoffset, vrp->yscale, &y);
		return (vrp->box.MaxY - y.high);
	}


/****** vrastport.lib/RastToRealX ******************************************
*
*   NAME	
*       RastToRealX -- Converts RastPort X coordinate to real X coordinate
*       (V1).
*
*   SYNOPSIS
*       realX = RastToRealX (vrastport, rastX)
*
*       LONG RastToRealX (struct VRastPort*, LONG);
*
*   FUNCTION
*       Converts X coordinate from RastPort coordinates system to VRastPort
*       system according to X axis scaling factor, X offset and coodrinates
*       of clipping rectangle on the RastPort.
*
*   INPUTS
*       vrastport - VRastPort to convert to.
*       rastX     - X coordinate in pixels. Range from -2^30+1 to +2^30-1 or
*                   smaller depending on VRastPort parameters.
*
*   RESULT
*       realX     - X coordinate in VRastPort base units. Range from -2^30+1
*                   to +2^30-1.
*
*   NOTES
*       Since one RastPort pixel represents at least two VRastPort base
*       units, returned value may be invalid when RastPort shows bigger
*       area than VRastPort area. In this case function returns
*       0x80000000. This value is never returned in normal conditions.
*
*       It is guarranted that RealToRastX (RastToRealX (a)) = a, if
*       RastToRealX() gives proper result.
*
*   SEE ALSO
*       RastToRealY(), RealToRastX(), RealToRastY(), SetVRPAttrsA()
*
******************************************************************************
*
*/


LONG RastToRealX (struct VRastPort *vrp, LONG xcoord)
	{
		LONG x0, x1 = -1073741823, x2 = 1073741823, x_rast;
		WORD i;

		if (xcoord > RealToRastX (vrp, x2)) return (0x80000000);
		if (xcoord < RealToRastX (vrp, x1)) return (0x80000000);
		for (i = 32; i; i--)
			{
				x0 = x1 + x2 >> 1;
				x_rast = RealToRastX (vrp, x0);
				if (xcoord > x_rast) x1 = x0;
				else if (xcoord < x_rast) x2 = x0;
				else return (x0);
			}
		return (x0);
	}



/****** vrastport.lib/RastToRealY ******************************************
*
*   NAME	
*       RastToRealY -- Converts RastPort Y coordinate to real Y coordinate
*       (V1).
*
*   SYNOPSIS
*       realY = RastToRealY (vrastport, rastY)
*
*       LONG RastToRealY (struct VRastPort*, LONG);
*
*   FUNCTION
*       Converts Y coordinate from RastPort coordinates system to VRastPort
*       system according to Y axis scaling factor, Y offset and coodrinates
*       of clipping rectangle on the RastPort.
*
*   INPUTS
*       vrastport - VRastPort to convert to.
*       rastY     - Y coordinate in pixels. Range from -2^30+1 to +2^30-1 or
*                   smaller depending on VRastPort parameters.
*
*   RESULT
*       realY     - Y coordinate in VRastPort base units. Range from -2^30+1
*                   to +2^30-1
*
*   NOTES
*       Since one RastPort pixel represents at least two VRastPort base
*       units, returned value may be invalid when RastPort shows bigger
*       area than VRastPort area. In this case function returns
*       0x80000000. This value is never returned in normal conditions.
*
*       It is guarranted that RealToRastY (RastToRealY (a)) = a, if
*       RastToRealY() gives proper result.
*
*   SEE ALSO
*       RastToRealX(), RealToRastX(), RealToRastY(), SetVRPAttrsA()
*
******************************************************************************
*
*/


LONG RastToRealY (struct VRastPort *vrp, LONG ycoord)
	{
		LONG y0, y1 = -1073741823, y2 = 1073741823, y_rast;
		WORD i;

		if (ycoord < RealToRastY (vrp, y2)) return (0x80000000);
		if (ycoord > RealToRastY (vrp, y1)) return (0x80000000);
		for (i = 32; i; i--)
			{
				y0 = (y1 + y2) >> 1;
				y_rast = RealToRastY (vrp, y0);
				if (ycoord < y_rast) y1 = y0;
				else if (ycoord > y_rast) y2 = y0;
				else return (y0);
			}
		return (y0);
	}


/****** vrastport.lib/VWritePixel ******************************************
*
*   NAME
*       VWritePixel -- Writes a pixel to VRastPort (V1).
*
*   SYNOPSIS
*       result = VWritePixel (vrastport, x, y)
*
*       LONG VWritePixel (struct VRastPort*, LONG, LONG);
*
*   FUNCTION
*       Writes a pixel to VRastPort. This always is rendered in RastPort as
*       single pixel no matter what VRP_XScale nad VRP_YScale are.
*
*   INPUTS
*       vrastport - VRastPort to render a pixel.
*       x, y      - Pixel coordinates in VRastPort base units. Range is from
*                   -2^30+1 to +2^30-1 for both.
*
*   RESULT
*       TRUE when pixel was actually placed in the RastPort, FALSE if it has
*       been clipped out.
*
*****************************************************************************
*
*/


LONG VWritePixel (struct VRastPort *vrp, LONG x, LONG y)
	{
		return (pixel_internal (vrp, RealToRastX (vrp, x), RealToRastY (vrp, y)));
	}


/****** vrastport.lib/VSetRast ******************************************
*
*   NAME   
*       VSetRast -- Fills the whole clipping rectangle with the given colour
*       (V1).
*
*   SYNOPSIS
*       VSetRast (vrastport, colour);
*
*       void VSetRast (struct VRastPort*, UBYTE);
*
*   FUNCTION
*       Fills the whole clipping rectangle with the given colour. Filling is
*       performed via RectFill(). RastPort APen is preserved.
*
*   INPUTS
*       vrastport - VRastPort to fill.
*       colour    - colour number in screen's ColorMap.
*
*   NOTES
*       VSetRast uses graphics.library/RectFill() to fill the clipping
*       rectangle. So it inherits RectFill() bugs.
*
*   SEE ALSO
*       graphics.library/RectFill(), graphics/view.h
*
*****************************************************************************
*
*/


void VSetRast (struct VRastPort *vrp, UBYTE pen)
	{
		UBYTE old_pen;

		old_pen = GetAPen (vrp->rp);
		SetAPen (vrp->rp, pen);
		RectFill (vrp->rp, vrp->box.MinX, vrp->box.MinY, vrp->box.MaxX, vrp->box.MaxY);
		SetAPen (vrp->rp, old_pen);
		return;
	}


/****** vrastport.lib/VDrawLine ******************************************
*
*   NAME   
*       VDrawLine -- Draws line in a VRastPort (V1).
*
*   SYNOPSIS
*       result = VDrawLine (vrastport, x0, y0, x1, y1)
*
*       LONG VDrawLine (struct VRastPort, LONG, LONG, LONG, LONG);
*
*   FUNCTION
*       Draws a line in VRastPort from point (x0,y0) to (x1,y1). Line is
*       clipped to clipping rectangle bounds.
*
*   INPUTS
*       vrastport - VRastPort to draw the line.
*       x0, y0    - line start point coordinates in VRastPort base units.
*                   Range from -2^30+1 to +2^30-1.
*       x0, y0    - line end point coordinates in VRastPort base units.
*                   Range from -2^30+1 to +2^30-1.
*
*   RESULT
*       TRUE if any section of the line is rendered. FALSE if the whole line
*       is clipped out.
*
*****************************************************************************
*
*/


LONG VDrawLine (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1)
	{
		struct Line line;

		/* converting real coords to raster coords */
		
		line.s.x = RealToRastX (vrp, x0);
		line.s.y = RealToRastY (vrp, y0);
		line.e.x = RealToRastX (vrp, x1);
		line.e.y = RealToRastY (vrp, y1);

		if (clip (&line, &vrp->box))
			{
		    /* drawing */

				Move (vrp->rp, line.s.x, line.s.y);
				Draw (vrp->rp, line.e.x, line.e.y);
				return (TRUE);
			}
		return (FALSE);
	}


/****** vrastport.lib/VDrawEllipse ******************************************
*
*   NAME   
*       VDrawEllipse -- Draw an ellipse outline in a VRastPort (V1).
*
*   SYNOPSIS
*       VDrawEllipse (vrastport, x, y, a, b)
*
*       void VDrawEllipse (struct VRastPort*, LONG, LONG, LONG, LONG);
*
*   FUNCTION
*       Draws ellipse outline to a VRastPort. Ellipse is clipped to clipping
*       rectangle bounds.
*
*   INPUTS
*       vrastport - VRastPort to draw the ellipse.
*       x, y      - coordinates of the ellipse centre in VRastPort base
*                   units. Range is from -2^30+1 to +2^30-1
*       a, b      - horizontal and vertical ellipse radius in VRastPort base
*                   units. Range is from -2^30+1 to +2^30-1.
*
*   NOTES
*       Function doesn't use graphics.library DrawEllipse() function. This
*       may change if on gfx boards OS code is faster than my code. On AGA
*       based Amigas my code is faster.
*
*   BUGS
*       Function doesn't draw anything if at least one of raster radii is
*       greater than 32767 pixels.
*
*   SEE ALSO
*       graphics.library/DrawEllipse()
*
*****************************************************************************
*
*/


void VDrawEllipse (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b)
	{
		ellipse_internal (vrp, x, y, a, b, ELLIPSE_MODE_PLOT);
		return;
	}


/****** vrastport.lib/VAreaEllipse ******************************************
*
*   NAME   
*       VAreaEllipse
*
*   SYNOPSIS
*       VAreaEllipse (vrastport, x, y, a, b);
*
*       void VAreaEllipse (struct VRastPort*, LONG, LONG, LONG, LONG);
*
*   FUNCTION
*       Draws a filled ellipse in the VRastPort. Ellipse is clipped to
*       clipping rectangle bounds.
*
*   INPUTS
*       vrastport - VRastPort to draw the ellipse.
*       x, y      - coordinates of the ellipse centre in VRastPort base
*                   units. Range is from -2^30+1 to +2^30-1.
*       a, b      - horizontal and vertical ellipse radius in VRastPort base
*                   units. Range is from -2^30+1 to +2^30-1.
*       
*   NOTES
*       This procedure doesn't use graphics.library/AreaEllipse() function.
*       This makes it independent on hardawre blitter or chip memory
*       limitations. It can draw an ellipse with both raster radii 32767
*       pixels without any chip-ram allocation. This function is also much
*       faster than OS one when drawing big (a or b > 256 pixels) ellipses.
*       On the other hand for small ellipses blitter is faster so using the
*       blitter for small ellipses may be implemented in the future.
*
*       Unlike OS AreaXxxx() functions, VAreaEllipse() doesn't require
*       InitArea() and AreaEnd() calls.
*
*   BUGS
*       Function doesn't draw anything if at least one of raster radii is
*       greater than 32767 pixels.
*
*   SEE ALSO
*       graphics.library/AreaEllipse()
*
*****************************************************************************
*
*/


void VAreaEllipse (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b)
	{
		ellipse_internal (vrp, x, y, a, b, ELLIPSE_MODE_FILL);
		return;
	}


/****** vrastport.lib/VDrawPolygon ******************************************
*
*   NAME   
*       VDrawPolygon -- Draws an outline of a polygon in the VRastPort (V1).
*
*   SYNOPSIS
*       success = VDrawPolygon (vrastport, polygon, vertices)
*       
*       LONG VDrawPolygon (struct VRastPort*, struct Point32*, WORD);
*
*   FUNCTION
*       Draws an outline of any polygon (may be not convex) in the
*       VRastPort. Polygon is clipped to clipping rectangle bounds.
*
*   INPUTS
*       vrastport - VRastPort to draw the polygon.
*       polygon   - pointer to a table of polygon vertices ((x,y) pairs). X,
*                   Y coordinates are limited to a range from -2^30+1 to
*                   +2^30-1.
*       vertices  - number for polygon vertices (from 3 to 16384).
*
*   RESULT
*       TRUE if all went OK. Function allocates some memory for internal
*       tables. If allocation fails VDrawPolygon returns FLASE.
*
*   BUGS
*       Memory for internal tables is allocated directly from the system. It
*       can lead to memory fragmentation. It will use a memory pool in the
*       future.
*
*****************************************************************************
*
*/


LONG VDrawPolygon (struct VRastPort *vrp, struct Point32 *polygon, WORD vertices)
	{
		WORD vcount;
		LONG ret = FALSE;                             /* sukces funkcji */
		struct Point32 *polygon_copy, *cliptable;
		
		/* zdobycie pamiëci na tablice */
		if (polygon_copy = (struct Point32*)AllocVec (sizeof (struct Point32) * vertices,
			MEMF_ANY))
			{
				if (cliptable = (struct Point32*)AllocVec (sizeof (struct Point32) * (vertices
					<< 1), MEMF_ANY))
					{
						CopyMem (polygon, polygon_copy, sizeof (struct Point32) * vertices);
						clip_polygon (vrp, polygon_copy, cliptable, vertices);
						for (vcount = 0; vcount < (vertices << 1); vcount += 2)
							{
								if (cliptable[vcount].x == 0x80000000) continue;
								Move (vrp->rp, cliptable[vcount].x, cliptable[vcount].y);
								Draw (vrp->rp, cliptable[vcount + 1].x, cliptable[vcount + 1].y);
							}
						ret = TRUE;
						FreeVec (cliptable);
					}
				FreeVec (polygon_copy);
			}
		return (ret);
	}


/****** vrastport.lib/VAreaPolygon ******************************************
*
*   NAME
*       VAreaPolygon -- Draws a filled convex polygon in the VRastPort (V1).
*
*   SYNOPSIS
*       success = VAreaPolygon (vrastport, polygon, vertices)
*
*       LONG VAreaPolygon (struct VRastPort*, struct Point32*, WORD);
*
*   FUNCTION
*       Draws a filled convex polygon in the RastPort. Polygon is clipped to
*       clipping rectangle bounds. 
*
*   INPUTS
*       vrastport - VRastPort to draw the filled polygon.
*       polygon   - pointer to a table of polygon vertices ((x,y) pairs). X,
*                   Y coordinates are limited to a range from -2^30+1 to
*                   +2^30-1.
*       vertices  - number for polygon vertices (from 3 to 16380).
*       
*   RESULT
*       TRUE if all went OK. Function allocates some memory for internal
*       tables. If allocation fails VDrawPolygon returns FLASE. It can also
*       fail when it needs to create a new temporary raster or AreaInfo for
*       filling operations, and this creation fails.
*       
*   NOTES
*       Polygon MUST BE convex. You'll get unpredictable results otherwise.
*
*       Unlike OS AreaXxxx() functions VAreaPolygon() automatically handles
*       low-level filling stuff like TmpRas, AreaInfo, InitArea() and
*       AreaEnd().
*
*   BUGS
*       Memory for internal tables is allocated directly from the system. It
*       can lead to memory fragmentation. It will use a memory pool in the
*       future.
*       
*****************************************************************************
*
*/


LONG VAreaPolygon (struct VRastPort *vrp, struct Point32 *polygon, WORD vertices)
	{
		WORD vcount;
		LONG ret = FALSE;                             /* function result */
		struct Point32 *polygon_copy, *cliptable;
		
		if (polygon_copy = (struct Point32*)AllocVec (sizeof (struct Point32) * vertices,
			MEMF_ANY))
			{
				if (cliptable = (struct Point32*)AllocVec (sizeof (struct Point32) * ((vertices
					<< 1) + 4), MEMF_ANY))
					{
						CopyMem (polygon, polygon_copy, sizeof (struct Point32) * vertices);
						clip_polygon (vrp, polygon_copy, cliptable, vertices);
						vertices = prepare_filled_polygon (vrp, polygon_copy, cliptable, vertices);
						if (vertices == 1) WritePixel (vrp->rp, cliptable[0].x, cliptable[0].y);
						else if (vertices == 2)
							{
								Move (vrp->rp, cliptable[0].x, cliptable[0].y);
								Draw (vrp->rp, cliptable[0].x, cliptable[0].y);
							}
						else
							{
								if (setup_tmpras (vrp))
									{
										if (setup_ainfo (vrp, vertices + 1))
											{
												struct TmpRas *old_tr = vrp->rp->TmpRas;
												struct AreaInfo *old_ai = vrp->rp->AreaInfo;

												InitArea (&vrp->ainfo, vrp->aitable, vertices + 1);
												vrp->rp->TmpRas = &vrp->tmpras;
												vrp->rp->AreaInfo = &vrp->ainfo;
												AreaMove (vrp->rp, cliptable[0].x, cliptable[0].y);
												for (vcount = 1; vcount < vertices; vcount++)
													{
														AreaDraw (vrp->rp, cliptable[vcount].x, cliptable[vcount].y);
													}														
												AreaEnd (vrp->rp);
												vrp->rp->TmpRas = old_tr;
												vrp->rp->AreaInfo = old_ai;
												ret = TRUE;
											}
									}
							}
						FreeVec (cliptable);
					}
				FreeVec (polygon_copy);
			}
		return (ret);
	}

/****** vrastport.lib/VDrawBox ******************************************
*
*   NAME   
*       VDrawBox -- Draws an outline of a rectangle. Rectangle sides are
*       vertical and horizontal (V2).
*
*   SYNOPSIS
*       VDrawBox (vrastport, x0, y0, x1, y1)
*
*       void VDrawBox (struct VRastPort*, LONG, LONG, LONG, LONG);
*
*   FUNCTION
*			  Draws an outline of rectangle placed parallel to VRastPort
*       coordinates system axes. VDrawBox() is much faster than 4 calls to
*       VDrawLine() or call to VDrawPolygon().
*
*   INPUTS
*       vrastport - VRastPort to render the box.
*       x0, y0    - coordinates of any rectangle corner in base units. Range
*                   from -2^30+1 to +2^30-1.
*       x1, y1    - coordinates of the opposite corner. Range from -2^30+1
*                   to +2^30-1.
*
*****************************************************************************
*
*/

void VDrawBox (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1)
	{
		WORD visible [4] = {TRUE, TRUE, TRUE, TRUE};
		
		x0 = RealToRastX (vrp, x0);
		y0 = RealToRastY (vrp, y0);
		x1 = RealToRastX (vrp, x1);
		y1 = RealToRastY (vrp, y1);

		if (x1 < x0) {LONG aux = x0; x0 = x1; x1 = aux;}
		if (y1 < y0) {LONG aux = y0; y0 = y1; y1 = aux;}

		if ((x0 > vrp->box.MaxX) || (x1 < vrp->box.MinX)) return;
		if ((y0 > vrp->box.MaxY) || (y1 < vrp->box.MinY)) return;

		if (x0 < vrp->box.MinX) {x0 = vrp->box.MinX; visible[3] = FALSE;}
		if (x1 > vrp->box.MaxX) {x1 = vrp->box.MaxX; visible[1] = FALSE;}
		if (y0 < vrp->box.MinY) {y0 = vrp->box.MinY; visible[0] = FALSE;}
		if (y1 > vrp->box.MaxY) {y1 = vrp->box.MaxY; visible[2] = FALSE;}

		Move (vrp->rp, x0, y0);
		if (visible[0]) Draw (vrp->rp, x1, y0); else Move (vrp->rp, x1, y0);
		if (visible[1]) Draw (vrp->rp, x1, y1); else Move (vrp->rp, x1, y1);
		if (visible[2]) Draw (vrp->rp, x0, y1); else Move (vrp->rp, x0, y1);
		if (visible[3]) Draw (vrp->rp, x0, y0); else Move (vrp->rp, x0, y0);

		return;
	}

/****** vrastport.lib/VAreaBox ******************************************
*
*   NAME   
*       VAreaBox -- Draws a filled rectangle. Rectangle sides are
*       vertical and horizontal (V2).
*
*   SYNOPSIS
*       VAreaBox (vrastport, x0, y0, x1, y1)
*
*       void VAreaBox (struct VRastPort*, LONG, LONG, LONG, LONG);
*
*   FUNCTION
*			  Draws a filled rectangle placed parallel to VRastPort coordinates
*       system axes. VDrawBox() is much faster than a call to VAreaPolygon().
*
*   INPUTS
*       vrastport - VRastPort to render the box.
*       x0, y0    - coordinates of any rectangle corner in base units. Range
*                   from -2^30+1 to +2^30-1.
*       x1, y1    - coordinates of the opposite corner. Range from -2^30+1
*                   to +2^30-1.
*
*****************************************************************************
*
*/

void VAreaBox (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1)
	{
		x0 = RealToRastX (vrp, x0);
		y0 = RealToRastY (vrp, y0);
		x1 = RealToRastX (vrp, x1);
		y1 = RealToRastY (vrp, y1);

		if (x1 < x0) {LONG aux = x0; x0 = x1; x1 = aux;}
		if (y1 < y0) {LONG aux = y0; y0 = y1; y1 = aux;}

		if ((x0 > vrp->box.MaxX) || (x1 < vrp->box.MinX)) return;
		if ((y0 > vrp->box.MaxY) || (y1 < vrp->box.MinY)) return;

		if (x0 < vrp->box.MinX) x0 = vrp->box.MinX;
		if (x1 > vrp->box.MaxX) x1 = vrp->box.MaxX;
		if (y0 < vrp->box.MinY) y0 = vrp->box.MinY;
		if (y1 > vrp->box.MaxY) y1 = vrp->box.MaxY;

		RectFill (vrp->rp, x0, y0, x1, y1);

		return;
	}

/*#########################################################################
#######  INTERNAL FUNCTIONS  ##############################################
#########################################################################*/

/* Comments in Polish language only - sorry. */



static LONG clip (struct Line *line, struct Rectangle *box)
	{
		if (line->s.x == line->e.x) return (clip_vert (line, box));
		else if (line->s.y == line->e.y) return (clip_horiz (line, box));
		else return (clip_any (line, box));
	}

//-------------------------------------------------------------------------------------
// Funkcja obcinajâca odcinek pod dowolnym kâtem ze wszystkich stron. Jeûeli odcinek
// nie wymaga obciëcia z danej strony, to nie jest obcinany.

static LONG clip_any (struct Line *line, struct Rectangle *box)
	{
		LONG best;
		struct Line clipped;
		
		clipped = *line;

		/* sprawdzam, czy prosta na której poîoûony jest odcinek przecina obszar okna */
		if (!check_section (line, box)) return (FALSE);
		
		/* porzâdkujë odcinek wedîug wspóîrzëdnej x */
		if (line->e.x < line->s.x) 
			{ struct Point32 aux = line->s; line->s = line->e; line->e = aux;
			                 aux = clipped.s; clipped.s = clipped.e; clipped.e = aux; }

		/* eliminujë przypadki, gdy odcinek poîoûony jest caîkowicie po lewej lub po prawej */
		if ((line->s.x > box->MaxX) || (line->e.x < box->MinX)) return (FALSE);

		/* obcinam z lewej, jeûeli odcinek przecina prostâ x = MinX */
		if (line->s.x < box->MinX)
			{
				best = search_best_y (box->MinY, box->MaxY, &line->s, &line->e, box->MinX);
				if (best > 0)
					{
						clipped.s.y = best;
						clipped.s.x = box->MinX;
					}
			}
			
		/* obcinam z prawej, jeûli odcinek przecina prostâ x = MaxX */
		if (line->e.x > box->MaxX)
			{
				best = search_best_y (box->MinY, box->MaxY, &line->s, &line->e, box->MaxX);
				if (best > 0)
					{
						clipped.e.y = best;
						clipped.e.x = box->MaxX;
					}
			}

    /* porzâdkujë odcinek wedîug wspóîrzëdnej y */
		if (line->e.y < line->s.y) 
			{ struct Point32 aux = line->s; line->s = line->e; line->e = aux;
			                 aux = clipped.s; clipped.s = clipped.e; clipped.e = aux; }

		/* eliminujë przypadki, gdy odcinek poîoûony jest w caîoôci nad lub pod oknem */			     
		if ((line->s.y > box->MaxY) || (line->e.y < box->MinY)) return (FALSE);

		/* obcinam od góry, jeûeli odcinek przecina prostâ y = MinY */
		if (line->s.y < box->MinY)
			{
				best = search_best_x (box->MinX, box->MaxX, &line->s, &line->e, box->MinY);
				if (best > 0)
					{
						clipped.s.x = best;
						clipped.s.y = box->MinY;
					}
			}
			
		/* obcinam od doîu, jeûeli odcinek przecina prostâ y = MaxY */
		if (line->e.y > box->MaxY)
			{
				best = search_best_x (box->MinX, box->MaxX, &line->s, &line->e, box->MaxY);
				if (best > 0)
					{
						clipped.e.x = best;
						clipped.e.y = box->MaxY;
					}
			}

		*line = clipped;
		return (TRUE);
	}

//-------------------------------------------------------------------------------------
// Funkcja obcinajâca odcinek pionowy od góry i od doîu. Jeûeli odcinek nie wymaga
// obciëcia z danej strony, to nie jest obcinany.

static LONG clip_vert (struct Line *line, struct Rectangle *box)
	{
		/* porzâdkujë koïce odcinka wedîug wspóîrzëdnej y. Poniewaû wspóîrzëdna x obu */
		/* punktów jest ta sama, wystarczy zamieniaê wspóîrzëdne y */
		if (line->e.y < line->s.y) 
					{ LONG aux = line->s.y; line->s.y = line->e.y; line->e.y = aux; }
		/* elimiujë linie leûâce w caîoôci po lewej i po prawej stronie okna */
		if ((line->s.x < box->MinX) || (line->s.x > box->MaxX)) return (FALSE);
		/* eliminujë linie leûâce w caîoôci ponad, lub pod oknem */
		if ((line->e.y < box->MinY) || (line->s.y > box->MaxY)) return (FALSE);
		/* obcinam z doîu */
		if (line->e.y > box->MaxY) line->e.y = box->MaxY;
		/* obcinam z góry */
		if (line->s.y < box->MinY) line->s.y = box->MinY;
		return (TRUE);
	}

//-------------------------------------------------------------------------------------
// Funkcja obcinajâca odcinek poziomy z lewej i z prawej. Jeûeli odcinek nie wymaga
// obciëcia z danej strony, to nie jest obcinany.

static LONG clip_horiz (struct Line *line, struct Rectangle *box)
	{
		/* porzâdkujë koïce odcinka wedîug wspóîrzëdnej x. Poniewaû wspóîrzëdna y obu */
		/* punktów jest ta sama, wystarczy zamieniaê wspóîrzëdne x */
		if (line->e.x < line->s.x) 
					{ LONG aux = line->s.x; line->s.x = line->e.x; line->e.x = aux; }
		/* elimiujë linie leûâce w caîoôci ponad i pod oknem */
		if ((line->s.y < box->MinY) || (line->s.y > box->MaxY)) return (FALSE);
		/* eliminujë linie leûâce w caîoôci po lewej lub po prawej stronie okna */
		if ((line->e.x < box->MinX) || (line->s.x > box->MaxX)) return (FALSE);
		/* obcinam od prawej */
		if (line->e.x > box->MaxX) line->e.x = box->MaxX;
		/* obcinam od lewej */
		if (line->s.x < box->MinX) line->s.x = box->MinX;
		return (TRUE);
	}

//-------------------------------------------------------------------------------------
// Funkcja okreôlajâca poîoûenie punktu P wzglëdem wektora SE. Jeûeli zmienna dev:
//  - jest < 0, to punkt leûy po lewej stronie wektora,
//  - jest = 0, to punkt leûy na wektorze,
//  - jest > 0, to punkt leûy po prawej stronie wektora.

static void calc_deviation (struct Point32 *s, struct Point32 *e, struct Point32 *p, 
                            Extended *dev)
	{
		Extended a;
		
		mul64 (p->x - s->x, p->y - e->y, dev);
		mul64 (p->y - s->y, p->x - e->x, &a);
		sub64 (&a, dev);
		return;
	}

//-------------------------------------------------------------------------------------
// Funkcja dla danych punktów odcinka (uporzâdkowanych wedîug y) poszukuje punktu
// przeciëcia z odcinkiem poziomym o wspóîrzëdnej y = y i kraïcach x1 = min, x2 = max.
// Jeûeli nie ma przeciëcia, funkcja zwraca 0x80000000. Funkcja wykonuje mniej obli-
// czeï, jeûeli odcinek poîoûony jest pod kâtem 45 stopni.

static LONG search_best_x (LONG min, LONG max, struct Point32 *s, struct Point32 *e,
                           LONG y)
	{
		LONG mid;
		struct Point32 p;
		Extended dmin, dmax, dmid;

		/* liczë odchyîki graniczne */
		p.y = y;
		p.x = min;
		calc_deviation (s, e, &p, &dmin);
		p.x = max;
		calc_deviation (s, e, &p, &dmax);

		/* jeûeli odchyîki takiego samego znaku, to obcinanie zbëdne. */
		if ((tst64 (&dmin) > 0) && (tst64 (&dmax) > 0)) return (BOTH_POSITIVE);
		if ((tst64 (&dmin) < 0) && (tst64 (&dmax) < 0)) return (BOTH_NEGATIVE);

		/* sprawdzam nachylenie 45 stopni, jeûeli tak, to obcinam metodâ skróconâ */
		if (e->y - s->y == e->x - s->x) return (s->x + y - s->y);
		if (e->y - s->y == s->x - e->x) return (s->x - y + s->y);

		/* pëtla szukania najmniejszej odchyîki metodâ poîowienia przedziaîu */	
		do
			{
			  LONG result;
			  
				mid = (min + max) >> 1;
				p.x = mid;
				calc_deviation (s, e, &p, &dmid);
				result = tst64 (&dmid);
				if (result > 0) { min = mid; dmin = dmid; }
				else if (result < 0) { max = mid; dmax = dmid; }
				else return (mid);
			}
		while (max - min > 1);

		/* po zawëûeniu obszaru poszukiwaï do 2 pikseli wybieram ten z mniejszâ warto- */
		/* ôciâ bezwzglëdnâ odchyîki */
		abs64 (&dmin);
		if (cmp64 (&dmin,&dmax) >= 0) return (max);
		else return (min);
	}

//-------------------------------------------------------------------------------------
// Funkcja dla danych punktów odcinka (uporzâdkowanych wedîug x) poszukuje punktu
// przeciëcia z odcinkiem pionowym o wspóîrzëdnej x = x i kraïcach y1 = min, y2 = max.
// Jeûeli nie ma przeciëcia, funkcja zwraca 0x80000000. Funkcja wykonuje mniej obli-
// czeï, jeûeli odcinek poîoûony jest pod kâtem 45 stopni.

static LONG search_best_y (LONG min, LONG max, struct Point32 *s, struct Point32 *e,
                           LONG x)
	{
		LONG mid;
		struct Point32 p;
		Extended dmin, dmax, dmid;

		/* liczë odchyîki graniczne */
		p.x = x;
		p.y = min;
		calc_deviation (s, e, &p, &dmin);
		p.y = max;
		calc_deviation (s, e, &p, &dmax);

		/* jeûeli odchyîki takiego samego znaku, to obcinanie zbëdne. */
		if ((tst64 (&dmin) > 0) && (tst64 (&dmax) > 0)) return (BOTH_POSITIVE);
		if ((tst64 (&dmin) < 0) && (tst64 (&dmax) < 0)) return (BOTH_NEGATIVE);

		/* sprawdzam nachylenie 45 stopni, jeûeli tak, to obcinam metodâ skróconâ */
		if (e->x - s->x == e->y - s->y) return (s->y + x - s->x);
		if (e->x - s->x == s->y - e->y) return (s->y - x + s->x);

		/* pëtla szukania najmniejszej odchyîki metodâ poîowienia przedziaîu */	
		do
			{
			  LONG result;
			  
				mid = (min + max) >> 1;
				p.y = mid;
				calc_deviation (s, e, &p, &dmid);
				result = tst64 (&dmid);
				if (result < 0) { min = mid; dmin = dmid; }
				else if (result > 0) { max = mid; dmax = dmid; }
				else return (mid);
			}
		while (max - min > 1);

		/* po zawëûeniu obszaru poszukiwaï do 2 pikseli wybieram ten z mniejszâ warto- */
		/* ôciâ bezwzglëdnâ odchyîki */
		abs64 (&dmin);
		if (cmp64 (&dmin,&dmax) >= 0) return (max);
		else return (min);
	}

//-------------------------------------------------------------------------------------
// Funkcja sprawdza, czy prosta, na której leûy odcinek okreôlany przez 'line' przecina 
// obszar okna danego przez 'box'.

static LONG check_section (struct Line *line, struct Rectangle *box)
	{
		Extended a, b, c, d;
		struct Point32 p;

		p.x = box->MinX;
		p.y = box->MinY;
		calc_deviation (&line->s, &line->e, &p, &a);
		p.y = box->MaxY;
		calc_deviation (&line->s, &line->e, &p, &b);
		p.x = box->MaxX;
		calc_deviation (&line->s, &line->e, &p, &c);
		p.y = box->MinY;
		calc_deviation (&line->s, &line->e, &p, &d);

		if ((tst64 (&a) > 0) && (tst64 (&b) > 0) && (tst64 (&c) > 0) && (tst64 (&d) > 0))
			return (FALSE);
		if ((tst64 (&a) < 0) && (tst64 (&b) < 0) && (tst64 (&c) < 0) && (tst64 (&d) < 0))
			return (FALSE);
		return (TRUE);
	}

//-------------------------------------------------------------------------------------
// Funkcja rysuje elipsë o ôrodku (x,y) i osiach a,b. Tryb wypeîniany lub nie (w zaleû-
// noôci od parametru 'mode'.

static void ellipse_internal (struct VRastPort *vrp, LONG x, LONG y, LONG a, LONG b,
                       WORD mode)
	{
		LONG xp, yp, ap, bp, dx, dy, f[6];
		Extended econst, dev[4];

		/* przeliczenie wspóîrzëdnych */
		xp = RealToRastX (vrp, x);
		yp = RealToRastY (vrp, y);
		ap = RealToRastX (vrp, a) - RealToRastX (vrp, 0);
		bp = RealToRastY (vrp, 0) - RealToRastY (vrp, b);

		/* sprawdzenie promieni */
		if ((ap > 32767) || (bp > 32767)) return;

		/* sprawdzenie minimalnego promienia */
		if ((ap < 2) || (bp < 2))
			{
				pixel_internal (vrp, xp, yp);
				return;
			}

		/* sprawdzenie obecnoôci elipsy na ekranie metodâ prostokâtów */
		if (xp + ap < vrp->box.MinX) return;
		if (xp - ap > vrp->box.MaxX) return;
		if (yp + bp < vrp->box.MinY) return;
		if (yp - bp > vrp->box.MaxY) return;

		/* obliczenie wielkoôci staîych w pëtli rysowania */
		f[2] = ap * ap;
		f[3] = bp * bp;
		mul64 (f[2], f[3], &econst);

		dx = 0; dy = -bp;

		/* pëtla rysujâca */
		do
			{
				if (mode == ELLIPSE_MODE_PLOT)
					{
						pixel_internal (vrp, xp + dx, yp + dy);
						pixel_internal (vrp, xp + dx, yp - dy);
						pixel_internal (vrp, xp - dx, yp + dy);
						pixel_internal (vrp, xp - dx, yp - dy);
					}
				if (mode == ELLIPSE_MODE_FILL)
					{
						fbox_internal (vrp, xp - dx, yp - dy, xp + dx, yp - dy);
						fbox_internal (vrp, xp - dx, yp + dy, xp + dx, yp + dy);
					}

				f[0] = dx * dx;
				f[1] = dy * dy;
				f[4] = f[0] + (dx << 1) + 1;         /* (dx+1)² */
				f[5] = f[1] + (dy << 1) + 1;         /* (dy+1)² */

				mul64 (f[4], f[3], &dev[0]);         /* (dx+1)²b² */
				mul64 (f[1], f[2], &dev[1]);         /* dy²a² */
				mul64 (f[0], f[3], &dev[2]);         /* dx²b² */
				mul64 (f[5], f[2], &dev[3]);         /* (dy+1)²a² */

				add64 (&dev[0], &dev[1]);
				sub64 (&econst, &dev[1]);            /* dev[1]=(dx+1)²b² + dy²a² - a²b² */
				add64 (&dev[3], &dev[2]);
				sub64 (&econst, &dev[2]);            /* dev[2]=dx²b² + (dy+1)²a² - a²b² */
				add64 (&dev[0], &dev[3]);
				sub64 (&econst, &dev[3]);            /* dev[2]=(dx+1)²b² + (dy+1)²a² - a²b² */

				abs64 (&dev[1]);            /* lewo */
				abs64 (&dev[2]);            /* dóî */
				abs64 (&dev[3]);            /* lewo i dóî */

				/* znalezienie najmniejszej wartoôci bezwzglëdnej odchyîki */
				if (cmp64 (&dev[1], &dev[2]) < 0)
					{
						dx++;
						if (cmp64 (&dev[1], &dev[3]) >= 0) dy++;
					}
				else
					{
						dy++;
						if (cmp64 (&dev[2], &dev[3]) >= 0) dx++;
					}
			}
		while (dy <= 0);
		
		return;
	}

//------------------------------------------------------------------------------------
// Funkcja sprawdza, czy piksel (x,y) znajduje sië wewnâtrz prostokâta obcinania,
// jeôli tak, stawia piksel.

static LONG pixel_internal (struct VRastPort *vrp, LONG x, LONG y)
	{
		if (y > vrp->box.MaxY) return (FALSE);
		if (y < vrp->box.MinY) return (FALSE);
		if (x > vrp->box.MaxX) return (FALSE);
		if (x < vrp->box.MinX) return (FALSE);
		WritePixel (vrp->rp, x, y);
		return (TRUE);
	}

//------------------------------------------------------------------------------------
// Funkcja rysuje wypeîniony prostokât o bokach równolegîych do osi ukîadu wspóîrzëd-
// nych.W razie potrzeby jest przycinany.Obowiâzuje x1 >= x0 i y1 >= y0.

static void fbox_internal (struct VRastPort *vrp, LONG x0, LONG y0, LONG x1, LONG y1)
	{
		struct Rectangle b = vrp->box;
		
		if ((x1 < b.MinX) || (x0 > b.MaxX)) return;
		if ((y1 < b.MinY) || (y0 > b.MaxY)) return;
		if (x0 < b.MinX) x0 = b.MinX;
		if (x1 > b.MaxX) x1 = b.MaxX;
		if (y0 < b.MinY) y0 = b.MinY;
		if (y1 > b.MaxY) y1 = b.MaxY;
		RectFill (vrp->rp, x0, y0, x1, y1);
		return;
	}

//-------------------------------------------------------------------------------------
// Funkcja sprawdza, czy naroûniki okna obcinania znajdujâ sië wewnâtrz wielokâta, a
// jeûeli tak, dopisuje je do tablicy 'cliptable' na czterech ostatnich pozycjach,
// jeûeli nie funkcja blokuje punkty ustawiajâc wspóîrzëdnâ x na 0x80000000. Nastëpnie
// funkcja uswa wszystkie dublujâce sië i zablokowane punkty z tablicy 'cliptable'.
// Ostatniâ czynnoôciâ jest uporzâdkowanie wierzchoîków w kolejnoôci rysowania.

static LONG prepare_filled_polygon (struct VRastPort *vrp, struct Point32 *polygon,
                                    struct Point32 *cliptable, WORD vertices)
	{
		WORD i, index, vert, byl;
		LONG devsign;
		Extended dev;
		struct Point32 p;
		
		/* 1. naroûnik lewy górny */
		p.x = vrp->box.MinX;
		p.y = vrp->box.MinY;
		cliptable[vertices << 1] = p;
		calc_deviation (&polygon[0], &polygon[1], &p, &dev);
		devsign = tst64 (&dev);
		for (index = 0; index < vertices; index++)
			{
				calc_deviation (&polygon[index], &polygon[(index + 1) % vertices], &p, &dev);
				if (tst64 (&dev) != devsign)
					{
						cliptable[vertices << 1].x = 0x80000000;
						break;
					}
      }

		/* 2. naroûnik lewy dolny */
		p.y = vrp->box.MaxY;
		cliptable[(vertices << 1) + 1] = p;
		calc_deviation (&polygon[0], &polygon[1], &p, &dev);
		devsign = tst64 (&dev);
		for (index = 0; index < vertices; index++)
			{
				calc_deviation (&polygon[index], &polygon[(index + 1) % vertices], &p, &dev);
				if (tst64 (&dev) != devsign)
					{
						cliptable[(vertices << 1) + 1].x = 0x80000000;
						break;
					}
      }

		/* 3. naroûnik prawy dolny */
		p.x = vrp->box.MaxX;
		cliptable[(vertices << 1) + 2] = p;
		calc_deviation (&polygon[0], &polygon[1], &p, &dev);
		devsign = tst64 (&dev);
		for (index = 0; index < vertices; index++)
			{
				calc_deviation (&polygon[index], &polygon[(index + 1) % vertices], &p, &dev);
				if (tst64 (&dev) != devsign)
					{
						cliptable[(vertices << 1) + 2].x = 0x80000000;
						break;
					}
      }

		/* 4. naroûnik prawy górny */
		p.y = vrp->box.MinY;
		cliptable[(vertices << 1) + 3] = p;
		calc_deviation (&polygon[0], &polygon[1], &p, &dev);
		devsign = tst64 (&dev);
		for (index = 0; index < vertices; index++)
			{
				calc_deviation (&polygon[index], &polygon[(index + 1) % vertices], &p, &dev);
				if (tst64 (&dev) != devsign)
					{
						cliptable[(vertices << 1) + 3].x = 0x80000000;
						break;
					}
      }

		/* usuniëcie powtarzajâcych sië i zablokowanych punktów z tablicy 'clipped' */
		vert = 0;
		for (index = 0; index < (vertices << 1) + 4; index++)
			{
				if (cliptable[index].x == 0x80000000) continue;
				byl = FALSE;
				for (i = vert - 1; i >= 0; i--)
					if ((cliptable[i].x == cliptable[index].x) && (cliptable[i].y ==
						cliptable[index].y))
						{
							byl = TRUE;
							break;
						}
				if (!byl) cliptable[vert++] = cliptable[index];
			}

		/* uîoûenie punktów w wielokât wypukîy */
		for (index = 0; index < vert - 2; index++)
			{
				for (i = 2 + index; i < vert; i++)
					{
						calc_deviation (&cliptable[index], &cliptable[index + 1], &cliptable[i],
							&dev);
						if (tst64 (&dev) < 0)
							{
								struct Point32 aux = cliptable[index + 1];
								cliptable[index + 1] = cliptable[i];
								cliptable[i] = aux;
								i = 1 + index;
							}
					}
			}
		return ((LONG)vert);
	}

//-------------------------------------------------------------------------------------
// Funkcja wykonuje nastëpujâce zadania:
// - przelicza wspóîrzëdne rzeczywiste wierzchoîków wielokâta na wspóîrzëdne rastrowe,
// - na ich podstawie wypeînia tablicë odcinków
// - przycina wszystkie odcinki do okna VRastPortu.
// Jeûeli wielokât znajduje sië caîkowicie poza oknem, funkcja zwraca 0.
// Parametry:
// polygon - tablica wierzchoîków wielokâta (wspóîrzëdne rzeczywiste).
// cliptable - tablica w której umieszczone bëdâ odcinki (wspóîrzëdne rastrowe).
// vertices - iloôê wierzchoîków (co najmniej 3).

static LONG clip_polygon (struct VRastPort *vrp, struct Point32 *polygon,
                          struct Point32 *cliptable, WORD vertices)
	{
		LONG draw = FALSE;           /* okreôla czy bëdzie coô do narysowania */
		LONG i;		

		/* przeliczanie wspóîrzëdnych w tablicy 'polygon' */
		for (i = 0; i < vertices; i++)
			{
				polygon[i].x = RealToRastX (vrp, polygon[i].x);
				polygon[i].y = RealToRastY (vrp, polygon[i].y);
			}

		/* wypeînianie tablicy odcinków 'cliptable' */

		cliptable[0] = cliptable[(vertices << 1) - 1] = polygon[0];
		for (i = 1; i < vertices; i++)
			cliptable[i << 1] = cliptable[(i << 1) - 1] = polygon[i];
		 	
		/* przycinanie */		
		for (i = 0; i < (vertices << 1); i += 2)
			{
				if (clip ((struct Line*)&cliptable[i], &vrp->box)) draw |= TRUE;
				else
					{
						cliptable[i].x = 0x80000000;
						cliptable[i + 1].x = 0x80000000;
					}
			}
		return (draw);
	}

//-------------------------------------------------------------------------------------

static LONG setup_tmpras (struct VRastPort *vrp)
	{
		if (!vrp->raster)
			{
				LONG size = (4 + ((vrp->box.MaxX - vrp->box.MinX + 32) >> 3) & 0xFFFC) *
					(vrp->box.MaxY - vrp->box.MinY + 1);
				vrp->raster = AllocVec (size, MEMF_CHIP);
				if (vrp->raster)
					{
						InitTmpRas (&vrp->tmpras, vrp->raster, size);
						return (TRUE);
					}
				else return (FALSE);
			}
		return (TRUE);
	}

//-------------------------------------------------------------------------------------

static void free_tmpras (struct VRastPort *vrp)
	{
		if (vrp->raster) FreeVec (vrp->raster);
		vrp->raster = NULL;
		return;
	}

//-------------------------------------------------------------------------------------

static LONG setup_ainfo (struct VRastPort *vrp, LONG vertices)
	{
		if (vrp->aitable)
			{
				if (vrp->aisize >= vertices) return (TRUE);
				else free_ainfo (vrp);
			}
	 	if (vrp->aitable = AllocVec (vertices * 5, MEMF_ANY))
			{
				vrp->aisize = vertices;
				return (TRUE);
			}
		return (FALSE);
	}

//-------------------------------------------------------------------------------------

static void free_ainfo (struct VRastPort *vrp)
	{
		if (vrp->aitable) FreeVec (vrp->aitable);
		vrp->aitable = NULL;
		return;
	}

