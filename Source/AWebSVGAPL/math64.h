/* math64.h */
/* $VER: math64.h 1.1 (14.10.98) */

#include <exec/types.h>

struct ExtendedLong
	{
		LONG high;
		ULONG low;
	};

typedef struct ExtendedLong Extended;

__asm LONG add64 (register __a0 Extended *a, register __a1 Extended *b);
__asm LONG sub64 (register __a0 Extended *a, register __a1 Extended *b);
__asm LONG cmp64 (register __a0 Extended *a, register __a1 Extended *b);
__asm void mul64 (register __d0 LONG a, register __d1 LONG b, register __a0 Extended *c);
__asm void abs64 (register __a0 Extended *a);
__asm LONG tst64 (register __a0 Extended *a);
__asm LONG div64 (register __a0 Extended *a, register __d0 LONG b);
__asm void shr64 (register __a0 Extended *a, register __d0 WORD shift);

