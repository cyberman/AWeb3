/*
 * zlib_wrapper.c - Implementation of z.library API wrapper
 * 
 * This file provides the implementation for the z.library API compatibility
 * layer used by AWebZen.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include "zlib_wrapper.h"

/* Global z.library base pointer */
struct Library *ZLibBase = NULL;

/**
 * Initialize z.library
 * 
 * Opens the z.library and sets up the global base pointer.
 * Must be called before using any zlib functions.
 * 
 * @return Z_OK on success, Z_VERSION_ERROR on failure
 */
LONG InitZLib(void)
{
    if (ZLibBase != NULL) {
        return Z_OK; /* Already initialized */
    }
    
    ZLibBase = OpenLibrary("z.library", 0);
    if (ZLibBase == NULL) {
        return Z_VERSION_ERROR;
    }
    
    return Z_OK;
}

/**
 * Cleanup z.library
 * 
 * Closes the z.library and resets the global base pointer.
 * Should be called when the application is shutting down.
 */
void CleanupZLib(void)
{
    if (ZLibBase != NULL) {
        CloseLibrary(ZLibBase);
        ZLibBase = NULL;
    }
} 