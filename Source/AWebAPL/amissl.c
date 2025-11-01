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

/* amissl.c - AWeb SSL function library. Updated for AmiSSL 5.20+ */
/* 
 * AmiSSL 5.20+ compatibility updates:
 * - Updated to use new OpenAmiSSLTags() API instead of deprecated InitAmiSSL()
 * - Added proper AmiSSLMaster library handling
 * - Updated to use modern OpenSSL 3.x API functions
 * - Enhanced error handling and resource cleanup
 * - Added proper pragma handling for SAS/C
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/filio.h>  /* For FIONBIO */
#include <sys/errno.h>  /* For EINTR and errno */
/* struct timeval and fd_set are provided by <sys/socket.h> via <proto/bsdsocket.h> */
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <proto/timer.h>  /* For GetSysTime() */
#include <proto/amisslmaster.h>
#include <proto/amissl.h>
#include <proto/bsdsocket.h>  /* For WaitSelect(), IoctlSocket(), Errno() */
#include <libraries/amisslmaster.h>
#include <libraries/amissl.h>
#include "aweb.h"
#include "awebssl.h"
#include "task.h"

/* CRITICAL: SocketBase must be declared for IoctlSocket() and WaitSelect() */
/* This is defined in http.c but we need it here too for SSL operations */
extern struct Library *SocketBase;

/* CRITICAL: Shared debug logging semaphore - defined in http.c, declared here */
/* This ensures both http.c and amissl.c use the same semaphore for thread-safe logging */
extern struct SignalSemaphore debug_log_sema;
extern BOOL debug_log_sema_initialized;
#include <amissl/amissl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <stdarg.h>

/* Pragma definitions are provided by <proto/amissl.h> and <proto/amisslmaster.h> */

/*-----------------------------------------------------------------------*/

struct Assl
{  struct Library *amisslmasterbase;
   struct Library *amisslbase;
   struct Library *amissslextbase;
   struct Library *socketbase;  /* CRITICAL: Store socketbase per-connection to avoid race condition with global SocketBase */
   SSL_CTX *sslctx;
   SSL *ssl;
   UBYTE *hostname;
   BOOL denied;
   BOOL closed;  /* CRITICAL: Flag to prevent use-after-free - set when SSL objects are freed */
   struct SignalSemaphore use_sema;  /* CRITICAL: Per-object semaphore to protect SSL object usage vs cleanup */
};

struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/* Semaphore to protect OpenSSL object creation/destruction */
/* SSL_CTX_new(), SSL_new(), SSL_free(), SSL_CTX_free() may access shared internal state */
/* Per-connection I/O operations (SSL_read, SSL_write, SSL_connect) don't need protection */
/* OPENSSL_init_ssl() is called once per task in Assl_initamissl(), not here */
static struct SignalSemaphore ssl_init_sema = {0};

/* Semaphore for thread-safe debug logging - shared with http.c via extern declaration */

/* Initialize SSL initialization semaphore - called once at startup */
static void InitSSLSemaphore(void)
{  InitSemaphore(&ssl_init_sema);
   /* NOTE: debug_log_sema is initialized in Inithttp() in http.c, not here */
   /* We just use it here via the extern declaration */
}

/* Thread-safe debug logging wrapper */
static void debug_printf(const char *format, ...)
{  va_list args;
   
   if(debug_log_sema_initialized)
   {  ObtainSemaphore(&debug_log_sema);
   }
   
   va_start(args, format);
   vprintf(format, args);
   va_end(args);
   
   if(debug_log_sema_initialized)
   {  ReleaseSemaphore(&debug_log_sema);
   }
}

/*-----------------------------------------------------------------------*/

struct Assl *Assl_initamissl(struct Library *socketbase)
{  
   struct Assl *assl;
   static BOOL sema_initialized = FALSE;
   
   /* Initialize semaphore on first call */
   if(!sema_initialized)
   {  InitSSLSemaphore();
      sema_initialized = TRUE;
   }
   
   if(socketbase && (assl=ALLOCSTRUCT(Assl,1,MEMF_CLEAR)))
   {  /* CRITICAL: Store socketbase in Assl struct to avoid race condition with global SocketBase */
      assl->socketbase = socketbase;
      /* CRITICAL: Initialize per-object semaphore FIRST, before any other operations */
      /* This must be done even if library initialization fails, to prevent bus errors */
      InitSemaphore(&assl->use_sema);
      assl->closed = FALSE;
      
      /* Check if AmiSSLMaster library is already open - reuse if so */
      if(!AmiSSLMasterBase)
      {
         /* Open AmiSSLMaster library first */
         if(AmiSSLMasterBase=OpenLibrary("amisslmaster.library",AMISSLMASTER_MIN_VERSION))
         {  
            /* Use new OpenAmiSSLTags API for AmiSSL 5.20+ */
            /* AmiSSL_InitAmiSSL defaults to TRUE, so InitAmiSSL() will be called automatically */
            if(OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
                              AmiSSL_UsesOpenSSLStructs, TRUE,
                              AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                              AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                              AmiSSL_SocketBase, socketbase,
                              AmiSSL_ErrNoPtr, &errno,
                              TAG_END) == 0)
            {  
               /* Success - libraries are now open and InitAmiSSL() was called by OpenAmiSSLTags */
               /* CRITICAL: According to AmiSSL examples, OPENSSL_init_ssl() should be called */
               /* once per task/application. It's idempotent, so safe to call multiple times */
               OPENSSL_init_ssl_32(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
            }
            else
            {  
               /* OpenAmiSSLTags failed */
               PutStr("ERROR: OpenAmiSSLTags() failed.\n");
               Lowlevelreq("AWeb could not initialize AmiSSL 5.20+.\nPlease check your AmiSSL installation and try again.");
               CloseLibrary(AmiSSLMasterBase);
               AmiSSLMasterBase = NULL;
            }
         }
         else
         {  
            PutStr("ERROR: Could not open amisslmaster.library.\n");
            Lowlevelreq("AWeb requires amisslmaster.library version 5.20 or newer for SSL/TLS connections.\nPlease install or update AmiSSL and try again.");
         }
      }
      else
      {  /* Libraries already open by another task - but THIS task still needs InitAmiSSL() */
         /* CRITICAL: Each subprocess/task MUST call InitAmiSSL() separately per AmiSSL docs */
         /* Even though libraries are shared, each task needs its own initialization */
         if(InitAmiSSL(AmiSSL_ErrNoPtr, &errno,
                       AmiSSL_SocketBase, socketbase,
                       AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                       AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                       TAG_END) != 0)
         {  /* InitAmiSSL failed for this task */
            PutStr("ERROR: InitAmiSSL() failed for this task.\n");
            FREE(assl);
            return NULL;
         }
         /* CRITICAL: OPENSSL_init_ssl() must be called once per task */
         /* It's idempotent, so safe to call even if called by another task */
         OPENSSL_init_ssl_32(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
      }
      
      /* If libraries are open, store references in this context */
      if(AmiSSLMasterBase && AmiSSLBase)
      {
         assl->amisslmasterbase = AmiSSLMasterBase;
         assl->amisslbase = AmiSSLBase;
         assl->amissslextbase = AmiSSLExtBase;
         /* Semaphore already initialized above, and closed flag already set to FALSE */
      }
      else
      {  
         /* Libraries failed to open - semaphore was already initialized, so safe to free */
         FREE(assl);
         assl=NULL;
      }
   }
   return assl;
}

/*-----------------------------------------------------------------------*/

/* Forward declaration for Assl_closessl() - needed since Assl_cleanup() calls it */
__asm void Assl_closessl(register __a0 struct Assl *assl);

/*-----------------------------------------------------------------------*/

static int __saveds __stdargs
   Certcallback(int ok,X509_STORE_CTX *sctx)
{  char *s,*u;
   struct Assl *assl;
   X509 *xs;
   int err;
   char buf[256];
   if(!ok && sctx)
   {  assl=Gettaskuserdata();
      /* CRITICAL: Check if SSL objects have been closed/freed to prevent use-after-free */
      /* Certcallback may be called asynchronously by OpenSSL, even after SSL objects are freed */
      if(assl && assl->amisslbase && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         xs=X509_STORE_CTX_get_current_cert(sctx);
         if(xs)
         {  err=X509_STORE_CTX_get_error(sctx);
            if(X509_NAME_oneline(X509_get_subject_name(xs),buf,sizeof(buf)))
            {  s=buf;         
               u=assl->hostname;
               ok=Httpcertaccept(u,s);
               if(!ok) assl->denied=TRUE;
            }
         }
      }
      else if(assl && assl->closed)
      {  /* SSL connection already closed - reject certificate to be safe */
         ok=0;
      }
   }
   return ok;
}

__asm void Assl_cleanup(register __a0 struct Assl *assl)
{  if(assl)
   {  /* CRITICAL: Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_cleanup: Invalid Assl pointer (%p), skipping\n", assl);
         return;
      }
      
      /* CRITICAL: First ensure SSL objects are closed */
      /* Assl_closessl() is idempotent and handles its own locking */
      if(assl->amisslbase)
      {  /* Call Assl_closessl() to properly clean up SSL objects */
         /* It will handle semaphore protection and is safe to call even if already closed */
         Assl_closessl(assl);
      }
      
      /* CRITICAL: Now obtain semaphore to ensure no concurrent operations */
      /* All SSL operations should be complete at this point */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Do NOT close global libraries here - they may be in use by other instances */
      /* The global AmiSSLMasterBase and AmiSSLBase are shared across all SSL connections */
      /* Only clear the local references, but don't close the libraries */
      /* Libraries will be cleaned up at program exit by the OS if still open */
      /* Assl_closessl() already nulled ssl and sslctx */
      /* We just need to null the library bases to signal this object is truly dead */
      assl->amisslbase = NULL;
      assl->amisslmasterbase = NULL;
      assl->amissslextbase = NULL;
      /* 'closed' flag was already set by Assl_closessl() */
      
      /* CRITICAL: Release semaphore */
      ReleaseSemaphore(&assl->use_sema);
      
      /* CRITICAL: DO NOT FREE THE STRUCT HERE! */
      /* FREE(assl); <-- THIS IS THE BUG! */
      /* The semaphore 'use_sema' is part of the struct itself */
      /* If we free the struct here, another task might try to obtain the semaphore */
      /* and crash accessing freed memory */
      /* The caller (AWeb) must now be responsible for calling FREE(assl) */
      /* after it calls Assl_cleanup() */
   }
}

__asm BOOL Assl_openssl(register __a0 struct Assl *assl)
{  BOOL result=FALSE;
   if(assl && assl->amisslbase)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      
      /* CRITICAL: Protect entire SSL context/object creation with semaphore */
      /* SSL_CTX_new() and SSL_new() access shared OpenSSL internal state */
      /* Even though each connection gets its own objects, creation must be serialized */
      ObtainSemaphore(&ssl_init_sema);
      
      /* CRITICAL: OPENSSL_init_ssl() is now called once per task in Assl_initamissl() */
      /* It should NOT be called here per connection - that's the bug! */
      
      /* CRITICAL: SSL context must be created fresh for each connection */
      /* Do NOT reuse SSL contexts - they are NOT thread-safe for concurrent use */
      /* CRITICAL: This function must ONLY be called on a clean Assl object */
      /* If sslctx or ssl already exist, that indicates a bug - the Assl is still in use */
      /* Each HTTPS connection must have its own dedicated Assl object */
      if(assl->sslctx || assl->ssl)
      {  printf("ERROR: Assl_openssl called on Assl that already has SSL objects (sslctx=%p, ssl=%p)\n",
                assl->sslctx, assl->ssl);
         printf("ERROR: This indicates the Assl object is being reused or is still in use by another task\n");
         printf("ERROR: Each HTTPS connection must have its own dedicated Assl object\n");
         /* CRITICAL: Do NOT free existing objects - they may be in use by another task */
         /* Return failure to indicate this is an error condition */
         ReleaseSemaphore(&ssl_init_sema);
         return FALSE;
      }
      
      /* Create new SSL context for this connection */
      /* CRITICAL: SSL_CTX_new() accesses shared OpenSSL state - must be serialized */
      debug_printf("DEBUG: Assl_openssl: Creating new SSL context\n");
      if(assl->sslctx=SSL_CTX_new(TLS_client_method()))
      {  debug_printf("DEBUG: Assl_openssl: SSL context created successfully\n");
         /* Set default certificate verification paths */
         SSL_CTX_set_default_verify_paths(assl->sslctx);
         
         /* Enhanced security: disable weak protocols and ciphers */
         SSL_CTX_set_options(assl->sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
         
         /* Set cipher list to strong ciphers only */
         SSL_CTX_set_cipher_list(assl->sslctx,"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK@STRENGTH");
         
         /* Set certificate verification callback */
         SSL_CTX_set_verify(assl->sslctx,SSL_VERIFY_FAIL_IF_NO_PEER_CERT,Certcallback);
      }
      else
      {  debug_printf("DEBUG: Assl_openssl: Failed to create SSL context\n");
      }
      
      /* CRITICAL: Reset denied flag and closed flag for new connection */
      assl->denied=FALSE;
      assl->closed=FALSE;
      
      /* Create new SSL object from context for this connection */
      /* CRITICAL: SSL_new() accesses shared OpenSSL state - must be serialized */
      if(assl->sslctx)
      {  debug_printf("DEBUG: Assl_openssl: Creating new SSL object from context\n");
         if(assl->ssl=SSL_new(assl->sslctx))
         {  debug_printf("DEBUG: Assl_openssl: SSL object created successfully\n");
            /* Store assl pointer for use in certificate callback */
            Settaskuserdata(assl);
         }
         else
         {  debug_printf("DEBUG: Assl_openssl: Failed to create SSL object\n");
         }
      }
      else
      {  debug_printf("DEBUG: Assl_openssl: Cannot create SSL object - no SSL context\n");
      }
      
      /* Set result based on success */
      result = (BOOL)(assl->sslctx && assl->ssl);
      
      /* CRITICAL: Release semaphore after all SSL object creation is complete */
      ReleaseSemaphore(&ssl_init_sema);
   }
   else
   {  debug_printf("DEBUG: Assl_openssl: Invalid parameters (assl=%p, amisslbase=%p)\n",
             assl, assl ? assl->amisslbase : NULL);
      result = FALSE;
   }
   
   return result;
}

__asm void Assl_closessl(register __a0 struct Assl *assl)
{  if(assl)
   {  struct Library *AmiSSLBase;
      /* CRITICAL: Validate Assl structure pointer is reasonable before accessing fields */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_closessl: Invalid Assl pointer (%p), skipping\n", assl);
         return;
      }
      
      /* CRITICAL: Semaphore is always accessible if assl pointer is valid (it's a field in the struct) */
      /* Use per-object semaphore to prevent cleanup while read/write operations are in progress */
      /* Obtain semaphore to ensure no concurrent read/write operations */
      /* CRITICAL: Do this BEFORE accessing other fields to ensure we hold the lock during validation */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Validate amisslbase pointer is reasonable after obtaining semaphore */
      /* This ensures we have the lock before checking if cleanup is needed */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_closessl: Invalid amisslbase pointer (%p), releasing semaphore and skipping\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return;
      }
      
      AmiSSLBase=assl->amisslbase;
      
      /* CRITICAL: Make this function idempotent - safe to call multiple times */
      /* If already closed, just return without doing anything */
      if(assl->closed)
      {  debug_printf("DEBUG: Assl_closessl: SSL connection already closed, skipping\n");
         ReleaseSemaphore(&assl->use_sema);
         return;
      }
      
      /* CRITICAL: Properly shutdown SSL before freeing to prevent corruption */
      /* MUST shutdown SSL connection BEFORE freeing SSL object */
      /* SSL_free() and SSL_CTX_free() may access shared OpenSSL state during cleanup */
      debug_printf("DEBUG: Assl_closessl: Closing SSL connection\n");
      
      /* CRITICAL: Mark as closed BEFORE freeing to prevent any further use */
      assl->closed = TRUE;
      
      /* CRITICAL: Protect SSL cleanup with global semaphore for OpenSSL internal state */
      /* SSL_free() and SSL_CTX_free() may access shared internal structures */
      ObtainSemaphore(&ssl_init_sema);
      
      /* CRITICAL: Shutdown SSL connection gracefully before freeing */
      /* This ensures SSL is properly disconnected from socket */
      if(assl->ssl)
      {  /* Validate pointer is reasonable before use */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0)
         {  /* Attempt graceful shutdown - SSL_shutdown may need to be called twice */
            /* First call sends close_notify, second call waits for peer's close_notify */
            /* For simplicity, we try once and ignore errors if socket is already closed */
            debug_printf("DEBUG: Assl_closessl: Attempting SSL shutdown\n");
            SSL_shutdown(assl->ssl);  /* Ignore return value - socket may already be closed */
            
            debug_printf("DEBUG: Assl_closessl: Freeing SSL object at %p\n", assl->ssl);
            /* CRITICAL: SSL_free() will automatically detach socket and clean up */
            SSL_free(assl->ssl);
            assl->ssl=NULL;
         }
         else
         {  debug_printf("DEBUG: Assl_closessl: Invalid SSL object pointer (%p), clearing reference\n", assl->ssl);
            assl->ssl=NULL;
         }
      }
      else
      {  debug_printf("DEBUG: Assl_closessl: No SSL object to free\n");
      }
      
      /* CRITICAL: Free SSL context AFTER SSL object is freed */
      /* Context can only be safely freed after all SSL objects using it are freed */
      if(assl->sslctx)
      {  /* Validate pointer is reasonable before freeing */
         if((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {  debug_printf("DEBUG: Assl_closessl: Freeing SSL context at %p\n", assl->sslctx);
            SSL_CTX_free(assl->sslctx);
            assl->sslctx=NULL;
         }
         else
         {  debug_printf("DEBUG: Assl_closessl: Invalid SSL context pointer (%p), clearing reference\n", assl->sslctx);
            assl->sslctx=NULL;
         }
      }
      else
      {  debug_printf("DEBUG: Assl_closessl: No SSL context to free\n");
      }
      
      /* CRITICAL: Release global semaphore after cleanup is complete */
      ReleaseSemaphore(&ssl_init_sema);
      
      /* CRITICAL: Release per-object semaphore - cleanup is complete, safe to allow new operations */
      ReleaseSemaphore(&assl->use_sema);
   }
   else
   {  debug_printf("DEBUG: Assl_closessl: Invalid parameters (assl=%p, amisslbase=%p)\n",
             assl, assl ? assl->amisslbase : NULL);
   }
}

__asm long Assl_connect(register __a0 struct Assl *assl,
   register __d0 long sock,
   register __a1 UBYTE *hostname)
{  long result=ASSLCONNECT_FAIL;
   struct Library *saved_socketbase = NULL;  /* CRITICAL: Save global SocketBase at function start for restoration */
   
   /* CRITICAL: Validate assl pointer before accessing semaphore field */
   if(assl)
   {  /* CRITICAL: Validate assl pointer range before accessing semaphore */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_connect: Invalid Assl pointer (%p)\n", assl);
         return ASSLCONNECT_FAIL;
      }
      
      /* CRITICAL: Save global SocketBase at start - we'll restore it at all exit points */
      saved_socketbase = SocketBase;
      
      /* CRITICAL: Obtain per-object semaphore to protect against cleanup */
      /* This prevents Assl_closessl() from freeing SSL objects while we're using them */
      /* CRITICAL: Obtain semaphore BEFORE accessing any struct fields */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Validate all pointers and structures AFTER obtaining semaphore */
      /* Check 'closed' flag *inside* the locked section to prevent race condition */
      if(assl->amisslbase && assl->sslctx && assl->ssl && !assl->closed && sock>=0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         
         /* CRITICAL: Validate SSL context and SSL object pointers are reasonable */
         if((ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0 ||
            (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
         {  /* Invalid pointers - return failure */
            debug_printf("DEBUG: Assl_connect: Invalid SSL pointer (sslctx=%p, ssl=%p)\n", assl->sslctx, assl->ssl);
            SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before releasing semaphore */
            ReleaseSemaphore(&assl->use_sema);
            return ASSLCONNECT_FAIL;
         }
         
         assl->hostname=hostname;
         
         /* CRITICAL: Validate socket descriptor is valid before use */
         if(SSL_set_fd(assl->ssl,sock) == 0)
         {  /* SSL_set_fd failed - SSL object might be invalid */
            debug_printf("DEBUG: Assl_connect: SSL_set_fd failed (sock=%ld)\n", sock);
            SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before releasing semaphore */
            ReleaseSemaphore(&assl->use_sema);
            return ASSLCONNECT_FAIL;
         }
         
         /* Set Server Name Indication (SNI) for TLS handshake */
         /* This is required for modern HTTPS servers that host multiple domains on one IP */
         if(hostname && *hostname)
         {  
            /* Validate hostname pointer is reasonable before dereferencing */
            if((ULONG)hostname < 0x1000 || (ULONG)hostname >= 0xFFFFFFF0)
            {  /* Invalid hostname pointer - skip SNI but continue connection */
               debug_printf("DEBUG: Assl_connect: Invalid hostname pointer (%p), skipping SNI\n", hostname);
            }
            else
            {  /* Validate hostname length before use */
               long hostname_len;
               hostname_len = strlen((char *)hostname);
               if(hostname_len > 0 && hostname_len < 256)
               {  /* CRITICAL: Use SSL_set_tlsext_host_name() as per AmiSSL example */
                  /* This is the proper way to set SNI in OpenSSL 3.x */
                  SSL_set_tlsext_host_name(assl->ssl, (char *)hostname);
                  debug_printf("DEBUG: Assl_connect: Set SNI hostname to '%s'\n", hostname);
               }
               else
               {  debug_printf("DEBUG: Assl_connect: Invalid hostname length (%ld), skipping SNI\n", hostname_len);
               }
            }
         }
         else
         {  debug_printf("DEBUG: Assl_connect: No hostname provided, skipping SNI\n");
         }
         
         /* Perform SSL/TLS handshake with timeout protection */
         /* CRITICAL: Socket timeouts (SO_RCVTIMEO/SO_SNDTIMEO) are set in Opensocket() */
         /* Try simple blocking SSL_connect() first - many servers work fine with this */
         /* Only use non-blocking I/O if we get WANT_READ/WANT_WRITE errors */
         {  long ssl_result;
            long ssl_error;
            ULONG nonblock;
            ULONG nonblock_restore = 0;
            fd_set readfds, writefds, exceptfds;
            struct timeval timeout;
            struct timeval start_time, current_time;
            long timeout_seconds = 30;  /* 30 second timeout for SSL handshake */
            BOOL socket_is_nonblocking = FALSE;
            BOOL handshake_complete = FALSE;
            
            debug_printf("DEBUG: Assl_connect: Starting SSL handshake\n");
            
            /* CRITICAL: Validate all pointers before first SSL_connect() call */
            if(!assl || !assl->amisslbase || !assl->sslctx || !assl->ssl)
            {  debug_printf("DEBUG: Assl_connect: Invalid pointers before SSL_connect() (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p)\n",
                       assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL);
               result=ASSLCONNECT_FAIL;
               SocketBase = saved_socketbase;
            }
            else if((ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0 ||
                    (ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0)
            {  debug_printf("DEBUG: Assl_connect: SSL pointers out of valid range before SSL_connect() (ssl=%p, sslctx=%p)\n",
                       assl->ssl, assl->sslctx);
               result=ASSLCONNECT_FAIL;
               SocketBase = saved_socketbase;
            }
            else if(sock < 0 || sock > 1000)
            {  debug_printf("DEBUG: Assl_connect: Invalid socket descriptor before SSL_connect() (sock=%ld)\n", sock);
               result=ASSLCONNECT_FAIL;
               SocketBase = saved_socketbase;
            }
            else
            {  /* First, try a simple blocking SSL_connect() call (like the earlier version) */
               /* Socket timeouts are already set, so this should timeout if the server hangs */
               debug_printf("DEBUG: Assl_connect: Attempting blocking SSL_connect() first\n");
               ssl_result = SSL_connect(assl->ssl);
            
               if(ssl_result == 1)
               {  /* Success on first try - simple case (like earlier version) */
                  result = ASSLCONNECT_OK;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL handshake successful on first attempt\n");
               }
               else if(assl->denied)
               {  /* Certificate denied by user */
                  result = ASSLCONNECT_DENIED;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL certificate denied by user\n");
               }
               else
               {  /* Check SSL error - on blocking socket, WANT_READ/WANT_WRITE should be rare */
                  ssl_error = SSL_get_error(assl->ssl, ssl_result);
                  debug_printf("DEBUG: Assl_connect: SSL_connect() returned %ld, SSL_get_error=%ld\n", ssl_result, ssl_error);
                  
                  if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                  {  /* Server needs non-blocking I/O - switch to non-blocking mode and retry */
                     debug_printf("DEBUG: Assl_connect: SSL wants I/O, switching to non-blocking mode for retry\n");
                     
                     /* CRITICAL: Set socket to non-blocking for WaitSelect() */
                     /* CRITICAL: Use per-connection socketbase instead of global SocketBase to avoid race conditions */
                     SocketBase = assl->socketbase;
                     nonblock = 1;
                     if(SocketBase && IoctlSocket(sock, FIONBIO, (char *)&nonblock) == 0)
                     {  socket_is_nonblocking = TRUE;
                        debug_printf("DEBUG: Assl_connect: Socket set to non-blocking mode\n");
                     }
                     else
                     {  debug_printf("DEBUG: Assl_connect: Failed to set socket to non-blocking, aborting\n");
                        result=ASSLCONNECT_FAIL;
                        SocketBase = saved_socketbase;
                        handshake_complete = TRUE;  /* Exit loop */
                     }
                     SocketBase = saved_socketbase;
                     
                     /* Get start time for timeout calculation */
                     if(!handshake_complete)
                     {  debug_printf("DEBUG: Assl_connect: Getting start time for timeout calculation\n");
                        GetSysTime(&start_time);
                        debug_printf("DEBUG: Assl_connect: Start time obtained, entering SSL handshake loop\n");
                     }
                  }
                  else
                  {  /* Real error - not WANT_READ/WANT_WRITE */
                     /* CRITICAL: For SSL_ERROR_SYSCALL, check errno for underlying system error */
                     if(ssl_error == SSL_ERROR_SYSCALL)
                     {  long errno_value = errno;
                        debug_printf("DEBUG: Assl_connect: SSL_connect failed with SSL_ERROR_SYSCALL (errno=%ld)\n", errno_value);
                        /* Common causes: connection reset, network unreachable, timeout, etc. */
                        if(errno_value == ECONNRESET)
                        {  debug_printf("DEBUG: Assl_connect: Connection reset by peer\n");
                        }
                        else if(errno_value == ETIMEDOUT)
                        {  debug_printf("DEBUG: Assl_connect: Connection timeout\n");
                        }
                        else if(errno_value == ECONNREFUSED)
                        {  debug_printf("DEBUG: Assl_connect: Connection refused\n");
                        }
                        else if(errno_value == ENETUNREACH)
                        {  debug_printf("DEBUG: Assl_connect: Network unreachable\n");
                        }
                     }
                     else
                     {  debug_printf("DEBUG: Assl_connect: SSL_connect failed, SSL_get_error returned %ld\n", ssl_error);
                     }
                     result=ASSLCONNECT_FAIL;
                     handshake_complete = TRUE;  /* Exit loop */
                  }
               }
            }
            
            /* Attempt SSL handshake with timeout loop (only if we need non-blocking I/O) */
            while(!handshake_complete && !assl->closed && socket_is_nonblocking)
            {  /* CRITICAL: Re-validate pointers before each iteration */
               if(!assl || !assl->ssl || !assl->sslctx || !assl->amisslbase)
               {  debug_printf("DEBUG: Assl_connect: Invalid pointers in handshake loop (assl=%p, ssl=%p, sslctx=%p, amisslbase=%p)\n",
                          assl, assl ? assl->ssl : NULL, assl ? assl->sslctx : NULL, assl ? assl->amisslbase : NULL);
                  result=ASSLCONNECT_FAIL;
                  break;
               }
               
               /* Check for task break before attempting handshake */
               if(Checktaskbreak())
               {  debug_printf("DEBUG: Assl_connect: Task break detected, aborting SSL handshake\n");
                  result=ASSLCONNECT_FAIL;
                  break;
               }
               
               /* Attempt SSL handshake */
               /* CRITICAL: Validate SSL object and socket one more time immediately before SSL_connect() */
               if(!assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL object invalid right before SSL_connect() (ssl=%p)\n", assl->ssl);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
               if(sock < 0)
               {  debug_printf("DEBUG: Assl_connect: Invalid socket descriptor (sock=%ld)\n", sock);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
               
               debug_printf("DEBUG: Assl_connect: Calling SSL_connect() (attempt in loop, ssl=%p, sock=%ld)\n", assl->ssl, sock);
               
               /* CRITICAL: Final validation immediately before SSL_connect() */
               /* Validate all critical structures one more time to catch any corruption */
               if(!assl || !assl->amisslbase || !assl->sslctx || !assl->ssl)
               {  debug_printf("DEBUG: Assl_connect: Critical pointers became invalid just before SSL_connect() (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p)\n",
                          assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* CRITICAL: Validate SSL object pointer range one more time */
               if((ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0 ||
                  (ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL pointers out of valid range just before SSL_connect() (ssl=%p, sslctx=%p)\n",
                          assl->ssl, assl->sslctx);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* CRITICAL: Validate socket descriptor is still valid */
               if(sock < 0 || sock > 1000)
               {  debug_printf("DEBUG: Assl_connect: Socket descriptor invalid just before SSL_connect() (sock=%ld)\n", sock);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* CRITICAL: SSL_connect() can crash if SSL object or socket is invalid */
               /* We hold the semaphore, so no other task should free assl->ssl, but validate after call */
               /* NOTE: If this crashes, it's likely an OpenSSL/AmiSSL library bug */
               ssl_result = SSL_connect(assl->ssl);
               
               /* CRITICAL: Validate SSL object is still valid after SSL_connect() */
               if(!assl || !assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL object became invalid during SSL_connect() (assl=%p, ssl=%p)\n", assl, assl ? assl->ssl : NULL);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
               
               debug_printf("DEBUG: Assl_connect: SSL_connect() returned %ld\n", ssl_result);
               
               if(ssl_result == 1)
               {  /* Handshake completed successfully */
                  result=ASSLCONNECT_OK;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL handshake successful\n");
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
               
               /* Check for certificate denial */
               if(assl->denied)
               {  result=ASSLCONNECT_DENIED;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL certificate denied by user\n");
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
               
               /* Get SSL error to determine next action */
               ssl_error = SSL_get_error(assl->ssl, ssl_result);
               
               /* Check if we need more I/O */
               if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
               {  /* SSL needs more I/O - wait for socket to be ready */
                  struct Library *saved_socketbase_wait;  /* CRITICAL: C89 - declare at start of block */
                  ULONG elapsed_secs;
                  
                  /* CRITICAL: Check timeout */
                  GetSysTime(&current_time);
                  /* Calculate elapsed time in seconds */
                  {  elapsed_secs = current_time.tv_secs - start_time.tv_secs;
                     if(elapsed_secs >= (ULONG)timeout_seconds)
                     {  debug_printf("DEBUG: Assl_connect: SSL handshake timeout after %ld seconds\n", timeout_seconds);
                        result=ASSLCONNECT_FAIL;
                        SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                        break;
                     }
                  }
                  
                  /* Set up fd_set for WaitSelect() */
                  FD_ZERO(&readfds);
                  FD_ZERO(&writefds);
                  FD_ZERO(&exceptfds);
                  
                  if(ssl_error == SSL_ERROR_WANT_READ)
                  {  FD_SET(sock, &readfds);
                     debug_printf("DEBUG: Assl_connect: SSL wants read, waiting for socket ready\n");
                  }
                  else
                  {  FD_SET(sock, &writefds);
                     debug_printf("DEBUG: Assl_connect: SSL wants write, waiting for socket ready\n");
                  }
                  FD_SET(sock, &exceptfds);
                  
                  /* Calculate remaining timeout */
                  {  elapsed_secs = current_time.tv_secs - start_time.tv_secs;
                     if(elapsed_secs >= (ULONG)timeout_seconds)
                     {  timeout.tv_sec = 0;
                        timeout.tv_micro = 100000;  /* 0.1 second minimum */
                     }
                     else
                     {  timeout.tv_sec = timeout_seconds - elapsed_secs;
                        timeout.tv_micro = 0;
                     }
                  }
                  
                  /* Wait for socket to be ready with timeout */
                  /* CRITICAL: Use per-connection socketbase - already set above */
                  if(!assl->socketbase)
                  {  debug_printf("DEBUG: Assl_connect: socketbase not set in Assl struct, aborting\n");
                     result=ASSLCONNECT_FAIL;
                     SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                     break;
                  }
                  /* CRITICAL: Set global SocketBase for WaitSelect() - save and restore to avoid race conditions */
                  saved_socketbase_wait = SocketBase;
                  SocketBase = assl->socketbase;
                  
                  /* Check for task break before waiting */
                  if(Checktaskbreak())
                  {  debug_printf("DEBUG: Assl_connect: Task break detected before WaitSelect, aborting\n");
                     SocketBase = saved_socketbase;  /* CRITICAL: Restore function-level SocketBase before breaking */
                     result=ASSLCONNECT_FAIL;
                     break;
                  }
                  
                  /* Wait for socket to be ready with timeout */
                  /* CRITICAL: Keep semaphore held - WaitSelect will respect timeout, preventing indefinite blocking */
                  /* If cleanup needs the semaphore, it will wait - this is safe because WaitSelect has a timeout */
                  /* CRITICAL: Do NOT pass SIGBREAKF_CTRL_C in signals parameter - it conflicts with break signal mask */
                  /* WaitSelect automatically handles break signal (Ctrl+C) and returns -1 with EINTR */
                  {  ULONG signals = 0;  /* No user signals - rely on break signal handling and timeout */
                     long wait_result;
                     long errno_value;
                     
                     /* WaitSelect with timeout - break signal (Ctrl+C) is automatically handled */
                     wait_result = WaitSelect(sock + 1, &readfds, &writefds, &exceptfds, &timeout, &signals);
                     
                     /* CRITICAL: Restore SocketBase immediately after WaitSelect() */
                     SocketBase = saved_socketbase_wait;
                     
                     /* CRITICAL: Check errno for EINTR when WaitSelect returns -1 (break signal) */
                     /* Per SDK docs: When break signal received, WaitSelect returns -1 with EINTR */
                     /* The signals mask is UNDEFINED when -1 is returned, so we check errno instead */
                     if(wait_result == -1)
                     {  errno_value = errno;  /* Use global errno variable from bsdsocket.library */
                        if(errno_value == EINTR)
                        {  /* Break signal received (Ctrl+C) - check for task break */
                           debug_printf("DEBUG: Assl_connect: WaitSelect interrupted by break signal (EINTR)\n");
                           if(Checktaskbreak())
                           {  debug_printf("DEBUG: Assl_connect: Task break detected, aborting SSL handshake\n");
                              result=ASSLCONNECT_FAIL;
                              SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                              break;
                           }
                           /* Continue loop to retry - break signal might be transient */
                           continue;
                        }
                        else
                        {  /* Other error - log and retry */
                           debug_printf("DEBUG: Assl_connect: WaitSelect error (result=%ld, errno=%ld), retrying\n", wait_result, errno_value);
                           /* Check for task break */
                           if(Checktaskbreak())
                           {  debug_printf("DEBUG: Assl_connect: Task break detected, aborting\n");
                              result=ASSLCONNECT_FAIL;
                              SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                              break;
                           }
                           /* Continue loop to retry - transient errors can occur */
                           continue;
                        }
                     }
                     
                     /* Check if object was closed while we were waiting */
                     if(assl->closed || !assl->amisslbase || !assl->sslctx || !assl->ssl)
                     {  debug_printf("DEBUG: Assl_connect: SSL object closed during WaitSelect, aborting\n");
                        result=ASSLCONNECT_FAIL;
                        SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                        break;
                     }
                     
                     if(wait_result == 0)
                     {  /* Timeout - check if we've exceeded total timeout */
                        GetSysTime(&current_time);
                        {  ULONG elapsed_secs;
                           elapsed_secs = current_time.tv_secs - start_time.tv_secs;
                           if(elapsed_secs >= (ULONG)timeout_seconds)
                           {  debug_printf("DEBUG: Assl_connect: WaitSelect timeout, SSL handshake timed out\n");
                              result=ASSLCONNECT_FAIL;
                              SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                              break;
                           }
                           else
                           {  /* Partial timeout - retry with remaining time */
                              debug_printf("DEBUG: Assl_connect: WaitSelect partial timeout, retrying\n");
                              /* Check for task break */
                              if(Checktaskbreak())
                              {  debug_printf("DEBUG: Assl_connect: Task break detected, aborting\n");
                                 result=ASSLCONNECT_FAIL;
                                 SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                                 break;
                              }
                              /* Continue loop to retry */
                              continue;
                           }
                        }
                     }
                     else if(wait_result > 0)
                     {  /* WaitSelect succeeded - check for exception conditions */
                        if(FD_ISSET(sock, &exceptfds))
                        {  /* Socket has exception condition - connection failed */
                           debug_printf("DEBUG: Assl_connect: Socket exception detected, handshake failed\n");
                           result=ASSLCONNECT_FAIL;
                           SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                           break;
                        }
                        /* Socket is ready - semaphore still held, continue to retry SSL_connect() */
                     }
                  }
                  
                  /* Socket is ready - continue loop to retry SSL_connect() */
                  continue;
               }
               else
               {  /* SSL error that's not WANT_READ/WANT_WRITE - handshake failed */
                  /* CRITICAL: For SSL_ERROR_SYSCALL, check errno for underlying system error */
                  if(ssl_error == SSL_ERROR_SYSCALL)
                  {  long errno_value = errno;
                     debug_printf("DEBUG: Assl_connect: SSL_connect failed with SSL_ERROR_SYSCALL (errno=%ld)\n", errno_value);
                     /* Common causes: connection reset, network unreachable, timeout, etc. */
                     if(errno_value == ECONNRESET)
                     {  debug_printf("DEBUG: Assl_connect: Connection reset by peer\n");
                     }
                     else if(errno_value == ETIMEDOUT)
                     {  debug_printf("DEBUG: Assl_connect: Connection timeout\n");
                     }
                     else if(errno_value == ECONNREFUSED)
                     {  debug_printf("DEBUG: Assl_connect: Connection refused\n");
                     }
                     else if(errno_value == ENETUNREACH)
                     {  debug_printf("DEBUG: Assl_connect: Network unreachable\n");
                     }
                  }
                  else
                  {  debug_printf("DEBUG: Assl_connect: SSL_connect failed, SSL_get_error returned %ld\n", ssl_error);
                  }
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* CRITICAL: Restore SocketBase before breaking */
                  break;
               }
            }
            
            /* CRITICAL: Restore socket blocking mode if we changed it */
            /* CRITICAL: SocketBase should already be restored from WaitSelect(), but ensure it's restored */
            if(socket_is_nonblocking && assl->socketbase)
            {  /* CRITICAL: Set global SocketBase temporarily for IoctlSocket() */
               struct Library *saved_socketbase_restore = SocketBase;
               SocketBase = assl->socketbase;
               nonblock = 0;
               if(IoctlSocket(sock, FIONBIO, (char *)&nonblock) == 0)
               {  debug_printf("DEBUG: Assl_connect: Socket restored to blocking mode\n");
               }
               SocketBase = saved_socketbase_restore;  /* Restore */
            }
            /* CRITICAL: Ensure SocketBase is restored (defensive - should already be restored) */
            SocketBase = saved_socketbase;
         }
      }
      else
      {  debug_printf("DEBUG: Assl_connect: Invalid parameters or already closed (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p, sock=%ld, closed=%d)\n",
                assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL, sock, assl ? assl->closed : -1);
      }
      
      /* CRITICAL: Always restore SocketBase before releasing semaphore and returning */
      /* This ensures we don't leave SocketBase in an inconsistent state */
      SocketBase = saved_socketbase;
      
      /* CRITICAL: Always release semaphore before returning */
      ReleaseSemaphore(&assl->use_sema);
   }
   else
   {  debug_printf("DEBUG: Assl_connect: Invalid Assl pointer (%p)\n", assl);
   }
   return result;
}

__asm char *Assl_geterror(register __a0 struct Assl *assl,
   register __a1 char *errbuf)
{  long err;
   UBYTE *p=NULL;
   short i;
   /* CRITICAL: Validate assl pointer before use */
   if(assl && errbuf)
   {  /* CRITICAL: Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  strcpy(errbuf, "Invalid Assl object");
         return errbuf;
      }
      
      /* CRITICAL: Obtain semaphore to protect access to amisslbase */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Check if amisslbase is still valid after obtaining semaphore */
      if(assl->amisslbase && (ULONG)assl->amisslbase >= 0x1000 && (ULONG)assl->amisslbase < 0xFFFFFFF0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* Modern OpenSSL doesn't need these deprecated functions */
         /* ERR_load_SSL_strings(); */
         err=ERR_get_error();
         if(err)
         {  ERR_error_string(err,errbuf);
            /* errbuf now contains something like: 
               "error:1408806E:SSL routines:SSL_SET_CERTIFICATE:certificate verify failed"
               Find the descriptive text after the 4th colon. */
            for(i=0,p=errbuf;i<4 && p;i++)
            {  p=strchr(p,':');
               if(!p) break;
               p++;
            }
         }
         else
         {  /* No error available, provide default message */
            strcpy(errbuf, "Unknown SSL error");
            p=errbuf;
         }
      }
      else
      {  /* SSL objects already cleaned up */
         strcpy(errbuf, "SSL connection closed");
         p=errbuf;
      }
      
      /* CRITICAL: Release semaphore */
      ReleaseSemaphore(&assl->use_sema);
   }
   else
   {  /* Invalid parameters */
      if(errbuf) strcpy(errbuf, "Invalid parameters");
   }
   if(!p && errbuf) p=errbuf;
   return (char *)p;
}

__asm long Assl_write(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   /* CRITICAL: Validate basic parameters first */
   /* CRITICAL: Validate buffer pointer range to prevent CHK instruction errors */
   if(assl && buffer && length>0 && length <= 1024*1024)  /* Max 1MB write */
   {  /* CRITICAL: Validate buffer pointer is in valid memory range */
      if((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid buffer pointer (%p)\n", buffer);
         return -1;
      }
      
      /* CRITICAL: Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid Assl pointer (%p)\n", assl);
         return -1;
      }
      
      /* CRITICAL: Use per-object semaphore to protect check-and-use of SSL objects */
      /* This prevents cleanup from freeing SSL objects while we're using them */
      /* CRITICAL: Obtain semaphore BEFORE accessing other fields */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Validate amisslbase after obtaining semaphore */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid amisslbase pointer (%p), releasing semaphore\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return -1;
      }
      
      /* CRITICAL: Check if SSL objects have been closed/freed AFTER obtaining semaphore */
      /* This ensures cleanup can't happen while we check and use the SSL object */
      if(assl->ssl && assl->sslctx && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* CRITICAL: Validate SSL object pointer is reasonable */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
            (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {  /* CRITICAL: SSL_write() operates on a unique SSL object per connection */
            /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
            /* CRITICAL: Keep semaphore held during I/O to prevent cleanup from freeing SSL object */
            /* This serializes operations on the SAME connection, but different connections are independent */
            result=SSL_write(assl->ssl,buffer,length);
            ReleaseSemaphore(&assl->use_sema);
            return result;  /* Return immediately after I/O completes */
         }
         else
         {  debug_printf("DEBUG: Assl_write: Invalid SSL pointer (ssl=%p, sslctx=%p)\n", assl->ssl, assl->sslctx);
            ReleaseSemaphore(&assl->use_sema);
         }
      }
      else if(assl->closed)
      {  /* SSL connection has been closed - return error */
         debug_printf("DEBUG: Assl_write: SSL connection already closed\n");
         ReleaseSemaphore(&assl->use_sema);
         result = -1;  /* Return error to indicate connection closed */
      }
      else
      {  debug_printf("DEBUG: Assl_write: SSL objects not available (ssl=%p, sslctx=%p, closed=%d)\n",
                assl->ssl, assl->sslctx, assl->closed);
         ReleaseSemaphore(&assl->use_sema);
      }
   }
   else
   {  debug_printf("DEBUG: Assl_write: Invalid parameters (assl=%p, amisslbase=%p, buffer=%p, length=%ld)\n",
             assl, assl ? assl->amisslbase : NULL, buffer, length);
   }
   return result;
}

__asm long Assl_read(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   /* CRITICAL: Validate basic parameters first */
   /* CRITICAL: Validate buffer pointer range to prevent CHK instruction errors */
   if(assl && buffer && length>0 && length <= 1024*1024)  /* Max 1MB read */
   {  /* CRITICAL: Validate buffer pointer is in valid memory range */
      if((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid buffer pointer (%p)\n", buffer);
         return -1;
      }
      
      /* CRITICAL: Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid Assl pointer (%p)\n", assl);
         return -1;
      }
      
      /* CRITICAL: Use per-object semaphore to protect check-and-use of SSL objects */
      /* This prevents cleanup from freeing SSL objects while we're using them */
      /* CRITICAL: Obtain semaphore BEFORE accessing other fields */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Validate amisslbase after obtaining semaphore */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid amisslbase pointer (%p), releasing semaphore\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return -1;
      }
      
      /* CRITICAL: Check if SSL objects have been closed/freed AFTER obtaining semaphore */
      /* This ensures cleanup can't happen while we check and use the SSL object */
      if(assl->ssl && assl->sslctx && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* CRITICAL: Validate SSL object pointer is reasonable */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
            (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {              /* CRITICAL: SSL_read() operates on a unique SSL object per connection */
            /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
            /* CRITICAL: Keep semaphore held during I/O to prevent cleanup from freeing SSL object */
            /* This serializes operations on the SAME connection, but different connections are independent */
            result=SSL_read(assl->ssl,buffer,length);
            ReleaseSemaphore(&assl->use_sema);
            return result;  /* Return immediately after I/O completes */
         }
         else
         {  debug_printf("DEBUG: Assl_read: Invalid SSL pointer (ssl=%p, sslctx=%p)\n", assl->ssl, assl->sslctx);
            ReleaseSemaphore(&assl->use_sema);
         }
      }
      else if(assl->closed)
      {  /* SSL connection has been closed - return error to indicate connection closed */
         debug_printf("DEBUG: Assl_read: SSL connection already closed\n");
         ReleaseSemaphore(&assl->use_sema);
         result = 0;  /* Return 0 to indicate EOF/connection closed */
      }
      else
      {  debug_printf("DEBUG: Assl_read: SSL objects not available (ssl=%p, sslctx=%p, closed=%d)\n",
                assl->ssl, assl->sslctx, assl->closed);
         ReleaseSemaphore(&assl->use_sema);
      }
   }
   else
   {  debug_printf("DEBUG: Assl_read: Invalid parameters (assl=%p, amisslbase=%p, buffer=%p, length=%ld)\n",
             assl, assl ? assl->amisslbase : NULL, buffer, length);
   }
   return result;
}

__asm char *Assl_getcipher(register __a0 struct Assl *assl)
{  char *result=NULL;
   /* CRITICAL: Validate assl pointer before use */
   if(assl)
   {  /* CRITICAL: Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  return NULL;
      }
      
      /* CRITICAL: Use per-object semaphore to protect check-and-use of SSL objects */
      /* Obtain semaphore BEFORE accessing any fields to prevent race conditions */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Check if amisslbase and SSL objects are still valid after obtaining semaphore */
      if(assl->amisslbase && (ULONG)assl->amisslbase >= 0x1000 && (ULONG)assl->amisslbase < 0xFFFFFFF0 &&
         assl->ssl && (ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         result=(char *)SSL_get_cipher(assl->ssl);
      }
      
      ReleaseSemaphore(&assl->use_sema);
   }
   return result;
}

__asm char *Assl_libname(register __a0 struct Assl *assl)
{  char *result=NULL;
   /* CRITICAL: Validate assl pointer before use */
   if(assl)
   {  /* CRITICAL: Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  return NULL;
      }
      
      /* CRITICAL: Use per-object semaphore to protect read of amisslbase */
      ObtainSemaphore(&assl->use_sema);
      
      /* CRITICAL: Check if amisslbase is still valid after obtaining semaphore */
      if(assl->amisslbase && (ULONG)assl->amisslbase >= 0x1000 && (ULONG)assl->amisslbase < 0xFFFFFFF0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         result=(char *)AmiSSLBase->lib_IdString;
      }
      
      /* CRITICAL: Release semaphore */
      ReleaseSemaphore(&assl->use_sema);
   }
   return result;
}

__asm void Assl_dummy(void)
{  return;
}

/*-----------------------------------------------------------------------*/

static UBYTE version[]="AwebAmiSSL.library";

struct Jumptab
{  UWORD jmp;
   void *function;
};
#define JMP 0x4ef9

/* Library jump table - referenced by awebamissllib structure for function dispatch */
static struct Jumptab jumptab[]=
{
   JMP,Assl_libname,
   JMP,Assl_getcipher,
   JMP,Assl_read,
   JMP,Assl_write,
   JMP,Assl_geterror,
   JMP,Assl_connect,
   JMP,Assl_closessl,
   JMP,Assl_openssl,
   JMP,Assl_cleanup,
   JMP,Assl_dummy, /* Extfunc */
   JMP,Assl_dummy, /* Expunge */
   JMP,Assl_dummy, /* Close */
   JMP,Assl_dummy, /* Open */
};
static struct Library awebamissllib=
{  {  NULL,NULL,NT_LIBRARY,0,version },
   0,0,
   sizeof(jumptab),
   sizeof(struct Library),
   1,0,
   version,
   0,0
};

struct Library *AwebAmisslBase=&awebamissllib;
