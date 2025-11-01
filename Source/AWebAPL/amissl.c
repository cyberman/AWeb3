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
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <proto/amisslmaster.h>
#include <proto/amissl.h>
#include <libraries/amisslmaster.h>
#include <libraries/amissl.h>
#include "aweb.h"
#include "awebssl.h"
#include "task.h"
#include <amissl/amissl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* Pragma definitions are provided by <proto/amissl.h> and <proto/amisslmaster.h> */

/*-----------------------------------------------------------------------*/

struct Assl
{  struct Library *amisslmasterbase;
   struct Library *amisslbase;
   struct Library *amissslextbase;
   SSL_CTX *sslctx;
   SSL *ssl;
   UBYTE *hostname;
   BOOL denied;
   BOOL closed;  /* CRITICAL: Flag to prevent use-after-free - set when SSL objects are freed */
};

struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/* Semaphore to protect OpenSSL object creation/destruction */
/* SSL_CTX_new(), SSL_new(), SSL_free(), SSL_CTX_free() may access shared internal state */
/* Per-connection I/O operations (SSL_read, SSL_write, SSL_connect) don't need protection */
/* OPENSSL_init_ssl() is called once per task in Assl_initamissl(), not here */
static struct SignalSemaphore ssl_init_sema = {0};

/* Initialize SSL initialization semaphore - called once at startup */
static void InitSSLSemaphore(void)
{  InitSemaphore(&ssl_init_sema);
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
   {  
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
      }
      else
      {  
         /* Libraries failed to open */
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
   {  /* Clean up ALL SSL resources for this instance */
      /* This is called when the entire Assl structure is being destroyed */
      /* CRITICAL: Assl_closessl() should have already freed SSL objects */
      /* But we check here to handle cases where Assl_closessl() wasn't called */
      if(assl->amisslbase && !assl->closed)
      {  /* SSL objects still exist and haven't been closed properly */
         /* Call Assl_closessl() to properly clean them up */
         printf("DEBUG: Assl_cleanup: SSL objects still exist, calling Assl_closessl() first\n");
         Assl_closessl(assl);
      }
      
      /* CRITICAL: Do NOT close global libraries here - they may be in use by other instances */
      /* The global AmiSSLMasterBase and AmiSSLBase are shared across all SSL connections */
      /* Only clear the local references, but don't close the libraries */
      /* Libraries will be cleaned up at program exit by the OS if still open */
      assl->amisslbase = NULL;
      assl->amisslmasterbase = NULL;
      assl->amissslextbase = NULL;
      
      FREE(assl);
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
      printf("DEBUG: Assl_openssl: Creating new SSL context\n");
      if(assl->sslctx=SSL_CTX_new(TLS_client_method()))
      {  printf("DEBUG: Assl_openssl: SSL context created successfully\n");
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
      {  printf("DEBUG: Assl_openssl: Failed to create SSL context\n");
      }
      
      /* CRITICAL: Reset denied flag and closed flag for new connection */
      assl->denied=FALSE;
      assl->closed=FALSE;
      
      /* Create new SSL object from context for this connection */
      /* CRITICAL: SSL_new() accesses shared OpenSSL state - must be serialized */
      if(assl->sslctx)
      {  printf("DEBUG: Assl_openssl: Creating new SSL object from context\n");
         if(assl->ssl=SSL_new(assl->sslctx))
         {  printf("DEBUG: Assl_openssl: SSL object created successfully\n");
            /* Store assl pointer for use in certificate callback */
            Settaskuserdata(assl);
         }
         else
         {  printf("DEBUG: Assl_openssl: Failed to create SSL object\n");
         }
      }
      else
      {  printf("DEBUG: Assl_openssl: Cannot create SSL object - no SSL context\n");
      }
      
      /* Set result based on success */
      result = (BOOL)(assl->sslctx && assl->ssl);
      
      /* CRITICAL: Release semaphore after all SSL object creation is complete */
      ReleaseSemaphore(&ssl_init_sema);
   }
   else
   {  printf("DEBUG: Assl_openssl: Invalid parameters (assl=%p, amisslbase=%p)\n",
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
      {  printf("DEBUG: Assl_closessl: Invalid Assl pointer (%p), skipping\n", assl);
         return;
      }
      
      /* CRITICAL: Validate amisslbase pointer is reasonable before accessing */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  printf("DEBUG: Assl_closessl: Invalid amisslbase pointer (%p), skipping\n", assl ? assl->amisslbase : NULL);
         return;
      }
      
      AmiSSLBase=assl->amisslbase;
      
      /* CRITICAL: Make this function idempotent - safe to call multiple times */
      /* If already closed, just return without doing anything */
      if(assl->closed)
      {  printf("DEBUG: Assl_closessl: SSL connection already closed, skipping\n");
         return;
      }
      
      /* CRITICAL: Properly shutdown SSL before freeing to prevent corruption */
      /* MUST shutdown SSL connection BEFORE freeing SSL object */
      /* SSL_free() and SSL_CTX_free() may access shared OpenSSL state during cleanup */
      printf("DEBUG: Assl_closessl: Closing SSL connection\n");
      
      /* CRITICAL: Protect SSL cleanup with semaphore */
      /* SSL_free() and SSL_CTX_free() may access shared internal structures */
      ObtainSemaphore(&ssl_init_sema);
      
      /* CRITICAL: Double-check closed flag after obtaining semaphore */
      /* Another task might have closed it while we were waiting for the semaphore */
      if(assl->closed)
      {  printf("DEBUG: Assl_closessl: SSL connection was closed by another task, releasing semaphore\n");
         ReleaseSemaphore(&ssl_init_sema);
         return;
      }
      
      /* CRITICAL: Shutdown SSL connection gracefully before freeing */
      /* This ensures SSL is properly disconnected from socket */
      if(assl->ssl)
      {  /* Validate pointer is reasonable before use */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0)
         {  /* Attempt graceful shutdown - SSL_shutdown may need to be called twice */
            /* First call sends close_notify, second call waits for peer's close_notify */
            /* For simplicity, we try once and ignore errors if socket is already closed */
            printf("DEBUG: Assl_closessl: Attempting SSL shutdown\n");
            SSL_shutdown(assl->ssl);  /* Ignore return value - socket may already be closed */
            
            printf("DEBUG: Assl_closessl: Freeing SSL object at %p\n", assl->ssl);
            /* CRITICAL: SSL_free() will automatically detach socket and clean up */
            SSL_free(assl->ssl);
            assl->ssl=NULL;
         }
         else
         {  printf("DEBUG: Assl_closessl: Invalid SSL object pointer (%p), clearing reference\n", assl->ssl);
            assl->ssl=NULL;
         }
      }
      else
      {  printf("DEBUG: Assl_closessl: No SSL object to free\n");
      }
      
      /* CRITICAL: Free SSL context AFTER SSL object is freed */
      /* Context can only be safely freed after all SSL objects using it are freed */
      if(assl->sslctx)
      {  /* Validate pointer is reasonable before freeing */
         if((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {  printf("DEBUG: Assl_closessl: Freeing SSL context at %p\n", assl->sslctx);
            SSL_CTX_free(assl->sslctx);
            assl->sslctx=NULL;
         }
         else
         {  printf("DEBUG: Assl_closessl: Invalid SSL context pointer (%p), clearing reference\n", assl->sslctx);
            assl->sslctx=NULL;
         }
      }
      else
      {  printf("DEBUG: Assl_closessl: No SSL context to free\n");
      }
      
      /* CRITICAL: Mark this Assl as closed to prevent use-after-free */
      /* Set flag BEFORE releasing semaphore to ensure visibility */
      assl->closed = TRUE;
      
      /* CRITICAL: Release semaphore after cleanup is complete */
      ReleaseSemaphore(&ssl_init_sema);
   }
   else
   {  printf("DEBUG: Assl_closessl: Invalid parameters (assl=%p, amisslbase=%p)\n",
             assl, assl ? assl->amisslbase : NULL);
   }
}

__asm long Assl_connect(register __a0 struct Assl *assl,
   register __d0 long sock,
   register __a1 UBYTE *hostname)
{  long result=ASSLCONNECT_FAIL;
   /* CRITICAL: Validate all pointers and structures before use */
   /* CRITICAL: Check if SSL objects have been closed/freed to prevent use-after-free */
   if(assl && assl->amisslbase && assl->sslctx && assl->ssl && !assl->closed && sock>=0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      
      /* CRITICAL: Validate SSL context and SSL object pointers are reasonable */
      if((ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0 ||
         (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
      {  /* Invalid pointers - return failure */
         printf("DEBUG: Assl_connect: Invalid SSL pointer (sslctx=%p, ssl=%p)\n", assl->sslctx, assl->ssl);
         return ASSLCONNECT_FAIL;
      }
      
      assl->hostname=hostname;
      
      /* CRITICAL: Validate socket descriptor is valid before use */
      if(SSL_set_fd(assl->ssl,sock) == 0)
      {  /* SSL_set_fd failed - SSL object might be invalid */
         printf("DEBUG: Assl_connect: SSL_set_fd failed (sock=%ld)\n", sock);
         return ASSLCONNECT_FAIL;
      }
      
      /* Set Server Name Indication (SNI) for TLS handshake */
      /* This is required for modern HTTPS servers that host multiple domains on one IP */
      if(hostname && *hostname)
      {  
         /* Validate hostname pointer is reasonable before dereferencing */
         if((ULONG)hostname < 0x1000 || (ULONG)hostname >= 0xFFFFFFF0)
         {  /* Invalid hostname pointer - skip SNI but continue connection */
            printf("DEBUG: Assl_connect: Invalid hostname pointer (%p), skipping SNI\n", hostname);
         }
         else
         {  /* Validate hostname length before use */
            long hostname_len;
            hostname_len = strlen((char *)hostname);
            if(hostname_len > 0 && hostname_len < 256)
            {  /* CRITICAL: Use SSL_set_tlsext_host_name() as per AmiSSL example */
               /* This is the proper way to set SNI in OpenSSL 3.x */
               SSL_set_tlsext_host_name(assl->ssl, (char *)hostname);
               printf("DEBUG: Assl_connect: Set SNI hostname to '%s'\n", hostname);
            }
            else
            {  printf("DEBUG: Assl_connect: Invalid hostname length (%ld), skipping SNI\n", hostname_len);
            }
         }
      }
      else
      {  printf("DEBUG: Assl_connect: No hostname provided, skipping SNI\n");
      }
      
      /* Perform SSL/TLS handshake */
      /* SSL_connect() returns:
       *   1 = handshake completed successfully
       *   0 = handshake not completed, needs more I/O (error)
       *  <0 = error occurred
       */
      /* CRITICAL: SSL_connect() operates on a unique SSL object per connection */
      /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
      /* No semaphore needed - concurrent SSL_connect() on different connections is safe */
      {  long ssl_result;
         printf("DEBUG: Assl_connect: Calling SSL_connect()...\n");
         
         ssl_result = SSL_connect(assl->ssl);
         
         printf("DEBUG: Assl_connect: SSL_connect() returned %ld\n", ssl_result);
         if(ssl_result == 1)
         {  /* Handshake completed successfully */
            result=ASSLCONNECT_OK;
            printf("DEBUG: Assl_connect: SSL handshake successful\n");
         }
         else if(assl->denied)
         {  /* Certificate was denied by user */
            result=ASSLCONNECT_DENIED;
            printf("DEBUG: Assl_connect: SSL certificate denied by user\n");
         }
         else
         {  /* Handshake failed - get error details */
            long ssl_error;
            ssl_error = SSL_get_error(assl->ssl, ssl_result);
            printf("DEBUG: Assl_connect: SSL_connect failed, SSL_get_error returned %ld\n", ssl_error);
            /* If error is SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, */
            /* it means more I/O is needed, which shouldn't happen with blocking sockets */
            /* For now, treat any non-success as failure */
            result=ASSLCONNECT_FAIL;
         }
      }
   }
   else
   {  printf("DEBUG: Assl_connect: Invalid parameters (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p, sock=%ld)\n",
             assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL, sock);
   }
   return result;
}

__asm char *Assl_geterror(register __a0 struct Assl *assl,
   register __a1 char *errbuf)
{  long err;
   UBYTE *p=NULL;
   short i;
   if(assl && assl->amisslbase && errbuf)
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
   if(!p) p=errbuf;
   return (char *)p;
}

__asm long Assl_write(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   /* CRITICAL: Validate all pointers and SSL resources before use */
   /* CRITICAL: Check if SSL objects have been closed/freed to prevent use-after-free */
   if(assl && assl->amisslbase && assl->ssl && assl->sslctx && !assl->closed && buffer && length>0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      /* CRITICAL: Validate SSL object pointer is reasonable */
      if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
         (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
      {  /* CRITICAL: SSL_write() operates on a unique SSL object per connection */
         /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
         /* No semaphore needed - concurrent writes on different connections are safe */
         result=SSL_write(assl->ssl,buffer,length);
      }
      else
      {  printf("DEBUG: Assl_write: Invalid SSL pointer (ssl=%p, sslctx=%p)\n", assl->ssl, assl->sslctx);
      }
   }
   else if(assl && assl->closed)
   {  /* SSL connection has been closed - return error */
      printf("DEBUG: Assl_write: SSL connection already closed\n");
      result = -1;  /* Return error to indicate connection closed */
   }
   else
   {  printf("DEBUG: Assl_write: Invalid parameters (assl=%p, amisslbase=%p, ssl=%p, sslctx=%p, closed=%d, buffer=%p, length=%ld)\n",
             assl, assl ? assl->amisslbase : NULL, assl ? assl->ssl : NULL, assl ? assl->sslctx : NULL, assl ? assl->closed : -1, buffer, length);
   }
   return result;
}

__asm long Assl_read(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   /* CRITICAL: Validate all pointers and SSL resources before use */
   /* CRITICAL: Check if SSL objects have been closed/freed to prevent use-after-free */
   if(assl && assl->amisslbase && assl->ssl && assl->sslctx && !assl->closed && buffer && length>0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      /* CRITICAL: Validate SSL object pointer is reasonable */
      if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
         (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
      {  /* CRITICAL: SSL_read() operates on a unique SSL object per connection */
         /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
         /* No semaphore needed - concurrent reads on different connections are safe */
         result=SSL_read(assl->ssl,buffer,length);
      }
      else
      {  printf("DEBUG: Assl_read: Invalid SSL pointer (ssl=%p, sslctx=%p)\n", assl->ssl, assl->sslctx);
      }
   }
   else if(assl && assl->closed)
   {  /* SSL connection has been closed - return error to indicate connection closed */
      printf("DEBUG: Assl_read: SSL connection already closed\n");
      result = 0;  /* Return 0 to indicate EOF/connection closed */
   }
   else
   {  printf("DEBUG: Assl_read: Invalid parameters (assl=%p, amisslbase=%p, ssl=%p, sslctx=%p, closed=%d, buffer=%p, length=%ld)\n",
             assl, assl ? assl->amisslbase : NULL, assl ? assl->ssl : NULL, assl ? assl->sslctx : NULL, assl ? assl->closed : -1, buffer, length);
   }
   return result;
}

__asm char *Assl_getcipher(register __a0 struct Assl *assl)
{  char *result=NULL;
   /* CRITICAL: Check if SSL objects have been closed/freed to prevent use-after-free */
   if(assl && assl->amisslbase && assl->ssl && !assl->closed)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      result=(char *)SSL_get_cipher(assl->ssl);
   }
   return result;
}

__asm char *Assl_libname(register __a0 struct Assl *assl)
{  char *result=NULL;
   if(assl && assl->amisslbase)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      result=(char *)AmiSSLBase->lib_IdString;
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
