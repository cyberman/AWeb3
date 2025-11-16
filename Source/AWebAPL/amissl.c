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

/* SocketBase must be declared for IoctlSocket() and WaitSelect() */
/* This is defined in http.c but we need it here too for SSL operations */
extern struct Library *SocketBase;

/* Shared debug logging semaphore - defined in http.c, declared here */
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

/* Per-task reference tracking for CleanupAmiSSL() calls */
struct TaskRefCount
{  struct Task *task;  /* Task pointer as identifier */
   ULONG refcount;     /* Number of Assl objects for this task */
   struct TaskRefCount *next;  /* Linked list */
};

struct Assl
{  struct Library *amisslmasterbase;
   struct Library *amisslbase;
   struct Library *amissslextbase;
   struct Library *socketbase;  /* Store socketbase per-connection to avoid race condition with global SocketBase */
   SSL_CTX *sslctx;
   SSL *ssl;
   UBYTE *hostname;
   BOOL denied;
   BOOL closed;  /* Flag to prevent use-after-free - set when SSL objects are freed */
   struct SignalSemaphore use_sema;  /* Per-object semaphore to protect SSL object usage vs cleanup */
   struct Task *owning_task;  /* Task that created this Assl object - used for cleanup tracking */
};

struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/* Semaphore to protect OpenSSL object creation/destruction */
/* SSL_CTX_new(), SSL_new(), SSL_free(), SSL_CTX_free() may access shared internal state */
/* Per-connection I/O operations (SSL_read, SSL_write, SSL_connect) don't need protection */
/* OPENSSL_init_ssl() is called once per task in Assl_initamissl(), not here */
static struct SignalSemaphore ssl_init_sema = {0};

/* Per-task reference counting for CleanupAmiSSL() calls */
/* Protected by ssl_init_sema since it's accessed during Assl creation/cleanup */
static struct TaskRefCount *task_ref_list = NULL;
static struct SignalSemaphore task_ref_sema = {0};

/* Semaphore for thread-safe debug logging - shared with http.c via extern declaration */

/* Initialize SSL initialization semaphore - called once at startup */
static void InitSSLSemaphore(void)
{  InitSemaphore(&ssl_init_sema);
   InitSemaphore(&task_ref_sema);
   /* NOTE: debug_log_sema is initialized in Inithttp() in http.c, not here */
   /* We just use it here via the extern declaration */
}

/* Increment reference count for current task */
/* Returns TRUE if this is the first Assl for this task (InitAmiSSL() was already called) */
static BOOL IncrementTaskRef(void)
{  struct Task *task;
   struct TaskRefCount *ref;
   BOOL is_first = FALSE;
   
   task = FindTask(NULL);
   if(!task)
   {  return FALSE;
   }
   
   ObtainSemaphore(&task_ref_sema);
   
   /* Search for existing entry for this task */
   ref = task_ref_list;
   while(ref)
   {  if(ref->task == task)
      {  ref->refcount++;
         ReleaseSemaphore(&task_ref_sema);
         return FALSE;  /* Not the first */
      }
      ref = ref->next;
   }
   
   /* Not found - create new entry */
   ref = (struct TaskRefCount *)AllocMem(sizeof(struct TaskRefCount), MEMF_CLEAR);
   if(ref)
   {  ref->task = task;
      ref->refcount = 1;
      ref->next = task_ref_list;
      task_ref_list = ref;
      is_first = TRUE;  /* First Assl for this task */
   }
   
   ReleaseSemaphore(&task_ref_sema);
   return is_first;
}

/* Decrement reference count for specified task */
/* Returns TRUE if this was the last Assl for this task (should call CleanupAmiSSL()) */
static BOOL DecrementTaskRef(struct Task *task)
{  struct TaskRefCount *ref;
   struct TaskRefCount *prev;
   BOOL is_last = FALSE;
   
   if(!task)
   {  return FALSE;
   }
   
   ObtainSemaphore(&task_ref_sema);
   
   /* Search for entry for this task */
   prev = NULL;
   ref = task_ref_list;
   while(ref)
   {  if(ref->task == task)
      {  ref->refcount--;
         if(ref->refcount == 0)
         {  /* Last Assl for this task - remove from list */
            is_last = TRUE;
            if(prev)
            {  prev->next = ref->next;
            }
            else
            {  task_ref_list = ref->next;
            }
            FreeMem(ref, sizeof(struct TaskRefCount));
         }
         ReleaseSemaphore(&task_ref_sema);
         return is_last;
      }
      prev = ref;
      ref = ref->next;
   }
   
   /* Not found - shouldn't happen, but be safe */
   ReleaseSemaphore(&task_ref_sema);
   return FALSE;
}

/*
 * MULTITHREADING SAFETY REQUIREMENTS (per AmiSSL 5.20+ documentation):
 * 
 * 1. Each subprocess/task MUST call InitAmiSSL() before using any amissl.library calls.
 *    - We do this in Assl_initamissl() for each task
 *    - OpenAmiSSLTags() automatically calls InitAmiSSL() for the first task
 *    - Subsequent tasks call InitAmiSSL() explicitly
 * 
 * 2. Each subprocess/task MUST call CleanupAmiSSL() before it exits.
 *    - IMPLEMENTED: Per-task reference counting tracks Assl objects per task
 *    - CleanupAmiSSL() is called automatically when the last Assl for a task is cleaned up
 *    - This prevents crashes per AmiSSL documentation requirement
 * 
 * 3. AmiSSLBase can be shared between subprocesses (unlike AmiSSL v1).
 *    - This is encouraged for certificate cache sharing
 *    - Each opener gets their own baserel-based library base
 *    - However, the global AmiSSLBase variable is still shared
 * 
 * 4. OpenSSL functions access the global AmiSSLBase internally via macro system.
 *    - We must ensure global AmiSSLBase is set correctly before every OpenSSL call
 *    - We do this defensively before SSL_CTX_new(), SSL_new(), SSL_connect(), etc.
 *    - We use semaphores to protect critical sections
 * 
 * 5. SSL objects (SSL_CTX, SSL) are NOT thread-safe for concurrent use.
 *    - Each connection must have its own SSL_CTX and SSL objects
 *    - We never reuse SSL objects - always create fresh ones per transaction
 *    - SSL object creation/destruction is serialized with ssl_init_sema
 * 
 * 6. Per-connection operations are serialized with per-object semaphores.
 *    - Each Assl struct has its own use_sema for serializing operations on that connection
 *    - Different connections can operate concurrently
 * 
 * CURRENT IMPLEMENTATION STATUS:
 * - ✅ InitAmiSSL() called per-task
 * - ✅ CleanupAmiSSL() called per-task when last Assl is cleaned up
 * - ✅ Global AmiSSLBase set before every OpenSSL call
 * - ✅ SSL objects never reused
 * - ✅ Semaphore protection for SSL object creation
 * - ✅ Per-connection semaphore protection
 * - ✅ Per-task reference counting for proper cleanup
 */

/* Helper function to get Task ID for logging */
static ULONG get_task_id(void)
{  struct Task *task;
   task = FindTask(NULL);
   return (ULONG)task;
}

/* Forward declaration for debug_printf - needed by check_ssl_error() */
static void debug_printf(const char *format, ...);

/* Helper function to check and log SSL errors after OpenSSL function calls */
/* Call this immediately after every OpenSSL function to catch errors early */
static void check_ssl_error(const char *function_name, struct Library *AmiSSLBase)
{  unsigned long err;
   char errbuf[256];
   char *errstr;
   
   /* Only check if we have a valid AmiSSLBase */
   if(!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 || (ULONG)AmiSSLBase >= 0xFFFFFFF0)
   {  return;
   }
   
   /* Check for errors in the OpenSSL error queue */
   err = ERR_get_error();
   if(err)
   {  /* Get error string - ERR_error_string() writes up to 256 bytes */
      ERR_error_string(err, errbuf);
      /* Find the descriptive part after the last colon */
      errstr = strrchr(errbuf, ':');
      if(errstr && *(errstr + 1) != '\0')
      {  errstr++;  /* Skip the colon */
         debug_printf("DEBUG: SSL ERROR after %s: %s (error code: 0x%08lX)\n", function_name, errstr, err);
      }
      else
      {  debug_printf("DEBUG: SSL ERROR after %s: %s (error code: 0x%08lX)\n", function_name, errbuf, err);
      }
      
      /* Check for additional errors in the queue */
      while((err = ERR_get_error()) != 0)
      {  ERR_error_string(err, errbuf);
         errstr = strrchr(errbuf, ':');
         if(errstr && *(errstr + 1) != '\0')
         {  errstr++;
            debug_printf("DEBUG: SSL ERROR (additional) after %s: %s (error code: 0x%08lX)\n", function_name, errstr, err);
         }
         else
         {  debug_printf("DEBUG: SSL ERROR (additional) after %s: %s (error code: 0x%08lX)\n", function_name, errbuf, err);
         }
      }
   }
}

/* Thread-safe debug logging wrapper with Task ID */
static void debug_printf(const char *format, ...)
{  va_list args;
   ULONG task_id;
   
   /* Only output if HTTPDEBUG mode is enabled */
   if(!httpdebug)
   {  return;
   }
   
   task_id = get_task_id();
   
   if(debug_log_sema_initialized)
   {  ObtainSemaphore(&debug_log_sema);
   }
   
   printf("[TASK:0x%08lX] ", task_id);
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
   
   debug_printf("DEBUG: Assl_initamissl: ENTRY - socketbase=%p\n", socketbase);
   
   /* Initialize semaphore on first call */
   if(!sema_initialized)
   {  debug_printf("DEBUG: Assl_initamissl: Initializing SSL init semaphore\n");
      InitSSLSemaphore();
      sema_initialized = TRUE;
      debug_printf("DEBUG: Assl_initamissl: SSL init semaphore initialized\n");
   }
   
   if(socketbase && (assl=ALLOCSTRUCT(Assl,1,MEMF_CLEAR)))
   {  debug_printf("DEBUG: Assl_initamissl: Allocated Assl struct at %p\n", assl);
      /* Store socketbase in Assl struct to avoid race condition with global SocketBase */
      assl->socketbase = socketbase;
      debug_printf("DEBUG: Assl_initamissl: Stored socketbase=%p in Assl struct\n", socketbase);
      /* Initialize per-object semaphore FIRST, before any other operations */
      /* This must be done even if library initialization fails, to prevent bus errors */
      InitSemaphore(&assl->use_sema);
      assl->closed = FALSE;
      debug_printf("DEBUG: Assl_initamissl: Initialized per-object semaphore and set closed=FALSE\n");
      
      /* Check if AmiSSLMaster library is already open - reuse if so */
      if(!AmiSSLMasterBase)
      {  debug_printf("DEBUG: Assl_initamissl: AmiSSLMaster library not open, opening now\n");
         /* Open AmiSSLMaster library first */
         if(AmiSSLMasterBase=OpenLibrary("amisslmaster.library",AMISSLMASTER_MIN_VERSION))
         {  debug_printf("DEBUG: Assl_initamissl: Opened amisslmaster.library at %p\n", AmiSSLMasterBase);
            /* Use new OpenAmiSSLTags API for AmiSSL 5.20+ */
            /* AmiSSL_InitAmiSSL defaults to TRUE, so InitAmiSSL() will be called automatically */
            debug_printf("DEBUG: Assl_initamissl: Calling OpenAmiSSLTags()\n");
            if(OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
                              AmiSSL_UsesOpenSSLStructs, TRUE,
                              AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                              AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                              AmiSSL_SocketBase, socketbase,
                              AmiSSL_ErrNoPtr, &errno,
                              TAG_END) == 0)
            {                 debug_printf("DEBUG: Assl_initamissl: OpenAmiSSLTags() succeeded\n");
               debug_printf("DEBUG: Assl_initamissl: AmiSSLBase=%p, AmiSSLExtBase=%p\n", AmiSSLBase, AmiSSLExtBase);
               /* CRITICAL: Ensure global AmiSSLBase is set correctly for this task */
               /* OpenAmiSSLTags() should have set it via AmiSSL_GetAmiSSLBase tag, but verify it */
               /* The global variable is shared across tasks, so we must ensure it's correct */
               if(!AmiSSLBase)
               {  debug_printf("DEBUG: Assl_initamissl: ERROR - Global AmiSSLBase is NULL after OpenAmiSSLTags()!\n");
               }
               else
               {  debug_printf("DEBUG: Assl_initamissl: Global AmiSSLBase verified: %p\n", AmiSSLBase);
               }
               /* Success - libraries are now open and InitAmiSSL() was called by OpenAmiSSLTags */
               /* According to AmiSSL examples, OPENSSL_init_ssl() should be called */
               /* once per task/application. It's idempotent, so safe to call multiple times */
               debug_printf("DEBUG: Assl_initamissl: Calling OPENSSL_init_ssl() for this task\n");
               OPENSSL_init_ssl_32(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
               debug_printf("DEBUG: Assl_initamissl: OPENSSL_init_ssl() completed\n");
            }
            else
            {  debug_printf("DEBUG: Assl_initamissl: OpenAmiSSLTags() failed\n");
               /* OpenAmiSSLTags failed */
               PutStr("ERROR: OpenAmiSSLTags() failed.\n");
               Lowlevelreq("AWeb could not initialize AmiSSL 5.20+.\nPlease check your AmiSSL installation and try again.");
               CloseLibrary(AmiSSLMasterBase);
               AmiSSLMasterBase = NULL;
               debug_printf("DEBUG: Assl_initamissl: Closed AmiSSLMasterBase after OpenAmiSSLTags failure\n");
            }
         }
         else
         {  debug_printf("DEBUG: Assl_initamissl: Failed to open amisslmaster.library\n");
            PutStr("ERROR: Could not open amisslmaster.library.\n");
            Lowlevelreq("AWeb requires amisslmaster.library version 5.20 or newer for SSL/TLS connections.\nPlease install or update AmiSSL and try again.");
         }
      }
      else
      {  debug_printf("DEBUG: Assl_initamissl: AmiSSLMaster library already open at %p, reusing\n", AmiSSLMasterBase);
         /* Libraries already open by another task - but THIS task still needs InitAmiSSL() */
         /* Each subprocess/task MUST call InitAmiSSL() separately per AmiSSL docs */
         /* Even though libraries are shared, each task needs its own initialization */
         debug_printf("DEBUG: Assl_initamissl: Calling InitAmiSSL() for this task\n");
         if(InitAmiSSL(AmiSSL_ErrNoPtr, &errno,
                       AmiSSL_SocketBase, socketbase,
                       AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                       AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                       TAG_END) != 0)
         {  debug_printf("DEBUG: Assl_initamissl: InitAmiSSL() failed for this task\n");
            /* InitAmiSSL failed for this task */
            PutStr("ERROR: InitAmiSSL() failed for this task.\n");
            FREE(assl);
            debug_printf("DEBUG: Assl_initamissl: Freed Assl struct after InitAmiSSL failure\n");
            return NULL;
         }
         debug_printf("DEBUG: Assl_initamissl: InitAmiSSL() succeeded, AmiSSLBase=%p, AmiSSLExtBase=%p\n", AmiSSLBase, AmiSSLExtBase);
         /* CRITICAL: Ensure global AmiSSLBase is set correctly for this task */
         /* InitAmiSSL() should have set it via AmiSSL_GetAmiSSLBase tag, but verify it */
         /* The global variable is shared across tasks, so we must ensure it's correct */
         if(!AmiSSLBase)
         {  debug_printf("DEBUG: Assl_initamissl: ERROR - Global AmiSSLBase is NULL after InitAmiSSL()!\n");
         }
         else
         {  debug_printf("DEBUG: Assl_initamissl: Global AmiSSLBase verified: %p\n", AmiSSLBase);
         }
         /* OPENSSL_init_ssl() must be called once per task */
         /* It's idempotent, so safe to call even if called by another task */
         debug_printf("DEBUG: Assl_initamissl: Calling OPENSSL_init_ssl() for this task\n");
         OPENSSL_init_ssl_32(OPENSSL_INIT_SSL_DEFAULT | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
         debug_printf("DEBUG: Assl_initamissl: OPENSSL_init_ssl() completed\n");
      }
      
      /* If libraries are open, store references in this context */
      if(AmiSSLMasterBase && AmiSSLBase)
      {  debug_printf("DEBUG: Assl_initamissl: Libraries open, storing references in Assl struct\n");
         assl->amisslmasterbase = AmiSSLMasterBase;
         assl->amisslbase = AmiSSLBase;
         assl->amissslextbase = AmiSSLExtBase;
         assl->owning_task = FindTask(NULL);  /* Store task pointer for cleanup tracking */
         debug_printf("DEBUG: Assl_initamissl: Stored library bases - master=%p, base=%p, ext=%p\n", 
                assl->amisslmasterbase, assl->amisslbase, assl->amissslextbase);
         debug_printf("DEBUG: Assl_initamissl: Stored owning task=%p\n", assl->owning_task);
         
         /* Increment per-task reference count */
         /* This tracks how many Assl objects each task has */
         /* When count reaches 0, we call CleanupAmiSSL() for that task */
         IncrementTaskRef();
         debug_printf("DEBUG: Assl_initamissl: Incremented task reference count\n");
         
         /* Semaphore already initialized above, and closed flag already set to FALSE */
         debug_printf("DEBUG: Assl_initamissl: SUCCESS - returning Assl struct at %p\n", assl);
      }
      else
      {  debug_printf("DEBUG: Assl_initamissl: Libraries failed to open, freeing Assl struct\n");
         /* Libraries failed to open - semaphore was already initialized, so safe to free */
         FREE(assl);
         assl=NULL;
         debug_printf("DEBUG: Assl_initamissl: Assl struct freed, returning NULL\n");
      }
   }
   else
   {  debug_printf("DEBUG: Assl_initamissl: Failed to allocate Assl struct or invalid socketbase\n");
   }
   debug_printf("DEBUG: Assl_initamissl: EXIT - returning %p\n", assl);
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
      /* Check if SSL objects have been closed/freed to prevent use-after-free */
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
   {  /* Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_cleanup: Invalid Assl pointer (%p), skipping\n", assl);
         return;
      }
      
      /* First ensure SSL objects are closed */
      /* Assl_closessl() is idempotent and handles its own locking */
      if(assl->amisslbase)
      {  /* Call Assl_closessl() to properly clean up SSL objects */
         /* It will handle semaphore protection and is safe to call even if already closed */
         Assl_closessl(assl);
      }
      
      /* Now obtain semaphore to ensure no concurrent operations */
      /* All SSL operations should be complete at this point */
      ObtainSemaphore(&assl->use_sema);
      
      /* Decrement per-task reference count BEFORE clearing library bases */
      /* If this was the last Assl for this task, we need to call CleanupAmiSSL() */
      /* We need the library bases to still be valid for CleanupAmiSSL() */
      if(assl->owning_task)
      {  struct Library *task_amisslbase = assl->amisslbase;  /* Save before clearing */
         struct Task *owning_task = assl->owning_task;  /* Save before clearing */
         BOOL is_last = DecrementTaskRef(owning_task);
         debug_printf("DEBUG: Assl_cleanup: Decremented task reference count for task %p, is_last=%d\n", owning_task, is_last);
         
         if(is_last && task_amisslbase)
         {  /* This was the last Assl for this task - call CleanupAmiSSL() */
            /* Per AmiSSL documentation: "Each subprocess MUST call CleanupAmiSSL() before it exits" */
            /* "Failure to do so can cause AmiSSL to crash" */
            debug_printf("DEBUG: Assl_cleanup: Last Assl for task %p, calling CleanupAmiSSL()\n", owning_task);
            
            /* Set global AmiSSLBase before calling CleanupAmiSSL() */
            /* CleanupAmiSSL() may access it internally */
            {  struct Library *saved_global_amisslbase = AmiSSLBase;
               AmiSSLBase = task_amisslbase;
               debug_printf("DEBUG: Assl_cleanup: Set global AmiSSLBase to %p before CleanupAmiSSL()\n", AmiSSLBase);
               
               CleanupAmiSSL(TAG_END);
               check_ssl_error("CleanupAmiSSL", AmiSSLBase);
               
               /* Restore global AmiSSLBase (though it may be used by other tasks) */
               AmiSSLBase = saved_global_amisslbase;
               debug_printf("DEBUG: Assl_cleanup: CleanupAmiSSL() completed, restored global AmiSSLBase to %p\n", AmiSSLBase);
            }
         }
      }
      
      /* Do NOT close global libraries here - they may be in use by other instances */
      /* The global AmiSSLMasterBase and AmiSSLBase are shared across all SSL connections */
      /* Only clear the local references, but don't close the libraries */
      /* Libraries will be cleaned up at program exit by the OS if still open */
      /* Assl_closessl() already nulled ssl and sslctx */
      /* We just need to null the library bases to signal this object is truly dead */
      assl->amisslbase = NULL;
      assl->amisslmasterbase = NULL;
      assl->amissslextbase = NULL;
      assl->owning_task = NULL;  /* Clear task pointer */
      /* 'closed' flag was already set by Assl_closessl() */
      
      /* Release semaphore */
      ReleaseSemaphore(&assl->use_sema);
      
      /* DO NOT FREE THE STRUCT HERE! */
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
   debug_printf("DEBUG: Assl_openssl: ENTRY - assl=%p\n", assl);
   
   if(assl && assl->amisslbase)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      
      debug_printf("DEBUG: Assl_openssl: Valid Assl and amisslbase, AmiSSLBase=%p\n", AmiSSLBase);
      
      /* Protect entire SSL context/object creation with semaphore */
      /* SSL_CTX_new() and SSL_new() access shared OpenSSL internal state */
      /* Even though each connection gets its own objects, creation must be serialized */
      debug_printf("DEBUG: Assl_openssl: Obtaining SSL init semaphore\n");
      ObtainSemaphore(&ssl_init_sema);
      debug_printf("DEBUG: Assl_openssl: SSL init semaphore obtained\n");
      
      /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling OpenSSL functions */
      /* SSL_CTX_new() and SSL_new() access the global AmiSSLBase internally */
      /* The global variable is shared across tasks, so we must ensure it's correct */
      if(!AmiSSLBase || AmiSSLBase != assl->amisslbase)
      {  debug_printf("DEBUG: Assl_openssl: ERROR - Global AmiSSLBase (%p) doesn't match assl->amisslbase (%p)!\n", AmiSSLBase, assl->amisslbase);
         debug_printf("DEBUG: Assl_openssl: CRITICAL - Setting global AmiSSLBase to prevent crash\n");
         /* CRITICAL: We must set the global AmiSSLBase before calling OpenSSL functions */
         /* Even though it's shared, InitAmiSSL() should have set it per-task */
         /* If it's wrong, we need to fix it to prevent crashes */
         /* WARNING: This may cause race conditions with other tasks, but crashing is worse */
         {  struct Library *old_amisslbase = AmiSSLBase;
            AmiSSLBase = assl->amisslbase;
            debug_printf("DEBUG: Assl_openssl: Set global AmiSSLBase to %p (was %p)\n", AmiSSLBase, old_amisslbase);
         }
      }
      else
      {  debug_printf("DEBUG: Assl_openssl: Global AmiSSLBase verified: %p matches assl->amisslbase\n", AmiSSLBase);
      }
      
      /* OPENSSL_init_ssl() is now called once per task in Assl_initamissl() */
      /* It should NOT be called here per connection - that's the bug! */
      
      /* SSL context must be created fresh for each connection */
      /* Do NOT reuse SSL contexts - they are NOT thread-safe for concurrent use */
      /* ALWAYS free any existing SSL objects before creating new ones */
      /* This ensures we never reuse SSL objects - each transaction gets a fresh SSL object */
      if(assl->sslctx || assl->ssl)
      {  debug_printf("DEBUG: Assl_openssl: WARNING - Assl already has SSL objects (sslctx=%p, ssl=%p), freeing them first\n",
                assl->sslctx, assl->ssl);
         
         /* CRITICAL: Set global AmiSSLBase before freeing SSL objects */
         /* SSL_free() and SSL_CTX_free() use the global AmiSSLBase internally */
         {  struct Library *saved_global_amisslbase = AmiSSLBase;
            AmiSSLBase = assl->amisslbase;
            if(saved_global_amisslbase != AmiSSLBase)
            {  debug_printf("DEBUG: Assl_openssl: Setting global AmiSSLBase to %p before freeing SSL objects (was %p)\n", AmiSSLBase, saved_global_amisslbase);
            }
         }
         
         /* Free existing SSL objects before creating new ones */
         /* This ensures we never reuse SSL objects - always create fresh ones */
         if(assl->ssl)
         {  /* Validate pointer before freeing */
            if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0)
            {  debug_printf("DEBUG: Assl_openssl: Freeing existing SSL object at %p\n", assl->ssl);
               SSL_free(assl->ssl);
               check_ssl_error("SSL_free (existing)", AmiSSLBase);
               assl->ssl = NULL;
            }
            else
            {  debug_printf("DEBUG: Assl_openssl: Invalid SSL object pointer (%p), clearing reference\n", assl->ssl);
               assl->ssl = NULL;
            }
         }
         if(assl->sslctx)
         {  /* Validate pointer before freeing */
            if((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
            {  debug_printf("DEBUG: Assl_openssl: Freeing existing SSL context at %p\n", assl->sslctx);
               SSL_CTX_free(assl->sslctx);
               check_ssl_error("SSL_CTX_free (existing)", AmiSSLBase);
               assl->sslctx = NULL;
            }
            else
            {  debug_printf("DEBUG: Assl_openssl: Invalid SSL context pointer (%p), clearing reference\n", assl->sslctx);
               assl->sslctx = NULL;
            }
         }
         /* Reset flags after freeing */
         assl->closed = FALSE;
         assl->denied = FALSE;
         debug_printf("DEBUG: Assl_openssl: Existing SSL objects freed, ready to create new ones\n");
      }
      
      /* Create new SSL context for this connection */
      /* SSL_CTX_new() accesses shared OpenSSL state - must be serialized */
      debug_printf("DEBUG: Assl_openssl: Creating new SSL context with TLS_client_method()\n");
      if(assl->sslctx=SSL_CTX_new(TLS_client_method()))
      {  debug_printf("DEBUG: Assl_openssl: SSL context created successfully at %p\n", assl->sslctx);
         check_ssl_error("SSL_CTX_new", AmiSSLBase);
         
         /* Set default certificate verification paths */
         debug_printf("DEBUG: Assl_openssl: Setting default certificate verification paths\n");
         SSL_CTX_set_default_verify_paths(assl->sslctx);
         check_ssl_error("SSL_CTX_set_default_verify_paths", AmiSSLBase);
         
         /* Enhanced security: disable weak protocols and ciphers */
         debug_printf("DEBUG: Assl_openssl: Setting SSL options (disabling SSLv2/SSLv3)\n");
         SSL_CTX_set_options(assl->sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
         check_ssl_error("SSL_CTX_set_options", AmiSSLBase);
         
         /* Set cipher list to strong ciphers only */
         debug_printf("DEBUG: Assl_openssl: Setting cipher list to strong ciphers only\n");
         SSL_CTX_set_cipher_list(assl->sslctx,"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK@STRENGTH");
         check_ssl_error("SSL_CTX_set_cipher_list", AmiSSLBase);
         
         /* Set certificate verification callback */
         debug_printf("DEBUG: Assl_openssl: Setting certificate verification callback\n");
         SSL_CTX_set_verify(assl->sslctx,SSL_VERIFY_FAIL_IF_NO_PEER_CERT,Certcallback);
         check_ssl_error("SSL_CTX_set_verify", AmiSSLBase);
         debug_printf("DEBUG: Assl_openssl: SSL context configuration complete\n");
      }
      else
      {  debug_printf("DEBUG: Assl_openssl: Failed to create SSL context\n");
         check_ssl_error("SSL_CTX_new (failed)", AmiSSLBase);
      }
      
      /* Reset denied flag and closed flag for new connection */
      assl->denied=FALSE;
      assl->closed=FALSE;
      debug_printf("DEBUG: Assl_openssl: Reset denied=FALSE, closed=FALSE\n");
      
      /* Create new SSL object from context for this connection */
      /* SSL_new() accesses shared OpenSSL state - must be serialized */
      if(assl->sslctx)
      {  debug_printf("DEBUG: Assl_openssl: Creating new SSL object from context\n");
         if(assl->ssl=SSL_new(assl->sslctx))
         {  debug_printf("DEBUG: Assl_openssl: SSL object created successfully at %p\n", assl->ssl);
            check_ssl_error("SSL_new", AmiSSLBase);
            /* Store assl pointer for use in certificate callback */
            debug_printf("DEBUG: Assl_openssl: Storing Assl pointer in task userdata for certificate callback\n");
            Settaskuserdata(assl);
            debug_printf("DEBUG: Assl_openssl: Task userdata set\n");
         }
         else
         {  debug_printf("DEBUG: Assl_openssl: Failed to create SSL object\n");
            check_ssl_error("SSL_new (failed)", AmiSSLBase);
         }
      }
      else
      {  debug_printf("DEBUG: Assl_openssl: Cannot create SSL object - no SSL context\n");
      }
      
      /* Set result based on success */
      result = (BOOL)(assl->sslctx && assl->ssl);
      debug_printf("DEBUG: Assl_openssl: SSL initialization result=%d (sslctx=%p, ssl=%p)\n", 
             result, assl->sslctx, assl->ssl);
      
      /* Release semaphore after all SSL object creation is complete */
      debug_printf("DEBUG: Assl_openssl: Releasing SSL init semaphore\n");
      ReleaseSemaphore(&ssl_init_sema);
      debug_printf("DEBUG: Assl_openssl: SSL init semaphore released\n");
   }
   else
   {  debug_printf("DEBUG: Assl_openssl: Invalid parameters (assl=%p, amisslbase=%p)\n",
             assl, assl ? assl->amisslbase : NULL);
      result = FALSE;
   }
   
   debug_printf("DEBUG: Assl_openssl: EXIT - returning %d\n", result);
   return result;
}

__asm void Assl_closessl(register __a0 struct Assl *assl)
{  if(assl)
   {  struct Library *AmiSSLBase;
      /* Validate Assl structure pointer is reasonable before accessing fields */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_closessl: Invalid Assl pointer (%p), skipping\n", assl);
         return;
      }
      
      /* Semaphore is always accessible if assl pointer is valid (it's a field in the struct) */
      /* Use per-object semaphore to prevent cleanup while read/write operations are in progress */
      /* Obtain semaphore to ensure no concurrent read/write operations */
      /* Do this BEFORE accessing other fields to ensure we hold the lock during validation */
      ObtainSemaphore(&assl->use_sema);
      
      /* Validate amisslbase pointer is reasonable after obtaining semaphore */
      /* This ensures we have the lock before checking if cleanup is needed */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_closessl: Invalid amisslbase pointer (%p), releasing semaphore and skipping\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return;
      }
      
      AmiSSLBase=assl->amisslbase;
      
      /* Make this function idempotent - safe to call multiple times */
      /* If already closed, just return without doing anything */
      if(assl->closed)
      {  debug_printf("DEBUG: Assl_closessl: SSL connection already closed, skipping\n");
         ReleaseSemaphore(&assl->use_sema);
         return;
      }
      
      /* Properly shutdown SSL before freeing to prevent corruption */
      /* MUST shutdown SSL connection BEFORE freeing SSL object */
      /* SSL_free() and SSL_CTX_free() may access shared OpenSSL state during cleanup */
      debug_printf("DEBUG: Assl_closessl: Closing SSL connection\n");
      
      /* Mark as closed BEFORE freeing to prevent any further use */
      assl->closed = TRUE;
      
      /* Protect SSL cleanup with global semaphore for OpenSSL internal state */
      /* SSL_free() and SSL_CTX_free() may access shared internal structures */
      ObtainSemaphore(&ssl_init_sema);
      
      /* Shutdown SSL connection gracefully before freeing */
      /* This ensures SSL is properly disconnected from socket */
      if(assl->ssl)
      {  /* Validate pointer is reasonable before use */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0)
         {              /* Attempt graceful shutdown - SSL_shutdown may need to be called twice */
            /* First call sends close_notify, second call waits for peer's close_notify */
            /* For simplicity, we try once and ignore errors if socket is already closed */
            debug_printf("DEBUG: Assl_closessl: Attempting SSL shutdown\n");
            SSL_shutdown(assl->ssl);  /* Ignore return value - socket may already be closed */
            check_ssl_error("SSL_shutdown", AmiSSLBase);
            
            debug_printf("DEBUG: Assl_closessl: Freeing SSL object at %p\n", assl->ssl);
            /* SSL_free() will automatically detach socket and clean up */
            SSL_free(assl->ssl);
            check_ssl_error("SSL_free", AmiSSLBase);
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
      
      /* Free SSL context AFTER SSL object is freed */
      /* Context can only be safely freed after all SSL objects using it are freed */
      if(assl->sslctx)
      {  /* Validate pointer is reasonable before freeing */
         if((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {  debug_printf("DEBUG: Assl_closessl: Freeing SSL context at %p\n", assl->sslctx);
            SSL_CTX_free(assl->sslctx);
            check_ssl_error("SSL_CTX_free", AmiSSLBase);
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
      
      /* Release global semaphore after cleanup is complete */
      ReleaseSemaphore(&ssl_init_sema);
      
      /* Release per-object semaphore - cleanup is complete, safe to allow new operations */
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
   struct Library *saved_socketbase = NULL;  /* Save global SocketBase at function start for restoration */
   
   debug_printf("DEBUG: Assl_connect: ENTRY - assl=%p, sock=%ld, hostname=%s\n", 
          assl, sock, hostname ? (char *)hostname : "(NULL)");
   
   /* Validate assl pointer before accessing semaphore field */
   if(assl)
   {  /* Validate assl pointer range before accessing semaphore */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_connect: Invalid Assl pointer (%p)\n", assl);
         return ASSLCONNECT_FAIL;
      }
      
      /* Save global SocketBase at start - we'll restore it at all exit points */
      saved_socketbase = SocketBase;
      
      /* Obtain per-object semaphore to protect against cleanup */
      /* This prevents Assl_closessl() from freeing SSL objects while we're using them */
      /* Obtain semaphore BEFORE accessing any struct fields */
      ObtainSemaphore(&assl->use_sema);
      
      /* Validate all pointers and structures AFTER obtaining semaphore */
      /* Check 'closed' flag *inside* the locked section to prevent race condition */
      if(assl->amisslbase && assl->sslctx && assl->ssl && !assl->closed && sock>=0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* C89 - declare all variables at start of block for SSL handshake */
         long ssl_result;
         long ssl_error;
         ULONG nonblock;
         fd_set readfds, writefds, exceptfds;
         struct timeval timeout;
         struct timeval start_time, current_time;
         long timeout_seconds = 30;  /* 30 second timeout for SSL handshake */
         BOOL socket_is_nonblocking = FALSE;
         BOOL handshake_complete = FALSE;
         
         /* Validate SSL context and SSL object pointers are reasonable */
         if((ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0 ||
            (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
         {  /* Invalid pointers - return failure */
            debug_printf("DEBUG: Assl_connect: Invalid SSL pointer (sslctx=%p, ssl=%p)\n", assl->sslctx, assl->ssl);
            SocketBase = saved_socketbase;  /* Restore SocketBase before releasing semaphore */
            ReleaseSemaphore(&assl->use_sema);
            return ASSLCONNECT_FAIL;
         }
         
         assl->hostname=hostname;
         
         /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling SSL_set_fd() */
         /* SSL_set_fd() uses the global AmiSSLBase internally via macro system */
         {  struct Library *saved_global_amisslbase = AmiSSLBase;
            AmiSSLBase = assl->amisslbase;
            if(saved_global_amisslbase != AmiSSLBase)
            {  debug_printf("DEBUG: Assl_connect: WARNING - Setting global AmiSSLBase to %p before SSL_set_fd() (was %p)\n", AmiSSLBase, saved_global_amisslbase);
            }
         }
         
         /* Validate socket descriptor is valid before use */
         if(SSL_set_fd(assl->ssl,sock) == 0)
         {  /* SSL_set_fd failed - SSL object might be invalid */
            debug_printf("DEBUG: Assl_connect: SSL_set_fd failed (sock=%ld)\n", sock);
            check_ssl_error("SSL_set_fd (failed)", AmiSSLBase);
            SocketBase = saved_socketbase;  /* Restore SocketBase before releasing semaphore */
            ReleaseSemaphore(&assl->use_sema);
            return ASSLCONNECT_FAIL;
         }
         else
         {  check_ssl_error("SSL_set_fd", AmiSSLBase);
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
               {  /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling SSL_set_tlsext_host_name() */
                  /* SSL_set_tlsext_host_name() uses the global AmiSSLBase internally via macro system */
                  {  struct Library *saved_global_amisslbase = AmiSSLBase;
                     AmiSSLBase = assl->amisslbase;
                     if(saved_global_amisslbase != AmiSSLBase)
                     {  debug_printf("DEBUG: Assl_connect: WARNING - Setting global AmiSSLBase to %p before SSL_set_tlsext_host_name() (was %p)\n", AmiSSLBase, saved_global_amisslbase);
                     }
                  }
                  /* Use SSL_set_tlsext_host_name() as per AmiSSL example */
                  /* This is the proper way to set SNI in OpenSSL 3.x */
                  SSL_set_tlsext_host_name(assl->ssl, (char *)hostname);
                  check_ssl_error("SSL_set_tlsext_host_name", AmiSSLBase);
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
         /* Socket timeouts (SO_RCVTIMEO/SO_SNDTIMEO) are set in Opensocket() */
         /* Try simple blocking SSL_connect() first - many servers work fine with this */
         /* Only use non-blocking I/O if we get WANT_READ/WANT_WRITE errors */
         debug_printf("DEBUG: Assl_connect: Starting SSL handshake\n");
         
         /* Validate all pointers before first SSL_connect() call */
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
               struct Library *AmiSSLBase;  /* C89 - declare at start of block */
               
               /* Validate library base is set before calling SSL_connect() */
               AmiSSLBase = assl->amisslbase;
               debug_printf("DEBUG: Assl_connect: Validating library base before SSL_connect() (AmiSSLBase=%p)\n", AmiSSLBase);
               if(!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 || (ULONG)AmiSSLBase >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: Invalid library base before SSL_connect() (%p)\n", AmiSSLBase);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  handshake_complete = TRUE;
               }
               else if(!assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: Invalid SSL object before SSL_connect() (ssl=%p)\n", assl->ssl);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  handshake_complete = TRUE;
               }
               else if(sock < 0 || sock > 1000)
               {  debug_printf("DEBUG: Assl_connect: Invalid socket descriptor before SSL_connect() (sock=%ld)\n", sock);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  handshake_complete = TRUE;
               }
               else
               {  long fd_check;  /* C89 - declare at start of block */
                  
                  debug_printf("DEBUG: Assl_connect: All validations passed, attempting blocking SSL_connect() first\n");
                  debug_printf("DEBUG: Assl_connect: SSL object=%p, socket=%ld, library base=%p\n", assl->ssl, sock, AmiSSLBase);
                  
                  /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling SSL_get_fd() */
                  /* SSL_get_fd() uses the global AmiSSLBase internally via macro system */
                  {  struct Library *saved_global_amisslbase = AmiSSLBase;
                     AmiSSLBase = assl->amisslbase;
                     if(saved_global_amisslbase != AmiSSLBase)
                     {  debug_printf("DEBUG: Assl_connect: WARNING - Setting global AmiSSLBase to %p before SSL_get_fd() (was %p)\n", AmiSSLBase, saved_global_amisslbase);
                     }
                  }
                  
                  /* Verify socket is still associated with SSL object before calling SSL_connect() */
                  /* SSL_get_fd() returns the socket file descriptor associated with the SSL object */
                  fd_check = SSL_get_fd(assl->ssl);
                  check_ssl_error("SSL_get_fd", AmiSSLBase);
                  debug_printf("DEBUG: Assl_connect: SSL_get_fd() returned %ld (expected %ld)\n", fd_check, sock);
                  if(fd_check != sock)
                  {  debug_printf("DEBUG: Assl_connect: ERROR - Socket mismatch! SSL object has fd=%ld but we're using sock=%ld\n", fd_check, sock);
                     result=ASSLCONNECT_FAIL;
                     SocketBase = saved_socketbase;
                     handshake_complete = TRUE;
                  }
                  else
                  {  /* Call SSL_connect() - InitAmiSSL() should have set AmiSSLBase for this task */
                     /* Do NOT modify global AmiSSLBase here - it causes race conditions with other tasks */
                     /* Each task has its own AmiSSLBase set by InitAmiSSL() in Assl_initamissl() */
                     /* Validate SSL object structure one more time before calling SSL_connect() */
                     /* SSL_connect() can crash with illegal instruction if SSL object is corrupted */
                     debug_printf("DEBUG: Assl_connect: Socket verified, about to call SSL_connect() - this may crash if SSL object is invalid\n");
                     debug_printf("DEBUG: Assl_connect: Global AmiSSLBase=%p, assl->amisslbase=%p (should match)\n", AmiSSLBase, assl->amisslbase);
                     debug_printf("DEBUG: Assl_connect: SSL object=%p, SSL context=%p, socket=%ld\n", assl->ssl, assl->sslctx, sock);
                     
                     /* Verify global AmiSSLBase is set correctly before calling OpenSSL functions */
                     /* InitAmiSSL() should have set it per-task - if it's wrong, that's a bug */
                     /* We can't safely modify the global here as it's shared across tasks */
                     /* However, OpenSSL functions may access the global internally, so we must ensure it's set */
                     /* For AmiSSL 5.20+, InitAmiSSL() sets per-task state, but the global may still be needed */
                     /* NOTE: We check the GLOBAL AmiSSLBase variable (declared at top of file), not the local variable */
                     /* The global variable is what OpenSSL functions use internally */
                     if(!AmiSSLBase || AmiSSLBase != assl->amisslbase)
                     {  debug_printf("DEBUG: Assl_connect: ERROR - Global AmiSSLBase (%p) doesn't match assl->amisslbase (%p)!\n", AmiSSLBase, assl->amisslbase);
                        debug_printf("DEBUG: Assl_connect: This indicates InitAmiSSL() was not called correctly for this task\n");
                        debug_printf("DEBUG: Assl_connect: CRITICAL - Setting global AmiSSLBase to prevent crash\n");
                        /* CRITICAL: We must set the global AmiSSLBase before calling OpenSSL functions */
                        /* Even though it's shared, InitAmiSSL() should have set it per-task */
                        /* If it's wrong, we need to fix it to prevent crashes */
                        /* This is safe because we hold the semaphore and InitAmiSSL() should have set it */
                        /* WARNING: This may cause race conditions with other tasks, but crashing is worse */
                        {  struct Library *old_amisslbase = AmiSSLBase;
                           AmiSSLBase = assl->amisslbase;
                           debug_printf("DEBUG: Assl_connect: Set global AmiSSLBase to %p (was %p)\n", AmiSSLBase, old_amisslbase);
                        }
                     }
                     else
                     {  debug_printf("DEBUG: Assl_connect: Global AmiSSLBase verified: %p matches assl->amisslbase\n", AmiSSLBase);
                     }
                     
                     /* Final validation - check that SSL object pointer is still valid */
                     if(!assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
                     {  debug_printf("DEBUG: Assl_connect: ERROR - SSL object became invalid just before SSL_connect() (ssl=%p)\n", assl->ssl);
                        result=ASSLCONNECT_FAIL;
                        SocketBase = saved_socketbase;
                        handshake_complete = TRUE;
                     }
                     else
                     {  /* Additional validation: verify SSL object is properly initialized */
                        /* Check that SSL object is associated with the correct SSL context */
                        SSL_CTX *sslctx_check;
                        
                        /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling SSL_get_SSL_CTX() */
                        /* SSL_get_SSL_CTX() uses the global AmiSSLBase internally via macro system */
                        {  struct Library *saved_global_amisslbase = AmiSSLBase;
                           AmiSSLBase = assl->amisslbase;
                           if(saved_global_amisslbase != AmiSSLBase)
                           {  debug_printf("DEBUG: Assl_connect: WARNING - Setting global AmiSSLBase to %p before SSL_get_SSL_CTX() (was %p)\n", AmiSSLBase, saved_global_amisslbase);
                           }
                        }
                        
                        sslctx_check = SSL_get_SSL_CTX(assl->ssl);
                        check_ssl_error("SSL_get_SSL_CTX", AmiSSLBase);
                        if(!sslctx_check || sslctx_check != assl->sslctx)
                        {  debug_printf("DEBUG: Assl_connect: ERROR - SSL object context mismatch! sslctx_check=%p, assl->sslctx=%p\n", sslctx_check, assl->sslctx);
                           result=ASSLCONNECT_FAIL;
                           SocketBase = saved_socketbase;
                           handshake_complete = TRUE;
                        }
                        else
                        {  debug_printf("DEBUG: Assl_connect: All validations passed, about to call SSL_connect()\n");
                           debug_printf("DEBUG: Assl_connect: SSL object=%p, SSL context=%p, socket=%ld, AmiSSLBase=%p\n", assl->ssl, assl->sslctx, sock, AmiSSLBase);
                           
                           /* CRITICAL: Protect SSL_connect() call with global semaphore */
                           /* This ensures no other task can modify global AmiSSLBase during the call */
                           /* We must hold ssl_init_sema to prevent race conditions */
                           ObtainSemaphore(&ssl_init_sema);
                           debug_printf("DEBUG: Assl_connect: Obtained ssl_init_sema for SSL_connect() protection\n");
                           
                           /* Set global AmiSSLBase IMMEDIATELY before SSL_connect() call */
                           /* With semaphore held, no other task can overwrite it */
                           {  struct Library *saved_global_amisslbase = AmiSSLBase;
                              AmiSSLBase = assl->amisslbase;
                              if(saved_global_amisslbase != AmiSSLBase)
                              {  debug_printf("DEBUG: Assl_connect: WARNING - Global AmiSSLBase was %p, setting to %p immediately before SSL_connect()\n", saved_global_amisslbase, AmiSSLBase);
                              }
                              debug_printf("DEBUG: Assl_connect: CRITICAL - About to call SSL_connect() - global AmiSSLBase=%p (protected by semaphore)\n", AmiSSLBase);
                              ssl_result = SSL_connect(assl->ssl);
                              /* Check for SSL errors immediately after SSL_connect() */
                              check_ssl_error("SSL_connect", AmiSSLBase);
                              /* Don't restore global AmiSSLBase - let it stay set for this task's next call */
                           }
                           
                           /* Release semaphore immediately after SSL_connect() returns */
                           ReleaseSemaphore(&ssl_init_sema);
                           debug_printf("DEBUG: Assl_connect: Released ssl_init_sema after SSL_connect()\n");
                           debug_printf("DEBUG: Assl_connect: SSL_connect() returned %ld (survived call)\n", ssl_result);
                           
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
                                 
                                 /* Set socket to non-blocking for WaitSelect() */
                                 /* Use per-connection socketbase instead of global SocketBase to avoid race conditions */
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
                                 /* For SSL_ERROR_SYSCALL, check errno for underlying system error */
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
                     }
                  }
               }
         }
         
         /* Attempt SSL handshake with timeout loop (only if we need non-blocking I/O) */
         while(!handshake_complete && !assl->closed && socket_is_nonblocking)
         {  /* Re-validate pointers before each iteration */
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
               /* Validate SSL object and socket one more time immediately before SSL_connect() */
               if(!assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL object invalid right before SSL_connect() (ssl=%p)\n", assl->ssl);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
               if(sock < 0)
               {  debug_printf("DEBUG: Assl_connect: Invalid socket descriptor (sock=%ld)\n", sock);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
               
               debug_printf("DEBUG: Assl_connect: Calling SSL_connect() (attempt in loop, ssl=%p, sock=%ld)\n", assl->ssl, sock);
               
               /* Final validation immediately before SSL_connect() */
               /* Validate all critical structures one more time to catch any corruption */
               if(!assl || !assl->amisslbase || !assl->sslctx || !assl->ssl)
               {  debug_printf("DEBUG: Assl_connect: Critical pointers became invalid just before SSL_connect() (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p)\n",
                          assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* Validate SSL object pointer range one more time */
               if((ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0 ||
                  (ULONG)assl->sslctx < 0x1000 || (ULONG)assl->sslctx >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL pointers out of valid range just before SSL_connect() (ssl=%p, sslctx=%p)\n",
                          assl->ssl, assl->sslctx);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* Validate socket descriptor is still valid */
               if(sock < 0 || sock > 1000)
               {  debug_printf("DEBUG: Assl_connect: Socket descriptor invalid just before SSL_connect() (sock=%ld)\n", sock);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;
                  break;
               }
               
               /* Verify global AmiSSLBase is set correctly before calling OpenSSL functions */
               /* InitAmiSSL() should have set it per-task - if it's wrong, that's a bug */
               /* We can't safely modify the global here as it's shared across tasks */
               /* However, OpenSSL functions may access the global internally, so we must ensure it's set */
               /* NOTE: We check the GLOBAL AmiSSLBase variable (declared at top of file), not a local variable */
               /* The global variable is what OpenSSL functions use internally */
               if(!AmiSSLBase || AmiSSLBase != assl->amisslbase)
               {  debug_printf("DEBUG: Assl_connect: ERROR - Global AmiSSLBase (%p) doesn't match assl->amisslbase (%p) in loop!\n", AmiSSLBase, assl->amisslbase);
                  debug_printf("DEBUG: Assl_connect: This indicates InitAmiSSL() was not called correctly for this task\n");
                  debug_printf("DEBUG: Assl_connect: CRITICAL - Setting global AmiSSLBase to prevent crash\n");
                  /* CRITICAL: We must set the global AmiSSLBase before calling OpenSSL functions */
                  /* Even though it's shared, InitAmiSSL() should have set it per-task */
                  /* If it's wrong, we need to fix it to prevent crashes */
                  /* WARNING: This may cause race conditions with other tasks, but crashing is worse */
                  {  struct Library *old_amisslbase = AmiSSLBase;
                     AmiSSLBase = assl->amisslbase;
                     debug_printf("DEBUG: Assl_connect: Set global AmiSSLBase to %p (was %p)\n", AmiSSLBase, old_amisslbase);
                  }
               }
               else
               {  debug_printf("DEBUG: Assl_connect: Global AmiSSLBase verified in loop: %p matches assl->amisslbase\n", AmiSSLBase);
               }
               
               /* Additional validation: verify SSL object is properly initialized */
               /* Check that SSL object is associated with the correct SSL context */
               {  SSL_CTX *sslctx_check;
                  
                  /* CRITICAL: Ensure global AmiSSLBase is set correctly before calling SSL_get_SSL_CTX() */
                  /* SSL_get_SSL_CTX() uses the global AmiSSLBase internally via macro system */
                  {  struct Library *saved_global_amisslbase = AmiSSLBase;
                     AmiSSLBase = assl->amisslbase;
                     if(saved_global_amisslbase != AmiSSLBase)
                     {  debug_printf("DEBUG: Assl_connect: WARNING - Setting global AmiSSLBase to %p before SSL_get_SSL_CTX() in loop (was %p)\n", AmiSSLBase, saved_global_amisslbase);
                     }
                  }
                  
                  sslctx_check = SSL_get_SSL_CTX(assl->ssl);
                  check_ssl_error("SSL_get_SSL_CTX (loop)", AmiSSLBase);
                  if(!sslctx_check || sslctx_check != assl->sslctx)
                  {  debug_printf("DEBUG: Assl_connect: ERROR - SSL object context mismatch in loop! sslctx_check=%p, assl->sslctx=%p\n", sslctx_check, assl->sslctx);
                     result=ASSLCONNECT_FAIL;
                     SocketBase = saved_socketbase;
                     break;
                  }
               }
               
               /* SSL_connect() can crash if SSL object or socket is invalid */
               /* We hold the semaphore, so no other task should free assl->ssl, but validate after call */
               /* NOTE: If this crashes, it's likely an OpenSSL/AmiSSL library bug */
               debug_printf("DEBUG: Assl_connect: All validations passed in loop, about to call SSL_connect()\n");
               debug_printf("DEBUG: Assl_connect: SSL object=%p, SSL context=%p, socket=%ld, AmiSSLBase=%p\n", assl->ssl, assl->sslctx, sock, AmiSSLBase);
               
               /* CRITICAL: Protect SSL_connect() call with global semaphore in loop */
               /* This ensures no other task can modify global AmiSSLBase during the call */
               /* We must hold ssl_init_sema to prevent race conditions */
               ObtainSemaphore(&ssl_init_sema);
               debug_printf("DEBUG: Assl_connect: Obtained ssl_init_sema for SSL_connect() protection in loop\n");
               
               /* Set global AmiSSLBase IMMEDIATELY before SSL_connect() call */
               /* With semaphore held, no other task can overwrite it */
               {  struct Library *saved_global_amisslbase = AmiSSLBase;
                  AmiSSLBase = assl->amisslbase;
                  if(saved_global_amisslbase != AmiSSLBase)
                  {  debug_printf("DEBUG: Assl_connect: WARNING - Global AmiSSLBase was %p in loop, setting to %p immediately before SSL_connect()\n", saved_global_amisslbase, AmiSSLBase);
                  }
                  debug_printf("DEBUG: Assl_connect: CRITICAL - About to call SSL_connect() in loop - global AmiSSLBase=%p (protected by semaphore)\n", AmiSSLBase);
                  ssl_result = SSL_connect(assl->ssl);
                  /* Check for SSL errors immediately after SSL_connect() */
                  check_ssl_error("SSL_connect (loop)", AmiSSLBase);
                  /* Don't restore global AmiSSLBase - let it stay set for this task's next call */
               }
               
               /* Release semaphore immediately after SSL_connect() returns */
               ReleaseSemaphore(&ssl_init_sema);
               debug_printf("DEBUG: Assl_connect: Released ssl_init_sema after SSL_connect() in loop\n");
               
               /* Validate SSL object is still valid after SSL_connect() */
               if(!assl || !assl->ssl || (ULONG)assl->ssl < 0x1000 || (ULONG)assl->ssl >= 0xFFFFFFF0)
               {  debug_printf("DEBUG: Assl_connect: SSL object became invalid during SSL_connect() (assl=%p, ssl=%p)\n", assl, assl ? assl->ssl : NULL);
                  result=ASSLCONNECT_FAIL;
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
               
               debug_printf("DEBUG: Assl_connect: SSL_connect() returned %ld\n", ssl_result);
               
               if(ssl_result == 1)
               {  /* Handshake completed successfully */
                  result=ASSLCONNECT_OK;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL handshake successful\n");
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
               
               /* Check for certificate denial */
               if(assl->denied)
               {  result=ASSLCONNECT_DENIED;
                  handshake_complete = TRUE;
                  debug_printf("DEBUG: Assl_connect: SSL certificate denied by user\n");
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
               
               /* Get SSL error to determine next action */
               ssl_error = SSL_get_error(assl->ssl, ssl_result);
               
               /* Check if we need more I/O */
               if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
               {  /* SSL needs more I/O - wait for socket to be ready */
                  struct Library *saved_socketbase_wait;  /* C89 - declare at start of block */
                  ULONG elapsed_secs;
                  
                  /* Check timeout */
                  GetSysTime(&current_time);
                  /* Calculate elapsed time in seconds */
                  {  elapsed_secs = current_time.tv_secs - start_time.tv_secs;
                     if(elapsed_secs >= (ULONG)timeout_seconds)
                     {  debug_printf("DEBUG: Assl_connect: SSL handshake timeout after %ld seconds\n", timeout_seconds);
                        result=ASSLCONNECT_FAIL;
                        SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                  /* Use per-connection socketbase - already set above */
                  if(!assl->socketbase)
                  {  debug_printf("DEBUG: Assl_connect: socketbase not set in Assl struct, aborting\n");
                     result=ASSLCONNECT_FAIL;
                     SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                     break;
                  }
                  /* Set global SocketBase for WaitSelect() - save and restore to avoid race conditions */
                  saved_socketbase_wait = SocketBase;
                  SocketBase = assl->socketbase;
                  
                  /* Check for task break before waiting */
                  if(Checktaskbreak())
                  {  debug_printf("DEBUG: Assl_connect: Task break detected before WaitSelect, aborting\n");
                     SocketBase = saved_socketbase;  /* Restore function-level SocketBase before breaking */
                     result=ASSLCONNECT_FAIL;
                     break;
                  }
                  
                  /* Wait for socket to be ready with timeout */
                  /* Keep semaphore held - WaitSelect will respect timeout, preventing indefinite blocking */
                  /* If cleanup needs the semaphore, it will wait - this is safe because WaitSelect has a timeout */
                  /* Do NOT pass SIGBREAKF_CTRL_C in signals parameter - it conflicts with break signal mask */
                  /* WaitSelect automatically handles break signal (Ctrl+C) and returns -1 with EINTR */
                  {  ULONG signals = 0;  /* No user signals - rely on break signal handling and timeout */
                     long wait_result;
                     long errno_value;
                     
                     /* WaitSelect with timeout - break signal (Ctrl+C) is automatically handled */
                     wait_result = WaitSelect(sock + 1, &readfds, &writefds, &exceptfds, &timeout, &signals);
                     
                     /* Restore SocketBase immediately after WaitSelect() */
                     SocketBase = saved_socketbase_wait;
                     
                     /* Check errno for EINTR when WaitSelect returns -1 (break signal) */
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
                              SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                              SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                        SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                              SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                              break;
                           }
                           else
                           {  /* Partial timeout - retry with remaining time */
                              debug_printf("DEBUG: Assl_connect: WaitSelect partial timeout, retrying\n");
                              /* Check for task break */
                              if(Checktaskbreak())
                              {  debug_printf("DEBUG: Assl_connect: Task break detected, aborting\n");
                                 result=ASSLCONNECT_FAIL;
                                 SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                           SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
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
                  /* For SSL_ERROR_SYSCALL, check errno for underlying system error */
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
                  SocketBase = saved_socketbase;  /* Restore SocketBase before breaking */
                  break;
               }
         }
         
         /* Restore socket blocking mode if we changed it */
         /* SocketBase should already be restored from WaitSelect(), but ensure it's restored */
         if(socket_is_nonblocking && assl->socketbase)
         {  /* Set global SocketBase temporarily for IoctlSocket() */
            struct Library *saved_socketbase_restore = SocketBase;
            SocketBase = assl->socketbase;
            nonblock = 0;
            if(IoctlSocket(sock, FIONBIO, (char *)&nonblock) == 0)
            {  debug_printf("DEBUG: Assl_connect: Socket restored to blocking mode\n");
            }
            SocketBase = saved_socketbase_restore;  /* Restore */
         }
         /* Ensure SocketBase is restored (defensive - should already be restored) */
         SocketBase = saved_socketbase;
      }
      else
      {  debug_printf("DEBUG: Assl_connect: Invalid parameters or already closed (assl=%p, amisslbase=%p, sslctx=%p, ssl=%p, sock=%ld, closed=%d)\n",
                assl, assl ? assl->amisslbase : NULL, assl ? assl->sslctx : NULL, assl ? assl->ssl : NULL, sock, assl ? assl->closed : -1);
      }
      
      /* Always restore SocketBase before releasing semaphore and returning */
      /* This ensures we don't leave SocketBase in an inconsistent state */
      SocketBase = saved_socketbase;
      
      /* Always release semaphore before returning */
      ReleaseSemaphore(&assl->use_sema);
      debug_printf("DEBUG: Assl_connect: Released semaphore, returning result=%ld\n", result);
   }
   else
   {  debug_printf("DEBUG: Assl_connect: Invalid Assl pointer (%p)\n", assl);
   }
   debug_printf("DEBUG: Assl_connect: EXIT - returning %ld\n", result);
   return result;
}

__asm char *Assl_geterror(register __a0 struct Assl *assl,
   register __a1 char *errbuf)
{  long err;
   UBYTE *p=NULL;
   short i;
   /* Local buffer for ERR_error_string() - OpenSSL can write up to 256 bytes */
   /* We use a local buffer to prevent overflow of caller's buffer */
   char local_errbuf[256];
   /* Conservative maximum size to copy to caller's buffer */
   /* Assume caller provides at least 80 bytes (historical AWeb minimum) */
   /* Use 79 to leave room for null terminator */
   const long max_copy = 79;
   
   /* Validate assl pointer before use */
   if(assl && errbuf)
   {  /* Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  /* Use strncpy with explicit null-termination to prevent overflow */
         strncpy(errbuf, "Invalid Assl object", max_copy);
         errbuf[max_copy] = '\0';
         return errbuf;
      }
      
      /* Obtain semaphore to protect access to amisslbase */
      ObtainSemaphore(&assl->use_sema);
      
      /* Check if amisslbase is still valid after obtaining semaphore */
      if(assl->amisslbase && (ULONG)assl->amisslbase >= 0x1000 && (ULONG)assl->amisslbase < 0xFFFFFFF0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* Modern OpenSSL doesn't need these deprecated functions */
         /* ERR_load_SSL_strings(); */
         err=ERR_get_error();
         if(err)
         {  /* Use local buffer for ERR_error_string() to prevent overflow */
            /* ERR_error_string() can write up to 256 bytes unconditionally */
            ERR_error_string(err, local_errbuf);
            /* errbuf now contains something like: 
               "error:1408806E:SSL routines:SSL_SET_CERTIFICATE:certificate verify failed"
               Find the descriptive text after the 4th colon. */
            for(i=0,p=local_errbuf;i<4 && p;i++)
            {  p=strchr(p,':');
               if(!p) break;
               p++;
            }
            /* If we found the descriptive part, copy it; otherwise copy the full error */
            if(p && *p)
            {  /* Copy descriptive part to caller's buffer with bounds checking */
               strncpy(errbuf, p, max_copy);
               errbuf[max_copy] = '\0';
               p = errbuf;
            }
            else
            {  /* No descriptive part found, copy full error message */
               strncpy(errbuf, local_errbuf, max_copy);
               errbuf[max_copy] = '\0';
               p = errbuf;
            }
         }
         else
         {  /* No error available, provide default message */
            strncpy(errbuf, "Unknown SSL error", max_copy);
            errbuf[max_copy] = '\0';
            p=errbuf;
         }
      }
      else
      {  /* SSL objects already cleaned up */
         strncpy(errbuf, "SSL connection closed", max_copy);
         errbuf[max_copy] = '\0';
         p=errbuf;
      }
      
      /* Release semaphore */
      ReleaseSemaphore(&assl->use_sema);
   }
   else
   {  /* Invalid parameters */
      if(errbuf)
      {  strncpy(errbuf, "Invalid parameters", max_copy);
         errbuf[max_copy] = '\0';
      }
   }
   if(!p && errbuf) p=errbuf;
   return (char *)p;
}

__asm long Assl_write(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   /* Validate basic parameters first */
   /* Validate buffer pointer range to prevent CHK instruction errors */
   if(assl && buffer && length>0 && length <= 1024*1024)  /* Max 1MB write */
   {  /* Validate buffer pointer is in valid memory range */
      if((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid buffer pointer (%p)\n", buffer);
         return -1;
      }
      
      /* Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid Assl pointer (%p)\n", assl);
         return -1;
      }
      
      /* Use per-object semaphore to protect check-and-use of SSL objects */
      /* This prevents cleanup from freeing SSL objects while we're using them */
      /* Obtain semaphore BEFORE accessing other fields */
      ObtainSemaphore(&assl->use_sema);
      
      /* Validate amisslbase after obtaining semaphore */
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_write: Invalid amisslbase pointer (%p), releasing semaphore\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return -1;
      }
      
      /* Check if SSL objects have been closed/freed AFTER obtaining semaphore */
      /* This ensures cleanup can't happen while we check and use the SSL object */
      if(assl->ssl && assl->sslctx && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* Validate SSL object pointer is reasonable */
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
            (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {              /* SSL_write() operates on a unique SSL object per connection */
            /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
            /* Keep semaphore held during I/O to prevent cleanup from freeing SSL object */
            /* This serializes operations on the SAME connection, but different connections are independent */
            result=SSL_write(assl->ssl,buffer,length);
            check_ssl_error("SSL_write", AmiSSLBase);
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
   
   debug_printf("DEBUG: Assl_read: ENTRY - assl=%p, buffer=%p, length=%ld\n", assl, buffer, length);
   
   /* Validate basic parameters first */
   /* Validate buffer pointer range to prevent CHK instruction errors */
   if(assl && buffer && length>0 && length <= 1024*1024)  /* Max 1MB read */
   {  debug_printf("DEBUG: Assl_read: Basic parameter validation passed\n");
      /* Validate buffer pointer is in valid memory range */
      if((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid buffer pointer (%p)\n", buffer);
         return -1;
      }
      debug_printf("DEBUG: Assl_read: Buffer pointer validation passed\n");
      
      /* Validate assl pointer before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid Assl pointer (%p)\n", assl);
         return -1;
      }
      debug_printf("DEBUG: Assl_read: Assl pointer validation passed\n");
      
      /* Validate semaphore field is accessible before trying to obtain it */
      /* The semaphore is at a fixed offset in the Assl struct, so validate the struct is intact */
      {  ULONG sema_offset;
         ULONG sema_addr;
         sema_offset = (ULONG)&assl->use_sema - (ULONG)assl;
         sema_addr = (ULONG)&assl->use_sema;
         debug_printf("DEBUG: Assl_read: Semaphore offset=%lu, address=%p\n", sema_offset, &assl->use_sema);
         if(sema_addr < 0x1000 || sema_addr >= 0xFFFFFFF0)
         {  debug_printf("DEBUG: Assl_read: Invalid semaphore address (%p), aborting\n", &assl->use_sema);
            return -1;
         }
      }
      
      /* Use per-object semaphore to protect check-and-use of SSL objects */
      /* This prevents cleanup from freeing SSL objects while we're using them */
      /* Obtain semaphore BEFORE accessing other fields */
      debug_printf("DEBUG: Assl_read: Obtaining use_sema semaphore\n");
      ObtainSemaphore(&assl->use_sema);
      debug_printf("DEBUG: Assl_read: use_sema semaphore obtained\n");
      
      /* Validate amisslbase after obtaining semaphore */
      debug_printf("DEBUG: Assl_read: Validating amisslbase pointer (amisslbase=%p)\n", assl->amisslbase);
      if(!assl->amisslbase || (ULONG)assl->amisslbase < 0x1000 || (ULONG)assl->amisslbase >= 0xFFFFFFF0)
      {  debug_printf("DEBUG: Assl_read: Invalid amisslbase pointer (%p), releasing semaphore\n", assl->amisslbase);
         ReleaseSemaphore(&assl->use_sema);
         return -1;
      }
      debug_printf("DEBUG: Assl_read: amisslbase validation passed\n");
      
      /* Check if SSL objects have been closed/freed AFTER obtaining semaphore */
      /* This ensures cleanup can't happen while we check and use the SSL object */
      debug_printf("DEBUG: Assl_read: Checking SSL objects (ssl=%p, sslctx=%p, closed=%d)\n", 
             assl->ssl, assl->sslctx, assl->closed);
      if(assl->ssl && assl->sslctx && !assl->closed)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         /* Validate SSL object pointer is reasonable */
         debug_printf("DEBUG: Assl_read: Validating SSL object pointers\n");
         if((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
            (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0)
         {  debug_printf("DEBUG: Assl_read: SSL object pointers valid, calling SSL_read()\n");
            /* SSL_read() operates on a unique SSL object per connection */
            /* OpenSSL 3.x is thread-safe when each connection has its own SSL object */
            /* Keep semaphore held during I/O to prevent cleanup from freeing SSL object */
            /* This serializes operations on the SAME connection, but different connections are independent */
            result=SSL_read(assl->ssl,buffer,length);
            check_ssl_error("SSL_read", AmiSSLBase);
            debug_printf("DEBUG: Assl_read: SSL_read() returned %ld\n", result);
            ReleaseSemaphore(&assl->use_sema);
            debug_printf("DEBUG: Assl_read: Released semaphore, returning %ld\n", result);
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
   debug_printf("DEBUG: Assl_read: EXIT - returning %ld\n", result);
   return result;
}

__asm char *Assl_getcipher(register __a0 struct Assl *assl)
{  char *result=NULL;
   /* Validate assl pointer before use */
   if(assl)
   {  /* Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  return NULL;
      }
      
      /* Use per-object semaphore to protect check-and-use of SSL objects */
      /* Obtain semaphore BEFORE accessing any fields to prevent race conditions */
      ObtainSemaphore(&assl->use_sema);
      
      /* Check if amisslbase and SSL objects are still valid after obtaining semaphore */
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
   /* Validate assl pointer before use */
   if(assl)
   {  /* Validate assl pointer range before accessing semaphore field */
      if((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0)
      {  return NULL;
      }
      
      /* Use per-object semaphore to protect read of amisslbase */
      ObtainSemaphore(&assl->use_sema);
      
      /* Check if amisslbase is still valid after obtaining semaphore */
      if(assl->amisslbase && (ULONG)assl->amisslbase >= 0x1000 && (ULONG)assl->amisslbase < 0xFFFFFFF0)
      {  struct Library *AmiSSLBase=assl->amisslbase;
         result=(char *)AmiSSLBase->lib_IdString;
      }
      
      /* Release semaphore */
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

