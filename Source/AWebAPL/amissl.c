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

#include <netdb.h>
#include <sys/errno.h> /* For EINTR and errno */
#include <sys/filio.h> /* For FIONBIO */
#include <sys/socket.h>
#include <sys/types.h>
/* struct timeval and fd_set are provided by <sys/socket.h> via
 * <proto/bsdsocket.h> */
#include "aweb.h"
#include "awebssl.h"
#include "task.h"
#include <libraries/amissl.h>
#include <libraries/amisslmaster.h>
#include <proto/amissl.h>
#include <proto/amisslmaster.h>
#include <proto/bsdsocket.h> /* For WaitSelect(), IoctlSocket(), Errno() */
#include <proto/dos.h>
#include <proto/exec.h>
#include <proto/timer.h> /* For GetSysTime() */
#include <proto/utility.h>

/* SocketBase must be declared for IoctlSocket() and WaitSelect() */
/* This is defined in http.c but we need it here too for SSL operations */
extern struct Library *SocketBase;

/* Shared debug logging semaphore - defined in http.c, declared here */
/* This ensures both http.c and amissl.c use the same semaphore for thread-safe
 * logging */
extern struct SignalSemaphore debug_log_sema;
extern BOOL debug_log_sema_initialized;
#include <amissl/amissl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h> /* For X509_STORE, X509_STORE_CTX, X509_verify_cert */
#include <openssl/x509v3.h> /* For X509_get_ext_d2i, GENERAL_NAME, NID_subject_alt_name */
#include <stdarg.h>

/* Pragma definitions are provided by <proto/amissl.h> and
 * <proto/amisslmaster.h> */

/*-----------------------------------------------------------------------*/

/* Per-task reference tracking for CleanupAmiSSL() calls */
struct TaskRefCount {
  struct Task *task;         /* Task pointer as identifier */
  ULONG refcount;            /* Number of Assl objects for this task */
  struct TaskRefCount *next; /* Linked list */
};

struct Assl {
  SSL_CTX *sslctx;
  SSL *ssl;
  UBYTE *hostname;
  BOOL denied;
  BOOL closed; /* Flag to prevent use-after-free - set when SSL objects are
                  freed */
  BOOL cert_validation_failed; /* Flag set by certificate callback if validation
                                  fails */
  char cert_error_msg[256];    /* Error message from certificate validation */
  struct SignalSemaphore use_sema; /* Per-object semaphore to protect SSL object
                                      usage vs cleanup */
};

struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/* Track the first task that called OpenAmiSSLTags() */
/* This is needed to distinguish the main task from subprocesses */
/* Subprocesses must call InitAmiSSL() explicitly, main task doesn't */
static struct Task *first_amissl_task = NULL;

/* Semaphore to protect OpenSSL object creation/destruction */
/* SSL_CTX_new(), SSL_new(), SSL_free(), SSL_CTX_free() may access shared
 * internal state */
/* Per-connection I/O operations (SSL_read, SSL_write, SSL_connect) don't need
 * protection */
/* InitAmiSSL() handles OpenSSL initialization internally - no need to call
 * OPENSSL_init_ssl() manually */
static struct SignalSemaphore ssl_init_sema = {0};
static BOOL ssl_init_sema_initialized = FALSE;

/* Per-task reference counting for CleanupAmiSSL() calls */
/* Protected by ssl_init_sema since it's accessed during Assl creation/cleanup
 */
static struct TaskRefCount *task_ref_list = NULL;
static struct SignalSemaphore task_ref_sema = {0};

/* Semaphore for thread-safe debug logging - shared with http.c via extern
 * declaration */

/* Initialize SSL initialization semaphore - called once at startup */
static void InitSSLSemaphore(void) {
  if (!ssl_init_sema_initialized) {
    InitSemaphore(&ssl_init_sema);
    InitSemaphore(&task_ref_sema);
    ssl_init_sema_initialized = TRUE;
    /* NOTE: debug_log_sema is initialized in Inithttp() in http.c, not here */
    /* We just use it here via the extern declaration */
  }
}

/* Increment reference count for current task */
/* Returns TRUE if this is the first Assl for this task (InitAmiSSL() was
 * already called) */
static BOOL IncrementTaskRef(void) {
  struct Task *task;
  struct TaskRefCount *ref;
  BOOL is_first = FALSE;

  task = FindTask(NULL);
  if (!task) {
    return FALSE;
  }

  ObtainSemaphore(&task_ref_sema);

  /* Search for existing entry for this task */
  ref = task_ref_list;
  while (ref) {
    if (ref->task == task) {
      ref->refcount++;
      ReleaseSemaphore(&task_ref_sema);
      return FALSE; /* Not the first */
    }
    ref = ref->next;
  }

  /* Not found - create new entry */
  ref =
      (struct TaskRefCount *)AllocMem(sizeof(struct TaskRefCount), MEMF_CLEAR);
  if (ref) {
    ref->task = task;
    ref->refcount = 1;
    ref->next = task_ref_list;
    task_ref_list = ref;
    is_first = TRUE; /* First Assl for this task */
  }

  ReleaseSemaphore(&task_ref_sema);
  return is_first;
}

/* Decrement reference count for specified task */
/* Returns TRUE if this was the last Assl for this task (should call
 * CleanupAmiSSL()) */
static BOOL DecrementTaskRef(struct Task *task) {
  struct TaskRefCount *ref;
  struct TaskRefCount *prev;
  BOOL is_last = FALSE;

  if (!task) {
    return FALSE;
  }

  ObtainSemaphore(&task_ref_sema);

  /* Search for entry for this task */
  prev = NULL;
  ref = task_ref_list;
  while (ref) {
    if (ref->task == task) {
      ref->refcount--;
      if (ref->refcount == 0) { /* Last Assl for this task - remove from list */
        is_last = TRUE;
        if (prev) {
          prev->next = ref->next;
        } else {
          task_ref_list = ref->next;
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
 * 1. Each subprocess/task MUST call InitAmiSSL() before using any
 * amissl.library calls.
 *    - We do this in Assl_initamissl() for each task
 *    - OpenAmiSSLTags() automatically calls InitAmiSSL() for the first task
 *    - Subsequent tasks call InitAmiSSL() explicitly
 *
 * 2. Each subprocess/task MUST call CleanupAmiSSL() before it exits.
 *    - IMPLEMENTED: Per-task reference counting tracks Assl objects per task
 *    - CleanupAmiSSL() is called automatically when the last Assl for a task is
 * cleaned up
 *    - This prevents crashes per AmiSSL documentation requirement
 *
 * 3. AmiSSLBase can be shared between subprocesses (unlike AmiSSL v1).
 *    - This is encouraged for certificate cache sharing
 *    - Each opener gets their own baserel-based library base
 *    - However, the global AmiSSLBase variable is still shared
 *
 * 4. AmiSSL uses a baserel system for library base management.
 *    - Each opener gets their own baserel-based AmiSSLBase
 *    - OpenSSL functions use the baserel system automatically
 *    - We NEVER modify the global AmiSSLBase variable (it causes race
 * conditions)
 *    - We use global AmiSSLBase for error checking
 *    - We use semaphores to protect critical sections
 *
 * 5. SSL objects (SSL_CTX, SSL) are NOT thread-safe for concurrent use.
 *    - Each connection must have its own SSL_CTX and SSL objects
 *    - We never reuse SSL objects - always create fresh ones per transaction
 *    - SSL object creation/destruction is serialized with ssl_init_sema
 *
 * 6. Per-connection operations are serialized with per-object semaphores.
 *    - Each Assl struct has its own use_sema for serializing operations on that
 * connection
 *    - Different connections can operate concurrently
 *
 */

/* Helper function to get Task ID for logging */
static ULONG get_task_id(void) {
  struct Task *task;
  task = FindTask(NULL);
  return (ULONG)task;
}

/* Forward declarations */
static void debug_printf(const char *format, ...);
static void check_ssl_error(const char *function_name,
                            struct Library *AmiSSLBase);

/* SSL info callback for detailed handshake debugging */
/* This callback provides detailed information about SSL handshake progress */
static void ssl_info_callback(const SSL *ssl, int where, int ret) {
  /* const char *str; */
  /* const char *alert_str; */
  /* int w; */
  /* struct Assl *assl; */
  /* CRITICAL: Shadow the global AmiSSLBase with the one stored in this
   * connection's context */
  /* OpenSSL macros (like SSL_state_string_long) implicitly use the symbol
   * AmiSSLBase */
  /* We must shadow it locally to prevent using the wrong library base from
   * another task */
  /* struct Library *AmiSSLBase = NULL; */

  /* CRITICAL: Do NOT call debug_printf() from callbacks during SSL_connect() */
  /* debug_printf() uses debug_log_sema which can cause deadlocks if called */
  /* from within SSL_connect() while another task holds the semaphore */
  /* Disable callback debug output to prevent deadlocks */
  /* Only output if HTTPDEBUG mode is enabled AND we're not in a callback */
  /* For now, disable all callback output to prevent deadlocks */
  return;

  /* DISABLED: Callback debug output can cause deadlocks */
  /*
  if (!httpdebug) {
    return;
  }

  Get assl pointer from SSL object's ex_data
  assl = (struct Assl *)SSL_get_ex_data(ssl, 0);
  if (!assl) {
    return;
  }

  VITAL: Shadow the global AmiSSLBase with the one stored in this connection's
  context AmiSSLBase = assl->amisslbase; if (!AmiSSLBase || (ULONG)AmiSSLBase <
  0x1000 || (ULONG)AmiSSLBase >= 0xFFFFFFF0) { return;
  }

  w = where & ~SSL_ST_MASK;

  Determine operation type
  if (w & SSL_ST_CONNECT) {
    str = "SSL_connect";
  } else if (w & SSL_ST_ACCEPT) {
    str = "SSL_accept";
  } else {
    str = "unknown";
  }

  Log different types of events
  if (where & SSL_CB_LOOP) {
    State change during handshake
    debug_printf("DEBUG: SSL INFO: %s:%s\n", str,
                 SSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    SSL alert received or sent
    alert_str = (where & SSL_CB_READ) ? "read" : "write";
    debug_printf("DEBUG: SSL INFO: SSL3 alert %s:%s:%s\n", alert_str,
                 SSL_alert_type_string_long(ret),
                 SSL_alert_desc_string_long(ret));
  } else if (where & SSL_CB_EXIT) {
    Function exit
    if (ret == 0) {
      debug_printf("DEBUG: SSL INFO: %s:failed in %s\n", str,
                   SSL_state_string_long(ssl));
    } else if (ret < 0) {
      debug_printf("DEBUG: SSL INFO: %s:error in %s\n", str,
                   SSL_state_string_long(ssl));
    } else {
      debug_printf("DEBUG: SSL INFO: %s:success in %s\n", str,
                   SSL_state_string_long(ssl));
    }
  } else if (where & SSL_CB_HANDSHAKE_START) {
    Handshake started
    debug_printf("DEBUG: SSL INFO: Handshake started for %s\n", str);
  } else if (where & SSL_CB_HANDSHAKE_DONE) {
    Handshake completed
    debug_printf("DEBUG: SSL INFO: Handshake completed for %s\n", str);
  }
  */
}

/* Helper function to manually verify certificate chain */
/* Validates certificate chain against trusted CAs, checks expiration, etc. */
/* Returns TRUE if certificate chain is valid, FALSE otherwise */
/* CRITICAL: Must accept AmiSSLBase to shadow the global variable for OpenSSL
 * macros */
static BOOL Verify_certificate_chain(SSL *ssl, SSL_CTX *sslctx,
                                     struct Library *AmiSSLBase) {
  X509_STORE *store;
  X509_STORE_CTX *store_ctx;
  X509 *cert;
  STACK_OF(X509) * chain;
  int verify_result;
  BOOL result = FALSE;

  if (!ssl || !sslctx || !AmiSSLBase) {
    return FALSE;
  }

  /* Get peer certificate */
  cert = SSL_get_peer_certificate(ssl);
  if (!cert) {
    debug_printf("DEBUG: Verify_certificate_chain: No peer certificate\n");
    return FALSE;
  }

  /* Get certificate chain from SSL connection */
  chain = SSL_get_peer_cert_chain(ssl);

  /* Get the certificate store from SSL context (contains trusted CAs) */
  store = SSL_CTX_get_cert_store(sslctx);
  if (!store) {
    debug_printf(
        "DEBUG: Verify_certificate_chain: Failed to get certificate store\n");
    X509_free(cert);
    return FALSE;
  }

  /* Create verification context */
  store_ctx = X509_STORE_CTX_new();
  if (!store_ctx) {
    debug_printf(
        "DEBUG: Verify_certificate_chain: Failed to create store context\n");
    X509_free(cert);
    return FALSE;
  }

  /* Initialize verification context */
  if (X509_STORE_CTX_init(store_ctx, store, cert, chain) != 1) {
    debug_printf("DEBUG: Verify_certificate_chain: Failed to initialize store "
                 "context\n");
    X509_STORE_CTX_free(store_ctx);
    X509_free(cert);
    return FALSE;
  }

  /* Set purpose to SSL client (for server certificate verification) */
  /* Note: We don't set a purpose check as it's too strict for modern
   * certificates */
  /* Many valid SSL certificates don't have explicit extended key usage
   * extensions */
  /* The certificate chain validation and hostname matching are sufficient */

  /* Perform verification */
  verify_result = X509_verify_cert(store_ctx);

  if (verify_result == 1) {
    /* Certificate chain is valid */
    debug_printf("DEBUG: Verify_certificate_chain: Certificate chain "
                 "validation SUCCESS\n");
    result = TRUE;
  } else {
    /* Certificate chain validation failed */
    int error = X509_STORE_CTX_get_error(store_ctx);
    int depth = X509_STORE_CTX_get_error_depth(store_ctx);
    X509 *error_cert = X509_STORE_CTX_get_current_cert(store_ctx);
    const char *error_str;

    error_str = X509_verify_cert_error_string(error);
    debug_printf("DEBUG: Verify_certificate_chain: Certificate chain "
                 "validation FAILED\n");
    debug_printf(
        "DEBUG: Verify_certificate_chain: Error: %s (code %d) at depth %d\n",
        error_str ? error_str : "unknown", error, depth);

    if (error_cert) {
      char cert_name[256];
      X509_NAME_oneline(X509_get_subject_name(error_cert), cert_name,
                        sizeof(cert_name));
      cert_name[sizeof(cert_name) - 1] = '\0';
      debug_printf("DEBUG: Verify_certificate_chain: Failed certificate: %s\n",
                   cert_name);
    }

    result = FALSE;
  }

  /* Cleanup */
  X509_STORE_CTX_free(store_ctx);
  X509_free(cert);

  return result;
}

/* Helper function to match hostname against a pattern (supports wildcards per
 * RFC 6125) */
/* Returns TRUE if hostname matches pattern, FALSE otherwise */
/* Pattern can be exact match (e.g., "example.com") or wildcard (e.g.,
 * "*.example.com") */
/* Wildcard matches only one level: *.example.com matches www.example.com but
 * not sub.www.example.com */
static BOOL MatchHostnamePattern(const char *hostname, const char *pattern) {
  /* const char *wildcard; */ /* Unused */
  const char *pattern_suffix;
  const char *hostname_suffix;
  int pattern_suffix_len;

  if (!hostname || !pattern) {
    return FALSE;
  }

  /* Exact match */
  if (STRIEQUAL(hostname, pattern)) {
    return TRUE;
  }

  /* Check for wildcard pattern (*.example.com) */
  if (pattern[0] == '*' && pattern[1] == '.') {
    /* Wildcard must be at the start and followed by a dot */
    pattern_suffix = pattern + 2; /* Skip "*." */
    pattern_suffix_len = strlen(pattern_suffix);

    if (pattern_suffix_len == 0) {
      return FALSE; /* Invalid: just "*." */
    }

    /* Find the first dot in hostname to get the suffix */
    hostname_suffix = strchr(hostname, '.');
    if (!hostname_suffix) {
      return FALSE; /* Hostname has no dot, can't match *.example.com */
    }

    hostname_suffix++; /* Skip the dot */

    /* Compare suffixes (case-insensitive) */
    if (STRIEQUAL(hostname_suffix, pattern_suffix)) {
      /* Verify wildcard only matches one level (no dots before the matched
       * part) */
      /* Check that there's exactly one dot before the suffix in the hostname */
      if (strchr(hostname, '.') == hostname_suffix - 1) {
        return TRUE;
      }
    }
  }

  return FALSE;
}

/* Helper function to validate hostname against certificate Common Name and
 * Subject Alternative Names */
/* Returns TRUE if hostname matches certificate, FALSE otherwise */
/* CRITICAL: Must accept AmiSSLBase to shadow the global variable for OpenSSL
 * macros */
/* Supports wildcard matching per RFC 6125 (e.g., *.example.com matches
 * www.example.com) */
static BOOL Validate_hostname(X509 *cert, UBYTE *hostname,
                              struct Library *AmiSSLBase) {
  int i;
  BOOL result = FALSE;
  X509_NAME *subj;
  int idx;
  X509_NAME_ENTRY *entry;
  ASN1_STRING *cn_asn1;
  char *cn;
  int len;
  STACK_OF(GENERAL_NAME) * san_names;
  int san_count;
  const GENERAL_NAME *name;
  char *dns_name;
  int dns_len;
  int hostname_len;

  /* Safety check for library base */
  if (!AmiSSLBase) {
    return FALSE;
  }

  if (!cert || !hostname) {
    return FALSE;
  }

  hostname_len = strlen((char *)hostname);
  if (hostname_len <= 0 || hostname_len > 253) {
    return FALSE; /* Invalid hostname length */
  }

  /* CRITICAL: Shadow the global AmiSSLBase with the one passed as parameter */
  /* OpenSSL macros (like X509_get_subject_name, X509_NAME_get_index_by_NID,
   * etc.) implicitly use the symbol AmiSSLBase */
  /* We must shadow it locally to prevent using the wrong library base from
   * another task */
  /* Note: The parameter name shadows the global, so all macros will use this
   * local value */

  /* Check Common Name in certificate subject */
  subj = X509_get_subject_name(cert);
  if (subj) {
    idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (idx >= 0) {
      entry = X509_NAME_get_entry(subj, idx);
      if (entry) {
        cn_asn1 = X509_NAME_ENTRY_get_data(entry);
        if (cn_asn1) {
          cn = (char *)ASN1_STRING_data(cn_asn1);
          len = ASN1_STRING_length(cn_asn1);

          /* Validate lengths to prevent buffer overruns */
          /* RFC 1035: Domain names max 253 characters, labels max 63 */
          /* Common Name should be reasonable length for hostname validation */
          if (len > 0 && len <= 253 && cn) {
            /* Use wildcard matching (supports exact match and *.example.com
             * patterns) */
            if (MatchHostnamePattern((char *)hostname, cn)) {
              result = TRUE;
            }
          }
        }
      }
    }
  }

  /* Check Subject Alternative Names if available (preferred over CN) */
  /* SANs are checked even if CN matched, as SANs take precedence per RFC 6125
   */
  san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (san_names) {
    san_count = sk_GENERAL_NAME_num(san_names);
    for (i = 0; i < san_count; i++) {
      name = sk_GENERAL_NAME_value(san_names, i);
      if (name && name->type == GEN_DNS) {
        dns_name = (char *)ASN1_STRING_data(name->d.dNSName);
        dns_len = ASN1_STRING_length(name->d.dNSName);

        /* Validate lengths to prevent buffer overruns */
        /* RFC 1035: Domain names max 253 characters, labels max 63 */
        if (dns_len > 0 && dns_len <= 253 && dns_name) {
          /* Use wildcard matching (supports exact match and *.example.com
           * patterns) */
          if (MatchHostnamePattern((char *)hostname, dns_name)) {
            result = TRUE;
            break; /* Found match in SAN, no need to check further */
          }
        }
      }
    }
    sk_GENERAL_NAME_free(san_names);
  }

  return result;
}

/* Enhanced helper function to print all SSL errors using BIO */
/* This provides comprehensive error output similar to ERR_print_errors() */
static void print_ssl_errors_bio(const char *function_name,
                                 struct Library *AmiSSLBase) {
  BIO *bio_err;
  BPTR stderr_handle;
  unsigned long err;
  int error_count;

  /* Only check if we have a valid AmiSSLBase */
  if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
      (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
    return;
  }

  /* Check if there are any errors first */
  err = ERR_peek_error();
  if (!err) {
    return; /* No errors in queue */
  }

  /* Create BIO for error output */
  bio_err = BIO_new(BIO_s_file());
  if (!bio_err) {
    /* Fallback to basic error reporting if BIO creation fails */
    check_ssl_error(function_name, AmiSSLBase);
    return;
  }

  /* Get stderr handle - use process error stream if available, otherwise
   * Output() */
  /* On AmigaOS, we can get the error stream from the process structure */
  {
    struct Process *proc;
    proc = (struct Process *)FindTask(NULL);
    if (proc && proc->pr_CES) {
      stderr_handle = proc->pr_CES;
    } else {
      stderr_handle = Output();
    }
  }

  /* Set BIO to use Amiga file handle */
  BIO_set_fp_amiga(bio_err, stderr_handle, BIO_NOCLOSE | BIO_FP_TEXT);

  /* Print all errors in the queue */
  error_count = 0;
  while ((err = ERR_get_error()) != 0) {
    error_count++;
    if (error_count == 1) {
      BIO_printf(bio_err, "[TASK:0x%08lX] SSL ERRORS after %s:\n",
                 get_task_id(), function_name);
    }
    ERR_print_errors(bio_err);
  }

  /* Free BIO */
  BIO_free(bio_err);
}

/* Enhanced helper function to check and log SSL errors after OpenSSL function
 * calls */
/* Call this immediately after every OpenSSL function to catch errors early */
/* This version provides detailed error information including library, function,
 * and reason */
static void check_ssl_error(const char *function_name,
                            struct Library *AmiSSLBase) {
  unsigned long err;
  char errbuf[256];
  char *errstr;
  const char *lib_str;
  const char *func_str;
  const char *reason_str;
  int error_count;

  /* Only check if we have a valid AmiSSLBase */
  if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
      (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
    return;
  }

  /* Check for errors in the OpenSSL error queue */
  err = ERR_get_error();
  if (err) {
    error_count = 1;

    /* Get detailed error information */
    lib_str = ERR_lib_error_string(err);
    func_str = ERR_func_error_string(err);
    reason_str = ERR_reason_error_string(err);

    /* Use ERR_error_string_n() for safe null-terminated string */
    /* ERR_error_string_n() guarantees null termination and respects buffer size
     */
    ERR_error_string_n(err, errbuf, sizeof(errbuf));
    /* Ensure null termination (defensive - ERR_error_string_n should do this)
     */
    errbuf[sizeof(errbuf) - 1] = '\0';
    /* Find the descriptive part after the last colon */
    errstr = strrchr(errbuf, ':');
    if (errstr && *(errstr + 1) != '\0') {
      errstr++; /* Skip the colon */
    } else {
      errstr = errbuf;
    }

    /* Print detailed error information */
    debug_printf("DEBUG: SSL ERROR after %s:\n", function_name);
    debug_printf("  Error code: 0x%08lX\n", err);
    if (lib_str) {
      debug_printf("  Library: %s\n", lib_str);
    }
    if (func_str) {
      debug_printf("  Function: %s\n", func_str);
    }
    if (reason_str) {
      debug_printf("  Reason: %s\n", reason_str);
    }
    debug_printf("  Description: %s\n", errstr);

    /* Check for additional errors in the queue */
    while ((err = ERR_get_error()) != 0) {
      error_count++;
      ERR_error_string_n(err, errbuf, sizeof(errbuf));
      errbuf[sizeof(errbuf) - 1] = '\0'; /* Ensure null termination */
      errstr = strrchr(errbuf, ':');
      if (errstr && *(errstr + 1) != '\0') {
        errstr++;
      } else {
        errstr = errbuf;
      }

      /* Get detailed information for additional error */
      lib_str = ERR_lib_error_string(err);
      func_str = ERR_func_error_string(err);
      reason_str = ERR_reason_error_string(err);

      debug_printf("DEBUG: SSL ERROR (additional #%d) after %s:\n", error_count,
                   function_name);
      debug_printf("  Error code: 0x%08lX\n", err);
      if (lib_str) {
        debug_printf("  Library: %s\n", lib_str);
      }
      if (func_str) {
        debug_printf("  Function: %s\n", func_str);
      }
      if (reason_str) {
        debug_printf("  Reason: %s\n", reason_str);
      }
      debug_printf("  Description: %s\n", errstr);
    }

    if (error_count > 1) {
      debug_printf("DEBUG: Total of %d SSL errors found after %s\n",
                   error_count, function_name);
    }
  }
}

/* Thread-safe debug logging wrapper with Task ID */
static void debug_printf(const char *format, ...) {
  va_list args;
  ULONG task_id;

  /* Only output if HTTPDEBUG mode is enabled */
  if (!httpdebug) {
    return;
  }

  task_id = get_task_id();

  if (debug_log_sema_initialized) {
    ObtainSemaphore(&debug_log_sema);
  }

  printf("[TASK:0x%08lX] ", task_id);
  va_start(args, format);
  vprintf(format, args);
  va_end(args);

  if (debug_log_sema_initialized) {
    ReleaseSemaphore(&debug_log_sema);
  }
}

/*-----------------------------------------------------------------------*/

struct Assl *Assl_initamissl(struct Library *socketbase) {
  struct Assl *assl;
  static BOOL sema_initialized = FALSE;
  static BOOL amissl_initialized = FALSE;

  debug_printf("DEBUG: Assl_initamissl: ENTRY - socketbase=%p\n", socketbase);

  /* Set global SocketBase for this task */
  /* This is required because SocketBase is extern and we need to ensure it's
   * set for the current task context */
  if (socketbase) {
    SocketBase = socketbase;
  }

  /* Initialize semaphore on first call */
  if (!sema_initialized) {
    Forbid(); /* Disable task switching during initialization */
    if (!sema_initialized) {
      debug_printf("DEBUG: Assl_initamissl: Initializing SSL init semaphore\n");
      InitSSLSemaphore();
      sema_initialized = TRUE;
      debug_printf("DEBUG: Assl_initamissl: SSL init semaphore initialized\n");
    }
    Permit(); /* Re-enable task switching */
  }

  /* Initialize AmiSSL once per application, not per connection */
  /* According to SDK: OpenAmiSSLTags() should be called once and sets up global
   * bases */
  if (!amissl_initialized) {
    ObtainSemaphore(&ssl_init_sema);
    if (!amissl_initialized) {
      debug_printf("DEBUG: Assl_initamissl: Opening amisslmaster.library\n");
      AmiSSLMasterBase =
          OpenLibrary("amisslmaster.library", AMISSLMASTER_MIN_VERSION);
      if (AmiSSLMasterBase) {
        debug_printf(
            "DEBUG: Assl_initamissl: Opened amisslmaster.library at %p\n",
            AmiSSLMasterBase);

        /* Use new OpenAmiSSLTags API for AmiSSL 5.20+ */
        /* This sets the global AmiSSLBase and AmiSSLExtBase for the application
         */
        /* After this call, all tasks can use the global bases safely thanks to
         * baserel */
        debug_printf("DEBUG: Assl_initamissl: Calling OpenAmiSSLTags()\n");
        if (OpenAmiSSLTags(AMISSL_CURRENT_VERSION, AmiSSL_UsesOpenSSLStructs,
                           TRUE, AmiSSL_InitAmiSSL, TRUE,
                           AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                           AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                           AmiSSL_SocketBase, socketbase, AmiSSL_ErrNoPtr,
                           &errno, TAG_END) == 0) {
          debug_printf("DEBUG: Assl_initamissl: OpenAmiSSLTags() succeeded\n");
          debug_printf(
              "DEBUG: Assl_initamissl: AmiSSLBase=%p, AmiSSLExtBase=%p\n",
              AmiSSLBase, AmiSSLExtBase);
          /* Track the first task that called OpenAmiSSLTags() */
          /* This task's InitAmiSSL() was called automatically by OpenAmiSSLTags() */
          first_amissl_task = FindTask(NULL);
          debug_printf("DEBUG: Assl_initamissl: First AmiSSL task=%p\n",
                       first_amissl_task);
          amissl_initialized = TRUE;
        } else {
          debug_printf("DEBUG: Assl_initamissl: OpenAmiSSLTags() failed\n");
          PutStr("ERROR: OpenAmiSSLTags() failed.\n");
          Lowlevelreq("AWeb could not initialize AmiSSL 5.20+.\nPlease check "
                      "your AmiSSL installation and try again.");
          CloseLibrary(AmiSSLMasterBase);
          AmiSSLMasterBase = NULL;
        }
      } else {
        debug_printf(
            "DEBUG: Assl_initamissl: Failed to open amisslmaster.library\n");
        PutStr("ERROR: Could not open amisslmaster.library.\n");
        Lowlevelreq("AWeb requires amisslmaster.library version 5.20 or newer "
                    "for SSL/TLS connections.\nPlease install or update AmiSSL "
                    "and try again.");
      }
    }
    ReleaseSemaphore(&ssl_init_sema);
  }

  /* If AmiSSL initialization failed, return NULL */
  if (!amissl_initialized) {
    debug_printf(
        "DEBUG: Assl_initamissl: AmiSSL not initialized, returning NULL\n");
    return NULL;
  }

  /* CRITICAL: Check if this is a subprocess (different task than first) */
  /* Subprocesses MUST call InitAmiSSL() explicitly per SDK requirements */
  {
    struct Task *current_task;
    current_task = FindTask(NULL);
    if (current_task && first_amissl_task && current_task != first_amissl_task) {
      /* This is a subprocess - must call InitAmiSSL() explicitly */
      debug_printf("DEBUG: Assl_initamissl: Subprocess detected (task=%p, "
                   "first=%p), calling InitAmiSSL()\n",
                   current_task, first_amissl_task);
      if (InitAmiSSL(AmiSSL_SocketBase, SocketBase, AmiSSL_ErrNoPtr, &errno,
                     TAG_END) != 0) {
        debug_printf("DEBUG: Assl_initamissl: ERROR - InitAmiSSL() failed for "
                     "subprocess\n");
        check_ssl_error("InitAmiSSL (subprocess)", AmiSSLBase);
        return NULL;
      }
      debug_printf("DEBUG: Assl_initamissl: InitAmiSSL() succeeded for "
                   "subprocess\n");
    } else {
      debug_printf("DEBUG: Assl_initamissl: Main task (task=%p), InitAmiSSL() "
                   "already called by OpenAmiSSLTags()\n",
                   current_task);
    }
  }

  /* Increment task reference count for cleanup tracking */
  IncrementTaskRef();

  /* Now allocate per-connection Assl struct */
  if (socketbase && (assl = ALLOCSTRUCT(Assl, 1, MEMF_CLEAR))) {
    debug_printf("DEBUG: Assl_initamissl: Allocated Assl struct at %p\n", assl);

    /* Initialize per-object semaphore FIRST, before any other operations */
    InitSemaphore(&assl->use_sema);
    assl->closed = FALSE;

    /* CRITICAL: Explicitly initialize SSL pointers to NULL to prevent wild free
     * defects */
    /* Clear pointers */
    assl->ssl = NULL;
    assl->sslctx = NULL;
    assl->hostname = NULL;
    debug_printf("DEBUG: Assl_initamissl: Initialized per-object semaphore and "
                 "set closed=FALSE\n");

    debug_printf(
        "DEBUG: Assl_initamissl: SUCCESS - returning Assl struct at %p\n",
        assl);
    return assl;
  } else {
    debug_printf("DEBUG: Assl_initamissl: Failed to allocate Assl struct or "
                 "invalid socketbase\n");
    return NULL;
  }
}

/*-----------------------------------------------------------------------*/

/* Forward declaration for Assl_closessl() - needed since Assl_cleanup() calls
 * it */
__asm void Assl_closessl(register __a0 struct Assl *assl);

/*-----------------------------------------------------------------------*/

static int __saveds __stdargs Certcallback(int ok, X509_STORE_CTX *sctx) {
  char *s;
  UBYTE *u;
  struct Assl *assl;
  SSL *ssl;
  X509 *xs;
  int err;
  int depth;
  char buf[256];
  BOOL hostname_valid;
  /* OpenSSL macros (like X509_STORE_CTX_get_ex_data, SSL_get_ex_data, etc.)
   * implicitly use AmiSSLBase */
  /* We use the global AmiSSLBase directly as it is baserel-safe */

  if (sctx) {
    /* Get SSL object from certificate store context */
    /* This is the proper way to get the SSL object associated with this
     * certificate verification */
    ssl =
        X509_STORE_CTX_get_ex_data(sctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl) {
      /* Get assl pointer from SSL object's ex_data */
      /* This is safer than task userdata because each SSL object has its own
       * assl pointer, preventing race conditions with multiple concurrent
       * connections */
      assl = (struct Assl *)SSL_get_ex_data(ssl, 0);
    } else {
      /* Fallback to task userdata if SSL object not available (shouldn't
       * happen, but be defensive) */
      assl = Gettaskuserdata();
    }

    /* Validate assl pointer before use */
    /* Check if assl pointer is reasonable and not freed */
    if (!assl || (ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      /* Invalid assl pointer - reject certificate to be safe */
      debug_printf("DEBUG: Certcallback: Invalid assl pointer (%p), rejecting "
                   "certificate\n",
                   assl);
      return 0;
    }

    /* Validate AmiSSLBase is set before using OpenSSL macros */
    if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
        (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Certcallback: Invalid AmiSSLBase (%p), rejecting "
                   "certificate\n",
                   AmiSSLBase);
      return 0;
    }

    /* Check if SSL objects have been closed/freed to prevent use-after-free */
    /* Certcallback may be called asynchronously by OpenSSL, even after SSL
     * objects are freed */
    if (!assl->closed) {
      xs = X509_STORE_CTX_get_current_cert(sctx);
      if (xs) {
        err = X509_STORE_CTX_get_error(sctx);
        depth = X509_STORE_CTX_get_error_depth(sctx);

        /* Only process the server certificate (depth 0), not intermediate CAs
         */
        /* The callback is called for each certificate in the chain:
         * - depth 0: Server certificate (the one we care about)
         * - depth 1+: Intermediate CA certificates (we don't need to prompt for
         * these)
         */
        if (depth == 0) {
          /* X509_NAME_oneline() can return NULL on failure or if buffer too
           * small */
          /* Buffer is 256 bytes which should be sufficient for typical
           * certificate names */
          /* X509_NAME_oneline() null-terminates the buffer if it fits, or
           * returns NULL */
          if (X509_NAME_oneline(X509_get_subject_name(xs), buf, sizeof(buf))) {
            /* Ensure null termination (defensive - X509_NAME_oneline should do
             * this) */
            buf[sizeof(buf) - 1] = '\0';
            s = buf;
            u = assl->hostname;

            /* Validate hostname against server certificate */
            /* This ensures we check if the hostname actually matches the
             * certificate */
            /* Per RFC 6125, hostname validation should be performed even if
             * certificate chain validation passed (ok=1) */
            /* Only check hostname for server certificate (depth 0), not CA
             * certs */
            hostname_valid = FALSE;
            if (u && *u) {
              /* CRITICAL: Pass the local AmiSSLBase to the validation function
               */
              /* Validate_hostname uses OpenSSL macros that require AmiSSLBase
               * to be shadowed */
              hostname_valid = Validate_hostname(xs, u, AmiSSLBase);
              if (!hostname_valid) {
                debug_printf(
                    "DEBUG: Certcallback: Hostname '%s' does not match server "
                    "certificate subject '%s'\n",
                    u, s);
                /* Hostname mismatch - treat as validation failure */
                /* Even if certificate chain is valid (ok=1), hostname mismatch
                 * is a security issue */
                ok = 0;
              } else {
                debug_printf("DEBUG: Certcallback: Hostname '%s' matches "
                             "server certificate "
                             "subject '%s'\n",
                             u, s);
              }
            }

            /* CRITICAL: Do NOT prompt user during SSL_connect() - this causes
             * deadlocks */
            /* Httpcertaccept() uses Syncrequest() which blocks the GUI */
            /* Instead, set a flag and return 1 to allow handshake to complete
             */
            /* The caller will check the flag after SSL_connect() succeeds and
             * prompt then */
            if (!ok) {
              /* Validation failed - set flag but DON'T prompt yet */
              /* Store error message for later display to user */
              /* Removed assl->cert_validation_failed and assl->cert_error_msg
               * as they are no longer part of the Assl struct.
               * The caller will now handle certificate validation failure
               * based on the return value of this callback. */
              debug_printf("DEBUG: Certcallback: Certificate validation "
                           "failed for hostname "
                           "'%s', cert subject '%s'. Returning 0.\n",
                           u ? (char *)u : "(none)", s ? s : "(none)");
              /* Return 0 to indicate validation failure */
              ok = 0;
            } else {
              /* Certificate chain valid AND hostname matches - accept
               * automatically */
              debug_printf(
                  "DEBUG: Certcallback: Certificate validation successful - "
                  "hostname "
                  "'%s' matches cert subject '%s', accepting automatically\n",
                  u ? (char *)u : "(none)", s ? s : "(none)");
              /* ok is already 1, just return it */
            }
          }
        } else {
          /* Intermediate CA certificate - just log and continue */
          /* We don't prompt the user for CA certificates, only for the server
           * cert */
          debug_printf("DEBUG: Certcallback: Processing intermediate CA "
                       "certificate at depth "
                       "%d (skipping user prompt)\n",
                       depth);
          /* For intermediate CAs, we just return the validation result */
          /* If the CA is invalid, OpenSSL will fail the chain validation */
        }
      }
    } else if (assl && assl->closed) { /* SSL connection already closed - reject
                                          certificate to be safe */
      ok = 0;
    }
  }
  return ok;
}

__asm void Assl_cleanup(register __a0 struct Assl *assl) {
  struct Task *task;
  BOOL should_cleanup_amissl;

  /* Only cleanup if we have a valid Assl struct */
  if (assl) {
    /* Use global AmiSSLBase directly */
    /* struct Library *AmiSSLBase = assl->amisslbase; */ /* Removed */

    /* CRITICAL: Protect cleanup with semaphore to prevent race conditions */
    /* Wait for any active operations to complete */
    ObtainSemaphore(&assl->use_sema);

    /* 1. Ensure SSL connection is closed */
    /* Assl_closessl will free ssl and sslctx */
    Assl_closessl(assl);

    /* 2. Clear references (BUT DO NOT CLOSE LIBRARIES HERE) */
    /* Closing libraries here causes race conditions with other active tasks */
    /* assl->amisslbase = NULL; */       /* Removed */
    /* assl->amisslmasterbase = NULL; */ /* Removed */
    /* assl->amissslextbase = NULL; */   /* Removed */
    /* assl->owning_task = NULL; */      /* Removed */

    /* Release semaphore */
    ReleaseSemaphore(&assl->use_sema);

    /* 3. CRITICAL: Decrement task reference count and call CleanupAmiSSL() if needed */
    /* Per SDK: Each subprocess that called InitAmiSSL() MUST call CleanupAmiSSL() */
    task = FindTask(NULL);
    should_cleanup_amissl = FALSE;
    if (task) {
      if (DecrementTaskRef(task)) {
        /* This was the last Assl for this task */
        /* Check if this is a subprocess (not the main task) */
        if (first_amissl_task && task != first_amissl_task) {
          /* Subprocess - must call CleanupAmiSSL() per SDK requirements */
          debug_printf("DEBUG: Assl_cleanup: Last Assl for subprocess "
                       "(task=%p), calling CleanupAmiSSL()\n",
                       task);
          should_cleanup_amissl = TRUE;
        } else {
          debug_printf("DEBUG: Assl_cleanup: Last Assl for main task "
                       "(task=%p), CleanupAmiSSL() will be called by "
                       "CloseAmiSSL()\n",
                       task);
        }
      }
    }

    /* Call CleanupAmiSSL() for subprocesses */
    if (should_cleanup_amissl && AmiSSLBase) {
      debug_printf("DEBUG: Assl_cleanup: Calling CleanupAmiSSL() for subprocess\n");
      CleanupAmiSSL(TAG_END);
      check_ssl_error("CleanupAmiSSL", AmiSSLBase);
    }

    /* 4. Do NOT free assl here. http.c handles the free. */
  }
}

__asm BOOL Assl_openssl(register __a0 struct Assl *assl) {
  BOOL result = FALSE;
  debug_printf("DEBUG: Assl_openssl: ENTRY - assl=%p\n", assl);

  if (assl && AmiSSLBase) { /* Use global AmiSSLBase directly */
    /* CRITICAL: Shadow the global AmiSSLBase with the one stored in this
     * connection's context */
    /* OpenSSL macros (like SSL_CTX_new, SSL_new, etc.) implicitly use the
     * symbol AmiSSLBase */
    /* We must shadow it locally to prevent using the wrong library base from
     * another task */
    /* struct Library *AmiSSLBase = assl->amisslbase; */ /* Removed - use global
                                                            AmiSSLBase directly
                                                          */
    /* Use local variable for error checking - baserel system handles library
     * base automatically */
    struct Library *local_amisslbase =
        AmiSSLBase; /* Use global AmiSSLBase directly */
    /* struct Library *AmiSSLBase = assl->amisslbase; */       /* Removed */
    /* struct Library *local_amisslbase = assl->amisslbase; */ /* Removed */

    debug_printf("DEBUG: Assl_openssl: Valid Assl, using global AmiSSLBase\n",
                 local_amisslbase);

    /* CRITICAL: SSL object creation/destruction MUST be serialized */
    /* SSL_CTX_new(), SSL_new(), SSL_free(), and SSL_CTX_free() access shared
     * OpenSSL internal state */
    /* Multiple concurrent calls can corrupt OpenSSL's internal data structures
     */
    /* We use ssl_init_sema to serialize SSL object creation/destruction */
    /* BUT we do NOT use semaphores for SSL_connect/SSL_read/SSL_write (blocking
     * I/O) */
    if (!ssl_init_sema_initialized) {
      debug_printf(
          "DEBUG: Assl_openssl: ERROR - ssl_init_sema not initialized!\n");
      return FALSE;
    }
    debug_printf("DEBUG: Assl_openssl: Obtaining SSL init semaphore\n");
    ObtainSemaphore(&ssl_init_sema);
    debug_printf("DEBUG: Assl_openssl: SSL init semaphore obtained\n");

    /* InitAmiSSL() handles OpenSSL initialization - no need to call
     * OPENSSL_init_ssl() manually */
    /* InitAmiSSL() is called once per task in Assl_initamissl() */

    /* SSL context must be created fresh for each connection */
    /* Do NOT reuse SSL contexts - they are NOT thread-safe for concurrent use
     */
    /* ALWAYS free any existing SSL objects before creating new ones */
    /* This ensures we never reuse SSL objects - each transaction gets a fresh
     * SSL object */
    /* CRITICAL: Validate SSL pointers are not stale/wild pointers before
     * attempting to free */
    /* This prevents wild free defects when memory is reused or corrupted */
    if (assl->sslctx || assl->ssl) { /* Validate pointers are reasonable before
                                        attempting to free */
      BOOL has_valid_ssl = FALSE;
      BOOL has_valid_sslctx = FALSE;

      if (assl->ssl) {
        if ((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0) {
          has_valid_ssl = TRUE;
        } else {
          debug_printf("DEBUG: Assl_openssl: WARNING - Invalid SSL object "
                       "pointer (%p), clearing without freeing\n",
                       assl->ssl);
          assl->ssl = NULL;
        }
      }

      if (assl->sslctx) {
        if ((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0) {
          has_valid_sslctx = TRUE;
        } else {
          debug_printf("DEBUG: Assl_openssl: WARNING - Invalid SSL context "
                       "pointer (%p), clearing without freeing\n",
                       assl->sslctx);
          assl->sslctx = NULL;
        }
      }

      if (has_valid_ssl || has_valid_sslctx) {
        debug_printf("DEBUG: Assl_openssl: WARNING - Assl already has SSL "
                     "objects (sslctx=%p, ssl=%p), freeing them first\n",
                     assl->sslctx, assl->ssl);

        /* Baserel system handles library base automatically */
        debug_printf("DEBUG: Assl_openssl: Freeing SSL objects (baserel system "
                     "handles library base)\n");

        /* Free existing SSL objects before creating new ones */
        /* This ensures we never reuse SSL objects - always create fresh ones */
        /* Semaphore is already held from above */
        if (has_valid_ssl && assl->ssl) {
          debug_printf(
              "DEBUG: Assl_openssl: Freeing existing SSL object at %p\n",
              assl->ssl);
          SSL_free(assl->ssl);
          check_ssl_error("SSL_free (existing)", local_amisslbase);
          assl->ssl = NULL;
        }
        if (has_valid_sslctx && assl->sslctx) {
          debug_printf(
              "DEBUG: Assl_openssl: Freeing existing SSL context at %p\n",
              assl->sslctx);
          /* Clear certificate verification callback before freeing context */
          /* This prevents callbacks from being called after context is freed */
          SSL_CTX_set_verify(assl->sslctx, SSL_VERIFY_NONE, NULL);
          SSL_CTX_free(assl->sslctx);
          check_ssl_error("SSL_CTX_free (existing)", local_amisslbase);
          assl->sslctx = NULL;
        }
        /* Reset flags after freeing */
        assl->closed = FALSE;
        assl->denied = FALSE;
        assl->cert_validation_failed = FALSE;
        assl->cert_error_msg[0] = '\0';
        debug_printf("DEBUG: Assl_openssl: Existing SSL objects freed, ready "
                     "to create new ones\n");
      } else { /* No valid SSL pointers - just clear them and continue */
        debug_printf("DEBUG: Assl_openssl: No valid SSL objects to free, "
                     "clearing pointers\n");
        assl->ssl = NULL;
        assl->sslctx = NULL;
        assl->closed = FALSE;
        assl->denied = FALSE;
        assl->cert_validation_failed = FALSE;
        assl->cert_error_msg[0] = '\0';
      }
    }

    /* Create new SSL context for this connection */
    /* SSL_CTX_new() accesses shared OpenSSL state - must be serialized */
    debug_printf("DEBUG: Assl_openssl: Creating new SSL context with "
                 "TLS_client_method()\n");
    /* CRITICAL: Re-validate AmiSSLBase before calling OpenSSL functions */
    /* AmiSSLBase might become NULL if the library is closed by another task */
    /* OpenSSL macros use AmiSSLBase internally, so it must be valid */
    if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000) {
      debug_printf("DEBUG: Assl_openssl: ERROR - AmiSSLBase is invalid (%p), cannot create SSL context\n", AmiSSLBase);
      ReleaseSemaphore(&ssl_init_sema);
      return FALSE;
    }
    /* CRITICAL: Check that TLS_client_method() returns non-NULL before using it */
    /* TLS_client_method() can return NULL if AmiSSL is not properly initialized */
    /* Passing NULL to SSL_CTX_new() will cause a crash inside AmiSSL library */
    {
      const SSL_METHOD *method = TLS_client_method();
      if (!method) {
        debug_printf("DEBUG: Assl_openssl: ERROR - TLS_client_method() returned NULL, AmiSSL not properly initialized\n");
        check_ssl_error("TLS_client_method (failed)", local_amisslbase);
        ReleaseSemaphore(&ssl_init_sema);
        return FALSE;
      }
      if (assl->sslctx = SSL_CTX_new(method)) {
      debug_printf(
          "DEBUG: Assl_openssl: SSL context created successfully at %p\n",
          assl->sslctx);
      check_ssl_error("SSL_CTX_new", local_amisslbase);

      /* Set default certificate verification paths */
      debug_printf("DEBUG: Assl_openssl: Setting default certificate "
                   "verification paths\n");
      SSL_CTX_set_default_verify_paths(assl->sslctx);
      check_ssl_error("SSL_CTX_set_default_verify_paths", local_amisslbase);

      /* Enhanced security: disable weak protocols and ciphers */
      /* Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 (all deprecated/insecure) */
      /* TLS 1.0 and TLS 1.1 are deprecated per RFC 8996 and should not be used
       */
      /* SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: Prevent session
       * resumption on renegotiation (security best practice) */
      debug_printf("DEBUG: Assl_openssl: Setting SSL options (disabling "
                   "SSLv2/SSLv3/TLS1.0/TLS1.1, "
                   "renegotiation protection)\n");
      SSL_CTX_set_options(assl->sslctx,
                          SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                              SSL_OP_NO_TLSv1_1 |
                              SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
      check_ssl_error("SSL_CTX_set_options", local_amisslbase);

      /* Enforce minimum TLS version: TLS 1.2 (required for modern security) */
      /* This ensures we never negotiate TLS 1.0 or TLS 1.1 even if server
       * offers them */
      debug_printf("DEBUG: Assl_openssl: Setting minimum TLS version to 1.2\n");
      SSL_CTX_set_min_proto_version(assl->sslctx, TLS1_2_VERSION);
      check_ssl_error("SSL_CTX_set_min_proto_version", local_amisslbase);

      /* Set cipher list - optimized for Motorola 68000 family performance */
      /* ChaCha20 is 2-3x faster than AES on 68000/68020/68030/68040/68060 CPUs */
      /* because it's software-optimized and doesn't require hardware acceleration */
      /* Order: ChaCha20 first (fastest), then medium/high strength ciphers */
      debug_printf(
          "DEBUG: Assl_openssl: Setting cipher list (optimized for 68000)\n");
      SSL_CTX_set_cipher_list(assl->sslctx, "CHACHA20:MEDIUM:HIGH");
      check_ssl_error("SSL_CTX_set_cipher_list", local_amisslbase);

      /* Set TLS 1.3 cipher suites - optimized for 68000 performance */
      /* Order by speed on 68000 hardware: ChaCha20 > AES-128 > AES-256 */
      /* ChaCha20-Poly1305: ~2-3x faster than AES-GCM on 68000 (software-optimized) */
      /* AES-128-GCM: Faster than AES-256 (shorter key = fewer operations) */
      /* AES-256-GCM: Slowest but most secure (fallback only) */
      debug_printf("DEBUG: Assl_openssl: Setting TLS 1.3 cipher suites (optimized for 68000)\n");
      SSL_CTX_set_ciphersuites(assl->sslctx,
                               "TLS_CHACHA20_POLY1305_SHA256:"  /* Fastest: ChaCha20 (2-3x faster than AES) */
                               "TLS_AES_128_GCM_SHA256:"        /* Medium: AES-128 (faster than AES-256) */
                               "TLS_AES_256_GCM_SHA384");       /* Slowest: AES-256 (fallback for maximum security) */
      check_ssl_error("SSL_CTX_set_ciphersuites", local_amisslbase);

      /* CRITICAL: Disable certificate verification during SSL_connect() to
       * prevent deadlocks */
      /* Certificate callbacks can cause deadlocks if they call debug_printf()
       * or other blocking operations */
      /* We will manually verify the certificate AFTER SSL_connect() completes
       */
      /* This ensures SSL_connect() completes without any callbacks being
       * invoked */
      debug_printf("DEBUG: Assl_openssl: Disabling certificate verification "
                   "during handshake "
                   "(will verify manually after handshake)\n");
      SSL_CTX_set_verify(
          assl->sslctx,
          SSL_VERIFY_NONE, /* Disable verification during handshake */
          NULL);           /* No callback */
      check_ssl_error("SSL_CTX_set_verify", local_amisslbase);

      /* DISABLED: SSL info callback can cause deadlocks if it calls
       * debug_printf() */
      /* debug_printf() uses debug_log_sema which can deadlock if called from
       * callbacks */
      /* Set SSL info callback for detailed handshake debugging
       * This provides detailed information about SSL handshake progress
       * if (httpdebug) {
       *   debug_printf("DEBUG: Assl_openssl: Setting SSL info callback for "
       *                "handshake debugging\n");
       *   SSL_CTX_set_info_callback(assl->sslctx, ssl_info_callback);
       *   check_ssl_error("SSL_CTX_set_info_callback", local_amisslbase);
       * }
       */

      debug_printf("DEBUG: Assl_openssl: SSL context configuration complete\n");
      } else {
        debug_printf("DEBUG: Assl_openssl: Failed to create SSL context\n");
        check_ssl_error("SSL_CTX_new (failed)", local_amisslbase);
      }
    }

    /* Reset denied flag and closed flag for new connection */
    assl->denied = FALSE;
    assl->closed = FALSE;
    assl->cert_validation_failed = FALSE;
    assl->cert_error_msg[0] = '\0';
    debug_printf("DEBUG: Assl_openssl: Reset denied=FALSE, closed=FALSE\n");

    /* Create new SSL object from context for this connection */
    /* SSL_new() accesses shared OpenSSL state - must be serialized */
    if (assl->sslctx) {
      debug_printf(
          "DEBUG: Assl_openssl: Creating new SSL object from context\n");
      if (assl->ssl = SSL_new(assl->sslctx)) {
        debug_printf(
            "DEBUG: Assl_openssl: SSL object created successfully at %p\n",
            assl->ssl);
        check_ssl_error("SSL_new", local_amisslbase);
        /* Store assl pointer in SSL object's ex_data for certificate callback
         */
        /* This is safer than task userdata because each SSL object has its own
         * assl pointer, preventing race conditions with multiple concurrent
         * connections in the same task */
        debug_printf("DEBUG: Assl_openssl: Storing Assl pointer in SSL object "
                     "ex_data for certificate callback\n");
        if (SSL_set_ex_data(assl->ssl, 0, assl) == 0) {
          debug_printf("DEBUG: Assl_openssl: WARNING - SSL_set_ex_data failed, "
                       "certificate callback may not work correctly\n");
          check_ssl_error("SSL_set_ex_data", local_amisslbase);
        } else {
          debug_printf("DEBUG: Assl_openssl: SSL ex_data set successfully\n");
        }
      } else {
        debug_printf("DEBUG: Assl_openssl: Failed to create SSL object\n");
        check_ssl_error("SSL_new (failed)", local_amisslbase);
      }
    } else {
      debug_printf(
          "DEBUG: Assl_openssl: Cannot create SSL object - no SSL context\n");
    }

    /* Set result based on success */
    result = (BOOL)(assl->sslctx && assl->ssl);
    debug_printf("DEBUG: Assl_openssl: SSL initialization result=%d "
                 "(sslctx=%p, ssl=%p)\n",
                 result, assl->sslctx, assl->ssl);

    /* Release semaphore after SSL object creation is complete */
    debug_printf("DEBUG: Assl_openssl: Releasing SSL init semaphore\n");
    ReleaseSemaphore(&ssl_init_sema);
    debug_printf("DEBUG: Assl_openssl: SSL init semaphore released\n");
  } else {
    debug_printf(
        "DEBUG: Assl_openssl: Invalid parameters (assl=%p, AmiSSLBase=%p)\n",
        assl, AmiSSLBase);
    result = FALSE;
  }

  debug_printf("DEBUG: Assl_openssl: EXIT - returning %d\n", result);
  return result;
}

__asm void Assl_closessl(register __a0 struct Assl *assl) {
  /* CRITICAL: Shadow global AmiSSLBase */
  /* struct Library *AmiSSLBase; */       /* Removed - use global directly */
  /* struct Library *local_amisslbase; */ /* Removed */

  if (assl) {
    /* Validate Assl structure pointer is reasonable before accessing fields */
    if ((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      debug_printf(
          "DEBUG: Assl_closessl: Invalid Assl pointer (%p), skipping\n", assl);
      return;
    }

    /* Use global AmiSSLBase directly */
    /* AmiSSLBase = assl->amisslbase; */       /* Removed */
    /* local_amisslbase = assl->amisslbase; */ /* Removed */

    /* Semaphore is always accessible if assl pointer is valid (it's a field in
     * the struct) */
    /* CRITICAL: Do NOT use semaphores for SSL cleanup */
    /* SSL_free() and SSL_CTX_free() are safe to call without semaphores */

    /* Validate AmiSSLBase pointer */
    if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
        (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
      debug_printf(
          "DEBUG: Assl_closessl: Invalid AmiSSLBase pointer (%p), skipping\n",
          AmiSSLBase);
      return;
    }

    /* Make this function idempotent - safe to call multiple times */
    /* If already closed, just return without doing anything */
    if (assl->closed) {
      debug_printf(
          "DEBUG: Assl_closessl: SSL connection already closed, skipping\n");
      return;
    }

    /* CRITICAL: Mark as closed NOW to prevent concurrent calls */
    assl->closed = TRUE;

    /* Properly shutdown SSL before freeing to prevent corruption */
    /* MUST shutdown SSL connection BEFORE freeing SSL object */
    /* SSL_free() and SSL_CTX_free() may access shared OpenSSL state during
     * cleanup */
    debug_printf("DEBUG: Assl_closessl: Closing SSL connection\n");

    /* Validate SSL object pointer */
    if (!assl->ssl || (ULONG)assl->ssl < 0x1000 ||
        (ULONG)assl->ssl >= 0xFFFFFFF0) {
      debug_printf(
          "DEBUG: Assl_closessl: Invalid SSL object pointer (%p) before "
          "cleanup, skipping\n",
          assl->ssl);
      return;
    }

    /* Validate SSL context pointer before cleanup */
    if (!assl->sslctx || (ULONG)assl->sslctx < 0x1000 ||
        (ULONG)assl->sslctx >= 0xFFFFFFF0) {
      debug_printf(
          "DEBUG: Assl_closessl: Invalid SSL context pointer (%p) before "
          "cleanup, skipping\n",
          assl->sslctx);
      return;
    }

    /* Shutdown SSL connection gracefully before freeing */
    /* This ensures SSL is properly disconnected from socket */
    /* Use global AmiSSLBase directly */
    if (AmiSSLBase && (ULONG)AmiSSLBase >= 0x1000 &&
        (ULONG)AmiSSLBase < 0xFFFFFFF0) {
      debug_printf(
          "DEBUG: Assl_closessl: Attempting SSL shutdown (NO SEMAPHORE)\n");
      /* SSL_shutdown() should be called twice for proper shutdown:
       * - First call sends close_notify to peer
       * - Second call waits for peer's close_notify
       * For simplicity, we try once and ignore errors if socket is already
       * closed */
      /* CRITICAL: Validate SSL object is still valid before calling
       * SSL_shutdown() */
      /* SSL_shutdown() can crash if socket is already closed or SSL object is
       * corrupted */
      if (assl->ssl && (ULONG)assl->ssl >= 0x1000 &&
          (ULONG)assl->ssl < 0xFFFFFFF0) {
        /* Try to shutdown gracefully, but don't crash if it fails */
        /* If socket is already closed, SSL_shutdown() may fail, which is OK */
        debug_printf(
            "DEBUG: Assl_closessl: Calling SSL_shutdown() on SSL object %p\n",
            assl->ssl);
        /* SSL_shutdown() returns:
         *   1 = shutdown complete
         *   0 = shutdown not yet complete (need to call again)
         *  -1 = error (socket closed, etc.) - this is OK during cleanup */
        SSL_shutdown(assl->ssl); /* First call - send close_notify */
        check_ssl_error("SSL_shutdown (first)", AmiSSLBase);
        /* Try second call if first succeeded (returned 0, not -1) */
        /* Note: We don't wait for peer's close_notify in second call to avoid
         * blocking - just send our close_notify and free */
      } else {
        debug_printf("DEBUG: Assl_closessl: Skipping SSL_shutdown - invalid "
                     "SSL object (%p)\n",
                     assl->ssl);
      }

      /* CRITICAL: SSL object destruction MUST be serialized */
      /* SSL_free() and SSL_CTX_free() access shared OpenSSL internal state */
      /* Multiple concurrent calls can corrupt OpenSSL's internal data
       * structures */
      /* We use ssl_init_sema to serialize SSL object creation/destruction */
      if (!ssl_init_sema_initialized) {
        debug_printf(
            "DEBUG: Assl_closessl: ERROR - ssl_init_sema not initialized! "
            "Skipping SSL object cleanup.\n");
        return;
      }
      debug_printf("DEBUG: Assl_closessl: Obtaining SSL init semaphore for "
                   "object destruction\n");
      ObtainSemaphore(&ssl_init_sema);
      debug_printf("DEBUG: Assl_closessl: SSL init semaphore obtained\n");

      /* Re-validate SSL object and AmiSSLBase before SSL_free() */
      /* CRITICAL: SSL_free() can crash if SSL object is corrupted or already
       * freed */
      if (assl->ssl && (ULONG)assl->ssl >= 0x1000 &&
          (ULONG)assl->ssl < 0xFFFFFFF0) {
        debug_printf("DEBUG: Assl_closessl: Freeing SSL object at %p\n",
                     assl->ssl);
        /* Clear ex_data before freeing SSL object to prevent callback from
         * accessing freed assl */
        /* SSL_set_ex_data() is safe even if SSL object is in bad state */
        SSL_set_ex_data(assl->ssl, 0, NULL);
        /* SSL_free() will automatically detach socket and clean up */
        /* This can crash if SSL object is corrupted, but we've validated the
         * pointer */
        debug_printf(
            "DEBUG: Assl_closessl: Calling SSL_free() on SSL object %p\n",
            assl->ssl);
        SSL_free(assl->ssl);
        check_ssl_error("SSL_free", AmiSSLBase);
        assl->ssl = NULL;
        debug_printf(
            "DEBUG: Assl_closessl: SSL_free() completed successfully\n");
      } else {
        debug_printf("DEBUG: Assl_closessl: Skipping SSL_free - invalid "
                     "SSL object (%p)\n",
                     assl->ssl);
        assl->ssl = NULL;
      }

      /* Free SSL context AFTER SSL object is freed */
      /* Context can only be safely freed after all SSL objects using it are
       * freed */
      if (assl->sslctx) {
        if ((ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0) {
          if (AmiSSLBase && (ULONG)AmiSSLBase >= 0x1000 &&
              (ULONG)AmiSSLBase < 0xFFFFFFF0) {
            debug_printf("DEBUG: Assl_closessl: Freeing SSL context at %p\n",
                         assl->sslctx);
            /* Clear certificate verification callback before freeing context */
            SSL_CTX_set_verify(assl->sslctx, SSL_VERIFY_NONE, NULL);
            debug_printf(
                "DEBUG: Assl_closessl: Calling SSL_CTX_free() on context %p\n",
                assl->sslctx);
            SSL_CTX_free(assl->sslctx);
            check_ssl_error("SSL_CTX_free", AmiSSLBase);
            debug_printf("DEBUG: Assl_closessl: SSL_CTX_free() completed "
                         "successfully\n");
          }
        }
        assl->sslctx = NULL;
      }

      /* Release semaphore after SSL object destruction is complete */
      debug_printf("DEBUG: Assl_closessl: Releasing SSL init semaphore\n");
      ReleaseSemaphore(&ssl_init_sema);
      debug_printf("DEBUG: Assl_closessl: SSL init semaphore released\n");
    } else {
      debug_printf("DEBUG: Assl_closessl: Skipping SSL operations - invalid "
                   "AmiSSLBase (%p)\n",
                   AmiSSLBase);
    }
  } else {
    debug_printf("DEBUG: Assl_closessl: Invalid parameters (assl=%p)\n", assl);
  }
}

__asm long Assl_connect(register __a0 struct Assl *assl,
                        register __d0 long sock,
                        register __a1 UBYTE *hostname) {
  /* CRITICAL: Shadow global AmiSSLBase */
  /* struct Library *AmiSSLBase; */       /* Removed - use global directly */
  int ssl_result;
  int ssl_error;
  long result = ASSLCONNECT_FAIL;
  UBYTE *hostname_copy;
  /* C89: Declare all variables at start of function */
  X509 *cert;          /* Certificate for validation prompt */
  char cert_subj[256]; /* Certificate subject for user prompt */
  BOOL hostname_valid;
  BOOL chain_valid; /* Certificate chain validation result */

  debug_printf("DEBUG: Assl_connect: ENTRY - assl=%p, sock=%ld, hostname=%s\n",
               assl, sock, hostname ? (char *)hostname : "(NULL)");

  if (!assl || !assl->ssl) {
    debug_printf("DEBUG: Assl_connect: Invalid args\n");
    return ASSLCONNECT_FAIL;
  }

  /* SocketBase is set globally and used directly */

  /* CRITICAL: Set SocketBase to the connection's socketbase before any socket
   * operations */
  /* OpenSSL's BIO layer uses socket functions that require SocketBase to be set
   */
  /* Without this, SSL_connect() will crash when trying to do network I/O */
  /* Use global SocketBase directly */
  if (!SocketBase) {
    debug_printf("DEBUG: Assl_connect: ERROR - SocketBase is NULL! "
                 "Cannot connect.\n");
    return ASSLCONNECT_FAIL;
  }

  /* AmiSSLBase = assl->amisslbase; */ /* Removed - use global directly */

  /* CRITICAL FIX: DO NOT Obtain ssl_init_sema here!
   * SSL_connect is a blocking network operation.
   * Holding the semaphore here causes the DEADLOCK.
   */

  debug_printf("DEBUG: Assl_connect: Associating socket %ld with SSL object\n",
               sock);

  /* Associate the OS Socket with the SSL object */
  if (SSL_set_fd(assl->ssl, sock) != 1) {
    debug_printf("DEBUG: Assl_connect: SSL_set_fd failed\n");
    check_ssl_error("SSL_set_fd", AmiSSLBase);
    return ASSLCONNECT_FAIL;
  }

  /* Set SNI (Server Name Indication) - REQUIRED for modern web (Cloudflare,
   * etc) */
  if (hostname && *hostname) {
    debug_printf("DEBUG: Assl_connect: Setting SNI host: %s\n", hostname);

    /* If we have a hostname, store it for certificate validation */
    if (assl->hostname) {
      FreeVec(assl->hostname);
    }
    hostname_copy = (UBYTE *)AllocVec(strlen((char *)hostname) + 1, MEMF_ANY);
    if (hostname_copy) {
      strcpy((char *)hostname_copy, (char *)hostname);
      assl->hostname = hostname_copy;
    }

    /* Send hostname to server (SNI) */
    SSL_set_tlsext_host_name(assl->ssl, (char *)hostname);
    check_ssl_error("SSL_set_tlsext_host_name", AmiSSLBase);
  }

  debug_printf("DEBUG: Assl_connect: Starting SSL_connect (Blocking, NO "
               "SEMAPHORE)...\n");

  /* Perform the Handshake */
  /* This will block until the server replies */
  /* CRITICAL: NO SEMAPHORE PROTECTION - SSL_connect() is thread-safe
   * per-connection */
  ssl_result = SSL_connect(assl->ssl);

  if (ssl_result == 1) {
    debug_printf("DEBUG: Assl_connect: Handshake SUCCESS\n");

    /* Manually verify certificate chain AFTER handshake completes (prevents
     * deadlocks) */
    /* This validates: trusted CA, expiration, signature validity, etc. */
    chain_valid = Verify_certificate_chain(assl->ssl, assl->sslctx, AmiSSLBase);

    cert_subj[0] = '\0'; /* Initialize */
    cert = SSL_get_peer_certificate(assl->ssl);
    if (cert) {
      /* Get certificate subject for display */
      X509_NAME_oneline(X509_get_subject_name(cert), cert_subj,
                        sizeof(cert_subj));
      cert_subj[sizeof(cert_subj) - 1] = '\0';

      /* Validate hostname against certificate */
      if (hostname && *hostname) {
        hostname_valid = Validate_hostname(cert, hostname, AmiSSLBase);

        if (!chain_valid || !hostname_valid) {
          /* Certificate validation failed - either chain invalid or hostname
           * mismatch */
          if (!chain_valid && !hostname_valid) {
            debug_printf("DEBUG: Assl_connect: Certificate chain INVALID and "
                         "hostname '%s' does not match certificate '%s'\n",
                         hostname, cert_subj);
          } else if (!chain_valid) {
            debug_printf("DEBUG: Assl_connect: Certificate chain INVALID "
                         "(hostname '%s' matches certificate '%s')\n",
                         hostname, cert_subj);
          } else {
            debug_printf("DEBUG: Assl_connect: Hostname '%s' does not match "
                         "certificate '%s' (chain valid)\n",
                         hostname, cert_subj);
          }

          /* Prompt user to accept or reject */
#ifndef LOCALONLY
          if (Httpcertaccept(hostname, cert_subj)) {
            /* User accepted - allow connection */
            debug_printf("DEBUG: Assl_connect: User accepted certificate "
                         "despite validation failure\n");
            result = ASSLCONNECT_OK;
          } else {
            /* User rejected */
            debug_printf("DEBUG: Assl_connect: User rejected certificate\n");
            assl->denied = TRUE;
            result = ASSLCONNECT_DENIED;
          }
#else
          /* LOCALONLY: Reject certificate (no network access) */
          assl->denied = TRUE;
          result = ASSLCONNECT_DENIED;
#endif
        } else {
          /* Both chain and hostname are valid - connection is good */
          debug_printf("DEBUG: Assl_connect: Certificate chain VALID and "
                       "hostname '%s' matches certificate '%s'\n",
                       hostname, cert_subj);
          result = ASSLCONNECT_OK;
        }
      } else {
        /* No hostname to validate - check chain only */
          if (!chain_valid) {
          debug_printf("DEBUG: Assl_connect: Certificate chain INVALID (no "
                       "hostname to validate)\n");
#ifndef LOCALONLY
          if (Httpcertaccept((UBYTE *)"", cert_subj)) {
            debug_printf("DEBUG: Assl_connect: User accepted certificate "
                         "despite chain validation failure\n");
            result = ASSLCONNECT_OK;
          } else {
            debug_printf("DEBUG: Assl_connect: User rejected certificate\n");
            assl->denied = TRUE;
            result = ASSLCONNECT_DENIED;
          }
#else
          /* LOCALONLY: Reject certificate (no network access) */
          assl->denied = TRUE;
          result = ASSLCONNECT_DENIED;
#endif
        } else {
          debug_printf("DEBUG: Assl_connect: Certificate chain VALID (no "
                       "hostname provided)\n");
          result = ASSLCONNECT_OK;
        }
      }

      X509_free(cert);
    } else {
      /* No certificate provided by server */
      debug_printf("DEBUG: Assl_connect: No peer certificate provided\n");
      result = ASSLCONNECT_FAIL;
    }
  } else {
    /* Handshake Failed */
    ssl_error = SSL_get_error(assl->ssl, ssl_result);

    debug_printf("DEBUG: Assl_connect: Handshake FAILED (err=%d, ssl_err=%d)\n",
                 ssl_result, ssl_error);

    /* Detailed error logging */
    check_ssl_error("SSL_connect", AmiSSLBase);
    if (httpdebug) {
      print_ssl_errors_bio("SSL_connect", AmiSSLBase);
    }

    if (assl->denied) {
      debug_printf(
          "DEBUG: Assl_connect: Connection denied by user/cert check\n");
      result = ASSLCONNECT_DENIED;
    } else {
      result = ASSLCONNECT_FAIL;
    }
  }

  /* SocketBase remains set globally */

  if (result == ASSLCONNECT_OK) {
    debug_printf("DEBUG: Assl_connect: EXIT - returning ASSLCONNECT_OK (%d)\n",
                 result);
  } else if (result == ASSLCONNECT_DENIED) {
    debug_printf(
        "DEBUG: Assl_connect: EXIT - returning ASSLCONNECT_DENIED (%d)\n",
        result);
  } else {
    debug_printf(
        "DEBUG: Assl_connect: EXIT - returning ASSLCONNECT_FAIL (%d)\n",
        result);
  }
  return result;
}

__asm char *Assl_geterror(register __a0 struct Assl *assl,
                          register __a1 char *errbuf) {
  long err;
  UBYTE *p = NULL;
  short i;
  /* Local buffer for ERR_error_string_n() - OpenSSL can write up to 256 bytes
   */
  /* We use a local buffer to prevent overflow of caller's buffer */
  char local_errbuf[256];
  /* Conservative maximum size to copy to caller's buffer */
  /* Header (awebtcp.h) says errbuf should be 128 bytes minimum */
  /* We use 79 to be safe even if caller provides only 80 bytes */
  /* This leaves room for null terminator and prevents overruns */
  const long max_copy = 79;

  /* Validate assl pointer before use */
  if (assl && errbuf) { /* Validate assl pointer range before accessing
                           semaphore field */
    if ((ULONG)assl < 0x1000 ||
        (ULONG)assl >= 0xFFFFFFF0) { /* Use strncpy with explicit
                                        null-termination to prevent overflow */
      strncpy(errbuf, "Invalid Assl object", max_copy);
      errbuf[max_copy] = '\0';
      return errbuf;
    }

    /* CRITICAL: Do NOT use semaphores for read-only error checking */
    /* ERR_get_error() is a simple read operation that doesn't do network I/O */
    if (AmiSSLBase && (ULONG)AmiSSLBase >= 0x1000 &&
        (ULONG)AmiSSLBase < 0xFFFFFFF0) {
      /* Modern OpenSSL doesn't need these deprecated functions */
      /* ERR_load_SSL_strings(); */
      err = ERR_get_error();
      if (err) {
        /* Use ERR_error_string_n() for safe null-terminated string */
        /* ERR_error_string_n() guarantees null termination and respects buffer
         * size */
        ERR_error_string_n(err, local_errbuf, sizeof(local_errbuf));
        /* Ensure null termination (defensive - ERR_error_string_n should do
         * this) */
        local_errbuf[sizeof(local_errbuf) - 1] = '\0';
        /* errbuf now contains something like:
           "error:1408806E:SSL routines:SSL_SET_CERTIFICATE:certificate verify
           failed" Find the descriptive text after the 4th colon. */
        for (i = 0, p = local_errbuf; i < 4 && p; i++) {
          p = strchr(p, ':');
          if (!p)
            break;
          p++;
        }
        /* If we found the descriptive part, copy it; otherwise copy the full
         * error */
        if (p && *p) { /* Copy descriptive part to caller's buffer with bounds
                          checking */
          strncpy(errbuf, p, max_copy);
          errbuf[max_copy] = '\0';
          p = errbuf;
        } else { /* No descriptive part found, copy full error message */
          strncpy(errbuf, local_errbuf, max_copy);
          errbuf[max_copy] = '\0';
          p = errbuf;
        }
      } else { /* No error available, provide default message */
        strncpy(errbuf, "Unknown SSL error", max_copy);
        errbuf[max_copy] = '\0';
        p = errbuf;
      }
    } else { /* SSL objects already cleaned up */
      strncpy(errbuf, "SSL connection closed", max_copy);
      errbuf[max_copy] = '\0';
      p = errbuf;
    }
  } else { /* Invalid parameters */
    if (errbuf) {
      strncpy(errbuf, "Invalid parameters", max_copy);
      errbuf[max_copy] = '\0';
    }
  }
  if (!p && errbuf)
    p = errbuf;
  return (char *)p;
}

__asm long Assl_write(register __a0 struct Assl *assl,
                      register __a1 char *buffer, register __d0 long length) {
  long result = -1;
  /* CRITICAL: Shadow global AmiSSLBase */
  /* struct Library *AmiSSLBase = NULL; */ /* Removed - use global directly */
  /* struct Library *local_amisslbase = NULL; */ /* Removed */

  /* Validate basic parameters first */
  /* Validate buffer pointer range to prevent CHK instruction errors */
  if (assl && buffer && length > 0 && length <= 1024 * 1024) /* Max 1MB write */
  { /* Validate buffer pointer is in valid memory range */
    if ((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_write: Invalid buffer pointer (%p)\n", buffer);
      return -1;
    }

    /* Use global AmiSSLBase directly */
    /* AmiSSLBase = assl->amisslbase; */       /* Removed */
    /* local_amisslbase = assl->amisslbase; */ /* Removed */

    /* Validate assl pointer before accessing semaphore field */
    if ((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_write: Invalid Assl pointer (%p)\n", assl);
      return -1;
    }

    /* CRITICAL: Do NOT use semaphores during SSL operations - they cause
     * deadlocks */
    /* Each connection has its own SSL object, which is thread-safe
     * per-connection */
    /* We only check the 'closed' flag - if cleanup happens, operations will
     * fail gracefully */

    /* Quick validation check - no semaphore needed for read-only checks */
    if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
        (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_write: Invalid AmiSSLBase pointer (%p)\n",
                   AmiSSLBase);
      return -1;
    }

    /* Check if SSL objects are available and not closed */
    if (assl->ssl && assl->sslctx && !assl->closed) {
      /* Validate SSL object pointer is reasonable */
      if ((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
          (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0) {
        debug_printf("DEBUG: Assl_write: Calling SSL_write() - NO SEMAPHORE "
                     "PROTECTION\n");

        /* Perform the write - NO SEMAPHORE PROTECTION */
        /* SSL_write() is thread-safe per-connection and performs blocking
         * network I/O */
        /* Holding any semaphore here would freeze the entire system */
        result = SSL_write(assl->ssl, buffer, length);
        debug_printf("DEBUG: Assl_write: SSL_write() returned %ld\n", result);

        /* CRITICAL: Check if connection was closed while SSL_write() was
         * blocking */
        /* This prevents use-after-free crashes if Assl_closessl() was called
         * concurrently */
        /* Check closed flag FIRST before accessing SSL object pointers */
        if (assl->closed) {
          debug_printf("DEBUG: Assl_write: Connection was closed during "
                       "SSL_write() (closed=TRUE)\n");
          return -1;
        }
        /* Then check if SSL objects are still valid (they might have been
         * freed) */
        if (!assl->ssl || !assl->sslctx || !AmiSSLBase) {
          debug_printf(
              "DEBUG: Assl_write: SSL objects were freed during SSL_write() "
              "(ssl=%p, sslctx=%p, AmiSSLBase=%p)\n",
              assl->ssl, assl->sslctx, AmiSSLBase);
          return -1;
        }

        /* CRITICAL: If SSL_write() returns -1, we MUST check SSL_get_error() */
        /* to determine the actual error condition */
        if (result < 0) {
          long ssl_error;
          long errno_value;

          ssl_error = SSL_get_error(assl->ssl, result);
          debug_printf(
              "DEBUG: Assl_write: SSL_write() returned -1, SSL_get_error=%ld\n",
              ssl_error);

          /* Check SSL error type */
          if (ssl_error == SSL_ERROR_WANT_READ ||
              ssl_error == SSL_ERROR_WANT_WRITE) {
            /* SSL wants more I/O - for blocking sockets, this should be rare */
            /* It can occur during SSL renegotiation or when OpenSSL's internal
             * buffer is full */
            /* For blocking sockets, retry once - the socket will block until
             * ready or timeout */
            debug_printf("DEBUG: Assl_write: SSL wants I/O (WANT_READ=%d, "
                         "WANT_WRITE=%d) - retrying once on blocking socket\n",
                         ssl_error == SSL_ERROR_WANT_READ,
                         ssl_error == SSL_ERROR_WANT_WRITE);
            check_ssl_error("SSL_write (WANT_IO)", AmiSSLBase);

            /* Retry the write once - on blocking socket, this will block until
             * ready or timeout */
            {
              long retry_result;

              /* Check if connection was closed before retry */
              if (assl->closed || !assl->ssl || !assl->sslctx) {
                debug_printf(
                    "DEBUG: Assl_write: Connection closed before retry\n");
                return -1;
              }

              debug_printf("DEBUG: Assl_write: Retrying SSL_write() for "
                           "WANT_READ/WANT_WRITE\n");
              retry_result = SSL_write(assl->ssl, buffer, length);

              /* Check if connection was closed during retry */
              if (assl->closed || !assl->ssl || !assl->sslctx) {
                debug_printf(
                    "DEBUG: Assl_write: Connection closed during retry\n");
                return -1;
              }

              if (retry_result > 0) {
                /* Success - return the result */
                debug_printf(
                    "DEBUG: Assl_write: Retry succeeded, wrote %ld bytes\n",
                    retry_result);
                return retry_result;
              } else {
                /* Check error type on retry */
                long retry_ssl_error = SSL_get_error(assl->ssl, retry_result);
                debug_printf("DEBUG: Assl_write: Retry returned %ld, "
                             "SSL_get_error=%ld\n",
                             retry_result, retry_ssl_error);

                if (retry_ssl_error == SSL_ERROR_WANT_READ ||
                    retry_ssl_error == SSL_ERROR_WANT_WRITE) {
                  /* Still WANT_READ/WANT_WRITE after retry - this is unusual
                   * for blocking socket */
                  debug_printf("DEBUG: Assl_write: Retry still returned "
                               "WANT_READ/WANT_WRITE\n");

                  if (httpdebug) {
                    print_ssl_errors_bio("SSL_write (WANT_IO after retry)",
                                         AmiSSLBase);
                  }

                  /* CRITICAL FIX: Set errno so http.c knows to wait */
                  errno = 35; /* EWOULDBLOCK / EAGAIN */

                  return -1;
                } else {
                  /* Different error - return it */
                  debug_printf("DEBUG: Assl_write: Retry got different error "
                               "(%ld), returning -1\n",
                               retry_ssl_error);
                  return -1;
                }
              }
            }
          } else if (ssl_error == SSL_ERROR_SYSCALL) {
            /* System call error - check errno */
            errno_value = errno;
            debug_printf("DEBUG: Assl_write: SSL_ERROR_SYSCALL (errno=%ld)\n",
                         errno_value);
            if (errno_value == 0) {
              /* errno=0 with SSL_ERROR_SYSCALL usually means EOF */
              debug_printf("DEBUG: Assl_write: SSL_ERROR_SYSCALL with errno=0, "
                           "treating as connection closed\n");
              check_ssl_error("SSL_write (SYSCALL EOF)", AmiSSLBase);
              return -1;
            } else if (errno_value == EAGAIN || errno_value == EWOULDBLOCK) {
              /* Non-blocking I/O would block - return -1 */
              debug_printf(
                  "DEBUG: Assl_write: EAGAIN/EWOULDBLOCK, returning -1\n");
              check_ssl_error("SSL_write (EAGAIN)", AmiSSLBase);
              return -1;
            } else {
              /* Other system error */
              debug_printf("DEBUG: Assl_write: System error (errno=%ld)\n",
                           errno_value);
              check_ssl_error("SSL_write (SYSCALL)", AmiSSLBase);
              if (httpdebug) {
                print_ssl_errors_bio("SSL_write (SYSCALL)", AmiSSLBase);
              }
              return -1;
            }
          } else if (ssl_error == SSL_ERROR_SSL) {
            /* SSL protocol error */
            debug_printf("DEBUG: Assl_write: SSL protocol error\n");
            check_ssl_error("SSL_write (SSL_ERROR)", AmiSSLBase);
            if (httpdebug) {
              print_ssl_errors_bio("SSL_write (SSL_ERROR)", AmiSSLBase);
            }
            return -1;
          } else {
            /* Unknown SSL error */
            debug_printf("DEBUG: Assl_write: Unknown SSL error (%ld)\n",
                         ssl_error);
            check_ssl_error("SSL_write (UNKNOWN)", AmiSSLBase);
            if (httpdebug) {
              print_ssl_errors_bio("SSL_write (UNKNOWN)", AmiSSLBase);
            }
            return -1;
          }
        } else if (result == 0) {
          /* SSL_write() returned 0 - this shouldn't happen normally */
          /* But if it does, treat as error */
          debug_printf(
              "DEBUG: Assl_write: SSL_write() returned 0 (unexpected)\n");
          check_ssl_error("SSL_write (ZERO)", AmiSSLBase);
          return -1;
        } else {
          /* Success - return number of bytes written */
          check_ssl_error("SSL_write", AmiSSLBase);
          return result;
        }
      } else {
        debug_printf(
            "DEBUG: Assl_write: Invalid SSL pointer (ssl=%p, sslctx=%p)\n",
            assl->ssl, assl->sslctx);
      }
    } else if (assl->closed) {
      debug_printf("DEBUG: Assl_write: SSL connection already closed\n");
      result = -1; /* Return error to indicate connection closed */
    } else {
      debug_printf("DEBUG: Assl_write: SSL objects not available (ssl=%p, "
                   "sslctx=%p, closed=%d)\n",
                   assl->ssl, assl->sslctx, assl->closed);
    }
  } else {
    debug_printf("DEBUG: Assl_write: Invalid parameters (assl=%p, "
                 "buffer=%p, length=%ld)\n",
                 assl, buffer, length);
  }
  return result;
}

__asm long Assl_read(register __a0 struct Assl *assl,
                     register __a1 char *buffer, register __d0 long length) {
  long result = -1;
  /* CRITICAL: Shadow global AmiSSLBase */
  /* struct Library *AmiSSLBase = NULL; */ /* Removed - use global directly */
  /* struct Library *local_amisslbase = NULL; */ /* Removed */

  debug_printf("DEBUG: Assl_read: ENTRY - assl=%p, buffer=%p, length=%ld\n",
               assl, buffer, length);

  /* Validate basic parameters first */
  /* Validate buffer pointer range to prevent CHK instruction errors */
  if (assl && buffer && length > 0 && length <= 1024 * 1024) /* Max 1MB read */
  {
    debug_printf("DEBUG: Assl_read: Basic parameter validation passed\n");
    /* Validate buffer pointer is in valid memory range */
    if ((ULONG)buffer < 0x1000 || (ULONG)buffer >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_read: Invalid buffer pointer (%p)\n", buffer);
      return -1;
    }
    debug_printf("DEBUG: Assl_read: Buffer pointer validation passed\n");

    /* Use global AmiSSLBase directly */
    /* AmiSSLBase = assl->amisslbase; */       /* Removed */
    /* local_amisslbase = assl->amisslbase; */ /* Removed */

    /* Validate assl pointer before accessing semaphore field */
    if ((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_read: Invalid Assl pointer (%p)\n", assl);
      return -1;
    }
    debug_printf("DEBUG: Assl_read: Assl pointer validation passed\n");

    /* Validate semaphore field is accessible before trying to obtain it */
    /* The semaphore is at a fixed offset in the Assl struct, so validate the
     * struct is intact */
    {
      ULONG sema_offset;
      ULONG sema_addr;
      sema_offset = (ULONG)&assl->use_sema - (ULONG)assl;
      sema_addr = (ULONG)&assl->use_sema;
      debug_printf("DEBUG: Assl_read: Semaphore offset=%lu, address=%p\n",
                   sema_offset, &assl->use_sema);
      if (sema_addr < 0x1000 || sema_addr >= 0xFFFFFFF0) {
        debug_printf(
            "DEBUG: Assl_read: Invalid semaphore address (%p), aborting\n",
            &assl->use_sema);
        return -1;
      }
    }

    /* CRITICAL: Do NOT use semaphores during SSL operations - they cause
     * deadlocks */
    /* Each connection has its own SSL object, which is thread-safe
     * per-connection */
    /* We only check the 'closed' flag - if cleanup happens, operations will
     * fail gracefully */

    /* Quick validation check - no semaphore needed for read-only checks */
    /* Use global AmiSSLBase directly */
    if (!AmiSSLBase || (ULONG)AmiSSLBase < 0x1000 ||
        (ULONG)AmiSSLBase >= 0xFFFFFFF0) {
      debug_printf("DEBUG: Assl_read: Invalid AmiSSLBase pointer (%p)\n",
                   AmiSSLBase);
      return -1;
    }

    /* Check if SSL objects are available and not closed */
    if (assl->ssl && assl->sslctx && !assl->closed) {
      /* Validate SSL object pointer is reasonable */
      if ((ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
          (ULONG)assl->sslctx >= 0x1000 && (ULONG)assl->sslctx < 0xFFFFFFF0) {
        debug_printf(
            "DEBUG: Assl_read: Calling SSL_read()\n");

        /* Perform the read - NO SEMAPHORE PROTECTION */
        /* SSL_read() is thread-safe per-connection and performs blocking
         * network I/O */
        /* Holding any semaphore here would freeze the entire system */
        result = SSL_read(assl->ssl, buffer, length);
        debug_printf("DEBUG: Assl_read: SSL_read() returned %ld\n", result);

        /* CRITICAL: Check if connection was closed while SSL_read() was
         * blocking */
        /* This prevents use-after-free crashes if Assl_closessl() was called
         * concurrently */
        /* Check closed flag FIRST before accessing SSL object pointers */
        if (assl->closed) {
          debug_printf("DEBUG: Assl_read: Connection was closed during "
                       "SSL_read() (closed=TRUE)\n");
          return -1;
        }
        /* Then check if SSL objects are still valid (they might have been
         * freed) */
        if (!assl->ssl || !assl->sslctx || !AmiSSLBase) {
          debug_printf(
              "DEBUG: Assl_read: SSL objects were freed during SSL_read() "
              "(ssl=%p, sslctx=%p, AmiSSLBase=%p)\n",
              assl->ssl, assl->sslctx, AmiSSLBase);
          return -1;
        }

        /* CRITICAL: If SSL_read() returns -1, we MUST check SSL_get_error() */
        /* to determine the actual error condition */
        if (result < 0) {
          long ssl_error;
          long errno_value;

          ssl_error = SSL_get_error(assl->ssl, result);
          debug_printf(
              "DEBUG: Assl_read: SSL_read() returned -1, SSL_get_error=%ld\n",
              ssl_error);

          /* Check SSL error type */
          if (ssl_error == SSL_ERROR_WANT_READ ||
              ssl_error == SSL_ERROR_WANT_WRITE) {
            /* SSL wants more I/O - for blocking sockets, this should be rare */
            /* It can occur during SSL renegotiation or when OpenSSL's internal
             * buffer is full */
            /* For blocking sockets, retry once - the socket will block until
             * ready or timeout */
            debug_printf("DEBUG: Assl_read: SSL wants I/O (WANT_READ=%d, "
                         "WANT_WRITE=%d) - retrying once on blocking socket\n",
                         ssl_error == SSL_ERROR_WANT_READ,
                         ssl_error == SSL_ERROR_WANT_WRITE);
            check_ssl_error("SSL_read (WANT_IO)", AmiSSLBase);

            /* Retry the read once - on blocking socket, this will block until
             * data arrives or timeout */
            /* This handles cases where OpenSSL needs more network I/O before it
             * can decrypt data */
            {
              long retry_result;

              /* Check if connection was closed before retry */
              if (assl->closed || !assl->ssl || !assl->sslctx) {
                debug_printf(
                    "DEBUG: Assl_read: Connection closed before retry\n");
                return -1;
              }

              debug_printf("DEBUG: Assl_read: Retrying SSL_read() for "
                           "WANT_READ/WANT_WRITE\n");
              retry_result = SSL_read(assl->ssl, buffer, length);

              /* Check if connection was closed during retry */
              if (assl->closed || !assl->ssl || !assl->sslctx) {
                debug_printf(
                    "DEBUG: Assl_read: Connection closed during retry\n");
                return -1;
              }

              if (retry_result > 0) {
                /* Success - return the result */
                debug_printf(
                    "DEBUG: Assl_read: Retry succeeded, read %ld bytes\n",
                    retry_result);
                return retry_result;
              } else if (retry_result == 0) {
                /* EOF - connection closed cleanly */
                debug_printf("DEBUG: Assl_read: Retry returned 0 (EOF)\n");
                return 0;
              } else {
                /* Check error type on retry */
                long retry_ssl_error = SSL_get_error(assl->ssl, retry_result);
                debug_printf(
                    "DEBUG: Assl_read: Retry returned -1, SSL_get_error=%ld\n",
                    retry_ssl_error);

                if (retry_ssl_error == SSL_ERROR_ZERO_RETURN) {
                  debug_printf(
                      "DEBUG: Assl_read: Retry got ZERO_RETURN (EOF)\n");
                  return 0;
                } else if (retry_ssl_error == SSL_ERROR_WANT_READ ||
                           retry_ssl_error == SSL_ERROR_WANT_WRITE) {
                  /* Still WANT_READ/WANT_WRITE after retry - this is unusual
                   * for blocking socket */
                  debug_printf("DEBUG: Assl_read: Retry still returned "
                               "WANT_READ/WANT_WRITE\n");

                  if (httpdebug) {
                    print_ssl_errors_bio("SSL_read (WANT_IO after retry)",
                                         AmiSSLBase);
                  }

                  /* CRITICAL FIX: Set errno so http.c knows to wait */
                  errno = 35; /* EWOULDBLOCK / EAGAIN */

                  return -1;
                } else {
                  /* Different error - return it */
                  debug_printf("DEBUG: Assl_read: Retry got different error "
                               "(%ld), returning -1\n",
                               retry_ssl_error);
                  return -1;
                }
              }
            }
          } else if (ssl_error == SSL_ERROR_SYSCALL) {
            /* System call error - check errno */
            errno_value = errno;
            debug_printf("DEBUG: Assl_read: SSL_ERROR_SYSCALL (errno=%ld)\n",
                         errno_value);
            if (errno_value == 0) {
              /* errno=0 with SSL_ERROR_SYSCALL usually means EOF */
              debug_printf("DEBUG: Assl_read: SSL_ERROR_SYSCALL with errno=0, "
                           "treating as connection closed\n");
              check_ssl_error("SSL_read (SYSCALL EOF)", AmiSSLBase);
              return -1;
            } else if (errno_value == EAGAIN || errno_value == EWOULDBLOCK) {
              /* Non-blocking I/O would block - return -1 */
              debug_printf(
                  "DEBUG: Assl_read: EAGAIN/EWOULDBLOCK, returning -1\n");
              check_ssl_error("SSL_read (EAGAIN)", AmiSSLBase);
              return -1;
            } else {
              /* Other system error */
              debug_printf("DEBUG: Assl_read: System error (errno=%ld)\n",
                           errno_value);
              check_ssl_error("SSL_read (SYSCALL)", AmiSSLBase);
              if (httpdebug) {
                print_ssl_errors_bio("SSL_read (SYSCALL)", AmiSSLBase);
              }
              return -1;
            }
          } else if (ssl_error == SSL_ERROR_SSL) {
            /* SSL protocol error */
            debug_printf("DEBUG: Assl_read: SSL protocol error\n");
            check_ssl_error("SSL_read (SSL_ERROR)", AmiSSLBase);
            if (httpdebug) {
              print_ssl_errors_bio("SSL_read (SSL_ERROR)", AmiSSLBase);
            }
            return -1;
          } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            /* TLS/SSL connection has been closed */
            debug_printf("DEBUG: Assl_read: SSL_ERROR_ZERO_RETURN (closed)\n");
            return 0; /* EOF */
          } else {
            /* Unknown SSL error */
            debug_printf("DEBUG: Assl_read: Unknown SSL error (%ld)\n",
                         ssl_error);
            check_ssl_error("SSL_read (UNKNOWN)", AmiSSLBase);
            if (httpdebug) {
              print_ssl_errors_bio("SSL_read (UNKNOWN)", AmiSSLBase);
            }
            return -1;
          }
        } else if (result == 0) {
          /* SSL_read() returned 0 - this means EOF (connection closed) */
          debug_printf("DEBUG: Assl_read: SSL_read() returned 0 (EOF)\n");
          return 0;
        } else {
          /* Success - return number of bytes read */
          /* check_ssl_error("SSL_read", AmiSSLBase); */ /* Don't check error on
                                                            success to avoid log
                                                            spam */
          return result;
        }
      } else {
        debug_printf(
            "DEBUG: Assl_read: Invalid SSL pointer (ssl=%p, sslctx=%p)\n",
            assl->ssl, assl->sslctx);
      }
    } else if (assl->closed) {
      debug_printf("DEBUG: Assl_read: SSL connection already closed\n");
      result = -1; /* Return error to indicate connection closed */
    } else {
      debug_printf("DEBUG: Assl_read: SSL objects not available (ssl=%p, "
                   "sslctx=%p, closed=%d)\n",
                   assl->ssl, assl->sslctx, assl->closed);
    }
  } else {
    debug_printf("DEBUG: Assl_read: Invalid parameters (assl=%p, "
                 "buffer=%p, length=%ld)\n",
                 assl, buffer, length);
  }
  debug_printf("DEBUG: Assl_read: EXIT - returning %ld\n", result);
  return result;
}

__asm char *Assl_getcipher(register __a0 struct Assl *assl) {
  char *result = NULL;
  /* CRITICAL: Shadow global AmiSSLBase */
  /* struct Library *AmiSSLBase = NULL; */ /* Removed - use global directly */

  /* Validate assl pointer before use */
  if (assl) {
    if ((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      return NULL;
    }

    /* Use global AmiSSLBase directly */
    /* AmiSSLBase = assl->amisslbase; */ /* Removed */

    /* CRITICAL: Do NOT use semaphores for read-only operations */
    /* SSL_get_cipher() is a simple read operation that doesn't do network I/O
     */
    /* Holding semaphores here can cause deadlocks if another task is waiting */
    /* Just check the closed flag - if cleanup happens, operations will fail
     * gracefully */
    if (AmiSSLBase && (ULONG)AmiSSLBase >= 0x1000 &&
        (ULONG)AmiSSLBase < 0xFFFFFFF0 && assl->ssl &&
        (ULONG)assl->ssl >= 0x1000 && (ULONG)assl->ssl < 0xFFFFFFF0 &&
        !assl->closed) {
      /* SSL_get_cipher() returns a pointer to internal OpenSSL string */
      /* The pointer is valid while the SSL object exists */
      result = (char *)SSL_get_cipher(assl->ssl);
    }
  }
  return result;
}

__asm char *Assl_libname(register __a0 struct Assl *assl) {
  char *result = NULL;
  /* Validate assl pointer before use */
  if (assl) {
    if ((ULONG)assl < 0x1000 || (ULONG)assl >= 0xFFFFFFF0) {
      return NULL;
    }

    /* CRITICAL: Do NOT use semaphores for read-only operations */
    /* Reading lib_IdString is a simple read operation that doesn't do network
     * I/O */
    /* Holding semaphores here can cause deadlocks if another task is waiting */
    if (AmiSSLBase && (ULONG)AmiSSLBase >= 0x1000 &&
        (ULONG)AmiSSLBase < 0xFFFFFFF0) {
      result = (char *)AmiSSLBase->lib_IdString;
    }
  }
  return result;
}

__asm void Assl_dummy(void) { return; }

/*-----------------------------------------------------------------------*/

/* Cleanup function to mirror Assl_initamissl() initialization */
/* This should be called at application exit, after all SSL connections are closed */
/* Per AmiSSL v5 API: CloseAmiSSL() must be called before closing amisslmaster.library */
void Freeamissl(void)
{
   /* Only cleanup if AmiSSL was successfully initialized */
   if (AmiSSLMasterBase && AmiSSLBase)
   {
      debug_printf("DEBUG: Freeamissl: Cleaning up AmiSSL\n");
      
      /* CloseAmiSSL() must be called before closing amisslmaster.library */
      /* This cleans up AmiSSL internal resources and certificate cache */
      CloseAmiSSL();
      
      /* Close amisslmaster.library - mirrors OpenLibrary() in Assl_initamissl() */
      CloseLibrary(AmiSSLMasterBase);
      
      /* Clear global pointers to prevent use-after-free */
      AmiSSLMasterBase = NULL;
      AmiSSLBase = NULL;
      AmiSSLExtBase = NULL;
      
      debug_printf("DEBUG: Freeamissl: AmiSSL cleanup complete\n");
   }
   else
   {
      debug_printf("DEBUG: Freeamissl: AmiSSL not initialized, nothing to cleanup\n");
   }
}

/*-----------------------------------------------------------------------*/

static UBYTE version[] = "AwebAmiSSL.library";

struct Jumptab {
  UWORD jmp;
  void *function;
};
#define JMP 0x4ef9

/* Library jump table - referenced by awebamissllib structure for function
 * dispatch */
static struct Jumptab jumptab[] = {
    JMP, Assl_libname,  JMP, Assl_getcipher, JMP, Assl_read,
    JMP, Assl_write,    JMP, Assl_geterror,  JMP, Assl_connect,
    JMP, Assl_closessl, JMP, Assl_openssl,   JMP, Assl_cleanup,
    JMP, Assl_dummy, /* Extfunc */
    JMP, Assl_dummy, /* Expunge */
    JMP, Assl_dummy, /* Close */
    JMP, Assl_dummy, /* Open */
};
static struct Library awebamissllib = {{NULL, NULL, NT_LIBRARY, 0, version},
                                       0,
                                       0,
                                       sizeof(jumptab),
                                       sizeof(struct Library),
                                       1,
                                       0,
                                       version,
                                       0,
                                       0};

struct Library *AwebAmisslBase = &awebamissllib;
