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

/* SAS/C pragmas for AmiSSL functions */
#ifdef __SASC
#pragma libcall AmiSSLMasterBase OpenAmiSSLTags 3c 8002
#pragma libcall AmiSSLMasterBase CloseAmiSSL 2a 00
#pragma libcall AmiSSLBase InitAmiSSLA 24 801
#pragma libcall AmiSSLBase CleanupAmiSSLA 2a 801
#pragma libcall AmiSSLBase SSL_new 1e 801
#pragma libcall AmiSSLBase SSL_free 24 801
#pragma libcall AmiSSLBase SSL_CTX_new 2a 801
#pragma libcall AmiSSLBase SSL_CTX_free 30 801
#pragma libcall AmiSSLBase SSL_set_fd 36 9802
#pragma libcall AmiSSLBase SSL_connect 3c 801
#pragma libcall AmiSSLBase SSL_write 42 9803
#pragma libcall AmiSSLBase SSL_read 48 9803
#pragma libcall AmiSSLBase SSL_get_cipher 4e 801
#pragma libcall AmiSSLBase SSL_CTX_set_default_verify_paths 54 801
#pragma libcall AmiSSLBase SSL_CTX_set_options 5a 9802
#pragma libcall AmiSSLBase SSL_CTX_set_cipher_list 60 9802
#pragma libcall AmiSSLBase SSL_CTX_set_verify 66 9803
#pragma libcall AmiSSLBase X509_STORE_CTX_get_current_cert 6c 801
#pragma libcall AmiSSLBase X509_STORE_CTX_get_error 72 801
#pragma libcall AmiSSLBase X509_get_subject_name 78 801
#pragma libcall AmiSSLBase X509_NAME_oneline 7e 9803
#pragma libcall AmiSSLBase ERR_get_error 84 00
#pragma libcall AmiSSLBase ERR_error_string 8a 9802
#pragma libcall AmiSSLBase SSL_set1_host 68e8 9802
#endif

/*-----------------------------------------------------------------------*/

struct Assl
{  struct Library *amisslmasterbase;
   struct Library *amisslbase;
   struct Library *amissslextbase;
   SSL_CTX *sslctx;
   SSL *ssl;
   UBYTE *hostname;
   BOOL denied;
};

struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
struct Library *AmiSSLExtBase;

/*-----------------------------------------------------------------------*/

struct Assl *Assl_initamissl(struct Library *socketbase)
{  
   struct Assl *assl;
   if(socketbase && (assl=ALLOCSTRUCT(Assl,1,MEMF_CLEAR)))
   {  
      /* Check if AmiSSLMaster library is already open - reuse if so */
      if(!AmiSSLMasterBase)
      {
         /* Open AmiSSLMaster library first */
         if(AmiSSLMasterBase=OpenLibrary("amisslmaster.library",AMISSLMASTER_MIN_VERSION))
         {  
            /* Use new OpenAmiSSLTags API for AmiSSL 5.20+ */
            if(OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
                              AmiSSL_UsesOpenSSLStructs, TRUE,
                              AmiSSL_GetAmiSSLBase, &AmiSSLBase,
                              AmiSSL_GetAmiSSLExtBase, &AmiSSLExtBase,
                              AmiSSL_SocketBase, socketbase,
                              AmiSSL_ErrNoPtr, &errno,
                              TAG_END) == 0)
            {  
               /* Success - libraries are now open */
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

static int __saveds __stdargs
   Certcallback(int ok,X509_STORE_CTX *sctx)
{  char *s,*u;
   struct Assl *assl;
   X509 *xs;
   int err;
   char buf[256];
   if(!ok && sctx)
   {  assl=Gettaskuserdata();
      if(assl && assl->amisslbase)
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
   }
   return ok;
}

__asm void Assl_cleanup(register __a0 struct Assl *assl)
{  if(assl)
   {  if(assl->ssl)
      {  SSL_free(assl->ssl);
         assl->ssl=NULL;
      }
      if(assl->sslctx)
      {  SSL_CTX_free(assl->sslctx);
         assl->sslctx=NULL;
      }
      if(assl->amisslbase)
      {  /* Clean up AmiSSL */
         struct Library *AmiSSLBase=assl->amisslbase;
         CleanupAmiSSLA(NULL);
         AmiSSLBase = NULL;
         AmiSSLExtBase = NULL;
      }
      if(assl->amisslmasterbase)
      {  /* Close AmiSSL */
         CloseAmiSSL();
         CloseLibrary(assl->amisslmasterbase);
         assl->amisslmasterbase = NULL;
         AmiSSLMasterBase = NULL;
      }
      FREE(assl);
   }
}

__asm BOOL Assl_openssl(register __a0 struct Assl *assl)
{  if(assl && assl->amisslbase)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      /* Modern OpenSSL doesn't need these deprecated functions */
      /* SSLeay_add_ssl_algorithms(); */
      /* SSL_load_error_strings(); */
      if(assl->sslctx=SSL_CTX_new(TLS_client_method()))
      {  SSL_CTX_set_default_verify_paths(assl->sslctx);
         /* Enhanced security: disable weak protocols and ciphers */
         SSL_CTX_set_options(assl->sslctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
         SSL_CTX_set_cipher_list(assl->sslctx,"HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK@STRENGTH");
         SSL_CTX_set_verify(assl->sslctx,SSL_VERIFY_FAIL_IF_NO_PEER_CERT,Certcallback);
         if(assl->ssl=SSL_new(assl->sslctx))
         {  Settaskuserdata(assl);
         }
      }
   }
   return (BOOL)(assl && assl->ssl);
}

__asm void Assl_closessl(register __a0 struct Assl *assl)
{  if(assl && assl->amisslbase)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      if(assl->ssl)
      {  /* SSL_Shutdown(assl->ssl); */
         SSL_free(assl->ssl);
         assl->ssl=NULL;
      }
      if(assl->sslctx)
      {  SSL_CTX_free(assl->sslctx);
         assl->sslctx=NULL;
      }
   }
}

__asm long Assl_connect(register __a0 struct Assl *assl,
   register __d0 long sock,
   register __a1 UBYTE *hostname)
{  long result=ASSLCONNECT_FAIL;
   if(assl && assl->amisslbase && assl->ssl && sock>=0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      assl->hostname=hostname;
      if(SSL_set_fd(assl->ssl,sock))
      {  
         /* Set Server Name Indication (SNI) for TLS handshake */
         /* This is required for modern HTTPS servers */
         /* SSL_set1_host is the recommended OpenSSL 1.1.0+ function for SNI */
         if(hostname && *hostname && assl->ssl)
         {  
            /* Set the hostname for SNI - returns 0 on success, 1 on error */
            SSL_set1_host(assl->ssl, (char *)hostname);
         }
         
         if(SSL_connect(assl->ssl)>=0)
         {  result=ASSLCONNECT_OK;
         }
         else if(assl->denied)
         {  result=ASSLCONNECT_DENIED;
         }
      }
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
   if(assl && assl->amisslbase && assl->ssl && buffer && length>0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      result=SSL_write(assl->ssl,buffer,length);
   }
   return result;
}

__asm long Assl_read(register __a0 struct Assl *assl,
   register __a1 char *buffer,
   register __d0 long length)
{  long result=-1;
   if(assl && assl->amisslbase && assl->ssl && buffer && length>0)
   {  struct Library *AmiSSLBase=assl->amisslbase;
      result=SSL_read(assl->ssl,buffer,length);
   }
   return result;
}

__asm char *Assl_getcipher(register __a0 struct Assl *assl)
{  char *result=NULL;
   if(assl && assl->amisslbase && assl->ssl)
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
