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

/* jerror.c - AWeb js Error object */

#include "awebjs.h"
#include "jprotos.h"

/* Helper function to get prototype object */
static struct Jobject *Getprototype(struct Jobject *jo)
{  struct Variable *proto;
   if((proto=Findproperty(jo,"prototype"))
   && proto->val.type==VTP_OBJECT && proto->val.value.obj.ovalue)
   {  return proto->val.value.obj.ovalue;
   }
   return NULL;
}

/* Find the string value of Nth argument */
static UBYTE *Strargument(struct Jcontext *jc,long n)
{  struct Variable *var;
   for(var=jc->functions.first->local.first;n && var->next;var=var->next,n--);
   if(var->next)
   {  Tostring(&var->val,jc);
      return var->val.value.svalue;
   }
   return "";
}

/*--------------------------------------------------------------------------------*/

static void Errortostring(struct Jcontext *jc)
{  struct Jobject *jo=jc->jthis;
   struct Variable *var;
   struct Jbuffer *bf;
   if((bf=Newjbuffer(jc->pool)))
   {  if((var=Findproperty(jo,"name")))
      {  Tostring(&var->val,jc);
         Addtojbuffer(bf,var->val.value.svalue,-1);
      }
      if((var=Findproperty(jo,"message")))
      {  Tostring(&var->val,jc);
         if(*var->val.value.svalue!='\0')
         {  Addtojbuffer(bf,": ",-1);
            Addtojbuffer(bf,var->val.value.svalue,-1);
         }
      }
      Asgstring(RETVAL(jc),bf->buffer,jc->pool);
      Freejbuffer(bf);
   }
   else
   {  Asgstring(RETVAL(jc),"",jc->pool);
   }
}

/*-----------------------------------------------------------------------*/

/* Make (jthis) a new Error object */
static void Constructor(struct Jcontext *jc)
{  struct Jobject *jo=jc->jthis;
   struct Variable *arg;
   arg=jc->functions.first->local.first;
   if(jo && (jc->flags&EXF_CONSTRUCT))
   {  jo->type=OBJT_ERROR;
      if(arg->next && arg->val.type!=VTP_UNDEFINED)
      {  struct Variable *var;
         Tostring(&arg->val,jc);
         if((var=Addproperty(jo,"message")))
         {  Asgvalue(&var->val,&arg->val);
         }
      }
   }
   else if(!(jc->flags&EXF_CONSTRUCT))
   {  /* Called as function */
      UBYTE *p=NULL;
      if(arg->next && arg->val.type!=VTP_UNDEFINED)
      {  Tostring(&arg->val,jc);
         p=arg->val.value.svalue;
      }
      if((jo=Newerror(jc,p)))
      {  Asgobject(RETVAL(jc),jo);
      }
   }
}

/*-----------------------------------------------------------------------*/

__asm __saveds void Initerror(
   register __a0 struct Jcontext *jc,
   register __a1 struct Jobject *jscope)
{  struct Jobject *jerror,*jo,*f,*p;
   struct Variable *prop;
   if(jerror=Internalfunction(jc,"Error",(void (*)(void *))Constructor,"errorMessage",NULL))
   {  Initconstruct(jc,jerror,jc->object);
      Addprototype(jc,jerror);
      if(jscope && (prop=Addproperty(jscope,"Error")))
      {  Asgobject(&prop->val,jerror);
         prop->flags|=VARF_DONTDELETE;
      }
      p=Getprototype(jerror);
      if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
      {  Addtoprototype(jc,jerror,f);
      }
      if(p && (prop=Addproperty(p,"message")))
      {  Asgstring(&prop->val,"",jc->pool);
      }
      if(p && (prop=Addproperty(p,"name")))
      {  Asgstring(&prop->val,"Error",jc->pool);
      }
      /* Create native error types */
      if(jo=Internalfunction(jc,NTE_TYPE,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_TYPE)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_TYPE,jc->pool);
         }
         jc->nativeErrors[0]=jo;
         Keepobject(jo,TRUE);
      }
      if(jo=Internalfunction(jc,NTE_EVAL,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_EVAL)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_EVAL,jc->pool);
         }
         jc->nativeErrors[1]=jo;
         Keepobject(jo,TRUE);
      }
      if(jo=Internalfunction(jc,NTE_RANGE,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_RANGE)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_RANGE,jc->pool);
         }
         jc->nativeErrors[2]=jo;
         Keepobject(jo,TRUE);
      }
      if(jo=Internalfunction(jc,NTE_SYNTAX,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_SYNTAX)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_SYNTAX,jc->pool);
         }
         jc->nativeErrors[3]=jo;
         Keepobject(jo,TRUE);
      }
      if(jo=Internalfunction(jc,NTE_REFERENCE,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_REFERENCE)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_REFERENCE,jc->pool);
         }
         jc->nativeErrors[4]=jo;
         Keepobject(jo,TRUE);
      }
      if(jo=Internalfunction(jc,NTE_URI,(void (*)(void *))Constructor,"errorMessage",NULL))
      {  Addprototype(jc,jo);
         if(jscope && (prop=Addproperty(jscope,NTE_URI)))
         {  Asgobject(&prop->val,jo);
            prop->flags|=VARF_DONTDELETE;
         }
         p=Getprototype(jo);
         if(f=Internalfunction(jc,"toString",(void (*)(void *))Errortostring,NULL))
         {  Addtoprototype(jc,jo,f);
         }
         if(p && (prop=Addproperty(p,"message")))
         {  Asgstring(&prop->val,"",jc->pool);
         }
         if(p && (prop=Addproperty(p,"name")))
         {  Asgstring(&prop->val,NTE_URI,jc->pool);
         }
         jc->nativeErrors[5]=jo;
         Keepobject(jo,TRUE);
      }
      jc->error=jerror;
      Keepobject(jerror,TRUE);
   }
}

__asm __saveds struct Jobject *Newerror(
   register __a0 struct Jcontext *jc,
   register __a1 UBYTE *message)
{  struct Jobject *jo=NULL;
   if((jo=Newobject(jc)))
   {  Initconstruct(jc,jo,jc->error);
      if(message)
      {  struct Variable *var;
         if((var=Addproperty(jo,"message")))
         {  Asgstring(&var->val,message,jc->pool);
         }
      }
   }
   return jo;
}

__asm __saveds struct Jobject *Newnativeerror(
   register __a0 struct Jcontext *jc,
   register __a1 UBYTE *type,
   register __a2 UBYTE *message)
{  struct Jobject *jo=NULL;
   struct Jobject *constructor=NULL;
   long i;
   /* Find the native error constructor */
   for(i=0;i<NUM_ERRORTYPES;i++)
   {  if(jc->nativeErrors[i])
      {  struct Variable *var;
         if((var=Findproperty(jc->nativeErrors[i],"name")))
         {  Tostring(&var->val,jc);
            if(STREQUAL(var->val.value.svalue,type))
            {  constructor=jc->nativeErrors[i];
               break;
            }
         }
      }
   }
   if((jo=Newobject(jc)))
   {  if(constructor)
      {  Initconstruct(jc,jo,constructor);
      }
      else
      {  Initconstruct(jc,jo,jc->error);
      }
      if(message)
      {  struct Variable *var;
         if((var=Addproperty(jo,"message")))
         {  Asgstring(&var->val,message,jc->pool);
         }
      }
   }
   return jo;
}

