/*
 *  PKCS#11 library for .Net smart cards
 *  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "stdafx.h"
#include "platconfig.h"
#include "config.h"
#include "util.h"

#include "publickeyobject.h"

PublicKeyObject :: PublicKeyObject() : KeyObject()
{
   this->_class         = CKO_PUBLIC_KEY;

   this->_encrypt       = CK_TRUE;
   this->_verify        = CK_TRUE;
   this->_verifyRecover = CK_TRUE;
   this->_wrap          = CK_FALSE;

   this->_subject       = NULL_PTR;

   this->_ctrIndex = 0xFF; //-1;
   this->_keyType  = CK_UNAVAILABLE_INFORMATION; //-1;
}

PublicKeyObject :: ~PublicKeyObject(){

   if(this->_subject != NULL_PTR){
      delete this->_subject;
   }
}

CK_BBOOL PublicKeyObject::Compare(CK_ATTRIBUTE attribute)
{
   switch(attribute.type){

        case CKA_ENCRYPT:
           return (this->_encrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_VERIFY:
           return (this->_verify == *(CK_BBOOL*)attribute.pValue);

        case CKA_VERIFY_RECOVER:
           return (this->_verifyRecover == *(CK_BBOOL*)attribute.pValue);

        case CKA_WRAP:
           return (this->_wrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_SUBJECT:
           return Util::CompareU1Arrays(this->_subject,attribute.pValue,attribute.ulValueLen);

        default:
           return KeyObject::Compare(attribute);
   }
}

CK_RV PublicKeyObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   switch(attribute->type){

        case CKA_ENCRYPT:
           return StorageObject::PutBBoolInAttribute(this->_encrypt,attribute);

        case CKA_VERIFY:
           return StorageObject::PutBBoolInAttribute(this->_verify,attribute);

        case CKA_VERIFY_RECOVER:
           return StorageObject::PutBBoolInAttribute(this->_verifyRecover,attribute);

        case CKA_WRAP:
           return StorageObject::PutBBoolInAttribute(this->_wrap,attribute);

        case CKA_SUBJECT:
           return StorageObject::PutU1ArrayInAttribute(this->_subject,attribute);

        default:
           return KeyObject::GetAttribute(attribute);

   }
}

CK_RV PublicKeyObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   CK_RV rv = CKR_OK;

   if(objCreation == CK_FALSE){
      switch(attribute.type){
            case CKA_ENCRYPT:
            case CKA_TRUSTED:
            case CKA_VERIFY:
            case CKA_VERIFY_RECOVER:
            case CKA_WRAP:
               if(*(CK_BBOOL*)attribute.pValue == CK_TRUE){
                  return CKR_ATTRIBUTE_READ_ONLY;
               }
               break;
      }
   }

   switch(attribute.type){

        case CKA_ENCRYPT:
           {
              CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_encrypt = btemp; }
           }
           break;

        case CKA_VERIFY:
           {
              CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_verify = btemp; }
           }
           break;

        case CKA_VERIFY_RECOVER:
           {
              CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_verifyRecover = btemp; }
           }
           break;

        case CKA_WRAP:
           {
              CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_wrap = btemp; }
           }
           break;

        case CKA_SUBJECT:
           if(this->_subject != NULL_PTR){
              delete this->_subject;
           }
           this->_subject = StorageObject::ReadU1ArrayFromAttribute(attribute);
           break;

        default:
           return KeyObject::SetAttribute(attribute,objCreation);
   }

   return rv;
}

void PublicKeyObject::Serialize(std::vector<u1> *to)
{
   KeyObject::Serialize(to);

   Util::PushBBoolInVector(to,this->_encrypt);

   Util::PushBBoolInVector(to,this->_verify);

   Util::PushBBoolInVector(to,this->_verifyRecover);

   Util::PushBBoolInVector(to,this->_wrap);

   Util::PushByteArrayInVector(to,this->_subject);

   // serialize the extra fields
   Util::PushBBoolInVector(to,this->_ctrIndex);

   Util::PushBBoolInVector(to,this->_keySpec);
}

void PublicKeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
   KeyObject::Deserialize(from,idx);

   this->_encrypt = Util::ReadBBoolFromVector(from,idx);

   this->_verify = Util::ReadBBoolFromVector(from,idx);

   this->_verifyRecover = Util::ReadBBoolFromVector(from,idx);

   this->_wrap = Util::ReadBBoolFromVector(from,idx);

   this->_subject = Util::ReadByteArrayFromVector(from,idx);

   // deserialize extra fields
   this->_ctrIndex = Util::ReadBBoolFromVector(from,idx);

   this->_keySpec = Util::ReadBBoolFromVector(from,idx);
}

