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

#include "secretkeyobject.h"

SecretKeyObject::SecretKeyObject() : KeyObject()
{
   this->_sensitive        = CK_FALSE;
   this->_encrypt          = CK_FALSE;
   this->_decrypt          = CK_FALSE;
   this->_sign             = CK_FALSE;
   this->_verify           = CK_FALSE;
   this->_wrap             = CK_FALSE;
   this->_unwrap           = CK_FALSE;
   this->_extractable      = CK_FALSE;
   this->_alwaysSensitive  = CK_FALSE;
   this->_neverExtractable = CK_FALSE;
   this->_checkSum         = NULL_PTR;
   this->_wrapWithTrusted  = CK_FALSE;
   this->_trusted          = CK_FALSE;

   this->_value            = NULL_PTR;
   this->_valueLength      = 0;

   this->_class            = CKO_SECRET_KEY;
}

SecretKeyObject::~SecretKeyObject(){

   if(this->_value != NULL_PTR){
      delete this->_value;
   }
}

CK_BBOOL SecretKeyObject::Compare(CK_ATTRIBUTE attribute)
{
   switch(attribute.type){

        case CKA_SENSITIVE:
           return (this->_sensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_ENCRYPT:
           return (this->_encrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_DECRYPT:
           return (this->_decrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN:
           return (this->_sign == *(CK_BBOOL*)attribute.pValue);

        case CKA_VERIFY:
           return (this->_verify == *(CK_BBOOL*)attribute.pValue);

        case CKA_UNWRAP:
           return (this->_unwrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_EXTRACTABLE:
           return (this->_extractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_SENSITIVE:
           return (this->_alwaysSensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_NEVER_EXTRACTABLE:
           return (this->_neverExtractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_CHECK_VALUE:
           return Util::CompareU1Arrays(this->_checkSum,attribute.pValue,attribute.ulValueLen);

        case CKA_WRAP_WITH_TRUSTED:
           return (this->_wrapWithTrusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_TRUSTED:
           return (this->_trusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_VALUE:
           return Util::CompareU1Arrays(this->_value,attribute.pValue,attribute.ulValueLen);

        case CKA_VALUE_LEN:
           return (this->_valueLength == *(CK_ULONG*)attribute.pValue);

        default:
           return KeyObject::Compare(attribute);
   }
}

CK_RV SecretKeyObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   switch(attribute->type)
   {
   case CKA_SENSITIVE:
      return StorageObject::PutBBoolInAttribute(this->_sensitive,attribute);

   case CKA_ENCRYPT:
      return StorageObject::PutBBoolInAttribute(this->_encrypt,attribute);

   case CKA_DECRYPT:
      return StorageObject::PutBBoolInAttribute(this->_decrypt,attribute);

   case CKA_SIGN:
      return StorageObject::PutBBoolInAttribute(this->_sign,attribute);

   case CKA_VERIFY:
      return StorageObject::PutBBoolInAttribute(this->_verify,attribute);

   case CKA_UNWRAP:
      return StorageObject::PutBBoolInAttribute(this->_unwrap,attribute);

   case CKA_EXTRACTABLE:
      return StorageObject::PutBBoolInAttribute(this->_extractable,attribute);

   case CKA_ALWAYS_SENSITIVE:
      return StorageObject::PutBBoolInAttribute(this->_alwaysSensitive,attribute);

   case CKA_NEVER_EXTRACTABLE:
      return StorageObject::PutBBoolInAttribute(this->_neverExtractable,attribute);

   case CKA_CHECK_VALUE:
      return StorageObject::PutU1ArrayInAttribute(this->_checkSum,attribute);

   case CKA_WRAP_WITH_TRUSTED:
      return StorageObject::PutBBoolInAttribute(this->_wrapWithTrusted,attribute);

   case CKA_TRUSTED:
      return StorageObject::PutBBoolInAttribute(this->_trusted,attribute);

   case CKA_VALUE:
      if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
         attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
         return CKR_ATTRIBUTE_SENSITIVE;
      }
      return StorageObject::PutU1ArrayInAttribute(this->_value,attribute);

   case CKA_VALUE_LEN:
      return StorageObject::PutULongInAttribute(this->_valueLength,attribute);

   default:
      return KeyObject::GetAttribute(attribute);
   }
}

CK_RV SecretKeyObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   switch(attribute.type)
   {
   case CKA_SENSITIVE:
      this->_sensitive = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_ENCRYPT:
      this->_encrypt = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_DECRYPT:
      this->_decrypt = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_SIGN:
      this->_sign = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_VERIFY:
      this->_verify = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_UNWRAP:
      this->_unwrap = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_EXTRACTABLE:
      this->_extractable = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_ALWAYS_SENSITIVE:
      this->_alwaysSensitive = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_NEVER_EXTRACTABLE:
      this->_neverExtractable = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_CHECK_VALUE:
      if(this->_checkSum != NULL_PTR){
         delete this->_checkSum;
      }
      this->_checkSum = new u1Array(attribute.ulValueLen);
      memcpy((u1*)this->_checkSum->GetBuffer(),(CK_BYTE_PTR)attribute.pValue,attribute.ulValueLen);
      break;

   case CKA_WRAP_WITH_TRUSTED:
      this->_wrapWithTrusted = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_TRUSTED:
      this->_trusted = *(CK_BBOOL*)attribute.pValue;
      break;

   case CKA_VALUE:
      if(this->_value != NULL_PTR){
         delete this->_value;
      }
      this->_value = new u1Array(attribute.ulValueLen);
      memcpy((u1*)this->_value->GetBuffer(),(CK_BYTE_PTR)attribute.pValue,attribute.ulValueLen);
      break;

   case CKA_VALUE_LEN:
      this->_valueLength = *(CK_ULONG*)attribute.pValue;
      break;

   default:
      return KeyObject::SetAttribute(attribute,objCreation);
   }

   return CKR_OK;
}

void SecretKeyObject::Serialize(std::vector<u1> *to)
{
   KeyObject::Serialize(to);

   Util::PushBBoolInVector(to,this->_sensitive);

   Util::PushBBoolInVector(to,this->_encrypt);

   Util::PushBBoolInVector(to,this->_decrypt);

   Util::PushBBoolInVector(to,this->_sign);

   Util::PushBBoolInVector(to,this->_verify);

   Util::PushBBoolInVector(to,this->_unwrap);

   Util::PushBBoolInVector(to,this->_extractable);

   Util::PushBBoolInVector(to,this->_alwaysSensitive);

   Util::PushBBoolInVector(to,this->_neverExtractable);

   Util::PushByteArrayInVector(to,this->_checkSum);

   Util::PushBBoolInVector(to,this->_wrapWithTrusted);

   Util::PushBBoolInVector(to,this->_trusted);

   Util::PushByteArrayInVector(to,this->_value);

   Util::PushULongInVector(to,this->_valueLength);
}

void SecretKeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
   KeyObject::Deserialize(from,idx);

   this->_sensitive = Util::ReadBBoolFromVector(from,idx);

   this->_encrypt = Util::ReadBBoolFromVector(from,idx);

   this->_decrypt = Util::ReadBBoolFromVector(from,idx);

   this->_sign = Util::ReadBBoolFromVector(from,idx);

   this->_verify = Util::ReadBBoolFromVector(from,idx);

   this->_unwrap = Util::ReadBBoolFromVector(from,idx);

   this->_extractable = Util::ReadBBoolFromVector(from,idx);

   this->_alwaysSensitive = Util::ReadBBoolFromVector(from,idx);

   this->_neverExtractable = Util::ReadBBoolFromVector(from,idx);

   this->_checkSum = Util::ReadByteArrayFromVector(from,idx);

   this->_wrapWithTrusted = Util::ReadBBoolFromVector(from,idx);

   this->_trusted = Util::ReadBBoolFromVector(from,idx);

   this->_value = Util::ReadByteArrayFromVector(from,idx);

   this->_valueLength = Util::ReadULongFromVector(from,idx);
}

