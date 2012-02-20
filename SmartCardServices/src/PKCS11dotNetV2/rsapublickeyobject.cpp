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

#include "rsapublickeyobject.h"

RSAPublicKeyObject :: RSAPublicKeyObject() : PublicKeyObject()
{
   this->_modulus    = NULL_PTR;
   this->_modulusLen = 0;
   this->_exponent   = NULL_PTR;

   this->_keyType        = CKK_RSA;
}

RSAPublicKeyObject :: ~RSAPublicKeyObject()
{
   if(this->_modulus != NULL_PTR)
      delete this->_modulus;

   if(this->_exponent != NULL_PTR)
      delete this->_exponent;
}

CK_BBOOL RSAPublicKeyObject ::Compare(CK_ATTRIBUTE attribute)
{
   switch(attribute.type){

        case CKA_MODULUS:
           return Util::CompareU1Arrays(this->_modulus,attribute.pValue,attribute.ulValueLen);

        case CKA_MODULUS_BITS:
           return (this->_modulusLen == *(CK_ULONG*)attribute.pValue);

        case CKA_PUBLIC_EXPONENT:
           return Util::CompareU1Arrays(this->_modulus,attribute.pValue,attribute.ulValueLen);

        default:
           return PublicKeyObject::Compare(attribute);
   }
}

CK_RV RSAPublicKeyObject ::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   switch(attribute->type){

        case CKA_MODULUS:
           return StorageObject::PutU1ArrayInAttribute(this->_modulus,attribute);

        case CKA_MODULUS_BITS:
           return StorageObject::PutULongInAttribute(this->_modulusLen,attribute);

        case CKA_PUBLIC_EXPONENT:
           return StorageObject::PutU1ArrayInAttribute(this->_exponent,attribute);

        default:
           return PublicKeyObject::GetAttribute(attribute);
   }
}

CK_RV RSAPublicKeyObject ::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   CK_RV rv = CKR_OK;

   if(objCreation == CK_FALSE){
      switch(attribute.type){
            case CKA_PUBLIC_EXPONENT:
            case CKA_MODULUS:
            case CKA_MODULUS_BITS:
               return CKR_ATTRIBUTE_READ_ONLY;
      }
   }

   switch(attribute.type){

        case CKA_MODULUS:
           if(this->_modulus != NULL_PTR){
              delete this->_modulus;
           }
           this->_modulus = StorageObject::ReadU1ArrayFromAttribute(attribute);
           this->_modulusLen = _modulus->GetLength()*8;
           break;

        case CKA_PUBLIC_EXPONENT:
           if(this->_exponent != NULL_PTR){
              delete this->_exponent;
           }
           this->_exponent = StorageObject::ReadU1ArrayFromAttribute(attribute);
           break;

        case CKA_MODULUS_BITS:
           {
              CK_ULONG utemp = StorageObject::ReadULongFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_modulusLen = utemp;}
           }
           break;

        default:
           return PublicKeyObject::SetAttribute(attribute,objCreation);
   }

   return rv;
}

void RSAPublicKeyObject ::Serialize(std::vector<u1> *to)
{
   PublicKeyObject::Serialize(to);

   Util::PushByteArrayInVector(to,this->_modulus);

   Util::PushByteArrayInVector(to,this->_exponent);

   Util::PushULongInVector(to,this->_modulusLen);
}

void RSAPublicKeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
   PublicKeyObject::Deserialize(from,idx);

   this->_modulus = Util::ReadByteArrayFromVector(from,idx);

   this->_exponent = Util::ReadByteArrayFromVector(from,idx);

   this->_modulusLen = Util::ReadULongFromVector(from,idx);
}

