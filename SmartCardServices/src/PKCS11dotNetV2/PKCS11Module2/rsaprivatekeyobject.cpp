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

#include "rsaprivatekeyobject.h"

RSAPrivateKeyObject :: RSAPrivateKeyObject() : PrivateKeyObject()
{
    this->_modulus        = NULL_PTR;
    this->_publicExponent = NULL_PTR;
    this->_d              = NULL_PTR;
    this->_p              = NULL_PTR;
    this->_q              = NULL_PTR;
    this->_dp             = NULL_PTR;
    this->_dq             = NULL_PTR;
    this->_inverseQ       = NULL_PTR;

    this->_keyType        = CKK_RSA;

}

RSAPrivateKeyObject :: ~RSAPrivateKeyObject()
{
    if(this->_modulus != NULL_PTR){
        delete this->_modulus;
    }

    if(this->_publicExponent != NULL_PTR){
        delete this->_publicExponent;
    }

    if(this->_d != NULL_PTR){
        delete this->_d;
    }

    if(this->_p != NULL_PTR){
        delete this->_p;
    }

    if(this->_q != NULL_PTR){
        delete this->_q;
    }

    if(this->_dp != NULL_PTR){
        delete this->_dp;
    }

    if(this->_dq != NULL_PTR){
        delete this->_dq;
    }

    if(this->_inverseQ != NULL_PTR){
        delete this->_inverseQ;
    }
}

CK_BBOOL RSAPrivateKeyObject ::Compare(CK_ATTRIBUTE attribute)
{
    switch(attribute.type){

        case CKA_MODULUS:
            return Util::CompareU1Arrays(this->_modulus,attribute.pValue,attribute.ulValueLen);

        case CKA_PUBLIC_EXPONENT:
            return Util::CompareU1Arrays(this->_publicExponent,attribute.pValue,attribute.ulValueLen);

        case CKA_PRIVATE_EXPONENT:
            return Util::CompareU1Arrays(this->_d,attribute.pValue,attribute.ulValueLen);

        case CKA_PRIME_1:
            return Util::CompareU1Arrays(this->_p,attribute.pValue,attribute.ulValueLen);

        case CKA_PRIME_2:
            return Util::CompareU1Arrays(this->_q,attribute.pValue,attribute.ulValueLen);

        case CKA_EXPONENT_1:
            return Util::CompareU1Arrays(this->_dp,attribute.pValue,attribute.ulValueLen);

        case CKA_EXPONENT_2:
            return Util::CompareU1Arrays(this->_dq,attribute.pValue,attribute.ulValueLen);

        case CKA_COEFFICIENT:
            return Util::CompareU1Arrays(this->_inverseQ,attribute.pValue,attribute.ulValueLen);

        default:
            return PrivateKeyObject::Compare(attribute);
    }
}

CK_RV RSAPrivateKeyObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

    if(objCreation == CK_FALSE){
        switch(attribute.type){
            case CKA_PUBLIC_EXPONENT:
            case CKA_MODULUS:
            case CKA_PRIVATE_EXPONENT:
            case CKA_PRIME_1:
            case CKA_PRIME_2:
            case CKA_EXPONENT_1:
            case CKA_EXPONENT_2:
            case CKA_COEFFICIENT:
                return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    switch(attribute.type){

         case CKA_MODULUS:
            if(this->_modulus != NULL_PTR){
                delete this->_modulus;
            }
            this->_modulus = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

         case CKA_PUBLIC_EXPONENT:
            if(this->_publicExponent != NULL_PTR){
                delete this->_publicExponent;
            }
            this->_publicExponent = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

         case CKA_PRIVATE_EXPONENT:
            if(this->_d != NULL_PTR){
                delete this->_d;
            }
            this->_d = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

         case CKA_EXPONENT_1:
            if(this->_dp != NULL_PTR){
                delete this->_dp;
            }
            this->_dp = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;


         case CKA_EXPONENT_2:
            if(this->_dq != NULL_PTR){
                delete this->_dq;
            }
            this->_dq = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;


         case CKA_PRIME_1:
            if(this->_p != NULL_PTR){
                delete this->_p;
            }
            this->_p = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;


         case CKA_PRIME_2:
            if(this->_q != NULL_PTR){
                delete this->_q;
            }
            this->_q = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;


         case CKA_COEFFICIENT:
            if( this->_inverseQ != NULL_PTR )
            {
                delete this->_inverseQ;
            }
            this->_inverseQ = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

         default:
             return PrivateKeyObject::SetAttribute(attribute,objCreation);

    }

    return CKR_OK;
}

CK_RV RSAPrivateKeyObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

        case CKA_MODULUS:
            return StorageObject::PutU1ArrayInAttribute(this->_modulus,attribute);

        case CKA_PUBLIC_EXPONENT:
            return StorageObject::PutU1ArrayInAttribute(this->_publicExponent,attribute);

        case CKA_PRIVATE_EXPONENT:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_d,attribute);

        case CKA_PRIME_1:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_p,attribute);

        case CKA_PRIME_2:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_q,attribute);

        case CKA_EXPONENT_1:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_dp,attribute);

        case CKA_EXPONENT_2:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_dq,attribute);

        case CKA_COEFFICIENT:
            if(this->_sensitive == CK_TRUE || this->_extractable == CK_FALSE){
                attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            return StorageObject::PutU1ArrayInAttribute(this->_inverseQ,attribute);

        default:
            return PrivateKeyObject::GetAttribute(attribute);
    }
}

void RSAPrivateKeyObject::Serialize(std::vector<u1> *to)
{
    PrivateKeyObject::Serialize(to);

    // since keys will reside in the key container we are not going
    // to marshal the key values except modulus and public exponent

    Util::PushByteArrayInVector(to,this->_modulus);

    Util::PushByteArrayInVector(to,this->_publicExponent);
}

void RSAPrivateKeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
    PrivateKeyObject::Deserialize(from,idx);

    this->_modulus = Util::ReadByteArrayFromVector(from,idx);

    this->_publicExponent = Util::ReadByteArrayFromVector(from,idx);
}



