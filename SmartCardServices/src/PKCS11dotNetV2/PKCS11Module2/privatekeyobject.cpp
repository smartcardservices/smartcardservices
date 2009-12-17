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

#include "privatekeyobject.h"

PrivateKeyObject :: PrivateKeyObject() : KeyObject()
{
    this->_class                = CKO_PRIVATE_KEY;

    this->_subject              = NULL_PTR;
    this->_sensitive            = CK_TRUE;
    this->_decrypt              = CK_TRUE;
    this->_sign                 = CK_TRUE;
    this->_signRecover          = CK_TRUE;
    this->_unwrap               = CK_FALSE;
    this->_extractable          = CK_FALSE;
    this->_alwaysSensitive      = CK_TRUE;
    this->_neverExtractable     = CK_TRUE;
    this->_wrapWithTrusted      = CK_FALSE;
    this->_alwaysAuthenticate   = CK_FALSE;

    this->_ctrIndex = 0xFF; //-1;
    this->_keyType  = CK_UNAVAILABLE_INFORMATION; //-1;
}

PrivateKeyObject :: ~PrivateKeyObject(){

    if(this->_subject != NULL_PTR){
        delete this->_subject;
    }
}

bool PrivateKeyObject::IsEqual(const StorageObject * that) const
{
    if(_uniqueId != 0 && that->_uniqueId != 0)
        return (_uniqueId == that->_uniqueId);

    // Only objects that have been stored under p11 directory
    // will have a non-zero _uniqueId. For other objects, do
    // a deep comparison based on other attributes.
    if(_class != that->_class)
        return false;

    const PrivateKeyObject * thatCert = static_cast<const PrivateKeyObject*>(that);
    return ( (_ctrIndex == thatCert->_ctrIndex) &&
             (_keySpec == thatCert->_keySpec) &&
             (_checkValue == thatCert->_checkValue));
}

CK_BBOOL PrivateKeyObject::Compare(CK_ATTRIBUTE attribute)
{
    switch(attribute.type){

        case CKA_SENSITIVE:
            return (this->_sensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_DECRYPT:
            return (this->_decrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN:
            return (this->_sign == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN_RECOVER:
            return (this->_signRecover == *(CK_BBOOL*)attribute.pValue);

        case CKA_UNWRAP:
            return (this->_unwrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_EXTRACTABLE:
            return (this->_extractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_SENSITIVE:
            return (this->_alwaysSensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_NEVER_EXTRACTABLE:
            return (this->_neverExtractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_WRAP_WITH_TRUSTED:
            return (this->_wrapWithTrusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_AUTHENTICATE:
            return (this->_alwaysAuthenticate == *(CK_BBOOL*)attribute.pValue);

        case CKA_SUBJECT:
            return Util::CompareU1Arrays(this->_subject,attribute.pValue,attribute.ulValueLen);

        default:
            return KeyObject::Compare(attribute);

    }
}

CK_RV PrivateKeyObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

        case CKA_SENSITIVE:
            return StorageObject::PutBBoolInAttribute(this->_sensitive,attribute);

        case CKA_DECRYPT:
            return StorageObject::PutBBoolInAttribute(this->_decrypt,attribute);

        case CKA_SIGN:
            return StorageObject::PutBBoolInAttribute(this->_sign,attribute);

        case CKA_SIGN_RECOVER:
            return StorageObject::PutBBoolInAttribute(this->_signRecover,attribute);

        case CKA_UNWRAP:
            return StorageObject::PutBBoolInAttribute(this->_unwrap,attribute);

        case CKA_EXTRACTABLE:
            return StorageObject::PutBBoolInAttribute(this->_extractable,attribute);

        case CKA_ALWAYS_SENSITIVE:
            return StorageObject::PutBBoolInAttribute(this->_alwaysSensitive,attribute);

        case CKA_NEVER_EXTRACTABLE:
            return StorageObject::PutBBoolInAttribute(this->_neverExtractable,attribute);

        case CKA_WRAP_WITH_TRUSTED:
            return StorageObject::PutBBoolInAttribute(this->_wrapWithTrusted,attribute);

        case CKA_ALWAYS_AUTHENTICATE:
            return StorageObject::PutBBoolInAttribute(this->_alwaysAuthenticate,attribute);

        case CKA_SUBJECT:
            return StorageObject::PutU1ArrayInAttribute(this->_subject,attribute);

        default:
            return KeyObject::GetAttribute(attribute);
    }
}

CK_RV PrivateKeyObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

    CK_RV rv = CKR_OK;

    if(objCreation == CK_FALSE)
    {
        switch(attribute.type)
        {
            case CKA_ALWAYS_AUTHENTICATE:
            case CKA_ALWAYS_SENSITIVE:
            case CKA_NEVER_EXTRACTABLE:
                return CKR_ATTRIBUTE_READ_ONLY;

            case CKA_DECRYPT:
            case CKA_EXTRACTABLE:
            case CKA_SENSITIVE:
            case CKA_SIGN:
            case CKA_SIGN_RECOVER:
            case CKA_UNWRAP:
            case CKA_WRAP_WITH_TRUSTED:
                if(*(CK_BBOOL*)attribute.pValue == CK_TRUE){
                    return CKR_ATTRIBUTE_READ_ONLY;
                }
                break;
        }
    }

    switch(attribute.type){

        case CKA_SENSITIVE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){

                    if((objCreation == CK_FALSE) && (this->_sensitive == CK_TRUE) && (btemp == CK_FALSE)){
                        rv = CKR_ATTRIBUTE_READ_ONLY;
                    }else{
                        this->_sensitive = btemp;

                        if(btemp == CK_FALSE){
                            this->_alwaysSensitive = CK_FALSE;
                        }
                    }
                }
            }
            break;

        case CKA_DECRYPT:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_decrypt = btemp; }
            }
            break;

        case CKA_SIGN:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_sign = btemp; }
            }
            break;

        case CKA_SIGN_RECOVER:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_signRecover = btemp; }
            }
            break;

        case CKA_UNWRAP:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_unwrap = btemp; }
            }
            break;

        case CKA_EXTRACTABLE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){

                    if((objCreation == CK_FALSE) && (this->_extractable == CK_FALSE) && (btemp == CK_TRUE)){
                        rv = CKR_ATTRIBUTE_READ_ONLY;
                    }else{
                        this->_extractable = btemp;

                        if(btemp == CK_TRUE){
                            this->_neverExtractable = CK_FALSE;
                        }
                    }
                }
            }
            break;

        case CKA_ALWAYS_SENSITIVE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_alwaysSensitive = btemp; }
            }
            break;


        case CKA_NEVER_EXTRACTABLE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_neverExtractable = btemp; }
            }
            break;

        case CKA_WRAP_WITH_TRUSTED:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_wrapWithTrusted = btemp; }
            }
            break;

        case CKA_ALWAYS_AUTHENTICATE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_alwaysAuthenticate = btemp; }
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

void PrivateKeyObject::Serialize(std::vector<u1> *to)
{
    KeyObject::Serialize(to);

    Util::PushBBoolInVector(to,this->_sensitive);

    Util::PushBBoolInVector(to,this->_decrypt);

    Util::PushBBoolInVector(to,this->_sign);

    Util::PushBBoolInVector(to,this->_signRecover);

    Util::PushBBoolInVector(to,this->_unwrap);

    Util::PushBBoolInVector(to,this->_extractable);

    Util::PushBBoolInVector(to,this->_alwaysSensitive);

    Util::PushBBoolInVector(to,this->_neverExtractable);

    Util::PushBBoolInVector(to,this->_wrapWithTrusted);

    Util::PushBBoolInVector(to,this->_alwaysAuthenticate);

    Util::PushByteArrayInVector(to,this->_subject);

    // serialize the extra fields

    PKCS11_ASSERT(_checkValue != 0);
    PKCS11_ASSERT(_ctrIndex < 100);
    PKCS11_ASSERT(_keySpec == 1 || _keySpec == 2 );

    Util::PushULongLongInVector(to,this->_checkValue);

    Util::PushBBoolInVector(to,this->_ctrIndex);

    Util::PushBBoolInVector(to,this->_keySpec);
}

void PrivateKeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
    KeyObject::Deserialize(from,idx);

    this->_sensitive = Util::ReadBBoolFromVector(from,idx);

    this->_decrypt = Util::ReadBBoolFromVector(from,idx);

    this->_sign = Util::ReadBBoolFromVector(from,idx);

    this->_signRecover = Util::ReadBBoolFromVector(from,idx);

    this->_unwrap = Util::ReadBBoolFromVector(from,idx);

    this->_extractable = Util::ReadBBoolFromVector(from,idx);

    this->_alwaysSensitive = Util::ReadBBoolFromVector(from,idx);

    this->_neverExtractable = Util::ReadBBoolFromVector(from,idx);

    this->_wrapWithTrusted = Util::ReadBBoolFromVector(from,idx);

    this->_alwaysAuthenticate = Util::ReadBBoolFromVector(from,idx);

    this->_subject = Util::ReadByteArrayFromVector(from,idx);

    // deserialize extra fields

    this->_checkValue = Util::ReadULongLongFromVector(from,idx);

    this->_ctrIndex = Util::ReadBBoolFromVector(from,idx);

    this->_keySpec = Util::ReadBBoolFromVector(from,idx);
}

