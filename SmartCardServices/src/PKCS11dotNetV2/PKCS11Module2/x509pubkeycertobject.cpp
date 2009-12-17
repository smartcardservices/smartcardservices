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

#include "x509pubkeycertobject.h"

X509PubKeyCertObject::X509PubKeyCertObject() : CertificateObject()
{
    this->_subject              = NULL_PTR;
    this->_id                   = NULL_PTR;
    this->_issuer               = NULL_PTR;
    this->_serialNumber         = NULL_PTR;
    this->_value                = NULL_PTR;
    this->_url                  = NULL_PTR;
    this->_hashOfSubjectPubKey  = NULL_PTR;
    this->_hashOfIssuerPubKey   = NULL_PTR;

    this->_certType             = CKC_X_509;
    this->_trusted              = CK_TRUE;
}

X509PubKeyCertObject::~X509PubKeyCertObject()
{
    if(this->_subject != NULL_PTR)
        delete this->_subject;

    if(this->_id != NULL_PTR)
        delete this->_id;

    if(this->_issuer != NULL_PTR)
        delete this->_issuer;

    if(this->_serialNumber != NULL_PTR)
        delete this->_serialNumber;

    if(this->_value != NULL_PTR)
        delete this->_value;

    if(this->_url != NULL_PTR)
        delete this->_url;

    if(this->_hashOfSubjectPubKey != NULL_PTR)
        delete this->_hashOfSubjectPubKey;

    if(this->_hashOfIssuerPubKey != NULL_PTR)
        delete this->_hashOfIssuerPubKey;

}

CK_BBOOL X509PubKeyCertObject::Compare(CK_ATTRIBUTE attribute)
{
    switch(attribute.type){

        case CKA_SUBJECT:
            return Util::CompareU1Arrays(this->_subject,attribute.pValue,attribute.ulValueLen);

        case CKA_ID:
            return Util::CompareU1Arrays(this->_id,attribute.pValue,attribute.ulValueLen);

        case CKA_ISSUER:
            return Util::CompareU1Arrays(this->_issuer,attribute.pValue,attribute.ulValueLen);

        case CKA_SERIAL_NUMBER:
            return Util::CompareU1Arrays(this->_serialNumber,attribute.pValue,attribute.ulValueLen);

        case CKA_VALUE:
            return Util::CompareU1Arrays(this->_value,attribute.pValue,attribute.ulValueLen);

        case CKA_URL:
            return Util::CompareU1Arrays(this->_url,attribute.pValue,attribute.ulValueLen);

        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
            return Util::CompareU1Arrays(this->_hashOfSubjectPubKey,attribute.pValue,attribute.ulValueLen);

        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
            return Util::CompareU1Arrays(this->_hashOfIssuerPubKey,attribute.pValue,attribute.ulValueLen);

        default:
            return CertificateObject::Compare(attribute);
    }
}

CK_RV X509PubKeyCertObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   CK_RV rv = CKR_OK;

    if(objCreation == CK_FALSE){
        switch(attribute.type){
            case CKA_SUBJECT:
            case CKA_VALUE:
                return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    switch(attribute.type){

        case CKA_SUBJECT:
            if(this->_subject != NULL_PTR){
                delete this->_subject;
            }
            this->_subject = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_ID:
            if(this->_id != NULL_PTR){
                delete this->_id;
            }
            this->_id = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_ISSUER:
            if(this->_issuer != NULL_PTR){
                delete this->_issuer;
            }
            this->_issuer = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_SERIAL_NUMBER:
            if(this->_serialNumber != NULL_PTR){
                delete this->_serialNumber;
            }
            this->_serialNumber = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_VALUE:
            if(this->_value != NULL_PTR){
                delete this->_value;
            }
            this->_value = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_URL:
            {
                u1Array* stemp = StorageObject::ReadStringFromAttribute(attribute,&rv);
                if(rv == CKR_OK){
                    if(this->_url != NULL_PTR){
                        delete this->_url;
                    }
                    this->_url = stemp;
                }
            }
            break;

        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
            if(this->_hashOfSubjectPubKey != NULL_PTR){
                delete this->_hashOfSubjectPubKey;
            }
            this->_hashOfSubjectPubKey = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
            if(this->_hashOfIssuerPubKey != NULL_PTR){
                delete this->_hashOfIssuerPubKey;
            }
            this->_hashOfIssuerPubKey = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        default:
            return CertificateObject::SetAttribute(attribute,objCreation);
    }

    return rv;
}

CK_RV X509PubKeyCertObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

        case CKA_SUBJECT:
            return StorageObject::PutU1ArrayInAttribute(this->_subject,attribute);

        case CKA_ID:
            return StorageObject::PutU1ArrayInAttribute(this->_id,attribute);

        case CKA_ISSUER:
            return StorageObject::PutU1ArrayInAttribute(this->_issuer,attribute);

        case CKA_SERIAL_NUMBER:
            return StorageObject::PutU1ArrayInAttribute(this->_serialNumber,attribute);

        case CKA_VALUE:
            return StorageObject::PutU1ArrayInAttribute(this->_value,attribute);

        case CKA_URL:
            return StorageObject::PutU1ArrayInAttribute(this->_url,attribute);

        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
            return StorageObject::PutU1ArrayInAttribute(this->_hashOfSubjectPubKey,attribute);

        case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
            return StorageObject::PutU1ArrayInAttribute(this->_hashOfIssuerPubKey,attribute);

        default:
            return CertificateObject::GetAttribute(attribute);
    }
}

void X509PubKeyCertObject::Serialize(std::vector<u1> *to)
{
    CertificateObject::Serialize(to);

    Util::PushByteArrayInVector(to,this->_subject);

    Util::PushByteArrayInVector(to,this->_id);

    Util::PushByteArrayInVector(to,this->_issuer);

    Util::PushByteArrayInVector(to,this->_serialNumber);

    Util::PushByteArrayInVector(to,this->_url);

    Util::PushByteArrayInVector(to,this->_hashOfSubjectPubKey);

    Util::PushByteArrayInVector(to,this->_hashOfIssuerPubKey);

    PKCS11_ASSERT(!this->_certName.empty());

}

void X509PubKeyCertObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CertificateObject::Deserialize(from,idx);

    this->_subject = Util::ReadByteArrayFromVector(from,idx);

    this->_id = Util::ReadByteArrayFromVector(from,idx);

    this->_issuer = Util::ReadByteArrayFromVector(from,idx);

    this->_serialNumber = Util::ReadByteArrayFromVector(from,idx);

    this->_url = Util::ReadByteArrayFromVector(from,idx);

    this->_hashOfSubjectPubKey = Util::ReadByteArrayFromVector(from,idx);

    this->_hashOfIssuerPubKey = Util::ReadByteArrayFromVector(from,idx);

}

