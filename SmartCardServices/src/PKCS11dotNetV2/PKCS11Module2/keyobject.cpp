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

#include "keyobject.h"

KeyObject::KeyObject() : StorageObject()
{
    this->_keyType          = 0;
    this->_id               = NULL_PTR;
    this->_startDate        = NULL_PTR;
    this->_endDate          = NULL_PTR;
    this->_allowedMechanism = NULL_PTR;

    this->_local         = CK_FALSE;
    this->_mechanismType = CK_UNAVAILABLE_INFORMATION;//-1;
}

KeyObject::~KeyObject()
{
    if(this->_startDate != NULL_PTR){
        delete this->_startDate;
    }

    if(this->_endDate != NULL_PTR){
        delete this->_endDate;
    }

    if(this->_id != NULL_PTR){
        delete this->_id;
    }
}

CK_BBOOL KeyObject::Compare(CK_ATTRIBUTE attribute)
{
    switch(attribute.type)
    {
        case CKA_KEY_TYPE:
            return (this->_keyType == *(CK_ULONG*)attribute.pValue);

        case CKA_ID:
            return Util::CompareU1Arrays(this->_id,attribute.pValue,attribute.ulValueLen);

        case CKA_START_DATE:
            return Util::CompareU1Arrays(this->_startDate,attribute.pValue,attribute.ulValueLen);

        case CKA_END_DATE:
            return Util::CompareU1Arrays(this->_endDate,attribute.pValue,attribute.ulValueLen);

        case CKA_LOCAL:
            return (this->_local == *(CK_BBOOL*)attribute.pValue);

        case CKA_DERIVE:
            return (this->_derive == *(CK_BBOOL*)attribute.pValue);

        case CKA_MECHANISM_TYPE:
            return (this->_mechanismType == *(CK_ULONG*)attribute.pValue);

        case CKA_ALLOWED_MECHANISMS:
            return Util::CompareU4Arrays(this->_allowedMechanism,attribute.pValue,attribute.ulValueLen);

        default:
            return StorageObject::Compare(attribute);

    }
}

CK_RV KeyObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

    CK_RV rv = CKR_OK;

    if(objCreation == CK_FALSE){
        switch(attribute.type){
            case CKA_KEY_TYPE:
            case CKA_LOCAL:
            case CKA_MECHANISM_TYPE:
                return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    switch(attribute.type){

        case CKA_KEY_TYPE:
            {
                CK_ULONG utemp = StorageObject::ReadULongFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_keyType = utemp;}
            }
            break;

        case CKA_ID:
            if(this->_id != NULL_PTR){
                delete this->_id;
            }
            this->_id = StorageObject::ReadU1ArrayFromAttribute(attribute);
            break;

        case CKA_START_DATE:
            {
                u1Array* dtemp = StorageObject::ReadDateFromAttribute(attribute,&rv);
                if(rv == CKR_OK){
                    if(this->_startDate != NULL_PTR){
                        delete this->_startDate;
                    }
                    this->_startDate = dtemp;
                }
            }
            break;

        case CKA_END_DATE:
           {
                u1Array* dtemp = StorageObject::ReadDateFromAttribute(attribute,&rv);
                if(rv == CKR_OK){
                    if(this->_endDate != NULL_PTR){
                        delete this->_endDate;
                    }
                    this->_endDate = dtemp;
                }
            }
            break;

        case CKA_LOCAL:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_local = btemp; }
            }
            break;

        case CKA_DERIVE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_derive = btemp; }
            }
            break;

        case CKA_MECHANISM_TYPE:
            {
                CK_ULONG utemp = StorageObject::ReadULongFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_mechanismType = utemp;}
            }
            break;

        case CKA_ALLOWED_MECHANISMS:
            if(this->_allowedMechanism != NULL_PTR){
                delete this->_allowedMechanism;
            }
            this->_allowedMechanism = new u4Array(attribute.ulValueLen/4);
            memcpy((u1*)this->_allowedMechanism->GetBuffer(),(CK_BYTE_PTR)attribute.pValue,attribute.ulValueLen);
            break;

        default:
            return StorageObject::SetAttribute(attribute,objCreation);

    }

    return rv;
}

CK_RV KeyObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type)
    {
        case CKA_KEY_TYPE:
            return StorageObject::PutULongInAttribute(this->_keyType,attribute);

        case CKA_ID:
            return StorageObject::PutU1ArrayInAttribute(this->_id,attribute);

        case CKA_START_DATE:
            return StorageObject::PutU1ArrayInAttribute(this->_startDate,attribute);

        case CKA_END_DATE:
            return StorageObject::PutU1ArrayInAttribute(this->_endDate,attribute);

        case CKA_LOCAL:
            return StorageObject::PutBBoolInAttribute(this->_local,attribute);

        case CKA_DERIVE:
            return StorageObject::PutBBoolInAttribute(this->_derive,attribute);

        case CKA_MECHANISM_TYPE:
            return StorageObject::PutULongInAttribute(this->_mechanismType,attribute);

        case CKA_ALLOWED_MECHANISMS:
            return StorageObject::PutU4ArrayInAttribute(this->_allowedMechanism,attribute);

        default:
            return StorageObject::GetAttribute(attribute);
    }
}

void KeyObject::Serialize(std::vector<u1> *to)
{
    StorageObject::Serialize(to);

    Util::PushULongInVector(to,this->_keyType);

    Util::PushByteArrayInVector(to,this->_id);

    Util::PushByteArrayInVector(to,this->_startDate);

    Util::PushByteArrayInVector(to,this->_endDate);

    Util::PushBBoolInVector(to,this->_local);

    Util::PushBBoolInVector(to,this->_derive);

    Util::PushULongInVector(to,this->_mechanismType);

    Util::PushIntArrayInVector(to,this->_allowedMechanism);
}

void KeyObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
    StorageObject::Deserialize(from,idx);

    this->_keyType = Util::ReadULongFromVector(from,idx);

    this->_id = Util::ReadByteArrayFromVector(from,idx);

    this->_startDate = Util::ReadByteArrayFromVector(from,idx);

    this->_endDate = Util::ReadByteArrayFromVector(from,idx);

    this->_local = Util::ReadBBoolFromVector(from,idx);

    this->_derive = Util::ReadBBoolFromVector(from,idx);

    this->_mechanismType = Util::ReadULongFromVector(from,idx);

    this->_allowedMechanism = Util::ReadIntArrayFromVector(from,idx);
}

