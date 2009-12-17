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
#include "storageobject.h"
#include "error.h"

StorageObject::StorageObject()
{
    this->_version     = 0;
    this->_uniqueId    = 0;
    this->_tokenObject = CK_FALSE;
    this->_private     = CK_FALSE;
    this->_modifiable  = CK_TRUE;
    this->_label       = NULL_PTR;
}

StorageObject::~StorageObject(){

    if(this->_label != NULL_PTR)
        delete this->_label;

}

bool StorageObject::IsEqual(const StorageObject * that) const
{
    if(_uniqueId != 0 && that->_uniqueId != 0)
        return (_uniqueId == that->_uniqueId);

    // Only objects that have been stored under p11 directory
    // will have a non-zero _uniqueId. For other objects, do
    // a deep comparison based on other attributes. In the base
    // class, only negative comparison based on _class can be performed.
    if(_class != that->_class)
        return false;
    else
        throw CkError(CKR_FUNCTION_FAILED);
}

CK_BBOOL StorageObject::Compare(CK_ATTRIBUTE attribute)
{
    switch(attribute.type){
        case CKA_CLASS:
            return (this->_class == *(CK_ULONG*)attribute.pValue);

        case CKA_PRIVATE:
            return (this->_private == *(CK_BBOOL*)attribute.pValue);

        case CKA_TOKEN:
            return (this->_tokenObject == *(CK_BBOOL*)attribute.pValue);

        case CKA_MODIFIABLE:
            return (this->_modifiable == *(CK_BBOOL*)attribute.pValue);

        case CKA_LABEL:
            if(this->_label->GetLength() == attribute.ulValueLen){
                return Util::CompareByteArrays(this->_label->GetBuffer(),(CK_BYTE_PTR)attribute.pValue,attribute.ulValueLen);
            }
            return CK_FALSE;

        default:
            return CK_FALSE;

    }
}

CK_RV StorageObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

    CK_RV rv = CKR_OK;

    if(objCreation == CK_FALSE){
        switch(attribute.type){
            case CKA_CLASS:
            case CKA_PRIVATE:
            case CKA_TOKEN:
            case CKA_MODIFIABLE:
                return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    switch(attribute.type){
        case CKA_CLASS:
            break;

        case CKA_PRIVATE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_private = btemp; }
            }
            break;

        case CKA_TOKEN:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_tokenObject = btemp; }
            }
            break;

        case CKA_MODIFIABLE:
            {
                CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
                if(rv == CKR_OK){ this->_modifiable = btemp; }
            }
            break;

        case CKA_LABEL:
            {
                u1Array* stemp = StorageObject::ReadStringFromAttribute(attribute,&rv);
                if(rv == CKR_OK){
                    if(this->_label != NULL_PTR){
                        delete this->_label;
                    }
                    this->_label = stemp;
                }
            }
            break;

        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;

    }

    return rv;
}

CK_RV StorageObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   CK_RV ulRet = CKR_OK;

    switch(attribute->type)
    {
        case CKA_CLASS:
            ulRet = StorageObject::PutULongInAttribute(this->_class,attribute);
            break;

        case CKA_PRIVATE:
            ulRet = StorageObject::PutBBoolInAttribute(this->_private,attribute);
            break;

        case CKA_TOKEN:
            ulRet = StorageObject::PutBBoolInAttribute(this->_tokenObject,attribute);
            break;

        case CKA_MODIFIABLE:
            ulRet = StorageObject::PutBBoolInAttribute(this->_modifiable,attribute);
            break;

        case CKA_LABEL:
            ulRet = StorageObject::PutU1ArrayInAttribute(this->_label,attribute);
            break;

        default:
           attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
           ulRet = CKR_ATTRIBUTE_TYPE_INVALID;
           break;
    }

    return ulRet;
}

void StorageObject::Serialize(std::vector<u1>* to)
{
    // serialize format version
    Util::PushBBoolInVector(to,this->_version);

    // serialize unique id
    Util::PushULongLongInVector(to,this->_uniqueId);

    // serialize class attribute
    Util::PushULongInVector(to,this->_class);

    // serialize private attribute
    Util::PushBBoolInVector(to,this->_private);

    // serialize token attribute
    Util::PushBBoolInVector(to,this->_tokenObject);

    // serialize modifiable attribute
    Util::PushBBoolInVector(to,this->_modifiable);

    // serialize label attribute
    Util::PushByteArrayInVector(to,this->_label);
}

void StorageObject::Deserialize(std::vector<u1> from,CK_ULONG_PTR idx)
{
    this->_version = Util::ReadBBoolFromVector(from,idx);

    this->_uniqueId = Util::ReadULongLongFromVector(from, idx);

    this->_class = Util::ReadULongFromVector(from,idx);

    this->_private = Util::ReadBBoolFromVector(from,idx);

    this->_tokenObject = Util::ReadBBoolFromVector(from,idx);

    this->_modifiable = Util::ReadBBoolFromVector(from,idx);

    this->_label = Util::ReadByteArrayFromVector(from,idx);
}

CK_RV StorageObject::PutU1ArrayInAttribute(u1Array* value,CK_ATTRIBUTE_PTR attribute)
{
    if(attribute->pValue == NULL_PTR){
        if(value == NULL_PTR){
            attribute->ulValueLen = 0;
        }else{
            attribute->ulValueLen = value->GetLength();
        }
        return CKR_OK;
    }
    if(value == NULL_PTR){
        // I am not sure about it (TBD: Check)
        attribute->ulValueLen = 0;
        return CKR_OK;
    }
    if(attribute->ulValueLen < value->GetLength()){
        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
        return CKR_BUFFER_TOO_SMALL;
    }

    attribute->ulValueLen = value->GetLength();
    memcpy((CK_BYTE_PTR)attribute->pValue,value->GetBuffer(),attribute->ulValueLen);

    return CKR_OK;
}

CK_RV StorageObject::PutU4ArrayInAttribute(u4Array* value,CK_ATTRIBUTE_PTR attribute)
{
    if(attribute->pValue == NULL_PTR){
        if(value == NULL_PTR){
            attribute->ulValueLen = 0;
        }else{
            attribute->ulValueLen = (value->GetLength() * 4);
        }
        return CKR_OK;
    }
    if(value == NULL_PTR){
        // I am not sure about it (TBD: Check)
        attribute->ulValueLen = 0;
        return CKR_OK;
    }
    if(attribute->ulValueLen < (value->GetLength() * 4)){
        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
        return CKR_BUFFER_TOO_SMALL;
    }

    attribute->ulValueLen = value->GetLength() * 4;
    memcpy((CK_BYTE_PTR)attribute->pValue,(u1*)value->GetBuffer(),attribute->ulValueLen);

    return CKR_OK;
}

CK_RV StorageObject::PutBBoolInAttribute(CK_BBOOL value, CK_ATTRIBUTE_PTR attribute)
{
    if(attribute->pValue == NULL_PTR){
        attribute->ulValueLen = sizeof(CK_BBOOL);
        return CKR_OK;
    }
    if(attribute->ulValueLen < sizeof(CK_BBOOL)){
        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
        return CKR_BUFFER_TOO_SMALL;
    }
    attribute->ulValueLen = sizeof(CK_BBOOL);
    *(CK_BBOOL*)attribute->pValue = value;

    return CKR_OK;
}

CK_RV StorageObject::PutULongInAttribute(CK_ULONG value, CK_ATTRIBUTE_PTR attribute)
{
    if(attribute->pValue == NULL_PTR){
        attribute->ulValueLen = sizeof(CK_ULONG);
        return CKR_OK;
    }
    if(attribute->ulValueLen < sizeof(CK_ULONG)){
        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
        return CKR_BUFFER_TOO_SMALL;
    }
    attribute->ulValueLen = sizeof(CK_ULONG);
    *(CK_ULONG*)attribute->pValue = value;

    return CKR_OK;
}

CK_ULONG StorageObject::ReadULongFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv)
{
    if(attribute.ulValueLen != sizeof(CK_ULONG)){
        *rv = CKR_ATTRIBUTE_VALUE_INVALID;
        return 0;
    }

    return *(CK_ULONG*)attribute.pValue;
}

CK_BBOOL StorageObject::ReadBBoolFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv)
{
    if(attribute.ulValueLen != sizeof(CK_BBOOL)){
        *rv = CKR_ATTRIBUTE_VALUE_INVALID;
        return 0;
    }

    CK_BBOOL val = *(CK_BBOOL*)attribute.pValue;

    if(val != 0x00 && val != 0x01){
        *rv = CKR_ATTRIBUTE_VALUE_INVALID;
        return 0;
    }

    return val;
}

u1Array* StorageObject::ReadU1ArrayFromAttribute(CK_ATTRIBUTE attribute)
{
    u1Array* val = new u1Array(attribute.ulValueLen);
    val->SetBuffer((CK_BYTE_PTR)attribute.pValue);

    return val;
}

u1Array* StorageObject::ReadDateFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv)
{
    if(attribute.ulValueLen != 8){
        *rv = CKR_ATTRIBUTE_VALUE_INVALID;
        return NULL_PTR;
    }

    return StorageObject::ReadU1ArrayFromAttribute(attribute);
}

u1Array* StorageObject::ReadStringFromAttribute(CK_ATTRIBUTE attribute,CK_RV* /*rv*/)
{

    // [HB]: Shall support UTF-8

    //for(u4 i=0;i<attribute.ulValueLen;i++){

    //    CK_BYTE bval = ((CK_BYTE_PTR)attribute.pValue)[i];

    //    if((bval < 0x20)||(bval > 0x7D)||(bval == 0x24)||(bval == 0x40)||(bval == 0x60)){
    //        *rv = CKR_ATTRIBUTE_VALUE_INVALID;
    //        return NULL_PTR;
    //    }
    //}

    return StorageObject::ReadU1ArrayFromAttribute(attribute);
}

