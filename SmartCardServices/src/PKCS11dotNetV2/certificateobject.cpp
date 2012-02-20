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
//#include "dbg.h"
#include "util.h"

#include "certificateobject.h"

CertificateObject::CertificateObject() : StorageObject()
{
   this->_trusted   = CK_FALSE;
   this->_checkSum  = NULL_PTR;
   this->_startDate = NULL_PTR;
   this->_endDate   = NULL_PTR;

   this->_class = CKO_CERTIFICATE;

   this->_ctrIndex = 0xFF;
   this->_keySpec  = 0xFF;
}

CertificateObject::~CertificateObject()
{
   if(this->_checkSum != NULL_PTR)
      delete this->_checkSum;

   if(this->_startDate != NULL_PTR)
      delete this->_startDate;

   if(this->_endDate != NULL_PTR)
      delete this->_endDate;

}

bool CertificateObject::IsEqual(const StorageObject * that) const
{
   if(_uniqueId != 0 && that->_uniqueId != 0)
      return (_uniqueId == that->_uniqueId);

   // Only objects that have been stored under p11 directory
   // will have a non-zero _uniqueId. For other objects, do
   // a deep comparison based on other attributes.
   if(_class != that->_class)
      return false;

   const CertificateObject * thatCert = static_cast<const CertificateObject*>(that);
   return ( (_ctrIndex == thatCert->_ctrIndex) &&
      (_keySpec == thatCert->_keySpec) &&
      (_checkValue == thatCert->_checkValue));
}

CK_BBOOL CertificateObject::Compare(CK_ATTRIBUTE attribute)
{
   switch(attribute.type){

        case CKA_CERTIFICATE_TYPE:
           return (this->_certType == *(CK_ULONG*)attribute.pValue);

        case CKA_CERTIFICATE_CATEGORY:
           return (this->_certCategory == *(CK_ULONG*)attribute.pValue);

        case CKA_TRUSTED:
           return (this->_trusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_CHECK_VALUE:
           return Util::CompareU1Arrays(this->_checkSum,attribute.pValue,attribute.ulValueLen);

        case CKA_START_DATE:
           return Util::CompareU1Arrays(this->_startDate,attribute.pValue,attribute.ulValueLen);

        case CKA_END_DATE:
           return Util::CompareU1Arrays(this->_endDate,attribute.pValue,attribute.ulValueLen);

        default:
           return StorageObject::Compare(attribute);
   }
}

CK_RV CertificateObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   CK_RV rv = CKR_OK;

   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   if(objCreation == CK_FALSE){
      switch(attribute.type){
            case CKA_CERTIFICATE_TYPE:
            case CKA_CERTIFICATE_CATEGORY:
               return CKR_ATTRIBUTE_READ_ONLY;
      }
   }

   switch(attribute.type){

        case CKA_CERTIFICATE_TYPE:
           {
              CK_ULONG utemp = StorageObject::ReadULongFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_certType = utemp;}
           }
           break;

        case CKA_CERTIFICATE_CATEGORY:
           {
              CK_ULONG utemp = StorageObject::ReadULongFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_certCategory = utemp;}
           }
           break;

        case CKA_TRUSTED:
           {
              CK_BBOOL btemp = StorageObject::ReadBBoolFromAttribute(attribute,&rv);
              if(rv == CKR_OK){ this->_trusted = btemp; }
           }
           break;

        case CKA_CHECK_VALUE:
           if(this->_checkSum != NULL_PTR){
              delete this->_checkSum;
           }
           this->_checkSum = StorageObject::ReadU1ArrayFromAttribute(attribute);
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

        default:
           return StorageObject::SetAttribute(attribute,objCreation);
   }

   return rv;
}

CK_RV CertificateObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   switch(attribute->type){

        case CKA_CERTIFICATE_TYPE:
           return StorageObject::PutULongInAttribute(this->_certType,attribute);

        case CKA_CERTIFICATE_CATEGORY:
           return StorageObject::PutULongInAttribute(this->_certCategory,attribute);

        case CKA_TRUSTED:
           return StorageObject::PutBBoolInAttribute(this->_trusted,attribute);

        case CKA_CHECK_VALUE:
           return StorageObject::PutU1ArrayInAttribute(this->_checkSum,attribute);

        case CKA_START_DATE:
           return StorageObject::PutU1ArrayInAttribute(this->_startDate,attribute);

        case CKA_END_DATE:
           return StorageObject::PutU1ArrayInAttribute(this->_endDate,attribute);

        default:
           return StorageObject::GetAttribute(attribute);
   }
}

void CertificateObject::Serialize(std::vector<u1> *to)
{
   StorageObject::Serialize(to);

   Util::PushULongInVector(to,this->_certType);

   Util::PushULongInVector(to,this->_certCategory);

   Util::PushBBoolInVector(to,this->_trusted);

   Util::PushByteArrayInVector(to,this->_startDate);

   Util::PushByteArrayInVector(to,this->_endDate);

   Util::PushByteArrayInVector(to,this->_checkSum);

   // serialize the extra fields

   PKCS11_ASSERT(_checkValue != 0);
   PKCS11_ASSERT(_ctrIndex < 100);
   PKCS11_ASSERT(_keySpec == 1 || _keySpec == 2 );

   Util::PushULongLongInVector(to,this->_checkValue);

   Util::PushBBoolInVector(to,this->_ctrIndex);

   Util::PushBBoolInVector(to,this->_keySpec);
}

void CertificateObject::Deserialize(std::vector<u1> from, CK_ULONG_PTR idx)
{
   StorageObject::Deserialize(from,idx);

   this->_certType = Util::ReadULongFromVector(from,idx);

   this->_certCategory = Util::ReadULongFromVector(from,idx);

   this->_trusted = Util::ReadBBoolFromVector(from,idx);

   this->_startDate = Util::ReadByteArrayFromVector(from,idx);

   this->_endDate = Util::ReadByteArrayFromVector(from,idx);

   this->_checkSum = Util::ReadByteArrayFromVector(from,idx);

   // serialize the extra fields

   this->_checkValue = Util::ReadULongLongFromVector(from,idx);

   this->_ctrIndex = Util::ReadBBoolFromVector(from,idx);

   this->_keySpec = Util::ReadBBoolFromVector(from,idx);

}

