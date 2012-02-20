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
#include "dataobject.h"

DataObject::DataObject() : StorageObject()
{
   this->_class    = CKO_DATA;
   this->_appName  = NULL_PTR;
   this->_objId    = NULL_PTR;
   this->_objValue = NULL_PTR;
}

DataObject::~DataObject(){

   if(this->_appName != NULL_PTR){
      delete this->_appName;
   }

   if(this->_objId != NULL_PTR){
      delete this->_objId;
   }

   if(this->_objValue != NULL_PTR){
      delete this->_objValue;
   }
}

CK_BBOOL DataObject::Compare(CK_ATTRIBUTE attribute)
{
   CK_BBOOL bRet = CK_FALSE;

   switch(attribute.type)
   {
   case CKA_APPLICATION:
      bRet = Util::CompareU1Arrays(this->_appName,attribute.pValue,attribute.ulValueLen);
      break;

   case CKA_OBJECT_ID:
      bRet = Util::CompareU1Arrays(this->_objId,attribute.pValue,attribute.ulValueLen);
      break;

   case CKA_VALUE:
      bRet = Util::CompareU1Arrays(this->_objValue,attribute.pValue,attribute.ulValueLen);
      break;

   default:
      bRet = StorageObject::Compare( attribute );
      break;
   }

   return bRet;
}

CK_RV DataObject::SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation)
{
   if( 0 == attribute.ulValueLen )
   {
      return CKR_OK;
   }

   CK_RV rv = CKR_OK;

   switch(attribute.type){

        case CKA_APPLICATION:
           {
              u1Array* stemp = StorageObject::ReadStringFromAttribute(attribute,&rv);
              if(rv == CKR_OK){
                 if(this->_appName != NULL_PTR){
                    delete this->_appName;
                 }
                 this->_appName = stemp;
              }
           }
           break;


        case CKA_OBJECT_ID:
           if(this->_objId != NULL_PTR){
              delete this->_objId;
           }
           this->_objId = StorageObject::ReadU1ArrayFromAttribute(attribute);
           break;

        case CKA_VALUE:
           if(this->_objValue != NULL_PTR){
              delete this->_objValue;
           }
           this->_objValue = StorageObject::ReadU1ArrayFromAttribute(attribute);
           break;

        default:
           return StorageObject::SetAttribute(attribute,objCreation);

   }

   return rv;
}

CK_RV DataObject::GetAttribute(CK_ATTRIBUTE_PTR attribute)
{
   CK_RV ulRet = CKR_OK;
   switch(attribute->type)
   {
   case CKA_APPLICATION:
      ulRet = StorageObject::PutU1ArrayInAttribute(this->_appName,attribute);
      break;

   case CKA_OBJECT_ID:
      ulRet = StorageObject::PutU1ArrayInAttribute(this->_objId,attribute);
      break;

   case CKA_VALUE:
      ulRet = StorageObject::PutU1ArrayInAttribute(this->_objValue,attribute);
      break;

   default:
      ulRet = StorageObject::GetAttribute(attribute);
      break;
   }

   return ulRet;
}


void DataObject::Serialize(std::vector<u1>* to)
{
   // first go ahead and serialize the fields in base class
   StorageObject::Serialize(to);

   // serialize label attribute
   Util::PushByteArrayInVector(to,this->_appName);

   // serialize label attribute
   Util::PushByteArrayInVector(to,this->_objId);

   // serialize label attribute
   Util::PushByteArrayInVector(to,this->_objValue);
}

void DataObject::Deserialize(std::vector<u1> from,CK_ULONG_PTR idx)
{
   // first go ahead and de-serialize the fields in base class
   StorageObject::Deserialize(from,idx);

   this->_appName = Util::ReadByteArrayFromVector(from,idx);

   this->_objId = Util::ReadByteArrayFromVector(from,idx);

   this->_objValue = Util::ReadByteArrayFromVector(from,idx);
}


