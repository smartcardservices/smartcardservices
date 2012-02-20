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


#include "Log.hpp"
#include "util.h"
#include "Pkcs11ObjectData.hpp"


DataObject::DataObject( ) : StorageObject( ) {

   m_Class = CKO_DATA;
}


bool DataObject::compare( const CK_ATTRIBUTE& attribute ) {

   bool bRet = false;

   switch(attribute.type)
   {
   case CKA_APPLICATION:
       bRet = Util::compareU1Arrays( m_pApplicationName.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );
      break;

   case CKA_OBJECT_ID:
      bRet = Util::compareU1Arrays( m_pID.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );
      break;

   case CKA_VALUE:
      bRet = Util::compareU1Arrays( m_pValue.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );
      break;

   default:
      bRet = StorageObject::compare( attribute );
      break;
   }

   return bRet;
}

void DataObject::setAttribute( const CK_ATTRIBUTE& attribute, const bool& objCreation)
{
   if( !attribute.ulValueLen )
   {
      return;
   }

   switch(attribute.type){

        case CKA_APPLICATION:
            m_pApplicationName.reset( StorageObject::/*readStringFromAttribute*/readU1ArrayFromAttribute(attribute ) );
           break;

        case CKA_OBJECT_ID:
           m_pID.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
           break;

        case CKA_VALUE:
           m_pValue.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
           break;

        default:
           StorageObject::setAttribute(attribute,objCreation);
   }
}


void DataObject::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
   switch(attribute->type)
   {
   case CKA_APPLICATION:
      StorageObject::putU1ArrayInAttribute( m_pApplicationName.get( ), attribute);
      break;

   case CKA_OBJECT_ID:
      StorageObject::putU1ArrayInAttribute( m_pID.get( ), attribute);
      break;

   case CKA_VALUE:
      StorageObject::putU1ArrayInAttribute( m_pValue.get( ), attribute);
      break;

   default:
      StorageObject::getAttribute(attribute);
      break;
   }
}


void DataObject::serialize(std::vector<u1>* to)
{
   // first go ahead and serialize the fields in base class
   StorageObject::serialize(to);

   // serialize label attribute
   Util::PushByteArrayInVector(to, m_pApplicationName.get( ) );

   // serialize label attribute
   Util::PushByteArrayInVector(to,m_pID.get( ) );

   // serialize label attribute
   Util::PushByteArrayInVector(to, m_pValue.get( ) );
}


void DataObject::deserialize(std::vector<u1>& from,CK_ULONG_PTR idx)
{
   // first go ahead and de-serialize the fields in base class
   StorageObject::deserialize(from,idx);

   m_pApplicationName.reset( Util::ReadByteArrayFromVector(from,idx) );

   m_pID.reset( Util::ReadByteArrayFromVector(from,idx) );

   m_pValue.reset( Util::ReadByteArrayFromVector(from,idx) );
}


/*
*/
void DataObject::print( void ) {

    StorageObject::print( );

    if( m_pApplicationName ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_APPLICATION", m_pApplicationName->GetBuffer( ), m_pApplicationName->GetLength( ) );
    }

    if( m_pID ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_OBJECT_ID", m_pID->GetBuffer( ), m_pID->GetLength( ) );
    }

    if( m_pValue ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_VALUE", m_pValue->GetBuffer( ), m_pValue->GetLength( ) );
    }
}
