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
#include "Pkcs11ObjectStorage.hpp"
#include "PKCS11Exception.hpp"


/*
*/
StorageObject::StorageObject( )
{
	m_Class = 0;

    m_iVersion = OBJECT_SERIALIZATION_CURRENT_VERSION;
    
    m_Token = CK_FALSE;
    
	m_Private = CK_FALSE;

    m_Modifiable = CK_TRUE;

	m_stFileName = "";

    m_bOffCardObject = false;
        
    _uniqueId = 0;
}


/*
*/
StorageObject::StorageObject( const StorageObject& a_Object ) {

	m_iVersion = a_Object.m_iVersion;
	
	m_Class = a_Object.m_Class;

	m_Token = a_Object.m_Token;

	m_Private = a_Object.m_Private;

	m_Modifiable = a_Object.m_Modifiable;

    if( a_Object.m_pLabel.get( ) ) {
    
        Marshaller::u1Array* pLabel = new Marshaller::u1Array( *(a_Object.m_pLabel.get( )) );

        m_pLabel.reset( pLabel );
    
    } else {
    
        m_pLabel.reset( );
    }
	
	m_stFileName = a_Object.m_stFileName; 

    m_bOffCardObject = a_Object.m_bOffCardObject;

    _uniqueId = a_Object._uniqueId;
}


/*
*/
bool StorageObject::compare( const CK_ATTRIBUTE& a_attribute ) {

    switch(a_attribute.type){
        case CKA_CLASS:
            return (m_Class == *(CK_ULONG*)a_attribute.pValue);

        case CKA_PRIVATE:
            return (m_Private == *(CK_BBOOL*)a_attribute.pValue);

        case CKA_TOKEN:
            return (m_Token == *(CK_BBOOL*)a_attribute.pValue);

        case CKA_MODIFIABLE:
            return (m_Modifiable == *(CK_BBOOL*)a_attribute.pValue);

        case CKA_LABEL:
			if( m_pLabel.get( ) && ( m_pLabel->GetLength( ) == a_attribute.ulValueLen ) ) {
                return Util::compareByteArrays(m_pLabel->GetBuffer(),(CK_BYTE_PTR)a_attribute.pValue,a_attribute.ulValueLen);
            }
            return false;

        default:
            return false;

    }
}


/*
*/
void StorageObject::setAttribute( const CK_ATTRIBUTE& a_attribute, const bool& a_objCreation) {

   if( !a_attribute.ulValueLen ) {

      return;
   }

    if( !a_objCreation ) {

        switch( a_attribute.type ) {

            case CKA_CLASS:
            case CKA_PRIVATE:
            case CKA_TOKEN:
            case CKA_MODIFIABLE:
                throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( a_attribute.type ) {

        case CKA_CLASS:
            break;

        case CKA_PRIVATE:
            m_Private = StorageObject::readBBoolFromAttribute( a_attribute );
            break;

        case CKA_TOKEN:
            m_Token = StorageObject::readBBoolFromAttribute( a_attribute );
            break;

        case CKA_MODIFIABLE:
            m_Modifiable = StorageObject::readBBoolFromAttribute( a_attribute );
            break;

        case CKA_LABEL:
				m_pLabel.reset( StorageObject::readU1ArrayFromAttribute( a_attribute ) );
            break;

        default:
            throw PKCS11Exception( CKR_ATTRIBUTE_TYPE_INVALID );
    }
}


/*
*/
void StorageObject::getAttribute( CK_ATTRIBUTE_PTR attribute ) {

    switch( attribute->type )
    {
        case CKA_CLASS:
            StorageObject::putULongInAttribute(m_Class,attribute);
            break;

        case CKA_PRIVATE:
            StorageObject::putBBoolInAttribute(m_Private,attribute);
            break;

        case CKA_TOKEN:
            StorageObject::putBBoolInAttribute(m_Token,attribute);
            break;

        case CKA_MODIFIABLE:
            StorageObject::putBBoolInAttribute(m_Modifiable,attribute);
            break;

        case CKA_LABEL:
			StorageObject::putU1ArrayInAttribute(m_pLabel.get( ),attribute);
            break;

        default:
           attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;

           throw PKCS11Exception( CKR_ATTRIBUTE_TYPE_INVALID );
    }
}


/*
*/
void StorageObject::serialize( std::vector<u1>* to ) {

    // serialize format version
    Util::PushBBoolInVector( to, (CK_BBOOL)m_iVersion );

    // serialize unique id for compatibility with old version of the P11 library
    Util::PushULongLongInVector( to, _uniqueId );

    // serialize class attribute
    Util::PushULongInVector( to, m_Class );

    // serialize private attribute
    Util::PushBBoolInVector( to, m_Private );

    // serialize token attribute
    Util::PushBBoolInVector( to, m_Token );

    // serialize modifiable attribute
    Util::PushBBoolInVector( to, m_Modifiable );

    // serialize label attribute
    Util::PushByteArrayInVector( to, m_pLabel.get( ) );
}


/*
*/
void StorageObject::deserialize( const std::vector<u1>& from, CK_ULONG_PTR idx )
{
    m_iVersion = Util::ReadBBoolFromVector( from, idx );

    // Unused value. Read to support old mapping.
    /*u8 ulUniqueId =*/ Util::ReadULongLongFromVector( from, idx );

    m_Class = Util::ReadULongFromVector( from, idx );

    m_Private = Util::ReadBBoolFromVector( from, idx );

    m_Token = Util::ReadBBoolFromVector( from, idx );

    m_Modifiable = Util::ReadBBoolFromVector( from, idx );

	m_pLabel.reset( Util::ReadByteArrayFromVector( from, idx ) );
}


/*
*/
void StorageObject::putU1ArrayInAttribute( Marshaller::u1Array* value, CK_ATTRIBUTE_PTR attribute ) {
    
    if( !attribute->pValue ) {

        if( !value ) {

            attribute->ulValueLen = 0; 
        
        } else {
        
            attribute->ulValueLen = value->GetLength();
        }

        return;
    }

    if( !value ) {

        attribute->ulValueLen = 0;

        return;
    }

    if( attribute->ulValueLen < value->GetLength( ) ) {

        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        
        throw PKCS11Exception(  CKR_BUFFER_TOO_SMALL );
    }

    attribute->ulValueLen = value->GetLength();
    
    memcpy((CK_BYTE_PTR)attribute->pValue,value->GetBuffer(),attribute->ulValueLen);
}


/*
*/
void StorageObject::putU4ArrayInAttribute( Marshaller::u4Array* value,CK_ATTRIBUTE_PTR attribute)
{
    if( !attribute->pValue ) {

        if( !value ) {

            attribute->ulValueLen = 0;
        
        } else {

            attribute->ulValueLen = (value->GetLength() * 4);
        }

        return;
    }

    if( !value ) {

        attribute->ulValueLen = 0;
        
        return;
    }

    if( attribute->ulValueLen < ( value->GetLength( ) * 4 ) ) {

        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        
        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    attribute->ulValueLen = value->GetLength() * 4;
    
    memcpy((CK_BYTE_PTR)attribute->pValue,(u1*)value->GetBuffer(),attribute->ulValueLen);
}


/*
*/
void StorageObject::putBBoolInAttribute( const CK_BBOOL& value, CK_ATTRIBUTE_PTR attribute) {

    if( !attribute->pValue ) {

        attribute->ulValueLen = sizeof(CK_BBOOL);
        
        return;
    }

    if( attribute->ulValueLen < sizeof( CK_BBOOL ) ) {

        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        
        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    attribute->ulValueLen = sizeof(CK_BBOOL);
    
    *(CK_BBOOL*)attribute->pValue = value;
}


/*
*/
void StorageObject::putULongInAttribute( const CK_ULONG& value, CK_ATTRIBUTE_PTR attribute ) {

    if( !attribute->pValue ) {

        attribute->ulValueLen = sizeof( CK_ULONG );

        return;
    }

    if( attribute->ulValueLen < sizeof( CK_ULONG ) ) {

        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        
		throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    attribute->ulValueLen = sizeof( CK_ULONG );

    *(CK_ULONG*)attribute->pValue = value;
}


/*
*/
CK_ULONG StorageObject::readULongFromAttribute( const CK_ATTRIBUTE&  a_Attribute ) {

    if( a_Attribute.ulValueLen != sizeof( CK_ULONG ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    return *(CK_ULONG*)a_Attribute.pValue;
}


/*
*/
CK_BBOOL StorageObject::readBBoolFromAttribute( const CK_ATTRIBUTE& a_Attribute ) {

    if( a_Attribute.ulValueLen != sizeof( CK_BBOOL ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    CK_BBOOL val = *(CK_BBOOL*)a_Attribute.pValue;

    if( ( val != 0x00 ) && ( val != 0x01 ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    return val;
}


/*
*/
Marshaller::u1Array* StorageObject::readU1ArrayFromAttribute( const CK_ATTRIBUTE& a_Attribute ) {

    Marshaller::u1Array* val = new Marshaller::u1Array( a_Attribute.ulValueLen );

    val->SetBuffer( (CK_BYTE_PTR) a_Attribute.pValue );

    return val;
}


/*
*/
Marshaller::u1Array* StorageObject::readDateFromAttribute( const CK_ATTRIBUTE& a_Attribute ) {

    if( a_Attribute.ulValueLen != 8 ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    return StorageObject::readU1ArrayFromAttribute( a_Attribute );
}


/*
*/
void StorageObject::print( void ) {

	Log::log( "CKA_CLASS <%ld>", m_Class );

    Log::log( "CKA_TOKEN <%ld>", m_Token );

    Log::log( "CKA_PRIVATE <%ld>", m_Private );

    Log::log( "CKA_MODIFIABLE <%ld>", m_Modifiable );

     if( m_pLabel.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_LABEL", m_pLabel->GetBuffer( ), m_pLabel->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_LABEL <null>" );
    }

    Log::log( "[FileName <%s>]",m_stFileName.c_str( ) );
}
