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
#include "Pkcs11ObjectKey.hpp"
#include "PKCS11Exception.hpp"


/*
*/
KeyObject::KeyObject( ) : StorageObject( ) {

    _keyType = 0;

    _derive = CK_FALSE;

    _local = CK_FALSE;

    _mechanismType = CK_UNAVAILABLE_INFORMATION;

    m_ucContainerIndex = 0xFF;

    m_ucKeySpec = 0;
}


KeyObject::KeyObject( const KeyObject* p ) : StorageObject( *p ) {

    if( p ) {

        _keyType = p->_keyType;

        _local = p->_local;

        _mechanismType = p->_mechanismType;

        m_ucContainerIndex = p->m_ucContainerIndex;

        m_ucKeySpec = p->m_ucKeySpec;

        _derive = p->_derive;

        if( p->m_pID.get( ) ) {

            Marshaller::u1Array* a = new Marshaller::u1Array( *( p->m_pID.get( ) ) );

            m_pID.reset( a );

        } else {

            m_pID.reset( );
        }

        if( p->m_pStartDate.get( ) ) {

            Marshaller::u1Array* a = new Marshaller::u1Array( *( p->m_pStartDate.get( ) ) );

            m_pStartDate.reset( a );

        } else {

            m_pStartDate.reset( );
        }

        if( p->m_pEndDate.get( ) ) {

            Marshaller::u1Array* a = new Marshaller::u1Array( *( p->m_pEndDate.get( ) ) );

            m_pEndDate.reset( a );

        } else {

            m_pEndDate.reset( );
        }

        if( p->m_pAllowedMechanism.get( ) ) {

            Marshaller::u4Array* a = new Marshaller::u4Array( *( p->m_pAllowedMechanism.get( ) ) );

            m_pAllowedMechanism.reset( a );

        } else {

            m_pAllowedMechanism.reset( );
        }

    } else {

    _keyType = 0;

    _local = CK_FALSE;

    _mechanismType = CK_UNAVAILABLE_INFORMATION;

    m_ucContainerIndex = 0xFF;

    m_ucKeySpec = 0;
        _derive = CK_FALSE;

        m_pID.reset( );
        m_pStartDate.reset( );
        m_pEndDate.reset( );
        m_pAllowedMechanism.reset( );
    }
}


/*
*/
bool KeyObject::compare( const CK_ATTRIBUTE& a_Attribute ) {

    switch( a_Attribute.type ) {

    case CKA_KEY_TYPE:
        return (_keyType == *(CK_ULONG*)a_Attribute.pValue);

    case CKA_ID:
        return Util::compareU1Arrays( m_pID.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

    case CKA_START_DATE:
        return Util::compareU1Arrays( m_pStartDate.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

    case CKA_END_DATE:
        return Util::compareU1Arrays( m_pEndDate.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

    case CKA_LOCAL:
        return (_local == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_DERIVE:
        return (_derive == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_MECHANISM_TYPE:
        return (_mechanismType == *(CK_ULONG*)a_Attribute.pValue);

    case CKA_ALLOWED_MECHANISMS:
        return Util::compareU4Arrays(m_pAllowedMechanism.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

    default:
        return StorageObject::compare( a_Attribute );

    }
}

void KeyObject::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation ) {

    if( !a_Attribute.ulValueLen )
    {
        return;
    }

    if( !objCreation ){

        switch(a_Attribute.type){

        case CKA_KEY_TYPE:
        case CKA_LOCAL:
        case CKA_MECHANISM_TYPE:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch(a_Attribute.type){

    case CKA_KEY_TYPE:
        _keyType = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    case CKA_ID:
        m_pID.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    case CKA_START_DATE:
        m_pStartDate.reset( StorageObject::readDateFromAttribute( a_Attribute ) );
        break;

    case CKA_END_DATE:
        m_pEndDate.reset( StorageObject::readDateFromAttribute( a_Attribute ) );
        break;

    case CKA_LOCAL:
        _local = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_DERIVE:
        _derive = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_MECHANISM_TYPE:
        _mechanismType = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    case CKA_ALLOWED_MECHANISMS:
        m_pAllowedMechanism.reset( new Marshaller::u4Array( a_Attribute.ulValueLen / 4 ) );
        memcpy( (unsigned char*)m_pAllowedMechanism->GetBuffer( ), (CK_BYTE_PTR)a_Attribute.pValue, a_Attribute.ulValueLen );
        break;

    default:
        StorageObject::setAttribute( a_Attribute, objCreation );

    }
}


/*
*/
void KeyObject::getAttribute( CK_ATTRIBUTE_PTR a_Attribute ) {

    switch( a_Attribute->type ) {

    case CKA_KEY_TYPE:
        StorageObject::putULongInAttribute( _keyType, a_Attribute );
        break;

    case CKA_ID:
        StorageObject::putU1ArrayInAttribute( m_pID.get( ), a_Attribute );
        break;

    case CKA_START_DATE:
        StorageObject::putU1ArrayInAttribute( m_pStartDate.get( ), a_Attribute );
        break;

    case CKA_END_DATE:
        StorageObject::putU1ArrayInAttribute( m_pEndDate.get( ), a_Attribute );
        break;

    case CKA_LOCAL:
        return StorageObject::putBBoolInAttribute(_local,a_Attribute);
        break;

    case CKA_DERIVE:
        StorageObject::putBBoolInAttribute( _derive, a_Attribute );
        break;

    case CKA_MECHANISM_TYPE:
        StorageObject::putULongInAttribute( _mechanismType, a_Attribute );
        break;

    case CKA_ALLOWED_MECHANISMS:
        StorageObject::putU4ArrayInAttribute( m_pAllowedMechanism.get( ), a_Attribute );
        break;

    default:
        StorageObject::getAttribute( a_Attribute );
        break;
    }
}


/*
*/
void KeyObject::serialize( std::vector<u1> *to ) {

    StorageObject::serialize( to );

    Util::PushULongInVector( to, _keyType );

    Util::PushByteArrayInVector( to, m_pID.get( ) );

    Util::PushByteArrayInVector( to, m_pStartDate.get( ) );

    Util::PushByteArrayInVector( to, m_pEndDate.get( ) );

    Util::PushBBoolInVector( to,_local );

    Util::PushBBoolInVector( to,_derive );

    Util::PushULongInVector( to, _mechanismType );

    Util::PushIntArrayInVector(to, m_pAllowedMechanism.get( ) );
}


/*
*/
void KeyObject::deserialize( std::vector<u1>& from, CK_ULONG_PTR idx ) {

    StorageObject::deserialize(from,idx);

    _keyType = Util::ReadULongFromVector(from,idx);

    m_pID.reset( Util::ReadByteArrayFromVector(from,idx) );

    m_pStartDate.reset( Util::ReadByteArrayFromVector(from,idx) );

    m_pEndDate.reset( Util::ReadByteArrayFromVector(from,idx) );

    _local = Util::ReadBBoolFromVector(from,idx);

    _derive = Util::ReadBBoolFromVector(from,idx);

    _mechanismType = Util::ReadULongFromVector(from,idx);

    m_pAllowedMechanism.reset( Util::ReadIntArrayFromVector(from,idx) );
}


/*
*/
void KeyObject::print( void ) {

    StorageObject::print( );

    Log::log( "CKA_KEY_TYPE <%ld>", _keyType );

    Log::log( "CKA_DERIVE <%ld>", _derive );

    Log::log( "CKA_LOCAL <%ld>", _local );

    Log::log( "CKA_KEY_GEN_MECHANISM <%ld>", _mechanismType );

    if( m_pID.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_ID", m_pID->GetBuffer( ), m_pID->GetLength( ) );

    } else {

        Log::log( "CKA_ID <null>" );
    }

    if( m_pStartDate.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_START_DATE", m_pStartDate->GetBuffer( ), m_pStartDate->GetLength( ) );

    } else {

        Log::log( "CKA_START_DATE <null>" );
    }

    if( m_pEndDate.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_END_DATE", m_pEndDate->GetBuffer( ), m_pEndDate->GetLength( ) );

    } else {

        Log::log( "CKA_END_DATE <null>" );
    }

    Log::log( "[Container Index <%d>]", m_ucContainerIndex );

    Log::log( "[KeySpec <%d>]", m_ucKeySpec );
}
