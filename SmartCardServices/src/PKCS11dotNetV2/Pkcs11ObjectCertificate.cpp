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
#include "Pkcs11ObjectCertificate.hpp"
#include "PKCS11Exception.hpp"


CertificateObject::CertificateObject( ) : StorageObject( ) {

    m_Class = CKO_CERTIFICATE;

    _trusted   = CK_FALSE;

    m_ucContainerIndex = 0xFF;

    m_ucKeySpec  = 0xFF;

    _certCategory = 0; // unspecified (default value)

    _checkValue = 0;
}


bool CertificateObject::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

    const CertificateObject* thatCert = static_cast< const CertificateObject* >( that );

    return ( ( m_ucContainerIndex == thatCert->m_ucContainerIndex ) && ( m_ucKeySpec == thatCert->m_ucKeySpec ) );
}


/*
*/
bool CertificateObject::compare( const CK_ATTRIBUTE& attribute ) {

    switch( attribute.type ) {

    case CKA_CERTIFICATE_TYPE:
        return ( _certType == *(CK_ULONG*)attribute.pValue );

    case CKA_CERTIFICATE_CATEGORY:
        return (_certCategory == *(CK_ULONG*)attribute.pValue);

    case CKA_TRUSTED:
        return (_trusted == *(CK_BBOOL*)attribute.pValue);

    case CKA_CHECK_VALUE:
        return Util::compareU1Arrays( m_pCheckSum.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_START_DATE:
        return Util::compareU1Arrays( m_pStartDate.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    case CKA_END_DATE:
        return Util::compareU1Arrays( m_pEndDate.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

    default:
        return StorageObject::compare( attribute );
    }
}


/*
*/
void CertificateObject::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& a_objCreation )
{

    //if( 0 == a_Attribute.ulValueLen ) {

    //    return;
    //}

    if( !a_objCreation ) {

        switch( a_Attribute.type ) {

        case CKA_CERTIFICATE_TYPE:
        case CKA_CERTIFICATE_CATEGORY:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( a_Attribute.type ) {

    case CKA_CERTIFICATE_TYPE:
        _certType = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    case CKA_CERTIFICATE_CATEGORY:
        _certCategory = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    case CKA_TRUSTED:
        _trusted = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_CHECK_VALUE:
        m_pCheckSum.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ));
        break;

    case CKA_START_DATE:
        m_pStartDate.reset( StorageObject::readDateFromAttribute( a_Attribute ));
        break;

    case CKA_END_DATE:
        m_pEndDate.reset( StorageObject::readDateFromAttribute( a_Attribute ));
        break;

    default:
        StorageObject::setAttribute( a_Attribute, a_objCreation );
    }
}


void CertificateObject::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_CERTIFICATE_TYPE:
        StorageObject::putULongInAttribute(_certType,attribute);
        break;

    case CKA_CERTIFICATE_CATEGORY:
        StorageObject::putULongInAttribute(_certCategory,attribute);
        break;

    case CKA_TRUSTED:
        StorageObject::putBBoolInAttribute(_trusted,attribute);
        break;

    case CKA_CHECK_VALUE:
        StorageObject::putU1ArrayInAttribute(m_pCheckSum.get( ),attribute);
        break;

    case CKA_START_DATE:
        StorageObject::putU1ArrayInAttribute(m_pStartDate.get( ),attribute);
        break;

    case CKA_END_DATE:
        StorageObject::putU1ArrayInAttribute(m_pEndDate.get( ),attribute);
        break;

    default:
        StorageObject::getAttribute(attribute);
        break;
    }
}


void CertificateObject::serialize(std::vector<u1> *to)
{
    StorageObject::serialize(to);

    Util::PushULongInVector(to,_certType);

    Util::PushULongInVector(to,_certCategory);

    Util::PushBBoolInVector(to,_trusted);

    Util::PushByteArrayInVector(to,m_pStartDate.get( ));

    Util::PushByteArrayInVector(to,m_pEndDate.get( ));

    Util::PushByteArrayInVector(to,m_pCheckSum.get( ));

    // serialize the extra fields
    
    Util::PushULongLongInVector( to,_checkValue );

    Util::PushBBoolInVector(to,m_ucContainerIndex);

    Util::PushBBoolInVector(to,m_ucKeySpec);
}


void CertificateObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    StorageObject::deserialize(from,idx);

    _certType = Util::ReadULongFromVector(from,idx);

    _certCategory = Util::ReadULongFromVector(from,idx);

    _trusted = Util::ReadBBoolFromVector(from,idx);

    m_pStartDate.reset( Util::ReadByteArrayFromVector(from,idx));

    m_pEndDate.reset( Util::ReadByteArrayFromVector(from,idx));

    m_pCheckSum.reset( Util::ReadByteArrayFromVector(from,idx));

    // serialize the extra fields
 
	// Read old checkvalue field
    Util::ReadULongLongFromVector(from,idx);

    m_ucContainerIndex = Util::ReadBBoolFromVector(from,idx);

    m_ucKeySpec = Util::ReadBBoolFromVector(from,idx);
}


/*
*/
void CertificateObject::print( void ) {

    StorageObject::print( );

    Log::log( "CKA_CERTIFICATE_TYPE <%ld>", _certType );

    Log::log( "CKA_TRUSTED <%ld>", _trusted );

    Log::log( "CKA_CERTIFICATE_CATEGORY <%ld>", _certCategory );

    if( m_pCheckSum ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_CHECK_VALUE", m_pCheckSum->GetBuffer( ), m_pCheckSum->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_CHECK_VALUE <null>" );
    }

    if( m_pStartDate ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_START_DATE", m_pStartDate->GetBuffer( ), m_pStartDate->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_START_DATE <null>" );
    }

    if( m_pEndDate ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_END_DATE", m_pEndDate->GetBuffer( ), m_pEndDate->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_END_DATE <null>" );
    }


    Log::log( "[Certificate Name <%s>]", m_stCertificateName.c_str( ) );

    Log::log( "[Container Index <%d>]", m_ucContainerIndex );

    Log::log( "[KeySpec <%d>]", m_ucKeySpec );
}
