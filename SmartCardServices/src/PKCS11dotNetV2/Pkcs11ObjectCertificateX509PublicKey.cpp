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
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"
#include "PKCS11Exception.hpp"


/*
*/
X509PubKeyCertObject::X509PubKeyCertObject( ) {

	_certType = CKC_X_509;

    _certCategory = 1; // Set as "token user"
	
    _trusted = CK_TRUE;
    
	m_bIsSmartCardLogon = false;

    m_bIsRoot = false;
}


/*
*/
bool X509PubKeyCertObject::compare( const CK_ATTRIBUTE& a_Attribute ) {

	switch( a_Attribute.type ) {

	case CKA_SUBJECT:
		return Util::compareU1Arrays( m_pSubject.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_ID:
        {
            Log::logCK_UTF8CHAR_PTR( "X509PubKeyCertObject::compare - Attribute", (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

            if( m_pID.get( ) ) {
            
                Log::logCK_UTF8CHAR_PTR( "X509PubKeyCertObject::compare - CKA_ID", m_pID->GetBuffer( ), m_pID->GetLength( ) );
            
            } else {
            
                Log::log( "X509PubKeyCertObject::compare - CKA_ID <null>" );
            }
		
            return Util::compareU1Arrays( m_pID.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );
        }

	case CKA_ISSUER:
		return Util::compareU1Arrays( m_pIssuer.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_SERIAL_NUMBER:
		return Util::compareU1Arrays( m_pSerialNumber.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_VALUE:
		return Util::compareU1Arrays( m_pValue.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_URL:
		return Util::compareU1Arrays( m_pURL.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		return Util::compareU1Arrays( m_pHashOfSubjectPubKey.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		return Util::compareU1Arrays( m_pHashOfIssuerPubKey.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

	default:
		return CertificateObject::compare( a_Attribute );
	}
}


/*
*/
void X509PubKeyCertObject::setAttribute( const CK_ATTRIBUTE& attribute, const bool& objCreation ) {

	//if( !attribute.ulValueLen ) {

	//	return;
	//}

	if( !objCreation && ( ( CKA_SUBJECT == attribute.type ) || ( CKA_VALUE == attribute.type ) ) ) {

			throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
	}

	switch( attribute.type ) {

	case CKA_SUBJECT:
		m_pSubject.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
		break;

	case CKA_ID:
        m_pID.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
        break;

	case CKA_ISSUER:
		m_pIssuer.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
		break;

	case CKA_SERIAL_NUMBER:
		m_pSerialNumber.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
		break;

	case CKA_VALUE:
		m_pValue.reset( StorageObject::readU1ArrayFromAttribute( attribute ) );
		break;

	case CKA_URL:
		m_pURL.reset( StorageObject::/*readStringFromAttribute*/readU1ArrayFromAttribute( attribute ) );
		break;

	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		m_pHashOfSubjectPubKey.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
		break;

	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		m_pHashOfIssuerPubKey.reset( StorageObject::readU1ArrayFromAttribute(attribute) );
		break;

	default:
		CertificateObject::setAttribute( attribute, objCreation );
	}
}


/*
*/
void X509PubKeyCertObject::getAttribute( CK_ATTRIBUTE_PTR attribute ) {

	switch( attribute->type ) {

	case CKA_SUBJECT:
		StorageObject::putU1ArrayInAttribute( m_pSubject.get( ), attribute );
        break;

	case CKA_ID:
		StorageObject::putU1ArrayInAttribute( m_pID.get( ),attribute);
        break;

	case CKA_ISSUER:
		StorageObject::putU1ArrayInAttribute(m_pIssuer.get( ),attribute);
        break;

    case CKA_SERIAL_NUMBER:
		StorageObject::putU1ArrayInAttribute(m_pSerialNumber.get( ),attribute);
        break;

	case CKA_VALUE:
		StorageObject::putU1ArrayInAttribute(m_pValue.get( ),attribute);
        break;

	case CKA_URL:
		StorageObject::putU1ArrayInAttribute(m_pURL.get( ),attribute);
        break;

	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		StorageObject::putU1ArrayInAttribute(m_pHashOfSubjectPubKey.get( ),attribute);
        break;

	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		StorageObject::putU1ArrayInAttribute(m_pHashOfIssuerPubKey.get( ),attribute);
        break;

	default:
		CertificateObject::getAttribute(attribute);
        break;
	}
}


/*
*/
void X509PubKeyCertObject::serialize(std::vector<u1> *to)
{
	CertificateObject::serialize(to);

	Util::PushByteArrayInVector( to, m_pSubject.get( ) );

	Util::PushByteArrayInVector(to, m_pID.get( ) );

	Util::PushByteArrayInVector(to,m_pIssuer.get( ) );

	Util::PushByteArrayInVector(to,m_pSerialNumber.get( ) );

	Util::PushByteArrayInVector(to,m_pURL.get( ) );

	Util::PushByteArrayInVector(to,m_pHashOfSubjectPubKey.get( ) );

	Util::PushByteArrayInVector(to,m_pHashOfIssuerPubKey.get( ) );
}

 
/*
*/
void X509PubKeyCertObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
	CertificateObject::deserialize(from,idx);

	m_pSubject.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pID.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pIssuer.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pSerialNumber.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pURL.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pHashOfSubjectPubKey.reset( Util::ReadByteArrayFromVector( from, idx ) );

	m_pHashOfIssuerPubKey.reset( Util::ReadByteArrayFromVector( from, idx ) );
}


/*
*/
void X509PubKeyCertObject::print( void ) {

    CertificateObject::print( );

    if( m_pSubject.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_SUBJECT", m_pSubject->GetBuffer( ), m_pSubject->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_SUBJECT <null>" );
    }

    if( m_pID.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_ID", m_pID->GetBuffer( ), m_pID->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_ID <null>" );
    }

    if( m_pIssuer.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_ISSUER", m_pIssuer->GetBuffer( ), m_pIssuer->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_ISSUER <null>" );
    }

    if( m_pSerialNumber.get( ) ) {
    
        Log::logCK_UTF8CHAR_PTR( "CKA_SERIAL_NUMBER", m_pSerialNumber->GetBuffer( ), m_pSerialNumber->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_SERIAL_NUMBER <null>" );
    }

    if( m_pValue.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_VALUE", m_pValue->GetBuffer( ), m_pValue->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_VALUE <null>" );
    }

    if( m_pURL.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_URL", m_pURL->GetBuffer( ), m_pURL->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_URL <null>" );
    }

    if( m_pHashOfSubjectPubKey.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", m_pHashOfSubjectPubKey->GetBuffer( ), m_pHashOfSubjectPubKey->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_HASH_OF_SUBJECT_PUBLIC_KEY <null>" );
    }

    if( m_pHashOfIssuerPubKey.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_HASH_OF_ISSUER_PUBLIC_KEY", m_pHashOfIssuerPubKey->GetBuffer( ), m_pHashOfIssuerPubKey->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_HASH_OF_ISSUER_PUBLIC_KEY <null>" );
    }

    Log::log( "[IsSmartCardLogon <%d>]", m_bIsSmartCardLogon );

    Log::log( "[IsRoot <%d>]", m_bIsRoot );
}
