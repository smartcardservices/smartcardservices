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
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "PKCS11Exception.hpp"


Pkcs11ObjectKeyPublicRSA::Pkcs11ObjectKeyPublicRSA( ) : Pkcs11ObjectKeyPublic( ) {

    m_ulModulusBits = 0;

    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;
}


Pkcs11ObjectKeyPublicRSA::Pkcs11ObjectKeyPublicRSA( const Pkcs11ObjectKeyPublicRSA* p ) : Pkcs11ObjectKeyPublic( p ) {


    _keyType = CKK_RSA;

    _mechanismType = CKM_RSA_PKCS_KEY_PAIR_GEN;

    if( p ) {

        m_ulModulusBits = p->m_ulModulusBits;

        if( p->m_pModulus.get( ) ) {

            Marshaller::u1Array* x = new Marshaller::u1Array( *(p->m_pModulus.get( )) );

            m_pModulus.reset( x );

        } else {

            m_pModulus.reset( );
        }

        if( p->m_pPublicExponent.get( ) ) {

            Marshaller::u1Array* x = new Marshaller::u1Array( *(p->m_pPublicExponent.get( )) );

            m_pPublicExponent.reset( x );

        } else {

            m_pPublicExponent.reset( );
        }
    } else {

        m_ulModulusBits = 0;

        m_pModulus.reset( );
        m_pPublicExponent.reset( );
    }
}


bool Pkcs11ObjectKeyPublicRSA ::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

    case CKA_MODULUS:
        return Util::compareU1Arrays(m_pModulus.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    case CKA_MODULUS_BITS:
        return (m_ulModulusBits == *(CK_ULONG*)attribute.pValue);

    case CKA_PUBLIC_EXPONENT:
        return Util::compareU1Arrays(m_pModulus.get( ), (unsigned char*)attribute.pValue,attribute.ulValueLen);

    default:
        return Pkcs11ObjectKeyPublic::compare(attribute);
    }
}

void Pkcs11ObjectKeyPublicRSA ::getAttribute(CK_ATTRIBUTE_PTR attribute)
{
    switch(attribute->type){

    case CKA_MODULUS:
        StorageObject::putU1ArrayInAttribute(m_pModulus.get( ),attribute);
        break;

    case CKA_MODULUS_BITS:
        StorageObject::putULongInAttribute(m_ulModulusBits,attribute);
        break;

    case CKA_PUBLIC_EXPONENT:
        StorageObject::putU1ArrayInAttribute(m_pPublicExponent.get( ),attribute);
        break;

    default:
        Pkcs11ObjectKeyPublic::getAttribute(attribute);
        break;
    }
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& a_bObjCreation ) {

    if( !a_Attribute.ulValueLen ) {

        return;
    }

    if( !a_bObjCreation ) {

        switch( a_Attribute.type ) {

        case CKA_PUBLIC_EXPONENT:
        case CKA_MODULUS:
        case CKA_MODULUS_BITS:
            throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
        }
    }

    switch( a_Attribute.type ) {

    case CKA_MODULUS:
        m_pModulus.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        m_ulModulusBits = m_pModulus->GetLength()*8;
        break;

    case CKA_PUBLIC_EXPONENT:
        m_pPublicExponent.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    case CKA_MODULUS_BITS:
        m_ulModulusBits = StorageObject::readULongFromAttribute( a_Attribute );
        break;

    default:
        Pkcs11ObjectKeyPublic::setAttribute( a_Attribute, a_bObjCreation );
    }
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::serialize( std::vector<u1> *to ) {

    Pkcs11ObjectKeyPublic::serialize(to);

    Util::PushByteArrayInVector(to,m_pModulus.get( ) );

    Util::PushByteArrayInVector(to,m_pPublicExponent.get( ) );

    Util::PushULongInVector(to,m_ulModulusBits);
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::deserialize( std::vector<u1>& from, CK_ULONG_PTR idx ) {

    Pkcs11ObjectKeyPublic::deserialize( from, idx );

    m_pModulus.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_pPublicExponent.reset( Util::ReadByteArrayFromVector( from, idx ) );

    m_ulModulusBits = Util::ReadULongFromVector( from, idx );
}


/*
*/
void Pkcs11ObjectKeyPublicRSA::print( void ) {

    Pkcs11ObjectKeyPublic::print( );

    Log::log( "CKA_MODULUS_BITS <%ld>", m_ulModulusBits );

    if( m_pModulus.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_MODULUS", m_pModulus->GetBuffer( ), m_pModulus->GetLength( ) );

    } else {

        Log::log( "CKA_MODULUS <null>" );
    }

    if( m_pPublicExponent.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_PUBLIC_EXPONENT", m_pPublicExponent->GetBuffer( ), m_pPublicExponent->GetLength( ) );

    } else {

        Log::log( "CKA_PUBLIC_EXPONENT <null>" );
    }
}
