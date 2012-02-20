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
#include "Pkcs11ObjectKeyPublic.hpp"
#include "PKCS11Exception.hpp"


Pkcs11ObjectKeyPublic::Pkcs11ObjectKeyPublic( ) : KeyObject( ) {

    m_Class         = CKO_PUBLIC_KEY;

    _encrypt       = CK_TRUE;
    _verify        = CK_TRUE;
    _verifyRecover = CK_TRUE;
    _wrap          = CK_FALSE;
    _trusted = CK_TRUE;
    _keyType  = CK_UNAVAILABLE_INFORMATION;
}


Pkcs11ObjectKeyPublic::Pkcs11ObjectKeyPublic( const Pkcs11ObjectKeyPublic* p ) : KeyObject( p ) {

    m_Class = CKO_PUBLIC_KEY;

    if( p ) {

        _encrypt       = p->_encrypt;
        _verify        = p->_verify;
        _verifyRecover = p->_verifyRecover;
        _wrap          = p->_wrap;
        _keyType  = p->_keyType;
        _trusted = p->_trusted;

        if( p->m_pSubject.get( ) ) {

            Marshaller::u1Array* pLabel = new Marshaller::u1Array( *(p->m_pSubject.get( )) );

            m_pSubject.reset( pLabel );

        } else {

            m_pSubject.reset( );
        }

    } else {

        _encrypt       = CK_TRUE;
        _verify        = CK_TRUE;
        _verifyRecover = CK_TRUE;
        _wrap          = CK_FALSE;

        _keyType  = CK_UNAVAILABLE_INFORMATION;

        _trusted = CK_TRUE;

        m_pSubject.reset( );
    }
}


bool Pkcs11ObjectKeyPublic::compare( const CK_ATTRIBUTE& a_Attribute)
{
    switch(a_Attribute.type){

    case CKA_ENCRYPT:
        return (_encrypt == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_VERIFY:
        return (_verify == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_VERIFY_RECOVER:
        return (_verifyRecover == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_WRAP:
        return (_wrap == *(CK_BBOOL*)a_Attribute.pValue);

    case CKA_SUBJECT:
        return Util::compareU1Arrays( m_pSubject.get( ), (unsigned char*)a_Attribute.pValue, a_Attribute.ulValueLen );

    default:
        return KeyObject::compare(a_Attribute);
    }
}


void Pkcs11ObjectKeyPublic::getAttribute(CK_ATTRIBUTE_PTR a_Attribute)
{
    switch(a_Attribute->type){

    case CKA_ENCRYPT:
        StorageObject::putBBoolInAttribute(_encrypt,a_Attribute);
        break;

    case CKA_VERIFY:
        StorageObject::putBBoolInAttribute(_verify,a_Attribute);
        break;

    case CKA_VERIFY_RECOVER:
        StorageObject::putBBoolInAttribute(_verifyRecover,a_Attribute);
        break;

    case CKA_WRAP:
        StorageObject::putBBoolInAttribute(_wrap,a_Attribute);
        break;

    case CKA_SUBJECT:
        StorageObject::putU1ArrayInAttribute( m_pSubject.get( ), a_Attribute );
        break;

    default:
        KeyObject::getAttribute(a_Attribute);
        break;

    }
}


void Pkcs11ObjectKeyPublic::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation)
{
    //if( 0 == a_Attribute.ulValueLen )
    //{
    //    return;
    //}

    if(objCreation == CK_FALSE){
        switch(a_Attribute.type){
        case CKA_ENCRYPT:
        case CKA_TRUSTED:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_WRAP:
            if(*(CK_BBOOL*)a_Attribute.pValue == CK_TRUE){
                throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
            }
            break;
        }
    }

    switch(a_Attribute.type){

    case CKA_ENCRYPT:
        _encrypt = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_VERIFY:
        _verify = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_VERIFY_RECOVER:
        _verifyRecover = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_WRAP:
        _wrap = StorageObject::readBBoolFromAttribute( a_Attribute );
        break;

    case CKA_SUBJECT:
        m_pSubject.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );
        break;

    default:
        KeyObject::setAttribute(a_Attribute,objCreation);
    }
}


void Pkcs11ObjectKeyPublic::serialize(std::vector<u1> *to)
{
    KeyObject::serialize(to);

    Util::PushBBoolInVector(to,_encrypt);

    Util::PushBBoolInVector(to,_verify);

    Util::PushBBoolInVector(to,_verifyRecover);

    Util::PushBBoolInVector(to,_wrap);

    Util::PushByteArrayInVector(to, m_pSubject.get( ) );

    // serialize the extra fields
    Util::PushBBoolInVector(to,m_ucContainerIndex);

    Util::PushBBoolInVector(to,m_ucKeySpec);
}

void Pkcs11ObjectKeyPublic::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    KeyObject::deserialize(from,idx);

    _encrypt = Util::ReadBBoolFromVector(from,idx);

    _verify = Util::ReadBBoolFromVector(from,idx);

    _verifyRecover = Util::ReadBBoolFromVector(from,idx);

    _wrap = Util::ReadBBoolFromVector(from,idx);

    m_pSubject.reset( Util::ReadByteArrayFromVector(from,idx) );

    // deserialize extra fields
    m_ucContainerIndex = Util::ReadBBoolFromVector(from,idx);

    m_ucKeySpec = Util::ReadBBoolFromVector(from,idx);
}


/*
*/
void Pkcs11ObjectKeyPublic::print( void ) {

    KeyObject::print( );

    if( m_pSubject.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_SUBJECT", m_pSubject->GetBuffer( ), m_pSubject->GetLength( ) );

    } else {

        Log::log( "CKA_SUBJECT <null>" );
    }

    Log::log( "CKA_ENCRYPT <%ld>", _encrypt );

    Log::log( "CKA_VERIFY <%ld>", _verify );

    Log::log( "CKA_VERIFY_RECOVER <%ld>", _verifyRecover );

    Log::log( "CKA_WRAP <%ld>", _wrap );

    Log::log( "CKA_TRUSTED <%ld>", _trusted );
}
