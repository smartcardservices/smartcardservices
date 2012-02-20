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
#include "Pkcs11ObjectKeyPrivate.hpp"
#include "PKCS11Exception.hpp"


PrivateKeyObject :: PrivateKeyObject( ) : KeyObject( ) {

    m_Class = CKO_PRIVATE_KEY;
    _sensitive = CK_TRUE;
    _decrypt = CK_TRUE;
    _sign = CK_TRUE;
    _signRecover = CK_TRUE;
    _unwrap = CK_FALSE;
    _extractable = CK_FALSE;
    _alwaysSensitive = CK_TRUE;
    _neverExtractable = CK_TRUE;
    _wrapWithTrusted = CK_FALSE;
    _alwaysAuthenticate = CK_FALSE;
    _keyType = CK_UNAVAILABLE_INFORMATION;
    _checkValue = 0;
}


PrivateKeyObject :: PrivateKeyObject( const PrivateKeyObject* p ) : KeyObject( p ) {

    if( p ) {

        m_Class = p->m_Class;
        _sensitive = p->_sensitive;
        _decrypt = p->_decrypt;
        _sign = p->_sign;
        _signRecover = p->_signRecover;
        _unwrap = p->_unwrap;
        _extractable = p->_extractable;
        _alwaysSensitive = p->_alwaysSensitive;
        _neverExtractable = p->_neverExtractable;
        _wrapWithTrusted = p->_wrapWithTrusted;
        _alwaysAuthenticate = p->_alwaysAuthenticate;
        _keyType  = p->_keyType;
        _checkValue = p->_checkValue;

    } else {

        m_Class = CKO_PRIVATE_KEY;
        _sensitive = CK_TRUE;
        _decrypt = CK_TRUE;
        _sign = CK_TRUE;
        _signRecover = CK_TRUE;
        _unwrap = CK_FALSE;
        _extractable = CK_FALSE;
        _alwaysSensitive = CK_TRUE;
        _neverExtractable = CK_TRUE;
        _wrapWithTrusted = CK_FALSE;
        _alwaysAuthenticate = CK_FALSE;
        _keyType = CK_UNAVAILABLE_INFORMATION;
        _checkValue = 0;
    }
}



bool PrivateKeyObject::isEqual( StorageObject * that) const
{
    if( m_Class != that->getClass( ) ) {

        return false;
    }

    const PrivateKeyObject * thatCert = static_cast< const PrivateKeyObject* >( that );

    return ( (m_ucContainerIndex == thatCert->m_ucContainerIndex) && (m_ucKeySpec == thatCert->m_ucKeySpec) );
}

bool PrivateKeyObject::compare( const CK_ATTRIBUTE& attribute)
{
    switch(attribute.type){

        case CKA_SENSITIVE:
            return (_sensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_DECRYPT:
            return (_decrypt == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN:
            return (_sign == *(CK_BBOOL*)attribute.pValue);

        case CKA_SIGN_RECOVER:
            return (_signRecover == *(CK_BBOOL*)attribute.pValue);

        case CKA_UNWRAP:
            return (_unwrap == *(CK_BBOOL*)attribute.pValue);

        case CKA_EXTRACTABLE:
            return (_extractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_SENSITIVE:
            return (_alwaysSensitive == *(CK_BBOOL*)attribute.pValue);

        case CKA_NEVER_EXTRACTABLE:
            return (_neverExtractable == *(CK_BBOOL*)attribute.pValue);

        case CKA_WRAP_WITH_TRUSTED:
            return (_wrapWithTrusted == *(CK_BBOOL*)attribute.pValue);

        case CKA_ALWAYS_AUTHENTICATE:
            return (_alwaysAuthenticate == *(CK_BBOOL*)attribute.pValue);

        case CKA_SUBJECT:
            return Util::compareU1Arrays( m_pSubject.get( ), (unsigned char*)attribute.pValue, attribute.ulValueLen );

        default:
            return KeyObject::compare(attribute);

    }
}

void PrivateKeyObject::getAttribute( CK_ATTRIBUTE_PTR attribute )
{
    switch(attribute->type){

        case CKA_SENSITIVE:
            StorageObject::putBBoolInAttribute(_sensitive,attribute);
        break;

        case CKA_DECRYPT:
            StorageObject::putBBoolInAttribute(_decrypt,attribute);
        break;

        case CKA_SIGN:
            StorageObject::putBBoolInAttribute(_sign,attribute);
        break;

        case CKA_SIGN_RECOVER:
            StorageObject::putBBoolInAttribute(_signRecover,attribute);
        break;

        case CKA_UNWRAP:
            StorageObject::putBBoolInAttribute(_unwrap,attribute);
        break;

        case CKA_EXTRACTABLE:
            StorageObject::putBBoolInAttribute(_extractable,attribute);
        break;

        case CKA_ALWAYS_SENSITIVE:
            StorageObject::putBBoolInAttribute(_alwaysSensitive,attribute);
        break;

        case CKA_NEVER_EXTRACTABLE:
            StorageObject::putBBoolInAttribute(_neverExtractable,attribute);
        break;

        case CKA_WRAP_WITH_TRUSTED:
            StorageObject::putBBoolInAttribute(_wrapWithTrusted,attribute);
        break;

        case CKA_ALWAYS_AUTHENTICATE:
            StorageObject::putBBoolInAttribute(_alwaysAuthenticate,attribute);
        break;

        case CKA_SUBJECT:
            StorageObject::putU1ArrayInAttribute( m_pSubject.get( ), attribute );
        break;

        default:
            KeyObject::getAttribute(attribute);
        break;
    }
}


/*
*/
void PrivateKeyObject::setAttribute( const CK_ATTRIBUTE& a_Attribute, const bool& objCreation ) {

   if( !a_Attribute.ulValueLen )
   {
      return;
   }

    if( !objCreation )
    {
        switch( a_Attribute.type )
        {
            case CKA_ALWAYS_AUTHENTICATE:
            case CKA_ALWAYS_SENSITIVE:
            case CKA_NEVER_EXTRACTABLE:
                throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );

            case CKA_DECRYPT:
            case CKA_EXTRACTABLE:
            case CKA_SENSITIVE:
            case CKA_SIGN:
            case CKA_SIGN_RECOVER:
            case CKA_UNWRAP:
            case CKA_WRAP_WITH_TRUSTED:
                if( *(CK_BBOOL*)a_Attribute.pValue ) {

                    throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
                }
                break;
        }
    }

    switch(a_Attribute.type){

        case CKA_SENSITIVE:
            {
                CK_BBOOL btemp = StorageObject::readBBoolFromAttribute( a_Attribute );

                    if( !objCreation && _sensitive && !btemp ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
                    
					}else{

                        _sensitive = btemp;

                        if( !btemp ){

                            _alwaysSensitive = CK_FALSE;
                        }
                    }
            }
            break;

        case CKA_DECRYPT:
            _decrypt = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_SIGN:
            _sign = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_SIGN_RECOVER:
            _signRecover = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_UNWRAP:
            _unwrap = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_EXTRACTABLE:
            {
                CK_BBOOL btemp = StorageObject::readBBoolFromAttribute( a_Attribute );

                    if( !objCreation && !_extractable && btemp ) {

                        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );

                    } else {

                        _extractable = btemp;

                        if( btemp ) {

                            _neverExtractable = CK_FALSE;
                        }
                    }
            }
            break;

        case CKA_ALWAYS_SENSITIVE:
            _alwaysSensitive = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;


        case CKA_NEVER_EXTRACTABLE:
            _neverExtractable = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_WRAP_WITH_TRUSTED:
            _wrapWithTrusted = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_ALWAYS_AUTHENTICATE:
            _alwaysAuthenticate = StorageObject::readBBoolFromAttribute( a_Attribute );
            break;

        case CKA_SUBJECT:
            m_pSubject.reset( StorageObject::readU1ArrayFromAttribute( a_Attribute ) );

            break;

        default:
            KeyObject::setAttribute( a_Attribute, objCreation );
    }
}

void PrivateKeyObject::serialize(std::vector<u1> *to)
{
    KeyObject::serialize(to);

    Util::PushBBoolInVector(to,_sensitive);

    Util::PushBBoolInVector(to,_decrypt);

    Util::PushBBoolInVector(to,_sign);

    Util::PushBBoolInVector(to,_signRecover);

    Util::PushBBoolInVector(to,_unwrap);

    Util::PushBBoolInVector(to,_extractable);

    Util::PushBBoolInVector(to,_alwaysSensitive);

    Util::PushBBoolInVector(to,_neverExtractable);

    Util::PushBBoolInVector(to,_wrapWithTrusted);

    Util::PushBBoolInVector(to,_alwaysAuthenticate);

    Util::PushByteArrayInVector( to, m_pSubject.get( ) );

    // serialize the extra fields

    Util::PushULongLongInVector(to,_checkValue);

    Util::PushBBoolInVector(to,m_ucContainerIndex);

    Util::PushBBoolInVector(to,m_ucKeySpec);
}

void PrivateKeyObject::deserialize(std::vector<u1>& from, CK_ULONG_PTR idx)
{
    KeyObject::deserialize(from,idx);

    _sensitive = Util::ReadBBoolFromVector(from,idx);

    _decrypt = Util::ReadBBoolFromVector(from,idx);

    _sign = Util::ReadBBoolFromVector(from,idx);

    _signRecover = Util::ReadBBoolFromVector(from,idx);

    _unwrap = Util::ReadBBoolFromVector(from,idx);

    _extractable = Util::ReadBBoolFromVector(from,idx);

    _alwaysSensitive = Util::ReadBBoolFromVector(from,idx);

    _neverExtractable = Util::ReadBBoolFromVector(from,idx);

    _wrapWithTrusted = Util::ReadBBoolFromVector(from,idx);

    _alwaysAuthenticate = Util::ReadBBoolFromVector(from,idx);

    m_pSubject.reset( Util::ReadByteArrayFromVector( from, idx ) );

    // deserialize extra fields

	/*u8 _checkValue = */Util::ReadULongLongFromVector(from,idx);

    m_ucContainerIndex = Util::ReadBBoolFromVector(from,idx);

    m_ucKeySpec = Util::ReadBBoolFromVector(from,idx);
}


/*
*/
void PrivateKeyObject::print( void ) {

    KeyObject::print( );

    if( m_pSubject.get( ) ) {

        Log::logCK_UTF8CHAR_PTR( "CKA_SUBJECT", m_pSubject->GetBuffer( ), m_pSubject->GetLength( ) );
    
    } else {
    
        Log::log( "CKA_SUBJECT <null>" );
    }

    Log::log( "CKA_SENSITIVE <%ld>", _sensitive );
        
    Log::log( "CKA_DECRYPT <%ld>", _decrypt );

    Log::log( "CKA_SIGN <%ld>", _sign );

    Log::log( "CKA_SIGN_RECOVER <%ld>", _signRecover );

    Log::log( "CKA_UNWRAP <%ld>", _unwrap );

    Log::log( "CKA_EXTRACTABLE <%ld>", _extractable );

    Log::log( "CKA_ALWAYS_SENSITIVE <%ld>", _alwaysSensitive );

    Log::log( "CKA_NEVER_EXTRACTABLE <%ld>", _neverExtractable );

    Log::log( "CKA_WRAP_WITH_TRUSTED <%ld>", _wrapWithTrusted );

    Log::log( "CKA_ALWAYS_AUTHENTICATE <%ld>", _alwaysAuthenticate );
}
