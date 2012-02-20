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


#include "MiniDriverContainer.hpp"
#include <boost/foreach.hpp>
#include <memory>
#include "Log.hpp"


const unsigned char g_ucPublicKeyExponentLen = 4;
const unsigned char g_ucPublicKeyModulusLen = 4;
#define CONTAINER_MAP_RECORD_GUID_SIZE 40 * sizeof( WCHAR )


/*
*/
MiniDriverContainer::MiniDriverContainer( ) {

    clear( );
}


/*
*/
void MiniDriverContainer::clear( void ) {

    memset( &m_ContainerMapRecord, 0, sizeof( CONTAINER_MAP_RECORD ) );

    m_bIsSmartCardLogon = false;

    m_ucSignatureContainerType = 0;

    m_ucExchangeContainerType = 0;

    m_PinIdentifier = MiniDriverAuthentication::PIN_USER;
}


/*
*/
void MiniDriverContainer::setContainerMapRecord( CONTAINER_MAP_RECORD* a_pContainerMapRecord ) {

    Log::begin( "MiniDriverContainer::setContainerMapRecord" );

    if( a_pContainerMapRecord->wSigKeySizeBits || a_pContainerMapRecord->wKeyExchangeKeySizeBits ) {

        m_ContainerMapRecord.bFlags = a_pContainerMapRecord->bFlags;

        m_ContainerMapRecord.wKeyExchangeKeySizeBits = a_pContainerMapRecord->wKeyExchangeKeySizeBits;

        m_ContainerMapRecord.wSigKeySizeBits = a_pContainerMapRecord->wSigKeySizeBits;

        if( a_pContainerMapRecord->wszGuid ) {

            memcpy( m_ContainerMapRecord.wszGuid, a_pContainerMapRecord->wszGuid, CONTAINER_MAP_RECORD_GUID_SIZE );
        
        } else {

            memset( m_ContainerMapRecord.wszGuid, 0, CONTAINER_MAP_RECORD_GUID_SIZE );
        }
    }

    //print( );
    Log::end( "MiniDriverContainer::setContainerMapRecord" );
}


/*
*/
void MiniDriverContainer::setContainerInformation( const boost::shared_ptr< Marshaller::u1Array >& a_pContainerInformation ) {

    Log::begin( "MiniDriverContainer::setContainerInformation" );
    std::string s;
    Log::toString( a_pContainerInformation->GetBuffer( ), a_pContainerInformation->GetLength( ), s );
    Log::log( "ContainerInformation <%s>", s.c_str( ) );

    // The container information is a byte array blob containing the public key(s) in the selected container. 
    // The blob is formatted as follows:  Blob = [Signature_Pub_Key] | [Exchange_Pub_Key] 
    // Signature_Pub_Key and Exchange_Pub_Key are optional depending on which key exists in the container and it’s a sequence of 3 TLV formatted as follows: 
    
    //T_Key_Type = 0x03 
    //L_Key_Type = 0x01 
    //V_Key_Type = 0x01 for Exchange_Pub_Key or 0x02 for Signature_Pub_Key 
    
    //T_Key_Pub_Exp = 0x01 
    //L_Key_Pub_Exp = 0x04 
    //V_Key_Pub_Exp = Value of Public key Exponent on 4 bytes. 
    
    //T_Key_Modulus = 0x02 
    //L_Key_Modulus = Key_Size_Bytes >> 4 (1 byte !) 
    //V_Key_Modulus = Value of Public key Modulus on Key_Size_Bytes bytes.

    // Get the first public key  type
    unsigned int iOffset = 2;
    unsigned char ucFirstPublicKeyType = a_pContainerInformation->ReadU1At( iOffset );

    // Read the first public key exponent value
    iOffset += 2;
    unsigned int uiFirstPublicKeyExponentLength = a_pContainerInformation->ReadU1At( iOffset );

    // Read the first public key exponent value
    iOffset += 1;
    Marshaller::u1Array* pFirstPublicKeyExponent = new Marshaller::u1Array( g_ucPublicKeyExponentLen );
    
    // The exponent must be a 4 bytes buffer.
    if( uiFirstPublicKeyExponentLength < g_ucPublicKeyExponentLen ) {
    
        // Add zero at the head of the buffer
        memset( pFirstPublicKeyExponent->GetBuffer( ), 0, g_ucPublicKeyExponentLen );
    
        int iPaddingLength = g_ucPublicKeyExponentLen - uiFirstPublicKeyExponentLength;

        memcpy( pFirstPublicKeyExponent->GetBuffer( ) + iPaddingLength, a_pContainerInformation->GetBuffer( ) + iOffset, uiFirstPublicKeyExponentLength );

    } else {
    
        memcpy( pFirstPublicKeyExponent->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, g_ucPublicKeyExponentLen );
    }

    // Read the first public key modulus len.
    // Keep in mind that the signature public key modulus len is stored as a 4 rigth-shifted byte (>>4) to pass the modulus length on 1 byte ofr values 64 to 256 (512 to 2048bits)
    iOffset += uiFirstPublicKeyExponentLength + 1;
    int ucPublicKeyModulusLen = a_pContainerInformation->ReadU1At( iOffset ) << 4;

    // Read the first public key modulus value
    iOffset += 1;
    Marshaller::u1Array* pFirstPublicKeyModulus = new Marshaller::u1Array( ucPublicKeyModulusLen );
    memcpy( pFirstPublicKeyModulus->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, ucPublicKeyModulusLen );

    if( KEYSPEC_EXCHANGE == ucFirstPublicKeyType ) {

        m_pExchangePublicKeyExponent.reset( pFirstPublicKeyExponent );

        m_pExchangePublicKeyModulus.reset( pFirstPublicKeyModulus );

    } else {

        m_pSignaturePublicKeyExponent.reset( pFirstPublicKeyExponent );

        m_pSignaturePublicKeyModulus.reset( pFirstPublicKeyModulus );   
    }

    // Check if the second key information is present into the container information
    iOffset += ucPublicKeyModulusLen + 1;
    if( iOffset < a_pContainerInformation->GetLength( ) ) {

        // Read the second public key type
        iOffset += 2;
        unsigned char ucSecondPublicKeyType = a_pContainerInformation->ReadU1At( iOffset );

        // Read the second public key exponent value
        iOffset += 2;
        unsigned int uiSecondPublicKeyExponentLength = a_pContainerInformation->ReadU1At( iOffset );

        // The exponent must be a 4 bytes buffer.
        Marshaller::u1Array* pSecondPublicKeyExponent = new Marshaller::u1Array( g_ucPublicKeyExponentLen );

        if( uiSecondPublicKeyExponentLength < g_ucPublicKeyExponentLen ) {
    
            // Add zero at the head of the buffer
            memset( pSecondPublicKeyExponent->GetBuffer( ), 0, g_ucPublicKeyExponentLen );
    
            int iPaddingLength = g_ucPublicKeyExponentLen - uiSecondPublicKeyExponentLength;

            memcpy( pSecondPublicKeyExponent->GetBuffer( ) + iPaddingLength, a_pContainerInformation->GetBuffer( ) + iOffset, uiSecondPublicKeyExponentLength );

        } else {
    
            memcpy( pSecondPublicKeyExponent->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, g_ucPublicKeyExponentLen );
        }

        // Read the second public key modulus len.
        // Keep in mind that the signature public key modulus len is stored as a 4 rigth-shifted byte (>>4) to pass the modulus length on 1 byte ofr values 64 to 256 (512 to 2048bits)
        iOffset += uiSecondPublicKeyExponentLength + 1;

        ucPublicKeyModulusLen = a_pContainerInformation->ReadU1At( iOffset ) << 4;

        // Read the second public key modulus value
        ++iOffset;
        Marshaller::u1Array* pSecondPublicKeyModulus = new Marshaller::u1Array( ucPublicKeyModulusLen );
        memcpy( pSecondPublicKeyModulus->GetBuffer( ), a_pContainerInformation->GetBuffer( ) + iOffset, ucPublicKeyModulusLen );

        if( KEYSPEC_EXCHANGE == ucSecondPublicKeyType ) {

            m_pExchangePublicKeyExponent.reset( pSecondPublicKeyExponent );

            m_pExchangePublicKeyModulus.reset( pSecondPublicKeyModulus );

        } else {

            m_pSignaturePublicKeyExponent.reset( pSecondPublicKeyExponent );

            m_pSignaturePublicKeyModulus.reset( pSecondPublicKeyModulus );   
        }
    }

    //print( );
    Log::end( "MiniDriverContainer::setContainerInformation" );
}


/*
*/ 
void MiniDriverContainer::print( void ) {

    if( !Log::s_bEnableLog ) {
    
        return;
    }

    Log::log( "MiniDriverContainer - ===" );

    Log::log( "MiniDriverContainer - [SmartCard Logon <%d>]", m_bIsSmartCardLogon );

    Log::log( "MiniDriverContainer - Flag <%#02x>", m_ContainerMapRecord.bFlags );

    Log::log( "MiniDriverContainer - wKeyExchangeKeySizeBits <%#02x>", m_ContainerMapRecord.wKeyExchangeKeySizeBits );

    Log::log( "MiniDriverContainer - wSigKeySizeBits <%#02x>", m_ContainerMapRecord.wSigKeySizeBits );

    std::string s;
    Log::toString( (const unsigned char*)m_ContainerMapRecord.wszGuid, (size_t)sizeof( m_ContainerMapRecord.wszGuid ), s );
    Log::log( "MiniDriverContainer - wszGuid <%s>", s.c_str( ) );

    s = "";
    if( m_pSignaturePublicKeyExponent ) {

        Log::toString( m_pSignaturePublicKeyExponent->GetBuffer( ), m_pSignaturePublicKeyExponent->GetLength( ), s );
        Log::log( "MiniDriverContainer - SignaturePublicKeyExponent <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - SignaturePublicKeyExponent <0>" );
    }

    if( m_pSignaturePublicKeyModulus ) {

        Log::toString( m_pSignaturePublicKeyModulus->GetBuffer( ), m_pSignaturePublicKeyModulus->GetLength( ), s );
        Log::log( "MiniDriverContainer - SignaturePublicKeyModulus <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - SignaturePublicKeyModulus <0>" );
    }    

    if( m_pExchangePublicKeyExponent ) {

        Log::toString( m_pExchangePublicKeyExponent->GetBuffer( ), m_pExchangePublicKeyExponent->GetLength( ), s );
        Log::log( "MiniDriverContainer - ExchangePublicKeyExponent <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - ExchangePublicKeyExponent <0>" );
    }    

    if( m_pExchangePublicKeyModulus ) {

        Log::toString( m_pExchangePublicKeyModulus->GetBuffer( ), m_pExchangePublicKeyModulus->GetLength( ), s );
        Log::log( "MiniDriverContainer - ExchangePublicKeyModulus <%s>", s.c_str( ) );

    } else {

        Log::log( "MiniDriverContainer - ExchangePublicKeyModulus <0>" );
    }  
}


void MiniDriverContainer::setGUID( const std::string& a_stGUID ) { 
    
   memset( m_ContainerMapRecord.wszGuid, 0, sizeof( m_ContainerMapRecord.wszGuid ) );

   size_t length = ( a_stGUID.size( ) > 39 ) ? 39 : a_stGUID.size( );

    for( size_t i = 0 ; i < length; ++i ) {

        m_ContainerMapRecord.wszGuid[ i ] = (WCHAR)a_stGUID[ i ];
    }

   //for( size_t i = 0 ; i < length; ++i ) {

   //   // Convert to wchar, little endian.
   //   m_ContainerMapRecord.wszGuid[ 2*i ]  = a_stGUID[ i ]; 
   //}
}
