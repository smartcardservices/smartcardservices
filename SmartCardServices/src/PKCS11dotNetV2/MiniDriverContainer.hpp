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


#ifndef __GEMALTO_MINIDRIVER_CONTAINER__
#define __GEMALTO_MINIDRIVER_CONTAINER__


#include <memory>
#include <string>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/shared_ptr.hpp>
#include "Array.hpp"
#include "cardmod.h"
#include "Log.hpp"
#include "MiniDriverAuthentication.hpp"


/*
*/
class MiniDriverContainer {

public:

    typedef enum { KEYSPEC_EXCHANGE = 0x01, KEYSPEC_SIGNATURE = 0x02 } KEYSPEC;

    typedef enum { CMAPFILE_FLAG_EMPTY = 0x00, CMAPFILE_FLAG_VALID = 0x01, CMAPFILE_FLAG_VALID_AND_DEFAULT = 0x03 } FLAG;

    MiniDriverContainer( );

    void clear( void );

    void setContainerMapRecord( CONTAINER_MAP_RECORD* );

    void setContainerInformation( const boost::shared_ptr< Marshaller::u1Array >& );

    void setGUID( const std::string& a_stGUID );

    inline void setFlags( const FLAG& a_ucFlags ) { m_ContainerMapRecord.bFlags = (unsigned char)a_ucFlags; }

    inline bool empty( void ) { return ( !m_ContainerMapRecord.wSigKeySizeBits && !m_ContainerMapRecord.wKeyExchangeKeySizeBits ); }

    inline const CONTAINER_MAP_RECORD& getContainerMapRecord( void ) { print( ); return m_ContainerMapRecord; }

    inline unsigned char getFlags( void ) { return m_ContainerMapRecord.bFlags; }

    inline WORD getKeyExchangeSizeBits( void ) { return m_ContainerMapRecord.wKeyExchangeKeySizeBits; }

    inline WORD getKeySignatureSizeBits( void ) { return m_ContainerMapRecord.wSigKeySizeBits; }

    inline void setKeyExchangeSizeBits( const WORD& a_wSize ) { m_ContainerMapRecord.wKeyExchangeKeySizeBits = a_wSize; }

    inline void setKeySignatureSizeBits( const WORD& a_wSize ) { m_ContainerMapRecord.wSigKeySizeBits = a_wSize; }

    inline boost::shared_ptr< Marshaller::u1Array >& getSignaturePublicKeyExponent( void ) { return m_pSignaturePublicKeyExponent; }

    inline boost::shared_ptr< Marshaller::u1Array >& getSignaturePublicKeyModulus( void ) { return m_pSignaturePublicKeyModulus; }

    inline boost::shared_ptr< Marshaller::u1Array >& getExchangePublicKeyExponent( void ) { return m_pExchangePublicKeyExponent; }

    inline boost::shared_ptr< Marshaller::u1Array >& getExchangePublicKeyModulus( void ) { return m_pExchangePublicKeyModulus; }

    inline bool getFlagSmartCardLogon( void ) { return m_bIsSmartCardLogon; }

    inline void setFlagSmartCardLogon( const bool& a_bIsSmartCardLogon ) { m_bIsSmartCardLogon = a_bIsSmartCardLogon; }


    inline void setContainerTypeForSignatureKey( const unsigned char& a_ContainerTypeForSignatureKey ) { m_ucSignatureContainerType = a_ContainerTypeForSignatureKey; }

    inline void setContainerTypeForExchangeKey( const unsigned char& a_ContainerTypeForExchangeKey ) { m_ucExchangeContainerType = a_ContainerTypeForExchangeKey; }

    inline void setPinIdentifier( const MiniDriverAuthentication::ROLES& a_ContainerPinIdentifier ) { m_PinIdentifier = a_ContainerPinIdentifier; }

    inline bool isImportedSignatureKey( void ) { return ( m_ucSignatureContainerType == 0x00 ); }

    inline bool isImportedExchangeKey( void ) { return ( 0x00 == m_ucExchangeContainerType ); }

    inline MiniDriverAuthentication::ROLES getPinIdentifier( void ) { return m_PinIdentifier; }

private:

    CONTAINER_MAP_RECORD m_ContainerMapRecord;

    boost::shared_ptr< Marshaller::u1Array > m_pSignaturePublicKeyExponent;

    boost::shared_ptr< Marshaller::u1Array > m_pSignaturePublicKeyModulus;

    boost::shared_ptr< Marshaller::u1Array > m_pExchangePublicKeyExponent;

    boost::shared_ptr< Marshaller::u1Array > m_pExchangePublicKeyModulus;

    bool m_bIsSmartCardLogon;

    unsigned char m_ucSignatureContainerType;

    unsigned char m_ucExchangeContainerType;

    MiniDriverAuthentication::ROLES m_PinIdentifier;

    void print( void );	

    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {

        ar & m_pSignaturePublicKeyModulus;
        ar & m_pSignaturePublicKeyExponent;
        ar & m_pExchangePublicKeyExponent;
        ar & m_pExchangePublicKeyModulus;
        ar & m_ContainerMapRecord.bFlags;
        ar & m_ContainerMapRecord.bReserved;
        ar & m_ContainerMapRecord.wKeyExchangeKeySizeBits;
        ar & m_ContainerMapRecord.wSigKeySizeBits;
        ar & m_ContainerMapRecord.wszGuid;
        ar & m_bIsSmartCardLogon;
        ar & m_ucSignatureContainerType;
        ar & m_ucExchangeContainerType;
        ar & m_PinIdentifier;
            
        //if( m_ContainerMapRecord.bFlags ) {

        // Log::begin( "MiniDriverContainer::serialize" );
        //   if( m_pSignaturePublicKeyExponent.get( ) ) {

        //        Log::logCK_UTF8CHAR_PTR( "SignaturePublicKeyExponent", m_pSignaturePublicKeyExponent->GetBuffer( ), m_pSignaturePublicKeyExponent->GetLength( ) );
        //    }
        //    if( m_pSignaturePublicKeyModulus.get( ) ) {
        //    
        //        Log::logCK_UTF8CHAR_PTR( "SignaturePublicKeyModulus", m_pSignaturePublicKeyModulus->GetBuffer( ), m_pSignaturePublicKeyModulus->GetLength( ) );
        //    }
        //    if( m_pExchangePublicKeyExponent.get( ) ) {
        //     
        //        Log::logCK_UTF8CHAR_PTR( "ExchangePublicKeyExponent", m_pExchangePublicKeyExponent->GetBuffer( ), m_pExchangePublicKeyExponent->GetLength( ) );
        //    }
        //    if( m_pExchangePublicKeyModulus.get( ) ) {

        //        Log::logCK_UTF8CHAR_PTR( "ExchangePublicKeyModulus", m_pExchangePublicKeyModulus->GetBuffer( ), m_pExchangePublicKeyModulus->GetLength( ) );
        //    }
        //    Log::log( "ContainerMapRecord.bFlags <%ld>", m_ContainerMapRecord.bFlags );
        //    Log::log( "ContainerMapRecord.bReserved <%ld>", m_ContainerMapRecord.bReserved );
        //    Log::log( "ContainerMapRecord.wKeyExchangeKeySizeBits <%ld>", m_ContainerMapRecord.wKeyExchangeKeySizeBits );
        //    Log::log( "ContainerMapRecord.wSigKeySizeBits <%ld>", m_ContainerMapRecord.wSigKeySizeBits );
        //    Log::logCK_UTF8CHAR_PTR( "m_ContainerMapRecord.wszGuid", (unsigned char*) m_ContainerMapRecord.wszGuid, 80 /*sizeof( m_ContainerMapRecord.wszGuid )*/ );
        //    Log::log( "m_bIsSmartCardLogon <%ld>", m_bIsSmartCardLogon );
        //    Log::log( "m_ucSignatureContainerType <%ld>", m_ucSignatureContainerType );
        //    Log::log( "m_ucExchangeContainerType <%ld>", m_ucExchangeContainerType );
        //    Log::log( "m_PinIdentifier <%ld>", m_PinIdentifier );
        // Log::end( "MiniDriverContainer::serialize" );
       //}
    }

};

BOOST_CLASS_VERSION( MiniDriverContainer, 1 )

#endif // __GEMALTO_MINIDRIVER_CONTAINER__
