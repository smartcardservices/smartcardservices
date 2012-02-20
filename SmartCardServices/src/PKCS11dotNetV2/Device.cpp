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


#include <memory>
#include "Device.hpp"


bool Device::s_bEnableCache = true;

#define TIMEOUT_CHANGE 2.0

#define TIMEOUT_AUTH 0.2

const BYTE g_DotNetSmartCardAtr[ ] = { 0x3b, 0x16, 0x96, 0x41, 0x73, 0x74, 0x72, 0x69, 0x64 };


/*
*/
Device::Device( const SCARD_READERSTATE& a_State, const unsigned char& a_ID ) {

    m_bIsLastAuth = false;

    m_ucDeviceID = a_ID;

    clear( );

    try {
    
        set( a_State );
    
    } catch( ... ) {
    
        // A reader is available but the smart card is not a .NET smart card
    }

    m_TimerLastChange.start( );
    
    m_TimerLastAuth.start( );
}


/*
*/
Device::~Device( ) {

    clear( );
}


/*
*/
void Device::clear( void ) {

    memset( &m_DeviceState, 0, sizeof( SCARD_READERSTATE ) );

    m_MiniDriver.reset( );

    m_SmartCardReader.reset( );
}


/*
*/
void Device::set( const SCARD_READERSTATE& scr ) {

    m_SmartCardReader.reset( new SmartCardReader( scr.szReader ) );

    m_DeviceState.szReader = m_SmartCardReader->getReaderName( ).c_str( );
    memcpy( m_DeviceState.rgbAtr, scr.rgbAtr, scr.cbAtr );
    m_DeviceState.cbAtr = scr.cbAtr;
    m_DeviceState.dwCurrentState = scr.dwCurrentState;
    m_DeviceState.dwEventState = scr.dwEventState;

    if( isSmartCardPresent( ) && ! isSmartCardMute( ) ) {

        addMiniDriver( );
    }
}


/*
*/
void Device::addMiniDriver( void ) {

    if( 0 != memcmp( g_DotNetSmartCardAtr, m_DeviceState.rgbAtr, m_DeviceState.cbAtr ) ) {
    
        throw MiniDriverException( SCARD_E_UNKNOWN_CARD ); 
    }

    try {
    
        // Create a card module service
        m_MiniDriver.reset( new MiniDriver( ) );

        m_MiniDriver->setSmartCardReader( m_SmartCardReader.get( ) );

        beginTransaction( );

        m_MiniDriver->read( s_bEnableCache );

        m_SmartCardReader->setCardHandle( m_MiniDriver->getCardHandle( ) );

        m_bIsLastAuth = m_MiniDriver->isAuthenticated( ); 
    
    } catch( ... ) {
    
    }

    endTransaction( );
}


/*
*/
void Device::removeMiniDriver( void ) {

    // Remove the card module service
    m_MiniDriver.reset( );
}


/*
*/
void Device::update( const SCARD_READERSTATE& scr ) {

    m_DeviceState.dwCurrentState = scr.dwCurrentState;
    m_DeviceState.dwEventState = scr.dwEventState;
}


/*
*/
void Device::put( SCARD_READERSTATE& scr ) {

    memset( &scr, 0, sizeof( SCARD_READERSTATE ) );
    scr.szReader = m_SmartCardReader->getReaderName( ).c_str( );
    scr.dwCurrentState = m_DeviceState.dwCurrentState;
    scr.dwEventState = m_DeviceState.dwEventState;
}


/*
*/
void Device::hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) {

    if( m_TimerLastChange.getCurrentDuration( ) < (double)TIMEOUT_CHANGE ) {
     
        return;
    }
    
    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }
    
    m_MiniDriver->hasChanged( a_Pins, a_Containers, a_Files );
    
    m_TimerLastChange.start( );
}


/*
*/
bool Device::isAuthenticated( void ) {

    if( m_TimerLastAuth.getCurrentDuration( ) < (double)TIMEOUT_AUTH ) {
     
        return m_bIsLastAuth;
    }

    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_bIsLastAuth = m_MiniDriver->isAuthenticated( ); 
    
    m_TimerLastAuth.start( );

    return m_bIsLastAuth;
}


/*
*/
void Device::verifyPin( Marshaller::u1Array* a_Pin ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->verifyPin( a_Pin ); 

    m_bIsLastAuth = true;

    m_TimerLastAuth.start( );
}


/*
*/
void Device::logOut( void ) {

    if( !m_MiniDriver ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->logOut( ); 

    m_TimerLastAuth.start( );

    m_bIsLastAuth = false;
}


/*
*/
Marshaller::u1Array* Device::getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    return m_MiniDriver->getCardProperty( a_ucProperty, a_ucFlags );
}


/*
*/
void Device::setCardProperty( const unsigned char& a_ucProperty, Marshaller::u1Array* a_Data, const unsigned char& a_ucFlags ) {

    if( !m_MiniDriver ) {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    m_MiniDriver->setCardProperty( a_ucProperty, a_Data, a_ucFlags );
}
