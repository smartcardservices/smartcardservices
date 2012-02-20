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
#include <boost/foreach.hpp>
#include <boost/mem_fn.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <vector>
#include <string>
#include "Log.hpp"
#include "DeviceMonitor.hpp"

#ifdef MACOSX_LEOPARD
#define SCardIsValidContext(x) SCARD_S_SUCCESS
#endif

extern boost::mutex io_mutex;

extern boost::condition_variable g_WaitForSlotEventCondition;

extern boost::mutex g_WaitForSlotEventMutex;

extern bool g_bWaitForSlotEvent;

const BYTE g_DotNetSmartCardAtr[ ] = { 0x3b, 0x16, 0x96, 0x41, 0x73, 0x74, 0x72, 0x69, 0x64 };

SCARDCONTEXT DeviceMonitor::m_hContext = 0;

bool DeviceMonitor::m_bStopPolling = false;

bool DeviceMonitor::m_bAlive = false;

boost::condition_variable g_WaitForDeviceMonitorThreadCondition;

boost::mutex g_WaitForDeviceMonitorThreadMutex;


/*
*/
DeviceMonitor::DeviceMonitor( ) {

    m_stEmptyDevice = "empty";

    unsigned char ucDeviceID = 0;

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        SCARD_READERSTATE s;

        memset( &s, 0, sizeof( SCARD_READERSTATE ) );

        s.szReader = m_stEmptyDevice.c_str( );

        s.dwCurrentState = SCARD_STATE_EMPTY;

        s.dwEventState = SCARD_STATE_EMPTY;

        d.reset( new Device( s, ucDeviceID ) );

        ++ucDeviceID;
    }
}


/* Spy reader insertion/removal
*/
void DeviceMonitor::getDevicesStates( const SCARDCONTEXT& h ) {

    long rv = SCardIsValidContext( h );

    if( SCARD_S_SUCCESS != rv ) {

        return;
    }

    // Get the name of all the connected devices
    std::vector< std::string > vDevices;

    vDevices.reserve( g_iMaxReader );

    vDevices.clear( );

    getDevicesList( h, vDevices );

    // Build an SCARD_READERSTATE array for all seen devices
    SCARD_READERSTATE aReaderStates[ g_iMaxReader ];

    memset( aReaderStates, 0, sizeof( aReaderStates ) );

    unsigned char j = 0;

    size_t m = vDevices.size( );

    BOOST_FOREACH( SCARD_READERSTATE &scr, aReaderStates ) {

        memset( &scr, 0, sizeof( SCARD_READERSTATE ) );

        if( j < m ) {

            aReaderStates[ j ].szReader = vDevices.at( j ).c_str( );

            ++j;

        } else {
         
            break;
        }
    }

    // Query the status for all known devices
    rv = SCardGetStatusChange( h, 100, &aReaderStates[ 0 ], j );

    if( SCARD_S_SUCCESS != rv ) {

        Log::log( "DeviceMonitor::getDevicesStates - SCardGetStatusChange <%#02x>", rv );
    }

    if( ( SCARD_W_REMOVED_CARD == rv ) || ( SCARD_W_RESET_CARD == rv ) ) {

        DWORD dwActiveProtocol = SCARD_PROTOCOL_T0;

        rv = SCardReconnect( h, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

        if( SCARD_S_SUCCESS != rv ) {

            Log::log( "DeviceMonitor::getDevicesStates - SCardReconnect <%#02x>", rv );

        } else {

            rv = SCardGetStatusChange( h, 100, &aReaderStates[ 0 ], j );
        }
    }

    // Create inner device objects
    j = 0;

    BOOST_FOREACH( SCARD_READERSTATE &scr, aReaderStates ) {

        // If he reader exists
        if( scr.szReader ) {

            scr.dwCurrentState = scr.dwEventState;

            addReader( scr, j );
        }

        ++j;
    }
}


/*
*/
void DeviceMonitor::getDevicesList( const SCARDCONTEXT& h, std::vector< std::string >& a_DeviceList ) {

    long rv = SCardIsValidContext( h );

    if( SCARD_S_SUCCESS != rv ) {

        return;
    }

    a_DeviceList.clear( );

    // Get the device list from the PCSC layer
    //LPSTR pszReaders = NULL;
    if ( m_bStopPolling ) {

        // If the library has been unloaded the thread must stopped right now
        return;
    }
    /*
    #ifdef SCARD_AUTOALLOCATE
    DWORD dwReaders = SCARD_AUTOALLOCATE;

    LONG rv = SCardListReaders( h, NULL, (LPSTR)&pszReaders, &dwReaders );

    if( SCARD_S_SUCCESS != rv )
    {
    Log::log( "DeviceMonitor::getDevicesList - SCardListReaders <%#02x>", rv );

    SCardFreeMemory( h, pszReaders );

    if( ( SCARD_W_REMOVED_CARD == rv ) || ( SCARD_W_RESET_CARD == rv ) ) {

    DWORD dwActiveProtocol = 0;

    rv = SCardReconnect( h, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

    if( SCARD_S_SUCCESS != rv ) {

    Log::log( "DeviceMonitor::getDevicesList - SCardReconnect <%#02x>", rv );
    return;
    }

    rv = SCardListReaders( h, NULL, (LPSTR)&pszReaders, &dwReaders );

    if( SCARD_S_SUCCESS != rv ) {

    Log::log( "DeviceMonitor::getDevicesList - SCardListReaders (2) <%#02x>", rv );
    SCardFreeMemory( h, pszReaders );

    return;
    }   

    } else {

    return;
    }
    }	
    #else
    */
    DWORD dwReaders = 0;
    rv = SCardListReaders( h, NULL, NULL, &dwReaders );

    if( SCARD_S_SUCCESS != rv ) {

        if( ( SCARD_W_REMOVED_CARD == rv ) || ( SCARD_W_RESET_CARD == rv ) ) {

            DWORD dwActiveProtocol = 0;

            rv = SCardReconnect( h, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

            if( SCARD_S_SUCCESS != rv ) {

                return;
            }

            rv = SCardListReaders( h, NULL, NULL, &dwReaders );

            if( SCARD_S_SUCCESS != rv ) {

                return;
            }   

        } else {

            return;
        }
    }

    std::auto_ptr< char > pszReaders( new char[ dwReaders ] );
    memset( pszReaders.get( ), 0,  dwReaders );
    //pszReaders = (char *)malloc(dwReaders);

    rv = SCardListReaders( h, NULL, pszReaders.get( ), &dwReaders);
    //#endif

    // Construct the PCSC device list
    LPSTR pReader = pszReaders.get( );

    while( pReader && ( '\0' != *pReader ) )
    {
        std::string s( pReader );

        std::vector< std::string >::iterator i = a_DeviceList.begin( );

        a_DeviceList.insert( i, s );

        // Advance to the next value
        size_t readerNameLen = s.length( );

        pReader = ( pReader + readerNameLen + 1 );
    }

    //#ifdef SCARD_AUTOALLOCATE
    //    SCardFreeMemory( h, pszReaders );
    //#else
    //free(pszReaders);
    //#endif
}


/*
*/
void DeviceMonitor::getReader( SCARD_READERSTATE& scr ) {

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( scr.szReader ) ) ) {

            //Log::log( "   ===> Update reader <%s>\n", scr.szReader );

            d->put( scr );

            return;
        }
    }	
}


/*
*/
void DeviceMonitor::updateReader( const SCARD_READERSTATE& scr ) {

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( scr.szReader ) ) ) {

            //Log::log( "   ===> Update reader <%s>\n", scr.szReader );

            d->update( scr );

            return;
        }
    }	
}


/*
*/
void DeviceMonitor::removeReader( LPCSTR s ) {

    unsigned char ucDeviceID = 0;

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( s ) ) ) {

            Log::log( "DeviceMonitor::removeReader - <%s> - id <%d>", s, ucDeviceID );

            SCARD_READERSTATE s;

            memset( &s, 0, sizeof( SCARD_READERSTATE ) );

            s.szReader = m_stEmptyDevice.c_str( );

            s.dwCurrentState = SCARD_STATE_EMPTY;

            s.dwEventState = SCARD_STATE_EMPTY;

            d.reset( new Device( s, ucDeviceID ) );

            return;
        }

        ++ucDeviceID;
    }	
}


/*
*/
void DeviceMonitor::addReader( const SCARDCONTEXT& h, const std::string& a_stDeviceName ) {

    // Query the status of the device
    SCARD_READERSTATE scr;
    memset( &scr, 0, sizeof( SCARD_READERSTATE ) );
    scr.szReader = a_stDeviceName.c_str( );

    if( h ) {

        LONG rv = SCardGetStatusChange( h, 100, &scr, 1 );

        if( SCARD_S_SUCCESS != rv ) {

            Log::log( "DeviceMonitor::addReader - SCardGetStatusChange <%#02x>", rv );

        }

        if( ( SCARD_W_REMOVED_CARD == rv ) || ( SCARD_W_RESET_CARD == rv ) ) {

            DWORD dwActiveProtocol = 0;

            rv = SCardReconnect( h, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

            if( SCARD_S_SUCCESS != rv ) {

                Log::log( "DeviceMonitor::addReader - SCardReconnect <%#02x>", rv );
                return;
            }

            SCardGetStatusChange( h, 100, &scr, 1 );
        }
    }

    scr.dwCurrentState = scr.dwEventState;

    unsigned char ucDeviceID = 0;

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( m_stEmptyDevice ) ) ) {

            Log::log( "DeviceMonitor::addReader - <%s> - id <%d>", a_stDeviceName.c_str( ), ucDeviceID );

            d.reset( new Device( scr, ucDeviceID ) );

            /*if( SCARD_STATE_PRESENT & scr.dwEventState ) {

                d->addMiniDriver( );
            }*/

            break;
        }

        ++ucDeviceID;
    }
}


/*
*/
void DeviceMonitor::addReader( const SCARD_READERSTATE& a_State, const unsigned char& a_ucDeviceID ) {

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( m_stEmptyDevice ) ) ) {

            Log::log( "DeviceMonitor::addReader - <%s> - id <%d>", a_State.szReader, a_ucDeviceID );

            d.reset( new Device( a_State, a_ucDeviceID ) );

            return;
        }
    }
}


/*
*/
void DeviceMonitor::removeSmartCard( const std::string& a_stReaderName ) {

    unsigned char ucDeviceID = 0;

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( a_stReaderName ) ) ) {

            Log::log( "DeviceMonitor::removeSmartCard - <%s> - id <%d>", a_stReaderName.c_str( ), ucDeviceID );

            // Remove the MiniDriver dedicated to this smart card
            d->removeMiniDriver( );
            
            // Initialize the state of the device to monitor
            SCARD_READERSTATE s;

            memset( &s, 0, sizeof( SCARD_READERSTATE ) );

            s.szReader = d->getReaderName( ).c_str( );

            s.dwCurrentState = SCARD_STATE_EMPTY;

            s.dwEventState = SCARD_STATE_EMPTY;

            d->update( s );

            return;
        }

        ++ucDeviceID;
    }
}


/*
*/
void DeviceMonitor::addSmartCard( const std::string& a_stReaderName ) {

    unsigned char ucDeviceID = 0;

    BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

        if( d.get( ) && ( 0 == d->getReaderName( ).compare( a_stReaderName ) ) ) {

            Log::log( "DeviceMonitor::addSmartCard - <%s> - id <%d>", a_stReaderName.c_str( ), ucDeviceID );

            //try {

                d->addMiniDriver( );

            //} catch( ... ) {

                // If the smart card is removed during the read operation
                // If the smart card is not a .NET smart card
                // then an exception is thrown
            //}

            return;
        }

        ++ucDeviceID;
    }
}


/*
*/
bool DeviceMonitor::isReaderExists( const SCARDCONTEXT& h, const std::string& a_stReaderName ) {

    std::vector< std::string > deviceList;

    getDevicesList( h, deviceList );

    BOOST_FOREACH( const std::string& s, deviceList ) {

        if( 0 == s.compare( a_stReaderName ) ) {

            Log::log( "DeviceMonitor::isReaderExists - Reader <%s> exists", a_stReaderName.c_str( ) );

            return true;
        }
    }

    return false;
    /*
    SCARD_READERSTATE scr;

    memset( &scr, 0, sizeof( SCARD_READERSTATE ) );

    scr.szReader = a_stReaderName.c_str( );

    LONG rv = SCardGetStatusChange( h, 100, &scr, 1 );

    Log::log( "DeviceMonitor::isReaderExists - Current state <%#02x>", scr.dwCurrentState );
    Log::log( "DeviceMonitor::isReaderExists - Event state <%#02x>", scr.dwEventState );

    if( SCARD_S_SUCCESS != rv ) { // Expect for 0x8010002E Cannot find a smart card reader

    Log::log( "DeviceMonitor::isReaderExists - SCardGetStatusChange <%#02x>", rv );

    return false;
    }

    return true;
    */
}


/*
*/
void DeviceMonitor::unblockWaitingThread( void ) {

    if( ! g_bWaitForSlotEvent ) {

        boost::lock_guard< boost::mutex > lock( g_WaitForSlotEventMutex );
        g_bWaitForSlotEvent = true;
    }

    g_WaitForSlotEventCondition.notify_all( );
}


/*
*/
void DeviceMonitor::notifyListenerReaderInserted( const std::string& a_stReaderName ) {

    if( m_bStopPolling ) {

        return;
    }

    // Update the states of the listeners
    BOOST_FOREACH( IDeviceMonitorListener* const d, m_Listeners ) {

        if( d ) {

            d->notifyReaderInserted( a_stReaderName );
        }
    }

    // Give access to the state
    unblockWaitingThread( );
}


/*
*/
void DeviceMonitor::notifyListenerReaderRemoved( const std::string& a_stReaderName ) {

    if( m_bStopPolling ) {

        return;
    }

    BOOST_FOREACH( IDeviceMonitorListener* const d, m_Listeners ) {

        if( d ) {

            d->notifyReaderRemoved( a_stReaderName );
        }
    }

    unblockWaitingThread( );
}


/*
*/
void DeviceMonitor::notifyListenerSmartCardInserted( const std::string& a_stReaderName ) {

    if( m_bStopPolling ) {

        return;
    }

    BOOST_FOREACH( IDeviceMonitorListener* const d, m_Listeners ) {

        if( d ) {

            d->notifySmartCardInserted( a_stReaderName );
        }
    }

    unblockWaitingThread( );
}


/*
*/
void DeviceMonitor::notifyListenerSmartCardRemoved( const std::string& a_stReaderName ) {

    if( m_bStopPolling ) {

        return;
    }

    BOOST_FOREACH(  IDeviceMonitorListener* const d, m_Listeners ) {

        if( d ) {

            d->notifySmartCardRemoved( a_stReaderName );
        }
    }

    unblockWaitingThread( );
}


/*
*/
void DeviceMonitor::notifyListenerSmartCardChanged( const std::string& a_stReaderName ) {

    if( m_bStopPolling ) {

        return;
    }

    BOOST_FOREACH( IDeviceMonitorListener* const d, m_Listeners ) {

        if( d ) {

            d->notifySmartCardChanged( a_stReaderName );
        }
    }

    unblockWaitingThread( );
}


/*
*/
void DeviceMonitor::addListener( IDeviceMonitorListener* const a_pListener ) {

    if( a_pListener ) {

        m_Listeners.insert( m_Listeners.begin( ), a_pListener );
    }
}


/*
*/
void DeviceMonitor::printDeviceList( void ) {

    //Log::log( "\n=============== DEVICES" );

    int i = 0;
    BOOST_FOREACH( boost::shared_ptr< Device > scr, m_aDevices ) {

        if( scr.get( ) ) {

            printReaderState( scr->getReaderState( ), i );

        }

        ++i;
    }

    //Log::log( "=============== DEVICES\n" );
}


/*
*/
void DeviceMonitor::printReaderStateList( boost::array< SCARD_READERSTATE, g_iMaxReader + 1 >& l ) {

    int i = 0;

    BOOST_FOREACH( SCARD_READERSTATE &scr, l ) {

        printReaderState( scr, i );

        ++i;
    }
}


/*
*/
void DeviceMonitor::printReaderState( const SCARD_READERSTATE& scrs, const int& iIndex ) {

    if( !Log::s_bEnableLog || !scrs.szReader ) {

        return;
    }

    std::string stStateCurrent;
    getState( scrs.dwCurrentState, stStateCurrent );

    std::string stStateEvent;
    getState( scrs.dwEventState, stStateEvent );

    std::string stATR;
    Log::toString( scrs.rgbAtr, scrs.cbAtr, stATR );

    Log::log( "Index <%d> - szReader <%s> - dwCurrentState <%#02x> (%s) - dwEventState <%#02x> (%s) - cbAtr <%#02x> - rgbAtr <%s>", iIndex, scrs.szReader, scrs.dwCurrentState, stStateCurrent.c_str( ), scrs.dwEventState, stStateEvent.c_str( ), scrs.cbAtr, stATR.c_str( ) );
}


/*
*/
void DeviceMonitor::getState( const DWORD& dwState, std::string& stState ) {

    // The application requested that this reader be ignored.  No other bits will be set.
    if( SCARD_STATE_IGNORE == ( SCARD_STATE_IGNORE & dwState ) ) {
        stState += "SCARD_STATE_IGNORE ";
    }

    // This implies that there is a difference between the state believed by the application, and
    // the state known by the Service Manager.  When this bit is set, the application may assume a
    // significant state change has occurred on this reader.
    if( SCARD_STATE_CHANGED == ( SCARD_STATE_CHANGED & dwState ) ) {
        stState += "SCARD_STATE_CHANGED ";
    }

    // This implies that the given reader name is not recognized by the Service Manager.  If this bit
    // is set, then SCARD_STATE_CHANGED and SCARD_STATE_IGNORE will also be set.
    if( SCARD_STATE_UNKNOWN == ( SCARD_STATE_UNKNOWN & dwState ) ) {
        stState += "SCARD_STATE_UNKNOWN ";
    }

    // This implies that the actual state of this reader is not available.  If this bit is set,
    // then all the following bits are clear.
    if( SCARD_STATE_UNAVAILABLE == ( SCARD_STATE_UNAVAILABLE & dwState ) ) {
        stState += "SCARD_STATE_UNAVAILABLE ";
    }

    // This implies that there is not card in the reader.  If this bit is set, all the following bits will be clear.
    if( SCARD_STATE_EMPTY == ( SCARD_STATE_EMPTY & dwState ) ) {
        stState += "SCARD_STATE_EMPTY ";
    }

    // This implies that there is a card in the reader.
    if( SCARD_STATE_PRESENT == ( SCARD_STATE_PRESENT & dwState ) ) {
        stState += "SCARD_STATE_PRESENT ";
    }

    // This implies that there is a card in the reader with an ATR matching one of the target cards.
    // If this bit is set, SCARD_STATE_PRESENT will also be set.  This bit is only returned on the SCardLocateCard() service.
    if( SCARD_STATE_ATRMATCH == ( SCARD_STATE_ATRMATCH & dwState ) ) {
        stState += "SCARD_STATE_ATRMATCH ";
    }

    // This implies that the card in the reader is allocated for exclusive use by another application.
    // If this bit is set, SCARD_STATE_PRESENT will also be set.
    if( SCARD_STATE_EXCLUSIVE == ( SCARD_STATE_EXCLUSIVE & dwState ) ) {
        stState += "SCARD_STATE_EXCLUSIVE ";
    }

    // This implies that the card in the reader is in use by one or more other applications, but may be
    // connected to in shared mode.  If this bit is set, SCARD_STATE_PRESENT will also be set.
    if( SCARD_STATE_INUSE == ( SCARD_STATE_INUSE & dwState ) ) {
        stState += "SCARD_STATE_INUSE ";
    }

    // This implies that the card in the reader is unresponsive or not supported by the reader or software.
    if( SCARD_STATE_MUTE == ( SCARD_STATE_MUTE & dwState ) ) {
        stState += "SCARD_STATE_MUTE ";
    }

    // This implies that the card in the reader has not been powered up.
    if( SCARD_STATE_UNPOWERED == ( SCARD_STATE_UNPOWERED & dwState ) ) {
        stState += "SCARD_STATE_UNPOWERED ";
    }

    // The application is unaware of the current state, and would like to know. The use of this value
    // results in an immediate return from state transition monitoring services. This is represented by
    // all bits set to zero.			
    if( stState.empty( ) && ( SCARD_STATE_UNAWARE == ( SCARD_STATE_UNAWARE & dwState ) ) ) {
        stState += "SCARD_STATE_UNAWARE ";
    }
}


/*
*/
void DeviceMonitor::start( void ) {

    // Initialize the PCSC context    
    long hResult = SCardEstablishContext( SCARD_SCOPE_USER, NULL, NULL, &m_hContext );

    if( SCARD_S_SUCCESS != hResult ) {

        //throw std::exception( );
        return;
    }

    // Establish the list of the connected devices
    getDevicesStates( m_hContext );

    m_bStopPolling = false;

    DeviceMonitor::m_bAlive = false;

    m_ThreadListener.reset( new boost::thread( &DeviceMonitor::monitorReaderEvent, this ) );

    Log::log( "DeviceMonitor::start - Wait for thread starting..." );

    Timer t;
    t.start( );

    /*
    ==========
    unsigned int i = 0;

    do {

        boost::this_thread::sleep( boost::posix_time::milliseconds( 100 ) );

        i += 100;

        Log::log( "DeviceMonitor::start - DeviceMonitor::m_bAlive <%d> - i <%ld>", DeviceMonitor::m_bAlive, i );

    } while( ( false == DeviceMonitor::m_bAlive ) && ( i < 1000 ) );
    ============
    */
    {
        boost::mutex::scoped_lock lock( g_WaitForDeviceMonitorThreadMutex );

        while( !DeviceMonitor::m_bAlive ) {

            g_WaitForDeviceMonitorThreadCondition.wait( lock );
        }
    }
    //g_WaitForDeviceMonitorThreadCondition.timed_wait( lock, boost::posix_time::milliseconds( 1000 ) );
    t.stop(  "DeviceMonitor::start - Thread started" );
}


/*
*/
void DeviceMonitor::stop( void ) {

    Log::begin( "DeviceMonitor::stop" );

    //unblockWaitingThread( );
    g_WaitForSlotEventCondition.notify_all( );

    Log::log( "DeviceMonitor::stop - Wait for event thread unblocked" );

    long rv = SCardCancel( m_hContext );
    Log::log( "DeviceMonitor::stop - SCardCancel <%#02x>", rv );

    m_bStopPolling = true;
    //Log::log( "DeviceMonitor::stop - m_bStopPolling <%#02x>", m_bStopPolling );

    Log::log( "DeviceMonitor::stop - bAlive <%#02x>", DeviceMonitor::m_bAlive );

    if( DeviceMonitor::m_bAlive ) {

        Log::log( "DeviceMonitor::stop - Waiting the thread stops..." );
        Timer t;
        t.start( );

        unsigned int i = 0;

        do {

            boost::this_thread::sleep( boost::posix_time::milliseconds( 100 ) );

            Log::log( "DeviceMonitor::stop - DeviceMonitor::m_bAlive <%d> - i <%ld>", DeviceMonitor::m_bAlive, i );

            i+= 100;

        } while( DeviceMonitor::m_bAlive && ( i < 2000 ) );

        t.stop( "DeviceMonitor::stop - Thread stopped" );
    }

    Log::end( "DeviceMonitor::stop" );
}


/* Spy reader insertion/removal
*/
void DeviceMonitor::monitorReaderEvent( void ) {

    Log::log( "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ DEVICE MONITOR THREAD STARTS ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]\n" );

    // Unblock all mutex waiting for the device monitor thread start
    {
        boost::mutex::scoped_lock lock( g_WaitForDeviceMonitorThreadMutex );

        DeviceMonitor::m_bAlive = true;
    }
    g_WaitForDeviceMonitorThreadCondition.notify_all( );


    if( DeviceMonitor::m_bStopPolling ) {

        Log::log( "DeviceMonitor::monitorReaderEvent - Stop thread at begining " );

        DeviceMonitor::m_bAlive = false;

        return;
    }

    try {

        std::string PNP_NOTIFICATION( "\\\\?PnP?\\Notification" );

        std::vector< std::string > vDevices;

        vDevices.reserve( g_iMaxReader );

        vDevices.clear( );

        // Build the smart card reader states buffer. Reserve the first cell to Plug&Play notification declaration
        SCARD_READERSTATE aReaderStates[ g_iMaxReader + 1 ];

        memset( &aReaderStates[ 0 ], 0, sizeof( aReaderStates ) );

        aReaderStates[ 0 ].szReader = PNP_NOTIFICATION.c_str( );

        DWORD dwReaderStatesCount = 1;

        BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

            // Ignore empty device cell
            if( d.get( ) && d->getReaderName( ).compare( m_stEmptyDevice ) ) {

                d->put( aReaderStates[ dwReaderStatesCount ] );

                ++dwReaderStatesCount;
            }
        }

        size_t uiReaderStatesLen = sizeof( aReaderStates ) / sizeof( SCARD_READERSTATE );

        // Start to spy the readers states
        do {

            Log::log( "DeviceMonitor::monitorReaderEvent - Start polling" );

            if ( DeviceMonitor::m_bStopPolling ) {

                Log::log( "DeviceMonitor::monitorReaderEvent - Stop polling required before status request" );
                break;
            }

            Log::log( "DeviceMonitor::monitorReaderEvent - Query new card/reader status for:" );
            for( size_t i = 0 ; i < uiReaderStatesLen ; ++i ) {
                
                if( aReaderStates[ i ].szReader ) {

                    Log::log( "DeviceMonitor::monitorReaderEvent -      <%s>", aReaderStates[ i ].szReader );
                }
            }

            // Query the status for all known devices plus the Plug&Play notification
            long rv;
            try {
                rv = SCardGetStatusChange( DeviceMonitor::m_hContext, INFINITE, aReaderStates, dwReaderStatesCount );
            }
            catch( ... ) { }

            boost::mutex::scoped_lock lock( io_mutex );

            Log::log( "DeviceMonitor::monitorReaderEvent - SCardGetStatusChange  <%#02x>", rv );

            if ( DeviceMonitor::m_bStopPolling ) {

                // If the library has been unloaded the thread must stopped right now
                Log::log( "DeviceMonitor::monitorReaderEvent - Stop polling required after status request" );
                break;
            }

            // Check if the get status action has been canceled or failed
            if( SCARD_E_CANCELLED == rv ) {

                Log::log( "DeviceMonitor::monitorReaderEvent - SCardGetStatusChange cancelled <%#02x>", rv );
                break;

            } else if( ( SCARD_W_REMOVED_CARD == rv ) || ( SCARD_W_RESET_CARD == rv ) ) {

                DWORD dwActiveProtocol = 0;
                rv = SCardReconnect( DeviceMonitor::m_hContext, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

                if( SCARD_S_SUCCESS != rv ) {

                    Log::log( "DeviceMonitor::monitorReaderEvent - SCardReconnect failed <%#02x>", rv );
                    break;
                }

                continue;

            } else if( SCARD_S_SUCCESS != rv ) {

                Log::log( "DeviceMonitor::monitorReaderEvent - SCardGetStatusChange failed <%#02x>", rv );
                break;
            }

            if ( m_bStopPolling ) {

                // If the library has been unloaded the thread must stopped right now
                break;
            }

            // A Plug&Play event occured. A reader has been removed or inserted
            if( aReaderStates[ 0 ].dwEventState & SCARD_STATE_CHANGED ) {

                Log::log( "DeviceMonitor::monitorReaderEvent - Pnp status changed" );

                // Get the new device list
                getDevicesList( m_hContext, vDevices );

                Log::log( "DeviceMonitor::monitorReaderEvent - New device list created" );

                if ( m_bStopPolling ) {

                    // If the library has been unloaded the thread must stopped right now
                    Log::log( "DeviceMonitor::monitorReaderEvent - Stop polling required after device list creation" );
                    break;
                }

                // First compare the current readers with the new device list to know if the reader has been previously detected
                bool bFound = false;

                BOOST_FOREACH( SCARD_READERSTATE& rs, aReaderStates ) {

                    if( rs.szReader && PNP_NOTIFICATION.compare( rs.szReader ) ) {

                        Log::log( "DeviceMonitor::monitorReaderEvent - Check removal of reader <%s>", rs.szReader );

                        bFound = false;

                        BOOST_FOREACH( std::string& s, vDevices ) {

                            Log::log( "DeviceMonitor::monitorReaderEvent - Locate removal of reader <%s> compared to <%s>", rs.szReader, s.c_str( ) );

                            if( 0 == s.compare( (LPSTR)( rs.szReader ) ) ) {

                                // The reader is still in use
                                bFound = true;

                                Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> still in use", s.c_str( ) );

                                break;
                            }
                        }

                        if( !bFound ) {

                            Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> removed", rs.szReader );

                            // The reader has been removed
                            notifyListenerReaderRemoved( rs.szReader );

                            // Remove the device from the current device list
                            removeReader( rs.szReader );
                        }
                    }
                }

                // Second compare the new device list to the old one to know if new devices have been inserted
                BOOST_FOREACH( std::string& s, vDevices ) {

                    Log::log( "DeviceMonitor::monitorReaderEvent - Locate new reader for reader <%s>", s.c_str( ) );

                    bool bFound = false;

                    BOOST_FOREACH( SCARD_READERSTATE& rs, aReaderStates ) {

                        Log::log( "DeviceMonitor::monitorReaderEvent - Locate new reader for reader <%s> compared to <%s>", s.c_str( ), rs.szReader );

                        if( rs.szReader && ( 0 == s.compare( (LPSTR)( rs.szReader ) ) ) ) {

                            // The reader is already known
                            bFound = true;

                            Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> is known", rs.szReader );

                            break;
                        }
                    }	

                    if( !bFound ) {

                        Log::log( "DeviceMonitor::monitorReaderEvent - Found new reader <%s>", s.c_str( ) );

                        // The reader is unknown. Add the new reader into the current device list
                        addReader( m_hContext, s ); 

                        // Notify the insertion
                        notifyListenerReaderInserted( s );
                    }
                }
            }

            // A real change state notification came.
            // Locate state changes in the current reader list avoiding the first cell which is dedicated to Plug&Play notification declaration
            BOOST_FOREACH( SCARD_READERSTATE& srs, aReaderStates ) {

                // Update the state
                srs.dwCurrentState = srs.dwEventState;

                if( !srs.szReader ) {

                    continue;
                }

                if( !PNP_NOTIFICATION.compare( srs.szReader ) ) {

                    continue;
                }

                if( SCARD_STATE_CHANGED & srs.dwEventState ) {

                    Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> - State changed <%#02x>", srs.szReader, srs.dwEventState );

                    // Get the current registered reader state to compare with the new incoming state
                    SCARD_READERSTATE scr;

                    memset( &scr, 0, sizeof( SCARD_READERSTATE ) );

                    scr.szReader = srs.szReader;

                    getReader( scr );

                    // If a smart card is present and this is not already the state of the reader
                    if( ( SCARD_STATE_PRESENT & srs.dwEventState ) && ( 0 == ( SCARD_STATE_PRESENT & scr.dwCurrentState ) ) ) {
// LCA: remove comment on ATR test!
                        // !!!!! ONLY NOTIFY IF A .NET SMART CARD IS PRESENT !!!!!
                        if( ( SCARD_STATE_MUTE != ( SCARD_STATE_MUTE & srs.dwEventState ) ) && ( 0 == memcmp( g_DotNetSmartCardAtr, srs.rgbAtr, srs.cbAtr ) ) ) {

                            Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> - .NET Card inserted", srs.szReader );

                            try {
                                
                                addSmartCard( srs.szReader );

                                notifyListenerSmartCardInserted( srs.szReader );
                            
                            } catch( ... ) {
                            
                                // This is not a .NET smart card. Nothing to do.
                            }
                        }

                        // If a smart card been removed and this is not already the state of the reader
                    } else if( ( SCARD_STATE_EMPTY & srs.dwEventState ) && ( 0 == ( SCARD_STATE_EMPTY & scr.dwCurrentState ) ) ) {
// LCA: Only notify for .NET card?
                        bool isDotNetToken = true;

                        BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

                            // Ignore empty device cell
                            if( d.get( ) && ( 0 == d->getReaderName( ).compare( srs.szReader ) ) ) {

                                try {

                                    d->getCardModule( );
                                
                                } catch (...) {

                                    isDotNetToken = false;
                                }

                                break;
                            }
                        }

                        if (isDotNetToken)
                        {
                            Log::log( "DeviceMonitor::monitorReaderEvent - Reader <%s> - Card removed", srs.szReader );

                            // Query the status of the device
                            if( isReaderExists( m_hContext, srs.szReader ) ) {

                                // The reader exists, only the smart card has been removed
                                removeSmartCard( srs.szReader );

                                notifyListenerSmartCardRemoved( srs.szReader );

                            } else {

                                // The reader has been removed and also the smart card
                                notifyListenerReaderRemoved( srs.szReader );

                                // Remove the device from the current device list
                                removeReader( srs.szReader );
                            }
                        }
                    }
                }

                // Store the reader state
                updateReader( srs );
            }
            Log::log( "DeviceMonitor::monitorReaderEvent - Rebuild the list of readers to poll" );

            // Build the new smart card reader state buffer with the plug& play notification query as first cell 
            dwReaderStatesCount = 1;

            //memset( &aReaderStates[ 1 ], 0, sizeof( SCARD_READERSTATE ) * (v g_iMaxReader );

            //aReaderStates[ 0 ].szReader = /*readerNames[ 0 ];*/ PNP_NOTIFICATION.c_str( );

            BOOST_FOREACH( boost::shared_ptr< Device >& d, m_aDevices ) {

                memset( &aReaderStates[ dwReaderStatesCount ], 0, sizeof( SCARD_READERSTATE ) );

                // Ignore empty device cell
                if( d.get( ) && d->getReaderName( ).compare( m_stEmptyDevice ) ) {

                    d->put( aReaderStates[ dwReaderStatesCount ] );

                    Log::log( "DeviceMonitor::monitorReaderEvent - Prepare to poll reader <%s>", aReaderStates[ dwReaderStatesCount ].szReader );

                    //memset( readerNames[ dwReaderStatesCount ], 0,sizeof( readerNames[ dwReaderStatesCount ] ) );

                    //memcpy( readerNames[ dwReaderStatesCount ], d->getReaderName( ).c_str( ), d->getReaderName( ).size( ) );

                    //aReaderStates[ dwReaderStatesCount ].szReader = d->getReaderName( ).c_str( ); //readerNames[ dwReaderStatesCount ];

                    ++dwReaderStatesCount;
                }
            }

            Log::log( "DeviceMonitor::monitorReaderEvent - Ready to poll" );

        } while( !DeviceMonitor::m_bStopPolling );

    } catch( ... ) {

        Log::log( "DeviceMonitor::monitorReaderEvent - CRASH !");
    }

    LONG l = SCardReleaseContext( DeviceMonitor::m_hContext );
    Log::log( "DeviceMonitor::monitorReaderEvent - SCardReleaseContext <%#02x>", l );

    Log::log( "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ DEVICE MONITOR THREAD STOPS ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]\n" );

    DeviceMonitor::m_bAlive = false;
}
