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


#ifndef __GEMALTO_DEVICE_MONITOR__
#define __GEMALTO_DEVICE_MONITOR__


#include <vector>
#include <string>
#include <list>
#include <boost/shared_ptr.hpp>
#include <boost/array.hpp>
#include <boost/thread.hpp>


#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif


//#ifdef __sun
//typedef LPSTR LPTSTR;
//#endif

#include "IDeviceMonitorListener.hpp"
#include "Device.hpp"


const int g_iMaxReader = 5; //MAXIMUM_SMARTCARD_READERS


/*
*/
class DeviceMonitor {

public:

	DeviceMonitor( );

    virtual ~DeviceMonitor( ) { }

    typedef boost::array< boost::shared_ptr< Device >, g_iMaxReader > DEVICES;

	inline DEVICES& getDeviceList( void ) { return m_aDevices; };

	void addListener( IDeviceMonitorListener* const );
	
	inline void removeListener( IDeviceMonitorListener* const a_pListener ) { m_Listeners.remove( a_pListener ); }

	void start( void );
	
	void stop( void );

	size_t size( ) { return m_aDevices.size( ); }

    	static SCARDCONTEXT m_hContext;

	static bool m_bStopPolling;

    static bool m_bAlive;

private:

	void getDevicesList( const SCARDCONTEXT&, std::vector< std::string >& );
	
	void getDevicesStates( const SCARDCONTEXT& );

    void monitorReaderEvent( void );

	void notifyListenerReaderInserted( const std::string& );

	void notifyListenerReaderRemoved( const std::string& );

	void notifyListenerSmartCardInserted( const std::string& );

	void notifyListenerSmartCardRemoved( const std::string& );

	void notifyListenerSmartCardChanged( const std::string& );

	void updateReader( const SCARD_READERSTATE& );

	void removeReader( LPCSTR );
	
	void addReader( const SCARDCONTEXT&, const std::string& );

    void addReader( const SCARD_READERSTATE&, const unsigned char& );

    void removeSmartCard( const std::string& );
	
	void addSmartCard( const std::string& );
	
	void getReader( SCARD_READERSTATE& );

	void unblockWaitingThread( void );

    bool isReaderExists( const SCARDCONTEXT& h, const std::string& );

	DEVICES m_aDevices;
	
	std::list< IDeviceMonitorListener* > m_Listeners;
    
    std::string m_stEmptyDevice;

	boost::shared_ptr< boost::thread > m_ThreadListener;
	
	void printReaderState( const SCARD_READERSTATE& scrs, const int& iIndex );
	void printDeviceList( void );
	void printReaderStateList( boost::array< SCARD_READERSTATE, g_iMaxReader + 1 >& );
	void getState( const DWORD& dwState, std::string& stState );

};

#endif
