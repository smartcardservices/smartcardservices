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


#ifndef __GEMALTO_APPLICATION__
#define __GEMALTO_APPLICATION__


#include <string>
#include "cryptoki.h"
#include "DeviceMonitor.hpp"
#include "IDeviceMonitorListener.hpp"
#include "Slot.hpp"
#include <boost/array.hpp>


const int g_iMaxSlot = 5;

class DeviceMonitor;
class Device;
class Slot;


/*
*/
class Application : public IDeviceMonitorListener {

public:

	typedef boost::array< boost::shared_ptr< Slot >, g_iMaxSlot > ARRAY_SLOTS;

	Application( );

	virtual ~Application( );

	inline ARRAY_SLOTS getSlotList( void ) { return m_Slots; }

	void getSlotList( const CK_BBOOL& tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount );

	const boost::shared_ptr< Slot >& getSlot( const CK_SLOT_ID& );

	const boost::shared_ptr< Slot >& getSlotFromSession( const CK_SESSION_HANDLE& );

    void initialize( void );

    void finalize( void );


private:

	void getDevices( void );

	void notifyReaderInserted( const std::string& );
	
	void notifyReaderRemoved( const std::string& );

	void notifySmartCardRemoved( const std::string& );
	
	void notifySmartCardInserted( const std::string& );
	
	void notifySmartCardChanged( const std::string& );

	void addSlot( const boost::shared_ptr< Device >& );

	ARRAY_SLOTS m_Slots;
	
	boost::shared_ptr< DeviceMonitor > m_DeviceMonitor;

};

#endif // __GEMALTO_APPLICATION__
