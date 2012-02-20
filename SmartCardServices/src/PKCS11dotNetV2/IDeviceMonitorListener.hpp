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


#ifndef __GEMALTO_DEVICE_MONITOR_LISTENER_INTERFACE__
#define __GEMALTO_DEVICE_MONITOR_LISTENER_INTERFACE__


/*
*/
class IDeviceMonitorListener {

public:

	virtual ~IDeviceMonitorListener( ) { }

	virtual void notifyReaderInserted( const std::string& s ) = 0;
	
	virtual void notifyReaderRemoved( const std::string& s ) = 0;
	
	virtual void notifySmartCardRemoved( const std::string& s ) = 0;
	
	virtual void notifySmartCardInserted( const std::string& s ) = 0;

	virtual void notifySmartCardChanged( const std::string& s ) = 0;

};

#endif // __GEMALTO_DEVICE_MONITOR_LISTENER_INTERFACE__
