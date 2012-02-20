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


#ifndef __GEMALTO_SMARTCARD_READER__
#define __GEMALTO_SMARTCARD_READER__


#include <string>
#include <boost/logic/tribool.hpp>


class SmartCardReader {

public:

	SmartCardReader( const std::string& );

	bool isVerifyPinSecured( void );

	inline const std::string& getReaderName( void ) { return m_stReaderName; }

	inline void setReaderName( const std::string& a_stReaderName ) { m_stReaderName = a_stReaderName; }

	void verifyPinSecured( const unsigned char& );

	inline void setCardHandle( const SCARDHANDLE& a_CardHandle ) { m_CardHandle = a_CardHandle; }


private:

	std::string m_stReaderName;

	DWORD m_dwIoctlVerifyPIN;

	SCARDHANDLE m_CardHandle;

    boost::logic::tribool m_bIsSecuredVerifyPIN;

};


#endif // __GEMALTO_SMARTCARD_READER__
