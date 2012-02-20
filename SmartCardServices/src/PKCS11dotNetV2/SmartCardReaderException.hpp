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


#ifndef __GEMALTO_READER_EXCEPTION__
#define __GEMALTO_READER_EXCEPTION__


#include <string>
#include <stdexcept>


/*
*/
class SmartCardReaderException : public std::runtime_error {

public:
    
	inline SmartCardReaderException( ) : std::runtime_error( "" ), m_lError( 0 ) { }

    inline SmartCardReaderException(  long a_lError ) : std::runtime_error( "" ), m_lError( a_lError ) { }
    
	inline SmartCardReaderException( const std::string& a_stMessage, long a_lError = 0 ) : std::runtime_error( a_stMessage ), m_lError( a_lError ) { }

    inline long getError( void ) const { return m_lError; }

private:

    long m_lError;

};

#endif // __GEMALTO_READER_EXCEPTION__
