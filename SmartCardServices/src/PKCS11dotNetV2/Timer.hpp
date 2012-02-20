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


#ifndef __GEMALTO_TIMER__
#define __GEMALTO_TIMER__


#ifdef WIN32
#include <time.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif


/*
*/
class Timer {

public:
	
	void start( void );

	void stop( void );

    void stop( const char* a_pMessage );

    inline double getDuration( void ) { return m_Duration; }

    double getCurrentDuration( void );

private:
    
#ifdef WIN32
	clock_t m_clockStart;
#else
	timeval m_clockStart;
#endif

    double m_Duration;

};


#endif // __GEMALTO_TIMER__
