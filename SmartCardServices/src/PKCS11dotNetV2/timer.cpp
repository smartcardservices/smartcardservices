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

#include <cstring>

#include "Timer.hpp"
#include "Log.hpp"


/*
*/
void Timer::start( void ) {

#ifdef WIN32
	m_clockStart = clock( );
#else	
   gettimeofday( &m_clockStart, NULL ); 
#endif
}


/*
*/
void Timer::stop( const char* a_pMessage ) {

    if( !Log::s_bEnableLog ) {

        return;
    }

    stop( );

	if( 0.400 < m_Duration ) {

        Log::log( "$$$$$$$$$$$$$$$$$$$$$$$ %s - Elapsed time <%f> seconds", a_pMessage, m_Duration );

    } else {
        Log::log( "%s - Elapsed time <%f> seconds", a_pMessage, m_Duration );
    }
}


/*
*/
double Timer::getCurrentDuration( void ) {
 
#ifdef WIN32
      double duration = (double)(clock( ) - m_clockStart) / CLOCKS_PER_SEC;
	  //m_clockStart = 0;
#else	
      timeval now;         
      gettimeofday( &now, NULL );  

      timeval diff;          
      diff.tv_sec = now.tv_sec - m_clockStart.tv_sec;
      diff.tv_usec = now.tv_usec - m_clockStart.tv_usec; 
      while( diff.tv_usec < 0 )
      {
         diff.tv_sec--;
         diff.tv_usec = 1000000 + ( now.tv_usec - m_clockStart.tv_usec );
      }
      double duration = diff.tv_sec;         
      duration += (double)( diff.tv_usec / 1e6 ); 
 
      //memset( &m_clockStart, 0, sizeof( timeval ) );
#endif

    //Log::log( "Timer::getCurrentDuration - Elapsed time <%f> seconds", duration );

	return duration;
}




/*
*/
void Timer::stop( void ) {

      m_Duration = getCurrentDuration( );
}
