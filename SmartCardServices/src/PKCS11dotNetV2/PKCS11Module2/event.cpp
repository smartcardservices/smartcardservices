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

#ifdef INCLUDE_EVENTING

#include "stdafx.h"
#include "platconfig.h"
//#include "dbg.h"
#ifndef WIN32
#include <pthread.h>
#include <sys/time.h>
#endif
#include "event.h"

CEvent::CEvent(CK_ULONG timeOut)
{
	#ifdef WIN32
    m_eventHandle = CreateEvent(NULL,TRUE,FALSE,NULL);
    #else
    pthread_mutex_init(&m_Mutex,0);
    pthread_cond_init(&m_Condition,0);
    #endif
    m_timeOut     = timeOut;
}

CEvent::~CEvent(void)
{
	#ifdef WIN32
    CloseHandle(m_eventHandle);
    #else
    pthread_mutex_destroy(&m_Mutex);
    pthread_cond_destroy(&m_Condition);
    #endif
}

void CEvent::Signal()
{
	#ifdef WIN32

    if(!m_eventHandle)
        assert(FALSE);  // throw CError(CKR_FUNCTION_FAILED);

    PulseEvent(m_eventHandle);

    #else

    if(pthread_cond_broadcast(&m_Condition) == 0)
    {
    	//assert(FALSE);
    }

    #endif

}

void CEvent::Set()
{
	#ifdef WIN32

    if(!m_eventHandle)
        assert(FALSE);  // throw CError(CKR_FUNCTION_FAILED);

    SetEvent(m_eventHandle);

    #else

    if(pthread_cond_signal( &m_Condition ) != 0)
    {
    	//assert(FALSE);
    }


    #endif
}

void CEvent::Reset()
{
	#ifdef WIN32
    if(!m_eventHandle)
        assert(FALSE);  // throw CError(CKR_FUNCTION_FAILED);

    ResetEvent(m_eventHandle);
    #endif
}

void CEvent::Wait()
{
	#ifdef WIN32
    if(!m_eventHandle)
        assert(FALSE);  // throw CError(CKR_FUNCTION_FAILED);

    DWORD rv = WaitForSingleObject(m_eventHandle,m_timeOut);

    if(rv == WAIT_TIMEOUT)
        assert(FALSE);  // throw CError(CKR_FUNCTION_FAILED);

    #else

    struct timeval CurrTime;

    gettimeofday(&CurrTime, NULL);

    timespec Abstime;

    // Calculate absolute time to time out.

    Abstime.tv_sec = CurrTime.tv_sec + m_timeOut/1000;
    Abstime.tv_nsec = CurrTime.tv_usec*1000 + (m_timeOut % 1000)*1000000;

    if(Abstime.tv_nsec>999999999) {
        Abstime.tv_sec++;
        Abstime.tv_nsec -= 1000000000;
    }

    if(pthread_cond_timedwait(&m_Condition,&m_Mutex,&Abstime) == 0)
    {
    	//assert(FALSE);
    }

    #endif
}

#endif

