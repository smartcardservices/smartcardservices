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

#ifndef _include_event_h
#define _include_event_h

#ifdef INCLUDE_EVENTING

class CEvent
{

private:
    #ifdef WIN32
    HANDLE      m_eventHandle;
    #else
    pthread_mutex_t m_Mutex;
    pthread_cond_t  m_Condition;
    #endif
    CK_ULONG    m_timeOut;

public:
    CEvent(CK_ULONG timeOut);
    ~CEvent(void);

    void Signal(void);
    void Set(void);
    void Reset(void);
    void Wait(void);  // Throws CK_RV exception on error

    #ifdef WIN32
    HANDLE GetHandle() { return m_eventHandle;}
    #endif
};

extern CEvent CryptokiEvent;

#endif

#endif

