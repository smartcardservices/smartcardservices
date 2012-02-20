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

// Copied from ACS

#include "stdafx.h"
#include "critsect.h"

#if !defined (_WIN32)
#include <stdexcept>
#endif

CCriticalSection::CCriticalSection()
{
    Init();
}

/*
CCriticalSection::CCriticalSection(bool)
{
    Init();
}
*/

CCriticalSection::~CCriticalSection(void)
{
#if defined (_WIN32)

    DeleteCriticalSection(&m_CriticalSection);

#else

    pthread_mutex_destroy(&m_Mutex);

#endif
}


void CCriticalSection::Enter()
{
#if defined (_WIN32)

    EnterCriticalSection(&m_CriticalSection);

#else

    if(pthread_equal(m_OwnerThread,pthread_self())) m_RefCount++;
    else {
        int Stat = pthread_mutex_lock(&m_Mutex);
        if(Stat)
            throw std::runtime_error("pthread_mutex_lock");

        m_OwnerThread = pthread_self();
        m_RefCount = 1;
    }

#endif
}

void CCriticalSection::Leave()
{

#if defined (_WIN32)

    LeaveCriticalSection(&m_CriticalSection);

#else

    if(pthread_equal(m_OwnerThread,pthread_self())) {
        m_RefCount--;
        if(!m_RefCount) {
            m_OwnerThread = 0;
            pthread_mutex_unlock(&m_Mutex);
        }
    }

#endif

    return;
}

void CCriticalSection::Init()
{
#if defined (_WIN32)

	InitializeCriticalSection(&m_CriticalSection);

#else

    pthread_mutex_init(&m_Mutex,0);
    m_OwnerThread = 0;
    m_RefCount = 0;

#endif
}
