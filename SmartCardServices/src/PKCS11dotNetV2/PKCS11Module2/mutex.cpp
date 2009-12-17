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
#include <string>
#ifndef WIN32
#include <pthread.h>
#endif
#include "mutex.h"

CMutex::CMutex()
{
#ifdef WIN32
    m_hMutex = NULL;
#endif
    m_strName = "";
}

CMutex::CMutex(const char* nm)
{
    m_strName = nm;

#ifdef WIN32
    m_hMutex = (unsigned long*)CreateMutex(NULL,FALSE,nm);

    if(m_hMutex == NULL)
    {
        assert(FALSE); //throw ThreadException("Failed to create mutex");
    }
#else
    pthread_mutex_init(&m_hMutex,0);
    m_ownerThread = 0;
    m_refCount = 0;
#endif
}

#ifdef WIN32
void CMutex::create(const char* nm)
#else
void CMutex::create(const char*)
#endif
{

#ifdef WIN32
    if(m_hMutex != NULL)
    {
        CloseHandle(m_hMutex);
        m_hMutex = NULL;
    }

    m_strName = nm;
    m_hMutex = (unsigned long*)CreateMutex(NULL,FALSE,nm);

    if(m_hMutex == NULL)
    {
        assert(FALSE); //throw ThreadException("Failed to create mutex");
    }
#else
    if(pthread_equal(m_ownerThread,pthread_self()))
    {
        m_refCount++;
    }
    else
    {
        if(pthread_mutex_lock(&m_hMutex) == 0)
        {
            //assert(FALSE);
        }
        m_ownerThread = pthread_self();
        m_refCount = 1;
    }


#endif
}

#ifdef WIN32
unsigned long* CMutex::getMutexHandle()
{
    return m_hMutex;
}
#endif

std::string CMutex::getName()
{
    return m_strName;
}

void CMutex::release()
{
#ifdef WIN32
    if(m_hMutex != NULL)
    {
        CloseHandle(m_hMutex);
        m_hMutex = NULL;
    }
#else
    if(pthread_equal(m_ownerThread,pthread_self()))
    {
        m_refCount--;

        if(!m_refCount)
        {
            m_ownerThread = 0;
            pthread_mutex_unlock(&m_hMutex);
        }
    }
#endif
}

CMutex::~CMutex()
{
#ifdef WIN32
    if(m_hMutex != NULL)
    {
        CloseHandle(m_hMutex);
    }
#else
    pthread_mutex_destroy(&m_hMutex);
#endif
}

#endif

