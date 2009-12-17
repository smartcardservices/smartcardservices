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

#ifndef _include_critsect_h
#define _include_critsect_h

#if defined(_WIN32)

#include <windows.h>

#else

#include <pthread.h>

#endif

class CCriticalSection
{

public:

    // A non-default constructor with a dummy parameter is added since
    // it is needed when CCriticalSection is used as static member in
    // template classes to instantiate properly with GCC. See for instance
    // http://gcc.gnu.org/ml/gcc-bugs/2005-01/msg03798.html

    CCriticalSection();
    //explicit CCriticalSection(bool dummy);
    ~CCriticalSection();
    void Enter();
    void Leave();

private:
    void Init();

#if defined(_WIN32)

	CRITICAL_SECTION m_CriticalSection;

#else

    pthread_mutex_t m_Mutex;
    pthread_t m_OwnerThread;
    unsigned long m_RefCount;

#endif

};

// Convenience class to manage locking

class CCriticalSectionLocker
{
public:
    CCriticalSectionLocker(CCriticalSection & cs) : m_cs(&cs)
    {
        m_cs->Enter();
    }
    CCriticalSectionLocker(CCriticalSection * cs) : m_cs(cs)
    {
        if(m_cs)
            m_cs->Enter();
    }
   ~CCriticalSectionLocker()
    {
        if(m_cs)
            m_cs->Leave();
    }

private:
    CCriticalSection * m_cs;
};


#endif // _include_critsect_h

