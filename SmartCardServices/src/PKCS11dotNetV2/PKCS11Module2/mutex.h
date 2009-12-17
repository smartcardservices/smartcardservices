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

#ifndef _include_mutex_h
#define _include_mutex_h

#ifdef INCLUDE_EVENTING

class CMutex
{
private:
    // unsigned long* to the low-level mutex object
#ifdef WIN32
    unsigned long* m_hMutex;
#else
    pthread_mutex_t m_hMutex;
    pthread_t 		m_ownerThread;
    unsigned long 	m_refCount;
#endif
    // name to identify the mutex
    std::string m_strName;

public:
    CMutex();
    CMutex(const char* nm);
    ~CMutex();

    void create(const char* nm);
    unsigned long* getMutexHandle();
    std::string getName();
    void release();
};

#endif

#endif

