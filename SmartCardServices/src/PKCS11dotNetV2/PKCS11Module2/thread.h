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

#ifndef _include_thread_h
#define _include_thread_h

#include <string>

#ifdef INCLUDE_EVENTING

using namespace std;

class CThread
{

private:
    // unsigned long* to the low-level thread object
#ifdef WIN32
    CK_ULONG_PTR m_hThread;
#else
    pthread_t 	 m_hThread;
#endif

    // a name to identify the thread
    std::string* m_strName;
    CK_BBOOL     m_stopRequested;

public:
    CThread();
    CThread(const char* nm);
    virtual ~CThread();

    void setName(const char* nm);
    std::string* getName() const;

    void start();
    virtual void run();
    void sleep(CK_LONG ms);
    void suspend();
    void resume();
    virtual void stop();

    void setPriority(CK_LONG p);
    CK_BBOOL isStopRequested();

    CK_BBOOL wait(const char* m,CK_LONG ms=5000);
    void release(const char* m);

public:
    // Thread priorities
    static const CK_LONG P_ABOVE_NORMAL;
    static const CK_LONG P_BELOW_NORMAL;
    static const CK_LONG P_HIGHEST;
    static const CK_LONG P_IDLE;
    static const CK_LONG P_LOWEST;
    static const CK_LONG P_NORMAL;
    static const CK_LONG P_CRITICAL;
};

// global function called by the thread object.
// this in turn calls the overridden run()
extern "C"
{
#ifdef WIN32
    unsigned int _ou_thread_proc(void* param);
#else
    void* _ou_thread_proc(void* param);
#endif
}

#endif

#endif

