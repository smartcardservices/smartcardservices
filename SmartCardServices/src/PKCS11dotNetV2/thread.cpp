
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
#include "thread.h"

#ifdef WIN32
const CK_LONG CThread::P_ABOVE_NORMAL = THREAD_PRIORITY_ABOVE_NORMAL;
const CK_LONG CThread::P_BELOW_NORMAL = THREAD_PRIORITY_BELOW_NORMAL;
const CK_LONG CThread::P_HIGHEST      = THREAD_PRIORITY_HIGHEST;
const CK_LONG CThread::P_IDLE         = THREAD_PRIORITY_IDLE;
const CK_LONG CThread::P_LOWEST       = THREAD_PRIORITY_LOWEST;
const CK_LONG CThread::P_NORMAL       = THREAD_PRIORITY_NORMAL;
const CK_LONG CThread::P_CRITICAL     = THREAD_PRIORITY_TIME_CRITICAL;
#endif

CThread::CThread()
{
#ifdef WIN32
    m_hThread = NULL;
#endif
    m_strName = NULL;
    m_stopRequested = false;
}

CThread::CThread(const char* nm)
{
#ifdef WIN32
    m_hThread = NULL;
#endif
    m_strName = new std::string(nm);
}

CThread::~CThread()
{
#ifdef WIN32
    if(m_hThread != NULL)
    {
        if(m_strName != NULL)
        {
            delete m_strName;
        }
        stop();
    }
#else

#endif
}

void CThread::setName(const char* nm)
{
    m_strName = new std::string(nm);
}

std::string* CThread::getName() const
{
    return m_strName;
}

void CThread::run()
{
    // Base run
}

void CThread::sleep(CK_LONG ms)
{
#ifdef WIN32
    Sleep(ms);
#else
    usleep(ms*1000);
#endif
}

void CThread::start()
{

#ifdef WIN32
    DWORD tid = 0;
    m_hThread = (unsigned long*)CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)_ou_thread_proc,(CThread*)this,0,&tid);

    if(m_hThread == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Failed to create thread");
    }
    else
    {
        setPriority(CThread::P_NORMAL);
    }

#else

    pthread_create(&m_hThread,0,_ou_thread_proc,(CThread*)this);

#endif

}

void CThread::stop()
{
#ifdef WIN32
    if(m_hThread == NULL) return;

    m_stopRequested = true;

    DWORD dwTimeout = 1000;
    DWORD dwSleepTime = 10;
    DWORD dwExitCode = STILL_ACTIVE;

    for(DWORD i=0; i< dwTimeout/dwSleepTime; i++)
    {
        if(GetExitCodeThread(m_hThread, &dwExitCode))
        {
            if(dwExitCode!=STILL_ACTIVE)
                break;
        }
        else
            break; // Some error
        Sleep(dwSleepTime);
    }

    if( dwExitCode == STILL_ACTIVE )
        TerminateThread(m_hThread, 0);

    // Never do this.
    ///WaitForSingleObject(m_hThread,INFINITE);
    CloseHandle(m_hThread);
    m_hThread = NULL;

    m_stopRequested = false;

#else

    m_stopRequested = true;

    pthread_join(m_hThread,NULL);

    m_stopRequested = false;

#endif
}

CK_BBOOL CThread::isStopRequested()
{
    return m_stopRequested;
}

#ifdef WIN32
void CThread::setPriority(CK_LONG tp)
#else
void CThread::setPriority( CK_LONG )
#endif
{
#ifdef WIN32
    if(m_hThread == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Thread object is null");
    }
    else
    {
        if(SetThreadPriority(m_hThread,tp) == 0)
        {
            assert(FALSE);
            //throw ThreadException("Failed to set priority");
        }
    }
#else
#endif
}

void CThread::suspend()
{

#ifdef WIN32
    if(m_hThread == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Thread object is null");
    }
    else
    {
        if((int)SuspendThread(m_hThread) < 0)
        {
            assert(FALSE);
            //throw ThreadException("Failed to suspend thread");
        }
    }
#else
#endif
}

void CThread::resume()
{
#ifdef WIN32
    if(m_hThread == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Thread object is null");
    }
    else
    {
        if((int)ResumeThread(m_hThread) < 0)
        {
            assert(FALSE);
            //throw ThreadException("Failed to resume thread");
        }
    }
#else
#endif
}

#ifdef WIN32
CK_BBOOL CThread::wait(const char* m,CK_LONG ms)
#else
CK_BBOOL CThread::wait( const char*, CK_LONG )
#endif
{
#ifdef WIN32
    HANDLE h = OpenMutex(MUTEX_ALL_ACCESS,FALSE,m);

    if(h == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Mutex not found");
    }
    DWORD d = WaitForSingleObject(h,ms);

    switch(d)
    {
    case WAIT_ABANDONED:
        assert(FALSE);
        //throw ThreadException("Mutex not signaled");
        break;
    case WAIT_OBJECT_0:
        return true;
    case WAIT_TIMEOUT:
        assert(FALSE);
        //throw ThreadException("Wait timed out");
        break;
    }
    return false;
#else
    return false;
#endif
}

#ifdef WIN32
void CThread::release(const char* m)
#else
void CThread::release( const char* )
#endif
{
#ifdef WIN32
    HANDLE h = OpenMutex(MUTEX_ALL_ACCESS,FALSE,m);
    if(h == NULL)
    {
        assert(FALSE);
        //throw ThreadException("Invalid mutex handle");
    }
    if(ReleaseMutex(h) == 0)
    {
        assert(FALSE);
        //throw ThreadException("Failed to release mutex");
    }
#else
#endif
}

#ifdef WIN32
// global thread caallback
unsigned int _ou_thread_proc(void* param)
{
    CThread* tp = (CThread*)param;
    tp->run();
    return 0;
}
#else
void* _ou_thread_proc(void* param)
{
    CThread* tp = (CThread*)param;
    tp->run();
    return NULL;
}
#endif

#endif

