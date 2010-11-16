/*
 *  Copyright (c) 2008 Apple Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_START@
 *
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *
 *  @APPLE_LICENSE_HEADER_END@
 */

#include "P11Mutexes.h"
#include <pthread.h>

class SystemWriteMutex : public UserMutex {
	NOCOPY(SystemWriteMutex);
public:
	SystemWriteMutex(pthread_rwlock_t &rwlock) : rwlock(rwlock) {
	}
	virtual ~SystemWriteMutex() {}
	void lock() {
		if(0 != pthread_rwlock_wrlock(&rwlock))
			throw P11Exception(CKR_GENERAL_ERROR);
	}
	void unlock() {
		if(0 != pthread_rwlock_unlock(&rwlock))
			throw P11Exception(CKR_GENERAL_ERROR);
	}
	UserMutex &writeMutex() { return *this; }
private:
	pthread_rwlock_t &rwlock;
};

class SystemMutex : public UserMutex {
	NOCOPY(SystemMutex);
public:
	SystemMutex() : rwlock(), writeLock(rwlock) {
		pthread_rwlock_init(&rwlock, NULL);
	}
	virtual ~SystemMutex() {
		pthread_rwlock_destroy(&rwlock);
	}
	void lock() {
		if(0 != pthread_rwlock_rdlock(&rwlock))
			throw P11Exception(CKR_GENERAL_ERROR);
	}
	void unlock() {
		if(0 != pthread_rwlock_unlock(&rwlock))
			throw P11Exception(CKR_GENERAL_ERROR);
	}
	UserMutex &writeMutex() {
		return writeLock;
	}
private:
	pthread_rwlock_t rwlock;
	SystemWriteMutex writeLock;
};

class NullMutex : public UserMutex {
	NOCOPY(NullMutex);
public:
	NullMutex() {}
	void lock() {
	}
	void unlock() {
	}
	UserMutex &writeMutex() {
		return *this;
	}
};

class AppMutex : public UserMutex {
	NOCOPY(AppMutex);
public:
	AppMutex(const struct ck_c_initialize_args &init_args)
	: init_args(init_args), mutex(NULL) {
		checkResult(init_args.create_mutex(&mutex));
	}
	virtual ~AppMutex() {
		init_args.destroy_mutex(mutex);
	}
	void lock() {
		checkResult(init_args.lock_mutex(mutex));
	}
	void unlock() {
		checkResult(init_args.unlock_mutex(mutex));
	}
	UserMutex &writeMutex() {
		return *this;
	}
private:
	const struct ck_c_initialize_args &init_args;
	void *mutex;
	static void checkResult(ck_rv_t ret) {
		if(CKR_OK != ret)
			throw P11Exception(ret);
	}
};

UserMutex *SystemMutexFactory::create() {
	return new SystemMutex();
}

UserMutex *NullMutexFactory::create() {
	return new NullMutex();
}

UserMutex *AppMutexFactory::create() {
	return new AppMutex(*(struct ck_c_initialize_args*)init_args);
}
