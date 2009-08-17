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

#ifndef P11MUTEXES_H
#define P11MUTEXES_H

#include "Utilities.h"

class SystemMutexFactory : public Factory<UserMutex> {
	NOCOPY(SystemMutexFactory);
public:
	SystemMutexFactory() {}
	UserMutex *create();
};

class NullMutexFactory : public Factory<UserMutex> {
	NOCOPY(NullMutexFactory);
public:
	NullMutexFactory() {}
	UserMutex *create();
};

class AppMutexFactory : public Factory<UserMutex> {
	NOCOPY(AppMutexFactory);
public:
	AppMutexFactory(const void *init_args)
	: init_args(init_args) {
	}
	UserMutex *create();
private:
	const void *init_args;
};

#endif
