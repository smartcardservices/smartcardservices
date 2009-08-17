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

#include "P11State.h"
#include "P11Mutexes.h"

ModuleNexus<P11State> globalState;

P11State::P11State()
:slots(), sessions(), mutex(), mutexFactory(), isInitialized(false), current_args() {
}

void P11State::assertInitialized() {
	if(!isInitialized)
		throw P11Exception(CKR_CRYPTOKI_NOT_INITIALIZED);
}

ck_rv_t P11State::initialize(const struct ck_c_initialize_args *init_args) {
	if (isInitialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	if (init_args->reserved)
		return CKR_ARGUMENTS_BAD;
	current_args = *init_args;
	/* OS locking preferred */
	if(current_args.flags & CKF_OS_LOCKING_OK) {
		mutexFactory.reset(new SystemMutexFactory());
	} else if (current_args.create_mutex && current_args.destroy_mutex && current_args.lock_mutex && current_args.unlock_mutex) {
		mutexFactory.reset(new AppMutexFactory(&current_args));
	} else {
		mutexFactory.reset(new NullMutexFactory());
	}
	mutex.reset(mutexFactory->create());
	/* Hook up globals */
	slots.reset(P11SlotsCreator::create());
	sessions.reset(P11SessionsCreator::create());
	isInitialized = true;
	return CKR_OK;
}

ck_rv_t P11State::finalize() {
	GlobalLockCheck globalLock;
	isInitialized = false;
	memset(&current_args, 0, sizeof(current_args));
	mutexFactory.reset();
	/* Swap out mutex to release after unlocking */
	auto_ptr<UserMutex> preserved(mutex);
	globalLock.lock->unlock();
	return CKR_OK;
}

void AssertGlobalInitialized() {
	globalState().assertInitialized();
}

GlobalLockCheck::GlobalLockCheck(bool readWrite) : lock() {
	globalState().assertInitialized();
	/* Warning, weak uninitialization safety... */
	lock.reset(new StLock<UserMutex>(globalState().getLock())); /* VALIDATED */
	globalState().assertInitialized();
}

ck_rv_t processSlotError(const P11Exception &e, ck_slot_id_t slot) {
	ck_rv_t rv = e.ret;
	if(rv != CKR_TOKEN_NOT_PRESENT)
		return rv;
	/* Kill all associated sessions */
	C_CloseAllSessions(slot);
	return rv;
}

ck_rv_t processSessionReturn(ck_rv_t rv, ck_session_handle_t session) {
	if(rv != CKR_TOKEN_NOT_PRESENT)
		return rv;
	rv = CKR_SESSION_HANDLE_INVALID;
	ck_slot_id_t slot;
	/* Get slot */
	{
		GlobalLockCheck globalLock;
		/* R Lock: Getting attributes performs no alterations */
		LockedSession lockedSession(session);
		slot = lockedSession.get()->getSlotID();
	}
	/* Kill all associated sessions */
	C_CloseAllSessions(slot);
	return rv;
}

ck_rv_t processSessionError(const P11Exception &e, ck_session_handle_t session) {
	return processSessionReturn(e.ret, session);
}
