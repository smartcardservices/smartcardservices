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

#include "Utilities.h"

#include "P11Slot.h"
#include "P11Slots.h"
#include "P11Session.h"

/**
 * Class managing global state.
 */
class P11State {
	NOCOPY(P11State);
private:
	friend class ModuleNexus<P11State>;
	/**
	 * Constructs the P11State, private to prevent construction
	 * by anything other than ModuleNexus which manages the global state
	 */
	P11State();
public:
	/**
	 * Performs the work of C_Initialize.
	 * Sets up the mutex factory and global lock
	 */
	ck_rv_t initialize(const struct ck_c_initialize_args *args);

	/** If the state is not initialized, throw a P11Exception */
	void assertInitialized();

	/** Make sure the state is initialized and lock it before killing everything */
	ck_rv_t finalize();

	/** Accessor to the slot manager */
	P11Slots &getSlots() { return *slots; }

	/** Accessor to the session manager */
	P11Sessions& getSessions() { return *sessions; }

	/** Obtain the global lock */
	UserMutex &getLock() { return *mutex; }
	/** Obtain a new mutex instance */
	UserMutex *newMutex() { return mutexFactory->create(); }
protected:
	auto_ptr<P11Sessions> sessions;
	auto_ptr<P11Slots> slots;
private:
	mutable auto_ptr<UserMutex> mutex;
	auto_ptr<Factory<UserMutex> > mutexFactory;
	bool isInitialized;

	/** Saved arguments from initialization */
	struct ck_c_initialize_args current_args;
};

/** Globally accessible state */
extern ModuleNexus<P11State> globalState;

/** Class to obtain a hold on the global state
 * If the P11 client does not permit OS primitives,
 * this will force all users of the P11 to be fully serialized.
 * Potential fix would be to use some sort of semaphore-type emulation mechanism...
 */
class GlobalLockCheck {
public:
	GlobalLockCheck(bool readWrite = false);
private:
	friend class P11State;
	auto_ptr<StLock<UserMutex> > lock;
};

/** Method to process errors for actual returns and session killing
 * If the token was removed.
 */
ck_rv_t processSlotError(const P11Exception &e, ck_slot_id_t slot);

/** Method to process errors for actual returns and session killing
 * If the token was removed.
 */
ck_rv_t processSessionError(const P11Exception &e, ck_session_handle_t session);

/** Method to process return values for actual returns and session killing */
ck_rv_t processSessionReturn(ck_rv_t rv, ck_session_handle_t session);
