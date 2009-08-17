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

#ifndef P11SLOTS_H
#define P11SLOTS_H

#include "pkcs11.h"

#include "P11Object.h"
#include "P11Mutexes.h"
#include "P11Slot.h"
#include "HandleManager.h"

class EmptySlot;

/* Class to manage what slots exist */
class P11Slots {
	NOCOPY(P11Slots);
private:
	/** Permit P11SlotsCreator to manage slot creation */
	friend class P11SlotsCreator;
	P11Slots();

public:
	/** Obtain a list of slots active/inactive, based on presentOnly flag */
	ck_rv_t list(ck_slot_id_t *slotList, ulong &slotCount, bool presentOnly);

	typedef map<SecKeychainRef,ck_slot_id_t> KeychainToSlotMap;
	typedef vector<P11Slot_Ref> P11SlotList;

	/** Accessor to the container lock */
	UserMutex &getLock() const { return *lock; }
protected:
	/** Permit access to ApplySlotChanges (access to slots, keychainToSlot, and loadEmptySlot */
	friend class ApplySlotChanges;
	typedef HandleManager<P11Slot> SlotHandleManager;
	SlotHandleManager slots;
	/** Mapping of keychains to slots to know what to kill on token removal */
	KeychainToSlotMap keychainToSlot;

	/** Get a reference to an slot to use w/ 'keychain' */
	P11Slot_Ref loadEmptySlot(SecKeychainRef keychain);
private:
	void refresh();
	mutable auto_ptr<UserMutex> lock;
protected:
	/* Locked object support */
	typedef P11Slot_Ref ref_type;
	typedef ck_slot_id_t handle_type;
	static const P11Slots &getContainer();

	friend class LockedSlot;
	friend class LockedContainedObject<P11Slots>;
	ref_type handleToValue(handle_type handle) const;
};


class P11SlotsCreator {
private:
	/** Permit only the P11State to create a slot manager */
	friend class P11State;
	static P11Slots *create() {
		return new P11Slots;
	}
};

/* Handles obtaining the necessary persistent lock for session handling */
class LockedSlot : public LockedContainedObject<P11Slots> {
public:
	LockedSlot(ck_slot_id_t handle, bool readWrite = false)
	:LockedContainedObject<P11Slots>(P11Slots::getContainer(), handle, readWrite) {}
};

#endif
