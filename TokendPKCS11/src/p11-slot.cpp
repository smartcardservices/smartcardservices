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
#include "IteratorUtilities.h"
#include "Utilities.h"

ck_rv_t C_GetSlotList(byte token_present, ck_slot_id_t *slot_list, ulong *count) {
	try {
		GlobalLockCheck globalLock;
		/* token_present ignored */
		if(!count)
			return CKR_ARGUMENTS_BAD;
		P11Slots &slots = globalState().getSlots();
		/* RW Lock : Listing slots causes a refresh */
		StLock<UserMutex> slotsLock(slots.getLock().writeMutex()); /* VALIDATED */
		return slots.list(slot_list, *count, token_present != 0);
	} catch(P11Exception &e) {
		return e.ret;
	}
}

ck_rv_t C_GetSlotInfo(ck_slot_id_t slot_id, struct ck_slot_info *info) {
	bool slotIsPresent;
	try {
		GlobalLockCheck globalLock;
		if(!info)
			return CKR_ARGUMENTS_BAD;
		/* R Lock: Just pulling slot data */
		LockedSlot lockedSlot(slot_id);
		P11Slot_Ref slot = lockedSlot.get();
		slotIsPresent = slot->isPresent();
		slot->getInformation(*info);
	} catch(P11Exception &e) {
		return e.ret;
	}
	if(!slotIsPresent) {
		/* Try to close all sessions */
		C_CloseAllSessions(slot_id);
	}
	return CKR_OK;
}

ck_rv_t C_GetTokenInfo(ck_slot_id_t slot_id, struct ck_token_info *info) {
	try {
		GlobalLockCheck globalLock;
		if(!info)
			return CKR_ARGUMENTS_BAD;
		/* R Lock: Just pulling slot data */
		LockedSlot lockedSlot(slot_id);
		P11Slot_Ref slot = lockedSlot.get();
		/* Global use and current use need to not be counted */
		slot->getTokenInformation(*info, slot.use_count() - 2);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSlotError(e, slot_id);
	}
}

ck_rv_t C_WaitForSlotEvent(ck_flags_t flags, ck_slot_id_t *slot, void *reserved) {
	try {
		GlobalLockCheck globalLock;
		/* NOTE: Existing apple impl does not impl */
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return e.ret;
	}
}

ck_rv_t C_GetMechanismList(ck_slot_id_t slot_id, ck_mechanism_type_t *mech_list, ulong *count) {
	try {
		GlobalLockCheck globalLock;
		if(!count)
			return CKR_ARGUMENTS_BAD;
		/* R Lock: Just pulling mechanism list */
		LockedSlot lockedSlot(slot_id);
		P11Slot_Ref slot = lockedSlot.get();
		return copy_list_of_keys(mech_list, slot->getMechanisms(), *count);
	} catch(P11Exception &e) {
		return processSlotError(e, slot_id);
	}
}

ck_rv_t C_GetMechanismInfo(ck_slot_id_t slot_id, ck_mechanism_type_t type, struct ck_mechanism_info *info) {
	try {
		GlobalLockCheck globalLock;
		if(!info)
			return CKR_ARGUMENTS_BAD;
		/* R Lock: Just pulling mechanism info */
		LockedSlot lockedSlot(slot_id);
		P11Slot_Ref slot = lockedSlot.get();
		P11Mechanism_Ref mech = slot->getMechanism(type);
		*info = mech->getInfo();
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSlotError(e, slot_id);
	}
}

ck_rv_t C_InitToken(ck_slot_id_t slot_id, byte *pin, ulong pin_len, byte *label) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSlotError(e, slot_id);
	}
}
