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

#include "P11Slots.h"

#include "P11State.h"
#include "IteratorUtilities.h"
#include "CFUtilities.h"
#include <Security/Security.h>
#include "config.h"

class FilterKeepOccupiedSlot : public Filter<P11Slot_Ref> {
public:
	inline bool operator() (const P11Slot_Ref &slot) const {
		return slot.get() && slot->isPresent();
	}
};

class FilterKeepUsedSlot : public Filter<P11Slot_Ref> {
public:
	inline bool operator() (const P11Slot_Ref &slot) const {
		return slot.get() && (!slot.unique() || slot->isPresent());
	}
};

class GetSlotID {
public:
	ck_slot_id_t operator() (const P11Slot_Ref &slot) {
		return slot.get() ? slot->getSlotID() : (ck_slot_id_t)-1;
	}
};

class ApplySlotChanges {
public:
	ApplySlotChanges(P11Slots &slots) : slots(slots) {
	}
	void operator() (const P11Slots::KeychainToSlotMap::value_type &value) {
		if(value.second != INVALID_HANDLE_VALUE) { /* Slot exists and must be deleted */
			P11Slots::SlotHandleManager::iterator iter = slots.slots.find(value.second);
			if(iter != slots.slots.end()) {
				/* Kill all sessions w/ this slot */
				{
					/* RW Lock - state alteration */
					P11Sessions &sessions = globalState().getSessions();
					StLock<UserMutex> sessionsLock(sessions.getLock().writeMutex()); /* VALIDATED */
					sessions.closeAll(iter->get()->getHandle());
				}
				slots.slots.kill_lockable_value(iter);
				/* Fill in the slot w/ dummy data */
				slots.slots.replace_value(iter, P11SlotCreator::DummySlot());
			}
			slots.keychainToSlot.erase(value.first);
		} else { /* New slot and must be instantiated */
			P11Slot_Ref ref = slots.loadEmptySlot(value.first);
			P11Slots::KeychainToSlotMap::value_type new_value(value.first,ref->getSlotID());
			slots.keychainToSlot.insert(new_value);
		}
	}
private:
	P11Slots &slots;
};

P11Slots::P11Slots() : slots(), keychainToSlot(), lock(globalState().newMutex()) {
	/* Create 'empty' slots until the minimum, ignoring slot emptiness */
	for(int i = 0; i < MIN_SLOTS; i++) {
		slots.add(P11SlotCreator::DummySlot(), FilterKeepAll<P11Slot_Ref>());
	}
}

ck_rv_t P11Slots::list(ck_slot_id_t *slotList, ulong &slotCount, bool presentOnly) {
	refresh();
	/* ck_slot_id is an unsigned long, assumes unsigned longs are sizeof ptr */
	std::vector<ck_slot_id_t> slotsToReturn;
	if(presentOnly)
		slots.copy_handles(back_insert_iterator<std::vector<ck_slot_id_t> >(slotsToReturn), FilterKeepOccupiedSlot());
	else
		slots.copy_handles(back_insert_iterator<std::vector<ck_slot_id_t> >(slotsToReturn), FilterKeepValid<P11Slot_Ref>());
	return copy_list(slotList, slotsToReturn, slotCount);
}
P11Slot_Ref P11Slots::handleToValue(ck_slot_id_t slotID) const {
	SlotHandleManager::const_iterator iter = slots.find(slotID);
	if(iter == slots.end())
		throw P11Exception(CKR_SLOT_ID_INVALID);
	return *iter;
}

const P11Slots &P11Slots::getContainer() {
	return globalState().getSlots();
}

static void LoadIntoMap(const void *value, void *context) {
	SecKeychainRef keychainRef = (SecKeychainRef)value;
	P11Slots::KeychainToSlotMap &set = *(P11Slots::KeychainToSlotMap*)context;
	set.insert(P11Slots::KeychainToSlotMap::value_type(keychainRef, INVALID_HANDLE_VALUE));
}

P11Slot_Ref P11Slots::loadEmptySlot(SecKeychainRef keychain) {
	return *slots.add(P11SlotCreator::ActiveSlot(keychain), FilterKeepOccupiedSlot());
}

/* T EXPECTED TO BE OF PAIR TYPE */
template<typename T>
bool KeyComparer(const T &first, const T &second) {
	return (intptr_t)(void*)first.first < (intptr_t)(void*)second.first;
}

void P11Slots::refresh() {
	// if we want to support soft tokens, must iterate over domains; see cacheKeychainLists
	OSStatus status = noErr;
	CFArrayRef searchList = NULL;
	
	status = SecKeychainCopyDomainSearchList(kSecPreferencesDomainDynamic, &searchList);
	if (status) {
		//??
		keychainToSlot.clear();
		return;
	}
	
	uint32_t count = searchList ? CFArrayGetCount(searchList) : 0;
	
	// Create new slots if not in list already
	KeychainToSlotMap activeKeychains;
	CFRange range = CFRangeMake(0, count);
	CFArrayApplyFunction(searchList, range, LoadIntoMap, &activeKeychains);
	
	/* Couldn't used existing typedef in the map due to const issues */
	typedef vector<std::pair<SecKeychainRef,ck_slot_id_t> > P11SlotMapIterList;
	P11SlotMapIterList slotDifference;
	set_symmetric_difference(keychainToSlot.begin(), keychainToSlot.end(), activeKeychains.begin(), activeKeychains.end(), back_insert_iterator<P11SlotMapIterList>(slotDifference), KeyComparer<KeychainToSlotMap::value_type>);
	
	/* Any slots in the difference list require an update of some kind
	 * If the slot iter contains an active slot, then it must be deleted
	 * else the slot is from the 'fresh' list and must be created */
	for_each(slotDifference.begin(), slotDifference.end(), ApplySlotChanges(*this));
	
	/* Until the max idle, trim off any dead slots */
	slots.remove_after_last_match(MAX_IDLE_SLOTS, FilterKeepUsedSlot());
	if (searchList)
		CFRelease(searchList);
}
