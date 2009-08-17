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
#include "P11Session.h"
#include "P11Slot.h"

/* Must offset due to shared namespace */
#define SESSION_OBJECT_BASE 0x08000000

P11Session::P11Session(const LockedSlot &slot, ck_flags_t flags, ck_notify_t notify, void *app_data)
:LockableHandledObject<P11Session>(globalState().newMutex()),
	decryptState(), signState(), activeSearch(),
	mFlags(flags), slotID(slot.get()->getSlotID()), objects(new P11Objects(SESSION_OBJECT_BASE)),
	notifyCallback(notify), applicationData(app_data) {
}

P11Session::~P11Session() {
}

void P11Session::information(struct ck_session_info &info, const LockedSlot &lockedSlot) {
	memset(&info, 0, sizeof(info));
	info.device_error = 0;
	info.slot_id = slotID;
	info.flags = CKF_SERIAL_SESSION; /* backwards compatibility requires */
	info.state = lockedSlot.get()->isLoggedIn() ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
}

void P11Session::initializeSearch() {
	activeSearch.reset(new P11ObjectHandleList);
}

void P11Session::lock_and_load_search(P11Objects &objects, const P11Attributes &search) {
	StLock<UserMutex> lockedObjects(objects.getLock()); /* VALIDATED */
	/* Load session-local objects */
	objects.search(search, *activeSearch);
}

P11Sessions::P11Sessions()
:sessions(), slotsToSessions(), lock(globalState().newMutex()) {
}

P11Sessions::~P11Sessions() {
}

void P11Sessions::create(const LockedSlot &slot, ck_flags_t flags, ck_notify_t notify, void *app_data, ck_session_handle_t &session) {
	P11Session_Ref newSession(P11SessionCreator::create(slot, flags, notify, app_data));
	sessions.add(newSession, FilterKeepValid<P11Session_Ref>());
	slotsToSessions.insert(P11SlotSessionMap::value_type(slot.get()->getSlotID(), newSession));
	session = newSession->getHandle();
}

P11Session_Ref P11Sessions::handleToValue(ck_session_handle_t handle) const {
	SessionManager::const_iterator iter = sessions.find(handle);
	if(iter == sessions.end() || !(*iter).get()) // Invalid or dead session
		throw P11Exception(CKR_SESSION_HANDLE_INVALID);
	return *iter;
}

void P11Sessions::close(ck_session_handle_t handle) {
	SessionManager::iterator iter = sessions.find(handle);
	if(iter == sessions.end() || !(*iter).get()) // Invalid or dead session
		throw P11Exception(CKR_SESSION_HANDLE_INVALID);
	sessions.kill_lockable_value(iter);
}

void P11Sessions::closeAll(ck_slot_id_t slot) {
	std::pair<P11SlotSessionMap::iterator,P11SlotSessionMap::iterator> slots = slotsToSessions.equal_range(slot);
	std::vector<P11Session_WeakRef> sessionsToDestroy;
	for(P11SlotSessionMap::iterator iter = slots.first; iter != slots.second; ++iter) {
		sessionsToDestroy.push_back(iter->second);
	}
	/* Kill the sessions from the mapping location */
	slotsToSessions.erase(slots.first, slots.second);
	/* Remove what should be the last reference to the sessions, after obtaining a lock for safety */
	for(int i = 0, len = sessionsToDestroy.size(); i < len; i++) {
		P11Session_Ref session = sessionsToDestroy[i].lock();
		if(!session.get()) continue;
		sessions.kill_lockable_value(sessions.find(session->getHandle()));
	}
	/* Until the max idle, trim off any dead sessions */
	sessions.remove_after_last_match(0, FilterKeepValid<P11Session_Ref>());
}

const P11Sessions &P11Sessions::getContainer() {
	return globalState().getSessions();
}
