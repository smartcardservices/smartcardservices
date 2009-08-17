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

#ifndef P11SESSION_H
#define P11SESSION_H

#include "P11Mutexes.h"
#include "P11Object.h"
#include "P11Attribute.h"
#include "P11Slot.h"
#include "P11CryptoState.h"

#include "HandleManager.h"

class P11Session;

typedef shared_ptr<P11Session> P11Session_Ref;
typedef weak_ptr<P11Session> P11Session_WeakRef;


/* P11Session can only be pulled after a lock on the P11Sessions object
 * No 'disabled' P11Session object will be accessible, so no extra checks needed
 */
class P11Session : public LockableHandledObject<P11Session> {
	NOCOPY(P11Session);
protected:
	friend class P11SessionCreator;
	P11Session(const LockedSlot &slot, ck_flags_t flags, ck_notify_t notify, void *app_data);

public:
	~P11Session();

	void information(struct ck_session_info &info, const LockedSlot &lockedSlot);

	/* CRYPTO APIs */
	auto_ptr<P11CryptoState> decryptState;
	auto_ptr<P11CryptoState> signState;

	P11Objects &getObjects() { return *objects; }
	ck_slot_id_t getSlotID() { return slotID; }

	/* Object APIs */
	void initializeSearch();
	void lock_and_load_search(P11Objects &objects, const P11Attributes &attributes);
	auto_ptr<P11ObjectHandleList> activeSearch;

	/* Notify */
	ck_rv_t notify(ck_notification_t event) {
		return notifyCallback(getHandle(), event, applicationData);
	}
	ck_session_handle_t getHandle() const { return HandledObject<P11Session>::getHandle(); }

protected:
	ck_flags_t	mFlags;				/* see below */

	ck_slot_id_t slotID;
	/* Session-specific objects */
	P11Objects_Ref objects;

	/* NOTIFY CALLBACK DATA */
	ck_notify_t notifyCallback;
	void *applicationData;
};

class P11SessionCreator {
public:
	/** Allow P11Sessions to create/destory slots */
	friend class P11Sessions;
private:
	static P11Session_Ref create(const LockedSlot &slot, ck_flags_t flags, ck_notify_t notify, void *app_data) {
		return P11Session_Ref(new P11Session(slot, flags, notify, app_data));
	}
};


class P11Sessions {
	NOCOPY(P11Sessions);
private:
	/** Permit P11SessionsCreator to manage session manager creation */
	friend class P11SessionsCreator;
	P11Sessions();
public:
	~P11Sessions();

	typedef map<ck_session_handle_t,P11Session_Ref> P11SessionMap;
	typedef multimap<ck_slot_id_t,P11Session_WeakRef> P11SlotSessionMap;

	void create(const LockedSlot &slot, ck_flags_t flags, ck_notify_t notify, void *app_data, ck_session_handle_t &session);

	void close(ck_session_handle_t hSession);
	void closeAll(ck_slot_id_t slotID);

	UserMutex &getLock() const { return *lock; }
protected:
	typedef HandleManager<P11Session> SessionManager;
	SessionManager sessions;
	P11SlotSessionMap slotsToSessions;

	mutable auto_ptr<UserMutex> lock;

	void refresh();
protected:
	/* Locked object support */
	typedef P11Session_Ref ref_type;
	typedef ck_session_handle_t handle_type;
	static const P11Sessions &getContainer();

	friend class LockedSession;
	friend class LockedContainedObject<P11Sessions>;
	ref_type handleToValue(handle_type handle) const;
};

class P11SessionsCreator {
private:
	friend class P11State;
	static P11Sessions *create() { return new P11Sessions; }
};

/* Handles obtaining the necessary persistent lock for session handling */
class LockedSession : public LockedContainedObject<P11Sessions> {
public:
	LockedSession(ck_session_handle_t session, bool readWrite = false)
	:LockedContainedObject<P11Sessions>(P11Sessions::getContainer(), session, readWrite) {}
};

#endif
