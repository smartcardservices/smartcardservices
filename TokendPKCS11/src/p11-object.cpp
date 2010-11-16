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
#include "P11State.h"

ck_rv_t C_GetObjectSize(ck_session_handle_t session, ck_object_handle_t object, ulong *size) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_GetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, ulong count) {
	try {
		GlobalLockCheck globalLock;
		if(!templ)
			return CKR_ARGUMENTS_BAD;
		/* R Lock: Getting attributes performs no alterations */
		LockedSession lockedSession(session);
		/* Obtain the object (or throw bad object handle) and return attributes */
		auto_ptr<LockedObject> obj(LockedObject::get_locked_object(lockedSession, object, false));
		return obj->get()->getAttributes().get(templ, count);
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_FindObjectsInit(ck_session_handle_t session, struct ck_attribute *templ, ulong count) {
	try {
		GlobalLockCheck globalLock;
		if(!templ && count != 0)
			return CKR_ARGUMENTS_BAD;
		/* RW Lock: Beginning a search initializes search variables in the session */
		LockedSession lockedSession(session, true);
		/* Construct the search */
		P11Attributes search(templ, count);

		P11Session_Ref sessionRef = lockedSession.get();
		lockedSession.get()->initializeSearch();
		/* Load up session objects */
		sessionRef->lock_and_load_search(sessionRef->getObjects(), search);
		/* Lock the slot and load it */
		LockedSlot lockedSlot(sessionRef->getSlotID());
		sessionRef->lock_and_load_search(lockedSlot.get()->getObjects(), search);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_FindObjects(ck_session_handle_t session, ck_object_handle_t *object, ulong max_object_count, ulong *object_count) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock: Pulling objects from the search alters the session */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		if(!sessionRef->activeSearch.get())
			return CKR_OPERATION_NOT_INITIALIZED;
		if(!object_count || !object)
			return CKR_ARGUMENTS_BAD;
		/* Pull out some of the values in the active search and return them */
		*object_count = min(max_object_count, sessionRef->activeSearch->size());
		P11ObjectHandleList::iterator begin = sessionRef->activeSearch->begin();
		P11ObjectHandleList::iterator endOfCopy = begin + *object_count;
		copy(begin, endOfCopy, object);
		sessionRef->activeSearch->erase(begin, endOfCopy);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_FindObjectsFinal(ck_session_handle_t session) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock: Completion of search alters the session by removing the active search */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		if(!sessionRef->activeSearch.get())
			return CKR_OPERATION_NOT_INITIALIZED;
		sessionRef->activeSearch.reset(NULL);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_CopyObject(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, ulong count, ck_object_handle_t *new_object) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DestroyObject(ck_session_handle_t session, ck_object_handle_t object) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock: Deletion alters the session, object-container, and object */
		/* NOTE: Slot objects are not deletable and will throw */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		P11Objects_Ref objectContainer;
		{
			/* Located the object and find its parent */
			auto_ptr<LockedObject> obj(LockedObject::get_locked_object(lockedSession, object, false));
			objectContainer = obj->get()->getParent().lock();
		}
		/* Container is gone... forget about it */
		if(!objectContainer.get())
			return CKR_OK;
		StLock<UserMutex> containerLock(objectContainer->getLock().writeMutex()); /* VALIDATED */
		objectContainer->destroyObject(object);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}
