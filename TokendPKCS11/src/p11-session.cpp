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

ck_rv_t C_OpenSession(ck_slot_id_t slot_id, ck_flags_t flags, void *application, ck_notify_t notify, ck_session_handle_t *session) {
	try {
		GlobalLockCheck globalLock;
		if(!session)
			return CKR_ARGUMENTS_BAD;
		/* RW Lock - state alteration */
		P11Sessions &sessions = globalState().getSessions();
		StLock<UserMutex> sessionsLock(sessions.getLock().writeMutex()); /* VALIDATED */
		sessions.create(slot_id, flags, notify, application, *session);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSlotError(e, slot_id);
	}
}

ck_rv_t C_CloseSession(ck_session_handle_t session) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock - state alteration */
		P11Sessions &sessions = globalState().getSessions();
		StLock<UserMutex> sessionsLock(sessions.getLock().writeMutex()); /* VALIDATED */
		sessions.close(session);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_CloseAllSessions(ck_slot_id_t slot_id) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock - state alteration */
		P11Sessions &sessions = globalState().getSessions();
		StLock<UserMutex> sessionsLock(sessions.getLock().writeMutex()); /* VALIDATED */
		sessions.closeAll(slot_id);
		return CKR_OK;
	} catch(P11Exception &e) {
		/* Exempt from error processing since it is in response to error processing */
		return e.ret;
	}
}

ck_rv_t C_GetSessionInfo(ck_session_handle_t session, struct ck_session_info *info) {
	try {
		GlobalLockCheck globalLock;
		/* R Lock: Get Session Info == no change, need slot... */
		LockedSession sessionRef(session);
		LockedSlot lockedSlot(sessionRef.get()->getSlotID());
		sessionRef.get()->information(*info, lockedSlot);
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_Login(ck_session_handle_t session, ck_user_type_t user_type, byte *pin, ulong pin_len) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock: Login changes slot state - not session state as pkcs11 wants... */
		LockedSession sessionRef(session, true);
		LockedSlot lockedSlot(sessionRef.get()->getSlotID(), true);
		return lockedSlot.get()->login(user_type, pin, pin_len);
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_Logout(ck_session_handle_t session) {
	try {
		GlobalLockCheck globalLock;
		/* RW Lock: Logout changes state */
		LockedSession sessionRef(session, true);
		LockedSlot lockedSlot(sessionRef.get()->getSlotID(), true);
		return lockedSlot.get()->logout();
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}
