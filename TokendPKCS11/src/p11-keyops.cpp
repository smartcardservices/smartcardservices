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

using std::tr1::dynamic_pointer_cast;

/* Supported algs
 * CKM_RSA_PKCS   Sign/Decrypt
 * CKM_RSA_X_X509 Sign/Decrypt
 */

ck_rv_t C_DecryptInit(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t key) {
	try {
		GlobalLockCheck globalLock;
		/* RW LOCK: Crypto ops alter the session */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		/* R LOCK: Nab the slot, crypto ops don't alter slot -- checks existence */
		LockedSlot lockedSlot(sessionRef->getSlotID());
		lockedSlot.get()->assertPresent();
		if(sessionRef->decryptState.get())
			throw P11Exception(CKR_OPERATION_ACTIVE);		
		auto_ptr<LockedObject> obj(LockedObject::get_locked_object(lockedSession, key));
		/* May throw if invalid mechanism/keyobject pair */
		/* Release a reference into the cryptostate */
		sessionRef->decryptState.reset(new P11CryptoState(obj->get(), *mech));
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_Decrypt(ck_session_handle_t session, byte *encrypted_data, ulong encrypted_data_len, byte *data, ulong *data_len) {
	try {
		GlobalLockCheck globalLock;
		if(!encrypted_data || !encrypted_data_len || !data_len)
			return CKR_ARGUMENTS_BAD;
		/* RW LOCK: Crypto ops alter the session */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		/* R LOCK: Nab the slot, crypto ops don't alter slot -- checks existence */
		LockedSlot lockedSlot(sessionRef->getSlotID());
		lockedSlot.get()->assertPresent();
		if(!sessionRef->decryptState.get())
			return CKR_OPERATION_NOT_INITIALIZED;
		ck_rv_t ret;
		try {
			ret = sessionRef->decryptState->decrypt(encrypted_data, encrypted_data_len, data, *data_len);
		} catch(P11Exception &e) {
			ret = e.ret;
		}
		/* size-obtaining funcs (CKR_OK and CKR_BUFFER_TOO_SMALL) do not kill the state */
		if(!(CKR_OK == ret && !data || CKR_BUFFER_TOO_SMALL == ret))
			sessionRef->decryptState.reset();
		return processSessionReturn(ret, session);
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DecryptUpdate(ck_session_handle_t session, byte *encrypted_part, ulong encrypted_part_len, byte *part, ulong *part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DecryptFinal(ck_session_handle_t session, byte *last_part, ulong *last_part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SignInit(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t key) {
	try {
		GlobalLockCheck globalLock;
		/* RW LOCK: Crypto ops alter the session */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		/* R LOCK: Nab the slot, crypto ops don't alter slot -- checks existence */
		LockedSlot lockedSlot(sessionRef->getSlotID());
		lockedSlot.get()->assertPresent();
		if(sessionRef->signState.get())
			throw P11Exception(CKR_OPERATION_ACTIVE);
		auto_ptr<LockedObject> obj(LockedObject::get_locked_object(lockedSession, key));
		sessionRef->signState.reset(new P11CryptoState(obj->get(), *mech));
		return CKR_OK;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_Sign(ck_session_handle_t session, byte *data, ulong data_len, byte *signature, ulong *signature_len) {
	try {
		GlobalLockCheck globalLock;
		if(!data || !data_len || !signature_len)
			return CKR_ARGUMENTS_BAD;
		/* RW LOCK: Crypto ops alter the session */
		LockedSession lockedSession(session, true);
		P11Session_Ref sessionRef = lockedSession.get();
		/* R LOCK: Nab the slot, crypto ops don't alter slot -- checks existence */
		LockedSlot lockedSlot(sessionRef->getSlotID());
		lockedSlot.get()->assertPresent();
		if(!sessionRef->signState.get())
			return CKR_OPERATION_NOT_INITIALIZED;
		ck_rv_t ret;
		try {
			ret = sessionRef->signState->sign(data, data_len, signature, *signature_len);
		} catch(P11Exception &e) {
			ret = e.ret;
		}
		/* size-obtaining funcs (CKR_OK and CKR_BUFFER_TOO_SMALL) do not kill the state */
		if(!(CKR_OK == ret && !signature || CKR_BUFFER_TOO_SMALL == ret))
			sessionRef->signState.reset();
		return processSessionReturn(ret, session);
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SignUpdate(ck_session_handle_t session, byte *part, ulong part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SignFinal(ck_session_handle_t session, byte *signature, ulong *signature_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_UnwrapKey(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t unwrapping_key, byte *wrapped_key, ulong wrapped_key_len, struct ck_attribute *templ, ulong attr_count, ck_object_handle_t *key) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}
