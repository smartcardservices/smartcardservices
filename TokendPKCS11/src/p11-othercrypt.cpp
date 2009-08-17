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

ck_rv_t C_SignRecoverInit(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t key) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SignRecover(ck_session_handle_t session, byte *data, ulong data_len, byte *signature, ulong *signature_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

/* Dual-operation crypto-digest/verify - user should split ops */
ck_rv_t C_DigestEncryptUpdate(ck_session_handle_t session, byte *part, ulong part_len, byte *encrypted_part, ulong *encrypted_part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DecryptDigestUpdate(ck_session_handle_t session, byte *encrypted_part, ulong encrypted_part_len, byte *part, ulong *part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SignEncryptUpdate(ck_session_handle_t session, byte *part, ulong part_len, byte *encrypted_part, ulong *encrypted_part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DecryptVerifyUpdate(ck_session_handle_t session, byte *encrypted_part, ulong encrypted_part_len, byte *part, ulong *part_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_WrapKey(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t wrapping_key, ck_object_handle_t key, byte *wrapped_key, ulong *wrapped_key_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_DeriveKey(ck_session_handle_t session, struct ck_mechanism *mech, ck_object_handle_t base_key, struct ck_attribute *templ, ulong attr_count, ck_object_handle_t *key) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SeedRandom(ck_session_handle_t session, byte *seed, ulong seed_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_GenerateRandom(ck_session_handle_t session, byte *random_data, ulong random_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}
