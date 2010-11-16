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

ck_rv_t C_InitPIN(ck_session_handle_t session, byte *pin, ulong pin_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SetPIN(ck_session_handle_t session, byte *old_pin, ulong old_len, byte *new_pin, ulong new_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_CreateObject(ck_session_handle_t session, struct ck_attribute *templ, ulong count, ck_object_handle_t *object) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, ulong count) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_GenerateKey(ck_session_handle_t session, struct ck_mechanism *mech, struct ck_attribute *templ, ulong count, ck_object_handle_t *key) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_GenerateKeyPair(ck_session_handle_t session, struct ck_mechanism *mech, struct ck_attribute *pubkey_template, ulong pubkey_attr_count, struct ck_attribute *privkey_template, ulong privkey_attr_count, ck_object_handle_t *pubkey, ck_object_handle_t *privkey) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}
