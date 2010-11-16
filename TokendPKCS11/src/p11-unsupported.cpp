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


ck_rv_t C_GetFunctionStatus(ck_session_handle_t session) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_CancelFunction(ck_session_handle_t session) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_GetOperationState(ck_session_handle_t session, byte *op_state, ulong *op_state_len) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

ck_rv_t C_SetOperationState(ck_session_handle_t session, byte *op_state, ulong op_state_len, ck_object_handle_t enc_key, ck_object_handle_t auth_key) {
	try {
		GlobalLockCheck globalLock;
		return CKR_FUNCTION_NOT_SUPPORTED;
	} catch(P11Exception &e) {
		return processSessionError(e, session);
	}
}

// MAX LINE LENGTH: 	268
