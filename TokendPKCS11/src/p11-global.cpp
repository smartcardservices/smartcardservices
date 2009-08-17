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

#include <assert.h>

#include "P11State.h"

#include "config.h"

/* WARNING - not thread safe per spec */
ck_rv_t C_Initialize(void *init_args) {
	try {
		struct ck_c_initialize_args blank_init_args;
		if(!init_args) {
			init_args = &blank_init_args;
			memset(&blank_init_args, 0, sizeof(blank_init_args));
		}

		return globalState().initialize((struct ck_c_initialize_args*)init_args);
	} catch(P11Exception &e) {
		return e.ret;
	}
}

/* WARNING - not completely thread safe per spec WRT duplicate calls */
ck_rv_t C_Finalize(void *reserved) {
	try {
		return globalState().finalize();
	} catch(P11Exception &e) {
		return e.ret;
	}
}

ck_rv_t C_GetInfo(struct ck_info *info) {
	try {
		memset(info, 0, sizeof(*info));

		info->cryptoki_version.major = CRYPTOKI_VERSION_MAJOR;
		info->cryptoki_version.minor = CRYPTOKI_VERSION_MINOR;
		pad_string_set(info->manufacturer_id, PKCS11_MANUFACTURER, sizeof(info->manufacturer_id));
		pad_string_set(info->library_description, PKCS11_DESCRIPTION, sizeof(info->library_description));
		info->library_version.major = PKCS11_LIBRARY_MAJOR;
		info->library_version.minor = PKCS11_LIBRARY_MINOR;
		return CKR_OK;
	} catch(P11Exception &e) {
		return e.ret;
	}
}

static struct ck_function_list pkcs11_functions = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

ck_rv_t C_GetFunctionList(struct ck_function_list **function_list) {
	try {
		if(!function_list)
			return CKR_ARGUMENTS_BAD;
		*function_list = (struct ck_function_list*)&pkcs11_functions;
		return CKR_OK;
	} catch(P11Exception &e) {
		return e.ret;
	}
}
