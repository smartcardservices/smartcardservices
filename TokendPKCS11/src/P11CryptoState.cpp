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

#include "P11CryptoState.h"
#include "P11Identity.h"

#include "CFUtilities.h"
#include <Security/Security.h>

P11CryptoState::P11CryptoState(P11Object_Ref key, const struct ck_mechanism &mechanism)
: key(key), mechanism(mechanism) {
	if(key->oclass() != CKO_PRIVATE_KEY)
		throw P11Exception(CKR_KEY_HANDLE_INVALID);
	/* CURRENTLY ONLY SUPPORT CKM_RSA_PKCS */
	/* MUST SUPPORT CKM_RSA_X_509 for SSL */
	if(mechanism.mechanism != CKM_RSA_PKCS && mechanism.mechanism != CKM_RSA_X_509)
		throw P11Exception(CKR_MECHANISM_INVALID);
	/* CKM_RSA_PKCS takes no params */
//	if(mechanism.parameter_len != 0)
//		throw P11Exception(CKR_MECHANISM_PARAM_INVALID);
	/* Null out the ptr since it wont be copied to use */
	this->mechanism.parameter = NULL;
}

P11CryptoState::~P11CryptoState() {
	if(mechanism.parameter)
		free(mechanism.parameter);
}

static void check(OSStatus status, ck_rv_t errorValue = CKR_FUNCTION_FAILED) {
	if(noErr != status)
		throw P11Exception(errorValue);
}

static int getKeySize(SecKeyRef keyRef) {
	const CSSM_KEY *cssmKey;
	check(SecKeyGetCSSMKey(keyRef, &cssmKey));
	return cssmKey->KeyHeader.LogicalKeySizeInBits / 8;
}


class CSSM_Context_Deleter {
public:
	static void call(CSSM_CC_HANDLE handle) {
		if(handle) CSSM_DeleteContext(handle);
	}
};

/* Expects input and output to handle full keysize of data */
static void rawCrypt(SecKeyRef keyRef, const byte *input, ulong input_len, byte *output, ulong &output_len) {
	ScopedCF<CSSM_CC_HANDLE,CSSM_Context_Deleter> cc;
	const CSSM_KEY *cssmKey;
	CSSM_CSP_HANDLE csp;
	const CSSM_ACCESS_CREDENTIALS *accessCred;
	CSSM_ALGORITHMS encrPad = CSSM_PADDING_NONE;
	CSSM_ALGORITHMS encrAlg = CSSM_ALGID_RSA;

	check(SecKeyGetCSSMKey(keyRef, &cssmKey));
	check(SecKeyGetCSPHandle(keyRef, &csp));
	check(SecKeyGetCredentials(keyRef, CSSM_ACL_AUTHORIZATION_DECRYPT, kSecCredentialTypeWithUI, &accessCred));
	check(CSSM_CSP_CreateAsymmetricContext(csp, encrAlg, accessCred, cssmKey, encrPad, &cc));

	CSSM_DATA dataBuf = { input_len, (byte*)input};
	CSSM_DATA result = { output_len, output };

	byte remainBuffer[1024];
	memset(remainBuffer, 0, sizeof(remainBuffer));
	memset(output, 0, output_len);
	CSSM_DATA remData = {sizeof(remainBuffer), remainBuffer};
	check(CSSM_DecryptData(cc, &dataBuf, 1, &result, 1, &output_len, &remData));
}

/* PKCS1 padding for signature */
static void pkcs_pad(const byte *input, ulong input_len, byte *output, ulong output_len) {
	int data_start = output_len - input_len;
	if(data_start < 11) /* Min 8-bytes of padding, w/ 3 bytes extra */
		throw P11Exception(CKR_DATA_LEN_RANGE);
	output[0] = 0;
	output[1] = 1;
	memset(&output[2], 0xFF, data_start - 3);
	output[data_start - 1] = 0;
	memcpy(&output[data_start], input, input_len);
}

static ck_rv_t pkcs_strip(const byte *input, ulong input_len, const byte **data_begin) {
	int i;
	if(input[0] != 0 || input[1] != 2)
		return CKR_ENCRYPTED_DATA_INVALID;
	for(i = 3; i < input_len; i++) {
		if(0 == input[i])
			goto found_end;
	}
	return CKR_ENCRYPTED_DATA_INVALID;
found_end:
	i++;
	*data_begin = &input[i];
	return CKR_OK;
}

ck_rv_t P11CryptoState::sign(const byte *input, ulong input_len, byte *output, ulong &output_len) {
	/* GET THE KEYCHAIN OBJECT */
	SecIdentityRef identityRef = getIdentityRef();
	ScopedCF<SecKeyRef> keyRef;
	OSStatus status = SecIdentityCopyPrivateKey(identityRef, &keyRef);
	if(noErr != status) /* TODO: Enhance error return */
		return CKR_FUNCTION_FAILED;
	if(!input)
		return CKR_ARGUMENTS_BAD;
	int key_size = getKeySize(keyRef);
	if(!output) {
		output_len = key_size;
		return CKR_OK;
	}
	if(output_len < key_size)
		return CKR_BUFFER_TOO_SMALL;
	byte dataToSign[key_size];
	switch(mechanism.mechanism) {
	case CKM_RSA_PKCS:
		pkcs_pad(input, input_len, dataToSign, key_size);
		break;
	case CKM_RSA_X_509:
		if(input_len != key_size)
			return CKR_SIGNATURE_LEN_RANGE;
		memcpy(dataToSign, input, key_size);
		break;
	default:
		/* Init must catch this case */
		return CKR_GENERAL_ERROR;
	}
	rawCrypt(keyRef, dataToSign, key_size, output, output_len);
	return CKR_OK;
}

ck_rv_t P11CryptoState::decrypt(const byte *input, ulong input_len, byte *output, ulong &output_len) {
	/* GET THE KEYCHAIN OBJECT */
	SecIdentityRef identityRef = getIdentityRef();
	ScopedCF<SecKeyRef> keyRef;
	OSStatus status = SecIdentityCopyPrivateKey(identityRef, &keyRef);
	if(noErr != status) /* TODO: Enhance error return */
		return CKR_FUNCTION_FAILED;
	if(!input)
		return CKR_ARGUMENTS_BAD;
	ulong key_size = getKeySize(keyRef);
	if(!output) { /* max size is keysize */
		output_len = key_size;
		return CKR_OK;
	}
	byte decryptedData[key_size];
	const byte *unpadded_data;
	rawCrypt(keyRef, input, input_len, decryptedData, key_size);
	switch(mechanism.mechanism) {
	case CKM_RSA_PKCS:
		{
			ck_rv_t ret = pkcs_strip(decryptedData, key_size, &unpadded_data);
			if(ret != CKR_OK)
				return ret;
		}
		break;
	case CKM_RSA_X_509:
		unpadded_data = decryptedData;
		break;
	default:
		/* Init must catch this case */
		return CKR_GENERAL_ERROR;
	}
	int unpadded_data_size = decryptedData + key_size - unpadded_data;
	if(!output) {
		output_len = unpadded_data_size;
		return CKR_OK;
	}
	if(output_len < unpadded_data_size) {
		output_len = unpadded_data_size;
		return CKR_BUFFER_TOO_SMALL;
	}
	output_len = unpadded_data_size;
	memcpy(output, unpadded_data, unpadded_data_size);
	return CKR_OK;
}

SecIdentityRef P11CryptoState::getIdentityRef() const {
	P11Identity_Ref identity = key->getIdentity().lock();
	if(!identity.get())
		throw P11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
	return identity->getIdentity();
}
