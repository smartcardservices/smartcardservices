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
#include "P11Slot.h"
#include "CFUtilities.h"
#include <Security/Security.h>

#include "config.h"

P11Mechanism::P11Mechanism(const struct ck_mechanism &mech, const struct ck_mechanism_info &info)
: mechanismType(mech.mechanism), parameter(0), info(info) {
	if(mech.parameter_len > 0)
		parameter.assign((byte*)mech.parameter, (byte*)mech.parameter + mech.parameter_len);
}

P11Slot::P11Slot()
:LockableHandledObject<P11Slot>(globalState().newMutex()),
	keychain(NULL), objects(new P11Objects(true, CKR_TOKEN_WRITE_PROTECTED)),
	identityValues(), mechanisms() {
}

P11Slot::P11Slot(SecKeychainRef keychain)
:LockableHandledObject<P11Slot>(globalState().newMutex()),
	keychain(keychain), objects(new P11Objects(true, CKR_TOKEN_WRITE_PROTECTED)),
	identityValues(), mechanisms() {
	CFRetain(keychain);

	/* Add mechanism objects */
	loadMechanisms();
	loadKeypairs();
}

void P11Slot::getInformation(struct ck_slot_info &info) {
	memset(&info, 0, sizeof(info));
	pad_string_set(info.slot_description, PKCS11_SLOT_DESCRIPTION, sizeof(info.slot_description));
	pad_string_set(info.manufacturer_id, PKCS11_MANUFACTURER, sizeof(info.manufacturer_id));
	info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	if(isPresent()) {
		info.flags |= CKF_TOKEN_PRESENT;
	}
}

void P11Slot::getTokenInformation(struct ck_token_info &info, int active_count) {
	assertPresent();
	memset(&info, 0, sizeof(info));
	char pathName[PATH_MAX];
	UInt32 ioPathLength = sizeof(pathName) - 1;
	if (noErr != SecKeychainGetPath(keychain, &ioPathLength, pathName))
		pad_string_set(info.label, "unknown", sizeof(info.label));// XXX
	else {
		pathName[ioPathLength] = 0;
		pad_string_set(info.label, pathName, sizeof(info.label));
	}
	pad_string_set(info.manufacturer_id, "unknown", sizeof(info.manufacturer_id));
	pad_string_set(info.model, "unknown", sizeof(info.model));
	pad_string_set(info.serial_number, "0", sizeof(info.serial_number));

	info.flags =
		CKF_WRITE_PROTECTED /* No personalization, so no write ops can be permitted */
		| CKF_TOKEN_INITIALIZED; /* No personalization permitted, assume token initialized */
#ifdef USE_PROTECTED_PATH
	info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH; /* To allow for keychain prompts rather than require UI from PKCS11 app */
#endif
#if defined(USE_PROTECTED_PATH) || defined(USE_PIN_AUTH)
		/* Tokend will perform it's own auth... this is to help protect against problems such as
		 * Firefox 3's CKF_PROTECTED_AUTHENTICATION_PATH problem while
		 * providing the best usability... note that
		 * all pkcs11 clients must have console access for this to work... */
	info.flags |= CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED; /* Login is required for certain ops (crypto) .... */
#endif
	info.max_session_count = CK_EFFECTIVELY_INFINITE;
	info.max_rw_session_count = 0;
	info.rw_session_count = 0;
	info.total_public_memory = CK_UNAVAILABLE_INFORMATION;
	info.total_private_memory = CK_UNAVAILABLE_INFORMATION;
	info.free_public_memory = CK_UNAVAILABLE_INFORMATION;
	info.free_private_memory = CK_UNAVAILABLE_INFORMATION;

	info.session_count = active_count;
}

P11Mechanism_Ref P11Slot::getMechanism(ck_mechanism_type_t mech) {
	P11MechanismMap::const_iterator iter = mechanisms.find(mech);
	if(iter == mechanisms.end())
		throw P11Exception(CKR_MECHANISM_INVALID);
	return iter->second;
}

ck_rv_t P11Slot::login(ck_user_type_t user_type, const byte *pin, ulong pin_len) {
	assertPresent();
	/* To handle keychain auth using popup, no pin passed */
	OSStatus status = SecKeychainUnlock(keychain, pin_len, pin, pin != NULL); /* Use password options? */
	switch(status) {
	case noErr:
		return CKR_OK;
	default:
		return CKR_PIN_INCORRECT;
	}
}

ck_rv_t P11Slot::logout() {
	assertPresent();
	SecKeychainLock(keychain);
	return CKR_OK;
}

bool P11Slot::isLoggedIn() const {
	assertPresent();
#ifdef USE_ALWAYS_AUTH_SESSION
	return true;
#else
	SecKeychainStatus status;
	OSStatus ret = SecKeychainGetStatus(keychain, &status);
	return ret == noErr && status & kSecUnlockStateStatus;
#endif
}

void P11Slot::assertPresent() const {
	if(!isPresent())
		throw P11Exception(CKR_TOKEN_NOT_PRESENT);
}

bool P11Slot::isPresent() const {
	/* Useful for tracking down a slot removed during usage */
	if(!keychain.get())
		return false;
	SecKeychainStatus status;
	OSStatus ret = SecKeychainGetStatus(keychain, &status);
	/* Should we return ok if no error? */
	return ret == noErr;
}

void P11Slot::loadMechanisms() {
	ck_mechanism_type_t mechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
	struct ck_mechanism mechData = { 0, NULL, 0 };
	/* Same support for each */
	struct ck_mechanism_info mechInfo = {
		1024,
		4096, /* Current max == 4096 .... */
		CKF_HW | CKF_DECRYPT | CKF_SIGN /* | CKF_UNWRAP */
	};
	int idx;
	for(idx = 0; idx < sizeof(mechs) / sizeof(mechs[0]); idx++) {
		mechData.mechanism = mechs[idx];
		P11Mechanism_Ref mech(new P11Mechanism(mechData, mechInfo));
		mechanisms.insert(P11MechanismMap::value_type(mechData.mechanism, mech));
	}
	/* Add objects */
	P11Attributes mechAttributes;
	mechAttributes.add(CKA_MECHANISM_TYPE, mechs, sizeof(mechs));
	P11Objects::addNew(objects, CKO_MECHANISM, mechAttributes);
}

void P11Slot::loadKeypairs() {
	ScopedCF<SecIdentitySearchRef> searchRef;
	OSStatus status = SecIdentitySearchCreate(keychain, NULL, &searchRef);
	if(status != noErr)
		throw P11Exception(CKR_GENERAL_ERROR);
	while(true) {
		SecIdentityRef itemRef = NULL;
		status = SecIdentitySearchCopyNext(searchRef, &itemRef);
		if(status || !itemRef) break;
		identityValues.createIdentity(objects, itemRef);
	}
}
