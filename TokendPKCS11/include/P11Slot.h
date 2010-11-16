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

#ifndef P11SLOT_H
#define P11SLOT_H

#include "pkcs11.h"

#include "P11Object.h"
#include "P11Mutexes.h"
#include "HandleManager.h"
#include "P11Identity.h"

#include "CFUtilities.h"

class P11Mechanism;
typedef shared_ptr<P11Mechanism> P11Mechanism_Ref;

/**
 * Utility PKCS11 class to convey cryptographic mechanism information
 */
class P11Mechanism {
	NOCOPY(P11Mechanism);
public:
	/** Construct the P11Mechanism object with given mechanism and info */
	P11Mechanism(const struct ck_mechanism &mech, const struct ck_mechanism_info &info);

	/** Return the mechanism's type */
	ck_mechanism_type_t getType() const { return mechanismType; }
	/** Accessor to the mechanism parameter */
	const vector<byte> &getParameter() const { return parameter; }
	/** Accessor to the mechanism information */
	const struct ck_mechanism_info &getInfo() { return info; }

protected:
	ck_mechanism_type_t mechanismType;
	vector<byte> parameter;
	struct ck_mechanism_info info;
};
typedef map<ck_mechanism_type_t,P11Mechanism_Ref> P11MechanismMap;

class P11Slot;
typedef shared_ptr<P11Slot> P11Slot_Ref;
typedef weak_ptr<P11Slot> P11Slot_WeakRef;

/**
 * P11 Slot interface
 */
class P11Slot : public LockableHandledObject<P11Slot> {
	NOCOPY(P11Slot);
private:
	/** Permit P11SlotCreator to manage slot creation */
	friend class P11SlotCreator;
	/* Create a dummy empty slot */
	P11Slot();
	/* Create an active slot */
	P11Slot(SecKeychainRef keychain);
public:
	/** Accessor to the slot's handle */
	ck_slot_id_t getSlotID() const {
		return getHandle();
	}

	/** Load slot information into ck_slot_info */
	void getInformation(struct ck_slot_info &info);
	/**
	 * Load token information
	 * @param info Structure to load data into
	 * @param active_count Number of active slot uses to supply
	 */
	void getTokenInformation(struct ck_token_info &info, int active_count);

	/** Obtain mechanism information of a given type */
	P11Mechanism_Ref getMechanism(ck_mechanism_type_t type);

	/** Log into the slot with the given pin
	 * @param user_type User type to login as, ignored since only 'user-login' is permitted
	 * @param pin PIN to use, if NULL, use 'Token Specific Login' aka Keychain login
	 * @param pin_len Length of the PIN to use
	 */
	ck_rv_t login(ck_user_type_t userType, const byte *pin, ulong pin_len);
	/** Log out of the slot */
	ck_rv_t logout();

	/** Check the login status of the user */
	bool isLoggedIn() const;
	/** Check if the token is present */
	bool isPresent() const;

	/** Get a reference to the contained slot objects */
	P11Objects &getObjects() { return *objects; }

	/** Check if the slot is still present, throw if not */
	void assertPresent() const;
protected:
	/** Loads the included mechanisms as objects into the object container */
	void loadMechanisms();
	/** Loads the associated public/private keys and certificates into the object container */
	void loadKeypairs();

	/** Reference to the keychain used */
	ScopedCF<SecKeychainRef> keychain;

	/** Reference to the slot's object manager */
	P11Objects_Ref objects;
	/** Reference to the slot's identity manager */
	P11Identities identityValues;
	/** Map of available mechanisms
	 * Note the mechanism availability management is partly spread out due to implementation
	 * challenges.
	 */
	P11MechanismMap mechanisms;
public:
	/** Accessor to available mechanism map */
	const P11MechanismMap &getMechanisms() const {
		assertPresent();
		return mechanisms;
	}
};


class P11SlotCreator {
public:
	/** Allow ApplySlotChanges and P11Slots to create/destory slots */
	friend class ApplySlotChanges;
	friend class P11Slots;
private:
	static P11Slot_Ref DummySlot() {
		return P11Slot_Ref(new P11Slot);
	}
	static P11Slot_Ref ActiveSlot(SecKeychainRef keychain) {
		return P11Slot_Ref(new P11Slot(keychain));
	}
};

#endif
