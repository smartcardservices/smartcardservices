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

#ifndef P11CRYPTOSTATE_H
#define P11CRYPTOSTATE_H

#include "P11Object.h"

class P11CryptoState {
public:
	/** Construct a crypto state w/ a given key and mechanism
	 * If they are incompatible/invalid, throw an exception
	 */
	P11CryptoState(P11Object_Ref key, const struct ck_mechanism &mechanism);
	virtual ~P11CryptoState();

	/** Perform decryption using the given key and mechanism
	 * May cause authentication prompts
	 */
	ck_rv_t decrypt(const byte *input, ulong input_len, byte *output, ulong &output_len);
	/** Perform signature using the given key and mechanism
	 * May cause authentication prompts
	 * XXX: Currently uses raw decryption, should use actual signature algorithms
	 */
	ck_rv_t sign(const byte *input, ulong input_len, byte *output, ulong &output_len);

private:
	P11Object_Ref key;
	struct ck_mechanism mechanism;

	SecIdentityRef getIdentityRef() const;
};


#endif
