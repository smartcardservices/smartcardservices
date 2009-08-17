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

#ifndef P11IDENTITY_H
#define P11IDENTITY_H

#include "P11Object.h"
#include "HandleManager.h"

class P11Identity;
typedef shared_ptr<P11Identity> P11Identity_Ref;

/* Represents a set of Private, Public, Cert */
class P11Identity : public HandledObject<P11Identity> {
	NOCOPY(P11Identity);
public:
	virtual ~P11Identity();
	
	SecIdentityRef getIdentity() { return identity; }
protected:
	friend class P11Identities;
	P11Identity(SecIdentityRef identity);

private:
	bool createObjects(P11Objects_Ref objectContainer, P11Identity_Ref &identity_reference);
	/* Weak references since P11Objects is the lifetime maintainer */
	P11Object_WeakRef privateKey;
	P11Object_WeakRef publicKey;
	P11Object_WeakRef certificate;

	SecIdentityRef identity;
};

class P11Identities {
	NOCOPY(P11Identities);
public:
	P11Identities();
	void createIdentity(P11Objects_Ref objectContainer, SecIdentityRef identity);
private:
	typedef HandleManager<P11Identity> IdentityManager;
	IdentityManager identities;
};

#endif

