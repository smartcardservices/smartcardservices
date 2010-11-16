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

#ifndef P11OBJECT_H
#define P11OBJECT_H

#include "Utilities.h"
#include "P11Mutexes.h"
#include "P11Attribute.h"

#include "HandleManager.h"

class P11Identity;
typedef weak_ptr<P11Identity> P11Identity_WeakRef;


class P11Objects;
typedef shared_ptr<P11Objects> P11Objects_Ref;
typedef weak_ptr<P11Objects> P11Objects_WeakRef;

/* A PKCS #11 object (session or on-card) */
class P11Object : public LockableHandledObject<P11Object> {
	NOCOPY(P11Object);
private:
	friend class P11ObjectCreator;
	P11Object(P11Objects_WeakRef parent, ck_object_class_t objectClass, const P11Attributes &attrTemplate);
public:
	virtual ~P11Object();

	void setIdentity(P11Identity_WeakRef identity) { this->identity = identity; }

	/* Shortcut attribute */
	ck_object_class_t oclass() const;

	const P11Attributes &getAttributes() const;

	ck_object_handle_t getHandle() const {
		return HandledObject<P11Object>::getHandle();
	}

	P11Objects_WeakRef getParent() const { return parent; }
	/* Return the associated identity if it exists */
	P11Identity_WeakRef getIdentity() const { return identity; }
protected:
	auto_ptr<P11Attributes> attributes;
	P11Objects_WeakRef parent;
	P11Identity_WeakRef identity;
};

typedef shared_ptr<P11Object> P11Object_Ref;
typedef weak_ptr<P11Object> P11Object_WeakRef;
typedef std::vector<ck_object_handle_t> P11ObjectHandleList;

class P11ObjectCreator {
private:
	friend class P11Identity;
	friend class P11Objects;
	static P11Object_Ref create(P11Objects_WeakRef parent, ck_object_class_t objectClass, const P11Attributes &attributes) {
		return P11Object_Ref(new P11Object(parent, objectClass, attributes));
	}
};

class P11Objects;
typedef shared_ptr<P11Objects> P11Objects_Ref;
typedef weak_ptr<P11Objects> P11Objects_WeakRef;

class P11Objects {
	NOCOPY(P11Objects);
public:
	P11Objects(int handle_base = 0);
	P11Objects(bool read_only, ck_rv_t read_only_error, int handle_base = 0);

	static P11Object_Ref addNew(P11Objects_Ref container, ck_object_class_t objectClass, const P11Attributes &attributes);

	void search(const P11Attributes &search, P11ObjectHandleList &output);

	P11Object_Ref getObject(ck_object_handle_t handle);
	bool destroyObject(ck_object_handle_t handle);
private:
	int refresh();

	typedef HandleManager<P11Object> ObjectManager;
	ObjectManager objects;
	bool read_only;
	ck_rv_t read_only_error;

	mutable auto_ptr<UserMutex> lock;
protected:
	/* Locked object support */
	typedef P11Object_Ref ref_type;
	typedef ck_object_handle_t handle_type;
	
	friend class LockedContainedObject<P11Objects>;
	ref_type handleToValue(handle_type handle) const;
public:	
	UserMutex &getLock() const { return *lock; }
};

class LockedSession;

/* Handles obtaining the necessary persistent lock for session handling */
class LockedObject : public LockedContainedObject<P11Objects> {
public:
	LockedObject(const P11Objects &container, ck_object_handle_t handle, bool readWrite = false)
	:LockedContainedObject<P11Objects>(container, handle, readWrite) {}
	/* Since Objects can be in two places, a utility function to get ahold of a locked version exists.. */
	static LockedObject *get_locked_object(const LockedSession &session, ck_object_handle_t handle, bool readWrite = false);
};


#endif
