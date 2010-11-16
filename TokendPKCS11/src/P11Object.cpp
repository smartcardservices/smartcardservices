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

#include "P11Object.h"
//#include "P11Slot.h"
#include "P11State.h"

P11Object::P11Object(P11Objects_WeakRef parent, ck_object_class_t objectClass, const P11Attributes &attributes)
:LockableHandledObject<P11Object>(globalState().newMutex()),
	attributes(new P11Attributes(attributes)), parent(parent) {
	this->attributes->addLong(CKA_CLASS, objectClass);
}
P11Object::~P11Object() {
}

ck_object_class_t P11Object::oclass() const {
	return getAttributes().oclass();
}

const P11Attributes &P11Object::getAttributes() const {
	/* Prepare attributes if not setup yet */
	return *attributes;
}

P11Objects::P11Objects(int handle_base /* = 0 */)
:objects(handle_base), read_only(false), read_only_error(CKR_OK), lock(globalState().newMutex()) {
}

P11Objects::P11Objects(bool read_only, ck_rv_t read_only_error, int handle_base /* = 0 */)
:objects(handle_base), read_only(read_only), read_only_error(read_only_error), lock(globalState().newMutex()) {
}

P11Object_Ref P11Objects::addNew(P11Objects_Ref container, ck_object_class_t objectClass, const P11Attributes &attributes) {
	P11Object_Ref ref = P11ObjectCreator::create(container, objectClass, attributes);
	container->objects.add(ref, FilterKeepValid<P11Object_Ref>());
	return ref;
}

P11Object_Ref P11Objects::handleToValue(ck_object_handle_t handle) const {
	ObjectManager::const_iterator iter = objects.find(handle);
	if(iter == objects.end() || !iter->get())
		throw P11Exception(CKR_OBJECT_HANDLE_INVALID);
	return *iter;
}

bool P11Objects::destroyObject(ck_object_handle_t handle) {
	if(read_only)
		throw P11Exception(read_only_error);
	ObjectManager::iterator iter = objects.find(handle);
	if(iter != objects.end() && (*iter)->isValid()) {
		objects.kill_lockable_value(iter);
		return true;
	}
	return false;
}

/* Protected attribute types
 CKO_MECHANISM
 CKO_HW_FEATURE
 */

class P11AttributeLoader {
public:
	P11AttributeLoader(const P11Attributes &search, P11ObjectHandleList &output) : search(search), output(output) {
		returnRestrictedObject = search.oclass() == CKO_MECHANISM || search.oclass() == CKO_HW_FEATURE;
	}
	void operator () (const P11Object_Ref &ref) {
		/* Double check that the object exists in the case of a deleted one */
		if(!ref.get() || !ref->isValid()) return;
		/* Check that the object's attributes match the search pattern */
		if(!ref->getAttributes().match(search)) return;

		/* Gotcha in the spec, if CKA_CLASS does not contain CKO_MECHANISM or CKO_HW_FEATURE
		 * explicitly do not include CKO_MECHANISM or CKO_HW_FEATURE objects
		 */
		if(!returnRestrictedObject && (ref->oclass() == CKO_MECHANISM || ref->oclass() == CKO_HW_FEATURE))
			return;
		output.push_back(ref->getHandle());
	}
private:
	const P11Attributes &search;
	P11ObjectHandleList &output;
	bool returnRestrictedObject;
};

void P11Objects::search(const P11Attributes &search, P11ObjectHandleList &output) {
	for_each(objects.begin(), objects.end(), P11AttributeLoader(search, output));
}

/* Since Objects can be in two places, a utility function to get ahold of a locked version exists.. */
LockedObject *LockedObject::get_locked_object(const LockedSession &session, ck_object_handle_t handle, bool readWrite /* = false */) {
	P11Session_Ref sessionRef = session.get();
	auto_ptr<LockedObject> obj;
	try {
		obj.reset(new LockedObject(sessionRef->getObjects(), handle));
	} catch(P11Exception &e) {
		if(e.ret != CKR_OBJECT_HANDLE_INVALID)
			throw e;
	}
	if(!obj.get()) {
		/* Lock the slot and get the object */
		LockedSlot lockedSlot(sessionRef->getSlotID(), false);
		obj.reset(new LockedObject(lockedSlot.get()->getObjects(), handle));
	}
	if(!obj.get())
		throw P11Exception(CKR_OBJECT_HANDLE_INVALID);
	return obj.release();
}
