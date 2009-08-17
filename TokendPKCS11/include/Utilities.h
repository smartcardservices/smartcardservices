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

#ifndef UTILITIES_H
#define UTILITIES_H

/* Mark a class as non-copyable, compile-error will occur on copy-attept */
#ifndef NOCOPY
#define NOCOPY(Type)    private: Type(const Type &); void operator = (const Type &);
#endif

/**
 * PKCS#11 Exception class which propogates a PKCS#11 ck_rv_t to the
 * calling application on loop-exit
 */
class P11Exception {
public:
	P11Exception(ck_rv_t ret) : ret(ret) {}

	const ck_rv_t ret;
};

/**
 * Wrapper class around a lockable object
 * - by default, this is a read lock
 * - a write-lock is accessible
 * NOTE: Some implementations may use a basic mutex
 * in which case read-lock == write-lock
 */
class UserMutex {
	NOCOPY(UserMutex);
public:
	UserMutex() {}
	virtual ~UserMutex() {}
	virtual void lock() = 0;
	virtual void unlock() = 0;
	virtual UserMutex &writeMutex() = 0;
};

/* Handles obtaining the necessary persistent lock for object handling */
template<typename ContainerType>
class LockedContainedObject {
	NOCOPY(LockedContainedObject);
private:
	typedef typename ContainerType::handle_type handle_type;
	typedef typename ContainerType::ref_type ref_type;
	typedef ContainerType container_type;
public:
	/**
	 * Obtains a LockedContainedObject from a container
	 * Obtains a reader lock on the container, then the given lock on the object itself
	 *
	 * @param container Container to pull the object from
	 * @param handle Handle identifier of the object to retreive
	 * @param readWrite Whether to obtain a read/write lock on the object itself
 	 * @throw P11Exception if the object doesn't exist at retreival-time
	 */
	LockedContainedObject(const container_type &container, handle_type handle, bool readWrite = false)
	:containerLock(container.getLock()),refLock(NULL),ref() {
		ref = container.handleToValue(handle);
		refLock.reset(new StLock<UserMutex>(readWrite ? ref->getLock().writeMutex() : ref->getLock())); /* VALIDATED */
	}
	virtual ~LockedContainedObject() {}
	/** Returns the contained reference to the locked object */
	const ref_type &get() const {
		return ref;
	}
private:
	StLock<UserMutex> containerLock; /* VALIDATED */
	/* Since the session mutex will only be revealed after construction */
	auto_ptr<StLock<UserMutex> > refLock;
	ref_type ref;
};

/** Template class for a generic create-only factory (object should be 'deleted') */
template<typename T>
class Factory {
public:
	virtual ~Factory() {}
	virtual T *create() = 0;
};

/** Writes out a space-padded string to the destination
 * Up to `size` bytes from `from` are copied to `to` and then padded with spaces up to `size`
 *
 * @param to Output byte buffer of 'size' bytes
 * @param from Null-terminated string that 'should' be less than 'size' bytes
 * @param size Size of the output buffer
 */
void pad_string_set(byte *to, const char *from, size_t size);

#endif
