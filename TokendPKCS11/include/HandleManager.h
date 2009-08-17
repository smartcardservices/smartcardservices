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

#ifndef HANDLE_MANAGER_H
#define HANDLE_MANAGER_H

template<typename T>
class HandleManager;

static const int INVALID_HANDLE_VALUE = -1;

template<typename T>
class HandledObject {
	NOCOPY(HandledObject);
public:
	HandledObject() : handle(INVALID_HANDLE_VALUE) {}
	virtual ~HandledObject() {}
	int getHandle() const {
		return handle;
	}
	bool isValid() const {
		return handle != INVALID_HANDLE_VALUE;
	}
protected:
	void invalidate() {
		this->handle = INVALID_HANDLE_VALUE;
	}

private:
	friend class HandleManager<T>;
	void setHandle(int handle) {
		this->handle = handle;
	}
	int handle;
};

template<typename T>
class LockableHandledObject : public HandledObject<T> {
	NOCOPY(LockableHandledObject);
public:
	LockableHandledObject(UserMutex *mutex) : mutex(mutex) {}

	UserMutex &getLock() const { return *mutex; }
protected:
	friend class HandleManager<T>;
	UserMutex *releaseLock() { return mutex.release(); }
private:
	mutable auto_ptr<UserMutex> mutex;
};
template<typename RefType>
class Filter {
public:
	virtual ~Filter() {}
	typedef const RefType argument_type;
	typedef bool return_type; /* If return true, keep value */
};

template<typename RefType>
class FilterKeepAll : public Filter<RefType> {
public:
	bool operator() (const RefType &value) const {
		return true;
	}
};

template<typename RefType>
class FilterKeepValid : public Filter<RefType> {
public:
	bool operator() (const RefType &value) const {
		return value.get() && value->isValid();
	}
};

/**
 * Class to handle (zero or custom)-based object-handles in a unified way
 */
template<typename T>
class HandleManager {
	NOCOPY(HandleManager);
public:
	typedef shared_ptr<T> ref_type;
	typedef std::vector<ref_type> value_collection;
	typedef HandledObject<T> handled_type;
	value_collection values;

	typedef typename value_collection::reverse_iterator reverse_iterator;
	typedef typename value_collection::iterator iterator;
	typedef typename value_collection::const_iterator const_iterator;
public:
	/**
	 * Initialize the HandleManager with a given base reference
	 * @param base Value to add to handles returned (for handlespace unification)
	 */
	HandleManager(int base = 0);

	/**
	 * Add a new reference value to the handle manager into an empty slot
	 * @param ref New value to add
	 * @param notEmpty Filter that returns success on a non-empty slot (negated during search)
	 */
	template<typename Filter>
	iterator add(ref_type ref, Filter notEmpty);

	/**
	 * Replace a given iterator's value, updating the new value's handle ref
	 * @param iter Location to update
	 * @param ref New value (which has it's location updated
	 */
	void replace_value(iterator iter, ref_type ref) {
		*iter = ref;
		refresh_active_reference(iter);
	}

	/**
	 * Copy out the handles that pass the given filter.
	 * Example use: dumping out available P11Object handles
	 *
	 * @param result Output iterator to dump the results
	 * @param filter The filter that must 'pass'
	 */
	template<typename OutputIterator, typename Filter>
	void copy_handles(OutputIterator result, Filter filter);

	/**
	 * Remove from the end everything until the last non 'filter-success' value or there's only size units left
	 *
	 * @param min_size Size at which to stop removing values
	 * @param filter Filter to use in determining whether a value should be a candidate for removal
	 */
	template<typename Filter>
	void remove_after_last_match(size_t min_size, Filter filter);

	/**
	 * Returns whether `handle` is a valid handle for this pool or not
	 */
	bool valid_handle(int handle) const;

	/**
	 * Find the given `handle` and return it or the `end` marker
	 */
	iterator find(int handle) {
		return !valid_handle(handle) ? values.end() : values.begin() + (handle - base);
	}
	/**
	 * Find the given `handle` and return it or the `end` marker
	 */
	const_iterator find(int handle) const {
		return !valid_handle(handle) ? values.end() : values.begin() + (handle - base);
	}
	/**
	 * Invalidate and release the reference at the given reference location
	 */
	void erase(const iterator &iter);

	/**
	 * Get a lock and 'erase' the value
	 */
	void kill_lockable_value(const iterator &iter);

	/**
	 * Return an iterator pointing to the beginning of the object collection.
	 * Facilitates manual searching through object values.
	 */
	iterator begin() {
		return values.begin();
	}

	/**
	 * Returns an iterator pointing just beyond the end of the object collection.
	 */
	iterator end() {
		return values.end();
	}

	/**
	 * Returns an iterator pointing just beyond the end of the object collection.
	 */
	const_iterator end() const {
		return values.end();
	}
private:
	/**
	 * Refereshes the handle for a given value reference.
	 * Calculates the correct handle value and assigns it to the contained value.
	 *
	 * @param iter Value reference to alter
	 */
	void refresh_active_reference(iterator iter);
	
	const int base;
};

#include "HandleManager.inc"

#endif
