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

template<typename T>
HandleManager<T>::HandleManager(int base /* = 0 */)
:values(), base(base) {
}

template<typename T>
void HandleManager<T>::refresh_active_reference(iterator iter) {
	int handle = iter - values.begin() + base;
	(*iter)->setHandle(handle);
}

template<typename T>
template<typename OutputIterator, typename Filter>
void HandleManager<T>::copy_handles(OutputIterator result, Filter filter) {
	for(int i = 0; i < values.size(); i++) {
		if(filter(values[i])) {
			*result = i + base;
			++result;
		}
	}
}


template<typename T>
template<typename Filter>
typename HandleManager<T>::iterator HandleManager<T>::add(ref_type ref, Filter notEmpty) {
	iterator iter = find_if(values.begin(), values.end(), not1(notEmpty));
	if(iter == values.end()) {
		values.push_back(ref);
		ref->setHandle(values.size() - 1 + base);
		return values.end() - 1;
	}
	*iter = ref;
	refresh_active_reference(iter);
	return iter;
}

/* Remove from the end everything until the last non 'filter-success' value or there's only size units left */
template<typename T>
template<typename Filter>
void HandleManager<T>::remove_after_last_match(size_t min_size, Filter filter) {
	if(values.size() <= min_size) return;
	reverse_iterator erase_begin = values.rbegin();
	reverse_iterator erase_end(values.begin() + min_size);
	erase_end = find_if(erase_begin, erase_end, filter);
	values.erase(erase_end.base(),erase_begin.base());
}

template<typename T>
bool HandleManager<T>::valid_handle(int handle) const {
	handle -= base;
	return handle < values.size() && handle >= 0 && handle != INVALID_HANDLE_VALUE;
}


template<typename T>
void HandleManager<T>::erase(const iterator &iter) {
	if(iter == end()) return;
	/* Reset handle to INVALID_HANDLE_VALUE in case anything's holding on */
	(*iter)->invalidate();
	(*iter).reset((T*)NULL);
	/* Cleanup is responsibility of client */
}

template<typename T>
void HandleManager<T>::kill_lockable_value(const iterator &iter) {
	if(iter == end()) return;
	/* C++ spec states that `sessionLock` will get collected before `saved_mutex` will at closeout, thus safety ensues */
	ref_type value = *iter;
	LockableHandledObject<T> &lockable = *value;
	StLock<UserMutex> valueLock(lockable.getLock().writeMutex()); /* VALIDATED */
	/* Pull out the lock for safety */
	auto_ptr<UserMutex> saved_mutex(lockable.releaseLock());
	erase(iter);
	/* Force early unlock before the mutex is destroyed */
	valueLock.unlock();
}

