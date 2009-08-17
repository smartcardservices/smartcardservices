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

#ifndef ITERATOR_UTILITIES_H
#define ITERATOR_UTILITIES_H

template<typename T>
const T *dereference(const shared_ptr<T> &value) {
	return value->get();
}
template<typename T, typename T2>
const T *dereference_key(const std::pair<shared_ptr<T>, T2> &value) {
	return value.first->get();
}
template<typename T>
const typename T::first_type &get_key(const T &pair) {
	return pair.first;
}

template<typename T, typename TList, typename F>
class TransformCopier {
public:
	TransformCopier(F func) : func(func) {}
	void operator() (T *to, const TList &from) {
		transform(from.begin(), from.end(), to, func);
	}
private:
	F func;
};

template<typename T, typename TList>
class SimpleCopier {
public:
	void operator() (T *to, const TList &from) {
		copy(from.begin(), from.end(), to);
	}
};	

template<typename T, typename TList, typename CopyOp>
ck_rv_t generic_copy_checked(T *to, const TList &from, size_t &size, CopyOp copier) {
	if(!to) {
		size = from.size();
		return CKR_OK;
	}
	if(size < from.size()) {
		size = from.size();
		return CKR_BUFFER_TOO_SMALL;
	}
	size = from.size();
	copier(to, from);
	return CKR_OK;
}


template<typename T, typename TList, typename F>
ck_rv_t copy_transformed_list(T *to, const TList &from, size_t &size, F func) {
	return generic_copy_checked(to, from, size, TransformCopier<T,TList,F>(func));
}

template<typename T, typename TList>
ck_rv_t copy_list(T *to, const TList &from, size_t &size) {
	return generic_copy_checked(to, from, size, SimpleCopier<T,TList>());	
}

template<typename T, typename TList>
ck_rv_t copy_list_of_refs(T *to, const TList &from, size_t &size) {
	return copy_transformed_list(to, from, size, dereference<T>);
}
template<typename T, typename TMap>
ck_rv_t copy_list_of_key_refs(T *to, const TMap &from, size_t &size) {
	return copy_transformed_list(to, from, size, dereference_key<T, typename TMap::mapped_type>);
}

template<typename T, typename TMap>
ck_rv_t copy_list_of_keys(T *to, const TMap &from, size_t &size) {
	return copy_transformed_list(to, from, size, get_key<typename TMap::value_type>);
}

template<typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_if(InputIterator first, InputIterator last, OutputIterator result, Predicate pred) {
	for(; first != last; ++first) {
		if(pred(*first)) {
			*result = *first;
			++result;
		}
	}
	return result;
}

#endif
