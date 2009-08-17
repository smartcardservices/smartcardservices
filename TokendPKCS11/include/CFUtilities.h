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

#ifndef CFUTILITIES_H
#define CFUTILITIES_H

#include <tr1/memory>

class CFDeleter {
public:
	void operator()(const void* ref) const { call(ref); }
	static void call(const void* ref);
};

/* Ref for any CF Type */
typedef std::tr1::shared_ptr<const void> CFTypeRef_Ref;

inline CFTypeRef_Ref wrapCFRef(const void* ref) {
	return CFTypeRef_Ref(ref, CFDeleter());
}

/** Wrapper class around CFTypeRefs that deletes the value on destruction */
template<typename T, typename D = CFDeleter>
class ScopedCF {
	NOCOPY(ScopedCF);
public:
	ScopedCF() : ref(NULL) {}
	ScopedCF(T ref) : ref(ref) {}
	~ScopedCF() {
		if(ref) D::call(ref);
	}
	/* Get's a pointer to ref - permits usage in functions that want a CF as input™ */
	T* operator &() { return &ref; }
	//operator T() { return ref; }
	T get() const { return ref; }
	template<typename X>
	operator X() const { return static_cast<X> (ref); }
	T release() {
		T ret = ref;
		ref = NULL;
		return ret;
	}
private:
	T ref;
};

#endif

