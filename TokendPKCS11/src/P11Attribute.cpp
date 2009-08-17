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

#include "P11Attribute.h"
#include "Utilities.h"

P11Attribute::P11Attribute(ck_attribute_type_t type, const void *data, size_t data_len) {
	init(type, data, data_len);
}

P11Attribute::P11Attribute(const struct ck_attribute &attr) {
	init(attr.type, attr.value, attr.value_len);
}

P11Attribute::~P11Attribute() {
	if(value)
		free(value);
}

void P11Attribute::init(ck_attribute_type_t type, const void *data, size_t data_len) {
	this->type = type;
	this->value_len = data_len;
	this->value = malloc(data_len);
	if(!this->value)
		throw P11Exception(CKR_HOST_MEMORY);
	memcpy(this->value, data, data_len);
}

bool P11Attribute::getBool() const {
	return 0 != getLong();
}

long P11Attribute::getLong() const {
	/* Try to be accomodating to diff sizes.. */
	switch(value_len) {
#if LONG_MAX != INT_MAX
	case sizeof(long):
		return *(long*)(value);
#endif
	case sizeof(int):
		return *(int*)(value);
	case sizeof(short):
		return *(short*)(value);
	case sizeof(char):
		return *(char*)(value);
	default:
		throw P11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
	}
}

bool P11Attribute::operator ==(const P11Attribute &comparand) const {
	return type == comparand.type
		&& value_len == comparand.value_len
		&& (value && comparand.value)
		&& 0 == memcmp(value, comparand.value, value_len);
}

P11Attributes::P11Attributes() : attributes() {
}

P11Attributes::P11Attributes(struct ck_attribute *attrs, ulong count) : attributes() {
	for(int i = 0; i < count; i++) {
		attributes[attrs[i].type] = P11Attribute_Ref(new P11Attribute(attrs[i]));
	}
}

void P11Attributes::add(ck_attribute_type_t type, const void *data, size_t data_len) {
	P11Attribute_Ref attr(new P11Attribute(type, data, data_len));
	attributes.insert(P11AttributeMap::value_type(type, attr));
}

ck_object_class_t P11Attributes::oclass() const {
	P11AttributeMap::const_iterator iter = attributes.find(CKA_CLASS);
	if(iter == attributes.end())
		return CKO_VENDOR_DEFINED; /* Should we err out? */
	return iter->second->getLong();
}

ck_rv_t P11Attributes::get(struct ck_attribute *attrs, ulong count) const {
	ck_rv_t ret = CKR_OK;
	/* FIRST: Check for permissions -- not so applicable here...
	 * SECOND: Check for all values existing
	 * THIRD: Check that there's enough space to hold the individual value
	 * -NOTE-: Even if there is such an error, do not return immediately, process all values
	 * Multiple errors lead to undefined error returned
	 */
	for(;count > 0; count--, attrs++) {
		const P11AttributeMap::const_iterator iter = attributes.find(attrs->type);
		/* NOOP: Permission check */
		if(iter == attributes.end()) {
			attrs->value_len = -1;
			ret = CKR_ATTRIBUTE_TYPE_INVALID;
		} else if(!attrs->value) {
			attrs->value_len = iter->second->value_len;
		} else if(attrs->value_len < iter->second->value_len) {
			attrs->value_len = -1;
			ret = CKR_BUFFER_TOO_SMALL;
		} else {
			attrs->value_len = iter->second->value_len;
			if(attrs->value)
				memcpy(attrs->value, iter->second->value, attrs->value_len);
		}
	}
	return ret;
}

/* Return true if this attribute object matches each element in search */
bool P11Attributes::match(const P11Attributes &search) const {
	P11AttributeMap::const_iterator iter, endIter = search.attributes.end();
	for(iter = search.attributes.begin(); iter != endIter; ++iter) {
		const P11AttributeMap::const_iterator matchIter = attributes.find(iter->first);
		/* Attribute missing */
		if(matchIter == attributes.end()) return false;
		if(!(*matchIter->second == *iter->second)) return false;
	}
	return true;
}
