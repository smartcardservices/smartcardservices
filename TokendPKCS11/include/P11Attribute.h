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

#ifndef P11ATTRIBUTE_H
#define P11ATTRIBUTE_H


/**
 * PKCS#11 Attribute wrapper object
 */
class P11Attribute : public ck_attribute {
	NOCOPY(P11Attribute);
public:
	/** Construct an attribute from the given type and data */
	P11Attribute(ck_attribute_type_t type, const void *data, size_t data_len);

	/**
	 * Initializes the attribute with a PKCS#11 spec attribute
	 */
	P11Attribute(const struct ck_attribute &ckattr);
	/** Releases the internally held 'value' ptr */
	~P11Attribute();

	/**
	 * Returns boolean value of attribute
	 * @pre Attribute must be an integer size (1,2,4,8 on 64-bit)
	 */
	bool getBool() const;
	/**
	 * Returns native integer value of attribute
	 * @pre Attribute must be an integer size (1,2,4,8 on 64-bit)
	 */
	long getLong() const;

	/** Compare two P11Attributes for equality in type and value */
	bool operator ==(const P11Attribute& comparand) const;
private:
	/** Initializes the object with the given type and data */
	void init(ck_attribute_type_t type, const void *data, size_t data_len);
};

typedef shared_ptr<P11Attribute> P11Attribute_Ref;
typedef map<ck_attribute_type_t,P11Attribute_Ref> P11AttributeMap;

/**
 * Object attribute container, used for both searches and data retreival
 */
class P11Attributes {
public:
	/** Construct an empty attribute container */
	P11Attributes();
	/** Construct an attribute container pre-populated with values */
	P11Attributes(struct ck_attribute *templates, ulong count);

	/** Obtain the CKA_CLASS value in ck_object_class_t form */
	ck_object_class_t oclass() const;

	/**
	 * Adds a long integer attribute (native byte-order)
	 * @param type Type of attribute
	 * @param value Value of attribute
	 */
	void addLong(ck_attribute_type_t type, long value) {
		add(type, &value, sizeof(value));
	}
	/**
	 * Adds a boolean attribute
	 * @param type Type of attribute
	 * @param value Value of attribute
	 */
	void addBool(ck_attribute_type_t type, bool value) {
		unsigned char bool_char = value ? 1 : 0;
		add(type, &bool_char, sizeof(bool_char));
	}
	/**
	 * Adds a single-byte attribute
	 * @param type Type of attribute
	 * @param value Value of attribute
	 */
	void addByte(ck_attribute_type_t type, byte value) {
		add(type, &value, sizeof(value));
	}
	/**
	 * Adds an arbitrary attribute
	 * @param type Type of attribute
	 * @param data Attribute value
	 * @param data_len Length of attribute
	 */
	void add(ck_attribute_type_t type, const void *data, size_t data_len);
	/**
	 * Pull attributes out in PKCS#11 form
	 * @param templates In/Out array of attributes to populate
	 * @param count Number of attributes
	 * @return CKR_* compliant with PKCS#11 specification for C_GetAttributeValue
	 */
	ck_rv_t get(struct ck_attribute *templates, ulong count) const;

	/**
	 * Return whether this attribute collection contains at least each search element
	 * @param search The attribute collection to match against
	 */
	bool match(const P11Attributes &search) const;
private:
	P11AttributeMap attributes;
};

#endif
