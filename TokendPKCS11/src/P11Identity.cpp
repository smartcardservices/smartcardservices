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

#include "P11Identity.h"
#include "CFUtilities.h"
#include <Security/Security.h>

#include "TLV.h"

#include "config-objects.h"

P11Identity::P11Identity(SecIdentityRef identity)
: identity(identity), privateKey(), publicKey(), certificate() {
	CFRetain(identity);
}

P11Identity::~P11Identity() {
	CFRelease(identity);
}


typedef struct bool_attr {
	ck_attribute_type_t type;
	byte value;
} bool_attr;
typedef struct long_attr {
	ck_attribute_type_t type;
	long value;
} long_attr;
typedef struct raw_attr {
	ck_attribute_type_t type;
	const void *value;
	ulong size;
} raw_attr;

static void check(OSStatus status, ck_rv_t errorValue = CKR_FUNCTION_FAILED) {
	if(noErr != status)
		throw P11Exception(errorValue);
}

static void checkAssert(bool value, ck_rv_t errorValue = CKR_FUNCTION_FAILED) {
	if(!value)
		throw P11Exception(errorValue);
}


class SKIPKEY {
};

static const std::string getLabel(SecKeychainItemRef item) {
	SecKeychainAttribute attr = {
		kSecLabelItemAttr, 0, NULL
	};
	SecKeychainAttributeList list = {
		1, &attr
	};
	check(SecKeychainItemCopyContent(item, NULL, &list, NULL, NULL));
	const std::string ret((char*)attr.data, attr.length);
	SecKeychainItemFreeContent(&list, NULL);
	return ret;
}

bool operator==(const CSSM_OID &a, const CSSM_OID &b) {
	return a.Length == b.Length && 0 == memcmp(a.Data, b.Data, a.Length);
}

bool operator!=(const CSSM_OID &a, const CSSM_OID &b) {
	return !(a == b);
}

static const std::string getPrivateKeyLabel(SecIdentityRef identity) {
	ScopedCF<SecKeyRef> keyRef;
	check(SecIdentityCopyPrivateKey(identity, &keyRef));
	return getLabel((SecKeychainItemRef)keyRef.get());
}

static void getCertData(SecIdentityRef identity, P11Attributes &certAttributes, P11Attributes &pubKeyAttributes, P11Attributes &keyAttributes) {
	ScopedCF<SecCertificateRef> certRef;
	check(SecIdentityCopyCertificate(identity, &certRef));
	
	const std::string &label = getLabel((SecKeychainItemRef)certRef.get());
	certAttributes.add(CKA_LABEL, label.data(), label.size());
	pubKeyAttributes.add(CKA_LABEL, label.data(), label.size());
	
	CSSM_DATA cert_data;
	check(SecCertificateGetData(certRef, &cert_data));
	certAttributes.add(CKA_VALUE, cert_data.Data, cert_data.Length);
	
	CSSM_CL_HANDLE cl;
	check(SecCertificateGetCLHandle(certRef, &cl));
	
	uint32 fieldCount = 0;
	CSSM_FIELD_PTR fields;
	CSSM_RETURN ret = CSSM_CL_CertGetAllFields(cl, &cert_data, &fieldCount, &fields);
	checkAssert(ret == CSSM_OK);
	try {
		for(int i = 0; i < fieldCount; i++) {
			/* Handle field */
			const CSSM_OID &oid = fields[i].FieldOid;
			const CSSM_DATA &data = fields[i].FieldValue;
			if(oid == CSSMOID_X509V1SerialNumber) {
				certAttributes.add(CKA_SERIAL_NUMBER, data.Data, data.Length);
			} else if(oid == CSSMOID_X509V1IssuerNameStd) {
				certAttributes.add(CKA_ISSUER, data.Data, data.Length);
			} else if(oid == CSSMOID_X509V1SubjectNameStd) {
				certAttributes.add(CKA_SUBJECT, data.Data, data.Length);
				keyAttributes.add(CKA_SUBJECT, data.Data, data.Length);
				pubKeyAttributes.add(CKA_SUBJECT, data.Data, data.Length);
			} else if(oid == CSSMOID_X509V1SubjectPublicKeyCStruct) {
				CSSM_X509_SUBJECT_PUBLIC_KEY_INFO *pubKeyInfo =
				(CSSM_X509_SUBJECT_PUBLIC_KEY_INFO *)data.Data;
				/* REQUIRE RSA */
				if(pubKeyInfo->algorithm.algorithm != CSSMOID_RSA)
					throw P11Exception(CKR_FUNCTION_FAILED);
				byte *begin = pubKeyInfo->subjectPublicKey.Data;
				byte *end = begin + pubKeyInfo->subjectPublicKey.Length;
				byte *ptr = begin;
				try {
					TLV_ref keyData = TLV::parse(ptr, end);
					checkAssert(keyData->getTag() == 0x30);
					const TLVList &values = keyData->getInnerValues();
					checkAssert(values.size() == 2);
					const byte_string &modulus = values[0]->getValue();
					const byte_string &exponent = values[1]->getValue();
					int modulusDataBegin = 0;
					/* Trim off extra zeroes in modulus encoding */
					while(!modulus[modulusDataBegin])
						modulusDataBegin++;
					pubKeyAttributes.add(CKA_MODULUS, &modulus[0], modulus.size());
					pubKeyAttributes.add(CKA_PUBLIC_EXPONENT, &exponent[0], exponent.size());
					pubKeyAttributes.addLong(CKA_MODULUS_BITS, (modulus.size() - modulusDataBegin) * 8);
					keyAttributes.add(CKA_MODULUS, &modulus[0], modulus.size());
					keyAttributes.add(CKA_PUBLIC_EXPONENT, &exponent[0], exponent.size());
					pubKeyAttributes.add(CKA_VALUE, begin, end - begin);
				} catch(runtime_error &e) {
					throw P11Exception(CKR_FUNCTION_FAILED);
				}
			}
		}
		CSSM_CL_FreeFields(cl, fieldCount, &fields);
	} catch(P11Exception &e) {
		CSSM_CL_FreeFields(cl, fieldCount, &fields);
		throw e;
	}
}

static int should_skip(const std::string &label) {
	for(const char **p = SKIP_OBJECT_MATCH; p && *p; p++) {
		if(-1 != label.find(*p))
			return 1;
	}
	return 0;
}

static void getKeyData(SecIdentityRef identity, P11Attributes &keyAttributes) {
	const std::string &label = getPrivateKeyLabel(identity);
	if(should_skip(label))
		throw SKIPKEY();
	keyAttributes.add(CKA_LABEL, label.data(), label.size());
}

#define SET_BOOL_ATTRIBUTES(store,attrs) do {\
for(int i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) \
store.addBool(attrs[i].type, attrs[i].value); \
} while(0)
#define SET_LONG_ATTRIBUTES(store,attrs) do {\
for(int i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) \
store.addLong(attrs[i].type, attrs[i].value); \
} while(0)
#define SET_RAW_ATTRIBUTES(store,attrs) do {\
for(int i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) \
store.add(attrs[i].type, attrs[i].value, attrs[i].size); \
} while(0)

bool P11Identity::createObjects(P11Objects_Ref objects, P11Identity_Ref &identity_reference) {
	static const long_attr keyLongs[] = {
		{ CKA_KEY_TYPE, CKK_RSA }
	};
	static const bool_attr keyBools[] = {
		/* Stored-object specific */
		{ CKA_MODIFIABLE, 0 },
		{ CKA_TOKEN, 1 },
		/* Key Specific */
		{ CKA_EXTRACTABLE, 0 },
		{ CKA_SENSITIVE, 1 },
		{ CKA_DECRYPT, 1 },
		{ CKA_SIGN, 1 },
		{ CKA_SIGN_RECOVER, 0 },
		{ CKA_UNWRAP, 0 }, /* CURRENTLY NO KEY UNWRAPPING */
		{ CKA_ALWAYS_AUTHENTICATE, 0 },
		{ CKA_WRAP_WITH_TRUSTED, 0 },
		{ CKA_ALWAYS_SENSITIVE, 1 },
		{ CKA_NEVER_EXTRACTABLE, 1 },
		{ CKA_LOCAL, 0 } /* NOTHING ASSUMED ABOUT KEY */
	};
	static const long mech_array[] = {
		CKM_RSA_PKCS,
		CKM_RSA_X_509
	};
	static const raw_attr keyRaws[] = {
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 },
		{ CKA_ALLOWED_MECHANISMS, mech_array, sizeof(mech_array) },
/* { CKA_KEY_GEN_MECHANISM, -- unavailable, not empty } */
		{ CKA_UNWRAP_TEMPLATE, NULL, 0 }
	};
	static const long_attr pubKeyLongs[] = {
		{ CKA_KEY_TYPE, CKK_RSA }
	};
	static const bool_attr pubKeyBools[] = {
		{ CKA_MODIFIABLE, 0 },
		{ CKA_TOKEN, 1 },
		{ CKA_ENCRYPT, 0 },
		{ CKA_VERIFY, 0 },
		{ CKA_VERIFY_RECOVER, 0 },
		{ CKA_WRAP, 0 },
		{ CKA_TRUSTED, 0 }
	};
	static const raw_attr pubKeyRaws[] = {
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 },
		{ CKA_WRAP_TEMPLATE, NULL, 0 }
	};
	static const bool_attr certBools[] = {
		/* Stored-object specific */
		{ CKA_MODIFIABLE, 0 },
		{ CKA_TOKEN, 1 },
		{ CKA_PRIVATE, 0 },
		{ CKA_TRUSTED, 0 }, /* Not a root */
	};
	static const long_attr certLongs[] = {
		{ CKA_CERTIFICATE_TYPE, CKC_X_509 },
		{ CKA_CERTIFICATE_CATEGORY, 1 }, // Token user cert
		{ CKA_JAVA_MIDP_SECURITY_DOMAIN, 0 } // Unspecified
	};
	static const raw_attr certRaws[] = {
		{ CKA_APPLICATION, NULL, 0 },
		{ CKA_OBJECT_ID, NULL, 0 },
		{ CKA_URL, NULL, 0 },
		{ CKA_HASH_OF_ISSUER_PUBLIC_KEY, NULL, 0 },
		{ CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NULL, 0 },
		{ CKA_START_DATE, NULL, 0 },
		{ CKA_END_DATE, NULL, 0 }
	};
	
	/* FOR EACH KEYPAIR */
	/* CKA_ID - all == generate based on identity value
	 * CKA_LABEL - all
	 */
	P11Attributes keyAttributes;
	P11Attributes pubKeyAttributes;
	P11Attributes certAttributes;
	SET_LONG_ATTRIBUTES(keyAttributes, keyLongs);
	SET_LONG_ATTRIBUTES(pubKeyAttributes, pubKeyLongs);
	SET_LONG_ATTRIBUTES(certAttributes, certLongs);
	SET_BOOL_ATTRIBUTES(keyAttributes, keyBools);
	SET_BOOL_ATTRIBUTES(pubKeyAttributes, pubKeyBools);
	SET_BOOL_ATTRIBUTES(certAttributes, certBools);
	SET_RAW_ATTRIBUTES(keyAttributes, keyRaws);
	SET_RAW_ATTRIBUTES(pubKeyAttributes, pubKeyRaws);
	SET_RAW_ATTRIBUTES(certAttributes, certRaws);

	certAttributes.addByte(CKA_ID, getHandle());
	keyAttributes.addByte(CKA_ID, getHandle());
	pubKeyAttributes.addByte(CKA_ID, getHandle());
	/* GET CERTIFICATE DATA */
	try {
		getCertData(identity, certAttributes, pubKeyAttributes, keyAttributes);
	} catch(P11Exception &e) {
		throw e;
	}
	/* END GET CERT DATA */
	try {
		getKeyData(identity, keyAttributes);
	} catch(P11Exception &e) {
		throw e;
	} catch(SKIPKEY &e) {
		return false;
	}

	P11Objects::addNew(objects, CKO_PUBLIC_KEY, pubKeyAttributes)->setIdentity(identity_reference);
	P11Objects::addNew(objects, CKO_PRIVATE_KEY, keyAttributes)  ->setIdentity(identity_reference);
	P11Objects::addNew(objects, CKO_CERTIFICATE, certAttributes) ->setIdentity(identity_reference);
	return true;
}

P11Identities::P11Identities() : identities() {
}

void P11Identities::createIdentity(P11Objects_Ref objects, SecIdentityRef identity) {
	P11Identity_Ref new_identity(new P11Identity(identity));
	IdentityManager::iterator iter = identities.add(new_identity, FilterKeepValid<P11Identity_Ref>());
	if(!new_identity->createObjects(objects, new_identity))
		identities.erase(iter);
}
