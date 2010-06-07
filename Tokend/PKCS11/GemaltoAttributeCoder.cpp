/*
 *  Copyright (c) 2008-2009 Gemalto <support@gemalto.com>
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

/*
 * GemaltoAttributeCoder.cpp
 * $Id$
 */

#include "GemaltoAttributeCoder.h"

#include "Attribute.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include "GemaltoRecord.h"
#include "GemaltoError.h"
#include "GemaltoToken.h"

#include <Security/SecKeychainItem.h>
#include <security_cdsa_utilities/cssmkey.h>

using namespace Tokend;


//
// KeyEncryptAttributeCoder
//
KeyEncryptAttributeCoder::~KeyEncryptAttributeCoder()
{
}


void KeyEncryptAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyEncryptAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = false;
	}
	else
	{
		boolValue = keyRecord.encrypt();
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyEncryptAttributeCoder::decode - Class <%lu> - Value <%lu>\n", keyRecord.getClass(),  boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyEncryptAttributeCoder::decode <END>\n");
}


//
// KeyDecryptAttributeCoder
//
KeyDecryptAttributeCoder::~KeyDecryptAttributeCoder()
{
}


void KeyDecryptAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyDecryptAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = keyRecord.encrypt();
	}
	else
	{
		boolValue = false;
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyDecryptAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyDecryptAttributeCoder::decode <END>\n");
}


//
// KeySignAttributeCoder
//
KeySignAttributeCoder::~KeySignAttributeCoder()
{
}


void KeySignAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeySignAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = keyRecord.verify();
	}
	else
	{
		boolValue = false;
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeySignAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeySignAttributeCoder::decode <END>\n");
}


//
// KeyVerifyAttributeCoder
//
KeyVerifyAttributeCoder::~KeyVerifyAttributeCoder()
{
}


void KeyVerifyAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyVerifyAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = false;
	}
	else
	{
		boolValue = keyRecord.verify();
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyVerifyAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyVerifyAttributeCoder::decode <END>\n");
}


//
// KeySignRecoverAttributeCoder
//
KeySignRecoverAttributeCoder::~KeySignRecoverAttributeCoder()
{
}


void KeySignRecoverAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeySignRecoverAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = keyRecord.verifyRecover();
	}
	else
	{
		boolValue = false;
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeySignRecoverAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeySignRecoverAttributeCoder::decode <END>\n");
}


//
// KeyVerifyRecoverAttributeCoder
//
KeyVerifyRecoverAttributeCoder::~KeyVerifyRecoverAttributeCoder()
{
}


void KeyVerifyRecoverAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyVerifyRecoverAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = false;
	}
	else
	{
		boolValue = keyRecord.verifyRecover();
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyVerifyRecoverAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyVerifyRecoverAttributeCoder::decode <END>\n");
}


//
// KeyWrapAttributeCoder
//
KeyWrapAttributeCoder::~KeyWrapAttributeCoder()
{
}


void KeyWrapAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyWrapAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = false;
	}
	else
	{
		boolValue = keyRecord.wrap();
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyWrapAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyWrapAttributeCoder::decode <END>\n");
}


//
// KeyUnwrapAttributeCoder
//
KeyUnwrapAttributeCoder::~KeyUnwrapAttributeCoder()
{
}


void KeyUnwrapAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyUnwrapAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = true;

	if (keyRecord.getClass() == CKO_PRIVATE_KEY)
	{
		boolValue = keyRecord.wrap();
	}
	else
	{
		boolValue = false;
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyUnwrapAttributeCoder::decode - Label <%s> - bool <%u>\n", str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyUnwrapAttributeCoder::decode <END>\n");
}


//
// KeyDeriveAttributeCoder
//
KeyDeriveAttributeCoder::~KeyDeriveAttributeCoder()
{
}


void KeyDeriveAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyDeriveAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	bool boolValue = keyRecord.derive();

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyDeriveAttributeCoder::decode - Label <%s> - keyType <%ld> - bool <%u>\n", keyRecord.getType(),str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyDeriveAttributeCoder::decode <END>\n");
}


//
// KeySensitiveAttributeCoder
//
KeySensitiveAttributeCoder::~KeySensitiveAttributeCoder()
{
}


void KeySensitiveAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeySensitiveAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	const bool boolValue = (keyRecord.getClass() == CKO_PRIVATE_KEY);

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeySensitiveAttributeCoder::decode - Label <%s> - keyType <%ld> - bool <%u>\n", keyRecord.getType(), str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeySensitiveAttributeCoder::decode <END>\n");
}


//
// KeyPrivateAttributeCoder
//
KeyPrivateAttributeCoder::~KeyPrivateAttributeCoder()
{
}


void KeyPrivateAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyPrivateAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	const bool boolValue = (keyRecord.getClass() == CKO_PRIVATE_KEY);

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyPrivateAttributeCoder::decode - Label <%s> - keyType <%ld> - bool <%u>\n", keyRecord.getType(), str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyPrivateAttributeCoder::decode <END>\n");
}


//
// KeyAlwaysSensitiveAttributeCoder
//
KeyAlwaysSensitiveAttributeCoder::~KeyAlwaysSensitiveAttributeCoder()
{
}


void KeyAlwaysSensitiveAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyAlwaysSensitiveAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	const bool boolValue = (keyRecord.getClass() == CKO_PRIVATE_KEY);

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyAlwaysSensitiveAttributeCoder::decode - Label <%s> - keyType <%ld> - bool <%u>\n", keyRecord.getType(), str.c_str(), boolValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(boolValue));

	GemaltoToken::log("KeyAlwaysSensitiveAttributeCoder::decode <END>\n");
}


//
// KeySizeAttributeCoder
//
KeySizeAttributeCoder::~KeySizeAttributeCoder()
{
}


void KeySizeAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeySizeAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	const uint32 longValue = keyRecord.sizeInBits();

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeySizeAttributeCoder::decode - Label <%s> - keyType <%ld> - size <%lu>\n", str.c_str(), keyRecord.getType(), longValue);
	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(longValue));

	GemaltoToken::log("KeySizeAttributeCoder::decode <END>\n");
}


//
// KeyAlgorithmAttributeCoder
//
KeyAlgorithmAttributeCoder::~KeyAlgorithmAttributeCoder()
{
}


void KeyAlgorithmAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyAlgorithmAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);
	const CK_KEY_TYPE keyType = keyRecord.getType();
	uint32 algID;
    switch (keyType)
	{
	case CKK_RSA:
		algID = CSSM_ALGID_RSA;
		break;
	/*case CKK_DSA:
		algID = CSSM_ALGID_DSA;
		break;
	case CKK_DH:
		algID = CSSM_ALGID_DH;
		break;
	case CKK_ECDSA:
		algID = CSSM_ALGID_ECDSA;
		break;
	case CKK_KEA:
		algID = CSSM_ALGID_KEA;
		break;
	case CKK_GENERIC_SECRET:
		algID = CSSM_ALGID_GenericSecret;
		break;
	case CKK_RC2:
		algID = CSSM_ALGID_RC2;
		break;
	case CKK_RC4:
		algID = CSSM_ALGID_RC4;
		break;
	case CKK_DES:
		algID = CSSM_ALGID_DES;
		break;
	case CKK_DES3:
		algID = CSSM_ALGID_3DES;
		break;
	case CKK_CAST:
		algID = CSSM_ALGID_CAST;
		break;
	case CKK_CAST3:
		algID = CSSM_ALGID_CAST3;
		break;
	case CKK_CAST5:
		algID = CSSM_ALGID_CAST5;
		break;
	case CKK_RC5:
		algID = CSSM_ALGID_RC5;
		break;
	case CKK_IDEA:
		algID = CSSM_ALGID_IDEA;
		break;
	case CKK_SKIPJACK:
		algID = CSSM_ALGID_SKIPJACK;
		break;
	case CKK_BATON:
		algID = CSSM_ALGID_BATON;
		break;
	case CKK_JUNIPER:
		algID = CSSM_ALGID_JUNIPER;
		break;
	case CKK_CDMF:
		algID = CSSM_ALGID_CDMF;
		break;
	case CKK_AES:
		algID = CSSM_ALGID_ECAES;
		break;
	case CKK_BLOWFISH:
		algID = CSSM_ALGID_BLOWFISH;
		break;
*/
	default:
		GemaltoToken::log("KeyAlgorithmAttributeCoder::decode - Unknown CKA_KEY_TYPE <%02lX>  - r <%p> - rid <%08lX> - aid <%lu>\n", keyType, &record, metaAttribute.metaRecord().relationId(), metaAttribute.attributeId());
		algID = CSSM_ALGID_CUSTOM;
		break;
	}

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyAlgorithmAttributeCoder::decode - Label <%s> - keyType <%lu> - algID <%lu>\n", str.c_str(), keyRecord.getType(), algID);

	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(algID));

	GemaltoToken::log("KeyAlgorithmAttributeCoder::decode <END>\n");
}


//
// KeyNameAttributeCoder
//
KeyNameAttributeCoder::~KeyNameAttributeCoder()
{
}


void KeyNameAttributeCoder::decode(Tokend::TokenContext */*tokenContext*/, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record)
{
	GemaltoToken::log("\nKeyNameAttributeCoder::decode <BEGIN>\n");

	GemaltoKeyRecord &keyRecord = dynamic_cast<GemaltoKeyRecord &>(record);

	std::string str = "";
	GemaltoToken::toStringHex(keyRecord.getLabel().ptr(), keyRecord.getLabel().size(), str);
	GemaltoToken::log("KeyNameAttributeCoder::decode - Label <%s>\n", str.c_str());

	record.attributeAtIndex(metaAttribute.attributeIndex(), new Attribute(keyRecord.getLabel().ptr(), keyRecord.getLabel().size()));

	GemaltoToken::log("KeyNameAttributeCoder::decode <END>\n");
}
