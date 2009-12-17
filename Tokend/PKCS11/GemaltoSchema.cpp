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
 *  GemaltoSchema.cpp
 *  Gemalto.tokend
 */

#include "GemaltoSchema.h"
#include "GemaltoToken.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"

#include <Security/SecCertificate.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecKey.h>

using namespace Tokend;

GemaltoSchema::~GemaltoSchema()
{
}

Tokend::Relation* GemaltoSchema::createKeyRelation(CSSM_DB_RECORDTYPE keyType)
{
	GemaltoToken::log( "\nGemaltoSchema::createKeyRelation <BEGIN>\n" );
	GemaltoToken::log( "CSSM_DB_RECORDTYPE <%ld>\n", keyType );

	Relation *rn = createStandardRelation(keyType);

	// Set up coders for key records.
	MetaRecord &mr = rn->metaRecord();
	mr.keyHandleFactory(&mGemaltoKeyHandleFactory);

	// Print name of a key might as well be the key name.
	mr.attributeCoder(kSecKeyPrintName, &mKeyNameCoder);

	// Other key valuess
	mr.attributeCoder(kSecKeyKeyType, &mKeyAlgorithmCoder);
	mr.attributeCoder(kSecKeyKeySizeInBits, &mKeySizeCoder);
	// @@@ Should be different for 3DES keys.
	mr.attributeCoder(kSecKeyEffectiveKeySize, &mKeySizeCoder);

	// Key attributes
	mr.attributeCoder(kSecKeyExtractable, &mFalseCoder);
	mr.attributeCoder(kSecKeySensitive, &mKeySensitiveCoder);
	mr.attributeCoder(kSecKeyModifiable, &mFalseCoder);
	mr.attributeCoder(kSecKeyPrivate, &mKeyPrivateCoder);
	mr.attributeCoder(kSecKeyNeverExtractable, &mTrueCoder);
	mr.attributeCoder(kSecKeyAlwaysSensitive, &mKeyAlwaysSensitiveCoder);

	// Key usage
	mr.attributeCoder(kSecKeyEncrypt, &mEncryptCoder);
	mr.attributeCoder(kSecKeyDecrypt, &mDecryptCoder);
	mr.attributeCoder(kSecKeyWrap, &mWrapCoder);
	mr.attributeCoder(kSecKeyUnwrap, &mUnwrapCoder);
	mr.attributeCoder(kSecKeySign, &mSignCoder);
	mr.attributeCoder(kSecKeyVerify, &mVerifyCoder);
	mr.attributeCoder(kSecKeySignRecover, &mSignRecoverCoder);
	mr.attributeCoder(kSecKeyVerifyRecover, &mVerifyRecoverCoder);
	mr.attributeCoder(kSecKeyDerive, &mDeriveCoder);

	GemaltoToken::log( "\nGemaltoSchema::createKeyRelation <END>\n" );

	return rn;
}


void GemaltoSchema::create()
{
	GemaltoToken::log( "\nGemaltoSchema::create <BEGIN>\n" );

	Schema::create();

	createStandardRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
	createKeyRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
	Relation *rn_publ = createKeyRelation(CSSM_DL_DB_RECORD_PUBLIC_KEY);

	// @@@ We need a coder that calculates the public key hash of a public key
	rn_publ->metaRecord().attributeCoder(kSecKeyLabel, &mZeroCoder);
	//rn_publ->metaRecord().attributeCoder(kSecKeyLabel, &mKeyNameCoder);

	GemaltoToken::log( "\nGemaltoSchema::create <END>\n" );
}

/* arch-tag: 8AB453F1-124C-11D9-B0F8-000A9595DEEE */
