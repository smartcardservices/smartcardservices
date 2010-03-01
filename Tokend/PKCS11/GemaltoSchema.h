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
 * GemaltoSchema.h
 * $Id$
 */

#ifndef _GEMALTOSCHEMA_H_
#define _GEMALTOSCHEMA_H_

#include "Schema.h"
#include "GemaltoAttributeCoder.h"
#include "GemaltoKeyHandle.h"

namespace Tokend
{
	class Relation;
	class MetaRecord;
	class AttributeCoder;
}

class GemaltoSchema : public Tokend::Schema
{
	NOCOPY(GemaltoSchema)
public:
    GemaltoSchema() {}
    virtual ~GemaltoSchema();

	virtual void create();

protected:
	Tokend::Relation* createKeyRelation(CSSM_DB_RECORDTYPE keyType);

private:
	// Coders we need.
	KeyNameAttributeCoder mKeyNameCoder;

	KeyAlgorithmAttributeCoder mKeyAlgorithmCoder;
	KeySizeAttributeCoder mKeySizeCoder;

	// Coders for attributes of keys
	KeySensitiveAttributeCoder mKeySensitiveCoder;
	KeyPrivateAttributeCoder mKeyPrivateCoder;
	KeyAlwaysSensitiveAttributeCoder mKeyAlwaysSensitiveCoder;

	// Coders for Directions (or usage bits) of keys
	KeyEncryptAttributeCoder mEncryptCoder;
	KeyDecryptAttributeCoder mDecryptCoder;
	KeySignAttributeCoder mSignCoder;
	KeyVerifyAttributeCoder mVerifyCoder;
	KeySignRecoverAttributeCoder mSignRecoverCoder;
	KeyVerifyRecoverAttributeCoder mVerifyRecoverCoder;
	KeyWrapAttributeCoder mWrapCoder;
	KeyUnwrapAttributeCoder mUnwrapCoder;
	KeyDeriveAttributeCoder mDeriveCoder;

	GemaltoKeyHandleFactory mGemaltoKeyHandleFactory;
};

#endif /* !_GEMALTOSCHEMA_H_ */

/* arch-tag: 8A998081-124C-11D9-B324-000A9595DEEE */
