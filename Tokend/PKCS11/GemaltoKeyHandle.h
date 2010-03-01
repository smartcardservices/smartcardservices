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
 * GemaltoKeyHandle.h
 * $Id$
 */

#ifndef _GEMALTOKEYHANDLE_H_
#define _GEMALTOKEYHANDLE_H_

#include "KeyHandle.h"

class GemaltoToken;
class GemaltoKeyRecord;


//
// A KeyHandle object which implements the crypto interface to Gemalto smartcards.
//
class GemaltoKeyHandle: public Tokend::KeyHandle
{
	NOCOPY(GemaltoKeyHandle)
public:
    GemaltoKeyHandle(GemaltoToken &GemaltoToken,
		const Tokend::MetaRecord &metaRecord, GemaltoKeyRecord &cpsKey);
    ~GemaltoKeyHandle();

    virtual void getKeySize(CSSM_KEY_SIZE &keySize);
    virtual uint32 getOutputSize(const Context &context, uint32 inputSize,
		bool encrypting);
    virtual void generateSignature(const Context &context,
		CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature);
    virtual void verifySignature(const Context &context,
		CSSM_ALGORITHMS signOnly, const CssmData &input,
		const CssmData &signature);
    virtual void generateMac(const Context &context, const CssmData &input,
		CssmData &output);
    virtual void verifyMac(const Context &context, const CssmData &input,
		const CssmData &compare);
    virtual void encrypt(const Context &context, const CssmData &clear,
		CssmData &cipher);
    virtual void decrypt(const Context &context, const CssmData &cipher,
		CssmData &clear);

	virtual void exportKey(const Context &context,
		const AccessCredentials *cred, CssmKey &wrappedKey);

private:
	GemaltoToken &mToken;
	GemaltoKeyRecord &mKey;
};


//
// A factory that creates GemaltoKeyHandle objects.
//
class GemaltoKeyHandleFactory : public Tokend::KeyHandleFactory
{
	NOCOPY(GemaltoKeyHandleFactory)
public:
	GemaltoKeyHandleFactory() {}
	virtual ~GemaltoKeyHandleFactory();

	virtual Tokend::KeyHandle *keyHandle(Tokend::TokenContext *tokenContext,
		const Tokend::MetaRecord &metaRecord, Tokend::Record &record) const;
};


#endif /* !_GEMALTOKEYHANDLE_H_ */

/* arch-tag: 8B057D7A-124C-11D9-92C8-000A9595DEEE */

