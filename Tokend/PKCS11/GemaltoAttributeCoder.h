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
 * GemaltoAttributeCoder.h
 * $Id$
 */

#ifndef _GEMALTOATTRIBUTECODER_H_
#define _GEMALTOATTRIBUTECODER_H_

#include "AttributeCoder.h"
#include <string>

#include "cryptoki.h"



//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyEncryptAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyEncryptAttributeCoder)
public:
	KeyEncryptAttributeCoder() {}
	virtual ~KeyEncryptAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyDecryptAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyDecryptAttributeCoder)
public:
	KeyDecryptAttributeCoder() {}
	virtual ~KeyDecryptAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeySignAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeySignAttributeCoder)
public:
	KeySignAttributeCoder() {}
	virtual ~KeySignAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyVerifyAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyVerifyAttributeCoder)
public:
	KeyVerifyAttributeCoder() {}
	virtual ~KeyVerifyAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeySignRecoverAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeySignRecoverAttributeCoder)
public:
	KeySignRecoverAttributeCoder() {}
	virtual ~KeySignRecoverAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyVerifyRecoverAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyVerifyRecoverAttributeCoder)
public:
	KeyVerifyRecoverAttributeCoder() {}
	virtual ~KeyVerifyRecoverAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyWrapAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyWrapAttributeCoder)
public:
	KeyWrapAttributeCoder() {}
	virtual ~KeyWrapAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyUnwrapAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyUnwrapAttributeCoder)
public:
	KeyUnwrapAttributeCoder() {}
	virtual ~KeyUnwrapAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyDeriveAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyDeriveAttributeCoder)
public:
	KeyDeriveAttributeCoder() {}
	virtual ~KeyDeriveAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeySensitiveAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeySensitiveAttributeCoder)
public:
	KeySensitiveAttributeCoder() {}
	virtual ~KeySensitiveAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyPrivateAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyPrivateAttributeCoder)
public:
	KeyPrivateAttributeCoder() {}
	virtual ~KeyPrivateAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces a boolean value based on pkcs11 attribute type
//
class KeyAlwaysSensitiveAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyAlwaysSensitiveAttributeCoder)
public:
	KeyAlwaysSensitiveAttributeCoder() {}
	virtual ~KeyAlwaysSensitiveAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that produces the LogicalKeySizeInBits of a key
//
class KeySizeAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeySizeAttributeCoder)
public:
	KeySizeAttributeCoder() {}
	virtual ~KeySizeAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder produces a CSSM_ALGID from a key
//
class KeyAlgorithmAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyAlgorithmAttributeCoder)
public:
	KeyAlgorithmAttributeCoder() {}
	virtual ~KeyAlgorithmAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


//
// A coder that reads the name of a key
//
class KeyNameAttributeCoder : public Tokend::AttributeCoder
{
	NOCOPY(KeyNameAttributeCoder)
public:

	KeyNameAttributeCoder() {}
	virtual ~KeyNameAttributeCoder();

	virtual void decode(Tokend::TokenContext *tokenContext, const Tokend::MetaAttribute &metaAttribute, Tokend::Record &record);
};


#endif /* !_GEMALTOATTRIBUTECODER_H_ */

/* arch-tag: C909C93A-F61D-11D8-8459-000A9595DEEE */
