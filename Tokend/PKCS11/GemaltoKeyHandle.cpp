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
 * GemaltoKeyHandle.cpp
 * $Id$
 */

#include "GemaltoKeyHandle.h"

#include "GemaltoRecord.h"
#include "GemaltoToken.h"

#include <security_utilities/debugging.h>
#include <security_utilities/utilities.h>
#include <security_cdsa_utilities/cssmerrors.h>
#include <Security/cssmerr.h>


//
// GemaltoKeyHandle
//
GemaltoKeyHandle::GemaltoKeyHandle(GemaltoToken &GemaltoToken, const Tokend::MetaRecord &metaRecord, GemaltoKeyRecord &cpsKey) :
	Tokend::KeyHandle(metaRecord, &cpsKey),
	mToken(GemaltoToken), mKey(cpsKey)
{
}


GemaltoKeyHandle::~GemaltoKeyHandle()
{
}


void GemaltoKeyHandle::getKeySize(CSSM_KEY_SIZE &keySize)
{
	GemaltoToken::log("\nGemaltoKeyHandle::getKeySize <BEGIN>\n");
	GemaltoToken::log("GemaltoKeyHandle::getOutputSize - sizeInBits <%lu>", mKey.sizeInBits());

	keySize.EffectiveKeySizeInBits = mKey.sizeInBits();
	keySize.LogicalKeySizeInBits = mKey.sizeInBits();

	GemaltoToken::log("GemaltoKeyHandle::getKeySize <END>\n");
}


uint32 GemaltoKeyHandle::getOutputSize(const Context &/*context*/, uint32 inputSize, bool encrypting)
{
	GemaltoToken::log("\nGemaltoKeyHandle::getOutputSize <BEGIN>\n");
	GemaltoToken::log("GemaltoKeyHandle::getOutputSize - inputSize <%lu> - encrypting <%d>", inputSize, encrypting);
	GemaltoToken::log("GemaltoKeyHandle::getOutputSize - sizeInBits / 8 <%lu>", (mKey.sizeInBits() / 8));

	GemaltoToken::log("GemaltoKeyHandle::getOutputSize <END>\n");

	return (mKey.sizeInBits() / 8);
}


static const unsigned char sha1sigheader[] =
{
	0x30, // SEQUENCE
	0x21, // LENGTH
	0x30, // SEQUENCE
	0x09, // LENGTH
	0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1a, // SHA1 OID (1 4 14 3 2 26)
	0x05, 0x00, // OPTIONAL ANY algorithm params (NULL)
	0x04, 0x14 // OCTECT STRING (20 bytes)
};


static const unsigned char md5sigheader[] =
{
	0x30, // SEQUENCE
	0x20, // LENGTH
	0x30, // SEQUENCE
	0x0C, // LENGTH
	0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, // MD5 OID (1 2 840 113549 2 5)
	0x05, 0x00, // OPTIONAL ANY algorithm params (NULL)
	0x04, 0x10 // OCTECT STRING (16 bytes)
};


void GemaltoKeyHandle::generateSignature(const Context &context, CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	GemaltoToken::log("\nGemaltoKeyHandle::generateSignature <BEGIN>\n");
	GemaltoToken::log("Algo <%lu> - SignOnly <%lu> Input <%s> - Signature <%s>\n", context.algorithm(), signOnly, input.toHex().c_str(), signature.toHex().c_str());

	if (context.type() != CSSM_ALGCLASS_SIGNATURE)
	{
		GemaltoToken::log("## Error ## CSSMERR_CSP_INVALID_CONTEXT\n");
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);
	}

	if (context.algorithm() != CSSM_ALGID_RSA)
	{
		GemaltoToken::log("## Error ## CSSMERR_CSP_INVALID_ALGORITHM\n");
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
	}

	// Find out if we are doing a SHA1 or MD5 signature and setup header to
	// point to the right asn1 blob.
	const unsigned char *header;
	size_t headerLength;
	CK_ULONG mech = CKM_RSA_PKCS;
	if (signOnly == CSSM_ALGID_SHA1)
	{
		GemaltoToken::log("Case CSSM_ALGID_SHA1\n");
		//secdebug("Gemalto.tokend", "GemaltoKeyHandle: CSSM_ALGID_SHA1 (%lu)", input.Length);

		if (input.Length != 20)
		{
			GemaltoToken::log("## Error ## CSSMERR_CSP_BLOCK_SIZE_MISMATCH\n");
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		}
		header = sha1sigheader;
		headerLength = sizeof(sha1sigheader);
	}
	else if (signOnly == CSSM_ALGID_MD5)
	{
		GemaltoToken::log("Case CSSM_ALGID_MD5\n");
		//secdebug("Gemalto.tokend", "GemaltoKeyHandle: CSSM_ALGID_MD5 (%lu)", input.Length);

		if (input.Length != 16)
		{
			GemaltoToken::log("## Error ## CSSMERR_CSP_BLOCK_SIZE_MISMATCH\n");
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		}

		header = md5sigheader;
		headerLength = sizeof(md5sigheader);
	}
	else if (signOnly == CSSM_ALGID_NONE)
	{
		GemaltoToken::log("Case CSSM_ALGID_NONE\n");
		//secdebug("Gemalto.tokend", "GemaltoKeyHandle: CSSM_ALGID_NONE");

		// Special case used by SSL it's an RSA signature, without the ASN1 stuff
		header = NULL;
		headerLength = 0;
	}
	else
	{
		GemaltoToken::log("## Error ## CSSMERR_CSP_INVALID_DIGEST_ALGORITHM\n");
		//secdebug("Gemalto.tokend", "GemaltoKeyHandle: Invalid sign algo");
		CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
	}

	// Create an input buffer in which we construct the data we will send to
	// the token.
	size_t inputDataSize = headerLength + input.Length;
	size_t keyLength = mKey.sizeInBits() / 8;
	auto_array<unsigned char> inputData(keyLength);
	unsigned char *to = inputData.get();

	// Get padding, but default to pkcs1 style padding
	uint32 padding = CSSM_PADDING_PKCS1;
	context.getInt(CSSM_ATTRIBUTE_PADDING, padding);
	GemaltoToken::log("Padding <%lu>\n", padding);

//JCD
/*
		if (padding != CSSM_PADDING_PKCS1)
		{
			CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
		}
*/
	// Gemalto pkcs11 can handle PKCS1 padding only
	switch(padding)
	{
		case CSSM_PADDING_PKCS1:
		mech = CKM_RSA_PKCS;
		break;

		case CSSM_PADDING_NONE:
		mech = CKM_RSA_X_509;
		break;

		case CSSM_PADDING_CUSTOM:
		case CSSM_PADDING_ZERO:
		case CSSM_PADDING_ONE:
		case CSSM_PADDING_ALTERNATE:
		case CSSM_PADDING_FF:
		case CSSM_PADDING_PKCS5:
		case CSSM_PADDING_PKCS7:
		case CSSM_PADDING_CIPHERSTEALING:
		case CSSM_PADDING_RANDOM:
		case CSSM_PADDING_VENDOR_DEFINED:
		default:
		GemaltoToken::log("## Error ## CSSMERR_CSP_INVALID_ATTR_PADDING\n");
		CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
	}
	GemaltoToken::log("Mechanism <%lu>\n", mech);
//JCD

	// Now copy the ASN1 header into the input buffer.
	// This header is the DER encoding of
	// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
	// digest OCTET STRING }
	// Where AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
	// parameters OPTIONAL ANY }
	if (headerLength)
	{
		memcpy(to, header, headerLength);
		to += headerLength;
	}

	// Finally copy the passed in data to the input buffer.
	memcpy(to, input.Data, input.Length);

	// @@@ Switch to using tokend allocators
	unsigned char *outputData = reinterpret_cast<unsigned char *>(malloc(keyLength));
	size_t outputLength = keyLength;
	try
	{
		const AccessCredentials *cred = context.get<const AccessCredentials>(CSSM_ATTRIBUTE_ACCESS_CREDENTIALS);
		// Sign the inputData using the token
		mKey.computeSign(mToken, mech, cred, inputData.get(), inputDataSize, outputData, outputLength);
	}
	catch (...)
	{
		GemaltoToken::log("## Error ## key computeSign\n");

		// @@@ Switch to using tokend allocators
		free(outputData);
		throw;
	}

	signature.Data = outputData;
	signature.Length = outputLength;

	GemaltoToken::log("GemaltoKeyHandle::generateSignature <END>\n");
}


void GemaltoKeyHandle::verifySignature(const Context &/*context*/, CSSM_ALGORITHMS /*signOnly*/, const CssmData &/*input*/, const CssmData &/*signature*/)
{
	GemaltoToken::log("\nGemaltoKeyHandle::verifySignature <BEGIN>\n");
	GemaltoToken::log("## Error ## CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED\n");
	GemaltoToken::log("GemaltoKeyHandle::verifySignature <END>\n");

	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void GemaltoKeyHandle::generateMac(const Context &/*context*/, const CssmData &/*input*/, CssmData &/*output*/)
{
	GemaltoToken::log("\nGemaltoKeyHandle::generateMac <BEGIN>\n");
	GemaltoToken::log("## Error ## CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED\n");
	GemaltoToken::log("GemaltoKeyHandle::generateMac <END>\n");

	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void GemaltoKeyHandle::verifyMac(const Context &, const CssmData &, const CssmData &)
{
	GemaltoToken::log("\nGemaltoKeyHandle::verifyMac <BEGIN>\n");
	GemaltoToken::log("## Error ## CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED\n");
	GemaltoToken::log("GemaltoKeyHandle::verifyMac <END>\n");

	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void GemaltoKeyHandle::encrypt(const Context &, const CssmData &, CssmData &)
{
	GemaltoToken::log("\nGemaltoKeyHandle::encrypt <BEGIN>\n");
	GemaltoToken::log("## Error ## CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED\n");
	GemaltoToken::log("GemaltoKeyHandle::encrypt <END>\n");

	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void GemaltoKeyHandle::decrypt(const Context &context, const CssmData &cipher, CssmData &clear)
{
	GemaltoToken::log("\nGemaltoKeyHandle::decrypt <BEGIN>\n");
	GemaltoToken::log("Alg <%lu> - cipher <%s> - clear <%s>\n", context.algorithm(), cipher.toHex().c_str(), clear.toHex().c_str());

	size_t keyLength = mKey.sizeInBits() / 8;

	// Get padding, but default to pkcs1 style padding
	uint32 padding = CSSM_PADDING_PKCS1;
	context.getInt(CSSM_ATTRIBUTE_PADDING, padding);
	GemaltoToken::log("Padding <%lu>\n", padding);

	// Gemalto pkcs11 can handle PKCS1 padding only
	if (padding != CSSM_PADDING_PKCS1)
	{
		GemaltoToken::log("## Error ## CSSMERR_CSP_INVALID_ATTR_PADDING\n");
		CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
	}

	// @@@ Switch to using tokend allocators
	unsigned char *outputData = reinterpret_cast<unsigned char *>(malloc(keyLength));
	size_t outputLength = keyLength;
	try
	{
		const AccessCredentials *cred = context.get<const AccessCredentials>(CSSM_ATTRIBUTE_ACCESS_CREDENTIALS);

		// Decrypt the inputData using the token
		mKey.computeDecrypt(mToken, CKM_RSA_PKCS, cred, cipher.Data, cipher.Length,	outputData, outputLength);
	}
	catch (...)
	{
		GemaltoToken::log("## Error ## mKey.computeDecrypt\n");

		// @@@ Switch to using tokend allocators
		free(outputData);
		throw;
	}

	clear.Data = outputData;
	clear.Length = outputLength;

	GemaltoToken::log("GemaltoKeyHandle::decrypt <END>\n");
}


void GemaltoKeyHandle::exportKey(const Context &, const AccessCredentials *, CssmKey &)
{
	GemaltoToken::log("\nGemaltoKeyHandle::exportKey <BEGIN>\n");
	GemaltoToken::log("## Error ## CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED\n");
	GemaltoToken::log("GemaltoKeyHandle::exportKey <END>\n");

	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


//
// GemaltoKeyHandleFactory
//
GemaltoKeyHandleFactory::~GemaltoKeyHandleFactory()
{
}


Tokend::KeyHandle* GemaltoKeyHandleFactory::keyHandle(Tokend::TokenContext *tokenContext, const Tokend::MetaRecord &metaRecord, Tokend::Record &record) const
{
	GemaltoToken::log("\nGemaltoKeyHandleFactory::keyHandle <BEGIN>\n");

	GemaltoKeyRecord &key = dynamic_cast<GemaltoKeyRecord &>(record);
	GemaltoToken &gemaltoToken = static_cast<GemaltoToken &>(*tokenContext);

	GemaltoToken::log("GemaltoKeyHandleFactory::keyHandle <END>\n");

	return new GemaltoKeyHandle(gemaltoToken, metaRecord, key);
}
