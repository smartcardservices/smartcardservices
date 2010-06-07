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
 * GemaltoRecord.cpp
 * $Id$
 */

#include "GemaltoRecord.h"

#include "GemaltoError.h"
#include "GemaltoToken.h"
#include "Attribute.h"
#include "MetaAttribute.h"
#include "MetaRecord.h"
#include <security_cdsa_client/aclclient.h>
#include <Security/SecKey.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
//#include <openssl/ssl.h>

//
// GemaltoRecord
//
GemaltoRecord::GemaltoRecord(GemaltoToken &/*gemaltoToken*/, CK_OBJECT_HANDLE handle)
	: mHandle(handle)
{
}


GemaltoRecord::GemaltoRecord()
{
	mHandle = 0;
	mClass = 0;
}


GemaltoRecord::~GemaltoRecord()
{
}


//
// GemaltoCertRecord
//
GemaltoCertRecord::GemaltoCertRecord(GemaltoToken &gemaltoToken, CK_OBJECT_HANDLE handle)
	:	GemaltoRecord(gemaltoToken, handle),
		mSubjectName(NULL),
		mIssuerName(NULL),
		mKeyType((CK_ULONG) -1),
		mKeySize(0),
		mKeyPubVerify(FALSE),
		mKeyPubWrap(FALSE),
        mKeyPubEncrypt(FALSE),
        mKeyPrvSign(FALSE),
	    mKeyPrvUnwrap(FALSE),
		mKeyPrvDecrypt(FALSE),
    	mSelfSigned(FALSE),
		mCA(FALSE)
{
	GemaltoToken::log("\nGemaltoCertRecord::GemaltoCertRecord <BEGIN>\n");

	mClass = CKO_CERTIFICATE;

	// Get the certificate value length
	CK_ATTRIBUTE valueAttr = {CKA_VALUE, NULL_PTR, 0};
	CKError::check(CK_D_(C_GetAttributeValue)(gemaltoToken.session(), mHandle, &valueAttr, 1));

	// Get the certificate value
	mValue.reserve(valueAttr.ulValueLen);
	valueAttr.pValue = mValue.ptr();
	CKError::check(CK_D_(C_GetAttributeValue)(gemaltoToken.session(), mHandle, &valueAttr, 1));

	std::string szOut = "";
	GemaltoToken::toStringHex(mValue.ptr(), mValue.size(), szOut);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Value - len <%lu> - value <%s>\n", mValue.size(), szOut.c_str());

	// Get a X509 OpenSSL certificate instance
	const unsigned char* p = mValue.ptr();
	X509* cert = d2i_X509(NULL, &p, mValue.size());
	if (NULL == cert)
	{
		GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - ## ERROR ## Cannot create OpenSSL certificate instance\n");
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);
	}

	// Initialize internal registers
	X509_check_purpose(cert, -1, 0);

	// Get the subject name
	char attr[1024];
	memset(attr, 0, sizeof(attr));
	std::string s = "Unknown subject name";
	/*
	X509_NAME_oneline(X509_get_subject_name(cert), attr, sizeof(attr));
	s = attr;
	mSubject.copy((CK_BYTE*)s.c_str(), s.size());
	*/
    X509_NAME* pName = X509_get_subject_name(cert);
    if (pName)
    {
		X509_NAME_get_text_by_NID(pName, NID_commonName, attr, sizeof(attr));
        s = attr;
    }
	mSubject.copy((CK_BYTE*)s.c_str(), s.size());

	szOut = "";
	GemaltoToken::toStringHex(mSubject.ptr(), mSubject.size(), szOut);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Subject - len <%lu> - value <%s>\n", mSubject.size(), szOut.c_str());

	// Get the issuer name
	memset(attr, 0, sizeof(attr));
	s = "";
	X509_NAME_oneline(X509_get_issuer_name(cert), attr, sizeof(attr));
	s = attr;
	mIssuer.copy((CK_BYTE*)s.c_str(), s.size());

	szOut = "";
	GemaltoToken::toStringHex(mIssuer.ptr(), mIssuer.size(), szOut);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Issuer - len <%lu> - value <%s>\n", mIssuer.size(), szOut.c_str());
	//GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Issuer - value <%s>\n", GemaltoDataString(mIssuer));

	// Compute if the certificate is selfsigned
	mSelfSigned = FALSE;
	// First check if the issuer and the subject are the same
	if (0 == X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)))
	{
		// Then, check the signature
		// Get the certificate public key
		//SSL_library_init();

		// Get issuer public key and verify this signature
		EVP_PKEY* l_CertPubKey = NULL;
		l_CertPubKey = X509_get_pubkey(cert);
		if (NULL != l_CertPubKey)
		{
			// Verify this signature
			int l_RetVal = X509_verify(cert, l_CertPubKey);
			EVP_PKEY_free(l_CertPubKey);

			// If signature verification is ok, issuer has been found, stop
			if (0 < l_RetVal)
			{
				mSelfSigned = TRUE;
			}
		}

		//mSelfSigned = TRUE;
   }
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - mSelfSigned - value <%lu>\n", mSelfSigned);

  	// Check that the public key type is RSA
	if (NID_rsaEncryption != OBJ_obj2nid(cert->cert_info->key->algor->algorithm))
	{
		GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - ## Error CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED\n");
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
	}

	mKeyType = CKK_RSA;
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Public key type RSA <%lu>\n", mKeyType);

	// Get the public key
    EVP_PKEY* pKey = X509_get_pubkey(cert);
	if (NULL == pKey)
	{
		GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - ## ERROR ## CSSM_ERRCODE_INVALID_SAMPLE_VALUE\n");
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);
	}

	// Get public key size
	mKeySize = BN_num_bits(pKey->pkey.rsa->n);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Public key size <%lu>\n", mKeySize);

	// Get the public key modulus
	mKeyModulus.reserve(mKeySize / 8);
    BN_bn2bin(pKey->pkey.rsa->n, mKeyModulus.ptr());

    // If a keyUsage extension is present, parse it
    if (EXFLAG_KUSAGE == (cert->ex_flags & EXFLAG_KUSAGE))
    {
		if (KU_CRL_SIGN == (cert->ex_kusage & KU_CRL_SIGN))
		{
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
		}
		if (KU_DATA_ENCIPHERMENT == (cert->ex_kusage & KU_DATA_ENCIPHERMENT))
		{
            mKeyPubWrap = TRUE;
            mKeyPubEncrypt = TRUE;
            mKeyPrvUnwrap = TRUE;
            mKeyPrvDecrypt = TRUE;
		}
		if (KU_DIGITAL_SIGNATURE == (cert->ex_kusage & KU_DIGITAL_SIGNATURE))
		{
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
		}
		if (KU_ENCIPHER_ONLY == (cert->ex_kusage & KU_ENCIPHER_ONLY))
		{
            mKeyPubWrap = TRUE;
            mKeyPubEncrypt = TRUE;
            mKeyPrvUnwrap = TRUE;
            mKeyPrvDecrypt = TRUE;
            mKeyPrvSign = FALSE;
			mKeyPubVerify = FALSE;
		}
		if (KU_KEY_AGREEMENT == (cert->ex_kusage & KU_KEY_AGREEMENT))
		{
            mKeyPubWrap = TRUE;
            mKeyPubEncrypt = TRUE;
            mKeyPrvUnwrap = TRUE;
            mKeyPrvDecrypt = TRUE;
		}
		if (KU_KEY_CERT_SIGN == (cert->ex_kusage & KU_KEY_CERT_SIGN))
		{
		// Attribut de ca
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
		}
		if (KU_KEY_ENCIPHERMENT == (cert->ex_kusage & KU_KEY_ENCIPHERMENT))
		{
            mKeyPubWrap = TRUE;
            mKeyPubEncrypt = TRUE;
            mKeyPrvUnwrap = TRUE;
            mKeyPrvDecrypt = TRUE;
		}
		if (KU_NON_REPUDIATION == (cert->ex_kusage & KU_NON_REPUDIATION))
		{
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
		}
	}

	// If an extendedKeyUsage extension is present parse it
	if (EXFLAG_XKUSAGE == (cert->ex_flags & EXFLAG_XKUSAGE))
	{
		if ((XKU_CODE_SIGN == (cert->ex_xkusage & XKU_CODE_SIGN))
			  || (XKU_SSL_CLIENT == (cert->ex_xkusage & XKU_SSL_CLIENT))
			  || (XKU_TIMESTAMP == (cert->ex_xkusage & XKU_TIMESTAMP))
			  || (XKU_OCSP_SIGN == (cert->ex_xkusage & XKU_OCSP_SIGN))
			)
		{
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
		}
		if ((XKU_SMIME == (cert->ex_xkusage & XKU_SMIME))
		|| (XKU_SSL_SERVER == (cert->ex_xkusage & XKU_SSL_SERVER))
			)
		{
            mKeyPrvSign = TRUE;
			mKeyPubVerify = TRUE;
            mKeyPubWrap = TRUE;
            mKeyPubEncrypt = TRUE;
            mKeyPrvUnwrap = TRUE;
            mKeyPrvDecrypt = TRUE;
		}
		// Others values are not defined (EFS) or not known
	}

	BASIC_CONSTRAINTS* bs = (BASIC_CONSTRAINTS*) X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
	mCA = (bs && bs->ca);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - CA <%lu>\n", mCA);

	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPrvSign <%lu>\n", mKeyPrvSign);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPubVerify <%lu>\n", mKeyPubVerify);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPubWrap <%lu>\n", mKeyPubWrap);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPubEncrypt <%lu>\n", mKeyPubEncrypt);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPrvUnwrap <%lu>\n", mKeyPrvUnwrap);
	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord - Key usage mKeyPrvDecrypt <%lu>\n", mKeyPrvDecrypt);

	GemaltoToken::log("GemaltoCertRecord::GemaltoCertRecord <END>\n");
}


/* GemaltoCertRecord Default constructor
*/
GemaltoCertRecord::GemaltoCertRecord()
	:	GemaltoRecord(),
		mSubjectName(NULL),
		mIssuerName(NULL),
		mKeyType((CK_ULONG) -1),
		mKeySize(0),
		mKeyPubVerify(FALSE),
		mKeyPubWrap(FALSE),
        mKeyPubEncrypt(FALSE),
        mKeyPrvSign(FALSE),
	    mKeyPrvUnwrap(FALSE),
		mKeyPrvDecrypt(FALSE),
    	mSelfSigned(FALSE),
		mCA(FALSE)
{
	mClass = CKO_CERTIFICATE;
}


GemaltoCertRecord::~GemaltoCertRecord()
{
	if (NULL != mSubjectName)
	{
		X509_NAME_free(mSubjectName);
		mSubjectName = NULL;
	}

	if (NULL != mIssuerName)
	{
		X509_NAME_free(mIssuerName);
		mIssuerName = NULL;
	}
}


Tokend::Attribute *GemaltoCertRecord::getDataAttribute(Tokend::TokenContext * /*tokenContext*/)
{
	GemaltoToken::log("\nGemaltoCertRecord::getDataAttribute <BEGIN>\n");

	std::string s = "";
	GemaltoToken::toStringHex(mValue.ptr(), mValue.size(), s);
	GemaltoToken::log("GemaltoCertRecord::getDataAttribute - size <%lu> - value <%s>\n", mValue.size(), s.c_str());

	GemaltoToken::log("GemaltoCertRecord::getDataAttribute <END>\n");

	return new Tokend::Attribute(mValue.ptr(), mValue.size());
}


//
// GemaltoKeyRecord
//
GemaltoKeyRecord::GemaltoKeyRecord(const GemaltoCertRecord &cert)
	:	GemaltoRecord(),
		mKeyType((CK_ULONG) -1),
		mKeySize(0),
		mKeyPubVerify(FALSE),
		mKeyPubWrap(FALSE),
		mKeyPubEncrypt(FALSE)
{
	GemaltoToken::log("\nGemaltoKeyRecord::GemaltoKeyRecord <BEGIN>\n");

	mHandle = cert.getHandle();

	mClass = CKO_PUBLIC_KEY;

	mKeyType = cert.getType();
	mKeySize = cert.sizeInBits();

	mKeyPubVerify = cert.verify();
	mKeyPubWrap = cert.wrap();
	mKeyPubEncrypt = cert.encrypt();

	mLabel = cert.getSubject();

	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord - Handle <%ld>\n", mHandle);

	std::string str = "";
	GemaltoToken::toStringHex(mLabel.ptr(), mLabel.size(), str);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Class <%lu>\n", mClass);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key type <%lu>\n", mKeyType);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key size <%lu>\n", mKeySize);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubVerify <%lu>\n", mKeyPubVerify);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubWrap <%lu>\n", mKeyPubWrap);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubEncrypt <%lu>\n", mKeyPubEncrypt);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key label <%s>\n", str.c_str());

	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord <END>\n");
}


GemaltoKeyRecord::GemaltoKeyRecord()
	:	GemaltoRecord(),
		mKeyType((CK_ULONG) -1),
		mKeySize(0),
		mKeyPubVerify(FALSE),
		mKeyPubWrap(FALSE),
		mKeyPubEncrypt(FALSE)
{
	mClass = CKO_PUBLIC_KEY;
}


GemaltoKeyRecord::~GemaltoKeyRecord()
{
}


void GemaltoKeyRecord::computeSign(GemaltoToken &/*gemaltoToken*/, CK_ULONG /*mech*/, const AccessCredentials * /*cred*/, unsigned char * /*data*/, size_t /*dataLength*/, unsigned char * /*output*/, size_t &/*outputLength*/)
{
	GemaltoToken::log("\nGemaltoKeyRecord::computeSign <BEGIN>\n");
	std::string str = "";
	GemaltoToken::toStringHex(mLabel.ptr(), mLabel.size(), str);
	GemaltoToken::log("GemaltoKeyRecord::computeSign() - Label <%s>\n", str.c_str());
	GemaltoToken::log("trow CSSMERR_CSP_KEY_USAGE_INCORRECT\n");
	GemaltoToken::log("GemaltoKeyRecord::computeSign <END>\n");

	CssmError::throwMe(CSSMERR_CSP_KEY_USAGE_INCORRECT);
}


void GemaltoKeyRecord::computeDecrypt(GemaltoToken &/*gemaltoToken*/, CK_ULONG /*mech*/, const AccessCredentials * /*cred*/, unsigned char * /*data*/, size_t /*dataLength*/, unsigned char * /*output*/, size_t &/*outputLength*/)
{
	GemaltoToken::log("\nGemaltoKeyRecord::computeDecrypt <BEGIN>\n");
	std::string str = "";
	GemaltoToken::toStringHex(mLabel.ptr(), mLabel.size(), str);
	GemaltoToken::log("GemaltoKeyRecord::computeDecrypt - Label <%s>\n", str.c_str());
	GemaltoToken::log("trow CSSMERR_CSP_KEY_USAGE_INCORRECT\n");
	GemaltoToken::log("GemaltoKeyRecord::computeDecrypt <END>\n");

	CssmError::throwMe(CSSMERR_CSP_KEY_USAGE_INCORRECT);
}


//
// GemaltoPrivateKeyRecord
//


GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord(const GemaltoCertRecord &cert)
	: GemaltoKeyRecord(cert)
{
	GemaltoToken::log("\nGemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord <BEGIN>\n");

	secdebug("Gemalto.tokend", "GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord(cert)");

	mHandle = cert.getHandle();

	mClass = CKO_PRIVATE_KEY;

	mKeyType = cert.getType();
	mKeySize = cert.sizeInBits();

	mKeyModulus = cert.getKeyPubModulus();

	mKeyPrvSign = cert.verify();
	mKeyPrvUnwrap = cert.wrap();
	mKeyPrvDecrypt = cert.encrypt();

	mLabel = cert.getSubject();

	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord - Handle <%ld>\n", mHandle);
	std::string str = "";
	GemaltoToken::toStringHex(mLabel.ptr(), mLabel.size(), str);
	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord() - Class <%lu>\n", mClass);
	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord() - Key type <%lu>\n", mKeyType);
	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord() - Key size <%lu>\n", mKeySize);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubVerify <%lu>\n", mKeyPubVerify);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubWrap <%lu>\n", mKeyPubWrap);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPubEncrypt <%lu>\n", mKeyPubEncrypt);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPrvSign <%lu>\n", mKeyPrvSign);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPrvUnwrap <%lu>\n", mKeyPrvUnwrap);
	GemaltoToken::log("GemaltoKeyRecord::GemaltoKeyRecord() - Key mKeyPrvDecrypt <%lu>\n", mKeyPrvDecrypt);
	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord() - Key label <%s>\n", str.c_str());

	GemaltoToken::log("GemaltoPrivateKeyRecord::GemaltoPrivateKeyRecord <END>\n");
}


GemaltoPrivateKeyRecord::~GemaltoPrivateKeyRecord()
{
}


void GemaltoPrivateKeyRecord::computeSign(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *output, size_t &outputLength)
{
	GemaltoToken::log("\nGemaltoPrivateKeyRecord::computeSign <BEGIN>\n");
	std::string str = "";
	GemaltoToken::toStringHex(getLabel().ptr(), getLabel().size(), str);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeSign - Label <%s>\n", str.c_str());
	str = "";
	GemaltoToken::toStringHex(getModulus().ptr(), getModulus().size(), str);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeSign - Modulus <%s>\n", str.c_str());

	if (dataLength > (mKeySize / 8))
	{
		GemaltoToken::log("## Error ## Bad data length <%lu>\n", dataLength);
		CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
	}

	if (cred && !gemaltoToken.pinStatus(1))
	{
		bool found = false;
		uint32 size = cred->size();
		for (uint32 ix = 0; ix < size; ++ix)
		{
			const TypedList &sample = (*cred)[ix];
			if (sample.type() == CSSM_SAMPLE_TYPE_PROMPTED_PASSWORD && sample.length() == 2)
            {
                CssmData &pin = sample[1].data();
                if (pin.Length >=  gemaltoToken.info()->ulMinPinLen)
                {
                    gemaltoToken.verifyPIN(1, pin.Data, pin.Length);
                    found = true;
                    break;
                }
			}
		}

		if (!found)
		{
			GemaltoToken::log("## Error ## Credentials not found\n");
			CssmError::throwMe(CSSM_ERRCODE_ACL_SUBJECT_TYPE_NOT_SUPPORTED);
		}
	}

	GemaltoToken::log("GemaltoPrivateKeyRecord::computeSign - Required Class <%lu>\n", mClass);
	std::string s = "";
	GemaltoToken::toStringHex(mKeyModulus.ptr(), mKeyModulus.size(), s);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeSign - Required Modulus <%s>\n", s.c_str());

	CK_ATTRIBUTE attrs[] =
	{
		{CKA_CLASS, &mClass, sizeof(mClass)},
		//{CKA_ID, mId.ptr(), mId.size()}};
		{ CKA_MODULUS, mKeyModulus.ptr(), mKeyModulus.size() }
	};
	CKError::check(CK_D_(C_FindObjectsInit)(gemaltoToken.session(), attrs, 2));

	CK_OBJECT_HANDLE hObject = NULL_PTR;
	try
	{
		CK_ULONG ulObjectCount;
		CKError::check(CK_D_(C_FindObjects)(gemaltoToken.session(), &hObject, 1, &ulObjectCount));
		if (ulObjectCount == 0)
		{
			GemaltoToken::log("## Error ## Private key not found\n");
			CssmError::throwMe(CSSMERR_CSP_PRIVATE_KEY_NOT_FOUND);
		}
		CK_D_(C_FindObjectsFinal)(gemaltoToken.session());
	}
	catch (...)
	{
		CK_D_(C_FindObjectsFinal)(gemaltoToken.session());
		throw;
	}

	CK_MECHANISM mechanism = { mech, NULL_PTR, 0 };
	CKError::check(CK_D_(C_SignInit)(gemaltoToken.session(), &mechanism, hObject));

	CK_ULONG dummy = outputLength;
	CKError::check(CK_D_(C_Sign)(gemaltoToken.session(), (unsigned char*) data, dataLength, output, &dummy));
	outputLength = dummy;

	GemaltoToken::log("GemaltoPrivateKeyRecord::computeSign <END>\n");
}


void GemaltoPrivateKeyRecord::computeDecrypt(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *output, size_t &outputLength)
{
	GemaltoToken::log("\nGemaltoPrivateKeyRecord::computeDecrypt <BEGIN>\n");
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - mechanism <%lu>\n", mech);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - cred <%p>\n", cred);
	char strData[6000];
	memset(strData, '\0', sizeof(strData));
	char* str = strData;
	for (size_t i=0; i<dataLength; i++)
	{
		str += sprintf(str, "%02x ", data[i]);
	}
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - dataLength <%lu> - data <%s>\n", dataLength, strData);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - output <%p>\n", output);
	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - outputLength <%lu>\n", outputLength);

	if (dataLength > (mKeySize / 8))
	{
		GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - ## Error bad data length <%lu> !\n", dataLength);
		CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
	}

	if (cred && !gemaltoToken.pinStatus(1))
	{
		bool found = false;
		uint32 size = cred->size();
		for (uint32 ix = 0; ix < size; ++ix)
		{
			const TypedList &sample = (*cred)[ix];
			if (sample.type() == CSSM_SAMPLE_TYPE_PROMPTED_PASSWORD && sample.length() == 2)
            {
                CssmData &pin = sample[1].data();
                if (pin.Length >=  gemaltoToken.info()->ulMinPinLen)
                {
                    gemaltoToken.verifyPIN(1, pin.Data, pin.Length);
                    found = true;
                    break;
                }
			}
		}

		if (!found)
		{
			GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt - ## Error cred not found!");
			CssmError::throwMe(CSSM_ERRCODE_ACL_SUBJECT_TYPE_NOT_SUPPORTED);
		}
	}

/*	CK_ATTRIBUTE attrs[] = {
		{CKA_CLASS, &mClass, sizeof(mClass)},
		{CKA_ID, mId.ptr(), mId.size()}};
*/
	CK_ATTRIBUTE attrs[] =
	{
		{CKA_CLASS, &mClass, sizeof(mClass)},
		//{CKA_ID, mId.ptr(), mId.size()}};
		{ CKA_MODULUS, mKeyModulus.ptr(), mKeyModulus.size() }
	};
	CKError::check(CK_D_(C_FindObjectsInit)(gemaltoToken.session(), attrs, 2));

	CK_OBJECT_HANDLE hObject = NULL_PTR;
	try
	{
		CK_ULONG ulObjectCount;
		CKError::check(CK_D_(C_FindObjects)(gemaltoToken.session(), &hObject, 1, &ulObjectCount));
		if (ulObjectCount == 0)
			CssmError::throwMe(CSSMERR_CSP_PRIVATE_KEY_NOT_FOUND);
		CK_D_(C_FindObjectsFinal)(gemaltoToken.session());
	}
	catch (...)
	{
		CK_D_(C_FindObjectsFinal)(gemaltoToken.session());
		throw;
	}

	CK_MECHANISM mechanism = { mech, NULL_PTR, 0 };
	CKError::check(CK_D_(C_DecryptInit)(gemaltoToken.session(), &mechanism, hObject));

	CK_ULONG dummy = outputLength;
	CKError::check(CK_D_(C_Decrypt)(gemaltoToken.session(), (unsigned char*) data, dataLength, output, &dummy));
	outputLength = dummy;

	GemaltoToken::log("GemaltoPrivateKeyRecord::computeDecrypt <END>\n");
}


void GemaltoPrivateKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	GemaltoToken::log("\nGemaltoPrivateKeyRecord::getAcl <BEGIN>\n");
	GemaltoToken::log("GemaltoPrivateKeyRecord::getAcl - tag <%s>\n", tag);

	// @@@ Key 1 has any acl for sign, key 2 has pin1 acl, and key3 has pin1
	// acl with auto-lock which we express as a prompted password subject.
	if (!mAclEntries) {
		mAclEntries.allocator(Allocator::standard());
        // Anyone can read the DB record for this key (which is a reference
		// CSSM_KEY)
        mAclEntries.add(CssmClient::AclFactory::AnySubject(
			mAclEntries.allocator()),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

		char tmptag[20];
		const uint32 slot = 1;	// hardwired for now, but...
		snprintf(tmptag, sizeof(tmptag), "PIN%d", slot);

		// Using this key to sign or decrypt will require PIN1
		mAclEntries.add(CssmClient::AclFactory::PinSubject(
			mAclEntries.allocator(), 1),
			AclAuthorizationSet(
				CSSM_ACL_AUTHORIZATION_DECRYPT,
				CSSM_ACL_AUTHORIZATION_SIGN,
				0), tmptag);
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();

	GemaltoToken::log("GemaltoPrivateKeyRecord::getAcl <END>\n");
}
