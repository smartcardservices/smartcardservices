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
 * GemaltoRecord.h
 * $Id$
 */

#ifndef _GEMALTORECORD_H_
#define _GEMALTORECORD_H_

#include "Record.h"
#include "cryptoki.h"

#include <security_cdsa_utilities/cssmcred.h>
#include <openssl/x509.h>

class GemaltoToken;

class GemaltoData
{
public:
	GemaltoData() : _ptr(NULL), _size(0) {}
	GemaltoData(const GemaltoData& b) : _ptr(NULL) { copy(b.ptr(), b.size()); }
	GemaltoData(CK_BYTE_PTR ptr, CK_ULONG size) : _ptr(NULL) { copy(ptr, size); }
	~GemaltoData()
	{
		if (NULL != _ptr)
		{
			delete[] _ptr;
		}
	}

	inline CK_BYTE_PTR ptr() const { return _ptr; }
	inline CK_ULONG size() const { return _size; }

	void copy(CK_BYTE_PTR ptr, CK_ULONG size)
	{
		if (NULL != _ptr)
		{
			delete[] _ptr;
		}
		_ptr = NULL;

		if (size != 0)
		{
			_ptr = new CK_BYTE[size];
			std::memcpy(_ptr, ptr, size);
		}
		_size = size;
	}

	void reserve(CK_ULONG n)
	{
		if (NULL != _ptr)
		{
			delete[] _ptr;
		}
		_ptr = NULL;

		if (n != 0)
			_ptr = new CK_BYTE[n];
		_size = n;
	}

	inline GemaltoData& operator=(const GemaltoData& b)
	{
		copy(b.ptr(), b.size());
		return *this;
	}

	inline CK_BYTE operator[](CK_ULONG n)
	{
		return *(_ptr + n);
	}

private:
	CK_BYTE_PTR	_ptr;
	CK_ULONG	_size;
};

inline bool operator==(const GemaltoData& a, const GemaltoData& b)
{
	return (a.size() == b.size() && (a.size() == 0 || std::memcmp(a.ptr(), b.ptr(), a.size()) == 0));
}

inline bool operator<(const GemaltoData& a, const GemaltoData& b)
{
	return (a.size() < b.size() || (b.size() != 0 && std::memcmp(a.ptr(), b.ptr(), b.size()) < 0));
}


class GemaltoRecord : public Tokend::Record
{
	NOCOPY(GemaltoRecord)
public:
	GemaltoRecord(GemaltoToken &gemaltoToken, CK_OBJECT_HANDLE handle);
	virtual ~GemaltoRecord();

	CK_OBJECT_HANDLE	getHandle() const	{ return mHandle; }
	CK_OBJECT_CLASS		getClass() const	{ return mClass; }

protected:
	GemaltoRecord();

	CK_OBJECT_HANDLE	mHandle;
	CK_OBJECT_CLASS		mClass;
};


class GemaltoCertRecord : public GemaltoRecord
{
	NOCOPY(GemaltoCertRecord)
public:
	GemaltoCertRecord(GemaltoToken &gemaltoToken, CK_OBJECT_HANDLE handle);
    virtual ~GemaltoCertRecord();

	const GemaltoData&	getSubject() const		{ return mSubject; }
	const GemaltoData&	getIssuer() const		{ return mIssuer; }
	const X509_NAME*	getSubjectName() const	{ return mSubjectName; }
	const X509_NAME*	getIssuerName() const	{ return mIssuerName; }

	CK_KEY_TYPE getType() const { return mKeyType; }
	uint32 sizeInBits() const { return mKeySize; }

	const GemaltoData& getKeyPubModulus() const { return mKeyModulus; }

	CK_BBOOL verify() const { return mKeyPubVerify; }
	CK_BBOOL verifyRecover() const { return (mKeyPubVerify | mKeyPrvSign); }
	CK_BBOOL encrypt() const { return (mKeyPubWrap | mKeyPubEncrypt); }
	CK_BBOOL derive() const { return FALSE; }
	CK_BBOOL wrap() const { return (mKeyPubWrap | mKeyPubEncrypt); }

	CK_BBOOL isSelfSigned() const { return mSelfSigned; }
	CK_BBOOL isCA() const { return mCA; }

	Tokend::Attribute *getDataAttribute(Tokend::TokenContext *tokenContext);

protected:
	GemaltoCertRecord();

	GemaltoData		mValue;
	GemaltoData		mSubject;
	GemaltoData		mIssuer;
	X509_NAME*		mSubjectName;
	X509_NAME*		mIssuerName;

	GemaltoData mKeyModulus;
	CK_KEY_TYPE	mKeyType;
	uint32	mKeySize;

	CK_BBOOL mKeyPubVerify;
	CK_BBOOL mKeyPubWrap;
	CK_BBOOL mKeyPubEncrypt;
	CK_BBOOL mKeyPrvSign;
	CK_BBOOL mKeyPrvUnwrap;
	CK_BBOOL mKeyPrvDecrypt;

	CK_BBOOL	mSelfSigned;
	CK_BBOOL	mCA;
};


class GemaltoKeyRecord : public GemaltoRecord
{
	NOCOPY(GemaltoKeyRecord)
public:

	GemaltoKeyRecord(const GemaltoCertRecord &certKey);

    virtual ~GemaltoKeyRecord();

	const GemaltoData& getLabel() const { return mLabel; }

	CK_KEY_TYPE getType() const { return mKeyType; }
	CK_ULONG sizeInBits() const { return mKeySize; }

	virtual CK_BBOOL verify() const { return mKeyPubVerify; }
	virtual CK_BBOOL verifyRecover() const { return mKeyPubVerify; }
	virtual CK_BBOOL encrypt() const { return (mKeyPubWrap | mKeyPubEncrypt); }
	virtual CK_BBOOL derive() const { return FALSE; }
	virtual CK_BBOOL wrap() const { return mKeyPubWrap; }

	virtual const GemaltoData& getModulus() const { return mKeyModulus; }

	virtual void computeSign(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *result, size_t &resultLength);

	virtual void computeDecrypt(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *result, size_t &resultLength);

protected:
	GemaltoKeyRecord();

	GemaltoData mLabel;

	CK_KEY_TYPE	mKeyType;
	CK_ULONG	mKeySize;
	GemaltoData mKeyModulus;

	CK_BBOOL mKeyPubVerify;
	CK_BBOOL mKeyPubWrap;
	CK_BBOOL mKeyPubEncrypt;

};


class GemaltoPrivateKeyRecord : public GemaltoKeyRecord
{
	NOCOPY(GemaltoPrivateKeyRecord)

public:
	GemaltoPrivateKeyRecord(const GemaltoCertRecord &certKey);
    virtual ~GemaltoPrivateKeyRecord();

	void computeSign(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *result, size_t &resultLength);

	void computeDecrypt(GemaltoToken &gemaltoToken, CK_ULONG mech, const AccessCredentials *cred, unsigned char *data, size_t dataLength, unsigned char *result, size_t &resultLength);

	void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

	CK_BBOOL verify() const { return mKeyPubVerify; }
	CK_BBOOL verifyRecover() const { return (mKeyPubVerify | mKeyPrvSign); }
	CK_BBOOL encrypt() const { return (mKeyPubWrap | mKeyPubEncrypt); }
	CK_BBOOL derive() const { return FALSE; }
	CK_BBOOL wrap() const { return (mKeyPubWrap | mKeyPubEncrypt); }

protected:
	CK_BBOOL mKeyPrvSign;
	CK_BBOOL mKeyPrvUnwrap;
	CK_BBOOL mKeyPrvDecrypt;

private:
	AutoAclEntryInfoList mAclEntries;

};


#endif /* !_GEMALTORECORD_H_ */
