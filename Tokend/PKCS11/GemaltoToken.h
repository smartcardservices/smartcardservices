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
 * GemaltoToken.h
 * $Id$
 */

#ifndef _GEMALTOTOKEN_H_
#define _GEMALTOTOKEN_H_

#include "Token.h"

#include <security_utilities/pcsc++.h>
#include "cryptoki.h"


class GemaltoSchema;

//
// "The" token
//
class GemaltoToken : public Tokend::Token, public Tokend::TokenContext
{
	NOCOPY(GemaltoToken)
public:
	GemaltoToken();
	virtual ~GemaltoToken();

    virtual uint32 probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID]);
	virtual void establish(const CSSM_GUID *guid, uint32 subserviceId, SecTokendEstablishFlags flags, const char *cacheDirectory, const char *workDirectory, char mdsDirectory[PATH_MAX], char printName[PATH_MAX]);
	virtual void getOwner(AclOwnerPrototype &owner);
	virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

	virtual void changePIN(int pinNum, const unsigned char *oldPin, size_t oldPinLength, const unsigned char *newPin, size_t newPinLength);
	virtual uint32_t pinStatus(int pinNum);
	virtual void verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength);
	virtual void unverifyPIN(int pinNum);

	static CK_FUNCTION_LIST_PTR s_CK_pFunctionList;

	static void log(const char * format, ...);
	static void toStringHex(const unsigned char* pIn, const std::size_t &ulInLen, std::string &szOut);

	inline CK_SESSION_HANDLE session(void) const	{ return mCKSession; }
	inline const CK_TOKEN_INFO* info(void) const	{ return &mCKTokenInfo; }

protected:
	void populate();

public:
	uint32_t mPinStatus;

	// temporary ACL cache hack - to be removed
	AutoAclOwnerPrototype mAclOwner;
	AutoAclEntryInfoList mAclEntries;

private:
	int FindSlotForReader(const CK_SLOT_ID* slotId, CK_ULONG slotCount, const SCARD_READERSTATE &readerState);

	void convert_hex(unsigned char* bin, const char* hex);

typedef struct card_atr
{
	char* name;
	unsigned int length;
	unsigned char* atr;
	unsigned char* mask;
} CardAtr;

	char* trim_line(char* line);
	uint32 _pinFromAclTag(const char *tag, const char *suffix = NULL);
	void _aclClear(AutoAclEntryInfoList& acl);
	void _addPinState(AutoAclEntryInfoList& acl, uint32 slot, uint32 status);

	CK_SESSION_HANDLE	mCKSession;
	CK_SLOT_ID			mCKSlotId;
	CK_TOKEN_INFO		mCKTokenInfo;

	void*				mDLHandle;

};

#define CK_D_(_name) \
		(* (gemaltoToken.s_CK_pFunctionList -> _name))

#endif /* !_GEMALTOTOKEN_H_ */
