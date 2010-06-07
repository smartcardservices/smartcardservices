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
 * GemaltoToken.cpp
 * $Id$
 */

#include "GemaltoToken.h"

#include "Adornment.h"
#include "AttributeCoder.h"
#include "SCardError.h"
#include "GemaltoError.h"
#include "GemaltoRecord.h"
#include "GemaltoSchema.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <security_cdsa_client/aclclient.h>
#include <map>
#include <vector>
#include <stdarg.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <dirent.h>

extern "C" const char *cssmErrorString(OSStatus status);

using CssmClient::AclFactory;

CK_FUNCTION_LIST_PTR GemaltoToken::s_CK_pFunctionList = NULL;

#define gemaltoToken	(*this)

#define GEMALTO_MAX_SLOT_COUNT	16

/* search PKCS#11 libs here.
 * See http://wiki.cacert.org/wiki/Pkcs11TaskForce */
#define PKCS11LIB_PATH "/usr/lib/pkcs11/"


GemaltoToken::GemaltoToken() :
	mPinStatus(0),
	mCKSession(CK_INVALID_HANDLE),
	mDLHandle(NULL)
{
	log("\nGemaltoToken::GemaltoToken <BEGIN>\n");

	mTokenContext = this;

	// Initialize libcrypto
	::ERR_load_crypto_strings();
	::X509V3_add_standard_extensions();

	log("GemaltoToken::GemaltoToken <END>\n");
}


GemaltoToken::~GemaltoToken()
{
	log("\nGemaltoToken::~GemaltoToken <BEGIN>\n");

	if (NULL != mSchema)
	{
		delete mSchema;
	}

	try
	{
		if (s_CK_pFunctionList)
		{
			CK_D_(C_Logout)(mCKSession);
			log("GemaltoToken::~GemaltoToken <LogOut>\n");

			if (mCKSession != CK_INVALID_HANDLE)
			{
				CK_D_(C_CloseSession)(mCKSession);
				mCKSession = CK_INVALID_HANDLE;
			}
			log("GemaltoToken::~GemaltoToken <CloseSession>\n");

			CK_D_(C_Finalize)(NULL_PTR);

			//(*(GemaltoToken::s_CK_pFunctionList->C_Finalize))(NULL_PTR);
			log("GemaltoToken::~GemaltoToken <Finalize>\n");

			s_CK_pFunctionList = NULL;
		}
	}
	catch(...)
	{
		log("## Error ## Crash \n");
	}

	if (NULL != mDLHandle)
	{
		dlclose(mDLHandle);
	}

	log("GemaltoToken::~GemaltoToken <END>\n");
}


void GemaltoToken::changePIN(int pinNum, const unsigned char *oldPin, size_t oldPinLength, const unsigned char *newPin, size_t newPinLength)
{
	log("\nGemaltoToken::changePIN <BEGIN>\n");
	//log("pinNum <%d> - oldPin <%.*s> - newPin <%.*s>\n", pinNum, (int) oldPinLength, oldPin, (int) newPinLength, newPin);

	if (pinNum != 1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	if (oldPinLength < mCKTokenInfo.ulMinPinLen || oldPinLength > mCKTokenInfo.ulMaxPinLen ||
		newPinLength < mCKTokenInfo.ulMinPinLen || newPinLength > mCKTokenInfo.ulMaxPinLen)
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);

	CK_BYTE* pOldPIN = new CK_BYTE[oldPinLength];
	memset(pOldPIN, 0, sizeof(CK_BYTE) * oldPinLength);
	for(size_t i = 0 ; i < oldPinLength ; i++)
	{
		pOldPIN[ i ] = (CK_BYTE)oldPin[ i ];
	}

	CK_BYTE* pNewPIN = new CK_BYTE[newPinLength];
	memset(pNewPIN, 0, sizeof(CK_BYTE) * newPinLength);
	for(size_t j = 0 ; j < newPinLength ; j++)
	{
		pNewPIN[ j ] = (CK_BYTE)newPin[ j ];
	}

	// Log the user only if he was not previously logged in
	bool bUserAlreadyLoggedIn = false;
	CK_RV rv = CK_D_(C_Login)(mCKSession, CKU_USER, pOldPIN, oldPinLength);
	if (rv == CKR_USER_ALREADY_LOGGED_IN)
	{
		bUserAlreadyLoggedIn = true;
	}
	else if (rv != CKR_OK)
	{
		delete[] pOldPIN;
		delete[] pNewPIN;

		log("GemaltoToken::changePIN - ## Error ## <%ld>\n", rv);

		CKError::check(rv);
	}

	// Change PIN
	rv = CK_D_(C_SetPIN)(mCKSession, pOldPIN, oldPinLength, pNewPIN, newPinLength);
	delete[] pOldPIN;
	delete[] pNewPIN;
	CKError::check(rv);

	// LogOut only if the user not previously logged in
	if (false == bUserAlreadyLoggedIn)
	{
		CKError::check(CK_D_(C_Logout)(mCKSession));
	}

	mPinStatus = SCARD_SUCCESS;

	log("GemaltoToken::changePIN <END>\n");
}


uint32_t GemaltoToken::pinStatus(int pinNum)
{
	log("\nGemaltoToken::pinStatus <BEGIN>\n");
	log("pinNum <%d>\n", pinNum);

	if (pinNum != 1)
	{
		log("## Error ##  pinStatus CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED\n");
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
	}

	log("GemaltoToken::pinStatus <END>\n");

	return mPinStatus;
}


void GemaltoToken::verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
	log("\nGemaltoToken::verifyPIN <BEGIN>\n");
	//log("pinNum <%d> - pin <%.*s>\n", pinNum, (int) pinLength, pin);

	if (pinNum != 1)
	{
		log("GemaltoToken::verifyPIN - ## ERROR ## Invalid pinNum <%d>\n", pinNum);
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
	}

	if ((pinLength < mCKTokenInfo.ulMinPinLen) || (pinLength > mCKTokenInfo.ulMaxPinLen))
	{
		log("GemaltoToken::verifyPIN - ## ERROR ## Invalid PIN length\n");
		CssmError::throwMe(CSSM_ERRCODE_INVALID_SAMPLE_VALUE);
	}

	CK_BYTE* pPIN = new CK_BYTE[pinLength];
	memset(pPIN, 0, sizeof(CK_BYTE) * pinLength);
	for(size_t i = 0 ; i < pinLength ; i++)
	{
		pPIN[ i ] = (CK_BYTE)pin[ i ];
	}

	CK_RV rv = CK_D_(C_Login)(mCKSession, CKU_USER, pPIN, pinLength);

	mPinStatus = SCARD_AUTHENTICATION_FAILED;
	if ((CKR_OK == rv) || (CKR_USER_ALREADY_LOGGED_IN == rv))
	{
		mPinStatus = SCARD_SUCCESS;
	}
	else
	{
		log("GemaltoToken::verifyPIN - ## Error ## <%ld>\n", rv);

		if (CKR_PIN_LOCKED == rv)
		{
			mPinStatus = SCARD_AUTHENTICATION_BLOCKED;
		}
	}

	delete[ ] pPIN;


	log("GemaltoToken::verifyPIN <END>\n");
}


void GemaltoToken::unverifyPIN(int pinNum)
{
	log("\nGemaltoToken::unverifyPIN <BEGIN>\n");
	log("pinNum <%d>\n", pinNum);

	if (pinNum != -1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	try
	{
		CKError::check(CK_D_(C_Logout)(mCKSession));
	}
	catch (CKError& err)
	{
		if (err.resultValue != CKR_USER_NOT_LOGGED_IN)
			throw;
	}

	mPinStatus = 0;

	log("GemaltoToken::unverifyPIN <END>\n");
}


#define PKCS11_FAILED(fct, rv) log("GemaltoToken::probe - " fct "() failed: %s\n", pkcs11_error(rv));
uint32 GemaltoToken::probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID])
{
	log("\nGemaltoToken::probe <BEGIN>\n");
	log("GemaltoToken::probe - flags <%x>\n", (unsigned int) flags);
	log("GemaltoToken::probe - tokenUid <%s>\n", tokenUid);

	uint32 score = 0;

	try
	{
		const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();
		if (readerState.cbAtr)
		{
			log("GemaltoToken::probe - Reader <%s>\n", readerState.szReader);
			std::string s = "";
			GemaltoToken::toStringHex(readerState.rgbAtr, readerState.cbAtr, s);
			log("GemaltoToken::probe - ATR <%s>\n", s.c_str());

			DIR *dirp = opendir(PKCS11LIB_PATH);
			if (NULL == dirp)
				CKError::throwMe(CKR_GENERAL_ERROR);

			bool found = false;
			struct dirent *dir_entry;
			while (!found && (dir_entry = readdir(dirp)) != NULL)
			{
				std::string lib_name = PKCS11LIB_PATH;
				const char* dlPath;
				CK_FUNCTION_LIST_PTR p;
				CK_RV rv;
				
				/* skip . and .. entries */
				if ((strcmp(dir_entry->d_name, ".") == 0) || (strcmp(dir_entry->d_name, "..") == 0))
					continue;
				
				/* only use files ending with ".dylib" */
#define VALID_FILE_EXTENSION ".dylib"
				char *ext = dir_entry->d_name + strlen(dir_entry->d_name) - sizeof(VALID_FILE_EXTENSION)+1;
				if (/* file name is at least as long as the extention */
					ext > dir_entry->d_name
					&& strcasecmp(ext, VALID_FILE_EXTENSION) != 0)
					continue;

				lib_name.append(dir_entry->d_name);
				dlPath = lib_name.c_str();
				log("GemaltoToken::probe - Using %s PKCS#11 library\n", dlPath);
				
				mDLHandle = dlopen(dlPath, RTLD_LAZY | RTLD_GLOBAL);
				if (NULL == mDLHandle)
				{
					log("GemaltoToken::probe - ## ERROR ## Cannot load the PKCS#11 library\n");
					continue;
				}
				
				CK_C_GetFunctionList C_GetFunctionList_PTR = (CK_C_GetFunctionList) dlsym(mDLHandle, "C_GetFunctionList");
				if (NULL == C_GetFunctionList_PTR)
				{
					log("GemaltoToken::probe - ## ERROR ## Cannot load the PKCS#11 function list\n", dlerror());
					continue;
				}
				
				/* ---- Cryptoki library standard initialization ---- */
				rv = (*C_GetFunctionList_PTR)(&s_CK_pFunctionList);
				if (rv != CKR_OK)
				{
					PKCS11_FAILED("C_GetFunctionList", rv);
					continue;
				}
				
				rv = CK_D_(C_Initialize)(NULL_PTR);
				if (rv != CKR_OK)
				{
					PKCS11_FAILED("C_Initialize", rv);
					continue;
				}

				CK_ULONG ulSlotCount = GEMALTO_MAX_SLOT_COUNT;
				CK_SLOT_ID pSlotID[GEMALTO_MAX_SLOT_COUNT];
				rv = CK_D_(C_GetSlotList)(CK_TRUE, pSlotID, &ulSlotCount);
				if (rv != CKR_OK)
				{
					PKCS11_FAILED("C_GetSlotList", rv);
					continue;
				}
				
				for (CK_ULONG i=0; i<ulSlotCount; i++)
				{
					CK_SLOT_INFO slotInfo;
					rv = CK_D_(C_GetSlotInfo)(pSlotID[i], &slotInfo);
					if (rv != CKR_OK)
					{
						PKCS11_FAILED("C_GetSlotInfo", rv);
						continue;
					}
					
					/* check that the PKCS#11 slot is using the reader selected by the tokend */
					if (strncmp((char*) slotInfo.slotDescription, readerState.szReader, strlen(readerState.szReader)) == 0)
					{
						rv  = CK_D_(C_GetTokenInfo)(pSlotID[i], &mCKTokenInfo);
						if (rv != CKR_OK)
						{
							PKCS11_FAILED("C_GetTokenInfo", rv);
							continue;
						}
						
						// Verify if token is initialized
						if ((mCKTokenInfo.flags & CKF_USER_PIN_INITIALIZED) != CKF_USER_PIN_INITIALIZED)
						{
							// ?????????
							//CKError::throwMe(CKR_USER_PIN_NOT_INITIALIZED);
						}
						
						score = 500;
						
						// Setup the tokendUID
						char label[ sizeof(mCKTokenInfo.label)+1 ];
						label[sizeof(mCKTokenInfo.label)] = '\0';
						memcpy(label, mCKTokenInfo.label,  sizeof(mCKTokenInfo.label));
						char* trimLabel = trim_line(label);
						snprintf(tokenUid, TOKEND_MAX_UID, "Gemalto smartcard %s (%.*s)", trimLabel, (int) sizeof(mCKTokenInfo.serialNumber), mCKTokenInfo.serialNumber);
						
						for (size_t len=strlen(tokenUid); tokenUid[len-1]==' '; len--)
							tokenUid[len-1] = '\0';
						log("tokenUid <%s>\n", tokenUid);

						found = true;
						mCKSlotId = pSlotID[i];
						break;
					}
				}

				/* Not the correct PKCS#11 lib. Close it and try the next one */
				if (!found)
				{
					rv = CK_D_(C_Finalize)(NULL_PTR);
					if (rv != CKR_OK)
						PKCS11_FAILED("C_Finalize", rv);
					s_CK_pFunctionList = NULL;

					dlclose(mDLHandle);
					mDLHandle = NULL;
				}
			}
			(void)closedir(dirp);
		}
	}
	catch (...)
	{
		score = 0;
	}

	log("GemaltoToken::probe <END>\n");

	return score;
}


void GemaltoToken::establish(const CSSM_GUID *guid, uint32 subserviceId, SecTokendEstablishFlags flags, const char *cacheDirectory, const char *workDirectory, char mdsDirectory[PATH_MAX], char printName[PATH_MAX])
{
	log("\nGemaltoToken::establish <BEGIN>\n");
	log("flags <%x> - cacheDirectory <%s> - workDirectory <%s>\n", (unsigned int)flags, cacheDirectory, workDirectory);

	Token::establish(guid, subserviceId, flags, cacheDirectory, workDirectory, mdsDirectory, printName);

	mSchema = new GemaltoSchema();
	mSchema->create();

	if (mCKSession == CK_INVALID_HANDLE)
		CKError::check(CK_D_(C_OpenSession)(mCKSlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION , NULL_PTR, NULL_PTR, &mCKSession));

	populate();

	char label[ 33 ];
	memset(label, 0, sizeof(label));
	memcpy(label, mCKTokenInfo.label,  sizeof(mCKTokenInfo.label));
 	char* trimLabel = trim_line(label);
	snprintf(printName, PATH_MAX, "Gemalto smartcard %s (%.*s)", trimLabel, (int) sizeof(mCKTokenInfo.serialNumber), mCKTokenInfo.serialNumber);
	for (size_t len=strlen(printName); printName[len-1]==' '; len--)
		printName[len-1] = '\0';

	log("printName <%s>\n", printName);
	log("GemaltoToken::establish <END>\n");
}


//
// Database-level ACLs
//
void GemaltoToken::getOwner(AclOwnerPrototype &owner)
{
	log("\nGemaltoToken::getOwner <BEGIN>\n");

	// we don't really know (right now), so claim we're owned by PIN #1
	if (!mAclOwner) {
		mAclOwner.allocator(Allocator::standard());
		mAclOwner = AclFactory::PinSubject(mAclOwner.allocator(), 1);
	}
	owner = mAclOwner;

	log("GemaltoToken::getOwner <END>\n");
}


void GemaltoToken::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	log("\nGemaltoToken::getAcl <BEGIN>\n");
	log("tag <%s> - count <%lu>\n", tag, count);

	Allocator &alloc = Allocator::standard();

	if (uint32 pin = _pinFromAclTag(tag, "?"))
	{
		static AutoAclEntryInfoList acl;
		_aclClear(acl);
		acl.allocator(alloc);
		uint32_t status = this->pinStatus(pin);
		if (status == SCARD_SUCCESS)
		{
			_addPinState(acl, pin, CSSM_ACL_PREAUTH_TRACKING_AUTHORIZED);
		}
		else if (SCARD_AUTHENTICATION_BLOCKED == status)
		{
			_addPinState(acl, pin, CSSM_ACL_PREAUTH_TRACKING_BLOCKED);
		}
		else
		{
			_addPinState(acl, pin, CSSM_ACL_PREAUTH_TRACKING_UNKNOWN);
		}
		count = acl.size();
		acls = acl.entries();

		log("count <%lu>\n", count);

		log("GemaltoToken::getAcl <END>\n");
		return;
	}

	// get pin list, then for each pin
	if (!mAclEntries)
	{
		mAclEntries.allocator(alloc);

		// Anyone can read the attributes and data of any record on this token
        // (it's further limited by the object itself).
		mAclEntries.add(CssmClient::AclFactory::AnySubject(	mAclEntries.allocator()), AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

        // We support PIN1 with either a passed in password subject or a prompted password subject.
		mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 1);
		mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
		mAclEntries.addPin(AclFactory::PinSubject(mAclEntries.allocator(), CssmData()), 1);
	}

	count = mAclEntries.size();
	acls = mAclEntries.entries();

	log("count <%lu>\n", count);
	log("GemaltoToken::getAcl <END>\n");
}


#pragma mark ---------------- Gemalto Specific --------------


void GemaltoToken::populate()
{
	log("\nGemaltoToken::populate <BEGIN>\n");

	Tokend::Relation &certRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
	Tokend::Relation &privateKeyRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);

	// Find all certificates into the smartcard
	CK_OBJECT_CLASS	ulClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE classAttr = { CKA_CLASS, &ulClass, sizeof(CK_OBJECT_CLASS) };
	CKError::check(CK_D_(C_FindObjectsInit)(mCKSession, &classAttr, 1));
	while (1)
	{
		CK_OBJECT_HANDLE ulObject = CK_INVALID_HANDLE;
		CK_ULONG ulObjectCount = 0;

		CKError::check(CK_D_(C_FindObjects)(mCKSession, &ulObject, 1, &ulObjectCount));
		if (0 == ulObjectCount)
		{
			log("GemaltoToken::populate - No more certificate into the smartcard. Nothing more to do !!!\n");
			break;
		}

		log("GemaltoToken::populate - Found a certificate into the smartcard \n");

		// Create a certificate instance
		RefPointer<GemaltoCertRecord> cert(new GemaltoCertRecord(*this, ulObject));
		certRelation.insertRecord(cert);

		// If the current certificate is not a ROOT CA certificate
		if (false == cert->isCA())
		{
			// If the current certificat is able to perform a cryptographic operation
			if (cert->verify() || cert->verifyRecover() || cert->encrypt() || cert->wrap())
			{
				log("GemaltoToken::populate - The current certificate is not a ROOT and owns private key usage(s). Create associated private key.\n");

				// Create a private key
				RefPointer<GemaltoKeyRecord> keyPrvRecord(new GemaltoPrivateKeyRecord(*cert));
				privateKeyRelation.insertRecord(keyPrvRecord);

				// The Adornment class links a particular CertificateRecord with its corresponding KeyRecord record
				keyPrvRecord->setAdornment(mSchema->publicKeyHashCoder().certificateKey(), new Tokend::LinkedRecordAdornment(cert));
			}
		}
	}
	CK_D_(C_FindObjectsFinal)(mCKSession);

	log("GemaltoToken::populate <END>\n");
}


void GemaltoToken::convert_hex(unsigned char* bin, const char* hex)
{
	char* dummy;
	char nibble[3];
	nibble[2] = 0;

	while (*hex) {
		nibble[0] = *hex++;
		if (*hex)
			nibble[1] = *hex++;
		else
			nibble[1] = '0';
		*bin++ = strtoul(nibble, &dummy, 16);
	}
}


char* GemaltoToken::trim_line(char* line)
{
	char* p = line;
	while (*p && isblank(*p))
		p++;
	char* e = p + strlen(p) - 1;
	while (e >= p && isspace(*e))
		*e-- = 0;
	return p;
}

//
// Extract the pin number from a "PIN%d?" tag.
// Returns 0 if the tag isn't of that form.
//
uint32 GemaltoToken::_pinFromAclTag(const char *tag, const char *suffix)
{
	if (tag)
	{
		char format[20];
		snprintf(format, sizeof(format), "PIN%%d%s%%n", suffix ? suffix : "");
		uint32 pin;
		unsigned consumed;
		sscanf(tag, format, &pin, &consumed);
		if (consumed == strlen(tag))	// complete and sufficient
			return pin;
	}
	return 0;
}


void GemaltoToken::_aclClear(AutoAclEntryInfoList& acl)
{
	if (acl == true)
	{
		DataWalkers::ChunkFreeWalker w(acl.allocator());
		for (uint32 ix = 0; ix < acl.size(); ix++)
			walk(w, acl.at(ix));
		acl.size(0);
	}
}


void GemaltoToken::_addPinState(AutoAclEntryInfoList& acl, uint32 slot, uint32 status)
{
	char tag[20];
	snprintf(tag, sizeof(tag), "PIN%d?", (int) slot);

	TypedList subj(acl.allocator(), CSSM_WORDID_PIN, new(acl.allocator()) ListElement(slot), new(acl.allocator()) ListElement(status));

	acl.add(subj, CSSM_WORDID_PIN, tag);
}


#pragma mark ---------------- Gemalto Debug --------------


// Define if you want to activate trace into the code
#undef __DEBUG_GEMALTO__

void GemaltoToken::toStringHex(const unsigned char* buffer, const std::size_t& size, std::string &result)
{
#ifdef __DEBUG_GEMALTO__
	if ((NULL == buffer) || (1 > size))
	{
		//result.assign("null");
		return;
	}

    std::ostringstream oss;
	oss.rdbuf()->str("");

    // Afficher en hexadecimal et en majuscule
    oss << std::hex << std::uppercase;

    // Remplir les blancs avec des zŽros
    oss << std::setfill('0');

    for(std::size_t i = 0; i < size; ++i)
    {
        // Separer chaque octet par un espace
        /*if (i != 0)
            oss << ' ';*/

        // Afficher sa valeur hexadécimale précédée de "0x"
        // setw(2) permet de forcer l'affichage à 2 caractères
        oss << /*"0x" <<*/ std::setw(2) << static_cast<int>(buffer[i]);
    }

    result.assign(oss.str());
#endif
}

#define LOG_FILE "/tmp/Gemalto.TokenD.log"
/* Log a message into the LOG_FILE file */
void GemaltoToken::log(const char * format, ...)
{
#ifdef __DEBUG_GEMALTO__
	// Try to open the file
	FILE* pLog = fopen(LOG_FILE, "a");
	if (NULL == pLog)
	{
		// The file does not exit
		// Nothing to log
		return;
	}

	va_list args;
	va_start(args, format);

	vfprintf(pLog, format, args);
	va_end(args);

	// Close the file
	fclose(pLog);
#endif
}
