/*
 *  PKCS#11 library for .Net smart cards
 *  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _include_token_h
#define _include_token_h

#include <memory>
#include <string>
#include <list>
#include <map>
#include "cardmoduleservice.h"
#include "rsapublickeyobject.h"
#include "rsaprivatekeyobject.h"
#include "x509pubkeycertobject.h"
#include "cr_rsa.h"

// This class represents the data in the card/token

#define FILE_TYPE_RAW_CERT          0
#define FILE_TYPE_DATA              1
#define FILE_TYPE_CERT              2
#define FILE_TYPE_SECRETKEY         3
#define FILE_TYPE_PUBLICKEY         4
#define FILE_TYPE_PRIVATEKEY        5

#define CARD_ROLE_EVERYONE      0x00
#define CARD_ROLE_USER          0x01
#define CARD_ROLE_ADMIN         0x02

#define CARD_PERMISSION_READ    0x04
#define CARD_PERMISSION_WRITE   0x02
#define CARD_PERMISSION_EXECUTE 0x01

#define KEYSPEC_KEYEXCHANGE  0x01
#define KEYSPEC_SIGNATURE    0x02

#define KEY_TAG_UNKNOWN         0x00
#define KEY_TAG_EXPONENT        0x01
#define KEY_TAG_MODULUS         0x02
#define KEY_TAG_KEYSPEC         0x03
#define KEY_TAG_MINBITLEN       0x04
#define KEY_TAG_MAXBITLEN       0x05
#define KEY_TAG_DEFAULTBITLEN   0x06
#define KEY_TAG_INCREMENTBITLEN 0x07

#define MODE_CHANGE_PIN         0x00
#define MODE_UNBLOCK_PIN        0x01

#define MAX_USER_PIN_TRIES      0x05
#define MAX_SO_PIN_TRIES        0x05

#define MIN_PIN_LEN             4
#define MAX_PIN_LEN             24

#define RSA_KEY_MIN_LENGTH 512
#define RSA_KEY_MAX_LENGTH 2048

// Constants defining layout of the records in cmapfile
#define SIZE_CONTAINERMAPRECORD 86
#define IDX_GUID_INFO 0
#define IDX_FLAGS 80
#define IDX_SIG_KEY_SIZE 82
#define IDX_EXC_KEY_SIZE 84

// Helper structs used when sync'ing CAPI containers
// against P11 data.

struct KeyPair
{
    KeyPair() : _checkValue(0), _fP11PrivKeyExists(false), _fP11CertExists(false) {}

    u1Array _publicExponent;
    u1Array _modulus;
    u8 _checkValue;
    u1Array _cert;
    string _certName;
    bool _fP11PrivKeyExists;
    bool _fP11CertExists;
};

struct ContainerInfo
{
    ContainerInfo() : _cmapEntry(false) {}

    bool _cmapEntry;        // True if it represents a valid entry in cmapfile
    KeyPair _signKP;
    KeyPair _exchKP;
};

class CardCache;

class Token {

private:
    CardModuleService*      _mscm;

    bool                    _initialized;
    bool                    _supportGarbageCollection;
    vector<StorageObject*>  _objects;
    vector<string>          _toDelete;          // List of files to be deleted at next login
    CardCache *             _cardCache;
    unsigned long           _cardCfTimer;       // Timer indicating when _cardCf was last known to be up-to-date
    CK_ULONG                _cardCf;            // Current state from \cardcf
    CK_ULONG                _publCardCf;        // Reflects state of public cached objects
    CK_ULONG                _privCardCf;        // Reflects state of private cached objects
    CK_ULONG                _cacheCardCf;       // Reflects state of card cache (_cardCache)

    bool                    _fPinChanged;
    bool                    _fContainerChanged;
    bool                    _fFileChanged;
   
    BYTE m_bCardMode;
    BYTE m_bTypePIN;
    //u1Array* m_u1aSerialNumber;

public:
    CK_BBOOL                _version;
    CK_TOKEN_INFO           _tokenInfo;
    CK_ULONG                _roleLogged;
    //bool m_isPinExternal;
    bool m_bIsPinPadSupported;
    bool m_bIsSSO;
    bool m_bIsNoPinSupported;

public:
    Token(std::string* reader);
    ~Token();

    CardModuleService* /*const*/ GetMiniDriverService( void ) { return _mscm; };

    void Clear();
    void BeginTransaction();
    void EndTransaction();
    void CardBeginTransaction();
    void CardEndTransaction();
    void ManageGC( bool bForceGarbage = false );

    CK_RV Login(CK_ULONG userType,u1Array* pin);
    CK_RV Logout();
    CK_RV GenerateRandom(CK_BYTE_PTR randomData,CK_ULONG len);
    CK_RV AddObject(auto_ptr<StorageObject> & stobj, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV AddPrivateKeyObject(auto_ptr<StorageObject> & stobj,CK_OBJECT_HANDLE_PTR phObject);
    CK_RV AddCertificateObject(auto_ptr<StorageObject> & stobj,CK_OBJECT_HANDLE_PTR phObject);
    CK_RV DeleteObject(CK_OBJECT_HANDLE hObject);
    CK_ULONG FindObjects(Session* session,CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount);

    CK_RV GetAttributeValue(CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
    CK_RV SetAttributeValue(CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);

    CK_RV GenerateKeyPair(auto_ptr<StorageObject> & stobjRsaPub, auto_ptr<StorageObject> & stobjRsaPriv,
                          CK_OBJECT_HANDLE_PTR phPubKey,CK_OBJECT_HANDLE_PTR phPrivKey);

    CK_RV GetObject(CK_OBJECT_HANDLE hObject,StorageObject** object);

    CK_RV Sign(StorageObject* privObj,u1Array* dataToSign,CK_ULONG mechanism,CK_BYTE_PTR pSignature);
    CK_RV Decrypt(StorageObject* privObj,u1Array* dataToDecrypt,CK_ULONG mechanism,CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV Verify(StorageObject* pubObj,u1Array* dataToVerify,CK_ULONG mechanism,u1Array* signature);
    CK_RV Encrypt(StorageObject* pubObj,u1Array* dataToEncrypt,CK_ULONG mechanism,CK_BYTE_PTR pEncryptedData);

    CK_RV InitToken(u1Array* pin,u1Array* label);
    CK_RV InitPIN(u1Array* soPIN,u1Array* userPIN);
    CK_RV SetPIN(u1Array* oldPIN,u1Array* newPIN);

    bool isAuthenticated( void );
    bool isSSO( void );
    bool isNoPinSupported( void );

private:

   void getCardConfiguration( BYTE& a_bMode, BYTE &a_bTypePIN );
   BYTE howToAuthenticate( BYTE bPinLen );
   bool isPinPadSupported( void );
   //bool isPinExternalSupported( void );
   CK_RV verifyPinWithPinPad( void );
   CK_RV verifyPinWithBio( void /*Marshaller::u1Array *pin*/ );
   DWORD m_dwIoctlVerifyPIN;

   std::string m_sReaderName;
    void Initialize();
    void Resynchronize();
    CK_RV AuthenticateUser(u1Array* pin);
    CK_RV AuthenticateAdmin(u1Array* key);
    void CreateDirIfNotPresent(std::string* parent,std::string* dir,u1Array* acls);
    bool IsInitialized();
    void PopulateDefaultTokenInfo();
    void SerializeTokenInfo();
    void DeserializeTokenInfo();
    CK_BYTE GetAvailableContainerIndex(u1Array const & cmapContents);
    CK_BYTE GetContainerForCert(u1Array const & cmapContents, u8 checkValue, u1 * keySpec);
    CK_BYTE GetContainerForPrivateKey(u1Array const & cmapContents, u8 checkValue, u1 * keySpec);

    auto_ptr<u1Array> UpdateCMap(CK_BYTE ctrIdx,u1Array const & contents,string const & contName);
    auto_ptr<u1Array> UpdateCMap(CK_BYTE ctrIdx,u1Array const & contents,u4 keySize,u1 keySpec,
                                 CK_BBOOL isDefault, string const & contName);

    vector <PrivateKeyObject*> FindPrivateKeys(vector<StorageObject*> const & objects, u8 checkValue);
    PrivateKeyObject* FindPrivateKey(vector<StorageObject*> const & objects, CK_BYTE ctrdIdx, u1 keySpec);
    vector <CertificateObject*> FindCertificates(vector<StorageObject*> const & objects, u8 checkValue);
    CertificateObject* FindCertificate(vector<StorageObject*> const & objects, CK_BYTE ctrdIdx, u1 keySpec);

    u1Array* PadRSAPKCS1v15(u1Array* dataToSign,CK_ULONG modulusLen);
    u1Array* PadRSAX509(u1Array* dataToSign,CK_ULONG modulusLen);
    u1Array* EncodeHashForSigning(u1Array* hashedData,CK_ULONG modulusLen,CK_ULONG hashAlgo);

    CK_BBOOL IsSynchronized();
    void SynchronizeCertificates(vector<StorageObject*> & objects, map<int, ContainerInfo> & contMap);
    void SynchronizePrivateKeys(vector<StorageObject*> & objects, map<int, ContainerInfo> & contMap);
    void PrepareCertAttributesFromRawData(X509PubKeyCertObject* certObject);
    bool PerformDeferredDelete();
    string FindFreeFileName(StorageObject* object);
    CK_RV WriteObject(StorageObject* object);

    void ReadAndPopulateObjects(vector<StorageObject*> & objects, vector<string> & toDelete,
                                std::string const & prefix, map<int, ContainerInfo> & contMap);
    void SynchronizePublicObjects(vector<StorageObject*> & objects, vector<string> & toDelete, map<int, ContainerInfo> & contMap);
    void SynchronizePrivateObjects(vector<StorageObject*> & objects, vector<string> & toDelete, map<int, ContainerInfo> & contMap);
    void BuildContainerInfoMap(map<int, ContainerInfo> & contMap);
    void DeleteCMapRecord(CK_BYTE ctrdIdx);
    void RemoveKeyFromCMapRecord(CK_BYTE ctrIndex, u1 keySpec);
    void SetDefaultContainer(u1Array & contents, CK_BYTE ctrIndex);
    u1Array* ComputeCryptogram(u1Array* challenge,u1Array* pin);
    CK_RV VerifyRSAPKCS1v15(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen);
    CK_RV VerifyRSAX509(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen);
    CK_RV VerifyHash(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen,CK_ULONG hashAlgo);

    static CK_RV DoPINValidityChecks(u1Array* pin, bool fCheckCharaceters = true);
    s4 RegisterStorageObject(StorageObject * object);
    void UnregisterStorageObject(StorageObject * object);
    auto_ptr<u1Array> ReadCertificateFile(string const & path);
    void RegisterPinUpdate();
    void RegisterContainerUpdate();
    void RegisterFileUpdate();
    //void CheckAvailableSpace();
    StorageObject * GetObject(CK_OBJECT_HANDLE hObject);

};


#endif

