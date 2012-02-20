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

#ifndef _include_session_h
#define _include_session_h

#include "template.h"
#include "digest.h"
#include "storageobject.h"
#include <map>

class Slot;

class CryptoOperation{
    CK_ULONG            _mechanism;
    StorageObject*      _object;

public:
    CryptoOperation(CK_ULONG mechanism,StorageObject* obj){
        this->_mechanism = mechanism;
        this->_object = obj;
    }

    ~CryptoOperation(){}

public:
    CK_ULONG    GetMechanism() { return this->_mechanism;}
    StorageObject* GetObject() { return this->_object;}
};

class Session{

public:
    CK_BBOOL                _isReadWrite;
    CK_ULONG                _state;
    vector<StorageObject*>  _objects;
    Template*               _searchTempl;
    CDigest*                _digest;
    CDigest*                _digestRSA;
    CDigest*                _digestRSAVerification;

    map<CK_ULONG, bool>     _sessionObjectsReturnedInSearch;
    map<CK_ULONG, bool>     _tokenObjectsReturnedInSearch;

    CryptoOperation*         _signature;
    CryptoOperation*         _decryption;
    CryptoOperation*         _verification;
    CryptoOperation*         _encryption;

    CK_BBOOL                _isSearchActive;
    CK_BBOOL                _isDigestActive;
    CK_BBOOL                _isDigestRSAActive;
    CK_BBOOL                _isDigestRSAVerificationActive;

    CK_ULONG                _id;
    Slot*                   _slot;

    u1Array*                _accumulatedDataToSign;
    u1Array*                _accumulatedDataToVerify;


    // Looks scary huh, the problem is that CardModule interface require
    // cryptogram as part of ChangeReferenceData method whereas
    // PKCS#11 first log SO in and then call InitPIN. InitPIN does not have any
    // information about SO PIN so what we do here is to cache it momentarily.
    // Basically during Login (as SO) we cache it and destroy it during closing
    // of session
    u1Array*                _soPIN;

public:
    Session(CK_BBOOL isReadWrite);
    ~Session();

    void SetSearchTemplate(Template* templ);
    void RemoveSearchTemplate();

    void SetDigest(CDigest* digest);
    void RemoveDigest();

    void SetEncryptionOperation(CryptoOperation* encryption);
    void RemoveEncryptionOperation();
    CK_BBOOL IsEncryptionActive();

    void SetVerificationOperation(CryptoOperation* verification);
    void RemoveVerificationOperation();
    CK_BBOOL IsVerificationActive();

    void SetDecryptionOperation(CryptoOperation* decryption);
    void RemoveDecryptionOperation();
    CK_BBOOL IsDecryptionActive();

    void SetSignatureOperation(CryptoOperation* signature);
    void RemoveSignatureOperation();
    CK_BBOOL IsSignatureActive();

    void SetDigestRSA(CDigest* digest);
    void RemoveDigestRSA();

    void SetDigestRSAVerification(CDigest* digest);
    void RemoveDigestRSAVerification();

    void UpdateState(CK_ULONG roleLogged);
    CK_BBOOL IsSearchActive();
    CK_BBOOL IsDigestActive();
    CK_BBOOL IsDigestRSAActive();
    CK_BBOOL IsDigestRSAVerificationActive();

    CK_RV AddObject(StorageObject* object,CK_OBJECT_HANDLE_PTR phObject);
    CK_RV DeleteObject(CK_OBJECT_HANDLE hObject);

    CK_ULONG FindObjects(CK_ULONG idx,CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount);

	CK_RV GetAttributeValue(CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
    CK_RV SetAttributeValue(CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);

    void SetId(CK_ULONG id);
    void SetSlot(Slot* slot);

    CK_RV GetObject(CK_OBJECT_HANDLE hObject,StorageObject** object);

private:
    CK_ULONG MakeObjectHandle(CK_ULONG idx);
};

#endif

