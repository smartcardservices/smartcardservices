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

#include "stdafx.h"
#include <winscard.h>      // inclusion needed for linux
#include "platconfig.h"
#include "config.h"
#include "thread.h"
#include "event.h"
#include "template.h"
#include "session.h"
#include "slot.h"

Session::Session(CK_BBOOL isReadWrite){
    this->_isReadWrite    = isReadWrite;
    this->_searchTempl    = NULL_PTR;
    this->_isSearchActive = CK_FALSE;

    this->_digest         = NULL_PTR;
    this->_digestRSA      = NULL_PTR;
    this->_digestRSAVerification = NULL_PTR;

    this->_isDigestActive = CK_FALSE;
    this->_isDigestRSAActive = CK_FALSE;
    this->_isDigestRSAVerificationActive = CK_FALSE;

    this->_signature = NULL_PTR;
    this->_decryption     = NULL_PTR;
    this->_encryption     = NULL_PTR;
    this->_verification   = NULL_PTR;

    this->_soPIN     = NULL_PTR;

    this->_accumulatedDataToSign = NULL_PTR;
    this->_accumulatedDataToVerify = NULL_PTR;

    _objects.clear();
    _sessionObjectsReturnedInSearch.clear();
    _tokenObjectsReturnedInSearch.clear();
}

Session::~Session(){

    for(size_t i = 0; i < _objects.size(); i++){
        delete _objects[i];
        _objects[i] = NULL_PTR;
    }

    if(this->_digest != NULL_PTR){
        delete this->_digest;
    }

    if(this->_digestRSA != NULL_PTR){
        delete this->_digestRSA;
    }

    if(this->_digestRSAVerification != NULL_PTR){
        delete this->_digestRSAVerification;
    }

    if(this->_signature != NULL_PTR){
        delete this->_signature;
    }

    if(this->_decryption != NULL_PTR){
        delete this->_decryption;
    }

    if(this->_encryption != NULL_PTR){
        delete this->_encryption;
    }

    if(this->_verification != NULL_PTR){
        delete this->_verification;
    }

    if(this->_soPIN != NULL_PTR){
        delete this->_soPIN;
    }

    if(this->_accumulatedDataToSign != NULL_PTR){
        delete this->_accumulatedDataToSign;
    }

    if(this->_accumulatedDataToVerify != NULL_PTR){
        delete this->_accumulatedDataToVerify;
    }
}

void Session::SetSearchTemplate(Template* templ)
{
    PKCS11_ASSERT(this->_isSearchActive == CK_FALSE);

    this->_searchTempl = templ;
    this->_isSearchActive = CK_TRUE;

    _tokenObjectsReturnedInSearch.clear();
    _sessionObjectsReturnedInSearch.clear();
}

void Session::RemoveSearchTemplate()
{
    if(this->_searchTempl != NULL_PTR){
        delete this->_searchTempl;
        this->_searchTempl = NULL_PTR;
    }

    this->_isSearchActive = CK_FALSE;
}

void Session::UpdateState(CK_ULONG roleLogged)
{
    if(this->_isReadWrite)
    {
        switch(roleLogged)
        {
            case CKU_NONE:
                this->_state = CKS_RW_PUBLIC_SESSION;
                break;

            case CKU_SO:
                this->_state = CKS_RW_SO_FUNCTIONS;
                break;

            case CKU_USER:
                this->_state = CKS_RW_USER_FUNCTIONS;
                break;
        }
    }
    else
    {
        switch(roleLogged)
        {
            case CKU_NONE:
                this->_state = CKS_RO_PUBLIC_SESSION;
                break;

            case CKU_USER:
                this->_state = CKS_RO_USER_FUNCTIONS;
                break;
        }
    }
}

CK_BBOOL Session::IsSearchActive()
{
    return this->_isSearchActive;
}

void Session::SetId(CK_ULONG id)
{
    this->_id = id;
}

void Session::SetSlot(Slot* slot)
{
    this->_slot = slot;
}

CK_ULONG Session::MakeObjectHandle(CK_ULONG idx)
{
     CK_ULONG objHandle = CO_SESSION_OBJECT | idx;
     objHandle = (this->_id << 16) | objHandle;

     return objHandle;
}

CK_ULONG Session::FindObjects(CK_ULONG idx,CK_OBJECT_HANDLE_PTR phObject,
                              CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount)
{

    PKCS11_ASSERT(this->_isSearchActive);

    for(CK_LONG i=0;i<static_cast<CK_LONG>(_objects.size()) && (idx < ulMaxObjectCount);i++){

        if(this->_objects[i] == NULL_PTR){
            continue;
        }

        if(this->_sessionObjectsReturnedInSearch[i] == CK_TRUE){
            continue;
        }

        if((this->_objects[i]->_private == CK_TRUE) &&
            (this->_slot->_token->_roleLogged != CKU_USER))
        {
            continue;
        }

        if(this->_searchTempl == NULL_PTR){
            phObject[idx++] = MakeObjectHandle(i+1);
            *pulObjectCount = *pulObjectCount + 1;
            this->_sessionObjectsReturnedInSearch[i] = CK_TRUE;
        }
        else{
            CK_BBOOL match = CK_TRUE;

            vector<CK_ATTRIBUTE> attributes = this->_searchTempl->_attributes;
            for(CK_ULONG a=0;a<attributes.size();a++){
                if(this->_objects[i]->Compare(attributes.at(a)) == CK_FALSE){
                    match = CK_FALSE;
                    break;
                }
            }

            if(match == CK_TRUE){
                phObject[idx++] = MakeObjectHandle(i+1);
                *pulObjectCount = *pulObjectCount + 1;
                this->_sessionObjectsReturnedInSearch[i] = CK_TRUE;
            }

        }
    }

    return idx;
}

CK_RV Session::AddObject(StorageObject* obj,CK_OBJECT_HANDLE_PTR phObject)
{
    for(CK_ULONG i = 0; i < static_cast<CK_ULONG>(_objects.size()); i++)
    {
        if(this->_objects[i] == NULL_PTR)
        {
            this->_objects[i] = obj;
            *phObject = MakeObjectHandle(i+1);

            return CKR_OK;
        }
    }

    _objects.push_back(obj);

    *phObject = MakeObjectHandle(static_cast<CK_ULONG>(_objects.size()));

    return CKR_OK;
}

CK_RV Session::DeleteObject(CK_OBJECT_HANDLE hObject)
{
    // object handle also encodes the session to which it
    // belongs, it is also possible to delete object of one
    // session from other

    CK_SESSION_HANDLE encodedSId = ((hObject >> 16) & 0x0000FFFF);

    if ((encodedSId < 1) || (encodedSId >= _slot->_sessions.size())){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if(this->_slot->_sessions[encodedSId] == NULL_PTR){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    // determine the index
    CK_LONG idx = (CK_LONG)(hObject & CO_OBJECT_HANDLE_MASK);
    if(idx < 1 || idx > static_cast<CK_LONG>(_slot->_sessions[encodedSId]->_objects.size()))
        return CKR_OBJECT_HANDLE_INVALID;

    StorageObject* obj = this->_slot->_sessions[encodedSId]->_objects[idx-1];

    if(obj == NULL_PTR){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    // if this is a readonly session and
    // user is not logged then only public session objects
    // can be created
    if(this->_isReadWrite == CK_FALSE)
    {
        if(obj->_tokenObject)
            return CKR_SESSION_READ_ONLY;
    }

    if ((this->_slot->_token->_roleLogged != CKU_USER) && (obj->_private == CK_TRUE)){
        return CKR_USER_NOT_LOGGED_IN;
    }

    delete obj;

    this->_slot->_sessions[encodedSId]->_objects[idx-1] = NULL_PTR;

    return CKR_OK;
}

CK_RV Session::GetAttributeValue(CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulCount)
{
    CK_RV rv  = CKR_OK;
    CK_RV arv = CKR_OK;

    CK_LONG idx = (CK_LONG)(hObject & CO_OBJECT_HANDLE_MASK);

    //  lets see if the object handle provided is a correct handle or not
    if((idx < 1) || (idx > static_cast<CK_LONG>(_objects.size())) || (this->_objects[idx-1] == NULL_PTR)){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    StorageObject* obj = this->_objects[idx-1];

    if((this->_slot->_token->_roleLogged != CKU_USER) && (obj->_private == CK_TRUE)){
        for(u4 i=0;i<ulCount;i++){
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
        }
        return CKR_USER_NOT_LOGGED_IN;
    }

    for(u4 i=0;i<ulCount;i++){
        rv = obj->GetAttribute(&pTemplate[i]);
        if(rv != CKR_OK){
            arv = rv;
        }
    }

    return arv;
}

CK_RV Session::SetAttributeValue(CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulCount)
{
    CK_RV rv  = CKR_OK;
    CK_RV arv = CKR_OK;

    CK_LONG idx = (CK_LONG)(hObject & CO_OBJECT_HANDLE_MASK);

    //  lets see if the object handle provided is a correct handle or not
    if((idx < 1) || (idx > static_cast<CK_LONG>(_objects.size())) || (this->_objects[idx-1] == NULL_PTR)){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    StorageObject* obj = this->_objects[idx-1];

    if ((this->_slot->_token->_roleLogged != CKU_USER) && (obj->_private == CK_TRUE)){
        return CKR_USER_NOT_LOGGED_IN;
    }

    for(u4 i=0;i<ulCount;i++){
        rv = obj->SetAttribute(pTemplate[i],CK_FALSE);
        if(rv != CKR_OK){
            arv = rv;
        }
    }

    return arv;
}

void Session::SetDigest(CDigest *digest)
{
    this->_digest = digest;
    this->_isDigestActive = CK_TRUE;
}

void Session::RemoveDigest()
{
    if(this->_digest != NULL_PTR){
        delete this->_digest;
        this->_digest = NULL_PTR;
    }

    this->_isDigestActive = CK_FALSE;
}

CK_BBOOL Session::IsDigestActive()
{
    return this->_isDigestActive;
}

void Session::SetDigestRSA(CDigest *digest)
{
    this->_digestRSA = digest;
    this->_isDigestRSAActive = CK_TRUE;
}

void Session::RemoveDigestRSA()
{
    if(this->_digestRSA != NULL_PTR){
        delete this->_digestRSA;
        this->_digestRSA = NULL_PTR;
    }

    this->_isDigestRSAActive = CK_FALSE;
}

CK_BBOOL Session::IsDigestRSAActive()
{
    return this->_isDigestRSAActive;
}

void Session::SetDigestRSAVerification(CDigest *digest)
{
    this->_digestRSAVerification = digest;
    this->_isDigestRSAVerificationActive = CK_TRUE;
}

void Session::RemoveDigestRSAVerification()
{
    if(this->_digestRSAVerification != NULL_PTR){
        delete this->_digestRSAVerification;
        this->_digestRSAVerification = NULL_PTR;
    }

    this->_isDigestRSAVerificationActive = CK_FALSE;
}

CK_BBOOL Session::IsDigestRSAVerificationActive()
{
    return this->_isDigestRSAVerificationActive;
}

CK_RV Session::GetObject(CK_OBJECT_HANDLE hObject,StorageObject** object)
{
    if(hObject == 0){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CK_SESSION_HANDLE encodedSId = ((hObject >> 16) & 0x0000FFFF);

    if ((encodedSId < 1) || (encodedSId >= _slot->_sessions.size())){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if(this->_slot->_sessions[encodedSId] == NULL_PTR){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    // determine the index
    CK_LONG idx = (CK_LONG)(hObject & CO_OBJECT_HANDLE_MASK);

    StorageObject* obj = this->_slot->_sessions[encodedSId]->_objects[idx-1];

    if(obj == NULL_PTR){
        return CKR_OBJECT_HANDLE_INVALID;
    }

    *object = obj;

    return CKR_OK;
}

void Session::SetEncryptionOperation(CryptoOperation *encryption)
{
    this->_encryption = encryption;
}

void Session::RemoveEncryptionOperation()
{
    if(this->_encryption != NULL_PTR){
        delete this->_encryption;
    }

    this->_encryption = NULL_PTR;
}

CK_BBOOL Session::IsEncryptionActive(){

   return (this->_encryption != NULL_PTR);
}

void Session::SetVerificationOperation(CryptoOperation *verification)
{
    this->_verification = verification;
}

void Session::RemoveVerificationOperation()
{
    if(this->_verification != NULL_PTR){
        delete this->_verification;
    }

    this->_verification = NULL_PTR;
}

CK_BBOOL Session::IsVerificationActive(){

   return (this->_verification != NULL_PTR);
}

void Session::SetDecryptionOperation(CryptoOperation *decryption)
{
    this->_decryption = decryption;
}

void Session::RemoveDecryptionOperation()
{
    if(this->_decryption != NULL_PTR){
        delete this->_decryption;
    }

    this->_decryption = NULL_PTR;
}

CK_BBOOL Session::IsDecryptionActive(){

   return (this->_decryption != NULL_PTR);
}

void Session::SetSignatureOperation(CryptoOperation* signature)
{
    this->_signature = signature;
}

void Session::RemoveSignatureOperation()
{
    if(this->_signature != NULL_PTR){
        delete this->_signature;
    }

    this->_signature = NULL_PTR;
}

CK_BBOOL Session::IsSignatureActive(){

    return (this->_signature != NULL_PTR);

}

