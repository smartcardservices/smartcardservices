// Machine generated C++ stub file (.cpp) for remote object CardModuleService
// Created on : 06/05/2008 12:22:51

#ifdef WIN32
#include <windows.h>
#endif
#include <winscard.h>
#include "cardmoduleservice.h"

using namespace std;
using namespace Marshaller;


// Constructors
CardModuleService::CardModuleService(string* uri) : SmartCardMarshaller(NULL, 0, uri, (u4)0xC04B4E, (u2)0x7FBD, 0) { return; }
CardModuleService::CardModuleService(string* uri, u4 index) : SmartCardMarshaller(NULL, 0, uri, (u4)0xC04B4E, (u2)0x7FBD, index) { return; }
CardModuleService::CardModuleService(u2 portNumber, string* uri) : SmartCardMarshaller(NULL, portNumber, uri, (u4)0xC04B4E, (u2)0x7FBD, 0) { return; }
CardModuleService::CardModuleService(u2 portNumber, string* uri, u4 index) : SmartCardMarshaller(NULL, portNumber, uri, (u4)0xC04B4E, (u2)0x7FBD, index) { return; }
CardModuleService::CardModuleService(string* readerName, string* uri) : SmartCardMarshaller(readerName, 0, uri, (u4)0xC04B4E, (u2)0x7FBD, 0) { return; }
CardModuleService::CardModuleService(string* readerName, u2 portNumber, string* uri) : SmartCardMarshaller(readerName, portNumber, uri, (u4)0xC04B4E, (u2)0x7FBD, 0) { return; }
CardModuleService::CardModuleService(SCARDHANDLE cardHandle, string* uri) : SmartCardMarshaller(cardHandle, 0, uri, (u4)0xC04B4E, (u2)0x7FBD) { return; }
CardModuleService::CardModuleService(SCARDHANDLE cardHandle, u2 portNumber, string* uri) : SmartCardMarshaller(cardHandle, portNumber, uri, (u4)0xC04B4E, (u2)0x7FBD) { return; }

// Extra method (Microsoft CardModule only)
void CardModuleService::UpdateCardHandle(SCARDHANDLE cardHandle)
{
    UpdatePCSCCardHandle(cardHandle);
}

// Pre-defined methods
std::string* CardModuleService::GetReader(void){return GetReaderName();}
SCARDHANDLE CardModuleService::GetPcscCardHandle(void){return GetCardHandle();}
void CardModuleService::DoSCardTransact(bool flag){DoTransact(flag);}

// Exposed methods

void CardModuleService::ChangeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries){
	Invoke(5, 0xE08A, MARSHALLER_TYPE_IN_U1, mode, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_IN_U1ARRAY, oldPin, MARSHALLER_TYPE_IN_U1ARRAY, newPin, MARSHALLER_TYPE_IN_S4, maxTries, MARSHALLER_TYPE_RET_VOID);
}


s4 CardModuleService::GetTriesRemaining(u1 role){
	s4 _s4 = 0;
	Invoke(1, 0x6D08, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_RET_S4, &_s4);
	return _s4;
}


void CardModuleService::CreateCAPIContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue){
	Invoke(5, 0x0234, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_IN_BOOL, keyImport, MARSHALLER_TYPE_IN_U1, keySpec, MARSHALLER_TYPE_IN_S4, keySize, MARSHALLER_TYPE_IN_U1ARRAY, keyValue, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::DeleteCAPIContainer(u1 ctrIndex){
	Invoke(1, 0xF152, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::GetCAPIContainer(u1 ctrIndex){
	u1Array* _u1Array = NULL;
	Invoke(1, 0x9B2E, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


u1Array* CardModuleService::PrivateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData){
	u1Array* _u1Array = NULL;
	Invoke(3, 0x6144, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_IN_U1, keyType, MARSHALLER_TYPE_IN_U1ARRAY, encryptedData, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


void CardModuleService::CreateFile(string* path,u1Array* acls,s4 initialSize){
	Invoke(3, 0xBEF1, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_IN_U1ARRAY, acls, MARSHALLER_TYPE_IN_S4, initialSize, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::CreateDirectory(string* path,u1Array* acls){
	Invoke(2, 0xACE9, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_IN_U1ARRAY, acls, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::WriteFile(string* path,u1Array* data){
	Invoke(2, 0xF20E, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_IN_U1ARRAY, data, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::ReadFile(string* path,s4 maxBytesToRead){
	u1Array* _u1Array = NULL;
	Invoke(2, 0x744C, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_IN_S4, maxBytesToRead, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


void CardModuleService::DeleteFile(string* path){
	Invoke(1, 0x6E2B, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::DeleteDirectory(string* path){
	Invoke(1, 0x9135, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_RET_VOID);
}


StringArray* CardModuleService::GetFiles(string* path){
	StringArray* _StringArray = NULL;
	Invoke(1, 0xE72B, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_RET_STRINGARRAY, &_StringArray);
	return _StringArray;
}


u1Array* CardModuleService::GetFileProperties(string* path){
	u1Array* _u1Array = NULL;
	Invoke(1, 0xA01B, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


void CardModuleService::ChangeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries){
	Invoke(6, 0x9967, MARSHALLER_TYPE_IN_U1, mode, MARSHALLER_TYPE_IN_U1, oldRole, MARSHALLER_TYPE_IN_U1ARRAY, oldPin, MARSHALLER_TYPE_IN_U1, newRole, MARSHALLER_TYPE_IN_U1ARRAY, newPin, MARSHALLER_TYPE_IN_S4, maxTries, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::GetContainerProperty(u1 ctrIndex,u1 property,u1 flags){
	u1Array* _u1Array = NULL;
	Invoke(3, 0x279C, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_IN_U1, property, MARSHALLER_TYPE_IN_U1, flags, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


void CardModuleService::SetContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags){
	Invoke(4, 0x98D1, MARSHALLER_TYPE_IN_U1, ctrIndex, MARSHALLER_TYPE_IN_U1, property, MARSHALLER_TYPE_IN_U1ARRAY, data, MARSHALLER_TYPE_IN_U1, flags, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::SetCardProperty(u1 property,u1Array* data,u1 flags){
	Invoke(3, 0xB0E4, MARSHALLER_TYPE_IN_U1, property, MARSHALLER_TYPE_IN_U1ARRAY, data, MARSHALLER_TYPE_IN_U1, flags, MARSHALLER_TYPE_RET_VOID);
}


s4 CardModuleService::GetMemory(){
	s4 _s4 = 0;
	Invoke(0, 0x1DB4, MARSHALLER_TYPE_RET_S4, &_s4);
	return _s4;
}


void CardModuleService::ForceGarbageCollector(){
	Invoke(0, 0x3D38, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::RecursiveDelete(string* path){
	Invoke(1, 0xEDD5, MARSHALLER_TYPE_IN_STRING, path, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::Select(MemoryStream* AID){
	Invoke(1, 0x32E1, MARSHALLER_TYPE_IN_MEMORYSTREAM, AID, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::Verify(u1 P1,u1 P2,u1Array* pin){
	Invoke(3, 0xD845, MARSHALLER_TYPE_IN_U1, P1, MARSHALLER_TYPE_IN_U1, P2, MARSHALLER_TYPE_IN_U1ARRAY, pin, MARSHALLER_TYPE_RET_VOID);
}













u1 CardModuleService::get_AdminPersonalized(){
	u1 _u1 = 0;
	Invoke(0, 0xCFBE, MARSHALLER_TYPE_RET_BOOL, &_u1);
	return _u1;
}


u1 CardModuleService::get_UserPersonalized(){
	u1 _u1 = 0;
	Invoke(0, 0xE710, MARSHALLER_TYPE_RET_BOOL, &_u1);
	return _u1;
}


u1Array* CardModuleService::GetChallenge(){
	u1Array* _u1Array = NULL;
	Invoke(0, 0xFA3B, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


s8 CardModuleService::get_AuthenticationDelay(){
	s8 _s8 = 0;
	Invoke(0, 0x5321, MARSHALLER_TYPE_RET_S8, &_s8);
	return _s8;
}

void CardModuleService::ExternalAuthenticate(u1Array* response){
	Invoke(1, 0x24FE, MARSHALLER_TYPE_IN_U1ARRAY, response, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::VerifyPin(u1 role,u1Array* pin){
	Invoke(2, 0x506B, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_IN_U1ARRAY, pin, MARSHALLER_TYPE_RET_VOID);
}


u1 CardModuleService::IsAuthenticated(u1 role){
	u1 _u1 = 0;
	Invoke(1, 0x9B0B, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_RET_BOOL, &_u1);
	return _u1;
}


s4Array* CardModuleService::QueryFreeSpace(){
	s4Array* _s4Array = NULL;
	Invoke(0, 0x00E5, MARSHALLER_TYPE_RET_S4ARRAY, &_s4Array);
	return _s4Array;
}


s4Array* CardModuleService::QueryKeySizes(){
	s4Array* _s4Array = NULL;
	Invoke(0, 0x5EE4, MARSHALLER_TYPE_RET_S4ARRAY, &_s4Array);
	return _s4Array;
}


void CardModuleService::LogOut(u1 role){
	Invoke(1, 0xC4E4, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_RET_VOID);
}




void CardModuleService::SerializeData(string* filename){
	Invoke(1, 0x9AEA, MARSHALLER_TYPE_IN_STRING, filename, MARSHALLER_TYPE_RET_VOID);
}


void CardModuleService::DeSerializeData(string* filename){
	Invoke(1, 0xA373, MARSHALLER_TYPE_IN_STRING, filename, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::get_SerialNumber(){
	u1Array* _u1Array = NULL;
	Invoke(0, 0xD017, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


string* CardModuleService::get_Version(){
	string* _string = NULL;
	Invoke(0, 0xDEEC, MARSHALLER_TYPE_RET_STRING, &_string);
	return _string;
}


void CardModuleService::SetHostVersion(u4 hostVersion){
	Invoke(1, 0xD9B1, MARSHALLER_TYPE_IN_U4, hostVersion, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::GetChallengeEx(u1 role){
	u1Array* _u1Array = NULL;
	Invoke(1, 0x8F0B, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


u1Array* CardModuleService::AuthenticateEx(u1 mode,u1 role,u1Array* pin){
	u1Array* _u1Array = NULL;
	Invoke(3, 0x5177, MARSHALLER_TYPE_IN_U1, mode, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_IN_U1ARRAY, pin, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


void CardModuleService::DeauthenticateEx(u1 roles){
	Invoke(1, 0xBD7B, MARSHALLER_TYPE_IN_U1, roles, MARSHALLER_TYPE_RET_VOID);
}


u1Array* CardModuleService::GetCardProperty(u1 property,u1 flags){
	u1Array* _u1Array = NULL;
	Invoke(2, 0x8187, MARSHALLER_TYPE_IN_U1, property, MARSHALLER_TYPE_IN_U1, flags, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


u1Array* CardModuleService::BM_GetBioHeader(u1 role){
	u1Array* _u1Array = NULL;
	Invoke(1, 0x4838, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}


u1 CardModuleService::BM_BioMatch(u1 role,u1Array* verificationData){
	u1 _u1 = 0;
	Invoke(2, 0x2D3D, MARSHALLER_TYPE_IN_U1, role, MARSHALLER_TYPE_IN_U1ARRAY, verificationData, MARSHALLER_TYPE_RET_BOOL, &_u1);
	return _u1;
}

u1Array* CardModuleService::BM_GetRoles(){
	u1Array* _u1Array = NULL;
	Invoke(0, 0xA77A, MARSHALLER_TYPE_RET_U1ARRAY, &_u1Array);
	return _u1Array;
}

u1 CardModuleService::get_BM_DefaultRole(){
	u1 _u1 = 0;
	Invoke(0, 0x17FD, MARSHALLER_TYPE_RET_U1, &_u1);
	return _u1;
}


void CardModuleService::set_BM_DefaultRole(u1 value){
	Invoke(1, 0x4F1E, MARSHALLER_TYPE_IN_U1, value, MARSHALLER_TYPE_RET_VOID);
}

u1 CardModuleService::get_BM_AuthPinAllowed(){
	u1 _u1 = 0;
	Invoke(0, 0x9063, MARSHALLER_TYPE_RET_BOOL, &_u1);
	return _u1;
}

string* CardModuleService::BM_GetVerifUIName(){
	string* _string = NULL;
	Invoke(0, 0x7BB7, MARSHALLER_TYPE_RET_STRING, &_string);
	return _string;
}


string* CardModuleService::BM_GetEnrollUIName(){
	string* _string = NULL;
	Invoke(0, 0x0D17, MARSHALLER_TYPE_RET_STRING, &_string);
	return _string;
}
