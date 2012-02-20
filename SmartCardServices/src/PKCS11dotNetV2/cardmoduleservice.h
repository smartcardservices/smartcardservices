// Machine generated C++ stub file (.h) for remote object CardModuleService
// Created on : 06/05/2008 12:22:51


#ifndef _include_CardModuleService_h
#define _include_CardModuleService_h

#include <string>
#include "MarshallerCfg.h"
#include "Array.h"
#include "PCSC.h"
#include "Marshaller.h"

#ifdef CardModuleService_EXPORTS
#define CardModuleService_API __declspec(dllexport)
#else
#define CardModuleService_API
#endif

using namespace std;
using namespace Marshaller;

class CardModuleService_API CardModuleService : private SmartCardMarshaller {
public:
	// Constructors
	CardModuleService(string* uri);
	CardModuleService(string* uri, u4 index);
	CardModuleService(u2 portNumber, string* uri);
	CardModuleService(u2 portNumber, string* uri, u4 index);
	CardModuleService(string* readerName, string* uri);
	CardModuleService(string* readerName, u2 portNumber, string* uri);
	CardModuleService(SCARDHANDLE cardHandle, string* uri);
	CardModuleService(SCARDHANDLE cardHandle, u2 portNumber, string* uri);

    // Extra method (Microsoft CardModule only)
    void UpdateCardHandle(SCARDHANDLE cardHandle);

	// Pre-defined methods
	string* GetReader(void);
	SCARDHANDLE GetPcscCardHandle(void);
    void DoSCardTransact(bool flag);

	// Exposed methods
	void ChangeReferenceData(u1 mode,u1 role,u1Array* oldPin,u1Array* newPin,s4 maxTries);
	s4 GetTriesRemaining(u1 role);
	void CreateCAPIContainer(u1 ctrIndex,u1 keyImport,u1 keySpec,s4 keySize,u1Array* keyValue);
	void DeleteCAPIContainer(u1 ctrIndex);
	u1Array* GetCAPIContainer(u1 ctrIndex);
	u1Array* PrivateKeyDecrypt(u1 ctrIndex,u1 keyType,u1Array* encryptedData);
	void CreateFile(string* path,u1Array* acls,s4 initialSize);
	void CreateDirectory(string* path,u1Array* acls);
	void WriteFile(string* path,u1Array* data);
	u1Array* ReadFile(string* path,s4 maxBytesToRead);
	void DeleteFile(string* path);
	void DeleteDirectory(string* path);
	StringArray* GetFiles(string* path);
	u1Array* GetFileProperties(string* path);
	void ChangeAuthenticatorEx(u1 mode,u1 oldRole,u1Array* oldPin,u1 newRole,u1Array* newPin,s4 maxTries);
	u1Array* GetContainerProperty(u1 ctrIndex,u1 property,u1 flags);
	void SetContainerProperty(u1 ctrIndex,u1 property,u1Array* data,u1 flags);
	void SetCardProperty(u1 property,u1Array* data,u1 flags);
	s4 GetMemory();
	void ForceGarbageCollector();
	void RecursiveDelete(string* path);
	void Select(MemoryStream* AID);
	void Verify(u1 P1,u1 P2,u1Array* pin);
	u1 get_AdminPersonalized();
	u1 get_UserPersonalized();
	u1Array* GetChallenge();
	s8 get_AuthenticationDelay();
	void ExternalAuthenticate(u1Array* response);
	void VerifyPin(u1 role,u1Array* pin);
	u1 IsAuthenticated(u1 role);
	s4Array* QueryFreeSpace();
	s4Array* QueryKeySizes();
	void LogOut(u1 role);
	void SerializeData(string* filename);
	void DeSerializeData(string* filename);
	u1Array* get_SerialNumber();
	string* get_Version();
	void SetHostVersion(u4 hostVersion);
	u1Array* GetChallengeEx(u1 role);
	u1Array* AuthenticateEx(u1 mode,u1 role,u1Array* pin);
	void DeauthenticateEx(u1 roles);
	u1Array* GetCardProperty(u1 property,u1 flags);

	u1Array* BM_GetBioHeader(u1 role);
	u1 BM_BioMatch(u1 role,u1Array* verificationData);
	u1Array* BM_GetRoles();
	u1 get_BM_DefaultRole();
	void set_BM_DefaultRole(u1 value);
	u1 get_BM_AuthPinAllowed();
	string* BM_GetVerifUIName();
	string* BM_GetEnrollUIName();
};


#endif
