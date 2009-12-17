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

#ifndef _include_slot_h
#define _include_slot_h

#include "sctoken.h"
#include "critsect.h"

#ifdef _XCL_
#include "xcl_public.h"
#include <xcl_utils.h>
#endif // _XCL

class CardMonitoringThread;

class Slot {

public:
   CK_SLOT_ID              _slotId;
   CK_SLOT_INFO            _slotInfo;
   std::string*            _readerName;
   CK_BBOOL                _event;
   CardMonitoringThread*   _tracker;
   vector<Session*>        _sessions;
   Token*                  _token;

private:
   CK_LONG AddSession(Session* session);
   void RemoveSession(CK_LONG sessionId);
   CK_BBOOL HasReadOnlySession();
   static /*bool*/ void checkConnection( Slot* a_pSlot );

public:
   Slot();
   virtual ~Slot();

   void UpdateSessionState();
   void UpdateAuthenticationState( void );

   static void ClearCache(void);
   static CK_RV GetSlotAndSessionIdFromSessionHandle(CK_SESSION_HANDLE hSession,
      Slot** slot,CK_ULONG_PTR sessionId);

   static CK_RV IsValidMechanism(CK_ULONG mechanism,CK_ULONG operation);
   static CK_RV IsValidCryptoOperation(StorageObject* object,CK_ULONG operation);

   CK_BBOOL    GetEvent();
   void        SetEvent(CK_BBOOL event);
   CK_SLOT_ID  GetSlotId() { return _slotId;}
   CK_BBOOL    IsCardPresent() { return ((_slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);}
   void        Clear(void);

   CK_RV  BuildToken(void);

   CK_RV  GetInfo(CK_SLOT_INFO_PTR pInfo);
   CK_RV  GetTokenInfo(CK_TOKEN_INFO_PTR pInfo);
   CK_RV  GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,CK_ULONG_PTR pulCount);
   CK_RV  GetMechanismInfo(CK_MECHANISM_TYPE type,CK_MECHANISM_INFO_PTR pInfo);
   CK_RV  OpenSession(CK_FLAGS flags,CK_VOID_PTR pApplication,CK_NOTIFY Notify,CK_SESSION_HANDLE_PTR phSession);
   static CK_RV  CloseSession(CK_SESSION_HANDLE hSession);
   CK_RV  CloseAllSessions(void);
   static CK_RV  GetSessionInfo(CK_SESSION_HANDLE hSession,CK_SESSION_INFO_PTR pInfo);

   static CK_RV  Login(CK_SESSION_HANDLE hSession,CK_USER_TYPE userType,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);
   static CK_RV  Logout(CK_SESSION_HANDLE hSession);

   CK_RV InitToken(CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen,CK_UTF8CHAR_PTR pLabel);
   static CK_RV  InitPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);
   static CK_RV  SetPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pOldPin,CK_ULONG ulOldLen,
      CK_UTF8CHAR_PTR pNewPin,CK_ULONG ulNewLen);

   static CK_RV  CreateObject(CK_SESSION_HANDLE hSession,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phObject);
   static CK_RV  DestroyObject(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject);
   static CK_RV  GetAttributeValue(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE  hObject,CK_ATTRIBUTE_PTR  pTemplate,CK_ULONG ulCount);
   static CK_RV  SetAttributeValue(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
   static CK_RV  FindObjectsInit(CK_SESSION_HANDLE hSession,CK_ATTRIBUTE_PTR  pTemplate,CK_ULONG ulCount);
   static CK_RV  FindObjects(CK_SESSION_HANDLE  hSession, CK_OBJECT_HANDLE_PTR phObject,CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount);
   static CK_RV  FindObjectsFinal(CK_SESSION_HANDLE hSession);

   static CK_RV  GenerateRandom(CK_SESSION_HANDLE hSession,CK_BYTE_PTR RandomData,CK_ULONG ulRandomLen);

   static CK_RV  GenerateKeyPair(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pPublicKeyTemplate,
      CK_ULONG ulPublicKeyAttributeCount,CK_ATTRIBUTE_PTR pPrivateKeyTemplate,CK_ULONG ulPrivateKeyAttributeCount,
      CK_OBJECT_HANDLE_PTR phPublicKey,CK_OBJECT_HANDLE_PTR phPrivateKey);

   //static CK_RV  WrapKey(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR  pMechanism,
   //                      CK_OBJECT_HANDLE  hWrappingKey,CK_OBJECT_HANDLE  hKey,
   //                      CK_BYTE_PTR pWrappedKey,CK_ULONG_PTR pulWrappedKeyLen);

   //static CK_RV  UnwrapKey(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,
   //                       CK_OBJECT_HANDLE hUnwrappingKey,CK_BYTE_PTR pWrappedKey,
   //                       CK_ULONG ulWrappedKeyLen,CK_ATTRIBUTE_PTR pTemplate,
   //                       CK_ULONG ulAttributeCount,CK_OBJECT_HANDLE_PTR phKey);

   static CK_RV  EncryptInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE  hKey);
   static CK_RV  Encrypt(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pEncryptedData,CK_ULONG_PTR pulEncryptedDataLen);

   static CK_RV  DecryptInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR  pMechanism,CK_OBJECT_HANDLE  hKey);
   static CK_RV  Decrypt(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedData,CK_ULONG ulEncryptedDataLen,CK_BYTE_PTR pData,CK_ULONG_PTR pulDataLen);

   static CK_RV  SignInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
   static CK_RV  Sign(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen);
   static CK_RV  SignUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
   static CK_RV  SignFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen);

   static CK_RV  VerifyInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
   static CK_RV  Verify(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen);
   static CK_RV  VerifyUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
   static CK_RV  VerifyFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen);
   //static CK_RV  VerifyRecoverInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
   //static CK_RV  VerifyRecover(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen,CK_BYTE_PTR pData,CK_ULONG_PTR pulDataLen);

   static CK_RV  DigestInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism);
   static CK_RV  Digest(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen);
   static CK_RV  DigestUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
   static CK_RV  DigestFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen);
};

#define CARD_PRESENT 1
#define CARD_ABSENT  2

#define CARD_DETECTION_INSERTED 1
#define CARD_DETECTION_REMOVED  2


#ifdef INCLUDE_EVENTING

extern CCriticalSection _critSect;

class CardMonitoringThread : public CThread
{

private:
   CK_BYTE m_bCardState;
   Slot*   m_slot;
   SCARDCONTEXT m_hMonitoringContext;

public:
   // CThread override
   void stop()
   {
      //printf( "%s - %d - %s - m_monitoringContext <%ld>\n", __FILE__, __LINE__, __FUNCTION__, m_hMonitoringContext );

#ifndef _XCL_

      if( 0 != m_hMonitoringContext )
      {
         SCardCancel(m_hMonitoringContext);
         //printf( "%s - %d - %s - SCardCancel\n", __FILE__, __LINE__, __FUNCTION__);

         /*
         printf( "%s - %d - %s - SCardReleaseContext -->\n", __FILE__, __LINE__, __FUNCTION__);
         SCardReleaseContext(m_hMonitoringContext);
         printf( "%s - %d - %s - SCardReleaseContext <--\n", __FILE__, __LINE__, __FUNCTION__);
         m_hMonitoringContext = 0;
         */
      }

#endif // _XCL_

      CThread::stop();
   }

   //------------------------------------------------------------------------------
   //------------------------------------------------------------------------------
   CardMonitoringThread(const char* nm) //: m_hMonitoringContext(0)
   {
      m_hMonitoringContext = 0;
      m_bCardState = CARD_ABSENT;
      CThread::setName(nm);
   }

   //------------------------------------------------------------------------------
   //------------------------------------------------------------------------------
   void SetSlot(Slot* slot)
   {
      m_slot = slot;

      if(slot->IsCardPresent() == CK_FALSE)
      {
         m_bCardState = CARD_ABSENT;
      }
      else
      {
         m_bCardState = CARD_PRESENT;
      }
   }

   //------------------------------------------------------------------------------
   //------------------------------------------------------------------------------
   void run()
   {
      bool bTrue = true;
      while( bTrue )
      {
         switch(m_bCardState)
         {
         case CARD_PRESENT:
            if(Monitor(CARD_DETECTION_REMOVED) == false)
            {
               return;
            }
            m_bCardState = CARD_ABSENT;

            // clean the slot, lock during session deletion
            {
               CCriticalSectionLocker cslock(_critSect);
               m_slot->Clear();
            }
            break;

         case CARD_ABSENT:
            if(Monitor(CARD_DETECTION_INSERTED) == false)
            {
               return;
            }
            m_bCardState = CARD_PRESENT;
            break;
         }

         // we fire the event from here
         m_slot->SetEvent(CK_TRUE);
         CryptokiEvent.Signal();
      }
   }

   //------------------------------------------------------------------------------
   //------------------------------------------------------------------------------

#ifndef _XCL_

   bool Monitor(BYTE detectionType)
   {

      // establish monitoring context
      LONG lReturn = SCardEstablishContext( SCARD_SCOPE_USER, NULL, NULL, &m_hMonitoringContext );
      //printf( "%s - %d - %s - SCardEstablishContext --> m_hMonitoringContext <%ld>\n", __FILE__, __LINE__,  __FUNCTION__, m_hMonitoringContext);

      //LONG lReturn = SCardEstablishContext(0, NULL, NULL, (LPSCARDCONTEXT)&m_monitoringContext);

      if(lReturn != SCARD_S_SUCCESS)
      {
         return false;
      }

      SCARD_READERSTATE readerStates;
      readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
      readerStates.szReader       = this->getName()->c_str();
      readerStates.pvUserData     = NULL;
      readerStates.dwEventState   = 0;         // TO INSPECT THIS STATE

      bool bTrue = true;
      while( bTrue )
      {

         if((lReturn = SCardGetStatusChange( m_hMonitoringContext, 60*1000, &readerStates, 1 )) != SCARD_S_SUCCESS)
         {
            if(lReturn == (LONG)SCARD_E_TIMEOUT)
            {
               if(this->isStopRequested() == CK_TRUE)
               {
                  SCardReleaseContext(m_hMonitoringContext);
                  //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
                  m_hMonitoringContext = 0;
                  return false;
               }

               goto resume;
            }

            SCardReleaseContext(m_hMonitoringContext);
            //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
            m_hMonitoringContext = 0;
            return false;
         }

resume:
         if((readerStates.dwEventState & SCARD_STATE_CHANGED) == SCARD_STATE_CHANGED)
         {
            if((readerStates.dwEventState & SCARD_STATE_UNAVAILABLE) == SCARD_STATE_UNAVAILABLE)
            {
               // reader removed
               SCardReleaseContext(m_hMonitoringContext);
               //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
               m_hMonitoringContext = 0;
               return true;
            }
            else if(((readerStates.dwCurrentState & SCARD_STATE_EMPTY) == SCARD_STATE_EMPTY) &&
               ((readerStates.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT))
            {
               if(detectionType == CARD_PRESENT)
               {
                  // card is inserted
                  SCardReleaseContext(m_hMonitoringContext);
                  //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
                  m_hMonitoringContext = 0;
                  return true;
               }
            }
            else if(((readerStates.dwCurrentState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT) &&
               ((readerStates.dwEventState & SCARD_STATE_EMPTY) == SCARD_STATE_EMPTY))
            {
               if(detectionType == CARD_ABSENT)
               {
                  // card is removed
                  SCardReleaseContext(m_hMonitoringContext);
                  //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
                  m_hMonitoringContext = 0;
                  return true;
               }
            }
         }

         readerStates.dwCurrentState = readerStates.dwEventState ;
      }

      SCardReleaseContext(m_hMonitoringContext);
      //printf( "%s - %d - %s - SCardReleaseContext\n", __FILE__, __LINE__, __FUNCTION__ );
      m_hMonitoringContext = 0;
      return false;
   }

#else // _XCL_

    bool Monitor(BYTE detectionType)
    {
        BOOL initialTokenPresent;
        BOOL currentTokenPresent;
        UINT rv;
        UINT deviceID2;
        xCL_DeviceHandle deviceHandle2;

        PRINT_MSG("IN Monitor top");

        initialTokenPresent = false;
        currentTokenPresent = false;

        deviceHandle2 = 0;
        deviceID2 = 0;
        rv = xCL_CreateHandleFromDeviceID(deviceID2, &deviceHandle2);
        if (rv == 0)
        {
            initialTokenPresent = true;
            currentTokenPresent = true;
        }
        rv = xCL_CloseHandle(deviceHandle2);

        while(true)
        {
            PRINT_MSG("IN Monitor loop");

            // sleep for some time
            sleep(500);

            // See if token is present now
            deviceHandle2 = 0;
            deviceID2 = 0;
            rv = xCL_CreateHandleFromDeviceID(deviceID2, &deviceHandle2);
            if (rv == 0)
            {
                currentTokenPresent = true;
                rv = xCL_CloseHandle(deviceHandle2);
            }
            else
            {
                currentTokenPresent = false;
            }

            if (initialTokenPresent == currentTokenPresent)
            {
                PRINT_MSG("IN Monitor no change");

                // No change in token state
                if(this->isStopRequested() == CK_TRUE)
                {
                    PRINT_MSG("IN Monitor no change exit");
                    return false;
                }
            }
            else
            {
                PRINT_MSG("IN Monitor yes change");
                // There is a change ...
                return true;
            }
        }
    }

#endif // _XCL_

};
#endif

#endif

