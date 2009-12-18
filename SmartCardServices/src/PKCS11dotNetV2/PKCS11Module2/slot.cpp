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

#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif
#include "cardmoduleservice.h"

#include <assert.h>
#include "stdafx.h"
#include "platconfig.h"
#include "config.h"
#include "thread.h"
#include "event.h"
#include "template.h"
#include "digest.h"
#include "sha1.h"
#include "sha256.h"
#include "md5.h"
#include "session.h"
#include "slot.h"
#include "dataobject.h"
#include "secretkeyobject.h"
#include "rsaprivatekeyobject.h"
#include "rsapublickeyobject.h"
#include "x509pubkeycertobject.h"
#include "application.h"
#include "transaction.h"
#include "log.h"
#include "error.h"

#ifdef _XCL_
#include "xcl_utils.h"
#endif // _XCL_

CK_MECHANISM_TYPE MechanismList[] = {
   CKM_RSA_PKCS_KEY_PAIR_GEN, // 0
   CKM_RSA_PKCS,              // 1
   CKM_RSA_X_509,             // 2
   CKM_MD5_RSA_PKCS,          // 3
   CKM_SHA1_RSA_PKCS,         // 4
   CKM_SHA256_RSA_PKCS,       // 5
#ifdef ENABLE_DIGEST
   CKM_MD5,                   // 6
   CKM_SHA_1,                 // 7
   CKM_SHA256,                // 8
#endif
#ifdef ENABLE_SYMMETRIC
   CKM_AES_KEY_GEN,           // 9
   CKM_AES_ECB,               // 10
   CKM_AES_CBC,               // 11
   CKM_AES_CBC_PAD,           // 12
   CKM_DES_KEY_GEN,           // 13
   CKM_DES_ECB,               // 14
   CKM_DES_CBC,               // 15
   CKM_DES_CBC_PAD,           // 16
   CKM_DES2_KEY_GEN,          // 17
   CKM_DES3_KEY_GEN,          // 18
   CKM_DES3_ECB,              // 19
   CKM_DES3_CBC,              // 20
   CKM_DES3_CBC_PAD           // 21
#endif
};

CK_MECHANISM_INFO MechanismInfo[] = {
   {/* 0 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_GENERATE_KEY_PAIR},
#ifdef ENABLE_SYMMETRIC
   {/* 1 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP},
   {/* 2 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP},
#else
   {/* 1 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_SIGN | /*CKF_SIGN_RECOVER |*/ CKF_VERIFY /*| CKF_VERIFY_RECOVER*/},
   {/* 2 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_SIGN | /*CKF_SIGN_RECOVER |*/ CKF_VERIFY /*| CKF_VERIFY_RECOVER*/},
#endif
   {/* 3 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_SIGN | CKF_VERIFY},
   {/* 4 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_SIGN | CKF_VERIFY},
   {/* 5 */  RSA_KEY_MIN_LENGTH,RSA_KEY_MAX_LENGTH, CKF_HW | CKF_SIGN | CKF_VERIFY},
#ifdef ENABLE_DIGEST
   {/* 6 */  0,0, CKF_SW | CKF_DIGEST},
   {/* 7 */  0,0, CKF_SW | CKF_DIGEST},
   {/* 8 */  0,0, CKF_SW | CKF_DIGEST},
#endif
#ifdef ENABLE_SYMMETRIC
   {/* 9 */  16,32, CKF_HW | CKF_GENERATE},
   {/* 10 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 11 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 12 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 13 */  0,0, CKF_HW | CKF_GENERATE},
   {/* 14 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 15 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 16 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 17 */  0,0, CKF_HW | CKF_GENERATE},
   {/* 18 */  0,0, CKF_HW | CKF_GENERATE},
   {/* 19 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 20 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP},
   {/* 21 */  0,0, CKF_HW | CKF_ENCRYPT  | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}
#endif
};

#define MAKE_SESSIONHANDLE(H,S)         (H | (S << 24))
#define GET_SESSIONID(H)                (H & 0x00FFFFFF)
#define GET_SLOTID(H)                   ((H & 0xFF000000) >> 24)

//#define CHECK_IF_NULL_SESSION(A,S)      if(A->_sessions[S] == NULL_PTR){return CKR_SESSION_HANDLE_INVALID;}
#define CHECK_IF_NULL_SESSION(A,S) try \
   { \
      if( A->_sessions.at( S ) == NULL_PTR ) \
      { \
         return CKR_SESSION_HANDLE_INVALID; \
      } \
   } \
   catch( ... ) \
   { \
      return CKR_SESSION_HANDLE_INVALID; \
   } \

#define CHECK_IF_TOKEN_IS_PRESENT(S)    if(S->_token == NULL_PTR){return CKR_TOKEN_NOT_PRESENT;}

Slot::Slot()
{
   // initialize the fields

   CK_ULONG idx;

   this->_token = NULL_PTR;
   this->_readerName = NULL_PTR;

   _sessions.resize(1,NULL_PTR);   // First element is dummy

   // initialize this slot
   this->_slotId = 0;
   this->_slotInfo.firmwareVersion.major = 0;
   this->_slotInfo.firmwareVersion.minor = 0;
   this->_slotInfo.flags                 = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
   this->_slotInfo.hardwareVersion.major = 0;
   this->_slotInfo.hardwareVersion.minor = 0;

   for(idx=0;idx<64;idx++)
      this->_slotInfo.slotDescription[idx] = ' ';

   this->_slotInfo.manufacturerID[0] = 'U';
   this->_slotInfo.manufacturerID[1] = 'n';
   this->_slotInfo.manufacturerID[2] = 'k';
   this->_slotInfo.manufacturerID[3] = 'n';
   this->_slotInfo.manufacturerID[4] = 'o';
   this->_slotInfo.manufacturerID[5] = 'w';
   this->_slotInfo.manufacturerID[6] = 'n';

   for(idx=7;idx<32;idx++){
      this->_slotInfo.manufacturerID[idx] = ' ';
   }

#ifdef INCLUDE_EVENTING
   this->_tracker = NULL_PTR;
   this->_event   = CK_FALSE;
#endif

}

Slot::~Slot(){

   if(this->_token != NULL_PTR)
   {
      delete this->_token;
      this->_token = NULL_PTR;
   }

#ifdef INCLUDE_EVENTING
   if(this->_tracker != NULL_PTR)
   {
      delete this->_tracker;
      this->_tracker = NULL_PTR;
   }
#endif

   if(this->_readerName != NULL_PTR)
   {
      delete this->_readerName;
      this->_readerName = NULL_PTR;
   }

   // destroy all opened sessions
   for(size_t i=1;i<_sessions.size();i++)
   {
      if( this->_sessions[i] != NULL_PTR)
      {
         delete this->_sessions[i];
         this->_sessions[i] = NULL_PTR;
      }
   }
}


#ifdef INCLUDE_EVENTING

void Slot::SetEvent(CK_BBOOL event)
{
   this->_event = event;
}

CK_BBOOL Slot::GetEvent()
{
   return this->_event;
}

void Slot::Clear()
{
   // close all the sessions when card is removed
   this->CloseAllSessions();

   if(this->_token != NULL_PTR)
   {
      delete this->_token;
      this->_token = NULL_PTR;
   }
}

#endif

CK_RV Slot::GetInfo(CK_SLOT_INFO_PTR pInfo)
{
   CK_BYTE idx;

   // Check Parameters
   if(pInfo == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   for(idx=0;idx<64;idx++)
   {
      pInfo->slotDescription[idx] = this->_slotInfo.slotDescription[idx];
   }

   for(idx=0;idx<32;idx++)
   {
      pInfo->manufacturerID[idx]  = this->_slotInfo.manufacturerID[idx];
   }

   pInfo->hardwareVersion.major = this->_slotInfo.hardwareVersion.major;
   pInfo->hardwareVersion.minor = this->_slotInfo.hardwareVersion.minor;
   pInfo->firmwareVersion.major = this->_slotInfo.firmwareVersion.major;
   pInfo->firmwareVersion.minor = this->_slotInfo.firmwareVersion.minor;

   // it turns out that we need to dynamically poll if
   // token is present or not. rest of the information should not
   // change since we enumerated
   SCARD_READERSTATE readerStates;

   readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
   readerStates.szReader = this->_readerName->c_str();

   // lets check if token is present
#ifndef _XCL_

   if (SCardGetStatusChange(Application::_hContext, 0, &readerStates, 1) == SCARD_S_SUCCESS)
   {
      if ((readerStates.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT)
      {
         // we found a card in this reader
         this->_slotInfo.flags |= CKF_TOKEN_PRESENT;
      }
      else
      {
         // No card in reader
         this->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
         CloseAllSessions();
      }
   }

#else // _XCL_

    PRINT_MSG("IN Slot::GetInfo");
    if (xCL_IsTokenPresent())
    {
        // we found a card in this reader
        this->_slotInfo.flags |= CKF_TOKEN_PRESENT;
    }
    else
    {
        // No card in reader
        this->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
    }

#endif // _XCL_

   pInfo->flags = this->_slotInfo.flags;

   return CKR_OK;
}


CK_RV Slot::GetTokenInfo( CK_TOKEN_INFO_PTR pInfo )
{
   Log::begin( "Slot::GetTokenInfo" );

   checkConnection( this );

   // Check Parameters
   if( NULL_PTR == pInfo )
   {
      Log::error( "Slot::GetTokenInfo", "CKR_ARGUMENTS_BAD" );
      return CKR_ARGUMENTS_BAD;
   }

   //Log::log( "Slot::GetTokenInfo - BuildToken..." );
   CK_RV rv = this->BuildToken( );
   //Log::log( "Slot::GetTokenInfo - BuildToken <%#02x>", rv );
   if( CKR_OK == rv )
   {
      Transaction trans(this);

      CK_BYTE idx;

      pInfo->firmwareVersion.major = this->_token->_tokenInfo.firmwareVersion.major;
      pInfo->firmwareVersion.minor = this->_token->_tokenInfo.firmwareVersion.minor;
      pInfo->flags                 = this->_token->_tokenInfo.flags;
      pInfo->hardwareVersion.major = this->_token->_tokenInfo.hardwareVersion.major;
      pInfo->hardwareVersion.minor = this->_token->_tokenInfo.hardwareVersion.minor;

      // label
      for(idx=0;idx<32;idx++)
      {
         pInfo->label[idx] = this->_token->_tokenInfo.label[idx];
      }

      // manufacturerID
      for(idx=0;idx<32;idx++)
      {
         pInfo->manufacturerID[idx]  = this->_token->_tokenInfo.manufacturerID[idx];
      }

      // model
      for(idx=0;idx<16;idx++)
      {
         pInfo->model[idx]  = this->_token->_tokenInfo.model[idx];
      }

      // serial number
      for(idx=0;idx<16;idx++)
      {
         pInfo->serialNumber[idx]  = this->_token->_tokenInfo.serialNumber[idx];
      }

      pInfo->ulFreePrivateMemory  = this->_token->_tokenInfo.ulFreePrivateMemory;
      pInfo->ulFreePublicMemory   = this->_token->_tokenInfo.ulFreePublicMemory;
      pInfo->ulMaxPinLen          = this->_token->_tokenInfo.ulMaxPinLen;
      pInfo->ulMinPinLen          = this->_token->_tokenInfo.ulMinPinLen;
      pInfo->ulMaxRwSessionCount  = CK_EFFECTIVELY_INFINITE;
      pInfo->ulSessionCount       = 0;
      pInfo->ulMaxSessionCount    = CK_EFFECTIVELY_INFINITE;
      pInfo->ulRwSessionCount     = 0;
      pInfo->ulTotalPrivateMemory = this->_token->_tokenInfo.ulTotalPrivateMemory;
      pInfo->ulTotalPublicMemory  = this->_token->_tokenInfo.ulTotalPublicMemory;

      for(size_t i=1;i<_sessions.size();i++)
      {
         if(_sessions[i])
         {
            ++pInfo->ulSessionCount;
            if(_sessions[i]->_isReadWrite)
               ++pInfo->ulRwSessionCount;
         }
      }

      // utcTime
      for(idx=0;idx<16;idx++)
      {
         pInfo->utcTime[idx]  = this->_token->_tokenInfo.utcTime[idx];
      }

      // Check if the smart card is in SSO mode
      if( ( true == this->_token->isSSO( ) ) && ( true == this->_token->isAuthenticated( ) ) )
      {
         this->_token->_tokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
      }
      else
      {
         this->_token->_tokenInfo.flags |= CKF_LOGIN_REQUIRED;
      }

      Log::log( "Slot::GetTokenInfo - tokenInfo formated ok" );
   }

   Log::logCK_RV( "Slot::GetTokenInfo", rv );
   Log::end( "Slot::GetTokenInfo" );

   return rv;
}


/*
*/
CK_RV Slot::GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,CK_ULONG_PTR pulCount)
{
   if(pulCount == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   if(pMechanismList == NULL_PTR)
   {
      *pulCount = (sizeof(MechanismList)/sizeof(CK_ULONG));
   }
   else
   {
      if(*pulCount < (sizeof(MechanismList)/sizeof(CK_ULONG)))
      {
         *pulCount = (sizeof(MechanismList)/sizeof(CK_ULONG));
         return CKR_BUFFER_TOO_SMALL;
      }

      for(size_t i=0;i<(sizeof(MechanismList)/sizeof(CK_ULONG));i++)
      {
         pMechanismList[i] = MechanismList[i];
      }
      *pulCount = (sizeof(MechanismList)/sizeof(CK_ULONG));
   }

   return CKR_OK;
}


/*
*/
CK_RV Slot::GetMechanismInfo(CK_MECHANISM_TYPE type,CK_MECHANISM_INFO_PTR pInfo)
{
   if(pInfo == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   size_t i = 0;
   CK_BBOOL found = CK_FALSE;
   for( ;i<(sizeof(MechanismList)/sizeof(CK_ULONG));i++)
   {
      if(MechanismList[i] == type)
      {
         found = CK_TRUE;
         break;
      }
   }

   if(found == CK_FALSE)
   {
      return CKR_MECHANISM_INVALID;
   }

   pInfo->ulMinKeySize = MechanismInfo[i].ulMinKeySize;
   pInfo->ulMaxKeySize = MechanismInfo[i].ulMaxKeySize;
   pInfo->flags  = MechanismInfo[i].flags;

   return CKR_OK;
}


CK_RV Slot::InitToken(CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen,CK_UTF8CHAR_PTR pLabel)
{
   CK_RV rv = CKR_OK;

   checkConnection( this );

   if(pPin == NULL_PTR || ulPinLen == 0 || pLabel == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }

   // check if we have an open session
   for(size_t i=1;i<_sessions.size();i++){
      if(this->_sessions[i] != NULL_PTR){
         return CKR_SESSION_EXISTS;
      }
   }

   rv = this->BuildToken();

   if(rv != CKR_OK){
      return rv;
   }

   u1Array* pin = new u1Array(ulPinLen);
   pin->SetBuffer(pPin);

   u1Array* label = new u1Array(32);
   label->SetBuffer(pLabel);

   // Don't do the Transaction here.

   rv = this->_token->InitToken(pin,label);

   delete pin;
   delete label;

   return rv;
}


/*
*/
CK_RV Slot::OpenSession( CK_FLAGS flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR phSession )
{
   checkConnection( this );

   if(phSession == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   if( ( flags & CKF_SERIAL_SESSION ) != CKF_SERIAL_SESSION )
   {
      return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
   }

   CK_RV rv = this->BuildToken( );
   if( rv != CKR_OK )
   {
      return rv;
   }

   Transaction trans( this );

   // if admin is logged we can not open RO session
   CK_BBOOL rwSession = ((flags & CKF_RW_SESSION) == CKF_RW_SESSION);

   if( ( this->_token->_roleLogged == CKU_SO ) && ( !rwSession ) )
   {
      return CKR_SESSION_READ_WRITE_SO_EXISTS;
   }

   // Create the session instance
   Session* session = new Session( rwSession );

   // lets create a session
   s4 sessionId = this->AddSession( session );
   if( 0 == sessionId )
   {
      return CKR_SESSION_COUNT;
   }

   session->SetId(sessionId);
   session->SetSlot(this);

   // Refresh the state of the session if the SSO mode is enabled
   UpdateAuthenticationState( );

   // prepare a unique session id
   *phSession = MAKE_SESSIONHANDLE(sessionId,this->_slotId);

   return rv;
}


/*
*/
CK_RV Slot::CloseSession( CK_SESSION_HANDLE hSession )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

   //CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   //Slot* pSlot = NULL_PTR;
   //GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   //checkConnection( pSlot );

   //hSessionId = CK_INVALID_HANDLE;
   //pSlot = NULL_PTR;
   //CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );

   if( CKR_OK == rv )
   {
      CHECK_IF_NULL_SESSION( pSlot, hSessionId );
      CHECK_IF_TOKEN_IS_PRESENT( pSlot );

      pSlot->RemoveSession( hSessionId );

      // Refresh the state of the session if the SSO mode is enabled
      pSlot->UpdateAuthenticationState( );
   }

   return rv;
}


/*
Check first if the card is in SSO mode then update the state of all sessions
*/
void Slot::UpdateAuthenticationState( void )
{
   // Check if the smart card is in SSO mode
   if( true == _token->isSSO( ) )
   {
      // Affect the role to the token if the user is authenticated
      _token->_roleLogged = CKU_NONE;
      if( true == _token->isAuthenticated( ) )
      {
         _token->_roleLogged = CKU_USER;
      }

      // Update the state of all sessions
      UpdateSessionState( );
   }
}


/*
*/
CK_RV Slot::CloseAllSessions(void)
{
   // remove all sessions
   for( size_t i = 1 ; i < _sessions.size( ) ; i++ )
   {
      if( NULL_PTR != this->_sessions[ i ] )
      {
         delete this->_sessions[ i ];
      }

      this->_sessions[ i ] = NULL_PTR;
   }

   _sessions.resize( 1 );

   CHECK_IF_TOKEN_IS_PRESENT( this );

   this->_token->_roleLogged = CKU_NONE;

   // Refresh the state of the session if the SSO mode is enabled
   UpdateAuthenticationState( );

   return CKR_OK;
}


/*
*/
CK_RV Slot::GetSessionInfo( CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

   if( CKR_OK != rv )
   {
      return rv;
   }

   if(pInfo == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   CHECK_IF_NULL_SESSION( pSlot, hSessionId);

   Transaction trans( pSlot );

   pInfo->slotID = pSlot->_slotId;
   pInfo->ulDeviceError = CKR_OK;

   // Check if the smart card is in SSO mode
   pSlot->UpdateAuthenticationState( );

   pInfo->flags = ( ( pSlot->_sessions[ hSessionId ]->_isReadWrite ) ? CKF_RW_SESSION : 0 ) | (CKF_SERIAL_SESSION);
   pInfo->state = pSlot->_sessions[ hSessionId ]->_state;

   return rv;
}


/*
*/
CK_RV Slot::Login( CK_SESSION_HANDLE hSession,
                   CK_USER_TYPE userType,
                   CK_UTF8CHAR_PTR pPin,
                   CK_ULONG ulPinLen )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

   if(rv != CKR_OK)
   {
      return rv;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   if(userType == CKU_SO)
   {
      if(pSlot->HasReadOnlySession())
      {
         return CKR_SESSION_READ_ONLY_EXISTS;
      }
   }

   if( NULL_PTR == pPin )
   {
      ulPinLen = 0;
   }

   u1Array* pinValue = new u1Array(ulPinLen);
   u1* pinValueBuffer = pinValue->GetBuffer();
   CK_BYTE idx = 0;
   for(idx=0;idx<ulPinLen;idx++)
   {
      pinValueBuffer[idx] = pPin[idx];
   }
   rv = pSlot->_token->Login(userType,pinValue);

   if(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
   {
      if(userType == CKU_SO)
      {
         // cache SO PIN for the duration of this session
         pSlot->_sessions[ hSessionId ]->_soPIN = new u1Array(pinValue->GetLength());
         pSlot->_sessions[ hSessionId ]->_soPIN->SetBuffer(pinValue->GetBuffer());
      }
   }

   if(rv == CKR_OK)
   {
      pSlot->UpdateSessionState();
   }

   delete pinValue;

   return rv;
}



CK_RV Slot::Logout( CK_SESSION_HANDLE hSession )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

   if(rv != CKR_OK)
   {
      return rv;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   rv = pSlot->_token->Logout( );

   pSlot->UpdateSessionState( );

   return rv;
}


CK_RV Slot::InitPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

   if(rv != CKR_OK){
      return rv;
   }

   if(pPin == NULL_PTR || ulPinLen == 0){
      return CKR_ARGUMENTS_BAD;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   if(session->_state != CKS_RW_SO_FUNCTIONS)
   {
      return CKR_USER_NOT_LOGGED_IN;
   }

   PKCS11_ASSERT(session->_soPIN != NULL_PTR);

   u1Array* pin = new u1Array(ulPinLen);
   pin->SetBuffer(pPin);

   rv = pSlot->_token->InitPIN(session->_soPIN,pin);

   delete pin;

   return rv;
}


/*
*/
CK_RV Slot::SetPIN( CK_SESSION_HANDLE hSession,
                    CK_UTF8CHAR_PTR pOldPin,
                    CK_ULONG ulOldLen,
                    CK_UTF8CHAR_PTR pNewPin,
                    CK_ULONG ulNewLen )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   if(pOldPin == NULL_PTR || ulOldLen == 0 || pNewPin == NULL_PTR || ulNewLen == 0)
   {
      return CKR_ARGUMENTS_BAD;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   CK_ULONG state = pSlot->_sessions[ hSessionId ]->_state;

   if((state != CKS_RW_PUBLIC_SESSION) &&
      (state != CKS_RW_SO_FUNCTIONS)&&
      (state != CKS_RW_USER_FUNCTIONS))
   {
      return CKR_SESSION_READ_ONLY;
   }

   u1Array* oldPin = new u1Array(ulOldLen);
   oldPin->SetBuffer(pOldPin);

   u1Array* newPin = new u1Array(ulNewLen);
   newPin->SetBuffer(pNewPin);

   rv = pSlot->_token->SetPIN(oldPin,newPin);

   delete oldPin;
   delete newPin;

   return rv;
}


CK_RV  Slot::FindObjectsInit(CK_SESSION_HANDLE hSession,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   if((pTemplate == NULL_PTR) && (ulCount != 0))
   {
      return CKR_ARGUMENTS_BAD;
   }

   Session* session = pSlot->_sessions[ hSessionId ];

   // check if search is active for this session or not
   if(session->IsSearchActive() == CK_TRUE)
   {
      return CKR_OPERATION_ACTIVE;
   }

   Template* searchTmpl = NULL_PTR;
   if(ulCount != 0)
   {
      searchTmpl = new Template(pTemplate,ulCount);
   }

   session->SetSearchTemplate(searchTmpl);

   return rv;
}



CK_RV  Slot::FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount)
{
   Log::begin( "Slot::FindObjects" );

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );
   if(rv != CKR_OK)
   {
      return rv;
   }

   if((phObject == NULL_PTR) || (pulObjectCount == NULL_PTR))
   {
      Log::error( "Slot::FindObjects", "CKR_ARGUMENTS_BAD" );
      return CKR_ARGUMENTS_BAD;
   }

   Log::log( "Slot::FindObjects - CHECK_IF_TOKEN_IS_PRESENT" );
   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   Log::log( "Slot::FindObjects - CHECK_IF_TOKEN_IS_PRESENT" );

   Log::log( "Slot::FindObjects - CHECK_IF_NULL_SESSION" );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Log::log( "Slot::FindObjects - CHECK_IF_NULL_SESSION" );

   // Not needed here...
   Log::log( "Slot::FindObjects - Transaction" );
   Transaction trans( pSlot );
   Log::log( "Slot::FindObjects - Transaction" );

   Log::log( "Slot::FindObjects - session" );
   Session* session = pSlot->_sessions[ hSessionId ];
   Log::log( "Slot::FindObjects - session" );

   // check if search is active for this session or not
   Log::log( "Slot::FindObjects - IsSearchActive" );
   if(session->IsSearchActive() == CK_FALSE)
   {
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   Log::log( "Slot::FindObjects - IsSearchActive" );

   *pulObjectCount = 0;

   // find the token objects matching the template
   // count will tell how much of the phObject buffer was written
   Log::log( "Slot::FindObjects - FindObjects" );
   CK_ULONG count = pSlot->_token->FindObjects( session, phObject, ulMaxObjectCount, pulObjectCount );
   Log::log( "Slot::FindObjects - FindObjects" );

   if(count < ulMaxObjectCount)
   {
      // find the session objects matching the template
      Log::log( "Slot::FindObjects - (count < ulMaxObjectCount)" );
      count = session->FindObjects(count,phObject,ulMaxObjectCount,pulObjectCount);
      Log::log( "Slot::FindObjects - (count < ulMaxObjectCount)" );
   }

   Log::logCK_RV( "Slot::FindObjects", rv );
   Log::end( "Slot::FindObjects" );

   return rv;
}



CK_RV  Slot::FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );
   if(rv != CKR_OK)
   {
      return rv;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );

   // Not needed here
   // Transaction trans(slot);

   Session* session = pSlot->_sessions[ hSessionId ];

   // check if search is active for this session or not
   if(session->IsSearchActive() == CK_FALSE)
   {
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   session->RemoveSearchTemplate();

   return rv;
}

CK_RV Slot::GenerateRandom(CK_SESSION_HANDLE hSession,CK_BYTE_PTR randomData,CK_ULONG ulRandomLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );
   if(rv != CKR_OK)
   {
      return rv;
   }

   if((randomData == NULL_PTR) || (ulRandomLen == 0))
   {
      return CKR_ARGUMENTS_BAD;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   return pSlot->_token->GenerateRandom(randomData,ulRandomLen);
}



CK_RV Slot::CreateObject( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject )
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   checkConnection( pSlot );

  if(rv != CKR_OK)
   {
      return rv;
   }

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   // check the pointer arguments
   if((pTemplate == NULL_PTR) || (ulCount == 0) || (phObject == NULL_PTR))
   {
      return CKR_ARGUMENTS_BAD;
   }

   // Check Template Consitency
   rv = Template::CheckTemplate(pTemplate, ulCount, MODE_CREATE);
   if (rv != CKR_OK)
   {
      return rv;
   }

   CK_ULONG classVal = Template::FindClassFromTemplate(pTemplate,ulCount);
   PKCS11_ASSERT(classVal != -1);

   auto_ptr<StorageObject> object;

   switch(classVal){

        case CKO_DATA:
           object = auto_ptr<StorageObject>(new DataObject());
           break;

        case CKO_SECRET_KEY:
           object = auto_ptr<StorageObject>(new SecretKeyObject());
           break;

        case CKO_PUBLIC_KEY:
           object = auto_ptr<StorageObject>(new RSAPublicKeyObject());
           break;

        case CKO_PRIVATE_KEY:
           object = auto_ptr<StorageObject>(new RSAPrivateKeyObject());
           break;

        case CKO_CERTIFICATE:
           object = auto_ptr<StorageObject>(new X509PubKeyCertObject());
           break;

        default:
           PKCS11_ASSERT(CK_FALSE);
           break;
   }

   CK_BBOOL objCreationFailed = CK_FALSE;
   CK_BYTE idx;
   for(idx = 0; idx < ulCount; idx++)
   {
      if((rv = object->SetAttribute(pTemplate[idx],CK_TRUE)) != CKR_OK){
         objCreationFailed = CK_TRUE;
         break;
      }
   }

   if(objCreationFailed)
   {
      return rv;
   }

   switch(object->_class)
   {
        case CKO_PUBLIC_KEY:
           if(((RSAPublicKeyObject*)object.get())->_keyType != CKK_RSA)
           {
              return CKR_KEY_TYPE_INCONSISTENT;
           }
           break;

        case CKO_PRIVATE_KEY:
           if(((RSAPrivateKeyObject*)object.get())->_keyType != CKK_RSA)
           {
              return CKR_KEY_TYPE_INCONSISTENT;
           }
           break;
   }

   Session* session = pSlot->_sessions[ hSessionId ];

   // if this is a readonly session and
   // user is not logged then only public session objects
   // can be created
   if(session->_isReadWrite == CK_FALSE)
   {
      if(object->_tokenObject)
      {
         return CKR_SESSION_READ_ONLY;
      }
   }

   if ((pSlot->_token->_roleLogged != CKU_USER) && (object->_private == CK_TRUE))
   {
      return CKR_USER_NOT_LOGGED_IN;
   }

   if(object->_tokenObject)
   {

      // any type of token object cannot be created
      // unless user is logged in

      // NOTE : Not PKCS#11 compilance
      // CardModule service does not allow 'deletion' of any file unless user is logged in. We can create a file
      // when nobody is logged in but we can not delete. In order to be symmetrical we do not also allow
      // the creation.
      if(pSlot->_token->_roleLogged != CKU_USER)
      {
         return CKR_USER_NOT_LOGGED_IN;
      }

      // some sanity checks
      if(object->_class == CKO_PRIVATE_KEY)
      {
         rv = pSlot->_token->AddPrivateKeyObject(object, phObject);
      }
      else if(object->_class == CKO_CERTIFICATE)
      {
         rv = pSlot->_token->AddCertificateObject(object, phObject);
      }
      else
      {
         rv = pSlot->_token->AddObject(object, phObject);
      }
   }
   else
   {
      rv = session->AddObject(object.get(),phObject);
      if(rv == CKR_OK)
         object.release();
   }

   return rv;
}



CK_RV Slot::DestroyObject(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hObject & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   // if this is a readonly session and
   // user is not logged then only public session objects
   // can be created
   if(session->_isReadWrite == CK_FALSE)
   {
      if(istoken)
      {
         return CKR_SESSION_READ_ONLY;
      }
   }

   if(istoken)
   {
      rv = pSlot->_token->DeleteObject(hObject);
   }
   else
   {
      rv = session->DeleteObject(hObject);
   }

   return rv;
}


/*
*/
CK_RV Slot::GetAttributeValue( CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulCount )
{
   if(pTemplate == NULL_PTR || ulCount == 0)
   {
      return CKR_ARGUMENTS_BAD;
   }

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hObject & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   // TBD : Attributes of types such as Array which have not be initialized ?
   // for eg label

   if(istoken)
   {
      rv = pSlot->_token->GetAttributeValue(hObject,pTemplate,ulCount);
   }
   else
   {
      rv = session->GetAttributeValue(hObject,pTemplate,ulCount);
   }

   return rv;
}


/*
*/
CK_RV Slot::SetAttributeValue( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount )
{
   if(pTemplate == NULL_PTR || ulCount == 0)
   {
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
  if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* pSession = pSlot->_sessions[ hSessionId ];

   // From object handle we can determine if it is a token object or session object
   CK_BBOOL istoken = ( ( hObject & CO_TOKEN_OBJECT ) == CO_TOKEN_OBJECT );
   if( TRUE == istoken )
   {
      if( CK_FALSE == pSession->_isReadWrite )
      {
         return CKR_SESSION_READ_ONLY;
      }

      rv = pSlot->_token->SetAttributeValue( hObject, pTemplate, ulCount );
   }
   else
   {
      rv = pSession->SetAttributeValue( hObject, pTemplate, ulCount );
   }

   return rv;
}


CK_RV Slot::GenerateKeyPair(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                            CK_ULONG ulPublicKeyAttributeCount,CK_ATTRIBUTE_PTR pPrivateKeyTemplate,CK_ULONG ulPrivateKeyAttributeCount,
                            CK_OBJECT_HANDLE_PTR phPublicKey,CK_OBJECT_HANDLE_PTR phPrivateKey)
{
   // Since MODULUS_BITS is an essential attribute pPublicKeyTemplate should never be NULL or ulPublicKeyAttributeCount
   // should not be zero. For private key template there is not compuslary attributes to be specified so it can be
   // NULL_PTR

   if((pMechanism == NULL_PTR) || (pPublicKeyTemplate == NULL_PTR) ||
      (ulPublicKeyAttributeCount == 0) || (phPublicKey == NULL_PTR) ||
      (phPrivateKey == NULL_PTR))
   {
      return CKR_ARGUMENTS_BAD;
   }

   if(pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)
      return CKR_MECHANISM_INVALID;

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   //Session* session = pSlot->_sessions[ hSessionId ];

   // Check Public Template Consitency
   rv = Template::CheckTemplate(pPublicKeyTemplate, ulPublicKeyAttributeCount, MODE_GENERATE_PUB);
   if (rv != CKR_OK)
      return rv;

   // Check Private Template Consitency
   rv = Template::CheckTemplate(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, MODE_GENERATE_PRIV);
   if (rv != CKR_OK)
      return rv;

   auto_ptr<StorageObject> rsaPubKey(new RSAPublicKeyObject());
   for(u4 i=0;i<ulPublicKeyAttributeCount;i++){
      rv = rsaPubKey->SetAttribute(pPublicKeyTemplate[i],CK_TRUE);
      if(rv != CKR_OK){
         return rv;
      }
   }

   auto_ptr<StorageObject> rsaPrivKey(new RSAPrivateKeyObject());
   for(u4 i=0;i<ulPrivateKeyAttributeCount;i++){
      rv = rsaPrivKey->SetAttribute(pPrivateKeyTemplate[i],CK_TRUE);
      if(rv != CKR_OK){
         return rv;
      }
   }

   if(rsaPrivKey->_tokenObject){
      rv = pSlot->_token->GenerateKeyPair(rsaPubKey,rsaPrivKey,phPublicKey,phPrivateKey);
   }else{

      // We do not support generation of key pair in the software
      // TBD: Should we ?. I have noticed that during the import of
      // p12 file using firefox it asks you to generate it in session

      return CKR_ATTRIBUTE_VALUE_INVALID;
   }

   if(rv == CKR_OK)
   {
      if(rsaPubKey.get() && !rsaPubKey->_tokenObject)
      {
         pSlot->_sessions[ hSessionId ]->AddObject(rsaPubKey.get(),phPublicKey);
         rsaPubKey.release();
      }
   }
   return rv;
}

// ------------------------------------------------------------------------------------------------
//                                  DIGEST RELATED FUNCTIONS
// ------------------------------------------------------------------------------------------------
CK_RV Slot::DigestInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism)
{
   if(pMechanism == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   // Not needed
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   if(session->IsDigestActive()){
      return CKR_OPERATION_ACTIVE;
   }

   switch(pMechanism->mechanism){

        case CKM_SHA_1:
           session->SetDigest(new CSHA1());
           break;

        case CKM_SHA256:
           session->SetDigest(new CSHA256());
           break;

        case CKM_MD5:
           session->SetDigest(new CMD5());
           break;

        default:
           return CKR_MECHANISM_INVALID;

   }

   return rv;
}


/*
*/
CK_RV Slot::Digest(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,
                   CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen)
{
   if((pData == NULL_PTR) || (ulDataLen == 0) || (pulDigestLen == NULL_PTR)){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsDigestActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   CDigest* digest = session->_digest;

   if((*pulDigestLen < (CK_ULONG)digest->HashLength()) && (pDigest != NULL_PTR)){
      *pulDigestLen = (CK_ULONG)digest->HashLength();
      return CKR_BUFFER_TOO_SMALL;
   }
   else if(!pDigest){
      *pulDigestLen = digest->HashLength();
      return CKR_OK;
   }

   digest->HashCore(pData, 0, ulDataLen);

   *pulDigestLen = (CK_ULONG)digest->HashLength();

   if (pDigest != NULL_PTR)
   {
      digest->HashFinal(pDigest);
      session->RemoveDigest();
   }

   return rv;
}


/*
*/
CK_RV Slot::DigestUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen)
{
   if(pPart == NULL_PTR || ulPartLen == 0)
   {
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsDigestActive() == CK_FALSE)
   {
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   session->_digest->HashCore(pPart,0,ulPartLen);

   return rv;
}


/*
*/
CK_RV Slot::DigestFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen)
{
   if(pulDigestLen == NULL_PTR)
   {
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   if(session->IsDigestActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   CDigest*    digest   = session->_digest;

   if((*pulDigestLen < (CK_ULONG)digest->HashLength()) && (pDigest != NULL_PTR)){
      *pulDigestLen = (CK_ULONG)digest->HashLength();
      return CKR_BUFFER_TOO_SMALL;
   }
   else if(!pDigest){
      *pulDigestLen = digest->HashLength();
      return CKR_OK;
   }

   *pulDigestLen = (CK_ULONG)digest->HashLength();

   if (pDigest != NULL_PTR){
      digest->HashFinal(pDigest);
      session->RemoveDigest();
   }

   return rv;
}

// ------------------------------------------------------------------------------------------------
//                                  SIGNATURE RELATED FUNCTIONS
// ------------------------------------------------------------------------------------------------
CK_RV Slot::SignInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey)
{
   if(pMechanism == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];

   if(session->IsSignatureActive() == CK_TRUE){
      return CKR_OPERATION_ACTIVE;
   }

   rv = Slot::IsValidMechanism(pMechanism->mechanism,CKF_SIGN);

   if(rv != CKR_OK){
      return rv;
   }

   if(pSlot->_token->_roleLogged != CKU_USER){
      return CKR_USER_NOT_LOGGED_IN;
   }

   // get the corresponding object
   StorageObject* object = NULL_PTR;

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hKey & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   if(istoken){
      rv = pSlot->_token->GetObject(hKey,&object);
   }else{
      rv = session->GetObject(hKey,&object);
   }

   if(rv != CKR_OK){

      if(rv == CKR_OBJECT_HANDLE_INVALID){
         return CKR_KEY_HANDLE_INVALID;
      }

      return rv;
   }

   rv = Slot::IsValidCryptoOperation(object,CKF_SIGN);

   if(rv != CKR_OK){
      return rv;
   }

   // let's initialize this crypto operation
   session->SetSignatureOperation(new CryptoOperation(pMechanism->mechanism,object));

   if(pMechanism->mechanism == CKM_SHA1_RSA_PKCS){
      session->SetDigestRSA(new CSHA1());
   }else if(pMechanism->mechanism == CKM_SHA256_RSA_PKCS){
      session->SetDigestRSA(new CSHA256());
   }else if(pMechanism->mechanism == CKM_MD5_RSA_PKCS){
      session->SetDigestRSA(new CMD5());
   }

   return rv;
}



CK_RV Slot::Sign(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,
                 CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsSignatureActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if(pData == NULL_PTR || ulDataLen == 0 || pulSignatureLen == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }

   StorageObject* object = session->_signature->GetObject();

   PKCS11_ASSERT(object->_class == CKO_PRIVATE_KEY);

   CK_ULONG mechanism = session->_signature->GetMechanism();

   // TBD : Private key may not necessarily have the modulus or modulus bits
   // if that is the case then we need to locate the corresponding public key
   // or may be I should always put the modulus bits in private key attributes

   u1Array* modulus = ((RSAPrivateKeyObject*)object)->_modulus;

   PKCS11_ASSERT(modulus != NULL_PTR);

   if(((mechanism == CKM_RSA_PKCS) && (ulDataLen > modulus->GetLength() - 11)) ||
      ((mechanism == CKM_RSA_X_509) && (ulDataLen > modulus->GetLength())))
   {
      return CKR_DATA_LEN_RANGE;
   }

   if(pSignature == NULL_PTR){
      *pulSignatureLen = modulus->GetLength();
      return CKR_OK;
   }else{
      if(*pulSignatureLen < modulus->GetLength()){
         *pulSignatureLen = modulus->GetLength();
         return CKR_BUFFER_TOO_SMALL;
      }
   }

   u1Array* dataToSign = NULL_PTR;

   if(session->IsDigestRSAActive() == CK_TRUE){
      // require hashing also
      CK_BYTE_PTR hash   = NULL_PTR;
      CDigest* digest = session->_digestRSA;

      hash = (CK_BYTE_PTR)malloc(digest->HashLength());

      digest->HashCore(pData,0,ulDataLen);
      digest->HashFinal(hash);

      dataToSign  = new u1Array(digest->HashLength());
      dataToSign->SetBuffer(hash);

      free(hash);
   }
   // Sign Only
   else {
      dataToSign = new u1Array(ulDataLen);
      dataToSign->SetBuffer(pData);
   }

   rv = pSlot->_token->Sign(session->_signature->GetObject(),dataToSign,session->_signature->GetMechanism(),pSignature);

   if(rv == CKR_OK){
      *pulSignatureLen = modulus->GetLength();
   }

   session->RemoveDigestRSA();
   session->RemoveSignatureOperation();

   delete dataToSign;

   return rv;
}



CK_RV Slot::SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
   // what we do here is to update the hash or
   // if hashing is not getting used we just accumulate it

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsSignatureActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if(pPart == NULL_PTR || ulPartLen == 0){
      return CKR_ARGUMENTS_BAD;
   }

   if(session->IsDigestRSAActive() == CK_TRUE){
      CDigest* digest = session->_digestRSA;
      digest->HashCore(pPart,0,ulPartLen);
   }
   // Sign Only
   else {

      if(session->_accumulatedDataToSign != NULL_PTR){
         // just accumulate the data
         u1Array* updatedData = new u1Array(session->_accumulatedDataToSign->GetLength() + ulPartLen);
         memcpy(updatedData->GetBuffer(),session->_accumulatedDataToSign->GetBuffer(),session->_accumulatedDataToSign->GetLength());

         memcpy((u1*)&updatedData->GetBuffer()[session->_accumulatedDataToSign->GetLength()],pPart,ulPartLen);

         delete session->_accumulatedDataToSign;

         session->_accumulatedDataToSign = updatedData;
      }else{

         session->_accumulatedDataToSign = new u1Array(ulPartLen);
         session->_accumulatedDataToSign->SetBuffer(pPart);
      }

      CK_ULONG mech = session->_signature->GetMechanism();
      u1Array* modulus = ((RSAPrivateKeyObject*)session->_signature->GetObject())->_modulus;

      if(((mech == CKM_RSA_PKCS) && (session->_accumulatedDataToSign->GetLength() > modulus->GetLength() - 11)) ||
         ((mech == CKM_RSA_X_509) && (session->_accumulatedDataToSign->GetLength() > modulus->GetLength())))
      {
         return CKR_DATA_LEN_RANGE;
      }
   }

   return rv;
}


/*
*/
CK_RV Slot::SignFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsSignatureActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if(pulSignatureLen == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }

   StorageObject* object = session->_signature->GetObject();

   PKCS11_ASSERT(object->_class == CKO_PRIVATE_KEY);


   // TBD : Private key may not necessarily have the modulus or modulus bits
   // if that is the case then we need to locate the corresponding public key
   // or may be I should always put the modulus bits in private key attributes

   u1Array* modulus = ((RSAPrivateKeyObject*)object)->_modulus;

   PKCS11_ASSERT(modulus != NULL_PTR);

   if(pSignature == NULL_PTR){
      *pulSignatureLen = modulus->GetLength();
      return CKR_OK;
   }else{
      if(*pulSignatureLen < modulus->GetLength()){
         *pulSignatureLen = modulus->GetLength();
         return CKR_BUFFER_TOO_SMALL;
      }
   }

   u1Array* dataToSign = NULL_PTR;

   if(session->IsDigestRSAActive() == CK_TRUE){
      // require hashing also
      CK_BYTE_PTR hash   = NULL_PTR;
      CDigest* digest = session->_digestRSA;

      hash = (CK_BYTE_PTR)malloc(digest->HashLength());

      digest->HashFinal(hash);

      dataToSign  = new u1Array(digest->HashLength());
      dataToSign->SetBuffer(hash);

      free(hash);
   }
   // Sign Only
   else {
      dataToSign = session->_accumulatedDataToSign;
   }

   rv = pSlot->_token->Sign(session->_signature->GetObject(),dataToSign,session->_signature->GetMechanism(),pSignature);

   if(rv == CKR_OK){
      *pulSignatureLen = modulus->GetLength();
   }

   session->RemoveDigestRSA();
   session->RemoveSignatureOperation();

   delete dataToSign;
   session->_accumulatedDataToSign = NULL_PTR;

   return rv;
}



CK_RV Slot::EncryptInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey)
{
   if(pMechanism == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsEncryptionActive() == CK_TRUE){
      return CKR_OPERATION_ACTIVE;
   }

   rv = Slot::IsValidMechanism(pMechanism->mechanism,CKF_ENCRYPT);

   if(rv != CKR_OK){
      return rv;
   }

   if(pSlot->_token->_roleLogged != CKU_USER){
      return CKR_USER_NOT_LOGGED_IN;
   }

   // get the corresponding object
   StorageObject* object = NULL_PTR;

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hKey & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   if(istoken){
      rv = pSlot->_token->GetObject(hKey,&object);
   }else{
      rv = session->GetObject(hKey,&object);
   }

   if(rv != CKR_OK){
      if(rv == CKR_OBJECT_HANDLE_INVALID){
         return CKR_KEY_HANDLE_INVALID;
      }

      return rv;
   }

   rv = Slot::IsValidCryptoOperation(object,CKF_ENCRYPT);

   if(rv != CKR_OK){
      return rv;
   }

   // let's initialize this crypto operation
   session->SetEncryptionOperation(new CryptoOperation(pMechanism->mechanism,object));

   return rv;
}


/*
*/
CK_RV Slot::Encrypt(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,
                    CK_BYTE_PTR pEncryptedData,CK_ULONG_PTR pulEncryptedDataLen)
{
   if(pData == NULL_PTR || ulDataLen == 0 || pulEncryptedDataLen == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
    if(rv != CKR_OK)
   {
      return rv;
   }
  checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsEncryptionActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   StorageObject* object = session->_encryption->GetObject();

   PKCS11_ASSERT(object->_class == CKO_PUBLIC_KEY);

   //CK_ULONG mechanism = session->_encryption->GetMechanism();

   u1Array* modulus = ((RSAPublicKeyObject*)object)->_modulus;

   PKCS11_ASSERT(modulus != NULL_PTR);

   if(pEncryptedData == NULL_PTR){
      *pulEncryptedDataLen = modulus->GetLength();
      return CKR_OK;
   }else{
      if(*pulEncryptedDataLen < modulus->GetLength()){
         *pulEncryptedDataLen = modulus->GetLength();
         return CKR_BUFFER_TOO_SMALL;
      }
   }

   u1Array* dataToEncrypt = new u1Array(ulDataLen);
   dataToEncrypt->SetBuffer(pData);

   rv = pSlot->_token->Encrypt(session->_encryption->GetObject(),dataToEncrypt,session->_encryption->GetMechanism(),pEncryptedData);

   if(rv == CKR_OK){
      *pulEncryptedDataLen = modulus->GetLength();
   }

   session->RemoveEncryptionOperation();

   delete dataToEncrypt;

   return rv;
}


/*
*/
CK_RV Slot::DecryptInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey)
{
   if(pMechanism == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsDecryptionActive() == CK_TRUE){
      return CKR_OPERATION_ACTIVE;
   }

   rv = Slot::IsValidMechanism(pMechanism->mechanism,CKF_DECRYPT);

   if(rv != CKR_OK){
      return rv;
   }

   if(pSlot->_token->_roleLogged != CKU_USER){
      return CKR_USER_NOT_LOGGED_IN;
   }

   // get the corresponding object
   StorageObject* object = NULL_PTR;

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hKey & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   if(istoken){
      rv = pSlot->_token->GetObject(hKey,&object);
   }else{
      rv = session->GetObject(hKey,&object);
   }

   if(rv != CKR_OK){
      if(rv == CKR_OBJECT_HANDLE_INVALID){
         return CKR_KEY_HANDLE_INVALID;
      }

      return rv;
   }

   rv = Slot::IsValidCryptoOperation(object,CKF_DECRYPT);

   if(rv != CKR_OK){
      return rv;
   }

   // let's initialize this crypto operation
   session->SetDecryptionOperation(new CryptoOperation(pMechanism->mechanism,object));

   return rv;
}


/*
*/
CK_RV Slot::Decrypt(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedData,CK_ULONG ulEncryptedDataLen,
                    CK_BYTE_PTR pData,CK_ULONG_PTR pulDataLen)
{
   if(pEncryptedData == NULL_PTR || ulEncryptedDataLen == 0 ||pulDataLen == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsDecryptionActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   StorageObject* object = session->_decryption->GetObject();

   PKCS11_ASSERT(object->_class == CKO_PRIVATE_KEY);

   CK_ULONG mechanism = session->_decryption->GetMechanism();

   // TBD : Private key may not necessarily have the modulus or modulus bits
   // if that is the case then we need to locate the corresponding public key
   // or may be I should always put the modulus bits in private key attributes

   u1Array* modulus = ((RSAPrivateKeyObject*)object)->_modulus;

   PKCS11_ASSERT(modulus != NULL_PTR);

   // [HB]: Fix length of return value
   if(mechanism == CKM_RSA_PKCS){
      // Can't know exact size of returned value before decryption has been done
      if(pData == NULL_PTR){
         *pulDataLen = modulus->GetLength() - 11;
         return CKR_OK;
      }
   }
   else if(mechanism == CKM_RSA_X_509){
      if(pData == NULL_PTR){
         *pulDataLen = modulus->GetLength();
         return CKR_OK;
      }else{
         if(*pulDataLen < modulus->GetLength()){
            *pulDataLen = modulus->GetLength();
            return CKR_BUFFER_TOO_SMALL;
         }
      }
   }
   else
      return CKR_MECHANISM_INVALID;

   if(ulEncryptedDataLen != modulus->GetLength()){
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }

   u1Array* dataToDecrypt = new u1Array(ulEncryptedDataLen);
   dataToDecrypt->SetBuffer(pEncryptedData);

   rv = pSlot->_token->Decrypt(session->_decryption->GetObject(),dataToDecrypt,session->_decryption->GetMechanism(),pData, pulDataLen);

   session->RemoveDecryptionOperation();

   delete dataToDecrypt;

   return rv;
}


/*
*/
CK_RV  Slot::VerifyInit(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey)
{
   if(pMechanism == NULL_PTR){
      return CKR_ARGUMENTS_BAD;
   }

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
    if(rv != CKR_OK)
   {
      return rv;
   }
  checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsVerificationActive() == CK_TRUE){
      return CKR_OPERATION_ACTIVE;
   }

   rv = Slot::IsValidMechanism(pMechanism->mechanism,CKF_VERIFY);

   if(rv != CKR_OK){
      return rv;
   }

   if(pSlot->_token->_roleLogged != CKU_USER){
      return CKR_USER_NOT_LOGGED_IN;
   }

   // get the corresponding object
   StorageObject* object = NULL_PTR;

   // from object handle we can determine
   // if it is a token object or session object
   CK_BBOOL istoken = ((hKey & CO_TOKEN_OBJECT) == CO_TOKEN_OBJECT);

   if(istoken){
      rv = pSlot->_token->GetObject(hKey,&object);
   }else{
      rv = session->GetObject(hKey,&object);
   }

   if(rv != CKR_OK){

      if(rv == CKR_OBJECT_HANDLE_INVALID){
         return CKR_KEY_HANDLE_INVALID;
      }

      return rv;
   }

   rv = Slot::IsValidCryptoOperation(object,CKF_VERIFY);

   if(rv != CKR_OK){
      return rv;
   }

   // let's initialize this crypto operation
   session->SetVerificationOperation(new CryptoOperation(pMechanism->mechanism,object));

   if(pMechanism->mechanism == CKM_SHA1_RSA_PKCS){
      session->SetDigestRSAVerification(new CSHA1());
   }else if(pMechanism->mechanism == CKM_SHA256_RSA_PKCS){
      session->SetDigestRSAVerification(new CSHA256());
   }else if(pMechanism->mechanism == CKM_MD5_RSA_PKCS){
      session->SetDigestRSAVerification(new CMD5());
   }

   return CKR_OK;

}


/*
*/
CK_RV  Slot::Verify(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsVerificationActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if((pData == NULL_PTR) || (ulDataLen == 0) ||
      (pSignature == NULL_PTR) || (ulSignatureLen == 0))
   {
      return CKR_ARGUMENTS_BAD;
   }

   CK_ULONG mechanism = session->_verification->GetMechanism();


   // I am doubtful regarding these 3 lines as
   // the object could be privatekey which contains
   // the public components
   StorageObject* object = session->_verification->GetObject();
   PKCS11_ASSERT(object->_class == CKO_PUBLIC_KEY);
   u1Array* modulus = ((RSAPublicKeyObject*)object)->_modulus;

   PKCS11_ASSERT(modulus != NULL_PTR);

   if(((mechanism == CKM_RSA_PKCS) && (ulDataLen > modulus->GetLength() - 11)) ||
      ((mechanism == CKM_RSA_X_509) && (ulDataLen > modulus->GetLength())))
   {
      return CKR_DATA_LEN_RANGE;
   }

   u1Array* dataToVerify = NULL_PTR;

   if(session->IsDigestRSAVerificationActive() == CK_TRUE){
      // require hashing also
      CK_BYTE_PTR hash   = NULL_PTR;
      CDigest* digest = session->_digestRSAVerification;

      hash = (CK_BYTE_PTR)malloc(digest->HashLength());

      digest->HashCore(pData,0,ulDataLen);
      digest->HashFinal(hash);

      dataToVerify  = new u1Array(digest->HashLength());
      dataToVerify->SetBuffer(hash);

      free(hash);
   }
   // Sign Only
   else {
      dataToVerify = new u1Array(ulDataLen);
      dataToVerify->SetBuffer(pData);
   }

   u1Array* signature = new u1Array(ulSignatureLen);
   signature->SetBuffer(pSignature);

   rv = pSlot->_token->Verify(session->_verification->GetObject(),dataToVerify,session->_verification->GetMechanism(),signature);

   delete signature;

   session->RemoveDigestRSAVerification();
   session->RemoveVerificationOperation();

   delete dataToVerify;

   return rv;
}


/*
*/
CK_RV Slot::VerifyUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen)
{

   // what we do here is to update the hash or
   // if hashing is not getting used we just accumulate it

   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsVerificationActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if(pPart == NULL_PTR || ulPartLen == 0){
      return CKR_ARGUMENTS_BAD;
   }

   if(session->IsDigestRSAVerificationActive() == CK_TRUE){
      CDigest* digest = session->_digestRSAVerification;
      digest->HashCore(pPart,0,ulPartLen);
   }
   // Sign Only
   else {

      if(session->_accumulatedDataToVerify != NULL_PTR){
         // just accumulate the data
         u1Array* updatedData = new u1Array(session->_accumulatedDataToVerify->GetLength() + ulPartLen);
         memcpy(updatedData->GetBuffer(),session->_accumulatedDataToVerify->GetBuffer(),session->_accumulatedDataToVerify->GetLength());

         memcpy((u1*)&updatedData->GetBuffer()[session->_accumulatedDataToVerify->GetLength()],pPart,ulPartLen);

         delete session->_accumulatedDataToVerify;

         session->_accumulatedDataToVerify = updatedData;
      }else{

         session->_accumulatedDataToVerify = new u1Array(ulPartLen);
         session->_accumulatedDataToVerify->SetBuffer(pPart);
      }

      CK_ULONG mech = session->_verification->GetMechanism();
      u1Array* modulus = ((RSAPublicKeyObject*)session->_verification->GetObject())->_modulus;

      if(((mech == CKM_RSA_PKCS) && (session->_accumulatedDataToVerify->GetLength() > modulus->GetLength() - 11)) ||
         ((mech == CKM_RSA_X_509) && (session->_accumulatedDataToVerify->GetLength() > modulus->GetLength())))
      {
         return CKR_DATA_LEN_RANGE;
      }
   }

   return rv;
}


/*
*/
CK_RV Slot::VerifyFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen)
{
   CK_SESSION_HANDLE hSessionId = CK_INVALID_HANDLE;
   Slot* pSlot = NULL_PTR;
   CK_RV rv = GetSlotAndSessionIdFromSessionHandle( hSession, &pSlot, &hSessionId );
   if(rv != CKR_OK)
   {
      return rv;
   }
   checkConnection( pSlot );

   CHECK_IF_TOKEN_IS_PRESENT( pSlot );
   CHECK_IF_NULL_SESSION( pSlot, hSessionId );
   Transaction trans( pSlot );

   Session* session = pSlot->_sessions[ hSessionId ];


   if(session->IsVerificationActive() == CK_FALSE){
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   if((pSignature == NULL_PTR) || (ulSignatureLen == 0)){
      return CKR_ARGUMENTS_BAD;
   }

   //StorageObject* object = session->_verification->GetObject();
   //PKCS11_ASSERT(object->_class == CKO_PUBLIC_KEY);

   u1Array* dataToVerify = NULL_PTR;

   if(session->IsDigestRSAVerificationActive() == CK_TRUE){
      // require hashing also
      CK_BYTE_PTR hash   = NULL_PTR;
      CDigest* digest = session->_digestRSAVerification;

      hash = (CK_BYTE_PTR)malloc(digest->HashLength());

      digest->HashFinal(hash);

      dataToVerify  = new u1Array(digest->HashLength());
      dataToVerify->SetBuffer(hash);

      free(hash);
   }
   // Sign Only
   else {
      dataToVerify = session->_accumulatedDataToVerify;
   }

   u1Array* signature = new u1Array(ulSignatureLen);
   signature->SetBuffer(pSignature);

   rv = pSlot->_token->Verify(session->_verification->GetObject(),dataToVerify,session->_verification->GetMechanism(),signature);

   session->RemoveDigestRSAVerification();
   session->RemoveVerificationOperation();

   delete dataToVerify;
   delete signature;
   session->_accumulatedDataToVerify = NULL_PTR;

   return rv;
}



// --------------



/* Return true if the connection is aware
*/
/*bool*/ void Slot::checkConnection( Slot* a_pSlot )
{
   Log::begin( "Slot::checkConnection" );

   //bool bRet = false;

   if( NULL_PTR != a_pSlot )
   {
      char readers[ 1024 ];
      memset( readers, 0, sizeof( readers ) );
      memcpy( readers, a_pSlot->_readerName->c_str( ), a_pSlot->_readerName->length( ) );
      DWORD dwLen = sizeof( readers );
      DWORD dwState = 0;
      DWORD dwProtocol = 0;
      BYTE Atr[32];
      memset( Atr, 0, sizeof( Atr ) );
      DWORD dwLenAtr = sizeof( Atr );
      if( NULL != a_pSlot->_token )
      {
         CardModuleService* pMSCM = a_pSlot->_token->GetMiniDriverService( );
         if( NULL != pMSCM )
         {
            SCARDHANDLE hCard = pMSCM->GetPcscCardHandle( );
            DWORD hResult = SCardStatus( hCard, readers, &dwLen, &dwState, &dwProtocol, &Atr[0], &dwLenAtr );
            Log::log( "Slot::checkConnection - SCardStatus <%#02x>", hResult );
            if( ( SCARD_W_RESET_CARD == hResult ) || ( SCARD_W_REMOVED_CARD == hResult ) )
            {
               Log::error( "Slot::checkConnection", "Connection is broken" );

               // Close all session
               a_pSlot->CloseAllSessions( );

               // Rebuild the token to restablish the CardModule communication
               delete a_pSlot->_token;
               a_pSlot->_token = NULL_PTR;
               a_pSlot->BuildToken( );

              // bRet = false;
            }
         }
      }
   }

   Log::end( "Slot::checkConnection" );

   //return bRet;
}


CK_LONG Slot::AddSession(Session* session)
{
   // 0 is an invalid session handle
   for(size_t i=1;i<_sessions.size();i++){
      if(this->_sessions[i] == NULL_PTR){
         this->_sessions[i] = session;
         session->UpdateState(this->_token->_roleLogged);
         return (CK_LONG)i;
      }
   }

   // No free elements, add a new
   _sessions.push_back(session);
   return (CK_LONG)(_sessions.size()-1);
}


/*
*/
void Slot::RemoveSession( CK_LONG sessionId )
{
   delete this->_sessions[ sessionId ];
   this->_sessions[sessionId] = NULL_PTR;

   // If this was the upper element in the vector, reduce size
   size_t maxId = 0;
   for( size_t i = 1 ; i < _sessions.size( ) ; i++ )
   {
      if( _sessions[ i ] )
      {
         maxId = i;
      }
   }
   if( maxId < _sessions.size( ) - 1 )
   {
      _sessions.resize( maxId + 1 );
   }

   // if this was the last session to be removed
   // then the login state of token for application
   // returns to public sessions
   if( 0 == maxId )
   {
      // TBD : Should I call logout here or merely set the flag ?
      // if I logged the user out from this application
      // what happens to another application
      // This is where on-card implementation helps

      PKCS11_ASSERT(this->_token != NULL_PTR);

      this->_token->_roleLogged = CKU_NONE;
   }
}

void Slot::UpdateSessionState()
{
   // update the state of all sessions
   for(size_t i=1;i<_sessions.size();i++){
      if(this->_sessions[i] != NULL_PTR){
         this->_sessions[i]->UpdateState(this->_token->_roleLogged);
      }
   }
}

CK_BBOOL Slot::HasReadOnlySession()
{
   for(size_t i=1;i<_sessions.size();i++){
      if(this->_sessions[i] != NULL_PTR){
         if(this->_sessions[i]->_isReadWrite == CK_FALSE){
            return CK_TRUE;
         }
      }
   }

   return CK_FALSE;
}

CK_RV Slot::GetSlotAndSessionIdFromSessionHandle(CK_SESSION_HANDLE hSession,
                                                 Slot** slot,
                                                 CK_ULONG_PTR sessionId)
{
   CK_SLOT_ID slotId  = GET_SLOTID(hSession);
   *sessionId         = GET_SESSIONID(hSession);

   if(((int)slotId < 0) || (slotId >= CONFIG_MAX_SLOT)){
      // we return here invalid session handle as
      // app does not have a notion of slot at this time
      return CKR_SESSION_HANDLE_INVALID;
   }

   if (Application::_slotCache[slotId] != NULL_PTR){
      *slot = Application::_slotCache[slotId];

      if((*sessionId < 1) || (*sessionId >= ((*slot)->_sessions.size()))){
         return CKR_SESSION_HANDLE_INVALID;
      }
      if((*slot)->_sessions[*sessionId]) {
         return CKR_OK;
      }
   }

   return CKR_SESSION_HANDLE_INVALID;
}

CK_RV Slot::BuildToken(void)
{
   Log::begin( "Slot::BuildToken" );

   if(this->_token == NULL_PTR)
   {
      SCARD_READERSTATE readerStates;
      memset( &readerStates, 0, sizeof( SCARD_READERSTATE ) );
      readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
      readerStates.szReader = this->_readerName->c_str( );

#ifndef _XCL_

      if( SCardGetStatusChange(Application::_hContext, 0, &readerStates, 1) == SCARD_S_SUCCESS)
      {
         if ((readerStates.dwEventState & SCARD_STATE_PRESENT) != SCARD_STATE_PRESENT)
         {
            // we not found a card in this reader
            this->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
            Log::log( "Slot::BuildToken - ((readerStates.dwEventState & SCARD_STATE_PRESENT) != SCARD_STATE_PRESENT)" );
            Log::logCK_RV( "Slot::BuildToken", CKR_TOKEN_NOT_PRESENT );
            return CKR_TOKEN_NOT_PRESENT;
         }
         else
         {
            // we found a card in this reader
            this->_slotInfo.flags |= CKF_TOKEN_PRESENT;
         }
      }

#else // _XCL_

      if (xCL_IsTokenPresent())
      {
          // we found a card in this reader
          this->_slotInfo.flags |= CKF_TOKEN_PRESENT;
      }
      else
      {
          // we not found a card in this reader
          this->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
          return CKR_TOKEN_NOT_PRESENT;
      }

#endif // _XCL_

      // TBD: Check if token is a .net smart card

      // token is present in the slot
      Log::log( "Slot::BuildToken - new Token..." );
      this->_token = new Token( this->_readerName );
      Log::log( "Slot::BuildToken - new Token ok"  );

      Log::logCK_RV( "Slot::BuildToken", CKR_OK );
      Log::end( "Slot::BuildToken" );
   }

   return CKR_OK;
}


CK_RV Slot::IsValidMechanism(CK_ULONG mechanism,CK_ULONG operation)
{
   size_t i = 0;

   CK_BBOOL found = CK_FALSE;

   for(;i<sizeof(MechanismList)/sizeof(CK_ULONG);i++){
      if(MechanismList[i] == mechanism){
         found = CK_TRUE;
         break;
      }
   }

   if(found == CK_FALSE){
      return CKR_MECHANISM_INVALID;
   }

   if((MechanismInfo[i].flags & operation) != operation){
      return CKR_MECHANISM_INVALID;
   }

   return CKR_OK;
}

CK_RV Slot::IsValidCryptoOperation(StorageObject* object,CK_ULONG operation)
{
   // Check if key is consistent
   switch(operation)
   {
   case CKF_ENCRYPT:
   case CKF_VERIFY:
   case CKF_VERIFY_RECOVER:
      if(object->_class != CKO_PUBLIC_KEY && object->_class != CKO_SECRET_KEY){
         return CKR_KEY_TYPE_INCONSISTENT;
      }
      break;

   case CKF_DECRYPT:
   case CKF_SIGN:
   case CKF_SIGN_RECOVER:
      if(object->_class != CKO_PRIVATE_KEY && object->_class != CKO_SECRET_KEY){
         return CKR_KEY_TYPE_INCONSISTENT;
      }
      break;
   }

   // Check if key supports the operation
   switch(operation)
   {
   case CKF_ENCRYPT:
      if(((object->_class == CKO_PUBLIC_KEY)&&(!((RSAPublicKeyObject*)object)->_encrypt))
#ifdef ENABLE_SYMMETRIC
         ||((object->_class == CKO_SECRET_KEY)&&(!((SecretKeyObject*)object)->_encrypt))
#endif
         ){
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;

   case CKF_DECRYPT:
      if(((object->_class == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)object)->_decrypt))
#ifdef ENABLE_SYMMETRIC
         ||((object->_class == CKO_SECRET_KEY)&&(!((SecretKeyObject*)object)->_decrypt))
#endif
         ){
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;

   case CKF_VERIFY:
      if(((object->_class == CKO_PUBLIC_KEY)&&(!((RSAPublicKeyObject*)object)->_verify))
#ifdef ENABLE_SYMMETRIC
         ||((object->_class == CKO_SECRET_KEY)&&(!((SecretKeyObject*)object)->_verify))
#endif
         ){
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;


   case CKF_VERIFY_RECOVER:
      if(((object->_class == CKO_PUBLIC_KEY)&&(!((RSAPublicKeyObject*)object)->_verifyRecover))){
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;


   case CKF_SIGN:
      if(((object->_class == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)object)->_sign))
#ifdef ENABLE_SYMMETRIC
         ||((object->_class == CKO_SECRET_KEY)&&(!((SecretKeyObject*)object)->_sign))
#endif
         ){
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;

   case CKF_SIGN_RECOVER:
      if(((object->_class == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)object)->_signRecover))){
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      break;

   }

   return CKR_OK;
}
