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

#ifdef WIN32
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4201)
#else
#define DBG_UNREFERENCED_LOCAL_VARIABLE(a)
#endif

#ifndef WIN32
#include <strings.h>
#endif
#include <string.h>
#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif
#include <stdexcept>
#include "MarshallerCfg.h"
#include "Array.h"
#include "PCSC.h"
#include "Except.h"


#ifdef __sun
typedef LPSTR LPTSTR;
#endif

// JCD
#include "log.h"



MARSHALLER_NS_BEGIN

extern u4 CheckForException(u1Array answer, u4 nameSpace, u2 type);
extern u4 ComReadU4At(u1Array &array, u4 pos);

#define SUPPORT_BETA_VERSION

const u1 isNetCardAPDU[] = {0x80,0xC2,0x00,0x00,0x1C,0xD8,0x00,0x01,0x6F,0x00,0xF5,0xEF,0xBF,0xB1,0x8C,0xDD,0xC2,0x00,0x0E,0x43,0x6F,0x6E,0x74,0x65,0x6E,0x74,0x4D,0x61,0x6E,0x61,0x67,0x65,0x72};

#define APDU_TO_CARD_MAX_SIZE                                                       0xFF
#define CARDMANAGER_SERVICE_PORT                                                    1
#define CARDMANAGER_SERVICE_NAME                                                    "ContentManager"

#define HIVECODE_NAMESPACE_SMARTCARD                                                0x00F5EFBF
#define HIVECODE_TYPE_SMARTCARD_CONTENTMANAGER                                      0xB18C
#define HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT                  0x7616
#define HIVECODE_NAMESPACE_SYSTEM                                                   0x00D25D1C
#define HIVECODE_TYPE_SYSTEM_INT32                                                  0x61C0


// *******************
// PCSC class
// *******************
PCSC::PCSC(M_SAL_IN std::string* readerName)
{
   DWORD activeProtocol;
   LONG lReturn;

   this->hContext      = 0;
   this->hCard	        = 0;

   lReturn = SCardEstablishContext(0, NULL, NULL, &this->hContext);
   if(lReturn != SCARD_S_SUCCESS) {
      throw RemotingException((lpCharPtr)"PCSC: SCardEstablishContext error",lReturn);
   }

   lReturn = SCardConnect(this->hContext, (LPTSTR)readerName->c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &this->hCard, &activeProtocol);
   if (lReturn != SCARD_S_SUCCESS) {
      throw RemotingException((lpCharPtr)"PCSC: SCardConnect error",lReturn);
   }

   this->readerName = new std::string(readerName->c_str());
}

PCSC::PCSC(M_SAL_IN std::string* inputReaderName, u2* portNumber, M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode, u4 index)
{
   Log::begin( "PCSC::PCSC" );

   std::string selfDiscover("selfdiscover");
   std::string* identifiedReaderName;
   LPTSTR pReaderList = NULL;
   LONG lReturn;

   if (inputReaderName == NULL) {
      inputReaderName = &selfDiscover;
   }

   identifiedReaderName = NULL;
   this->hContext    = 0;
   this->hCard       = 0;

   lReturn = SCardEstablishContext(0, NULL, NULL, &this->hContext);
   Log::log( "PCSC::PCSC - SCardEstablishContext <%#02x>", lReturn );
   if(lReturn != SCARD_S_SUCCESS)
   {
      Log::log( "PCSC::PCSC - ## ERROR ## SCardEstablishContext <%#02x>", lReturn );
      throw RemotingException((lpCharPtr)"PCSC: SCardEstablishContext error",lReturn);
   }

   // self-discovery mechanism
#ifdef WIN32
   if (_stricmp("selfdiscover", inputReaderName->c_str()) == 0) {
#else
   if (strncasecmp("selfdiscover", inputReaderName->c_str(),inputReaderName->length()) == 0) {
#endif
      // In Windows SCARD_AUTOALLOCATE (-1) as a value of readerListChatLength
      // would signal the SCardListReaders to determine the size of reader string
      // This is not available in Linux so we call the SCardListReaders twice. First
      // to get the length and then the reader names.
#ifdef WIN32
      DWORD readerListCharLength = SCARD_AUTOALLOCATE;
      lReturn = SCardListReaders(this->hContext, NULL, (LPTSTR)&pReaderList, &readerListCharLength);
      Log::log( "PCSC::PCSC - SCardListReaders <%#02x>", lReturn );

#else
      DWORD readerListCharLength = 0;

      lReturn = SCardListReaders(this->hContext,NULL,NULL,&readerListCharLength);
      if(lReturn != SCARD_S_SUCCESS)
         throw RemotingException((lpCharPtr)"PCSC: SCardListReaders error",lReturn);

      pReaderList = (lpCharPtr)malloc(sizeof(char)*readerListCharLength);
      lReturn = SCardListReaders(this->hContext, NULL,pReaderList, &readerListCharLength);
#endif


      if(lReturn != SCARD_S_SUCCESS)
      {
         Log::log( "PCSC::PCSC - ## ERROR ## SCardListReaders <%#02x>", lReturn );
         throw RemotingException((lpCharPtr)"PCSC: SCardListReaders error",lReturn);
      }
      else
      {
         u4 count = 0;
         u1 foundReader = FALSE;
         SCARDHANDLE finalCardHandle = 0;
         try
         {
            lpTCharPtr pReader = pReaderList;
            while ('\0' != *pReader )
            {
               size_t readerNameLen = strlen((const char*)pReader);
               SCARD_READERSTATE readerStates[1];
               readerStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
               readerStates[0].szReader = pReader;
               if (SCardGetStatusChange(this->hContext, 0, readerStates, 1) == SCARD_S_SUCCESS)
               {
                  if ((readerStates[0].dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT)
                  {
                     // we found a card in this reader
                     if (identifiedReaderName != NULL)
                     {
                        delete identifiedReaderName;
                        identifiedReaderName = NULL;
                     }

                     identifiedReaderName = new std::string((lpCharPtr)pReader);
                     DWORD activeProtocol;

                     Log::log( "PCSC::PCSC SCardConnect..." );
                     lReturn = SCardConnect(this->hContext, (LPTSTR)identifiedReaderName->c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &this->hCard, &activeProtocol);
                     Log::log( "PCSC::PCSC - SCardConnect <%#02x>", lReturn );

                     if (lReturn == SCARD_S_SUCCESS)
                     {
                        // try to identify if we're dealing with a .NetCard
                        u1 answerData[258];
                        DWORD answerLen = 258;

                        Log::log( "PCSC::PCSC SCardTransmit..." );
                        lReturn = SCardTransmit(hCard, SCARD_PCI_T0, isNetCardAPDU, sizeof(isNetCardAPDU), NULL, (LPBYTE)answerData, &answerLen);
                        Log::log( "PCSC::PCSC - SCardTransmit <%#02x>", lReturn );

                        if (lReturn == SCARD_S_SUCCESS)
                        {
                           u1 rethrowException = FALSE;
                           try {
                              if (answerData[answerLen - 2] == 0x61)
                              {
                                 if (answerData[answerLen - 1] > 10)
                                 {
                                    u1Array invokeAPDU(0);
                                    invokeAPDU += (u1)0xD8;
                                    invokeAPDU += (u2)CARDMANAGER_SERVICE_PORT;
                                    invokeAPDU += (u1)0x6F;
                                    invokeAPDU += (u4)HIVECODE_NAMESPACE_SMARTCARD;
                                    invokeAPDU += (u2)HIVECODE_TYPE_SMARTCARD_CONTENTMANAGER;
                                    invokeAPDU += (u2)HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT;
                                    std::string* cmServiceUri = new std::string(CARDMANAGER_SERVICE_NAME);
                                    invokeAPDU.Append(cmServiceUri);
                                    delete cmServiceUri;
                                    invokeAPDU += (u4)nameSpaceHivecode;
                                    invokeAPDU += (u2)typeHivecode;
                                    invokeAPDU.Append(uri);

                                    // construct call
                                    if(invokeAPDU.GetLength() <= (s4)APDU_TO_CARD_MAX_SIZE) {
                                       u1Array apdu(5);
                                       apdu.GetBuffer()[0] = 0x80;
                                       apdu.GetBuffer()[1] = 0xC2;
                                       apdu.GetBuffer()[2] = 0x00;
                                       apdu.GetBuffer()[3] = 0x00;
                                       apdu.GetBuffer()[4] = (u1)invokeAPDU.GetLength();
                                       apdu += invokeAPDU;

                                       u1Array answer(0);

                                       Log::log( "PCSC::PCSC - ExchangeData..." );
                                       this->ExchangeData(apdu, answer);
                                       Log::log( "PCSC::PCSC - ExchangeData ok" );

                                       Log::log( "PCSC::PCSC - CheckForException..." );
                                       u4 protocolOffset = CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT32);
                                       Log::log( "PCSC::PCSC - CheckForException ok" );

                                       u4 discoveredPortNumber = ComReadU4At(answer, protocolOffset);
                                       if ((*portNumber == 0) || (discoveredPortNumber == *portNumber))
                                       {
                                          *portNumber = (u2)discoveredPortNumber;

                                          if (foundReader == TRUE)
                                          {
                                             if (index == 0)
                                             {
                                                // this is the second reader/card/app that matches - we error at this point
                                                rethrowException = TRUE;
                                                char errorMessage[255];
                                                strcpy(errorMessage, "At least 2 cards posses \"");
                                                strcat(errorMessage, uri->c_str());
                                                strcat(errorMessage, "\" service\r\nRemove conflicting cards from your system");

                                                Log::error( "PCSC::PCSC", errorMessage );

                                                throw RemotingException(errorMessage);
                                             }
                                          }

                                          foundReader = TRUE;
                                          finalCardHandle = this->hCard;

                                          // Advance to the next value.
                                          count++;

                                          if (count == index)
                                          {
                                             // we enumerate one by one the valid readers - so stop here
                                             break;
                                          }

                                          pReader = (lpTCharPtr)((lpTCharPtr)pReader + readerNameLen + 1);
                                          continue;
                                       }
                                    }
                                 }
                              }
                           }
                           catch (...)
                           {
                              if (rethrowException == TRUE)
                              {
                                 throw;
                              }
                              else
                              {
                                 // swallow exception
                              }
                           }

                           SCardDisconnect(this->hCard, SCARD_LEAVE_CARD);
                           this->hCard = 0;
                        }
                        // this is not a .NetCard, or the service was not found - let's try another reader/card
                        else
                        {
                           Log::error( "PCSC::PCSC", "SCardTransmit failed" );
                        }
                     }
                     else
                     {
                        Log::error( "PCSC::PCSC", "SCardConnect failed" );
                     }
                  }
                  else
                  {
                     Log::error( "PCSC::PCSC", "SCARD_STATE_PRESENT not present" );
                  }
               }
               else
               {
                  Log::error( "PCSC::PCSC", "SCardGetStatusChange != SCARD_S_SUCCESS" );
               }

               // Advance to the next value.
               pReader = (lpTCharPtr)((lpTCharPtr)pReader + readerNameLen + 1);
            }
         } catch (...) {
            if (identifiedReaderName != NULL) {
               delete identifiedReaderName;
            }

#ifdef WIN32
            lReturn = SCardFreeMemory(this->hContext, pReaderList);
            if(lReturn != SCARD_S_SUCCESS) {
               throw RemotingException((lpCharPtr)"PCSC: SCardFreeMemory error",lReturn);
            }
#else
            if(pReaderList != NULL)
               free(pReaderList);
#endif
            throw;
         }

         // have we found anything ?
         if (foundReader == FALSE) {
            if (identifiedReaderName != NULL) {
               delete identifiedReaderName;
            }

#ifdef WIN32
            lReturn = SCardFreeMemory(this->hContext, pReaderList);
            if(lReturn != SCARD_S_SUCCESS) {
               throw RemotingException((lpCharPtr)"PCSC: SCardFreeMemory error",lReturn);
            }
#else
            if(pReaderList != NULL)
               free(pReaderList);
#endif

            throw RemotingException((lpCharPtr)"Could not find any Cryptoflex .NET smart card",SCARD_E_NO_SMARTCARD);
         }

         this->hCard = finalCardHandle;
      }

      this->readerName = new std::string(identifiedReaderName->c_str());

      delete identifiedReaderName;

   } else {
      this->readerName = new std::string(inputReaderName->c_str());
   }

   Log::end( "PCSC::PCSC" );
}

PCSC::PCSC(SCARDHANDLE cardHandle)
{
   this->hContext   = 0;
   this->hCard		 = cardHandle;
   this->readerName = NULL;
   this->fDoTransact = true;
}

std::string* PCSC::GetReaderName(void)
{
   return this->readerName;
}

void PCSC::BeginTransaction(void)
{
   if(fDoTransact) // TODO: TEST RETURN CODE!!
      SCardBeginTransaction(this->hCard);
}

void PCSC::EndTransaction(void)
{
   if(fDoTransact) // TODO: TEST RETURN CODE!!
      SCardEndTransaction(this->hCard, SCARD_LEAVE_CARD);
}

SCARDHANDLE PCSC::GetCardHandle(void)
{
   return this->hCard;
}

void PCSC::SetCardHandle(SCARDHANDLE hCard)
{
   this->hCard = hCard;
}

void PCSC::DoTransact(bool flag)
{
   this->fDoTransact = flag;
}

void PCSC::ExchangeData(u1Array &dataIn, u1Array &dataout)
{
   u1 answerData[258];

   // check validity of handle
   if (this->hCard == 0) {
      throw RemotingException((lpCharPtr)"PCSC: Invalid card handle", SCARD_E_INVALID_HANDLE);
   }

#ifdef __DEBUG_APDU__
   FILE *pFile = fopen("C:\\AxaltoProtocolAnalyzer.txt","a");
#endif

   try {

      BeginTransaction();

      DWORD answerLen = sizeof(answerData);

#ifdef __DEBUG_APDU__
      fprintf(pFile, "APDU DataIn Buffer\n");
      for(int i=0; i < (s4)dataIn.GetLength(); i++) {
         fprintf(pFile, "%02x",dataIn.GetBuffer()[i]);
      }
      fprintf(pFile, "\n");
#endif

      s4 lReturn = SCardTransmit(hCard, SCARD_PCI_T0, dataIn.GetBuffer(), dataIn.GetLength(), NULL, (lpByte)answerData, &answerLen);
      if (lReturn != SCARD_S_SUCCESS) {
         throw RemotingException((lpCharPtr)"PCSC: SCardTransmit error",lReturn);
      }

      if (answerLen < 2) {
         throw RemotingException((lpCharPtr)"PCSC: SCardTransmit error - Incorrect length returned",SCARD_F_COMM_ERROR);
      }

      if (answerLen > 2) {
         u1Array temp(answerLen - 2);
         temp.SetBuffer(answerData);
         dataout += temp;
#ifdef __DEBUG_APDU__
         fprintf(pFile, "APDU DataOut Buffer\n");
         for(int i=0; i< (s4)temp.GetLength(); i++) {
            fprintf(pFile, "%02x",temp.GetBuffer()[i]);
         }
         fprintf(pFile, "\n");
#endif
      }

      u1 sw1 = answerData[answerLen - 2];
      u1 sw2 = answerData[answerLen - 1];

#ifdef __DEBUG_APDU__
      fprintf(pFile, "APDU Status Buffer\n");
      fprintf(pFile, "%02x%02x",sw1,sw2);
      fprintf(pFile, "\n");
#endif

      while ((sw1 == 0x61) || (sw1 == 0x9F))
      {
         u1 GetResponse[5];
         if (sw1 == 0x9F) {
            GetResponse[0] = 0xA0;
         } else {
            GetResponse[0] = 0x00;
         }
         GetResponse[1] = 0xC0;
         GetResponse[2] = 0x00;
         GetResponse[3] = 0x00;
         GetResponse[4] = sw2;
         answerLen = 258;

#ifdef __DEBUG_APDU__
         fprintf(pFile, "APDU DataIn Buffer\n");
         for(int i=0; i<5; i++) {
            fprintf(pFile, "%02x",GetResponse[i]);
         }
         fprintf(pFile, "\n");
#endif

         lReturn = SCardTransmit(hCard, SCARD_PCI_T0, (lpCByte)GetResponse, 5, NULL, (lpByte)answerData, &answerLen);
         if (lReturn != SCARD_S_SUCCESS) {
            throw RemotingException((lpCharPtr)"PCSC: SCardTransmit error",lReturn);
         }

         if (answerLen < 2) {
            throw RemotingException((lpCharPtr)"PCSC: SCardTransmit error - Incorrect length returned",SCARD_F_COMM_ERROR);
         }

         if (answerLen > 2) {
            u1Array temp(answerLen - 2);
            temp.SetBuffer(answerData);
            dataout += temp;
#ifdef __DEBUG_APDU__
            fprintf(pFile, "APDU DataOut Buffer\n");
            for(int i=0; i< (s4)temp.GetLength(); i++) {
               fprintf(pFile, "%02x",temp.GetBuffer()[i]);
            }
            fprintf(pFile, "\n");
#endif
         }
         sw1 = answerData[answerLen - 2];
         sw2 = answerData[answerLen - 1];

#ifdef __DEBUG_APDU__
         fprintf(pFile, "APDU Status Buffer\n");
         fprintf(pFile, "%02x%02x",sw1,sw2);
         fprintf(pFile, "\n");
#endif
      }
   } catch (...) {
#ifdef __DEBUG_APDU__
      fflush(pFile);
      fclose(pFile);
#endif
      EndTransaction();
      throw;
   }

#ifdef __DEBUG_APDU__
   fflush(pFile);
   fclose(pFile);
#endif

   EndTransaction();
}

PCSC::~PCSC(void)
{
   // we cleanup the various context and card handle only if we allocated it (depends of constructor)
   if (hContext != 0) {
      if (hCard != 0) {
         SCardDisconnect(hCard, SCARD_LEAVE_CARD);
         hCard = 0;
      }
      SCardReleaseContext(hContext);
      hContext = 0;
   }

   if (this->readerName != NULL) {
      delete this->readerName;
      this->readerName = NULL;
   }
}

MARSHALLER_NS_END

