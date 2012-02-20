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

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>

#ifdef MACOSX_LEOPARD
#define SCardIsValidContext(x) SCARD_S_SUCCESS
#endif

#else 
#include <winscard.h>
#endif

#ifndef WIN32
#include <strings.h>
#endif
#include <string.h>
#include <stdexcept>
#include "MarshallerCfg.h"
#include "Array.hpp"
#include "PCSC.h"
#include "Except.h"

#ifdef __sun
typedef LPSTR LPTSTR;
#endif

#include "Log.hpp"
#include "Timer.hpp"


MARSHALLER_NS_BEGIN

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


/*
*/
PCSC::PCSC( std::string& a_stReaderName ) {

    m_hContextPCSC = 0;

    m_hCardPCSC = 0;

    m_bDoTransact = true;

    LONG lReturn = SCardEstablishContext( 0, NULL, NULL, &m_hContextPCSC );

    if( SCARD_S_SUCCESS != lReturn ) {

        Log::log( "PCSC::PCSC - SCardEstablishContext <%#02x>", lReturn );

        throw RemotingException( "PCSC::PCSC - SCardEstablishContext error", lReturn );
    }

    DWORD dwActiveProtocol = SCARD_PROTOCOL_T0;

    lReturn = SCardConnect( m_hContextPCSC, (LPTSTR)a_stReaderName.c_str( ), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &m_hCardPCSC, &dwActiveProtocol );

    if( SCARD_S_SUCCESS != lReturn ) {

        Log::log( "PCSC::PCSC - SCardConnect <%#02x>", lReturn );

        throw RemotingException( (lpCharPtr)"PCSC: SCardConnect error", lReturn );
    }

    m_stReaderName = a_stReaderName;
}


/*
*/
PCSC::PCSC( std::string& a_stInputReaderName, u2& a_u2PortNumber, std::string& a_stURI, u4& a_NameSpaceHivecode, u2& a_TypeHivecode, u4& a_Index ) {

    Log::begin( "PCSC::PCSC" );

    m_bDoTransact = true;

    std::string stIdentifiedReaderName = "";

    LPTSTR pReaderList = NULL;

    if( a_stInputReaderName.empty( ) ) {

        a_stInputReaderName = "selfdiscover";
    }

    m_hContextPCSC = 0;

    m_hCardPCSC = 0;

    LONG lReturn = SCardEstablishContext( 0, NULL, NULL, &m_hContextPCSC );

    if( SCARD_S_SUCCESS != lReturn )
    {
        std::string msg = "";
        Log::toString( msg, "SCardEstablishContext <%#02x>", lReturn );
        Log::error( "PCSC::PCSC", msg.c_str( ) );

        throw RemotingException((lpCharPtr)"PCSC: SCardEstablishContext error",lReturn);
    }

    // self-discovery mechanism
#ifdef WIN32
    if (_stricmp("selfdiscover", a_stInputReaderName.c_str()) == 0) {
#else
    if (strncasecmp("selfdiscover", a_stInputReaderName.c_str(),a_stInputReaderName.length()) == 0) {
#endif
        // In Windows SCARD_AUTOALLOCATE (-1) as a value of readerListChatLength
        // would signal the SCardListReaders to determine the size of reader string
        // This is not available in Linux so we call the SCardListReaders twice. First
        // to get the length and then the reader names.
#ifdef WIN32
        DWORD readerListCharLength = SCARD_AUTOALLOCATE;
        lReturn = SCardListReaders( m_hContextPCSC, NULL, (LPTSTR)&pReaderList, &readerListCharLength);

#else
        DWORD readerListCharLength = 0;

        lReturn = SCardListReaders(m_hContextPCSC,NULL,NULL,&readerListCharLength);
        if(lReturn != SCARD_S_SUCCESS)
            throw RemotingException((lpCharPtr)"PCSC: SCardListReaders error",lReturn);

        pReaderList = (lpCharPtr)malloc(sizeof(char)*readerListCharLength);
        lReturn = SCardListReaders(m_hContextPCSC, NULL,pReaderList, &readerListCharLength);
#endif


        if(lReturn != SCARD_S_SUCCESS) {

            std::string msg = "";
            Log::toString( msg, "SCardListReaders <%#02x>", lReturn );
            Log::error( "PCSC::PCSC", msg.c_str( ) );
            throw RemotingException((lpCharPtr)"PCSC: SCardListReaders error",lReturn);

        } else {

            u4 count = 0;
            u1 foundReader = FALSE;
            SCARDHANDLE finalCardHandle = 0;

            try {

                lpTCharPtr pReader = pReaderList;

                while ('\0' != *pReader ) {

                    size_t readerNameLen = strlen((const char*)pReader);
                    SCARD_READERSTATE readerStates[1];
                    readerStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
                    readerStates[0].szReader = pReader;

                    if ( SCardGetStatusChange( m_hContextPCSC, 0, readerStates, 1) == SCARD_S_SUCCESS) {

                        if ((readerStates[0].dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT) {

                            // we found a card in this reader
                            stIdentifiedReaderName = pReader;

                            DWORD activeProtocol;

                            lReturn = SCardConnect( m_hContextPCSC, (LPTSTR)stIdentifiedReaderName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &m_hCardPCSC, &activeProtocol);

                            if (lReturn == SCARD_S_SUCCESS) {

                                // try to identify if we're dealing with a .NetCard
                                u1 answerData[258];
                                DWORD answerLen = 258;

                                Log::log( "PCSC::PCSC SCardTransmit..." );
                                lReturn = SCardTransmit( m_hCardPCSC, SCARD_PCI_T0, isNetCardAPDU, sizeof(isNetCardAPDU), NULL, (LPBYTE)answerData, &answerLen);
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
                                                std::string* cmServicem_stURI = new std::string(CARDMANAGER_SERVICE_NAME);
                                                invokeAPDU.Append(cmServicem_stURI);
                                                delete cmServicem_stURI;
                                                invokeAPDU += (u4)a_NameSpaceHivecode;
                                                invokeAPDU += (u2)a_TypeHivecode;
                                                invokeAPDU.Append(&a_stURI);

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
                                                    exchangeData(apdu, answer);
                                                    Log::log( "PCSC::PCSC - ExchangeData ok" );

                                                    Log::log( "PCSC::PCSC - CheckForException..." );
                                                    u4 protocolOffset = m_MarshallerUtil.CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT32);
                                                    Log::log( "PCSC::PCSC - CheckForException ok" );

                                                    u4 discoveredPortNumber = m_MarshallerUtil.ComReadU4At(answer, protocolOffset);
                                                    if ((a_u2PortNumber == 0) || (discoveredPortNumber == a_u2PortNumber))
                                                    {
                                                        a_u2PortNumber = (u2)discoveredPortNumber;

                                                        if (foundReader == TRUE)
                                                        {
                                                            if (a_Index == 0)
                                                            {
                                                                // this is the second reader/card/app that matches - we error at this point
                                                                rethrowException = TRUE;
                                                                std::string errorMessage( "At least 2 cards posses \"");
                                                                errorMessage += a_stURI.c_str( );
                                                                errorMessage += "\" service\r\nRemove conflicting cards from your system";
                                                                Log::error( "PCSC::PCSC", errorMessage.c_str( ) );

                                                                throw RemotingException(errorMessage);
                                                            }
                                                        }

                                                        foundReader = TRUE;
                                                        finalCardHandle = m_hCardPCSC;

                                                        // Advance to the next value.
                                                        count++;

                                                        if (count == a_Index)
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

                                    SCardDisconnect( m_hCardPCSC, SCARD_LEAVE_CARD);
                                    m_hCardPCSC = 0;
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

                stIdentifiedReaderName = "";

#ifdef WIN32
                /*lReturn = */SCardFreeMemory( m_hContextPCSC, pReaderList);
                /*if(lReturn != SCARD_S_SUCCESS) {
                throw RemotingException((lpCharPtr)"PCSC: SCardFreeMemory error",lReturn);
                }*/
#else
                if( pReaderList ) {

                    free(pReaderList);
                }
#endif
                throw;
            }

            // have we found anything ?
            if( !foundReader) {

                stIdentifiedReaderName = "";

#ifdef WIN32
                /*lReturn = */SCardFreeMemory( m_hContextPCSC, pReaderList);
                //if(lReturn != SCARD_S_SUCCESS) {
                //    throw RemotingException((lpCharPtr)"PCSC: SCardFreeMemory error",lReturn);
                //}
#else
                if(pReaderList ) {

                    free(pReaderList);
                }
#endif

                throw RemotingException((lpCharPtr)"Could not find any .NET smart card", SCARD_E_NO_SMARTCARD );
            }

            m_hCardPCSC = finalCardHandle;
        }

        m_stReaderName = stIdentifiedReaderName;

    } else {

        m_stReaderName = a_stInputReaderName;
    }

    Log::end( "PCSC::PCSC" );
}


/*
*/
void PCSC::exchangeData( u1Array &dataIn, u1Array &dataout ) {

    // check validity of handle
    if ( SCARD_S_SUCCESS != SCardIsValidContext( m_hContextPCSC ) ) {

        throw RemotingException( (lpCharPtr)"PCSC: Invalid handle", SCARD_E_INVALID_HANDLE );
    }

    try {

        if( m_bDoTransact ) { 

            beginTransaction( );
        }

        unsigned char ucRetry = 0;

        do {

            ucRetry++;

            unsigned char answerData[ 258 ];
            memset( answerData, 0, sizeof( answerData ) );

            DWORD answerLen = sizeof( answerData );

#ifdef __DEBUG_APDU__
            Log::logCK_UTF8CHAR_PTR( "PCSC::ExchangeData - Command", dataIn.GetBuffer( ), dataIn.GetLength( ) );
            Timer t;
            t.start( );
#endif

            LONG lReturn = SCardTransmit( m_hCardPCSC, SCARD_PCI_T0, dataIn.GetBuffer( ), dataIn.GetLength( ), NULL, (lpByte)answerData, &answerLen );

            if( SCARD_S_SUCCESS != lReturn ) {

                std::string msg = "";
                Log::toString( msg, "SCardTransmit <%#02x>", lReturn );
                Log::error( "PCSC::ExchangeData", msg.c_str( ) );
            }

            if( ( SCARD_W_REMOVED_CARD == lReturn ) || ( SCARD_W_RESET_CARD == lReturn ) ) {

                DWORD dwActiveProtocol = SCARD_PROTOCOL_T0;

                lReturn = SCardReconnect( m_hCardPCSC, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

                if( SCARD_S_SUCCESS != lReturn ) {

                    std::string msg = "";
                    Log::toString( msg, "SCardReconnect <%#02x>", lReturn );
                    Log::error( "PCSC::ExchangeData", msg.c_str( ) );

                    throw RemotingException( (lpCharPtr)"PCSC: SCardReconnect error", lReturn );
                }

                lReturn = SCardTransmit( m_hCardPCSC, SCARD_PCI_T0, dataIn.GetBuffer( ), dataIn.GetLength( ), NULL, (lpByte)answerData, &answerLen );

                if( SCARD_S_SUCCESS != lReturn ) {

                    Log::log( "PCSC::ExchangeData - SCardTransmit <%#02x>", lReturn );
                }

            } else if( SCARD_S_SUCCESS != lReturn ) {

                std::string s;
                Log::toString( s, "SCardTransmit failed <%#02x>", lReturn );
                Log::error( "PCSC::ExchangeData", s.c_str( ) );

                throw RemotingException( (lpCharPtr)"PCSC: SCardTransmit error", lReturn );
            }

            if (answerLen < 2) {

                Log::error( "PCSC::ExchangeData", "Incorrect length returned" );

                throw RemotingException((lpCharPtr)"PCSC: SCardTransmit error - Incorrect length returned",SCARD_F_COMM_ERROR);
            }

            if (answerLen > 2) {

                u1Array temp(answerLen - 2);

                temp.SetBuffer(answerData);

                dataout += temp;
            }

            u1 sw1 = answerData[answerLen - 2];

            u1 sw2 = answerData[answerLen - 1];

#ifdef __DEBUG_APDU__
            Log::log( "PCSC::ExchangeData - Status (1) <%02x%02x>", sw1, sw2 );
            Log::logCK_UTF8CHAR_PTR( "PCSC::ExchangeData - Response", answerData, answerLen );
            t.stop( "PCSC::ExchangeData - Response" );
#endif

            while( (sw1 == 0x61 ) || ( sw1 == 0x9F ) ) {

                memset( answerData, 0, sizeof( answerData ) );

                unsigned char GetResponse[ 5 ];

                memset( GetResponse, 0, sizeof( GetResponse ) );

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
                Log::logCK_UTF8CHAR_PTR( "PCSC::ExchangeData - Command", GetResponse, sizeof( GetResponse ) );
                t.start( );
#endif

                lReturn = SCardTransmit( m_hCardPCSC, SCARD_PCI_T0, (lpCByte)GetResponse, 5, NULL, (lpByte)answerData, &answerLen );

                if( ( SCARD_W_REMOVED_CARD == lReturn ) || ( SCARD_W_RESET_CARD == lReturn ) ) {

                    DWORD dwActiveProtocol = SCARD_PROTOCOL_T0;

                    lReturn = SCardReconnect( m_hCardPCSC, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

                    lReturn = SCardTransmit( m_hCardPCSC, SCARD_PCI_T0, (lpCByte)GetResponse, 5, NULL, (lpByte)answerData, &answerLen );

                } else if( SCARD_S_SUCCESS != lReturn ) {

                    std::string s;
                    Log::toString( s, "SCardTransmit failed <%02x>", lReturn );
                    Log::error( "PCSC::ExchangeData", s.c_str( ) );

                    throw RemotingException( (lpCharPtr)"PCSC: SCardTransmit error", lReturn );
                }

                if( answerLen < 2 ) {

                    Log::error( "PCSC::ExchangeData", "Incorrect length returned" );

                    throw RemotingException( (lpCharPtr)"PCSC: SCardTransmit error - Incorrect length returned", SCARD_F_COMM_ERROR );
                }

                if( answerLen > 2 ) {

                    u1Array temp( answerLen - 2 );

                    temp.SetBuffer( answerData );

                    dataout += temp;
                }

                sw1 = answerData[ answerLen - 2 ];

                sw2 = answerData[ answerLen - 1 ];

#ifdef __DEBUG_APDU__
                Log::log( "PCSC::ExchangeData - Status (2) <%02x%02x>", sw1, sw2 );
                Log::logCK_UTF8CHAR_PTR( "PCSC::ExchangeData - Response", answerData, answerLen );
                t.stop( "PCSC::ExchangeData - Response" );
#endif
            }

            // The response is not acceptable. We have to retry the data transmission
            if( ( 0x63 == sw1 ) || ( ( 0x69 == sw1 ) && ( 0x99 == sw2 ) ) ) {

                Log::log( "PCSC::ExchangeData - Invalid response. Retry" );

            } else {

                break;
            }

 /*               if( ( 0x90 == sw1 ) && ( 0x00 == sw2 ) ) {

                break;
            }*/

        } while ( 3 > ucRetry );

    } catch (...) {

        if( m_bDoTransact ) { 

            endTransaction( );
        }

        throw;
    }

    if( m_bDoTransact ) { 

        endTransaction( );
    }
}


/* Cleanup the context and card handle
*/
PCSC::~PCSC( ) {

    if( m_hCardPCSC ) {

        SCardDisconnect( m_hCardPCSC, SCARD_LEAVE_CARD );

        m_hCardPCSC = 0;
    }

    if( m_hContextPCSC ) {

        SCardReleaseContext( m_hContextPCSC );

        m_hContextPCSC = 0;
    }
}

MARSHALLER_NS_END
