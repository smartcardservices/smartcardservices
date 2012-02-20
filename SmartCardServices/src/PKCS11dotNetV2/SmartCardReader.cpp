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
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif
#include "SmartCardReader.hpp"
#include "SmartCardReaderException.hpp"
#include "CardModuleService.hpp"

#ifndef WIN32
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif

#include "PCSCMissing.h"


#pragma pack(push, mdnet, 1)

typedef struct PIN_VERIFY_STRUCTURE
{
    BYTE bTimerOut;                  /* timeout is seconds (00 means use default timeout) */
    BYTE bTimerOut2;                 /* timeout in seconds after first key stroke */
    BYTE bmFormatString;             /* formatting options */
    BYTE bmPINBlockString;           /* bits 7-4 bit size of PIN length in APDU,
                                     * bits 3-0 PIN block size in bytes after
                                     * justification and formatting */
    BYTE bmPINLengthFormat;          /* bits 7-5 RFU,
                                     * bit 4 set if system units are bytes, clear if
                                     * system units are bits,
                                     * bits 3-0 PIN length position in system units
                                     */
    BYTE bPINMaxExtraDigit1;         /* Max PIN size*/
    BYTE bPINMaxExtraDigit2;         /* Min PIN size*/
    BYTE bEntryValidationCondition;  /* Conditions under which PIN entry should
                                     * be considered complete */
    BYTE bNumberMessage;             /* Number of messages to display for PIN
                                     verification */
    USHORT wLangId;                  /* Language for messages */
    BYTE bMsgIndex;                  /* Message index (should be 00) */
    BYTE bTeoPrologue[3];            /* T=1 block prologue field to use (fill with 00) */
    ULONG ulDataLength;              /* length of Data to be sent to the ICC */
    BYTE abData[13];                 /* Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

#pragma pack(pop, mdnet)


#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_DIRECT 0x06


/*
*/
SmartCardReader::SmartCardReader( const std::string& a_stReaderName ) {

    m_dwIoctlVerifyPIN = 0;

    m_stReaderName = a_stReaderName;

    m_CardHandle = 0;

    m_bIsSecuredVerifyPIN = boost::logic::indeterminate;
}


/*
*/
bool SmartCardReader::isVerifyPinSecured( void ) {

    if( boost::logic::indeterminate( m_bIsSecuredVerifyPIN ) ) {

        // Get Reader Features
        BYTE outBuffer[ 256 ];
        //memset( outBuffer, 0, sizeof( outBuffer ) );
        
        DWORD dwLen = 0;
        
        LONG hResult = SCARD_F_INTERNAL_ERROR;

        unsigned char ucRetry = 0;
        
        do {

            memset( outBuffer, 0, sizeof( outBuffer ) );
            
            dwLen = 0;

            hResult = SCardControl( m_CardHandle, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, outBuffer, sizeof( outBuffer ), &dwLen );

            //Log::log( "=============================================================================================== SmartCardReader::isVerifyPinSecured - retry <%d> - result <%#02x>", ucRetry, hResult );

            ucRetry++;

        } while( ( SCARD_S_SUCCESS != hResult ) && ( ucRetry < 5 ) );


        if ( ( SCARD_S_SUCCESS == hResult ) && ( dwLen > 0 ) ) {

            m_bIsSecuredVerifyPIN = false;

            int i = 0;

            // Search IOCTL of Verify PIN feature
            while( ( i + 6 ) <= (int)dwLen ) {

                // Search Verify PIN feature Tag
                if( ( outBuffer[ i ] == FEATURE_VERIFY_PIN_DIRECT ) && ( outBuffer[ i + 1 ] == 4 ) ) {

                    m_dwIoctlVerifyPIN += ( outBuffer[ i + 2 ] << 24 );
                    m_dwIoctlVerifyPIN += ( outBuffer[ i + 3 ] << 16 );
                    m_dwIoctlVerifyPIN += ( outBuffer[ i + 4 ] << 8 );
                    m_dwIoctlVerifyPIN += outBuffer[ i + 5 ];

                    m_bIsSecuredVerifyPIN = true;

                    break;

                } else {

                    i += (outBuffer[ i + 1 ] + 2 );
                }
            }
        } else {
         
            // The ScardControl failed. Return false and read the flag next time
            return false;
        }
    }

    return m_bIsSecuredVerifyPIN;
}


/*
*/
void SmartCardReader::verifyPinSecured( const unsigned char& a_ucRole ) {

    if( true != m_bIsSecuredVerifyPIN ) {

        throw SmartCardReaderException( SCARD_E_READER_UNSUPPORTED );
    }

    //DWORD PinId = a_ucRole;
    LONG                 lRet;
    BYTE                 offset;
    DWORD                dwSendLen;
    PIN_VERIFY_STRUCTURE pin_verify;
    BYTE                 inBuffer[256];
    DWORD                dwInLen = 0;
    BYTE                 outBuffer[256];
    DWORD                dwOutLen = 0;


    // Time out between key stroke = max(bTimerOut, bTimerOut2). Must be between 15 and 40 sec.
    pin_verify.bTimerOut = 30;
    pin_verify.bTimerOut2 = 00;

    // Padding V2=0x82
    pin_verify.bmFormatString = 0x82;

    pin_verify.bmPINBlockString = 0x06;
    pin_verify.bmPINLengthFormat = 0x00;
    // Max PIN length
    pin_verify.bPINMaxExtraDigit1 = 0x08;
    // Min PIN length
    pin_verify.bPINMaxExtraDigit2 = 0x04; 
    // Validation when key pressed
    pin_verify.bEntryValidationCondition = 0x02;
    pin_verify.bNumberMessage = 0x01;
    pin_verify.wLangId = 0x0904;
    pin_verify.bMsgIndex = 0x00;
    pin_verify.bTeoPrologue[0] = 0x00;
    pin_verify.bTeoPrologue[1] = 0x00;

    // pin_verify.ulDataLength = 0x00; we don't know the size yet
    pin_verify.bTeoPrologue[2] = 0x00;

    offset = 0;
    // Class
    pin_verify.abData[offset++] = 0x00;
    // Instruction Verify
    pin_verify.abData[offset++] = 0x20;
    // P1 always 0
    pin_verify.abData[offset++] = 0x00;
    // P2 Pin reference
    pin_verify.abData[offset++] = a_ucRole;
    // Lc 8 data bytes
    pin_verify.abData[offset++] = 0x08;

    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;
    pin_verify.abData[offset++] = 0xFF;

    // APDU size
    pin_verify.ulDataLength = offset;

    dwSendLen = sizeof(PIN_VERIFY_STRUCTURE);

    // Select MSCM Application
    inBuffer[0] = 0x00;   //CLA
    inBuffer[1] = 0xA4;   //INS
    inBuffer[2] = 0x04;   //P1
    inBuffer[3] = 0x00;   //P2
    inBuffer[4] = 0x04;   //Li

    char pCardModuleServiceName[ ] = "MSCM";
    memcpy( &inBuffer[ 5 ], pCardModuleServiceName, 4 ); // ??? TO DO ??? Manage the size dynamically

    dwInLen = 5 + inBuffer[ 4 ];

    dwOutLen = sizeof(outBuffer);
    memset(outBuffer, 0x00, sizeof(outBuffer));

    lRet = SCardTransmit( m_CardHandle, SCARD_PCI_T0, inBuffer, dwInLen, NULL, outBuffer, &dwOutLen );

    // Send Verify command to the reader
    dwOutLen = 0;
    memset(outBuffer, 0x00, sizeof(outBuffer));

    lRet = SCardControl( m_CardHandle, m_dwIoctlVerifyPIN, (BYTE *)&pin_verify, dwSendLen, outBuffer, sizeof(outBuffer), &dwOutLen );

    if( ( SCARD_W_REMOVED_CARD == lRet ) || ( SCARD_W_RESET_CARD == lRet ) ) {

        DWORD dwActiveProtocol = 0;

        lRet = SCardReconnect( m_CardHandle, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_LEAVE_CARD, &dwActiveProtocol );

        lRet = SCardControl( m_CardHandle, m_dwIoctlVerifyPIN, (BYTE *)&pin_verify, dwSendLen, outBuffer, sizeof(outBuffer), &dwOutLen );
    }	

    //Log::log( "Token::verifyPinWithPinPad - sw <%#02x %#02x>", outBuffer[ 0 ], outBuffer[ 1 ] );

    if( ( 0x90 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) ) {
        // The PIN is verified

    } else if( ( 0x63 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) ) {

        throw SmartCardReaderException( SCARD_W_WRONG_CHV );

    } else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x01 == outBuffer[ 1 ] ) ) {

        // operation was cancelled by the ‘Cancel’ button
        throw SmartCardReaderException( SCARD_W_CANCELLED_BY_USER );

    } else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) ) {

        // operation timed out
        throw SmartCardReaderException( SCARD_E_TIMEOUT );

    } else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x03 == outBuffer[ 1 ] ) ) {

        // operation timed out
        throw SmartCardReaderException( SCARD_E_TIMEOUT );
    }
}
