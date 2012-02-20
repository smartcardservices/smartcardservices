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
#pragma warning(disable:4201)
#else
#define DBG_UNREFERENCED_LOCAL_VARIABLE(a)
#endif

#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#ifndef WIN32
#include <strings.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdexcept>
#include "MarshallerCfg.h"
#include "Array.hpp"
#include "PCSC.h"
#include "Marshaller.h"
#include "Except.h"
#include "Log.hpp"

MARSHALLER_NS_BEGIN


    /*
    */
    SmartCardMarshaller::SmartCardMarshaller( std::string a_pstReaderName, u2 a_PortNumber, std::string a_stURI, u4 a_NameSpaceHivecode, u2 a_TypeHivecode, u4 a_Index ) {

        m_stURI = a_stURI;

        m_pPCSC = NULL;

        m_PortNumber = a_PortNumber;

        m_NameSpaceHivecode = a_NameSpaceHivecode;

        m_TypeHivecode = a_TypeHivecode;

        m_pProcessInputStream  = NULL;

        m_pProcessOutputStream = NULL;

#ifdef WIN32
        if( ( a_pstReaderName.empty( ) ) || (_stricmp( "selfdiscover", a_pstReaderName.c_str( ) ) == 0 ) ) {
#else
        if( ( a_pstReaderName.empty( ) ) || ( strncasecmp( "selfdiscover", a_pstReaderName.c_str( ), a_pstReaderName.length( ) ) == 0 ) ) {
#endif

            m_pPCSC = new PCSC( a_pstReaderName, m_PortNumber, a_stURI, a_NameSpaceHivecode, a_TypeHivecode, a_Index );

        } else {

            m_pPCSC = new PCSC( a_pstReaderName );
        }
}


/*
*/
SmartCardMarshaller::~SmartCardMarshaller( ) {

    delete m_pPCSC;
    m_pPCSC = NULL;
}


/*
*/
void SmartCardMarshaller::Invoke( s4 nParam, ... ) {

    // Allow selfdiscovery of port
    if ( !m_PortNumber ) {

        s4 _s4 = 0;

        u4 nameSpaceHivecode = m_NameSpaceHivecode;

        u2 typeHivecode = m_TypeHivecode;

        std::string stURI = m_stURI;

        m_PortNumber = CARDMANAGER_SERVICE_PORT;

        m_NameSpaceHivecode = HIVECODE_NAMESPACE_SMARTCARD;

        m_TypeHivecode = HIVECODE_TYPE_SMARTCARD_CONTENTMANAGER;

        m_stURI = CARDMANAGER_SERVICE_NAME;

        try {

            // call the GetAssociatedPort method.
            //Invoke(3, HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT, MARSHALLER_TYPE_IN_S4, m_NameSpaceHivecode, MARSHALLER_TYPE_IN_S2, m_TypeHivecode, MARSHALLER_TYPE_IN_STRING, m_stURI, MARSHALLER_TYPE_RET_S4, &_s4);
            Invoke(3, HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT, MARSHALLER_TYPE_IN_S4, m_NameSpaceHivecode, MARSHALLER_TYPE_IN_S2, m_TypeHivecode, MARSHALLER_TYPE_IN_STRING, m_stURI.c_str( ), MARSHALLER_TYPE_RET_S4, &_s4);

        } catch (...) {

            m_PortNumber = (u2)_s4;
            m_NameSpaceHivecode = nameSpaceHivecode;
            m_TypeHivecode = typeHivecode;
            m_stURI = stURI;

            throw;
        }

        m_PortNumber = (u2)_s4;
        m_NameSpaceHivecode = nameSpaceHivecode;
        m_TypeHivecode = typeHivecode;
        m_stURI = stURI;

    }

    u1Array invokeAPDU(0);

    va_list marker;

    va_start(marker, nParam);

    // add 0xD8
    invokeAPDU += (u1)0xD8;

    // add port number
    invokeAPDU += (u2)m_PortNumber;

    // add 0x6F
    invokeAPDU += (u1)0x6F;

    // add namespace Hivecode
    invokeAPDU += m_NameSpaceHivecode;

    // add type hivecode
    invokeAPDU += m_TypeHivecode;

    // NOTE : va_arg(marker,type)
    // As per ISO C++ if the pritives types
    // char,short,byte are passed as argument to varidic method
    // they are upcasted to int.
    //
    // On windows if you use va_arg(marker,u2), no warning will be issued
    // and there will be no complain at run time, whereas
    // On Linux (with g++) if you use va_arg(markey,u2), a warning will be issued
    // saying that it is invalid to do this and run time will fail and it does fail
    // with message "Segmentation fault".
    //
    // So va_arg for all int primitive types (char, short, byte and their unsigned values)
    // should have s4 as the type.

    // add method name
    u2 methodID = (u2)va_arg(marker, s4);
    
    invokeAPDU += methodID;

    // add URI
    u1Array URIArray(ComputeUTF8Length((char*)m_stURI.c_str( )));
    
    UTF8Encode((char*)m_stURI.c_str(), URIArray);
    
    invokeAPDU += (u2)URIArray.GetLength();
    
    invokeAPDU += URIArray;

    u1Array invokeAPDU_data(0);

    // process input arguments
    for (s4 iParam = 0; iParam < nParam; iParam++) {
        
        u1 type = (u1)va_arg(marker, s4);
        
        m_MarshallerUtil.ProcessInputArguments(type, &invokeAPDU_data, &marker);
    }

    if( m_pProcessInputStream  ){
    
        u1Array invokeAPDU_data_Modified(0);
        
        m_pProcessInputStream(invokeAPDU_data,invokeAPDU_data_Modified);
        
        invokeAPDU += invokeAPDU_data_Modified;
    
    }else{
    
        invokeAPDU += invokeAPDU_data;
    }

    u1Array answer_o(0);

    if(invokeAPDU.GetLength() > (s4)APDU_TO_CARD_MAX_SIZE)
    {
        u4 offset = 0;
        u4 size = invokeAPDU.GetLength() -1 - 2 - 1 - 4 - 2 - 2 - 2 -  URIArray.GetLength();

        u1 first = TRUE;

        u4 dataToSendLength = invokeAPDU.GetLength();
        u4 invokeApduStartOffset = 0;

        while(dataToSendLength > 0){

            u4 encodedSize = size;
            u4 encodedOffset = (u4)offset;

            u4 subCommandMaxAllowed = APDU_TO_CARD_MAX_SIZE -1 - 2 - 8;

            u4 length = dataToSendLength > subCommandMaxAllowed ? subCommandMaxAllowed : dataToSendLength;

            u1Array subApdu(0);

            if(first){
                u4 usefulDataLength = length -1 - 2 -1 -4 -2 -2 -2 - URIArray.GetLength();

                subApdu += (u1)0xD8;
                subApdu += (u2)0xFFFF;
                subApdu += encodedSize;
                subApdu += usefulDataLength;

                if ((u8)(invokeApduStartOffset + length) > (u8)invokeAPDU.GetLength()) {
                    
                    throw ArgumentOutOfRangeException( (char*)"" );
                }

                for(u4 j = invokeApduStartOffset; j < (invokeApduStartOffset + length); j++) {

                    subApdu += invokeAPDU.GetBuffer()[j];
                }

                first = FALSE;
                offset += usefulDataLength;

            }else{

                subApdu += (u1)0xD8;
                subApdu += (u2)0xFFFF;
                subApdu += encodedOffset;
                subApdu += length;

                if ((u8)(invokeApduStartOffset + length) > (u8)invokeAPDU.GetLength()) {
                    
                    throw ArgumentOutOfRangeException( (char*)"" );
                }

                for(u4 j = invokeApduStartOffset; j < (invokeApduStartOffset + length); j++) {

                    subApdu += invokeAPDU.GetBuffer()[j];
                }

                offset += length;
            }

            size = 0;
            invokeApduStartOffset = invokeApduStartOffset + length;
            dataToSendLength = dataToSendLength - length;

            u1Array apduToSend(5);

            apduToSend.GetBuffer()[0] = 0x80;
            apduToSend.GetBuffer()[1] = 0xC2;
            apduToSend.GetBuffer()[2] = 0x00;
            apduToSend.GetBuffer()[3] = 0x00;
            apduToSend.GetBuffer()[4] = (u1)subApdu.GetLength();
            apduToSend += subApdu;

            m_pPCSC->exchangeData(apduToSend, answer_o);
        }

    }else{

        // construct call
        u1Array apdu(5);
        apdu.GetBuffer()[0] = 0x80;
        apdu.GetBuffer()[1] = 0xC2;
        apdu.GetBuffer()[2] = 0x00;
        apdu.GetBuffer()[3] = 0x00;
        apdu.GetBuffer()[4] = (u1)invokeAPDU.GetLength();
        apdu += invokeAPDU;

        m_pPCSC->exchangeData(apdu, answer_o);
    }

    u1Array answer(0);

    if( m_pProcessOutputStream && ( answer_o.GetLength( ) > 0 ) && ( answer_o.ReadU1At( 0 ) == 0x01 ) ) {

        u1Array answerI( 0 );

        u1Array answerM( 0 );

        unsigned int l = answer_o.GetLength( );

        for( unsigned int i = 1; i < l ; ++i ) {

            answerI += answer_o.GetBuffer( )[ i ];
        }

        m_pProcessOutputStream(answerI, answerM);

        answer += answer_o.GetBuffer()[0];

        l = answerM.GetLength( );

        for( unsigned int i = 0 ; i < l ; ++i ) {

            answer += answerM.GetBuffer( )[ i ];
        }

    } else {

        unsigned int l = answer_o.GetLength( );

        for( unsigned int i = 0 ; i < l ; ++i ) {

            answer += answer_o.GetBuffer( )[ i ];
        }
    }

    // analyze return type
    u4 offset = m_MarshallerUtil.ProcessReturnType((u1)va_arg(marker, s4), &answer, &marker);

    va_end(marker);

    // process byref types
    va_start(marker, nParam);

    // skip method name param
    u2 methodID2 = (u2)va_arg(marker, s4);

    if (methodID2 == methodID) {

        for (s4 iParam = 0; iParam < nParam; iParam++) {
        
            u1 type = (u1)va_arg(marker, s4);
            
            m_MarshallerUtil.ProcessOutputArguments(type, &answer, &offset, &marker);
        }
    }

    va_end(marker);
}


MARSHALLER_NS_END
