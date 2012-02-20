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

#ifndef _include_marshaller_h
#define _include_marshaller_h

#ifdef _XCL_
#include "xcl_broker.h"
#endif // _XCL_

MARSHALLER_NS_BEGIN

typedef void (*pCommunicationStream)(u1Array& st,u1Array& stM);

class SMARTCARDMARSHALLER_DLLAPI SmartCardMarshaller
{

private:
    u4            nameSpaceHivecode;
    u2            typeHivecode;
    u2            portNumber;
    std::string*  uri;
#ifndef _XCL_
    PCSC*         pcsc;
#else 	// _XCL_
    XCLBroker*    pcsc;
#endif 	// _XCL_

    pCommunicationStream ProcessInputStream;
    pCommunicationStream ProcessOutputStream;

public:
    // Existing PCSC connection
    SmartCardMarshaller(SCARDHANDLE pcscCardHandle, u2 portNumber,M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode);

    // PCSC compatible readers
    SmartCardMarshaller(M_SAL_IN std::string* readerName, u2 portNumber,M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode, u4 index);

    // destructor
    ~SmartCardMarshaller(void);

    // Remoting marshalling method
    void Invoke(s4 nParam, ...);

    void UpdatePCSCCardHandle(SCARDHANDLE hCard);

    void SetInputStream(pCommunicationStream inStream);
    void SetOutputStream(pCommunicationStream outStream);

    std::string* GetReaderName();
    SCARDHANDLE GetCardHandle();
    void DoTransact(bool flag);

};

MARSHALLER_NS_END

#endif


