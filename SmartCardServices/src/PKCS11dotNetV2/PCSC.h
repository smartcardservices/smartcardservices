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

#ifndef _include_marshaller_pcsc_h
#define _include_marshaller_pcsc_h

MARSHALLER_NS_BEGIN

class PCSC
{

private:
    SCARDCONTEXT hContext;
    SCARDHANDLE  hCard;
    std::string*    readerName;
    bool fDoTransact;

public:
    PCSC(SCARDHANDLE cardHandle);
	PCSC(M_SAL_IN std::string* readerName);
	PCSC(M_SAL_IN std::string* readerName, u2* portNumber, M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode, u4 index);
    SCARDHANDLE GetCardHandle(void);
    void SetCardHandle(SCARDHANDLE hCard);
    void DoTransact(bool flag);
    std::string* GetReaderName(void);
    void BeginTransaction(void);
    void EndTransaction(void);
    void ExchangeData(u1Array &dataIn, u1Array &dataout);
    ~PCSC(void);

};

MARSHALLER_NS_END

#endif

