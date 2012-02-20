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


#ifndef __GEMALTO_MARSHALLER_H__
#define __GEMALTO_MARSHALLER_H__


#include "MarshallerUtil.h"
#include "PCSC.h"


MARSHALLER_NS_BEGIN

typedef void (*pCommunicationStream)(u1Array& st,u1Array& stM);

class SMARTCARDMARSHALLER_DLLAPI SmartCardMarshaller {

private:

    PCSC* m_pPCSC;

    u4 m_NameSpaceHivecode;
    
	u2 m_TypeHivecode;

	u2 m_PortNumber;
    
	std::string m_stURI;

	MarshallerUtil m_MarshallerUtil;


    pCommunicationStream m_pProcessInputStream;

    pCommunicationStream m_pProcessOutputStream;

public:
    // Existing PCSC connection
    //SmartCardMarshaller( SCARDHANDLE, u2, std::string, u4, u2 );

    // PCSC compatible readers
    SmartCardMarshaller( std::string, u2, std::string, u4, u2, u4 );

    // destructor
    virtual ~SmartCardMarshaller( );

    // Remoting marshalling method
    void Invoke( s4 nParam, ... );

    inline void UpdatePCSCCardHandle( SCARDHANDLE m_hCard ) { if( m_pPCSC ) { m_pPCSC->setCardHandle( m_hCard ); } }

    inline void SetInputStream( pCommunicationStream a_inStream ) { m_pProcessInputStream = a_inStream; }
	
	inline void SetOutputStream( pCommunicationStream a_outStream ){ m_pProcessOutputStream = a_outStream; }

    inline std::string& GetReaderName( void ) { if( m_pPCSC ) { return m_pPCSC->getReaderName( ); } else throw ("Empty PCSC context"); }

    inline SCARDHANDLE GetCardHandle( void ) { if( m_pPCSC ) { return m_pPCSC->getCardHandle( ); } return NULL; }
    
    inline void DoTransact( bool& flag ) { if( m_pPCSC ) { m_pPCSC->doTransact( flag ); } }

    inline void beginTransaction( void ) { if( m_pPCSC ) { m_pPCSC->beginTransaction( ); } }

    inline void endTransaction( void ) { if( m_pPCSC ) { m_pPCSC->endTransaction( ); } }

};

MARSHALLER_NS_END

#endif // __GEMALTO_MARSHALLER_H__


