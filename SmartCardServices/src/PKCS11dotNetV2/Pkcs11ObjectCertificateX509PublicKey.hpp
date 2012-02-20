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


#ifndef __GEMALTO_OBJECT_CERTIFICATE_X509_PUBLIC_KEY__
#define __GEMALTO_OBJECT_CERTIFICATE_X509_PUBLIC_KEY__


#include <boost/shared_ptr.hpp>
#include "Pkcs11ObjectCertificate.hpp"


class X509PubKeyCertObject : public CertificateObject {

public:

    boost::shared_ptr< Marshaller::u1Array > m_pSubject;

    boost::shared_ptr< Marshaller::u1Array > m_pID;
	
    boost::shared_ptr< Marshaller::u1Array > m_pIssuer;
	
    boost::shared_ptr< Marshaller::u1Array > m_pSerialNumber;
	
    boost::shared_ptr< Marshaller::u1Array > m_pValue;
	
    boost::shared_ptr< Marshaller::u1Array > m_pURL;
	
    boost::shared_ptr< Marshaller::u1Array > m_pHashOfSubjectPubKey;
	
    boost::shared_ptr< Marshaller::u1Array > m_pHashOfIssuerPubKey;

    bool m_bIsSmartCardLogon;

    bool m_bIsRoot;

	boost::shared_ptr< Marshaller::u1Array > m_pModulus;


	X509PubKeyCertObject( );

    virtual ~X509PubKeyCertObject( ) { }

	virtual bool compare( const CK_ATTRIBUTE& );

	virtual void setAttribute( const CK_ATTRIBUTE&, const bool& );

	virtual void getAttribute( CK_ATTRIBUTE_PTR );

	virtual void serialize( std::vector< u1 >* );

	virtual void deserialize( std::vector< u1 >&, CK_ULONG_PTR );

    virtual void print( void );

};

#endif //__GEMALTO_OBJECT_CERTIFICATE_X509_PUBLIC_KEY__
