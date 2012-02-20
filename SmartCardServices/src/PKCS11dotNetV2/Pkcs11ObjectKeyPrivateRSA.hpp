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


#ifndef __GEMALTO_OBJECT_KEY_PRIVATE_RSA__
#define __GEMALTO_OBJECT_KEY_PRIVATE_RSA__


#include <boost/shared_ptr.hpp>
#include "Pkcs11ObjectKeyPrivate.hpp"


class RSAPrivateKeyObject : public PrivateKeyObject {

public:

    // Attribute CKA_PUBLIC_EXPONENT (CRT public exponent e)
	boost::shared_ptr< Marshaller::u1Array > m_pPublicExponent;
	
    // Attribute CKA_MODULUS (CRT modulus n)
    boost::shared_ptr< Marshaller::u1Array > m_pModulus;
    
	// Attribute CKA_PRIVATE_EXPONENT (CRT private exponent d)
    boost::shared_ptr< Marshaller::u1Array > m_pPrivateExponent;
	
    // Attribute CKA_PRIME_1 (CRT prime p)
    boost::shared_ptr< Marshaller::u1Array > m_pPrime1;
	
    // Attribute CKA_PRIME_2 (CRT prime q)
    boost::shared_ptr< Marshaller::u1Array > m_pPrime2;
	
    // Attribute CKA_EXPONENT_1 (CRT private exponent d modulo p-1)
    boost::shared_ptr< Marshaller::u1Array > m_pExponent1;
	
    // Attribute CKA_EXPONENT_2 (CRT private exponent d modulo q-1)
    boost::shared_ptr< Marshaller::u1Array > m_pExponent2;
	
    // Attribute CKA_COEFFICIENT (CRT coefficient q-1)
    boost::shared_ptr< Marshaller::u1Array > m_pCoefficient;

	RSAPrivateKeyObject( );

	RSAPrivateKeyObject( const RSAPrivateKeyObject* );

    virtual ~RSAPrivateKeyObject( ) { }

	virtual bool compare( const CK_ATTRIBUTE& );

	virtual void setAttribute( const CK_ATTRIBUTE&, const bool& );

	virtual void getAttribute( CK_ATTRIBUTE_PTR );

	virtual void serialize( std::vector< u1 >* );

	virtual void deserialize( std::vector< u1 >&, CK_ULONG_PTR );

    virtual void print( void );

};

#endif // __GEMALTO_OBJECT_KEY_PRIVATE_RSA__
