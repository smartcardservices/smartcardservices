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


#ifndef __GEMALTO_PKCS11_OBJECT_STORAGE__
#define __GEMALTO_PKCS11_OBJECT_STORAGE__


#include <string>
#include <memory>
#include "cryptoki.h"
#include "Array.hpp"
#include <boost/shared_ptr.hpp>


const int OBJECT_SERIALIZATION_CURRENT_VERSION = 2;


/*
*/
class StorageObject {

public:

	StorageObject( );

	StorageObject( const StorageObject& a_Object );

    virtual ~StorageObject( ) { }

	inline bool isModifiable( void ) { return ( ( m_Modifiable == CK_TRUE ) ? true : false ); }

	inline bool isToken( void ) { return ( ( m_Token == CK_TRUE ) ? true : false ); }

	inline CK_OBJECT_CLASS getClass( void ) { return m_Class; } 

	inline bool isPrivate( void ) { return ( ( m_Private == CK_TRUE ) ? true : false ); }

	inline virtual bool isEqual( StorageObject * that) const { return ( m_Class == that->m_Class ); }

	virtual bool compare( const CK_ATTRIBUTE& );

	virtual void setAttribute( const CK_ATTRIBUTE&, const bool& );

	virtual void getAttribute( CK_ATTRIBUTE_PTR );

	virtual void serialize( std::vector< u1 >* );

	virtual void deserialize(const std::vector< u1 >&, CK_ULONG_PTR );

//protected:

    virtual void print( void );

	void putU1ArrayInAttribute( Marshaller::u1Array*, CK_ATTRIBUTE_PTR );

	void putU4ArrayInAttribute( Marshaller::u4Array*, CK_ATTRIBUTE_PTR );

	void putULongInAttribute( const CK_ULONG&, CK_ATTRIBUTE_PTR );

	void putBBoolInAttribute( const CK_BBOOL&, CK_ATTRIBUTE_PTR );

	CK_BBOOL readBBoolFromAttribute( const CK_ATTRIBUTE& );

	CK_ULONG readULongFromAttribute( const CK_ATTRIBUTE& );

	Marshaller::u1Array* readU1ArrayFromAttribute( const CK_ATTRIBUTE& );

	Marshaller::u1Array* readDateFromAttribute( const CK_ATTRIBUTE& );

	int m_iVersion;
	
	CK_ULONG m_Class;

	CK_BBOOL m_Token;

	CK_BBOOL m_Private;

	CK_BBOOL m_Modifiable;

	boost::shared_ptr< Marshaller::u1Array > m_pLabel;

    u8 _uniqueId;

	// name of the PKCS11 file in the card which contains this object attributes
	std::string m_stFileName;

    bool m_bOffCardObject;
};

#endif // __GEMALTO_PKCS11_OBJECT_STORAGE__
