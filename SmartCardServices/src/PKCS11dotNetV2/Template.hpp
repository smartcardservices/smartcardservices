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


#ifndef __GEMALTO_TEMPLATE__
#define __GEMALTO_TEMPLATE__


#include <vector>
#include "cryptoki.h"


/*
*/
class Template
{

public:

	enum MODE { MODE_CREATE, MODE_GENERATE_PUB, MODE_GENERATE_PRIV };

	Template( ) { }

	Template( CK_ATTRIBUTE_PTR, const CK_ULONG& );

	virtual ~Template( );

	void fixEndianness( CK_ATTRIBUTE& );

	CK_OBJECT_CLASS getClass( CK_ATTRIBUTE_PTR, const CK_ULONG& );

	CK_CERTIFICATE_TYPE getCertificateType( CK_ATTRIBUTE_PTR, const CK_ULONG& );

	bool isToken( CK_ATTRIBUTE_PTR, const CK_ULONG& );

	bool isPresent( CK_ATTRIBUTE_PTR, const CK_ULONG&, const CK_ATTRIBUTE_TYPE& );

    bool isPrivate( CK_ATTRIBUTE_PTR, const CK_ULONG& );

	void checkTemplate( CK_ATTRIBUTE_PTR, const CK_ULONG&, const unsigned char& );

	inline std::vector< CK_ATTRIBUTE >& getAttributes( void ) { return m_Attributes; }

private:

	std::vector< CK_ATTRIBUTE > m_Attributes;

};

#endif // __GEMALTO_TEMPLATE__
