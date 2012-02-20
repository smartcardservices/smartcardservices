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


#ifndef __GEMALTO_MARSHALLER_UTIL_H__
#define __GEMALTO_MARSHALLER_UTIL_H__

#include <stdarg.h>

#include "MarshallerCfg.h"
#include "Array.hpp"


MARSHALLER_NS_BEGIN


class MarshallerUtil {

public:

	u2 ComReadU2At( u1Array&, const u4& );

	u4 ComReadU4At( u1Array&, const u4& );

	u8 ComReadU8At( u1Array&, const u4& );

	void ProcessException( u1Array&, const u4& );

	u4 CheckForException( u1Array&, const u4&, const u2& );

	void ProcessByReferenceArguments( const u1&, u1Array*, u4*, va_list*, const u1& );

	void ProcessOutputArguments( const u1&, u1Array*, u4*, va_list*);

	u4 ProcessReturnType( const u1&, u1Array*, va_list* );

	void ProcessInputArguments( const u1&, u1Array*, va_list* );

};

MARSHALLER_NS_END

#endif // __GEMALTO_MARSHALLER_UTIL_H__


