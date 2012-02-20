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


#ifndef __GEMALTO_SHA1__
#define __GEMALTO_SHA1__


#include "digest.h"
#include "algo_sha1.h"


class CSHA1 : public CDigest {

private:
    
    void TransformBlock( unsigned char* data, long counter, unsigned char* result );
    
    void TransformFinalBlock( unsigned char* data, long length, long counter, unsigned char* result );

public:

    CSHA1( );
    
    virtual ~CSHA1( );

};

#endif // __GEMALTO_SHA1__
