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

#ifndef _include_sha256_h
#define _include_sha256_h

#include "MarshallerCfg.h"
#include "algo_sha256.h"

class CSHA256 : public CDigest
{
private:
    void TransformBlock(CK_BYTE_PTR data,CK_LONG counter,CK_BYTE_PTR result);
    void TransformFinalBlock(CK_BYTE_PTR data,CK_LONG length,CK_LONG counter,CK_BYTE_PTR result);

public:
    CSHA256();
    ~CSHA256();
};

#endif

