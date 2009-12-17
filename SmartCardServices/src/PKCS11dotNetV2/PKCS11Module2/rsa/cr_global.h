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

#ifndef _CR_GLOBAL_H_
#define _CR_GLOBAL_H_

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* Error codes.
 */
#define RE_CONTENT_ENCODING		0x0400
#define RE_DATA					0x0401
#define RE_DIGEST_ALGORITHM		0x0402
#define RE_ENCODING				0x0403
#define RE_KEY					0x0404
#define RE_KEY_ENCODING			0x0405
#define RE_LEN					0x0406
#define RE_MODULUS_LEN			0x0407
#define RE_NEED_RANDOM			0x0408
#define RE_PRIVATE_KEY			0x0409
#define RE_PUBLIC_KEY			0x040a
#define RE_SIGNATURE			0x040b
#define RE_SIGNATURE_ENCODING	0x040c
#define RE_ENCRYPTION_ALGORITHM 0x040d

#define R_memset(x, y, z)   memset(x, y, z)
#define R_memcpy(x, y, z)   memcpy(x, y, z)
#define R_memcmp(x, y, z)   memcmp(x, y, z)

#endif

