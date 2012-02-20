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


#ifndef __GEMALTO_PCSC_MISSING__
#define __GEMALTO_PCSC_MISSING__


#ifndef SCARD_E_NO_SUCH_CERTIFICATE
#define SCARD_E_NO_SUCH_CERTIFICATE ((LONG)0x8010002C)
#endif

#ifndef SCARD_E_FILE_NOT_FOUND
#define SCARD_E_FILE_NOT_FOUND ((LONG)0x80100024)
#endif

#ifndef SCARD_E_COMM_DATA_LOST
#define SCARD_E_COMM_DATA_LOST ((LONG)0x8010002F)
#endif

#ifndef SCARD_W_CHV_BLOCKED
#define SCARD_W_CHV_BLOCKED ((LONG)0x8010006C)
#endif

#ifndef SCARD_E_UNEXPECTED
#define SCARD_E_UNEXPECTED ((LONG)0x8010001F)
#endif

#ifndef SCARD_E_WRITE_TOO_MANY
#define SCARD_E_WRITE_TOO_MANY ((LONG)0x80100028)
#endif

#ifndef SCARD_W_CANCELLED_BY_USER
#define SCARD_W_CANCELLED_BY_USER ((LONG)0x8010006E)
#endif

#ifndef SCARD_W_WRONG_CHV
#define SCARD_W_WRONG_CHV ((LONG)0x8010006B)
#endif

#ifndef SCARD_W_CARD_NOT_AUTHENTICATED
#define SCARD_W_CARD_NOT_AUTHENTICATED  ((LONG)0x8010006F)
#endif

#ifndef SCARD_E_DIR_NOT_FOUND
#define SCARD_E_DIR_NOT_FOUND ((LONG)0x80100023)
#endif

#ifndef SCARD_E_INVALID_CHV
#define SCARD_E_INVALID_CHV ((LONG)0x8010002A)
#endif

#ifndef SCARD_E_CERTIFICATE_UNAVAILABLE
#define SCARD_E_CERTIFICATE_UNAVAILABLE ((LONG)0x8010002D)
#endif

#ifndef SCARD_E_NO_ACCESS
#define SCARD_E_NO_ACCESS ((LONG)0x80100027)
#endif

#endif //__GEMALTO_PCSC_MISSING__

