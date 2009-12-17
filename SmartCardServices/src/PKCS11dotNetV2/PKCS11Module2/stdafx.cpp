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

#include "stdafx.h"

// Determine Processor Endianess
#include <limits.h>
#if (UINT_MAX == 0xffffffffUL)
   typedef unsigned int _u4;
#else
#  if (ULONG_MAX == 0xffffffffUL)
     typedef unsigned long _u4;
#  else
#    if (USHRT_MAX == 0xffffffffUL)
       typedef unsigned short _u4;
#    endif
#  endif
#endif

_u4 endian = 1;

bool IS_LITTLE_ENDIAN = (*((unsigned char *)(&endian))) ? true  : false;
bool IS_BIG_ENDIAN    = (*((unsigned char *)(&endian))) ? false : true;

