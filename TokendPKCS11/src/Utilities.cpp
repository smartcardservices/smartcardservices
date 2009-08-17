/*
 *  Copyright (c) 2008 Apple Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_START@
 *
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *
 *  @APPLE_LICENSE_HEADER_END@
 */

#include "Utilities.h"

#include <string.h>

/******************************************************************************
 ** Function: strnlen
 **
 ** Limited length strlen function (normally included with GNU compiler)
 *******************************************************************************/
size_t strnlen(const char *__string, size_t __maxlen)
{
    size_t i;

    for (i = 0; i < __maxlen; i++)
        if (__string[i] == 0x00) break;

    return i;
}

void pad_string_set(byte *to, const char *from, size_t size) {
	memset(to, 0x20, size);
	memcpy(to, from, strnlen(from, size));
}
