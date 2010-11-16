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

#ifndef CONFIG_H
#define CONFIG_H

#define PKCS11_MANUFACTURER "Apple"
#define PKCS11_DESCRIPTION "Apple PKCS #11 module"
#define PKCS11_SLOT_DESCRIPTION "Apple Tokend"
#define PKCS11_LIBRARY_MAJOR 0
#define PKCS11_LIBRARY_MINOR 1

/* #define USE_PROTECTED_PATH */
/* #define USE_PIN_AUTH */
#define USE_ALWAYS_AUTH_SESSION

#define MAX_IDLE_SLOTS 8
#define MIN_SLOTS 4

#endif
