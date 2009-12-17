/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This is a sample file containing the top level include directives
 * for building Win32 Cryptoki libraries and applications.
 */

#ifndef _include_platconfig_h
#define _include_platconfig_h

#ifndef NULL_PTR
    #define NULL_PTR 0
#endif

#ifdef _WIN32

#pragma pack(push, plcryptoki, 1)

/* Specifies that the function is a DLL entry point. */
#define CK_IMPORT_SPEC __declspec(dllimport)

#ifdef CRYPTOKI_EXPORTS
#define CK_EXPORT_SPEC __declspec(dllexport)
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#endif

/* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#ifdef _DEBUG
    #define PKCS11_ASSERT(X)        assert(X)
#else
    #define PKCS11_ASSERT(X)
#endif

#include "pkcs11.h"

#pragma pack(pop, plcryptoki)

#else

#define CK_IMPORT_SPEC
#define CK_EXPORT_SPEC
#define CK_CALL_SPEC

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#define PKCS11_ASSERT(X)

#include "pkcs11.h"

#endif

#endif

