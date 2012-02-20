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


#ifndef __GEMALTO_CRYPTOKI__
#define __GEMALTO_CRYPTOKI__


  #if defined(_WINDOWS)
  
    #pragma pack(push, cryptoki, 1)
    
    // Specifies that the function is a DLL entry point
    #define CK_IMPORT_SPEC __declspec(dllimport)
    
    // Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do not define it in applications
    #ifdef CRYPTOKI_EXPORTS
      // Specified that the function is an exported DLL entry point
      #define CK_EXPORT_SPEC __declspec(dllexport)
    #else
      #define CK_EXPORT_SPEC CK_IMPORT_SPEC
    #endif
  
    // Ensures the calling convention for Win32 builds
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
  
    #ifndef NULL_PTR
      #define NULL_PTR 0
    #endif
  
    #include "pkcs11.h"
    #include "pkcs-11v2-20a3.h"
  
    ///* C_GetCardProperty obtains a property value from the .NET MiniDriver */
    //extern CK_DECLARE_FUNCTION(CK_RV, C_GetCardProperty)
    //(
    //    CK_SLOT_ID ulSlotID, 
    //    CK_BYTE a_ucProperty, 
    //    CK_BYTE a_ucFlags, 
    //    CK_BYTE_PTR a_pValue, 
    //    CK_ULONG_PTR a_pValueLen
    //);

    ///* C_SetCardProperty pushes a property value to the .NET MiniDriver */
    //extern CK_DECLARE_FUNCTION(CK_RV, C_SetCardProperty)
    //(
    //    CK_SLOT_ID ulSlotID, 
    //    CK_BYTE a_ucProperty, 
    //    CK_BYTE a_ucFlags, 
    //    CK_BYTE_PTR a_pValue, 
    //    CK_ULONG_PTR a_pValueLen
    //);
  
    #pragma pack(pop, cryptoki)
  
  #else
  
    #define CK_PTR *

#ifdef __APPLE__
    #define CK_DEFINE_FUNCTION(returnType, name) \
      __attribute__((visibility("default"))) returnType name
#else   
    #define CK_DEFINE_FUNCTION(returnType, name) \
      returnType name
#endif
     
     #define CK_DECLARE_FUNCTION(returnType, name) \
      returnType name
    
    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
      returnType (* name)
    
    #define CK_CALLBACK_FUNCTION(returnType, name) \
      returnType (* name)
    
    #define CK_ENTRY
  
    #ifndef NULL_PTR
      #define NULL_PTR 0
    #endif
  
    #include "pkcs11.h"
    #include "pkcs-11v2-20a3.h"

    ///* C_GetCardProperty obtains a property value from the .NET MiniDriver */
    //extern CK_DECLARE_FUNCTION(CK_RV, C_GetCardProperty)
    //(
    //    CK_SLOT_ID ulSlotID, 
    //    CK_BYTE a_ucProperty, 
    //    CK_BYTE a_ucFlags, 
    //    CK_BYTE_PTR a_pValue, 
    //    CK_ULONG_PTR a_pValueLen
    //);

    ///* C_SetCardProperty pushes a property value to the .NET MiniDriver */
    //extern CK_DECLARE_FUNCTION(CK_RV, C_SetCardProperty)
    //(
    //    CK_SLOT_ID ulSlotID, 
    //    CK_BYTE a_ucProperty, 
    //    CK_BYTE a_ucFlags, 
    //    CK_BYTE_PTR a_pValue, 
    //    CK_ULONG_PTR a_pValueLen
    //);

#endif

#endif // __GEMALTO_CRYPTOKI__
