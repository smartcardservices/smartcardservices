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

#ifdef WIN32
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable:4201)
#else
#define DBG_UNREFERENCED_LOCAL_VARIABLE(a)
#endif

#ifdef INCLUDE_VLD
#include <vld.h>
#endif

#ifndef WIN32
#include <strings.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdexcept>
#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif
#include "MarshallerCfg.h"
#include "Array.h"
#ifndef _XCL_
#include "PCSC.h"
#else // _XCL_
#include "xcl_broker.h"
#endif // _XCL_
#include "Marshaller.h"
#include "Except.h"

#include "log.h"

MARSHALLER_NS_BEGIN

#define SUPPORT_BETA_VERSION

#define APDU_TO_CARD_MAX_SIZE                                   0xFF

#define HIVECODE_NAMESPACE_SYSTEM                               0x00D25D1C
#define HIVECODE_NAMESPACE_SYSTEM_IO                            0x00D5E6DB
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_REMOTING_CHANNELS     0x0000886E
#define HIVECODE_NAMESPACE_NETCARD_FILESYSTEM                   0x00A1AC39
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_REMOTING              0x00EB3DD9
#define HIVECODE_NAMESPACE_SYSTEM_SECURITY_CRYPTOGRAPHY         0x00ACF53B
#define HIVECODE_NAMESPACE_SYSTEM_COLLECTIONS                   0x00C5A010
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_REMOTING_CONTEXTS     0x001F4994
#define HIVECODE_NAMESPACE_SYSTEM_SECURITY                      0x00964145
#define HIVECODE_NAMESPACE_SYSTEM_REFLECTION                    0x0008750F
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_SERIALIZATION         0x008D3B3D
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_REMOTING_MESSAGING    0x00DEB940
#define HIVECODE_NAMESPACE_SYSTEM_DIAGNOSTICS                   0x0097995F
#define HIVECODE_NAMESPACE_SYSTEM_RUNTIME_COMPILERSERVICES      0x00F63E11
#define HIVECODE_NAMESPACE_SYSTEM_TEXT                          0x00702756

#define HIVECODE_TYPE_SYSTEM_VOID           0xCE81
#define HIVECODE_TYPE_SYSTEM_INT32          0x61C0
#define HIVECODE_TYPE_SYSTEM_INT32_ARRAY    0x61C1
#define HIVECODE_TYPE_SYSTEM_BOOLEAN        0x2227
#define HIVECODE_TYPE_SYSTEM_BOOLEAN_ARRAY  0x2228
#define HIVECODE_TYPE_SYSTEM_SBYTE          0x767E
#define HIVECODE_TYPE_SYSTEM_SBYTE_ARRAY    0x767F
#define HIVECODE_TYPE_SYSTEM_UINT16         0xD98B
#define HIVECODE_TYPE_SYSTEM_UINT16_ARRAY   0xD98C
#define HIVECODE_TYPE_SYSTEM_UINT32         0x95E7
#define HIVECODE_TYPE_SYSTEM_UINT32_ARRAY   0x95E8
#define HIVECODE_TYPE_SYSTEM_BYTE           0x45A2
#define HIVECODE_TYPE_SYSTEM_BYTE_ARRAY     0x45A3
#define HIVECODE_TYPE_SYSTEM_CHAR           0x958E
#define HIVECODE_TYPE_SYSTEM_CHAR_ARRAY     0x958F
#define HIVECODE_TYPE_SYSTEM_INT16          0xBC39
#define HIVECODE_TYPE_SYSTEM_INT16_ARRAY    0xBC3A
#define HIVECODE_TYPE_SYSTEM_STRING         0x1127
#define HIVECODE_TYPE_SYSTEM_STRING_ARRAY   0x1128
#define HIVECODE_TYPE_SYSTEM_INT64			0xDEFB
#define HIVECODE_TYPE_SYSTEM_INT64_ARRAY	0xDEFC
#define HIVECODE_TYPE_SYSTEM_UINT64			0x71AF
#define HIVECODE_TYPE_SYSTEM_UINT64_ARRAY	0x71B0

#define HIVECODE_TYPE_SYSTEM_IO_MEMORYSTREAM 0xFED7

// for port discovery lookup.
#define CARDMANAGER_SERVICE_PORT                                                    1
#define CARDMANAGER_SERVICE_NAME                                                    "ContentManager"
#define HIVECODE_NAMESPACE_SMARTCARD                                                0x00F5EFBF
#define HIVECODE_TYPE_SMARTCARD_CONTENTMANAGER                                      0xB18C
#define HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT                  0x7616

#define HIVECODE_TYPE_SYSTEM_EXCEPTION                                      0xD4B0
#define HIVECODE_TYPE_SYSTEM_SYSTEMEXCEPTION                                0x28AC
#define HIVECODE_TYPE_SYSTEM_OUTOFMEMORYEXCEPTION                           0xE14E
#define HIVECODE_TYPE_SYSTEM_ARGUMENTEXCEPTION                              0xAB8C
#define HIVECODE_TYPE_SYSTEM_ARGUMENTNULLEXCEPTION                          0x2138
#define HIVECODE_TYPE_SYSTEM_NULLREFERENCEEXCEPTION                         0xC5B8
#define HIVECODE_TYPE_SYSTEM_ARGUMENTOUTOFRANGEEXCEPTION                    0x6B11
#define HIVECODE_TYPE_SYSTEM_NOTSUPPORTEDEXCEPTION                          0xAA74
#define HIVECODE_TYPE_SYSTEM_INVALIDCASTEXCEPTION                           0xD24F
#define HIVECODE_TYPE_SYSTEM_INVALIDOPERATIONEXCEPTION                      0xFAB4
#define HIVECODE_TYPE_SYSTEM_NOTIMPLEMENTEDEXCEPTION                        0x3CE5
#define HIVECODE_TYPE_SYSTEM_OBJECTDISPOSEDEXCEPTION                        0x0FAC
#define HIVECODE_TYPE_SYSTEM_UNAUTHORIZEDACCESSEXCEPTION                    0x4697
#define HIVECODE_TYPE_SYSTEM_INDEXOUTOFRANGEEXCEPTION                       0xBF1D
#define HIVECODE_TYPE_SYSTEM_FORMATEXCEPTION                                0xF3BF
#define HIVECODE_TYPE_SYSTEM_ARITHMETICEXCEPTION                            0x6683
#define HIVECODE_TYPE_SYSTEM_OVERFLOWEXCEPTION                              0x20A0
#define HIVECODE_TYPE_SYSTEM_BADIMAGEFORMATEXCEPTION                        0x530A
#define HIVECODE_TYPE_SYSTEM_APPLICATIONEXCEPTION                           0xB1EA
#define HIVECODE_TYPE_SYSTEM_ARRAYTYPEMISMATCHEXCEPTION                     0x3F88
#define HIVECODE_TYPE_SYSTEM_DIVIDEBYZEROEXCEPTION                          0xDFCF
#define HIVECODE_TYPE_SYSTEM_MEMBERACCESSEXCEPTION                          0xF5F3
#define HIVECODE_TYPE_SYSTEM_MISSINGMEMBEREXCEPTION                         0x20BB
#define HIVECODE_TYPE_SYSTEM_MISSINGFIELDEXCEPTION                          0x7366
#define HIVECODE_TYPE_SYSTEM_MISSINGMETHODEXCEPTION                         0x905B
#define HIVECODE_TYPE_SYSTEM_RANKEXCEPTION                                  0xB2AE
#define HIVECODE_TYPE_SYSTEM_STACKOVERFLOWEXCEPTION                         0x0844
#define HIVECODE_TYPE_SYSTEM_TYPELOADEXCEPTION                              0x048E
#define HIVECODE_TYPE_SYSTEM_IO_IOEXCEPTION                                 0x3BBE
#define HIVECODE_TYPE_SYSTEM_IO_DIRECTORYNOTFOUNDEXCEPTION                  0x975A
#define HIVECODE_TYPE_SYSTEM_IO_FILENOTFOUNDEXCEPTION                       0x07EB
#define HIVECODE_TYPE_SYSTEM_RUNTIME_REMOTING_REMOTINGEXCEPTION             0xD52A
#define HIVECODE_TYPE_SYSTEM_RUNTIME_SERIALIZATION_SERIALIZATIONEXCEPTION   0xA1D2
#define HIVECODE_TYPE_SYSTEM_SECURITY_SECURITYEXCEPTION						0x31AF
#define HIVECODE_TYPE_SYSTEM_SECURITY_VERIFICATIONEXCEPTION					0x67F1
#define HIVECODE_TYPE_SYSTEM_SECURITY_CRYPTOGRAPHY_CRYPTOGRAPHICEXCEPTION   0x8FEB

#ifdef SMARTCARDMARSHALLER_EXPORTS

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
   UNREFERENCED_PARAMETER(hModule);
   UNREFERENCED_PARAMETER(lpReserved);

   switch (ul_reason_for_call)
   {
   case DLL_PROCESS_ATTACH:
   case DLL_THREAD_ATTACH:
   case DLL_THREAD_DETACH:
   case DLL_PROCESS_DETACH:
      break;
   }
   return TRUE;
}

#endif

static u2 ComReadU2At(u1Array &array, u4 pos)
{
   if ((u8)(pos + sizeof(u2)) > (u8)array.GetLength()) {
      throw ArgumentOutOfRangeException((lpCharPtr)"");
   }
   u1* buff = array.GetBuffer();
   return (u2)((((u2)buff[pos]) << 8) + buff[pos + 1]);
}

u4 ComReadU4At(u1Array &array, u4 pos);
u4 ComReadU4At(u1Array &array, u4 pos)
{
   if ((u8)(pos + sizeof(u4)) > (u8)array.GetLength()) {
      throw ArgumentOutOfRangeException((lpCharPtr)"");
   }
   u1* buff = array.GetBuffer();
   return (u4)((((u4)buff[pos]) << 24) + (((u4)buff[pos + 1]) << 16) + (((u4)buff[pos + 2]) << 8) + buff[pos + 3]);
}

static u8 ComReadU8At(u1Array &array, u4 pos)
{
   if ((u8)(pos + sizeof(u8)) > (u8)array.GetLength()) {
      throw ArgumentOutOfRangeException((lpCharPtr)"");
   }
   u1* buff = array.GetBuffer();

   u1 b1 = buff[pos];
   u1 b2 = buff[pos + 1];
   u1 b3 = buff[pos + 2];
   u1 b4 = buff[pos + 3];
   u1 b5 = buff[pos + 4];
   u1 b6 = buff[pos + 5];
   u1 b7 = buff[pos + 6];
   u1 b8 = buff[pos + 7];

   return (((u8)b1 << 56) | ((u8)b2 << 48) | ((u8)b3 << 40) | ((u8)b4 << 32) | ((u8)b5 << 24) | ((u8)b6 << 16) | ((u8)b7 << 8) | b8);
}

static void ProcessException(u1Array answer, u4 protocolOffset)
{
   u4 exceptionNamespace;
   u4 exceptionName;
   char* chst = NULL;

   try {
      exceptionNamespace = ComReadU4At(answer, protocolOffset + 0);
      exceptionName      = ComReadU2At(answer, protocolOffset + 4);

      if (answer.GetLength() > (protocolOffset + 6)) {
         u2 strLen = ComReadU2At(answer, protocolOffset + 6);
         if ((strLen > 0) && (strLen != 0xFFFF)) {
            u2 len = ComputeLPSTRLength(answer, protocolOffset + 8, strLen);
            chst = new char[len + 1];
            chst[len] = '\0';
            UTF8Decode(answer, protocolOffset + 8, strLen, chst);
         }
      }
   } catch (...) {
      // someone is messing with the protocol
      if (chst != NULL) {
         delete[] chst;
      }
      throw RemotingException((lpCharPtr)"");
   }

   if (chst == NULL) {
      // prepare empty string
      chst = new char[1];
      chst[0] = '\0';
   }

   // create a string object on the stack.
   // when exception is thrown the exception object is copied on
   // a temporary location and live till used by catch block
   //
   // it is not a good idea to pass chst as a parameter of exception object
   // as there will be no way to delete it.
   std::string chstr(chst);

   delete[] chst;

   switch (exceptionNamespace)
   {
   case HIVECODE_NAMESPACE_SYSTEM:
      {
         switch(exceptionName){

   case (u2)HIVECODE_TYPE_SYSTEM_EXCEPTION:
      throw Exception(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_SYSTEMEXCEPTION:
      throw SystemException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_OUTOFMEMORYEXCEPTION:
      throw OutOfMemoryException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_ARGUMENTEXCEPTION:
      throw ArgumentException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_ARGUMENTNULLEXCEPTION:
      throw ArgumentNullException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_NULLREFERENCEEXCEPTION:
      throw NullReferenceException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_ARGUMENTOUTOFRANGEEXCEPTION:
      throw ArgumentOutOfRangeException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_NOTSUPPORTEDEXCEPTION:
      throw NotSupportedException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_INVALIDCASTEXCEPTION:
      throw InvalidCastException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_INVALIDOPERATIONEXCEPTION:
      throw InvalidOperationException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_NOTIMPLEMENTEDEXCEPTION:
      throw NotImplementedException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_OBJECTDISPOSEDEXCEPTION:
      throw ObjectDisposedException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_UNAUTHORIZEDACCESSEXCEPTION:
      throw UnauthorizedAccessException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_INDEXOUTOFRANGEEXCEPTION:
      throw IndexOutOfRangeException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_FORMATEXCEPTION:
      throw FormatException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_ARITHMETICEXCEPTION:
      throw ArithmeticException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_OVERFLOWEXCEPTION:
      throw OverflowException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_BADIMAGEFORMATEXCEPTION:
      throw BadImageFormatException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_APPLICATIONEXCEPTION:
      throw ApplicationException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_ARRAYTYPEMISMATCHEXCEPTION:
      throw ArrayTypeMismatchException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_DIVIDEBYZEROEXCEPTION:
      throw DivideByZeroException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_MEMBERACCESSEXCEPTION:
      throw MemberAccessException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_MISSINGMEMBEREXCEPTION:
      throw MissingMemberException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_MISSINGFIELDEXCEPTION:
      throw MissingFieldException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_MISSINGMETHODEXCEPTION:
      throw MissingMethodException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_RANKEXCEPTION:
      throw RankException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_STACKOVERFLOWEXCEPTION:
      throw StackOverflowException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_TYPELOADEXCEPTION:
      throw TypeLoadException(chstr);
         }
      }
      break;

   case HIVECODE_NAMESPACE_SYSTEM_IO:
      {
         switch(exceptionName){
   case (u2)HIVECODE_TYPE_SYSTEM_IO_IOEXCEPTION:
      throw IOException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_IO_DIRECTORYNOTFOUNDEXCEPTION:
      throw DirectoryNotFoundException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_IO_FILENOTFOUNDEXCEPTION:
      throw FileNotFoundException(chstr);
         }
      }
      break;

   case HIVECODE_NAMESPACE_SYSTEM_SECURITY:
      {
         switch(exceptionName){
   case (u2)HIVECODE_TYPE_SYSTEM_SECURITY_SECURITYEXCEPTION:
      throw SecurityException(chstr);

   case (u2)HIVECODE_TYPE_SYSTEM_SECURITY_VERIFICATIONEXCEPTION:
      throw VerificationException(chstr);
         }
      }
      break;

   case HIVECODE_NAMESPACE_SYSTEM_RUNTIME_REMOTING:
      {
         switch(exceptionName){
   case (u2)HIVECODE_TYPE_SYSTEM_RUNTIME_REMOTING_REMOTINGEXCEPTION:
      throw RemotingException(chstr);
         }
      }
      break;

   case HIVECODE_NAMESPACE_SYSTEM_RUNTIME_SERIALIZATION:
      {
         switch(exceptionName){
   case (u2)HIVECODE_TYPE_SYSTEM_RUNTIME_SERIALIZATION_SERIALIZATIONEXCEPTION:
      throw SerializationException(chstr);
         }
      }
      break;

   case HIVECODE_NAMESPACE_SYSTEM_SECURITY_CRYPTOGRAPHY:
      {
         switch(exceptionName){
   case (u2)HIVECODE_TYPE_SYSTEM_SECURITY_CRYPTOGRAPHY_CRYPTOGRAPHICEXCEPTION:
      throw CryptographicException(chstr);
         }
      }
      break;
   }

   // custom exception from the card application or someone is messing with the protocol
   // no means of translation.
   throw Exception(chstr);
}

u4 CheckForException(u1Array answer, u4 nameSpace, u2 type);
u4 CheckForException(u1Array answer, u4 nameSpace, u2 type)
{
   u1 protocolAnswerPrefix = answer.ReadU1At(0);

#ifdef SUPPORT_BETA_VERSION
   if (protocolAnswerPrefix == 0) {
      // beta version protocol (namespace & type systematically returned)
      if ((ComReadU4At(answer, 0) != nameSpace) || (ComReadU2At(answer, 4) != type)) {
         ProcessException(answer, 0);
      }
      // skip namespace & type
      return (4 + 2);
   }
#endif

   // new protocol
   if (protocolAnswerPrefix != 0x01) {
      if (protocolAnswerPrefix == 0xFF) {
         // exception info expected in the buffer
         ProcessException(answer, 1);
      } else {
         // someone is messing with the protocol
         throw RemotingException((lpCharPtr)"");
      }
   }

   // skip return type info (protocolAnswerPrefix: 0x01 = ok, 0xFF = exception)
   return 1;
}

SmartCardMarshaller::SmartCardMarshaller(SCARDHANDLE cardHandle, u2 portNumber, M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode)
{
   this->uri = NULL;
   this->pcsc = NULL;
   this->portNumber = portNumber;
   this->nameSpaceHivecode = nameSpaceHivecode;
   this->typeHivecode = typeHivecode;
   this->ProcessInputStream  = NULL;
   this->ProcessOutputStream = NULL;

#ifndef _XCL_
   this->pcsc = new PCSC(cardHandle);
#else // _XCL_
    this->pcsc = new XCLBroker(cardHandle);
#endif // _XCL_

   try {
      this->uri = new std::string(uri->c_str());
   } catch (...) {
      delete this->pcsc;
      throw;
   }
}

SmartCardMarshaller::SmartCardMarshaller(M_SAL_IN std::string* readerName, u2 portNumber, M_SAL_IN std::string* uri, u4 nameSpaceHivecode, u2 typeHivecode, u4 index)
{
   Log::begin( "SmartCardMarshaller::SmartCardMarshaller" );

   this->uri = NULL;
   this->pcsc = NULL;
   this->portNumber = portNumber;
   this->nameSpaceHivecode = nameSpaceHivecode;
   this->typeHivecode = typeHivecode;
   this->ProcessInputStream  = NULL;
   this->ProcessOutputStream = NULL;

#ifdef WIN32
   if ((readerName == NULL) || (_stricmp("selfdiscover", readerName->c_str()) == 0))
   {
#else
   if ((readerName == NULL) || (strncasecmp("selfdiscover", readerName->c_str(),readerName->length()) == 0))
   {
#endif
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new PCSC( readerName, &portNumber, uri, nameSpaceHivecode, typeHivecode, index) ..." );
#ifndef _XCL_
      this->pcsc = new PCSC( readerName, &portNumber, uri, nameSpaceHivecode, typeHivecode, index);
#else // _XCL
        this->pcsc = new XCLBroker(readerName, &portNumber, uri, nameSpaceHivecode, typeHivecode, index);
#endif // _XCL_
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new PCSC( readerName, &portNumber, uri, nameSpaceHivecode, typeHivecode, index) ok" );
   }
   else
   {
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new PCSC( readerName ) ..." );
#ifndef _XCL_
      this->pcsc = new PCSC( readerName );
#else // _XCL_
        this->pcsc = new XCLBroker(readerName);
#endif // _XCL_
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new PCSC( readerName ) ok" );
   }

   try
   {
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new std::string(uri->c_str()) ..." );
      this->uri = new std::string(uri->c_str());
      Log::log( "SmartCardMarshaller::SmartCardMarshaller -  new std::string(uri->c_str()) ok" );
   }
   catch (...)
   {
      Log::error( "SmartCardMarshaller::SmartCardMarshaller", "(...)" );
      delete this->pcsc;
      throw;
   }

   Log::end( "SmartCardMarshaller::SmartCardMarshaller" );
}

std::string* SmartCardMarshaller::GetReaderName(void)
{
   return this->pcsc->GetReaderName();
}

SCARDHANDLE SmartCardMarshaller::GetCardHandle(void)
{
   return this->pcsc->GetCardHandle();
}

void SmartCardMarshaller::DoTransact(bool flag)
{
   this->pcsc->DoTransact(flag);
}

SmartCardMarshaller::~SmartCardMarshaller(void)
{
   if (this->uri != NULL) {
      delete this->uri;
      this->uri = NULL;
   }

   if (this->pcsc != NULL) {
      delete this->pcsc;
      this->pcsc = NULL;
   }
}

void SmartCardMarshaller::UpdatePCSCCardHandle(SCARDHANDLE hCard)
{
   this->pcsc->SetCardHandle(hCard);
}

static void ProcessByReferenceArguments(u1 type, u1Array* dataArray, u4* offsetPtr, va_list* markerPtr, u1 isIn)
{
   //va_list marker = *markerPtr;
   u4 offset = *offsetPtr;

   switch (type) {

        case MARSHALLER_TYPE_REF_BOOL:
        case MARSHALLER_TYPE_REF_U1:
        case MARSHALLER_TYPE_REF_S1:
           {
              u1* val = va_arg(/*marker*/*markerPtr, u1*);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }
              if (isIn == TRUE) {
                 *dataArray += *val;
              }
              else {
                 *val = (*dataArray).ReadU1At(offset);
              }
              offset += sizeof(u1);
           }
           break;

        case MARSHALLER_TYPE_REF_CHAR:
        case MARSHALLER_TYPE_REF_U2:
        case MARSHALLER_TYPE_REF_S2:
           {
              u2* val = va_arg(/*marker*/*markerPtr, u2*);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }
              if (isIn == TRUE) {
                 *dataArray += *val;
              }
              else {
                 *val = ComReadU2At(*dataArray, offset);
              }
              offset += sizeof(u2);
           }
           break;

        case MARSHALLER_TYPE_REF_U4:
        case MARSHALLER_TYPE_REF_S4:
           {
              u4* val = va_arg(/*marker*/*markerPtr, u4*);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }
              if (isIn == TRUE) {
                 *dataArray += *val;
              }
              else {
                 *val = ComReadU4At(*dataArray, offset);
              }
              offset += sizeof(u4);
           }
           break;

        case MARSHALLER_TYPE_REF_U8:
        case MARSHALLER_TYPE_REF_S8:
           {
              u8* val = va_arg(/*marker*/*markerPtr, u8*);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }
              if (isIn == TRUE) {
                 *dataArray += *val;
              }
              else {
                 *val = ComReadU8At(*dataArray, offset);
              }
              offset += sizeof(u8);
           }
           break;

        case MARSHALLER_TYPE_REF_STRING:
           {
              std::string** val = va_arg(/*marker*/*markerPtr, std::string**);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }
              if (isIn == TRUE) {
                 offset += sizeof(u2);
                 if (*val != NULL) {
                    offset += ComputeUTF8Length((lpCharPtr)((*val)->c_str()));
                 }
                 (*dataArray).Append(*val);
              } else {
                 u2 len = ComReadU2At(*dataArray, offset);
                 offset += sizeof(u2);
                 if (len == 0xFFFF) {
                    *val = NULL;
                 } else {
                    // store result
                    u2 l = ComputeLPSTRLength(*dataArray, offset, len);
                    char* chstr = new char[l + 1];
                    try {
                       chstr[l] = '\0';
                       UTF8Decode(*dataArray, offset, len, chstr);
                       *val = new std::string(chstr);
                    } catch (...) {
                       delete[] chstr;
                       throw;
                    }
                    delete[] chstr;
                    offset += len;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_REF_S1ARRAY:
        case MARSHALLER_TYPE_REF_BOOLARRAY:
        case MARSHALLER_TYPE_REF_U1ARRAY:
           {
              u1Array** val = va_arg(/*marker*/*markerPtr, u1Array**);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }

              if (isIn == TRUE) {
                 offset += sizeof(u4);
                 if ((*val)->IsNull() == FALSE) {
                    u4  valLen = (*val)->GetLength();
                    u1* valBuf = (*val)->GetBuffer();
                    *dataArray += valLen;
                    for(u4 v = 0; v < valLen; v++) {
                       *dataArray += valBuf[v];
                    }
                    offset += (sizeof(u1) * valLen);
                 } else {
                    *dataArray += 0xFFFFFFFF;
                 }
              } else {

                 u4 len = ComReadU4At(*dataArray, offset);
                 offset += sizeof(u4);

                 u1Array* refArray = NULL;

                 try {
                    if (len == 0xFFFFFFFF) {
                       refArray = new u1Array(-1);
                    } else {
                       refArray = new u1Array(len);
                       for (u4 i = 0; i < len; i++) {
                          refArray->SetU1At(i, dataArray->ReadU1At(offset));
                          offset += sizeof(u1);
                       }
                    }
                 } catch (...) {
                    if (refArray != NULL) {
                       delete refArray;
                    }
                    throw;
                 }

                 if (*val != NULL) {
                    // perform cleanup
                    delete *val;
                 }

                 *val = refArray;
              }
           }
           break;

        case MARSHALLER_TYPE_REF_S2ARRAY:
        case MARSHALLER_TYPE_REF_U2ARRAY:
           {
              u2Array** val = va_arg(/*marker*/*markerPtr, u2Array**);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }

              if (isIn == TRUE) {
                 offset += sizeof(u4);
                 if ((*val)->IsNull() == FALSE) {
                    u4  valLen = (*val)->GetLength();
                    u2* valBuf = (*val)->GetBuffer();
                    *dataArray += valLen;
                    for(u4 v = 0; v < valLen; v++) {
                       *dataArray += valBuf[v];
                    }
                    offset += (sizeof(u2) * valLen);
                 } else {
                    *dataArray += 0xFFFFFFFF;
                 }
              } else {

                 u4 len = ComReadU4At(*dataArray, offset);
                 offset += sizeof(u4);

                 u2Array* refArray = NULL;

                 try {
                    if (len == 0xFFFFFFFF) {
                       refArray = new u2Array(-1);
                    } else {
                       refArray = new u2Array(len);
                       for (u4 i = 0; i < len; i++) {
                          refArray->SetU2At(i, ComReadU2At(*dataArray, offset));
                          offset += sizeof(u2);
                       }
                    }
                 } catch (...) {
                    if (refArray != NULL) {
                       delete refArray;
                    }
                    throw;
                 }

                 if (*val != NULL) {
                    // perform cleanup
                    delete *val;
                 }

                 *val = refArray;
              }
           }
           break;

        case MARSHALLER_TYPE_REF_S4ARRAY:
        case MARSHALLER_TYPE_REF_U4ARRAY:
           {
              u4Array** val = va_arg(/*marker*/*markerPtr, u4Array**);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }

              if (isIn == TRUE) {
                 offset += sizeof(u4);
                 if ((*val)->IsNull() == FALSE) {
                    u4  valLen = (*val)->GetLength();
                    u4* valBuf = (*val)->GetBuffer();
                    *dataArray += valLen;
                    for(u4 v = 0; v < valLen; v++) {
                       *dataArray += valBuf[v];
                    }
                    offset += (sizeof(u4) * valLen);
                 } else {
                    *dataArray += 0xFFFFFFFF;
                 }
              } else {

                 u4 len = ComReadU4At(*dataArray, offset);
                 offset += sizeof(u4);

                 u4Array* refArray = NULL;

                 try {
                    if (len == 0xFFFFFFFF) {
                       refArray = new u4Array(-1);
                    } else {
                       refArray = new u4Array(len);
                       for (u4 i = 0; i < len; i++) {
                          refArray->SetU4At(i, ComReadU4At(*dataArray, offset));
                          offset += sizeof(u4);
                       }
                    }
                 } catch (...) {
                    if (refArray != NULL) {
                       delete refArray;
                    }
                    throw;
                 }

                 if (*val != NULL) {
                    // perform cleanup
                    delete *val;
                 }

                 *val = refArray;
              }
           }
           break;

        case MARSHALLER_TYPE_REF_S8ARRAY:
        case MARSHALLER_TYPE_REF_U8ARRAY:
           {
              u8Array** val = va_arg(/*marker*/*markerPtr, u8Array**);
              if (val == NULL) {
                 throw NullReferenceException((lpCharPtr)"");
              }

              if (isIn == TRUE) {
                 offset += sizeof(u4);
                 if ((*val)->IsNull() == FALSE) {
                    u4  valLen = (*val)->GetLength();
                    u8* valBuf = (*val)->GetBuffer();
                    *dataArray += valLen;
                    for(u4 v = 0; v < valLen; v++) {
                       *dataArray += valBuf[v];
                    }
                    offset += (sizeof(u8) * valLen);
                 } else {
                    *dataArray += 0xFFFFFFFF;
                 }
              } else {

                 u4 len = ComReadU4At(*dataArray, offset);
                 offset += sizeof(u4);

                 u8Array* refArray = NULL;

                 try {
                    if (len == 0xFFFFFFFF) {
                       refArray = new u8Array(-1);
                    } else {
                       refArray = new u8Array(len);
                       for (u4 i = 0; i < len; i++) {
                          refArray->SetU8At(i, ComReadU8At(*dataArray, offset));
                          offset += sizeof(u4);
                       }
                    }
                 } catch (...) {
                    if (refArray != NULL) {
                       delete refArray;
                    }
                    throw;
                 }

                 if (*val != NULL) {
                    // perform cleanup
                    delete *val;
                 }

                 *val = refArray;
              }
           }
           break;

        default:
           {
              if (isIn == TRUE) {
                 throw Exception("Un-recognized input argument type");
              } else {
                 throw Exception("Un-recognized byref argument type");
              }
           }
           break;
   }

   //*markerPtr = marker;
   *offsetPtr = offset;
}


static void ProcessOutputArguments(u1 type, u1Array* answerPtr, u4* offsetPtr, va_list* markerPtr)
{
   switch (type) {

        case MARSHALLER_TYPE_IN_BOOL:
        case MARSHALLER_TYPE_IN_S1:
        case MARSHALLER_TYPE_IN_U1:
        case MARSHALLER_TYPE_IN_CHAR:
        case MARSHALLER_TYPE_IN_S2:
        case MARSHALLER_TYPE_IN_U2:
        case MARSHALLER_TYPE_IN_S4:
        case MARSHALLER_TYPE_IN_U4:
        case MARSHALLER_TYPE_IN_STRING:
        case MARSHALLER_TYPE_IN_MEMORYSTREAM:
        case MARSHALLER_TYPE_IN_BOOLARRAY:
        case MARSHALLER_TYPE_IN_S1ARRAY:
        case MARSHALLER_TYPE_IN_U1ARRAY:
        case MARSHALLER_TYPE_IN_CHARARRAY:
        case MARSHALLER_TYPE_IN_S2ARRAY:
        case MARSHALLER_TYPE_IN_U2ARRAY:
        case MARSHALLER_TYPE_IN_S4ARRAY:
        case MARSHALLER_TYPE_IN_U4ARRAY:
        case MARSHALLER_TYPE_IN_S8ARRAY:
        case MARSHALLER_TYPE_IN_U8ARRAY:
        case MARSHALLER_TYPE_IN_STRINGARRAY:
           {
              // ignore input argument (slot size = 4 bytes)
              //va_list marker = *markerPtr;
              /*u4 v = */va_arg(/*marker*/*markerPtr, u4);
              //*markerPtr = marker;

              /*DBG_UNREFERENCED_LOCAL_VARIABLE(v);*/
           }
           break;

        case MARSHALLER_TYPE_IN_S8:
        case MARSHALLER_TYPE_IN_U8:
           {
              // ignore input argument (slot size = 8 bytes)
              //va_list marker = *markerPtr;
              /*u8 v = */va_arg(/*marker*/*markerPtr, u8);
              //*markerPtr = marker;

              /*DBG_UNREFERENCED_LOCAL_VARIABLE(v);*/
           }
           break;

        default:
           ProcessByReferenceArguments(type, answerPtr, offsetPtr, markerPtr, FALSE);
           break;
   }
}

static u4 ProcessReturnType(u1 type, u1Array* answerPtr, va_list* markerPtr)
{
   u1Array answer = *answerPtr;
   u4 offset = 0;
   //va_list marker = *markerPtr;

   switch (type) {

      // void (can happen for the method return param)
        case MARSHALLER_TYPE_RET_VOID:
           {
              if (answer.GetLength() > 0) {
#ifdef SUPPORT_BETA_VERSION
                 if (answer.ReadU1At(0) == 0x00) {
                    // beta version protocol
                    ProcessException(answer, 0);
                 }
#endif
                 // new protocol
                 ProcessException(answer, 1);
              }
           }
           break;

        case MARSHALLER_TYPE_RET_BOOL:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_BOOLEAN);
              u1* valToReturn = va_arg(/*marker*/*markerPtr, u1*);
              if (answer.ReadU1At(offset) == 0) {
                 *valToReturn = FALSE;
              } else {
                 *valToReturn = TRUE;
              }
              offset += sizeof(u1);
           }
           break;

        case MARSHALLER_TYPE_RET_S1:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_SBYTE);
              s1* valToReturn = va_arg(/*marker*/*markerPtr, s1*);
              *valToReturn = answer.ReadU1At(offset);
              offset += sizeof(u1);
           }
           break;

        case MARSHALLER_TYPE_RET_U1:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_BYTE);
              u1* valToReturn = va_arg(/*marker*/*markerPtr, u1*);
              *valToReturn = answer.ReadU1At(offset);
              offset += sizeof(u1);
           }
           break;

        case MARSHALLER_TYPE_RET_CHAR:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_CHAR);
              char* valToReturn = va_arg(/*marker*/*markerPtr, char*);
              *valToReturn = (char)ComReadU2At(answer, offset);
              offset += sizeof(u2);
           }
           break;

        case MARSHALLER_TYPE_RET_S2:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT16);
              s2* valToReturn = va_arg(/*marker*/*markerPtr, s2*);
              *valToReturn = ComReadU2At(answer, offset);
              offset += sizeof(u2);
           }
           break;

        case MARSHALLER_TYPE_RET_U2:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT16);
              u2* valToReturn = va_arg(/*marker*/*markerPtr, u2*);
              *valToReturn = ComReadU2At(answer, offset);
              offset += sizeof(u2);
           }
           break;

        case MARSHALLER_TYPE_RET_S4:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT32);
              s4* valToReturn = va_arg(/*marker*/*markerPtr, s4*);
              *valToReturn = ComReadU4At(answer, offset);
              offset += sizeof(u4);
           }
           break;

        case MARSHALLER_TYPE_RET_U4:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT32);
              u4* valToReturn = va_arg(/*marker*/*markerPtr, u4*);
              *valToReturn = ComReadU4At(answer, offset);
              offset += sizeof(u4);
           }
           break;

        case MARSHALLER_TYPE_RET_S8:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT64);
              s8* valToReturn = va_arg(/*marker*/*markerPtr, s8*);
              *valToReturn = ComReadU8At(answer, offset);
              offset += sizeof(u8);
           }
           break;

        case MARSHALLER_TYPE_RET_U8:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT64);
              u8* valToReturn = va_arg(/*marker*/*markerPtr, u8*);
              *valToReturn = ComReadU8At(answer, offset);
              offset += sizeof(u8);
           }
           break;

        case MARSHALLER_TYPE_RET_STRING:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_STRING);
              std::string** valToReturn = va_arg(/*marker*/*markerPtr, std::string**);
              u2 len = ComReadU2At(answer, offset);
              offset += sizeof(u2);
              if (len == 0xFFFF) {
                 *valToReturn = NULL;
              } else {
                 // store result
                 u2 l = ComputeLPSTRLength(answer, offset, len);
                 char* chstr = new char[l + 1];
                 try {
                    chstr[l] = '\0';
                    UTF8Decode(answer, offset, len, chstr);
                    *valToReturn = new std::string(chstr);
                 } catch (...) {
                    delete[] chstr;
                    throw;
                 }
                 delete[] chstr;
                 offset += len;
              }
           }
           break;

        case MARSHALLER_TYPE_RET_BOOLARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_BOOLEAN_ARRAY);
              u1Array** valToReturn = va_arg(/*marker*/*markerPtr, u1Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new u1Array(-1);
              } else {
                 // store result
                 *valToReturn = new u1Array(answer, offset, len);
                 offset += len;
              }
           }
           break;

        case MARSHALLER_TYPE_RET_S1ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_SBYTE_ARRAY);
              s1Array** valToReturn = va_arg(/*marker*/*markerPtr, s1Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new s1Array(-1);
              } else {
                 // store result
                 *valToReturn = new s1Array(answer, offset, len);
                 offset += len;
              }
           }
           break;

        case MARSHALLER_TYPE_RET_U1ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_BYTE_ARRAY);
              u1Array** valToReturn = va_arg(/*marker*/*markerPtr, u1Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new u1Array(-1);
              } else {
                 // store result
                 *valToReturn = new u1Array(answer, offset, len);
                 offset += len;
              }
           }
           break;

        case MARSHALLER_TYPE_RET_CHARARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_CHAR_ARRAY);
              charArray** valToReturn = va_arg(/*marker*/*markerPtr, charArray**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new charArray(-1);
              } else {
                 // store result
                 *valToReturn = new charArray(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU2At(answer, offset);
                       offset += sizeof(s2);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_S2ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT16_ARRAY);
              s2Array** valToReturn = va_arg(/*marker*/*markerPtr, s2Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new s2Array(-1);
              } else {
                 // store result
                 *valToReturn = new s2Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU2At(answer, offset);
                       offset += sizeof(s2);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_U2ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT16_ARRAY);
              u2Array** valToReturn = va_arg(/*marker*/*markerPtr, u2Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new u2Array(-1);
              } else {
                 // store result
                 *valToReturn = new u2Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU2At(answer, offset);
                       offset += sizeof(u2);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_S4ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT32_ARRAY);
              s4Array** valToReturn = va_arg(/*marker*/*markerPtr, s4Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new s4Array(-1);
              } else {
                 // store result
                 *valToReturn = new s4Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU4At(answer, offset);
                       offset += sizeof(s4);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_U4ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT32_ARRAY);
              u4Array** valToReturn = va_arg(/*marker*/*markerPtr, u4Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new u4Array(-1);
              } else {
                 // store result
                 *valToReturn = new u4Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU4At(answer, offset);
                       offset += sizeof(u4);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_S8ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT64_ARRAY);
              s8Array** valToReturn = va_arg(/*marker*/*markerPtr, s8Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new s8Array(-1);
              } else {
                 // store result
                 *valToReturn = new s8Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU8At(answer, offset);
                       offset += sizeof(s8);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_U8ARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT64_ARRAY);
              u8Array** valToReturn = va_arg(/*marker*/*markerPtr, u8Array**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new u8Array(-1);
              } else {
                 // store result
                 *valToReturn = new u8Array(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       (*valToReturn)->GetBuffer()[j] = ComReadU8At(answer, offset);
                       offset += sizeof(u8);
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_STRINGARRAY:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_STRING_ARRAY);
              StringArray** valToReturn = va_arg(/*marker*/*markerPtr, StringArray**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new StringArray(-1);
              } else {
                 // store result
                 *valToReturn = new StringArray(len);
                 try {
                    for (u4 j = 0; j < len; j++) {
                       u2 lenStr = ComReadU2At(answer, offset);
                       offset += sizeof(u2);
                       if (lenStr != 0xFFFF) {
                          u2 blen = ComputeLPSTRLength(answer, offset, lenStr);
                          char* lpstr = new char[blen + 1];
                          try {
                             lpstr[blen] = '\0';
                             UTF8Decode(answer, offset, lenStr, lpstr);
                             offset += lenStr;

                             (*valToReturn)->SetStringAt(j, new std::string(lpstr));
                          } catch (...) {
                             delete[] lpstr;
                             throw;
                          }
                          delete[] lpstr;
                       }
                    }
                 } catch (...) {
                    delete *valToReturn;
                    throw;
                 }
              }
           }
           break;

        case MARSHALLER_TYPE_RET_MEMORYSTREAM:
           {
              offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM_IO, HIVECODE_TYPE_SYSTEM_IO_MEMORYSTREAM);
              MemoryStream** valToReturn = va_arg(/*marker*/*markerPtr, MemoryStream**);
              u4 len = ComReadU4At(answer, offset);
              offset += sizeof(u4);
              if (len == 0xFFFFFFFF) {
                 *valToReturn = new MemoryStream(-1);
              } else {
                 // store result
                 *valToReturn = new MemoryStream(answer, offset, len);
                 offset += len;
              }
           }
           break;

        default:
           {
              throw Exception("Un-recognized return type");
           }
           break;
   }

   //*markerPtr = marker;
   return offset;
}

static void ProcessInputArguments(u1 type, u1Array* invokeAPDU_data, va_list* markerPtr)
{
   //va_list marker = *markerPtr;

   switch (type) {

        case MARSHALLER_TYPE_IN_BOOL:
        case MARSHALLER_TYPE_IN_S1:
        case MARSHALLER_TYPE_IN_U1:
           {
              u1 val = (u1)va_arg(/*marker*/*markerPtr, s4);
              *invokeAPDU_data += val;
           }
           break;

        case MARSHALLER_TYPE_IN_CHAR:
        case MARSHALLER_TYPE_IN_S2:
        case MARSHALLER_TYPE_IN_U2:
           {
              u2 val = (u2)va_arg(/*marker*/*markerPtr, s4);
              *invokeAPDU_data += val;
           }
           break;

        case MARSHALLER_TYPE_IN_S4:
        case MARSHALLER_TYPE_IN_U4:
           {
              u4 val = (u4)va_arg(/*marker*/*markerPtr, s4);
              *invokeAPDU_data += val;
           }
           break;

        case MARSHALLER_TYPE_IN_S8:
        case MARSHALLER_TYPE_IN_U8:
           {
              u8 val = (u8)va_arg(/*marker*/*markerPtr,u8);
              *invokeAPDU_data += val;
           }
           break;

        case MARSHALLER_TYPE_IN_STRING:
           {
              std::string* val = va_arg(/*marker*/*markerPtr, std::string*);
              (*invokeAPDU_data).Append(val);
           }
           break;

        case MARSHALLER_TYPE_IN_MEMORYSTREAM:
        case MARSHALLER_TYPE_IN_BOOLARRAY:
        case MARSHALLER_TYPE_IN_S1ARRAY:
        case MARSHALLER_TYPE_IN_U1ARRAY:
           {
              u1Array* val = va_arg(/*marker*/*markerPtr, u1Array*);
              if ((val != NULL) && (val->IsNull() == FALSE)) {
                 u4  valLen = val->GetLength();
                 u1* valBuf = val->GetBuffer();
                 // add length
                 *invokeAPDU_data += valLen;
                 // add data
                 for(u4 v = 0; v < valLen; v++)
                    *invokeAPDU_data += valBuf[v];
              } else {
                 // add null pointer
                 *invokeAPDU_data += (u4)0xFFFFFFFF;
              }
           }
           break;

        case MARSHALLER_TYPE_IN_CHARARRAY:
        case MARSHALLER_TYPE_IN_S2ARRAY:
        case MARSHALLER_TYPE_IN_U2ARRAY:
           {
              u2Array* val = va_arg(/*marker*/*markerPtr, u2Array*);
              if ((val != NULL) && (val->IsNull() == FALSE)) {
                 u4  valLen = val->GetLength();
                 u2* valBuf = val->GetBuffer();
                 *invokeAPDU_data += valLen;
                 for(u4 v = 0; v < valLen; v++) {
                    *invokeAPDU_data += valBuf[v];
                 }
              } else {
                 // add null pointer
                 *invokeAPDU_data += (u4)0xFFFFFFFF;
              }
           }
           break;

        case MARSHALLER_TYPE_IN_S4ARRAY:
        case MARSHALLER_TYPE_IN_U4ARRAY:
           {
              u4Array* val = va_arg(/*marker*/*markerPtr, u4Array*);
              if ((val != NULL) && (val->IsNull() == FALSE)) {
                 u4  valLen = val->GetLength();
                 u4* valBuf = val->GetBuffer();
                 *invokeAPDU_data += valLen;
                 for(u4 v = 0; v < valLen; v++) {
                    *invokeAPDU_data += valBuf[v];
                 }
              } else {
                 // add null pointer
                 *invokeAPDU_data += (u4)0xFFFFFFFF;
              }
           }
           break;

        case MARSHALLER_TYPE_IN_S8ARRAY:
        case MARSHALLER_TYPE_IN_U8ARRAY:
           {
              u8Array* val = va_arg(/*marker*/*markerPtr, u8Array*);
              if ((val != NULL) && (val->IsNull() == FALSE)) {
                 u4  valLen = val->GetLength();
                 u8* valBuf = val->GetBuffer();
                 *invokeAPDU_data += valLen;
                 for(u4 v = 0; v < valLen; v++) {
                    *invokeAPDU_data += valBuf[v];
                 }
              } else {
                 // add null pointer
                 *invokeAPDU_data += (u4)0xFFFFFFFF;
              }
           }
           break;

        case MARSHALLER_TYPE_IN_STRINGARRAY:
           {
              StringArray* val = va_arg(/*marker*/*markerPtr, StringArray*);
              if ((val != NULL) && (val->IsNull() == FALSE)) {
                 u4  valLen = val->GetLength();
                 *invokeAPDU_data += valLen;
                 // add data
                 for (u4 j = 0; j < valLen; j++) {
                    std::string* str = val->GetStringAt(j);
                    if(str == NULL){ // add null pointer
                       *invokeAPDU_data += (u2)0xFFFF;
                    }else{
                       (*invokeAPDU_data).Append(str);
                    }
                 }
              } else {
                 // add null pointer
                 *invokeAPDU_data += (u4)0xFFFFFFFF;
              }
           }
           break;

        default:
           u4 offset = 0;
           ProcessByReferenceArguments(type, invokeAPDU_data, &offset, /*markerPtr*/markerPtr, TRUE);
           // do not adjust markerPtr.
           return;

   }

   //*markerPtr = marker;
}

void SmartCardMarshaller::Invoke(s4 nParam, ...)
{
   // Allow selfdiscovery of port
   if (this->portNumber == 0) {
      s4 _s4 = 0;
      u4 nameSpaceHivecode = this->nameSpaceHivecode;
      u2 typeHivecode      = this->typeHivecode;
      std::string* uri     = this->uri;

      this->portNumber		= CARDMANAGER_SERVICE_PORT;
      this->nameSpaceHivecode = HIVECODE_NAMESPACE_SMARTCARD;
      this->typeHivecode		= HIVECODE_TYPE_SMARTCARD_CONTENTMANAGER;
      this->uri				= new std::string(CARDMANAGER_SERVICE_NAME);

      try {

         // call the GetAssociatedPort method.
         Invoke(3, HIVECODE_METHOD_SMARTCARD_CONTENTMANAGER_GETASSOCIATEDPORT, MARSHALLER_TYPE_IN_S4, nameSpaceHivecode, MARSHALLER_TYPE_IN_S2, typeHivecode, MARSHALLER_TYPE_IN_STRING, uri, MARSHALLER_TYPE_RET_S4, &_s4);

      } catch (...) {

         delete this->uri;

         this->portNumber		= (u2)_s4;
         this->nameSpaceHivecode = nameSpaceHivecode;
         this->typeHivecode		= typeHivecode;
         this->uri				= uri;

         throw;
      }

      delete this->uri;

      this->portNumber		= (u2)_s4;
      this->nameSpaceHivecode = nameSpaceHivecode;
      this->typeHivecode		= typeHivecode;
      this->uri				= uri;
   }

   u1Array invokeAPDU(0);

   va_list marker;

   va_start(marker, nParam);

   // add 0xD8
   invokeAPDU += (u1)0xD8;

   // add port number
   invokeAPDU += (u2)this->portNumber;

   // add 0x6F
   invokeAPDU += (u1)0x6F;

   // add namespace Hivecode
   invokeAPDU += this->nameSpaceHivecode;

   // add type hivecode
   invokeAPDU += this->typeHivecode;

   // NOTE : va_arg(marker,type)
   // As per ISO C++ if the pritives types
   // char,short,byte are passed as argument to varidic method
   // they are upcasted to int.
   //
   // On windows if you use va_arg(marker,u2), no warning will be issued
   // and there will be no complain at run time, whereas
   // On Linux (with g++) if you use va_arg(markey,u2), a warning will be issued
   // saying that it is invalid to do this and run time will fail and it does fail
   // with message "Segmentation fault".
   //
   // So va_arg for all int primitive types (char, short, byte and their unsigned values)
   // should have s4 as the type.

   // add method name
   u2 methodID = (u2)va_arg(marker, s4);
   invokeAPDU += methodID;

   // add uri
   u1Array uriArray(ComputeUTF8Length((lpCharPtr)this->uri->c_str()));
   UTF8Encode((lpCharPtr)this->uri->c_str(), uriArray);
   invokeAPDU += (u2)uriArray.GetLength();
   invokeAPDU += uriArray;

   u1Array invokeAPDU_data(0);

   // process input arguments
   for (s4 iParam = 0; iParam < nParam; iParam++) {
      u1 type = (u1)va_arg(marker, s4);
      ProcessInputArguments(type, &invokeAPDU_data, &marker);
   }

   if(ProcessInputStream != NULL){
      u1Array invokeAPDU_data_Modified(0);
      ProcessInputStream(invokeAPDU_data,invokeAPDU_data_Modified);
      invokeAPDU += invokeAPDU_data_Modified;
   }else{
      invokeAPDU += invokeAPDU_data;
   }

   u1Array answer_o(0);

   this->pcsc->BeginTransaction();

   try {

      if(invokeAPDU.GetLength() > (s4)APDU_TO_CARD_MAX_SIZE)
      {
         u4 offset = 0;
         u4 size = invokeAPDU.GetLength() -1 - 2 - 1 - 4 - 2 - 2 - 2 -  uriArray.GetLength();

         u1 first = TRUE;

         u4 dataToSendLength = invokeAPDU.GetLength();
         u4 invokeApduStartOffset = 0;

         while(dataToSendLength > 0){

            u4 encodedSize = size;
            u4 encodedOffset = (u4)offset;

            u4 subCommandMaxAllowed = APDU_TO_CARD_MAX_SIZE -1 - 2 - 8;

            u4 length = dataToSendLength > subCommandMaxAllowed ? subCommandMaxAllowed : dataToSendLength;

            u1Array subApdu(0);

            if(first == TRUE){
               u4 usefulDataLength = length -1 - 2 -1 -4 -2 -2 -2 - uriArray.GetLength();

               subApdu += (u1)0xD8;
               subApdu += (u2)0xFFFF;
               subApdu += encodedSize;
               subApdu += usefulDataLength;

               if ((u8)(invokeApduStartOffset + length) > (u8)invokeAPDU.GetLength()) {
                  throw ArgumentOutOfRangeException((lpCharPtr)"");
               }

               for(u4 j = invokeApduStartOffset; j < (invokeApduStartOffset + length); j++) {
                  subApdu += invokeAPDU.GetBuffer()[j];
               }

               first = FALSE;
               offset += usefulDataLength;

            }else{

               subApdu += (u1)0xD8;
               subApdu += (u2)0xFFFF;
               subApdu += encodedOffset;
               subApdu += length;

               if ((u8)(invokeApduStartOffset + length) > (u8)invokeAPDU.GetLength()) {
                  throw ArgumentOutOfRangeException((lpCharPtr)"");
               }

               for(u4 j = invokeApduStartOffset; j < (invokeApduStartOffset + length); j++) {
                  subApdu += invokeAPDU.GetBuffer()[j];
               }

               offset += length;
            }

            size = 0;
            invokeApduStartOffset = invokeApduStartOffset + length;
            dataToSendLength = dataToSendLength - length;

            u1Array apduToSend(5);

            apduToSend.GetBuffer()[0] = 0x80;
            apduToSend.GetBuffer()[1] = 0xC2;
            apduToSend.GetBuffer()[2] = 0x00;
            apduToSend.GetBuffer()[3] = 0x00;
            apduToSend.GetBuffer()[4] = (u1)subApdu.GetLength();
            apduToSend += subApdu;

            this->pcsc->ExchangeData(apduToSend, answer_o);
         }
      }else{

         // construct call
         u1Array apdu(5);
         apdu.GetBuffer()[0] = 0x80;
         apdu.GetBuffer()[1] = 0xC2;
         apdu.GetBuffer()[2] = 0x00;
         apdu.GetBuffer()[3] = 0x00;
         apdu.GetBuffer()[4] = (u1)invokeAPDU.GetLength();
         apdu += invokeAPDU;

         this->pcsc->ExchangeData(apdu, answer_o);
      }
   } catch (...) {
      this->pcsc->EndTransaction();
      throw;
   }

   this->pcsc->EndTransaction();

   u1Array answer(0);

   if ((ProcessOutputStream != NULL) && (answer_o.GetLength() > 0) && (answer_o.ReadU1At(0) == 0x01)){
      u1Array answerI(0);
      u1Array answerM(0);

      for(u4 i = 1; i < answer_o.GetLength(); i++){
         answerI += answer_o.GetBuffer()[i];
      }

      ProcessOutputStream(answerI, answerM);

      answer += answer_o.GetBuffer()[0];

      for(u4 i=0;i<answerM.GetLength();i++){
         answer += answerM.GetBuffer()[i];
      }

   } else {
      for(u4 i=0;i<answer_o.GetLength();i++)
         answer += answer_o.GetBuffer()[i];
   }

   // analyze return type
   u4 offset = ProcessReturnType((u1)va_arg(marker, s4), &answer, &marker);

   va_end(marker);

   // process byref types
   va_start(marker, nParam);

   // skip method name param
   u2 methodID2 = (u2)va_arg(marker, s4);

   if (methodID2 == methodID) {
      for (s4 iParam = 0; iParam < nParam; iParam++) {
         u1 type = (u1)va_arg(marker, s4);
         ProcessOutputArguments(type, &answer, &offset, &marker);
      }
   }

   va_end(marker);
}

void SmartCardMarshaller::SetInputStream(pCommunicationStream inStream){
   this->ProcessInputStream = inStream;
}

void  SmartCardMarshaller::SetOutputStream(pCommunicationStream outStream){
   this->ProcessOutputStream = outStream;
}

MARSHALLER_NS_END

