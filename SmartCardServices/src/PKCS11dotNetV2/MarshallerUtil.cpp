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


#include "MarshallerUtil.h"
#include "Except.h"

MARSHALLER_NS_BEGIN

#define SUPPORT_BETA_VERSION


/*
*/
u2 MarshallerUtil::ComReadU2At( u1Array & a_Buffer, const u4& a_Position ) {

	if( (u8)( a_Position + sizeof( u2 ) ) > (u8)a_Buffer.GetLength( ) ) {

		throw ArgumentOutOfRangeException( (char*)"" );
	}

	u1* p = a_Buffer.GetBuffer();

	return (u2)( ( ( (u2) p[ a_Position ] ) << 8 ) + p[ a_Position + 1 ] );
}


/*
*/
u4 MarshallerUtil::ComReadU4At( u1Array& a_Buffer, const u4& a_Position ) {

	if( (u8)( a_Position + sizeof( u4 ) ) > (u8)a_Buffer.GetLength()) {

		throw ArgumentOutOfRangeException( (char*)"" );
	}

	u1* p = a_Buffer.GetBuffer();

	return (u4)( ( ( (u4)p[ a_Position ] ) << 24) + ( ( (u4)p[ a_Position + 1 ] ) << 16 ) + ( ( (u4) p[ a_Position + 2 ] ) << 8 ) + p[ a_Position + 3 ] );
}


/*
*/
u8 MarshallerUtil::ComReadU8At( u1Array& a_Buffer, const u4& a_Position ) {

	if( (u8)( a_Position + sizeof( u8 ) ) > (u8)a_Buffer.GetLength( ) ) {

		throw ArgumentOutOfRangeException( (char*)"" );
	}

	u1* p = a_Buffer.GetBuffer( );

	u1 b1 = p[ a_Position ];
	u1 b2 = p[ a_Position + 1 ];
	u1 b3 = p[ a_Position + 2 ];
	u1 b4 = p[ a_Position + 3 ];
	u1 b5 = p[ a_Position + 4 ];
	u1 b6 = p[ a_Position + 5 ];
	u1 b7 = p[ a_Position + 6 ];
	u1 b8 = p[ a_Position + 7 ];

	return ( ( (u8) b1 << 56 ) | ( (u8) b2 << 48 ) | ( (u8)b3 << 40 ) | ( (u8)b4 << 32 ) | ( (u8)b5 << 24 ) | ( (u8)b6 << 16 ) | ( (u8)b7 << 8 ) | b8 );
}


/*
*/
void MarshallerUtil::ProcessException( u1Array& a_Answer, const u4& a_ProtocolOffset ) {

	u4 exceptionNamespace;
	u4 exceptionName;
	char* chst = NULL;

	try {

		exceptionNamespace = ComReadU4At( a_Answer, a_ProtocolOffset + 0 );

		exceptionName = ComReadU2At( a_Answer, a_ProtocolOffset + 4 );

		if( a_Answer.GetLength( ) > ( a_ProtocolOffset + 6 ) ) {

			u2 strLen = ComReadU2At( a_Answer, a_ProtocolOffset + 6 );

			if ((strLen > 0) && (strLen != 0xFFFF)) {

				u2 len = ComputeLPSTRLength( a_Answer, a_ProtocolOffset + 8, strLen );

				chst = new char[ len + 1 ];

				chst[len] = '\0';

				UTF8Decode( a_Answer, a_ProtocolOffset + 8, strLen, chst );
			}
		}
	} catch (...) {

		// someone is messing with the protocol
		if( chst ) {
			delete[ ] chst;
		}

		throw RemotingException( (char*)"" );
	}

	if( !chst ) {

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
	std::string chstr( chst );

	delete[ ] chst;

	switch( exceptionNamespace ) {

	case HIVECODE_NAMESPACE_SYSTEM:
		{
			switch( exceptionName ) {

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
			switch(exceptionName) {

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
	throw Exception( chstr );
}


/*
*/
u4 MarshallerUtil::CheckForException( u1Array& a_Answer, const u4& a_NameSpace, const u2& a_Type ) {

	u1 protocolAnswerPrefix = a_Answer.ReadU1At( 0 );

#ifdef SUPPORT_BETA_VERSION
	if( protocolAnswerPrefix == 0 ) {

		// beta version protocol (namespace & type systematically returned)
		if( ( ComReadU4At( a_Answer, 0 ) != a_NameSpace ) || ( ComReadU2At( a_Answer, 4 ) != a_Type ) ) {

			ProcessException( a_Answer, 0 );
		}

		// skip namespace & type
		return ( 4 + 2 );
	}
#endif

	// new protocol
	if( protocolAnswerPrefix != 0x01 ) {

		if( protocolAnswerPrefix == 0xFF ) {

			// exception info expected in the buffer
			ProcessException( a_Answer, 1 );

		} else {

			// someone is messing with the protocol
			throw RemotingException( (char*)"" );
		}
	}

	// skip return type info (protocolAnswerPrefix: 0x01 = ok, 0xFF = exception)
	return 1;
}


/*
*/
void MarshallerUtil::ProcessByReferenceArguments( const u1& a_Type, u1Array* a_DataArray, u4* a_OffsetPtr, va_list* a_MarkerPtr, const u1&  a_isIn ) {
	
	//va_list marker = *markerPtr;
	u4 offset = *a_OffsetPtr;

	switch( a_Type ) {

	case MARSHALLER_TYPE_REF_BOOL:
	case MARSHALLER_TYPE_REF_U1:
	case MARSHALLER_TYPE_REF_S1:
		{
			u1* val = va_arg( *a_MarkerPtr, u1* );

			if( !val ) {

				throw NullReferenceException( (char*)"" );
			}

			if( a_isIn ) {

				*a_DataArray += *val;
			
			} else {

				*val = (*a_DataArray).ReadU1At( offset );
			}

			offset += sizeof( u1 );
		}
		break;

	case MARSHALLER_TYPE_REF_CHAR:
	case MARSHALLER_TYPE_REF_U2:
	case MARSHALLER_TYPE_REF_S2:
		{
			u2* val = va_arg( *a_MarkerPtr, u2* );

			if( !val ) {

				throw NullReferenceException( (char*)"" );
			}

			if( a_isIn ) {
			
				*a_DataArray += *val;
			
			} else {

				*val = ComReadU2At( *a_DataArray, offset );
			}

			offset += sizeof( u2 );
		}
		break;

	case MARSHALLER_TYPE_REF_U4:
	case MARSHALLER_TYPE_REF_S4:
		{
			u4* val = va_arg( *a_MarkerPtr, u4* );

			if( !val ) {

				throw NullReferenceException( (char*)"" );
			}

			if( a_isIn ) {
			
				*a_DataArray += *val;
			
			} else {

				*val = ComReadU4At( *a_DataArray, offset );
			}

			offset += sizeof( u4 );
		}
		break;

	case MARSHALLER_TYPE_REF_U8:
	case MARSHALLER_TYPE_REF_S8:
		{
			u8* val = va_arg( *a_MarkerPtr, u8* );

			if ( !val ) {
			
				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {
			
				*a_DataArray += *val;
			
			} else {

				*val = ComReadU8At( *a_DataArray, offset );
			}

			offset += sizeof( u8 );
		}
		break;

	case MARSHALLER_TYPE_REF_STRING:
		{
			std::string** val = va_arg( *a_MarkerPtr, std::string** );

			if ( !val ) {

				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {
			
				offset += sizeof(u2);
				
				if( *val ) {

					offset += ComputeUTF8Length((char*)((*val)->c_str()));
				}

				(*a_DataArray).Append(*val);

			} else {
				
				u2 len = ComReadU2At(*a_DataArray, offset);
				
				offset += sizeof(u2);
				
				if (len == 0xFFFF) {
				
					*val = NULL;
				
				} else {
					// store result
					u2 l = ComputeLPSTRLength(*a_DataArray, offset, len);
				
					char* chstr = new char[l + 1];
					
					try {
					
						chstr[l] = '\0';
						
						UTF8Decode(*a_DataArray, offset, len, chstr);
						
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
			u1Array** val = va_arg(*a_MarkerPtr, u1Array**);

			if ( !val ) {
			
				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {

				offset += sizeof(u4);
				
				if( !(*val)->IsNull( ) ) {
					
					u4  valLen = (*val)->GetLength();
					
					u1* valBuf = (*val)->GetBuffer();
					
					*a_DataArray += valLen;
					
					for(u4 v = 0; v < valLen; v++) {
					
						*a_DataArray += valBuf[v];
					}

					offset += (sizeof(u1) * valLen);
				
				} else {
				
					*a_DataArray += 0xFFFFFFFF;
				}
			} else {

				u4 len = ComReadU4At(*a_DataArray, offset);

				offset += sizeof(u4);

				u1Array* refArray = NULL;

				try {

					if (len == 0xFFFFFFFF) {
					
						refArray = new u1Array();
					
					} else {
					
						refArray = new u1Array(len);
						
						for (u4 i = 0; i < len; i++) {
						
							refArray->SetU1At(i, a_DataArray->ReadU1At(offset));
							
							offset += sizeof(u1);
						}
					}
				} catch (...) {

					if ( refArray ) {
					
						delete refArray;
					}

					throw;
				}

				if( *val ) {
					
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
			u2Array** val = va_arg(*a_MarkerPtr, u2Array**);

			if ( !val ) {
			
				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {
				
				offset += sizeof(u4);
				
				if( !(*val)->IsNull( ) ) {

					u4  valLen = (*val)->GetLength();
					
					u2* valBuf = (*val)->GetBuffer();
					
					*a_DataArray += valLen;
					
					for(u4 v = 0; v < valLen; v++) {
					
						*a_DataArray += valBuf[v];
					}

					offset += (sizeof(u2) * valLen);
				
				} else {
				
					*a_DataArray += 0xFFFFFFFF;
				}
			} else {

				u4 len = ComReadU4At(*a_DataArray, offset);
				
				offset += sizeof(u4);

				u2Array* refArray = NULL;

				try {
				
					if (len == 0xFFFFFFFF) {
					
						refArray = new u2Array(-1);
			
					} else {
					
						refArray = new u2Array(len);
						
						for (u4 i = 0; i < len; i++) {
						
							refArray->SetU2At(i, ComReadU2At(*a_DataArray, offset));
							
							offset += sizeof(u2);
						}
					}
				} catch (...) {
					
					if ( refArray ) {
					
						delete refArray;
					}

					throw;
				}

				if( *val ) {
					
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
			u4Array** val = va_arg(*a_MarkerPtr, u4Array**);

			if ( !val ) {
			
				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {
				
				offset += sizeof(u4);
				
				if( !(*val)->IsNull( ) ) {

					u4  valLen = (*val)->GetLength();
					
					u4* valBuf = (*val)->GetBuffer();
					
					*a_DataArray += valLen;
					
					for(u4 v = 0; v < valLen; v++) {
					
						*a_DataArray += valBuf[v];
					}

					offset += (sizeof(u4) * valLen);
				
				} else {
				
					*a_DataArray += 0xFFFFFFFF;
				}
			} else {

				u4 len = ComReadU4At(*a_DataArray, offset);
				
				offset += sizeof(u4);

				u4Array* refArray = NULL;

				try {
				
					if (len == 0xFFFFFFFF) {
					
						refArray = new u4Array(-1);
				
					} else {
					
						refArray = new u4Array(len);
						
						for (u4 i = 0; i < len; i++) {
						
							refArray->SetU4At(i, ComReadU4At(*a_DataArray, offset));
							
							offset += sizeof(u4);
						}
					}
				} catch (...) {
					
					if ( refArray ) {
					
						delete refArray;
					}

					throw;
				}

				if( *val ) {
					
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
			u8Array** val = va_arg(*a_MarkerPtr, u8Array**);
			if ( !val ) {
			
				throw NullReferenceException( (char*)"" );
			}

			if ( a_isIn ) {
				
				offset += sizeof(u4);
				
				if (!(*val)->IsNull() ) {
				
					u4  valLen = (*val)->GetLength();
					
					u8* valBuf = (*val)->GetBuffer();
					
					*a_DataArray += valLen;
					
					for(u4 v = 0; v < valLen; v++) {
					
						*a_DataArray += valBuf[v];
					}

					offset += (sizeof(u8) * valLen);
			
				} else {
				
					*a_DataArray += 0xFFFFFFFF;
				}
			} else {

				u4 len = ComReadU4At(*a_DataArray, offset);
				
				offset += sizeof(u4);

				u8Array* refArray = NULL;

				try {
				
					if (len == 0xFFFFFFFF) {
					
						refArray = new u8Array(-1);
				
					} else {
					
						refArray = new u8Array(len);
						
						for (u4 i = 0; i < len; i++) {
						
							refArray->SetU8At(i, ComReadU8At(*a_DataArray, offset));
							
							offset += sizeof(u4);
						}
					}
				} catch (...) {
					
					if ( refArray ) {
					
						delete refArray;
					}

					throw;
				}

				if( *val ) {
					
					// perform cleanup
					delete *val;
				}

				*val = refArray;
			}
		}
		break;

	default:
		{
			if ( a_isIn ) {
				
				throw Exception("Un-recognized input argument type");
			
			} else {
			
				throw Exception("Un-recognized byref argument type");
			}
		}
		break;
	}

	*a_OffsetPtr = offset;
}


/*
*/
void MarshallerUtil::ProcessOutputArguments( const u1& a_Type, u1Array* a_AnswerPtr, u4* a_OffsetPtr, va_list* a_MarkerPtr ) {

	switch( a_Type ) {

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
			va_arg( *a_MarkerPtr, u4 );
		}
		break;

	case MARSHALLER_TYPE_IN_S8:
	case MARSHALLER_TYPE_IN_U8:
		{
			// ignore input argument (slot size = 8 bytes)
			va_arg( *a_MarkerPtr, u8 );
		}
		break;

	default:
		ProcessByReferenceArguments( a_Type, a_AnswerPtr, a_OffsetPtr, a_MarkerPtr, false );
		break;
	}
}


/*
*/
u4 MarshallerUtil::ProcessReturnType( const u1& a_Type, u1Array* a_AnswerPtr, va_list* a_MarkerPtr ) {

	u1Array answer = *a_AnswerPtr;

	u4 offset = 0;

	switch( a_Type ) {

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
			u1* valToReturn = va_arg(*a_MarkerPtr, u1*);
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
			s1* valToReturn = va_arg(*a_MarkerPtr, s1*);
			*valToReturn = answer.ReadU1At(offset);
			offset += sizeof(u1);
		}
		break;

	case MARSHALLER_TYPE_RET_U1:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_BYTE);
			u1* valToReturn = va_arg(*a_MarkerPtr, u1*);
			*valToReturn = answer.ReadU1At(offset);
			offset += sizeof(u1);
		}
		break;

	case MARSHALLER_TYPE_RET_CHAR:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_CHAR);
			char* valToReturn = va_arg(*a_MarkerPtr, char*);
			*valToReturn = (char)ComReadU2At(answer, offset);
			offset += sizeof(u2);
		}
		break;

	case MARSHALLER_TYPE_RET_S2:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT16);
			s2* valToReturn = va_arg(*a_MarkerPtr, s2*);
			*valToReturn = ComReadU2At(answer, offset);
			offset += sizeof(u2);
		}
		break;

	case MARSHALLER_TYPE_RET_U2:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT16);
			u2* valToReturn = va_arg(*a_MarkerPtr, u2*);
			*valToReturn = ComReadU2At(answer, offset);
			offset += sizeof(u2);
		}
		break;

	case MARSHALLER_TYPE_RET_S4:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT32);
			s4* valToReturn = va_arg(*a_MarkerPtr, s4*);
			*valToReturn = ComReadU4At(answer, offset);
			offset += sizeof(u4);
		}
		break;

	case MARSHALLER_TYPE_RET_U4:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT32);
			u4* valToReturn = va_arg(*a_MarkerPtr, u4*);
			*valToReturn = ComReadU4At(answer, offset);
			offset += sizeof(u4);
		}
		break;

	case MARSHALLER_TYPE_RET_S8:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_INT64);
			s8* valToReturn = va_arg(*a_MarkerPtr, s8*);
			*valToReturn = ComReadU8At(answer, offset);
			offset += sizeof(u8);
		}
		break;

	case MARSHALLER_TYPE_RET_U8:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_UINT64);
			u8* valToReturn = va_arg(*a_MarkerPtr, u8*);
			*valToReturn = ComReadU8At(answer, offset);
			offset += sizeof(u8);
		}
		break;

	case MARSHALLER_TYPE_RET_STRING:
		{
			offset += CheckForException(answer, HIVECODE_NAMESPACE_SYSTEM, HIVECODE_TYPE_SYSTEM_STRING);
			std::string** valToReturn = va_arg(*a_MarkerPtr, std::string**);
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
			u1Array** valToReturn = va_arg(*a_MarkerPtr, u1Array**);
			u4 len = ComReadU4At(answer, offset);
			offset += sizeof(u4);
			if (len == 0xFFFFFFFF) {
				*valToReturn = new u1Array();
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
			s1Array** valToReturn = va_arg(*a_MarkerPtr, s1Array**);
			u4 len = ComReadU4At(answer, offset);
			offset += sizeof(u4);
			if (len == 0xFFFFFFFF) {
				*valToReturn = new s1Array();
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

			u1Array** valToReturn = va_arg(*a_MarkerPtr, u1Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new u1Array();
			
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

			charArray** valToReturn = va_arg(*a_MarkerPtr, charArray**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new charArray(-1);
		
			} else {
			
				// store result
				*valToReturn = new charArray(len);
				
				try {
				
					u2* p = (*valToReturn)->GetBuffer( );

					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU2At(answer, offset);
						
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

			s2Array** valToReturn = va_arg(*a_MarkerPtr, s2Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new s2Array(-1);
			
			} else {
			
				// store result
				*valToReturn = new s2Array(len);
				
				try {
				
					u2* p = (*valToReturn)->GetBuffer();

					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU2At(answer, offset);
						
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

			u2Array** valToReturn = va_arg(*a_MarkerPtr, u2Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new u2Array(-1);
			
			} else {
			
				// store result
				*valToReturn = new u2Array(len);
				
				try {
				
					u2* p = (*valToReturn)->GetBuffer( );

					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU2At(answer, offset);
						
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

			s4Array** valToReturn = va_arg(*a_MarkerPtr, s4Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new s4Array(-1);
			
			} else {
			
				// store result
				*valToReturn = new s4Array(len);
				
				try {
				
					u4* p = (*valToReturn)->GetBuffer( );

					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU4At(answer, offset);
						
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

			u4Array** valToReturn = va_arg(*a_MarkerPtr, u4Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new u4Array(-1);
			
			} else {
				
				// store result
				*valToReturn = new u4Array(len);
				
				u4* p = (*valToReturn)->GetBuffer( );

				try {
				
					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU4At(answer, offset);
						
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
			
			s8Array** valToReturn = va_arg(*a_MarkerPtr, s8Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new s8Array(-1);
			
			} else {
			
				// store result
				*valToReturn = new s8Array(len);
				
				try {
				
					u8* p = (*valToReturn)->GetBuffer( );
					for (u4 j = 0; j < len; j++) {

						p[j] = ComReadU8At(answer, offset);

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

			u8Array** valToReturn = va_arg(*a_MarkerPtr, u8Array**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new u8Array(-1);
			
			} else {
			
				// store result
				*valToReturn = new u8Array(len);
				
				try {
				
					u8* p = (*valToReturn)->GetBuffer( );

					for (u4 j = 0; j < len; j++) {
					
						p[j] = ComReadU8At(answer, offset);
						
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

			StringArray** valToReturn = va_arg(*a_MarkerPtr, StringArray**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new StringArray();
			
			} else {
			
				// store result
				*valToReturn = new StringArray(len);
				
				try {

					u2 lenStr = 0;
					u2 blen = 0;
					char* lpstr = 0;
					for( u4 j = 0 ; j < len ; ++j ) {
					
						lenStr = ComReadU2At( answer, offset );
						
						offset += sizeof( u2 );
						
						if (lenStr != 0xFFFF) {
						
							blen = ComputeLPSTRLength( answer, offset, lenStr );
							
							lpstr = new char[blen + 1];
							
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

			MemoryStream** valToReturn = va_arg(*a_MarkerPtr, MemoryStream**);
			
			u4 len = ComReadU4At(answer, offset);
			
			offset += sizeof(u4);
			
			if (len == 0xFFFFFFFF) {
			
				*valToReturn = new MemoryStream();
			
			} else {
			
				// store result
				*valToReturn = new MemoryStream(answer, offset, len);
				
				offset += len;
			}
		}
		break;

	default:
		throw Exception("Un-recognized return type");
	}

	return offset;
}


/*
*/
void MarshallerUtil::ProcessInputArguments( const u1& a_Type, u1Array* a_InvokeAPDU_data, va_list* a_MarkerPtr ) {

	switch( a_Type ) {

	case MARSHALLER_TYPE_IN_BOOL:
	case MARSHALLER_TYPE_IN_S1:
	case MARSHALLER_TYPE_IN_U1:
		{
			u1 val = (u1)va_arg(*a_MarkerPtr, s4);

			*a_InvokeAPDU_data += val;
		}
		break;

	case MARSHALLER_TYPE_IN_CHAR:
	case MARSHALLER_TYPE_IN_S2:
	case MARSHALLER_TYPE_IN_U2:
		{
			u2 val = (u2)va_arg(*a_MarkerPtr, s4);

			*a_InvokeAPDU_data += val;
		}
		break;

	case MARSHALLER_TYPE_IN_S4:
	case MARSHALLER_TYPE_IN_U4:
		{
			u4 val = (u4)va_arg(*a_MarkerPtr, s4);

			*a_InvokeAPDU_data += val;
		}
		break;

	case MARSHALLER_TYPE_IN_S8:
	case MARSHALLER_TYPE_IN_U8:
		{
			u8 val = (u8)va_arg(*a_MarkerPtr,u8);

			*a_InvokeAPDU_data += val;
		}
		break;

	case MARSHALLER_TYPE_IN_STRING:
		{
			char * val = va_arg(*a_MarkerPtr, char*);
            
			(*a_InvokeAPDU_data).Append(val);
		}
		break;

	case MARSHALLER_TYPE_IN_MEMORYSTREAM:
	case MARSHALLER_TYPE_IN_BOOLARRAY:
	case MARSHALLER_TYPE_IN_S1ARRAY:
	case MARSHALLER_TYPE_IN_U1ARRAY:
		{
			u1Array* val = va_arg(*a_MarkerPtr, u1Array*);

			if( val && !val->IsNull( ) ) {
			
				u4  valLen = val->GetLength( );
				
				u1* valBuf = val->GetBuffer( );
				
				// add length
				*a_InvokeAPDU_data += valLen;
				
				// add data
				for( u4 v = 0; v < valLen ; ++v ) {
				
					*a_InvokeAPDU_data += valBuf[v];
				}

			} else {
			
				// add null pointer
				*a_InvokeAPDU_data += (u4)0xFFFFFFFF;
			}
		}
		break;

	case MARSHALLER_TYPE_IN_CHARARRAY:
	case MARSHALLER_TYPE_IN_S2ARRAY:
	case MARSHALLER_TYPE_IN_U2ARRAY:
		{
			u2Array* val = va_arg(*a_MarkerPtr, u2Array*);

			if( val && !val->IsNull( ) ) {
			
				u4  valLen = val->GetLength();
				
				u2* valBuf = val->GetBuffer();
				
				*a_InvokeAPDU_data += valLen;
				
				for( u4 v = 0 ; v < valLen ; ++v ) {

					*a_InvokeAPDU_data += valBuf[v];
				}

			} else {
				
				// add null pointer
				*a_InvokeAPDU_data += (u4)0xFFFFFFFF;
			}
		}
		break;

	case MARSHALLER_TYPE_IN_S4ARRAY:
	case MARSHALLER_TYPE_IN_U4ARRAY:
		{
			u4Array* val = va_arg(*a_MarkerPtr, u4Array*);

			if( val && !val->IsNull( ) ) {
			
				u4  valLen = val->GetLength();
				
				u4* valBuf = val->GetBuffer();

				*a_InvokeAPDU_data += valLen;

				for( u4 v = 0 ; v < valLen ; ++v ) {

					*a_InvokeAPDU_data += valBuf[v];
				}

			} else {

				// add null pointer
				*a_InvokeAPDU_data += (u4)0xFFFFFFFF;
			}
		}
		break;

	case MARSHALLER_TYPE_IN_S8ARRAY:
	case MARSHALLER_TYPE_IN_U8ARRAY:
		{
			u8Array* val = va_arg(*a_MarkerPtr, u8Array*);
			
			if( val && !val->IsNull( ) ) {
			
				u4  valLen = val->GetLength();
				
				u8* valBuf = val->GetBuffer();
				
				*a_InvokeAPDU_data += valLen;
				
				for( u4 v = 0 ; v < valLen ; ++v ) {

					*a_InvokeAPDU_data += valBuf[v];
				}

			} else {
				
				// add null pointer
				*a_InvokeAPDU_data += (u4)0xFFFFFFFF;
			}
		}
		break;

	case MARSHALLER_TYPE_IN_STRINGARRAY:
		{
			StringArray* val = va_arg(*a_MarkerPtr, StringArray*);

			if( val && !val->IsNull( ) ) {

				u4  valLen = val->GetLength();

				*a_InvokeAPDU_data += valLen;

				// add data
				for( u4 j = 0 ; j < valLen ; ++j ) {

					std::string* str = val->GetStringAt(j);

					if( str ){

						(*a_InvokeAPDU_data).Append(str);
					
					}else{ 
						// add null pointer
						*a_InvokeAPDU_data += (u2)0xFFFF;
					}
				}

			} else {
				
				// add null pointer
				*a_InvokeAPDU_data += (u4)0xFFFFFFFF;
			}
		}
		break;

	default:
		u4 offset = 0;

		ProcessByReferenceArguments( a_Type, a_InvokeAPDU_data, &offset, a_MarkerPtr, true );
		
		// do not adjust a_MarkerPtr.
		return;

	}
}


MARSHALLER_NS_END
