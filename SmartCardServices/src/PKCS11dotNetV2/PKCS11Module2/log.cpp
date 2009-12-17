
/* ---------------- Gemalto Debug -------------- */


#include <string.h>
#include "log.h"


// Define to unable if you want to activate trace into the code or at compilation time
//#define __DEBUG_GEMALTO__

#ifdef WIN32
#include <windows.h>
#define LOG_FILE_NAME "c:\\Gemalto.NET.PKCS11.log"
#else
#define LOG_FILE_NAME "/tmp/Gemalto.NET.PKCS11.log"
#endif


#define T_BOOL 0
#define T_BYTES 1
#define T_LONG 2
#define T_KEY_TYPE 3
#define T_CERTIFICATE_TYPE 4
#define T_CLASS 5
#define T_DATE 6
#define T_KEY_GEN_MECHANISM 7
#define T_UNKNOWN 8


/* Log a message into the log file
*/
void Log::log( const char * format, ... )
{
#ifdef __DEBUG_GEMALTO__
   // Try to open the file
   FILE* pLog = fopen( LOG_FILE_NAME, "a" );
   if( NULL == pLog )
   {
      // The file does not exit. Nothing to log
      return;
   }

   // Write the message to the log file
   va_list args;
   va_start( args, format );
   vfprintf( pLog, format, args );
   va_end( args );
   fprintf(pLog, "\n");

#ifndef WIN32
   // Write the message to stderr stream
   va_start( args, format );
	vfprintf( stderr, format, args );
   va_end( args );
	fprintf( stderr, "\n");
#else
   // Get the size of the buffer necessary to write the message
   // The size must be extended to include the '\n' and the '\0' characters.
   va_start( args, format );
   size_t len = _vscprintf( format, args );
   va_end( args );

   // Allocate the buffer for the message
   char *buffer = new char[ len + 2 ];
   memset( buffer, '\0', len + 2 );

   // Write the message into the buffer.
   va_start( args, format );
   vsprintf_s( buffer, len + 1, format, args );
   va_end( args );
   buffer[ len ] = '\n';

   // Write the message to the console
   OutputDebugString( buffer );

   // Release the buffer
   delete[] buffer;
#endif

   va_end( args );

   // Close the file
   fclose( pLog );
#endif
}

/*

#ifdef __DEBUG_GEMALTO__
void Log::log( const char * format, ... )
{
   // Try to open the file
   FILE* pLog = fopen( LOG_FILE_NAME, "a" );
   if( NULL == pLog )
   {
      // The file does not exit. Nothing to log
      return;
   }

   // Get the size of the buffer necessary to write the message
   // The size must be extended to include the '\n' and the '\0' characters.
   va_list args;
   va_start( args, format );
#ifdef WIN32
   size_t len = _vscprintf( format, args );
#else
   char tmp[1];
   int len = vsnprintf( tmp, sizeof(tmp), format, args );
#endif
   va_end( args );

   // Allocate the buffer for the message
   char *buffer = new char[ len + 2 ];
   memset( buffer, '\0', len + 2 );

   // Write the message into the buffer.
   va_start( args, format );
#ifdef WIN32
   vsprintf_s( buffer, len + 1, format, args );
#else
   vsprintf( buffer, format, args );
#endif
   va_end( args );
   buffer[ len ] = '\n';

   // Write the message to the console
#ifdef WIN32
   OutputDebugString( buffer );
#else
   printf( buffer );
#endif

   // Write the message to the log file
   fputs( buffer, pLog );
   fflush( pLog );

   // Close the file
   fclose( pLog );

   // Release the buffer
   delete[] buffer;
}
#else
void Log::log( const char*, ... )
{
}
#endif
*/



/*
*/
void Log::begin( const char* a_pMethod )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - <BEGIN>", a_pMethod );
#else
	(void)a_pMethod;
#endif
}


/*
*/
void Log::end( const char* a_pMethod )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - <END>", a_pMethod );
#endif
}


/*
*/
void Log::in( const char* a_pMethod )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - [IN]", a_pMethod );
#endif
}


/*
*/
void Log::out( const char* a_pMethod )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - [OUT]", a_pMethod );
#endif
}


/*
*/
void Log::error( const char* a_pMethod, const char* a_pError )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - ## Error ## %s", a_pMethod, a_pError );
#endif
}



void Log::logCK_UTF8CHAR_PTR( const char* a_pName, const unsigned char* a_pBuffer, const std::size_t& a_Size )
{
#ifdef __DEBUG_GEMALTO__
   std::string s = "";
   if( NULL_PTR != a_pBuffer )
   {
      toString( a_pBuffer, a_Size, s );
   }
   log( "%s - <%#02x> - size <%ld> - buffer <%s>", a_pName, a_pBuffer, a_Size, s.c_str( ) );
#endif
}


/*
*/
void Log::logCK_MECHANISM_INFO_PTR( const char* a_pMethod, CK_MECHANISM_INFO_PTR pInfo )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR != pInfo )
	{
	   std::string flags = "";
	   CK_FLAGS f = pInfo->flags;
	   mechanismFlagsToString( f, flags );

      log( "%s - CK_MECHANISM_INFO - ulMinKeySize <%#02x> - ulMaxKeySize <%#02x> - flags <%s>", a_pMethod, pInfo->ulMinKeySize, pInfo->ulMaxKeySize, flags.c_str( ) );
   }
   else
   {
      log( "%s - CK_MECHANISM_INFO - NULL_PTR", a_pMethod );
	}
#endif
}


/*
*/
void Log::logCK_INFO( const char* a_pMethod, const CK_INFO_PTR pInfo )
{
#ifdef __DEBUG_GEMALTO__
   if( NULL_PTR != pInfo )
   {
	   std::string s = "";
	   CK_INFOToString( pInfo, s );
      log( "%s - CK_INFO <%s>", a_pMethod, s.c_str( ) );
   }
   else
   {
      log( "%s - CK_INFO <NULL_PTR>", a_pMethod );
   }
#endif
}


void Log::logCK_RV( const char* a_pMethod, const CK_RV& rv )
{
#ifdef __DEBUG_GEMALTO__
   if( CKR_OK == rv )
   {
      log( "%s - [RV] <0x00> (CKR_OK)", a_pMethod );
   }
   else
  {
      std::string s = "";
      CK_RVToString( rv, s );
      log( "%s - [RV] <%#02x> (%s)", a_pMethod, rv, s.c_str( ) );
   }
#endif
}


void Log::logCK_C_INITIALIZE_ARGS_PTR( const char* a_pMethod, CK_C_INITIALIZE_ARGS_PTR a_pArgs )
{
#ifdef __DEBUG_GEMALTO__
   if( NULL_PTR != a_pArgs )
   {
		//log( a_pMethod, "pInitArgs->CreateMutex <%#02x>", a_pArgs.CreateMutex );
		log( "%s - CK_C_INITIALIZE_ARGS - DestroyMutex <%#02x> - LockMutex <%#02x> - UnlockMutex <%#02x> - flags <%#02x> - pReserved <%#02x>",
         a_pMethod, a_pArgs->DestroyMutex, a_pArgs->LockMutex, a_pArgs->UnlockMutex, a_pArgs->flags, a_pArgs->pReserved );
   }
   else
   {
		log( "%s - CK_C_INITIALIZE_ARGS - CreateMutex <NULL_PTR> - DestroyMutex <NULL_PTR> - LockMutex <NULL_PTR> - UnlockMutex <NULL_PTR> - flags <NULL_PTR> - pReserved <NULL_PTR>", a_pMethod );
   }
#endif
}


/*
*/
void Log::logCK_SLOT_ID_PTR( const char* a_pMethod, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount )
{
#ifdef __DEBUG_GEMALTO__
   if( NULL_PTR == pSlotList )
   {
      log( "%s - CK_SLOT_ID_PTR - pulCount <%#02x> (%ld) - pSlotList <NULL_PTR>", a_pMethod, pulCount, ( NULL_PTR != pulCount ) ? *pulCount : 0 );
   }
   else
   {
      std::string sList = "";
      if( NULL_PTR != pulCount )
      {
	      for( size_t i = 0 ; i < (size_t)*pulCount ; i++ )
	      {
		      std::string s = "";
		      toString( (unsigned long) pSlotList[ i ], s );
		      sList += s;
		      if( i != (size_t)( *pulCount - 1 ) )
		      {
			      sList += ", " ;
		      }
	      }
      }
      log( "%s - CK_SLOT_ID_PTR - pulCount <%#02x> (%ld) - pSlotList <%#02x> (%s)", a_pMethod, pulCount, ( NULL_PTR != pulCount ) ? *pulCount : 0, pSlotList, sList.c_str( ) );
   }
#endif
}


void Log::logCK_SLOT_INFO_PTR( const char* a_pMethod, CK_SLOT_INFO_PTR pInfo )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR != pInfo )
	{
	   std::string slotDescription = "";
	   toString( pInfo->slotDescription, 64, slotDescription );

	   std::string manufacturerID = "";
	   toString( pInfo->manufacturerID, 32, manufacturerID );

	   std::string flags = "";
	   CK_FLAGS f = pInfo->flags;
	   slotFlagsToString( f, flags );

	   std::string hardwareVersion = "";
	   CK_VERSIONToString( &(pInfo->hardwareVersion), hardwareVersion );

	   std::string firmwareVersion = "";
	   CK_VERSIONToString( &(pInfo->firmwareVersion), firmwareVersion );

      log( "%s - CK_SLOT_INFO_PTR - slotDescription <%s> - manufacturerID <%s> - flags <%s> - hardwareVersion <%s> - firmwareVersion <%s>",
		   a_pMethod, slotDescription.c_str( ), manufacturerID.c_str( ), flags.c_str( ), hardwareVersion.c_str( ), firmwareVersion.c_str( ) );
   }
   else
   {
      log( "%s - CK_SLOT_INFO_PTR - NULL_PTR", a_pMethod );
   }
#endif
}


void Log::logCK_TOKEN_INFO_PTR( const char* a_pMethod, CK_TOKEN_INFO_PTR pInfo )
{
#ifdef __DEBUG_GEMALTO__
   if( NULL_PTR != pInfo )
	{
	   std::string label = "";
	   toString( pInfo->label, 32, label );

	   std::string manufacturerID = "";
	   toString( pInfo->manufacturerID, 32, manufacturerID );

	   std::string model = "";
	   toString( pInfo->model, 16, model );

	   std::string serialNumber = "";
	   toString( pInfo->serialNumber, 16, serialNumber );

	   std::string hardwareVersion = "";
	   CK_VERSIONToString( &(pInfo->hardwareVersion), hardwareVersion );

	   std::string firmwareVersion = "";
	   CK_VERSIONToString( &(pInfo->firmwareVersion), firmwareVersion );

	   std::string utcTime = "";
	   toString( pInfo->utcTime, 16, utcTime );

	   log( "%s - CK_TOKEN_INFO_PTR - <%#02x> - label <%s> - manufacturerID <%s> - model <%s> - serialNumber <%s> - flags <%#02x> - ulMaxSessionCount <%#02x> - ulSessionCount <%#02x> - \
		   ulMaxRwSessionCount <%#02x> - ulRwSessionCount <%#02x> - ulMaxPinLen <%#02x> - ulMinPinLen <%#02x> - ulTotalPublicMemory <%#02x> - \
		   ulFreePublicMemory <%#02x> - ulTotalPrivateMemory <%#02x> - ulFreePrivateMemory <%#02x> - hardwareVersion <%s> - \
		   firmwareVersion <%s> - utcTime <%s>",
		   a_pMethod,
         pInfo,
         label.c_str( ),
		   manufacturerID.c_str( ),
		   model.c_str( ),
		   serialNumber.c_str( ),
		   pInfo->flags,
		   pInfo->ulMaxSessionCount,
		   pInfo->ulSessionCount,
		   pInfo->ulMaxRwSessionCount,
		   pInfo->ulRwSessionCount,
		   pInfo->ulMaxPinLen,
		   pInfo->ulMinPinLen,
		   pInfo->ulTotalPublicMemory,
		   pInfo->ulFreePublicMemory,
		   pInfo->ulTotalPrivateMemory,
		   pInfo->ulFreePrivateMemory,
		   hardwareVersion.c_str( ),
		   firmwareVersion.c_str( ),
		   utcTime.c_str( ) );
	}
   else
   {
      log( "%s - CK_TOKEN_INFO_PTR - <NULL_PTR>", a_pMethod );
   }
#endif
}


/*
*/
void Log::logCK_MECHANISM_TYPE( const char* a_pMethod, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount )
{
#ifdef __DEBUG_GEMALTO__
   std::string s = "";
   if( ( NULL_PTR != pMechanismList ) && ( NULL_PTR != pulCount ) )
   {
		CK_MECHANISM_TYPEToString( pMechanismList, *pulCount, s );
	}
   log( "%s - CK_MECHANISM_TYPE_PTR - pulCount <%#02x> (%ld) - pMechanismList <%#02x> (%s)", a_pMethod, pulCount, ( ( NULL_PTR != pulCount ) ? *pulCount : 0 ), pMechanismList, s.c_str( ) );
#endif
}


/*
*/
void Log::logCK_MECHANISM_TYPE( const char* a_pMethod, CK_MECHANISM_TYPE & ulMechanism )
{
#ifdef __DEBUG_GEMALTO__
   std::string s = "";
	CK_MECHANISM_TYPEToString( ulMechanism, s );
   log( "%s - CK_MECHANISM_TYPE <%s>", a_pMethod, s.c_str( ) );
#endif
}


/*
*/
void Log::logSessionFlags( const char* a_pMethod, CK_FLAGS & flags )
{
#ifdef __DEBUG_GEMALTO__
	std::string s = "";
	sessionFlagsToString( flags, s );
	log( "%s - CK_FLAGS <%s>", a_pMethod, s.c_str( ) );
#endif
}


/*
*/
void Log::logCK_SESSION_INFO_PTR( const char* a_pMethod, CK_SESSION_INFO_PTR pInfo )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR != pInfo )
   {
      std::string s = "";
	   CK_SESSION_INFOToString( pInfo, s );
	   log( "%s - CK_SESSION_INFO <%#02x> (%s)", a_pMethod, pInfo, s.c_str( ) );
   }
   else
	{
	   log( "%s - CK_SESSION_INFO <NULL_PTR>", a_pMethod );
	}
#endif
}


/*
*/
void Log::logCK_USER_TYPE( const char* a_pMethod, CK_USER_TYPE &userType )
{
#ifdef __DEBUG_GEMALTO__
	std::string s = "";
	CK_USER_TYPEToString( userType, s );
	log( "%s - CK_USER_TYPE <%s>", a_pMethod, s.c_str( ) );
#endif
}


/*
*/
void Log::logCK_MECHANISM_PTR( const char* a_pMethod, CK_MECHANISM_PTR pMechanism )
{
#ifdef __DEBUG_GEMALTO__
	std::string s = "";
   CK_MECHANISMToString( pMechanism, s );
	log( "%s - CK_MECHANISM_PTR <%s>", a_pMethod, s.c_str( ) );
#endif
}


/*
*/
void Log::logCK_ATTRIBUTE_PTR( const char* a_pMethod, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG& ulCount )
{
#ifdef __DEBUG_GEMALTO__
   log( "%s - pTemplate <%#02x> - ulCount <%ld>", a_pMethod, pTemplate, ulCount );
	if( NULL_PTR != pTemplate )
	{
	   for( size_t i = 0; i < (size_t)ulCount; i++ )
	   {
		   CK_ATTRIBUTE a = pTemplate[ i ];
		   std::string attribute = "";
		   CK_ATTRIBUTEToString( &a, attribute );

         log( "%s	- Attribute #%d - %s", a_pMethod, i, attribute.c_str( ) );
	   }
   }
#endif
}


/*
*/
void Log::CK_MECHANISMToString( CK_MECHANISM_PTR m, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == m )
	{
		return;
	}

	std::string mechanismType = "";
	CK_MECHANISM_TYPE t = m->mechanism;
	CK_MECHANISM_TYPEToString( t, mechanismType );

	std::string mechanismParam = "";
	toString( (const unsigned char*)m->pParameter, m->ulParameterLen, mechanismParam );

	toString( result,
		"Type <%s> - Parameter <%s> - ParameterLen <%#02x>",
		mechanismType.c_str( ),
		mechanismParam.c_str( ),
		m->ulParameterLen );
#endif
}


void Log::CK_ATTRIBUTEToString( const CK_ATTRIBUTE_PTR a, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == a )
	{
		return;
	}

	std::string t = "";
	int type = T_UNKNOWN;
	CK_ATTRIBUTE_TYPEToString( a->type, t, type );

	if( ( (CK_ULONG)(-1) ) == a->ulValueLen )
	{
		toString( result, "Type <%s> - Length <-1> - Value <UNKNOWN>", t.c_str( ) );
		return;
	}

	std::string v = "";
	if( NULL_PTR == a->pValue )
	{
		v = "null";
	}
	else
	{
		switch( type )
		{
		case T_BOOL:
			toString( ((bool*)a->pValue)[0], v );
			break;

		case T_BYTES:
			toString( (CK_BYTE_PTR) a->pValue, a->ulValueLen, v );
			break;

		case T_LONG:
			toString( ((CK_ULONG*)a->pValue)[0], v );
			break;

		case T_KEY_TYPE:
			CK_KEY_TYPEToString( ((CK_KEY_TYPE *)a->pValue)[0], v );
			break;

		case T_CERTIFICATE_TYPE:
			CK_CERTIFICATE_TYPEToString( ((CK_CERTIFICATE_TYPE *)a->pValue)[0], v );
			break;

		case T_CLASS:
			CK_OBJECT_CLASSToString( ((CK_OBJECT_CLASS *)a->pValue)[0], v );
			break;

		case T_DATE:
			CK_DATEToString( (CK_DATE*) a->pValue, v );
			break;

		case T_KEY_GEN_MECHANISM:
			CK_MECHANISM_TYPEToString( ((CK_MECHANISM_TYPE *)a->pValue)[0], v );
			break;

		default:
			v = "UNPREDICTABLE VALUE";
		}
	}

	toString( result, "Type <%s> - Length <%#02x> - Value <%s>", t.c_str( ), a->ulValueLen, v.c_str( ) );
#endif
}


/*
*/
void Log::CK_ATTRIBUTE_TYPEToString( const CK_ATTRIBUTE_TYPE& a, std::string &t, int& type )
{
#ifdef __DEBUG_GEMALTO__
	switch( a )
	{
	case CKA_CLASS:
		t = "CKA_CLASS";
		type = T_CLASS;
		break;

	case CKA_TOKEN:
		t = "CKA_TOKEN";
		type = T_BOOL;
		break;

	case CKA_PRIVATE:
		t = "CKA_PRIVATE";
		type = T_BOOL;
		break;

	case CKA_LABEL:
		t = "CKA_LABEL";
		type = T_BYTES;
		break;

	case CKA_APPLICATION:
		t = "CKA_APPLICATION";
		type = T_BYTES;
		break;

	case CKA_VALUE:
		t = "CKA_VALUE";
		type = T_BYTES;
		break;

	case CKA_CERTIFICATE_TYPE:
		t = "CKA_CERTIFICATE_TYPE";
		type = T_CERTIFICATE_TYPE;
		break;

	case CKA_ISSUER:
		t = "CKA_ISSUER";
		type = T_BYTES;
		break;

	case CKA_SERIAL_NUMBER:
		t = "CKA_SERIAL_NUMBER";
		type = T_BYTES;
		break;

	case CKA_KEY_TYPE:
		t = "CKA_KEY_TYPE";
		type = T_KEY_TYPE;
		break;

	case CKA_SUBJECT:
		t = "CKA_SUBJECT";
		type = T_BYTES;
		break;

	case CKA_ID:
		t = "CKA_ID";
		type = T_BYTES;
		break;

	case CKA_SENSITIVE:
		t = "CKA_SENSITIVE";
		type = T_BOOL;
		break;

	case CKA_ENCRYPT:
		t = "CKA_ENCRYPT";
		type = T_BOOL;
		break;

	case CKA_DECRYPT:
		t = "CKA_DECRYPT";
		type = T_BOOL;
		break;

	case CKA_WRAP:
		t = "CKA_WRAP";
		type = T_BOOL;
		break;

	case CKA_UNWRAP:
		t = "CKA_UNWRAP";
		type = T_BOOL;
		break;

	case CKA_SIGN:
		t = "CKA_SIGN";
		type = T_BOOL;
		break;

	case CKA_SIGN_RECOVER:
		t = "CKA_SIGN_RECOVER";
		type = T_BOOL;
		break;

	case CKA_VERIFY:
		t = "CKA_VERIFY";
		type = T_BOOL;
		break;

	case CKA_VERIFY_RECOVER:
		t = "CKA_VERIFY_RECOVER";
		type = T_BOOL;
		break;

	case CKA_DERIVE:
		t = "CKA_DERIVE";
		type = T_BOOL;
		break;

	case CKA_START_DATE:
		t = "CKA_START_DATE";
		type = T_DATE;
		break;

	case CKA_END_DATE:
		t = "CKA_END_DATE";
		type = T_DATE;
		break;

	case CKA_MODULUS:
		t = "CKA_MODULUS";
		type = T_BYTES;
		break;

	case CKA_MODULUS_BITS:
		t = "CKA_MODULUS_BITS";
		type = T_LONG;
		break;

	case CKA_PUBLIC_EXPONENT:
		t = "CKA_PUBLIC_EXPONENT";
		type = T_BYTES;
		break;

	case CKA_PRIVATE_EXPONENT:
		t = "CKA_PRIVATE_EXPONENT";
		type = T_BYTES;
		break;

	case CKA_PRIME_1:
		t = "CKA_PRIME_1";
		type = T_BYTES;
		break;

	case CKA_PRIME_2:
		t = "CKA_PRIME_2";
		type = T_BYTES;
		break;

	case CKA_EXPONENT_1:
		t = "CKA_EXPONENT_1";
		type = T_BYTES;
		break;

	case CKA_EXPONENT_2:
		t = "CKA_EXPONENT_2";
		type = T_BYTES;
		break;

	case CKA_COEFFICIENT:
		t = "CKA_COEFFICIENT";
		type = T_BYTES;
		break;

	case CKA_PRIME:
		t = "CKA_PRIME";
		type = T_BYTES;
		break;

	case CKA_SUBPRIME:
		t = "CKA_SUBPRIME";
		type = T_BYTES;
		break;

	case CKA_BASE:
		t = "CKA_BASE";
		type = T_BYTES;
		break;

	case CKA_VALUE_BITS:
		t = "CKA_VALUE_BITS";
		type = T_BYTES;
		break;

	case CKA_VALUE_LEN:
		t = "CKA_VALUE_LEN";
		type = T_LONG;
		break;

	case CKA_EXTRACTABLE:
		t = "CKA_EXTRACTABLE";
		type = T_BOOL;
		break;

	case CKA_LOCAL:
		t = "CKA_LOCAL";
		type = T_BOOL;
		break;

	case CKA_NEVER_EXTRACTABLE:
		t = "CKA_NEVER_EXTRACTABLE";
		type = T_BOOL;
		break;

	case CKA_ALWAYS_SENSITIVE:
		t = "CKA_ALWAYS_SENSITIVE";
		type = T_BOOL;
		break;

	case CKA_MODIFIABLE:
		t = "CKA_MODIFIABLE";
		type = T_BOOL;
		break;

	case CKA_ECDSA_PARAMS:
		t = "CKA_ECDSA_PARAMS";
		type = T_BYTES;
		break;

	case CKA_EC_POINT:
		t = "CKA_EC_POINT";
		type = T_BYTES;
		break;

	case CKA_VENDOR_DEFINED:
		t = "CKA_VENDOR_DEFINED";
		type = T_BYTES;
		break;

		//case CKA_KEY_GEN_MECHANISM:
		//	t = "CKA_KEY_GEN_MECHANISM";
		//	type = T_KEY_GEN_MECHANISM;
		//	break;

	default:
		toString( t, "UNKNOWN TYPE <%#02x>", a );
		type = T_UNKNOWN;
	}
#endif
}


/*
*/
void Log::CK_DATEToString( const CK_DATE* t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == t )
	{
		return;
	}

	std::string year = "";
	toString( t->year, 4, year );

	std::string month = "";
	toString( t->month, 2, month );

	std::string day = "";
	toString( t->day, 2, day );

	result = "Year <" + year + "> - Month <" + month + "> - Day <" + day + ">";
#endif
}


/*
*/
void Log::CK_OBJECT_CLASSToString( const CK_OBJECT_CLASS& t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( t )
	{
	case CKO_DATA:
		result = "CKO_DATA";
		break;

	case CKO_CERTIFICATE:
		result = "CKO_CERTIFICATE";
		break;

	case CKO_PUBLIC_KEY:
		result = "CKO_PUBLIC_KEY";
		break;

	case CKO_PRIVATE_KEY:
		result = "CKO_PRIVATE_KEY";
		break;

	case CKO_SECRET_KEY:
		result = "CKO_SECRET_KEY";
		break;

	case CKO_VENDOR_DEFINED:
		result = "CKO_VENDOR_DEFINED";
		break;

	default:
		toString( result, "UNKNOWN OBJECT CLASS <%#02x>", t );
	}
#endif
}


/*
*/
void Log::CK_KEY_TYPEToString( const CK_KEY_TYPE& t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( t )
	{
	case CKK_RSA:
		result = "CKK_RSA";
		break;

	case CKK_DSA:
		result = "CKK_DSA";
		break;

	case CKK_ECDSA:
		result = "CKK_ECDSA";
		break;

	case CKK_DH:
		result = "CKK_DH";
		break;

	case CKK_KEA:
		result = "CKK_KEA";
		break;

	case CKK_GENERIC_SECRET:
		result = "CKK_GENERIC_SECRET";
		break;

	case CKK_RC2:
		result = "CKK_RC2";
		break;

	case CKK_RC4:
		result = "CKK_RC4";
		break;

	case CKK_DES:
		result = "CKK_DES";
		break;

	case CKK_DES2:
		result = "CKK_DES2";
		break;

	case CKK_DES3:
		result = "CKK_DES3";
		break;

	case CKK_CAST:
		result = "CKK_CAST";
		break;

	case CKK_CAST3:
		result = "CKK_CAST3";
		break;

	case CKK_CAST5:
		result = "CKK_CAST5/128";
		break;

	case CKK_RC5:
		result = "CKK_RC5";
		break;

	case CKK_IDEA:
		result = "CKK_IDEA";
		break;

	case CKK_SKIPJACK:
		result = "CKK_SKIPJACK";
		break;

	case CKK_BATON:
		result = "CKK_BATON";
		break;

	case CKK_JUNIPER:
		result = "CKK_JUNIPER";
		break;

	case CKK_CDMF:
		result = "CKK_CDMF";
		break;

	case CKK_VENDOR_DEFINED:
		result = "CKK_VENDOR_DEFINED";
		break;

	default:
		toString( result, "UNKNOWN KEY TYPE <%#02x>", t );
	}
#endif
}


/*
*/
void Log::CK_CERTIFICATE_TYPEToString( const CK_CERTIFICATE_TYPE &t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( t )
	{
	case CKC_X_509:
		result = "CKC_X_509";
		break;

	case CKC_VENDOR_DEFINED:
		result = "CKC_VENDOR_DEFINED";
		break;

	default:
		toString( result, "UNKNOWN CERTIFICATE TYPE <%#02x>", t );
	}
#endif
}


/*
*/
void Log::CK_INFOToString( CK_INFO_PTR pInfo, std::string& result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == pInfo )
	{
		return;
	}

	std::string cryptokiVersion = "";
	CK_VERSIONToString( &(pInfo->cryptokiVersion), cryptokiVersion );

	std::string manufacturerID = "";
	toString( pInfo->manufacturerID, 32, manufacturerID );

	std::string flags = "";
	CK_FLAGS f = pInfo->flags;
	toString( f, flags );

	std::string libraryDescription = "";
	toString( pInfo->libraryDescription, 32, libraryDescription );

	std::string libraryVersion = "";
	CK_VERSIONToString( &(pInfo->libraryVersion), libraryVersion );

	result = "cryptokiVersion <" + cryptokiVersion
		+ "> - manufacturerID <" + manufacturerID
		+ "> - flags <" + flags
		+ "> - libraryDescription <" + libraryDescription
		+ "> - libraryVersion <" + libraryVersion
		+ ">";
#endif
}


/*
*/
void Log::CK_RVToString( const CK_RV& rv, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( rv )
	{
	case CKR_OK:
		result = "CKR_OK";
		break;
	case CKR_CANCEL:
		result = "CKR_CANCEL";
		break;
	case CKR_HOST_MEMORY:
		result = "CKR_HOST_MEMORY";
		break;
	case CKR_SLOT_ID_INVALID:
		result = "CKR_SLOT_ID_INVALID";
		break;
	case CKR_GENERAL_ERROR:
		result = "CKR_GENERAL_ERROR";
		break;
	case CKR_FUNCTION_FAILED:
		result = "CKR_FUNCTION_FAILED";
		break;
	case CKR_ARGUMENTS_BAD:
		result = "CKR_ARGUMENTS_BAD";
		break;
	case CKR_NO_EVENT:
		result = "CKR_NO_EVENT";
		break;
	case CKR_NEED_TO_CREATE_THREADS:
		result = "CKR_NEED_TO_CREATE_THREADS";
		break;
	case CKR_CANT_LOCK:
		result = "CKR_CANT_LOCK";
		break;
	case CKR_ATTRIBUTE_READ_ONLY:
		result = "CKR_ATTRIBUTE_READ_ONLY";
		break;
	case CKR_ATTRIBUTE_SENSITIVE:
		result = "CKR_ATTRIBUTE_SENSITIVE";
		break;
	case CKR_ATTRIBUTE_TYPE_INVALID:
		result = "CKR_ATTRIBUTE_TYPE_INVALID";
		break;
	case CKR_ATTRIBUTE_VALUE_INVALID:
		result = "CKR_ATTRIBUTE_VALUE_INVALID";
		break;
	case CKR_DATA_INVALID:
		result = "CKR_DATA_INVALID";
		break;
	case CKR_DATA_LEN_RANGE:
		result = "CKR_DATA_LEN_RANGE";
		break;
	case CKR_DEVICE_ERROR:
		result = "CKR_DEVICE_ERROR";
		break;
	case CKR_DEVICE_MEMORY:
		result = "CKR_DEVICE_MEMORY";
		break;
	case CKR_DEVICE_REMOVED:
		result = "CKR_DEVICE_REMOVED";
		break;
	case CKR_ENCRYPTED_DATA_INVALID:
		result = "CKR_ENCRYPTED_DATA_INVALID";
		break;
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		result = "CKR_ENCRYPTED_DATA_LEN_RANGE";
		break;
	case CKR_FUNCTION_CANCELED:
		result = "CKR_FUNCTION_CANCELED";
		break;
	case CKR_FUNCTION_NOT_PARALLEL:
		result = "CKR_FUNCTION_NOT_PARALLEL";
		break;
	case CKR_FUNCTION_NOT_SUPPORTED:
		result = "CKR_FUNCTION_NOT_SUPPORTED";
		break;
	case CKR_KEY_HANDLE_INVALID:
		result = "CKR_KEY_HANDLE_INVALID";
		break;
	case CKR_KEY_SIZE_RANGE:
		result = "CKR_KEY_SIZE_RANGE";
		break;
	case CKR_KEY_TYPE_INCONSISTENT:
		result = "CKR_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_KEY_NOT_NEEDED:
		result = "CKR_KEY_NOT_NEEDED";
		break;
	case CKR_KEY_CHANGED:
		result = "CKR_KEY_CHANGED";
		break;
	case CKR_KEY_NEEDED:
		result = "CKR_KEY_NEEDED";
		break;
	case CKR_KEY_INDIGESTIBLE:
		result = "CKR_KEY_INDIGESTIBLE";
		break;
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		result = "CKR_KEY_FUNCTION_NOT_PERMITTED";
		break;
	case CKR_KEY_NOT_WRAPPABLE:
		result = "CKR_KEY_NOT_WRAPPABLE";
		break;
	case CKR_KEY_UNEXTRACTABLE:
		result = "CKR_KEY_UNEXTRACTABLE";
		break;
	case CKR_MECHANISM_INVALID:
		result = "CKR_MECHANISM_INVALID";
		break;
	case CKR_MECHANISM_PARAM_INVALID:
		result = "CKR_MECHANISM_PARAM_INVALID";
		break;
	case CKR_OBJECT_HANDLE_INVALID:
		result = "CKR_OBJECT_HANDLE_INVALID";
		break;
	case CKR_OPERATION_ACTIVE:
		result = "CKR_OPERATION_ACTIVE";
		break;
	case CKR_OPERATION_NOT_INITIALIZED:
		result = "CKR_OPERATION_NOT_INITIALIZED";
		break;
	case CKR_PIN_INCORRECT:
		result = "CKR_PIN_INCORRECT";
		break;
	case CKR_PIN_INVALID:
		result = "CKR_PIN_INVALID";
		break;
	case CKR_PIN_LEN_RANGE:
		result = "CKR_PIN_LEN_RANGE";
		break;
	case CKR_PIN_EXPIRED:
		result = "CKR_PIN_EXPIRED";
		break;
	case CKR_PIN_LOCKED:
		result = "CKR_PIN_LOCKED";
		break;
	case CKR_SESSION_CLOSED:
		result = "CKR_SESSION_CLOSED";
		break;
	case CKR_SESSION_COUNT:
		result = "CKR_SESSION_COUNT";
		break;
	case CKR_SESSION_HANDLE_INVALID:
		result = "CKR_SESSION_HANDLE_INVALID";
		break;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		result = "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		break;
	case CKR_SESSION_READ_ONLY:
		result = "CKR_SESSION_READ_ONLY";
		break;
	case CKR_SESSION_EXISTS:
		result = "CKR_SESSION_EXISTS";
		break;
	case CKR_SESSION_READ_ONLY_EXISTS:
		result = "CKR_SESSION_READ_ONLY_EXISTS";
		break;
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		result = "CKR_SESSION_READ_WRITE_SO_EXISTS";
		break;
	case CKR_SIGNATURE_INVALID:
		result = "CKR_SIGNATURE_INVALID";
		break;
	case CKR_SIGNATURE_LEN_RANGE:
		result = "CKR_SIGNATURE_LEN_RANGE";
		break;
	case CKR_TEMPLATE_INCOMPLETE:
		result = "CKR_TEMPLATE_INCOMPLETE";
		break;
	case CKR_TEMPLATE_INCONSISTENT:
		result = "CKR_TEMPLATE_INCONSISTENT";
		break;
	case CKR_TOKEN_NOT_PRESENT:
		result = "CKR_TOKEN_NOT_PRESENT";
		break;
	case CKR_TOKEN_NOT_RECOGNIZED:
		result = "CKR_TOKEN_NOT_RECOGNIZED";
		break;
	case CKR_TOKEN_WRITE_PROTECTED:
		result = "CKR_TOKEN_WRITE_PROTECTED";
		break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		result = "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		result = "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		result = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_USER_ALREADY_LOGGED_IN:
		result = "CKR_USER_ALREADY_LOGGED_IN";
		break;
	case CKR_USER_NOT_LOGGED_IN:
		result = "CKR_USER_NOT_LOGGED_IN";
		break;
	case CKR_USER_PIN_NOT_INITIALIZED:
		result = "CKR_USER_PIN_NOT_INITIALIZED";
		break;
	case CKR_USER_TYPE_INVALID:
		result = "CKR_USER_TYPE_INVALID";
		break;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		result = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		break;
	case CKR_USER_TOO_MANY_TYPES:
		result = "CKR_USER_TOO_MANY_TYPES";
		break;
	case CKR_WRAPPED_KEY_INVALID:
		result = "CKR_WRAPPED_KEY_INVALID";
		break;
	case CKR_WRAPPED_KEY_LEN_RANGE:
		result = "CKR_WRAPPED_KEY_LEN_RANGE";
		break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		result = "CKR_WRAPPING_KEY_HANDLE_INVALID";
		break;
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		result = "CKR_WRAPPING_KEY_SIZE_RANGE";
		break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		result = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		result = "CKR_RANDOM_SEED_NOT_SUPPORTED";
		break;
	case CKR_RANDOM_NO_RNG:
		result = "CKR_RANDOM_NO_RNG";
		break;
	case CKR_BUFFER_TOO_SMALL:
		result = "CKR_BUFFER_TOO_SMALL";
		break;
	case CKR_SAVED_STATE_INVALID:
		result = "CKR_SAVED_STATE_INVALID";
		break;
	case CKR_INFORMATION_SENSITIVE:
		result = "CKR_INFORMATION_SENSITIVE";
		break;
	case CKR_STATE_UNSAVEABLE:
		result = "CKR_STATE_UNSAVEABLE";
		break;
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		result = "CKR_CRYPTOKI_NOT_INITIALIZED";
		break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		result = "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		break;
	case CKR_MUTEX_BAD:
		result = "CKR_MUTEX_BAD";
		break;
	case CKR_MUTEX_NOT_LOCKED:
		result = "CKR_MUTEX_NOT_LOCKED";
		break;
	case CKR_VENDOR_DEFINED:
		result = "CKR_VENDOR_DEFINED";
		break;
	default:
		toString( result, "UNKNOWN ERROR <%#02x>", rv );
	}
#endif
}

/*
*/
void Log::toString( std::string &result, const char * format, ... )
{
#ifdef __DEBUG_GEMALTO__
	result = "";

   // Get the size of the buffer necessary to write the message
   // The size must be extended to include the '\n' and the '\0' characters.
   va_list args;
   va_start( args, format );
#ifdef WIN32
   size_t len = _vscprintf( format, args );
#else
   char tmp[1];
   int len = vsnprintf( tmp, sizeof(tmp), format, args );
#endif
   va_end( args );

   // Allocate the buffer for the message
   char *buffer = new char[ len + 2 ];
   memset( buffer, '\0', len + 2 );

   // Write the message into the buffer.
   va_start( args, format );
#ifdef WIN32
   vsprintf_s( buffer, len + 1, format, args );
#else
   vsprintf( buffer, format, args );
#endif
   va_end( args );

   // Write the message to the string
   result = buffer;

   // Release the buffer
   delete[] buffer;
#endif
}


/*
*/
void Log::toString( const unsigned char* buffer, std::size_t size, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( ( NULL == buffer ) || ( 1 > size ) )
	{
		//result.assign( "null" );
		return;
	}

    std::ostringstream oss;
	oss.rdbuf( )->str( "" );

    // Afficher en héxadécimal et en majuscule
    oss << std::hex << std::uppercase;

    // Remplir les blancs avec des zéros
    oss << std::setfill('0');

    for( std::size_t i = 0; i < size; ++i )
    {
        // Séparer chaque octet par un espace
        if (i != 0)
            oss << ' ';

        // Afficher sa valeur hexadécimale précédée de "0x"
        // setw(2) permet de forcer l'affichage à 2 caractères
        oss << /*"0x" <<*/ std::setw(2) << static_cast<int>( buffer[i] );
    }

    result.assign( oss.str( ) );
#endif
}


/*
*/
void Log::toString( const unsigned long &l, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	classtoString<unsigned long>( l, result );
#endif
}


template<typename T> void Log::classtoString( const T & value, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL == &value )
	{
		return;
	}
	std::ostringstream str;
	str << value;
	result.assign( str.str( ) );
#endif
}


void Log::slotFlagsToString( const CK_FLAGS& f, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	result = "";

	// Slot Information Flags
	if( f & CKF_TOKEN_PRESENT )
	{
		result += "CKF_TOKEN_PRESENT";
	}

	if( f & CKF_REMOVABLE_DEVICE )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_REMOVABLE_DEVICE";
	}

	if( f & CKF_HW_SLOT )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_HW_SLOT";
	}
#endif
}


/*
*/
void Log::CK_VERSIONToString( CK_VERSION_PTR pVersion, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == pVersion )
	{
		return;
	}

	toString( result, "%#02x - %#02x", pVersion->major, pVersion->minor );
#endif
}


/*
*/
void Log::CK_MECHANISM_TYPEToString( CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG mechanismListLen, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == pMechanismList )
	{
		return;
	}

	result = "";

	for( size_t i = 0 ; i < (size_t)mechanismListLen; i++ )
	{
		std::string m = "";
		CK_MECHANISM_TYPEToString( pMechanismList[ i ], m );
		result += m;
		if( i != (size_t)( mechanismListLen - 1 ) )
		{
			result +=", ";
		}
	}
#endif
}


/*
*/
void Log::CK_MECHANISM_TYPEToString( const CK_MECHANISM_TYPE &t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( t )
	{
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		result = "CKM_RSA_PKCS_KEY_PAIR_GEN";
		break;
	case CKM_RSA_PKCS:
		result = "CKM_RSA_PKCS";
		break;
	case CKM_RSA_9796:
		result = "CKM_RSA_9796";
		break;
	case CKM_RSA_X_509:
		result = "CKM_RSA_X_509";
		break;
	case CKM_MD2_RSA_PKCS:
		result = "CKM_MD2_RSA_PKCS";
		break;
	case CKM_MD5_RSA_PKCS:
		result = "CKM_MD5_RSA_PKCS";
		break;
	case CKM_SHA1_RSA_PKCS:
		result = "CKM_SHA1_RSA_PKCS";
		break;
	case CKM_DSA_KEY_PAIR_GEN:
		result = "CKM_DSA_KEY_PAIR_GEN";
		break;
	case CKM_DSA:
		result = "CKM_DSA";
		break;
	case CKM_DSA_SHA1:
		result = "CKM_DSA_SHA1";
		break;
	case CKM_DH_PKCS_KEY_PAIR_GEN:
		result = "CKM_DH_PKCS_KEY_PAIR_GEN";
		break;
	case CKM_DH_PKCS_DERIVE:
		result = "CKM_DH_PKCS_DERIVE";
		break;
	case CKM_RC2_KEY_GEN:
		result = "CKM_RC2_KEY_GEN";
		break;
	case CKM_RC2_ECB:
		result = "CKM_RC2_ECB";
		break;
	case CKM_RC2_CBC:
		result = "CKM_RC2_CBC";
		break;
	case CKM_RC2_MAC:
		result = "CKM_RC2_MAC";
		break;
	case CKM_RC2_MAC_GENERAL:
		result = "CKM_RC2_MAC_GENERAL";
		break;
	case CKM_RC2_CBC_PAD:
		result = "CKM_RC2_CBC_PAD";
		break;
	case CKM_RC4_KEY_GEN:
		result = "CKM_RC4_KEY_GEN";
		break;
	case CKM_RC4:
		result = "CKM_RC4";
		break;
	case CKM_DES_KEY_GEN:
		result = "CKM_DES_KEY_GEN";
		break;
	case CKM_DES_ECB:
		result = "CKM_DES_ECB";
		break;
	case CKM_DES_CBC:
		result = "CKM_DES_CBC";
		break;
	case CKM_DES_MAC:
		result = "CKM_DES_MAC";
		break;
	case CKM_DES_MAC_GENERAL:
		result = "CKM_DES_MAC_GENERAL";
		break;
	case CKM_DES_CBC_PAD:
		result = "CKM_DES_CBC_PAD";
		break;
	case CKM_DES2_KEY_GEN:
		result = "CKM_DES2_KEY_GEN";
		break;
	case CKM_DES3_KEY_GEN:
		result = "CKM_DES3_KEY_GEN";
		break;
	case CKM_DES3_ECB:
		result = "CKM_DES3_ECB";
		break;
	case CKM_DES3_CBC:
		result = "CKM_DES3_CBC";
		break;
	case CKM_DES3_MAC:
		result = "CKM_DES3_MAC";
		break;
	case CKM_DES3_MAC_GENERAL:
		result = "CKM_DES3_MAC_GENERAL";
		break;
	case CKM_DES3_CBC_PAD:
		result = "CKM_DES3_CBC_PAD";
		break;
	case CKM_CDMF_KEY_GEN:
		result = "CKM_CDMF_KEY_GEN";
		break;
	case CKM_CDMF_ECB:
		result = "CKM_CDMF_ECB";
		break;
	case CKM_CDMF_CBC:
		result = "CKM_CDMF_CBC";
		break;
	case CKM_CDMF_MAC:
		result = "CKM_CDMF_MAC";
		break;
	case CKM_CDMF_MAC_GENERAL:
		result = "CKM_CDMF_MAC_GENERAL";
		break;
	case CKM_CDMF_CBC_PAD:
		result = "CKM_CDMF_CBC_PAD";
		break;
	case CKM_MD2:
		result = "CKM_MD2";
		break;
	case CKM_MD2_HMAC:
		result = "CKM_MD2_HMAC";
		break;
	case CKM_MD2_HMAC_GENERAL:
		result = "CKM_MD2_HMAC_GENERAL";
		break;
	case CKM_MD5:
		result = "CKM_MD5";
		break;
	case CKM_MD5_HMAC:
		result = "CKM_MD5_HMAC";
		break;
	case CKM_MD5_HMAC_GENERAL:
		result = "CKM_MD5_HMAC_GENERAL";
		break;
	case CKM_SHA_1:
		result = "CKM_SHA_1";
		break;
	case CKM_SHA_1_HMAC:
		result = "CKM_SHA_1_HMAC";
		break;
	case CKM_SHA_1_HMAC_GENERAL:
		result = "CKM_SHA_1_HMAC_GENERAL";
		break;
	case CKM_CAST_KEY_GEN:
		result = "CKM_CAST_KEY_GEN";
		break;
	case CKM_CAST_ECB:
		result = "CKM_CAST_ECB";
		break;
	case CKM_CAST_CBC:
		result = "CKM_CAST_CBC";
		break;
	case CKM_CAST_MAC:
		result = "CKM_CAST_MAC";
		break;
	case CKM_CAST_MAC_GENERAL:
		result = "CKM_CAST_MAC_GENERAL";
		break;
	case CKM_CAST_CBC_PAD:
		result = "CKM_CAST_CBC_PAD";
		break;
	case CKM_CAST3_KEY_GEN:
		result = "CKM_CAST3_KEY_GEN";
		break;
	case CKM_CAST3_ECB:
		result = "CKM_CAST3_ECB";
		break;
	case CKM_CAST3_CBC:
		result = "CKM_CAST3_CBC";
		break;
	case CKM_CAST3_MAC:
		result = "CKM_CAST3_MAC";
		break;
	case CKM_CAST3_MAC_GENERAL:
		result = "CKM_CAST3_MAC_GENERAL";
		break;
	case CKM_CAST3_CBC_PAD:
		result = "CKM_CAST3_CBC_PAD";
		break;
		/*case CKM_CAST5_KEY_GEN:
		result = "CKM_CAST5_KEY_GEN";
		break;*/
	case CKM_CAST128_KEY_GEN:
		result = "CKM_CAST128_KEY_GEN/CKM_CAST5_KEY_GEN";
		break;
		/*case CKM_CAST5_ECB:
		result = "CKM_CAST5_ECB";
		break;*/
	case CKM_CAST128_ECB:
		result = "CKM_CAST128_ECB/CKM_CAST5_ECB";
		break;
		/*case CKM_CAST5_CBC:
		result = "CKM_CAST5_CBC";
		break;*/
	case CKM_CAST128_CBC:
		result = "CKM_CAST128_CBC/CKM_CAST5_CBC";
		break;
		/*case CKM_CAST5_MAC:
		result = "CKM_CAST5_MAC";
		break;*/
	case CKM_CAST128_MAC:
		result = "CKM_CAST128_MAC/CKM_CAST5_MAC";
		break;
		/*case CKM_CAST5_MAC_GENERAL:
		result = "CKM_CAST5_MAC_GENERAL";
		break;*/
	case CKM_CAST128_MAC_GENERAL:
		result = "CKM_CAST128_MAC_GENERAL/CKM_CAST5_MAC_GENERAL";
		break;
		/*case CKM_CAST5_CBC_PAD:
		result = "CKM_CAST5_CBC_PAD";
		break;*/
	case CKM_CAST128_CBC_PAD:
		result = "CKM_CAST128_CBC_PAD/CKM_CAST5_CBC_PAD";
		break;
	case CKM_RC5_KEY_GEN:
		result = "CKM_RC5_KEY_GEN";
		break;
	case CKM_RC5_ECB:
		result = "CKM_RC5_ECB";
		break;
	case CKM_RC5_CBC:
		result = "CKM_RC5_CBC";
		break;
	case CKM_RC5_MAC:
		result = "CKM_RC5_MAC";
		break;
	case CKM_RC5_MAC_GENERAL:
		result = "CKM_RC5_MAC_GENERAL";
		break;
	case CKM_RC5_CBC_PAD:
		result = "CKM_RC5_CBC_PAD";
		break;
	case CKM_IDEA_KEY_GEN:
		result = "CKM_IDEA_KEY_GEN";
		break;
	case CKM_IDEA_ECB:
		result = "CKM_IDEA_ECB";
		break;
	case CKM_IDEA_CBC:
		result = "CKM_IDEA_CBC";
		break;
	case CKM_IDEA_MAC:
		result = "CKM_IDEA_MAC";
		break;
	case CKM_IDEA_MAC_GENERAL:
		result = "CKM_IDEA_MAC_GENERAL";
		break;
	case CKM_IDEA_CBC_PAD:
		result = "CKM_IDEA_CBC_PAD";
		break;
	case CKM_GENERIC_SECRET_KEY_GEN:
		result = "CKM_GENERIC_SECRET_KEY_GEN";
		break;
	case CKM_CONCATENATE_BASE_AND_KEY:
		result = "CKM_CONCATENATE_BASE_AND_KEY";
		break;
	case CKM_CONCATENATE_BASE_AND_DATA:
		result = "CKM_CONCATENATE_BASE_AND_DATA";
		break;
	case CKM_CONCATENATE_DATA_AND_BASE:
		result = "CKM_CONCATENATE_DATA_AND_BASE";
		break;
	case CKM_XOR_BASE_AND_DATA:
		result = "CKM_XOR_BASE_AND_DATA";
		break;
	case CKM_EXTRACT_KEY_FROM_KEY:
		result = "CKM_EXTRACT_KEY_FROM_KEY";
		break;
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
		result = "CKM_SSL3_PRE_MASTER_KEY_GEN";
		break;
	case CKM_SSL3_MASTER_KEY_DERIVE:
		result = "CKM_SSL3_MASTER_KEY_DERIVE";
		break;
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
		result = "CKM_SSL3_KEY_AND_MAC_DERIVE";
		break;
	case CKM_SSL3_MD5_MAC:
		result = "CKM_SSL3_MD5_MAC";
		break;
	case CKM_SSL3_SHA1_MAC:
		result = "CKM_SSL3_SHA1_MAC";
		break;
	case CKM_MD5_KEY_DERIVATION:
		result = "CKM_MD5_KEY_DERIVATION";
		break;
	case CKM_MD2_KEY_DERIVATION:
		result = "CKM_MD2_KEY_DERIVATION";
		break;
	case CKM_SHA1_KEY_DERIVATION:
		result = "CKM_SHA1_KEY_DERIVATION";
		break;
	case CKM_PBE_MD2_DES_CBC:
		result = "CKM_PBE_MD2_DES_CBC";
		break;
	case CKM_PBE_MD5_DES_CBC:
		result = "CKM_PBE_MD5_DES_CBC";
		break;
	case CKM_PBE_MD5_CAST_CBC:
		result = "CKM_PBE_MD5_CAST_CBC";
		break;
	case CKM_PBE_MD5_CAST3_CBC:
		result = "CKM_PBE_MD5_CAST3_CBC";
		break;
		/*case CKM_PBE_MD5_CAST5_CBC:
		result = "CKM_PBE_MD5_CAST5_CBC";
		break;*/
	case CKM_PBE_MD5_CAST128_CBC:
		result = "CKM_PBE_MD5_CAST128_CBC/CKM_PBE_MD5_CAST5_CBC";
		break;
		/*case CKM_PBE_SHA1_CAST5_CBC:
		result = "CKM_PBE_SHA1_CAST5_CBC";
		break;*/
	case CKM_PBE_SHA1_CAST128_CBC:
		result = "CKM_PBE_SHA1_CAST128_CBC/CKM_PBE_SHA1_CAST5_CBC";
		break;
	case CKM_PBE_SHA1_RC4_128:
		result = "CKM_PBE_SHA1_RC4_128";
		break;
	case CKM_PBE_SHA1_RC4_40:
		result = "CKM_PBE_SHA1_RC4_40";
		break;
	case CKM_PBE_SHA1_DES3_EDE_CBC:
		result = "CKM_PBE_SHA1_DES3_EDE_CBC";
		break;
	case CKM_PBE_SHA1_DES2_EDE_CBC:
		result = "CKM_PBE_SHA1_DES2_EDE_CBC";
		break;
	case CKM_PBE_SHA1_RC2_128_CBC:
		result = "CKM_PBE_SHA1_RC2_128_CBC";
		break;
	case CKM_PBE_SHA1_RC2_40_CBC:
		result = "CKM_PBE_SHA1_RC2_40_CBC";
		break;
	case CKM_PBA_SHA1_WITH_SHA1_HMAC:
		result = "CKM_PBA_SHA1_WITH_SHA1_HMAC";
		break;
	case CKM_KEY_WRAP_LYNKS:
		result = "CKM_KEY_WRAP_LYNKS";
		break;
	case CKM_KEY_WRAP_SET_OAEP:
		result = "CKM_KEY_WRAP_SET_OAEP";
		break;
	case CKM_SKIPJACK_KEY_GEN:
		result = "CKM_SKIPJACK_KEY_GEN";
		break;
	case CKM_SKIPJACK_ECB64:
		result = "CKM_SKIPJACK_ECB64";
		break;
	case CKM_SKIPJACK_CBC64:
		result = "CKM_SKIPJACK_CBC64";
		break;
	case CKM_SKIPJACK_OFB64:
		result = "CKM_SKIPJACK_OFB64";
		break;
	case CKM_SKIPJACK_CFB64:
		result = "CKM_SKIPJACK_CFB64";
		break;
	case CKM_SKIPJACK_CFB32:
		result = "CKM_SKIPJACK_CFB32";
		break;
	case CKM_SKIPJACK_CFB16:
		result = "CKM_SKIPJACK_CFB16";
		break;
	case CKM_SKIPJACK_CFB8:
		result = "CKM_SKIPJACK_CFB8";
		break;
	case CKM_SKIPJACK_WRAP:
		result = "CKM_SKIPJACK_WRAP";
		break;
	case CKM_SKIPJACK_PRIVATE_WRAP:
		result = "CKM_SKIPJACK_PRIVATE_WRAP";
		break;
	case CKM_SKIPJACK_RELAYX:
		result = "CKM_SKIPJACK_RELAYX";
		break;
	case CKM_KEA_KEY_PAIR_GEN:
		result = "CKM_KEA_KEY_PAIR_GEN";
		break;
	case CKM_KEA_KEY_DERIVE:
		result = "CKM_KEA_KEY_DERIVE";
		break;
	case CKM_FORTEZZA_TIMESTAMP:
		result = "CKM_FORTEZZA_TIMESTAMP";
		break;
	case CKM_BATON_KEY_GEN:
		result = "CKM_BATON_KEY_GEN";
		break;
	case CKM_BATON_ECB128:
		result = "CKM_BATON_ECB128";
		break;
	case CKM_BATON_ECB96:
		result = "CKM_BATON_ECB96";
		break;
	case CKM_BATON_CBC128:
		result = "CKM_BATON_CBC128";
		break;
	case CKM_BATON_COUNTER:
		result = "CKM_BATON_COUNTER";
		break;
	case CKM_BATON_SHUFFLE:
		result = "CKM_BATON_SHUFFLE";
		break;
	case CKM_BATON_WRAP:
		result = "CKM_RSA_9796";
		break;
	case CKM_ECDSA:
		result = "CKM_ECDSA";
		break;
	case CKM_ECDSA_SHA1:
		result = "CKM_ECDSA_SHA1";
		break;
	case CKM_JUNIPER_KEY_GEN:
		result = "CKM_JUNIPER_KEY_GEN";
		break;
	case CKM_JUNIPER_ECB128:
		result = "CKM_JUNIPER_ECB128";
		break;
	case CKM_JUNIPER_CBC128:
		result = "CKM_JUNIPER_CBC128";
		break;
	case CKM_JUNIPER_COUNTER:
		result = "CKM_JUNIPER_COUNTER";
		break;
	case CKM_JUNIPER_SHUFFLE:
		result = "CKM_JUNIPER_SHUFFLE";
		break;
	case CKM_JUNIPER_WRAP:
		result = "CKM_JUNIPER_WRAP";
		break;
	case CKM_FASTHASH:
		result = "CKM_FASTHASH";
		break;
	case CKM_VENDOR_DEFINED:
		result = "CKM_VENDOR_DEFINED";
		break;
	case CKM_SHA256:
		result = "CKM_SHA256";
		break;
	case CKM_SHA256_RSA_PKCS:
		result = "CKM_SHA256_RSA_PKCS";
		break;
	default:
		toString( result, "UNKNOWN MECHANISM <%#02x>", t );
	}
#endif
}


/*
*/
void Log::CK_MECHANISM_INFOToString( CK_MECHANISM_INFO_PTR pInfo, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == pInfo )
	{
		 return;
	}

	std::string flags = "";
	CK_FLAGS f = pInfo->flags;
	mechanismFlagsToString( f, flags );

	toString( result, "ulMinKeySize <%#02x> - ulMaxKeySize <%#02x> - flags <%s>", pInfo->ulMinKeySize, pInfo->ulMaxKeySize, flags.c_str( ) );
#endif
}


/*
*/
void Log::mechanismFlagsToString( const CK_FLAGS& f, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	if( f & CKF_EXTENSION )
	{
		result += "CKF_EXTENSION";
	}
	if( f & CKF_DERIVE )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_DERIVE";
	}
	if( f & CKF_UNWRAP )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_UNWRAP";
	}
	if( f & CKF_WRAP )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_WRAP";
	}
	if( f & CKF_GENERATE_KEY_PAIR )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_GENERATE_KEY_PAIR";
	}
	if( f & CKF_GENERATE )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_GENERATE";
	}
	if( f & CKF_VERIFY_RECOVER )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_VERIFY_RECOVER";
	}
	if( f & CKF_VERIFY )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_VERIFY";
	}
	if( f & CKF_SIGN_RECOVER )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_SIGN_RECOVER";
	}
	if( f & CKF_HW )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_HW";
	}
	if( f & CKF_ENCRYPT )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_ENCRYPT";
	}
	if( f & CKF_DECRYPT )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_DECRYPT";
	}
	if( f & CKF_DIGEST )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_DIGEST";
	}
	if( f & CKF_SIGN )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_SIGN";
	}
#endif
}


/*
*/
void Log::sessionFlagsToString( const CK_FLAGS &f, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	result = "";

	// Session information flags
	if( f & CKF_SERIAL_SESSION )
	{
		result += "CKF_SERIAL_SESSION";
	}

	if( f & CKF_RW_SESSION )
	{
		if( !result.empty( ) )
		{
			result += " | ";
		}
		result += "CKF_RW_SESSION";
	}
#endif
}


/*
*/
void Log::CK_SESSION_INFOToString( CK_SESSION_INFO_PTR pInfo, std::string& result )
{
#ifdef __DEBUG_GEMALTO__
	if( NULL_PTR == pInfo )
	{
		return;
	}

	std::string flags = "";
	CK_FLAGS f = pInfo->flags;
	sessionFlagsToString( f, flags );

	toString( result, "slotID <%#02x> - state <%#02x> - flags <%#02x> (%s) - ulDeviceError <%#02x>",
				pInfo->slotID,
				pInfo->state,
				pInfo->flags,
				flags.c_str( ),
				pInfo->ulDeviceError );
#endif
}

/*
*/
void Log::CK_USER_TYPEToString( const CK_USER_TYPE& t, std::string &result )
{
#ifdef __DEBUG_GEMALTO__
	switch( t )
	{
	case CKU_USER:
		result = "CKU_USER";
		break;

	case CKU_SO:
		result  = "CKU_SO";
		break;

	default:
		toString( result, "UNKNOWN USER TYPE <%#02x>", t );
	}
#endif
}

