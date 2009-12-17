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
#include "error.h"
#include "log.h"


#define ERROR_MEMORY "Persistent"


/* CheckMarshallerException
*/
CK_RV CkError::CheckMarshallerException( Marshaller::Exception &x )
{
   UnauthorizedAccessException* uae = dynamic_cast< UnauthorizedAccessException* >( &x );
   if( uae )
   {
      Log::log( "CheckMarshallerException", "## Error ## UnauthorizedAccessException <%s>", x.what( ) );
      return CKR_USER_NOT_LOGGED_IN;
   }

   OutOfMemoryException* oome = dynamic_cast< OutOfMemoryException* >( &x );
   if( oome )
   {
      Log::log( "CheckMarshallerException", "## Error ## OutOfMemoryException <%s>", x.what( ) );
      return CKR_DEVICE_MEMORY;
   }

   if( NULL != x.what( ) )
   {
      if( 0 == strcmp( x.what( ), ERROR_MEMORY ) )
      {
         Log::log( "CheckMarshallerException", "## Error ## OutOfMemoryException %s <%s>", ERROR_MEMORY, x.what( ) );
         return CKR_DEVICE_MEMORY;
      }
   }

   {
      DirectoryNotFoundException * e = dynamic_cast<DirectoryNotFoundException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## DirectoryNotFoundException <%s>", x.what( ) );
         return CKR_TOKEN_NOT_RECOGNIZED;
      }
   }
   {
      FileNotFoundException * e = dynamic_cast<FileNotFoundException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## FileNotFoundException <%s>", x.what( ) );
         return CKR_TOKEN_NOT_RECOGNIZED;
      }
   }
   {
      IOException * e = dynamic_cast<IOException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## IOException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      RemotingException * e = dynamic_cast<RemotingException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## RemotingException <%s>", x.what( ) );
         return CKR_TOKEN_NOT_PRESENT;
      }
   }

   {
      CryptographicException * e = dynamic_cast<CryptographicException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## CryptographicException <%s>", x.what( ) );
         return CKR_DEVICE_MEMORY;
      }
   }

   {
      SystemException * e = dynamic_cast<SystemException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## SystemException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ArgumentException * e = dynamic_cast<ArgumentException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ArgumentException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ArgumentNullException * e = dynamic_cast<ArgumentNullException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ArgumentNullException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ArgumentOutOfRangeException * e = dynamic_cast<ArgumentOutOfRangeException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ArgumentOutOfRangeException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      IndexOutOfRangeException * e = dynamic_cast<IndexOutOfRangeException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## IndexOutOfRangeException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      InvalidCastException * e = dynamic_cast<InvalidCastException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## InvalidCastException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      InvalidOperationException * e = dynamic_cast<InvalidOperationException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## InvalidOperationException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      NotImplementedException * e = dynamic_cast<NotImplementedException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## NotImplementedException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      NotSupportedException * e = dynamic_cast<NotSupportedException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## NotSupportedException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      NullReferenceException * e = dynamic_cast<NullReferenceException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## NullReferenceException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ObjectDisposedException * e = dynamic_cast<ObjectDisposedException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ObjectDisposedException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ApplicationException * e = dynamic_cast<ApplicationException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ApplicationException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ArithmeticException * e = dynamic_cast<ArithmeticException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ArithmeticException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      ArrayTypeMismatchException * e = dynamic_cast<ArrayTypeMismatchException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## ArrayTypeMismatchException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      BadImageFormatException * e = dynamic_cast<BadImageFormatException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## BadImageFormatException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      DirectoryNotFoundException * e = dynamic_cast<DirectoryNotFoundException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## DirectoryNotFoundException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      DivideByZeroException * e = dynamic_cast<DivideByZeroException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## DivideByZeroException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      FormatException * e = dynamic_cast<FormatException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## FormatException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      RankException * e = dynamic_cast<RankException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## RankException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      RemotingException * e = dynamic_cast<RemotingException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## RemotingException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      StackOverflowException * e = dynamic_cast<StackOverflowException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## StackOverflowException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      TypeLoadException * e = dynamic_cast<TypeLoadException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## TypeLoadException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      MemberAccessException * e = dynamic_cast<MemberAccessException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## MemberAccessException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      MissingFieldException * e = dynamic_cast<MissingFieldException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## MissingFieldException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      MissingMemberException * e = dynamic_cast<MissingMemberException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## MissingMemberException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      MissingMethodException * e = dynamic_cast<MissingMethodException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## MissingMethodException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      OverflowException * e = dynamic_cast<OverflowException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## OverflowException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      SecurityException * e = dynamic_cast<SecurityException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## SecurityException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      VerificationException * e = dynamic_cast<VerificationException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## VerificationException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }
   {
      SerializationException * e = dynamic_cast<SerializationException *>( &x );
      if(e)
      {
         Log::log( "CheckMarshallerException", "## Error ## SerializationException <%s>", x.what( ) );
         return CKR_DEVICE_ERROR;
      }
   }

   return CKR_FUNCTION_FAILED;
}
