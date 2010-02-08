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

#include <memory>
#include "stdafx.h"
#include "cardcache.h"
#include "error.h"
#include "log.h"


#define KEYSPEC_KEYEXCHANGE  0x01
#define KEYSPEC_SIGNATURE    0x02
#define MAX_RETRY 2
#define LOW_MEMORY_LIMIT 25000


/* Constructor
*/
CardCache::CardCache( CardModuleService * mscm ) : _mscm( mscm )
{
   if( !mscm )
   {
      throw CkError( CKR_FUNCTION_FAILED );
   }
}

/*
*/
void CardCache::ManageGC( void )
{
   try
   {
      if( NULL != _mscm )
      {
         s4 freeMemory = _mscm->GetMemory( );

         if ( freeMemory < LOW_MEMORY_LIMIT )
         {
             //printf( "\nCardCache::ManageGC - ForceGarbageCollector\n" );
             Log::error( "CardCache::ManageGC", "ForceGarbageCollector" );
            _mscm->ForceGarbageCollector( );
         }
      }
   }
   catch( ... )
   {
   }
}


/* WriteFile
Write the incoming data into the incoming pointed path into the smartcard
and then into the cache
*/
void CardCache::WriteFile( std::string const & path, u1Array const & data )
{
   int ntry = 0;
   while( ntry < MAX_RETRY )
   {
      try
      {
         ntry++;
         _mscm->WriteFile( const_cast< std::string* >( &path ), const_cast< u1Array* >( &data ) );
         ManageGC( );
         _fileCache[ path ] = data;
         break;
      }
      catch( Marshaller::Exception & x )
      {
         CK_RV rv = CkError::CheckMarshallerException( x );
         if( CKR_DEVICE_MEMORY == rv )
         {
            Log::error( "CardCache::WriteFile", "ForceGarbageCollector" );
           _mscm->ForceGarbageCollector( );
            if( ntry >= MAX_RETRY )
            {
               _fileCache.erase( path );
               throw CkError( rv );
            }
         }
         else
         {
            _fileCache.erase( path );
            throw CkError( rv );
         }
      }
      catch( ... )
      {
         _fileCache.erase( path );
         throw CkError( CKR_FUNCTION_FAILED );
      }
   }
}


/* ReadFile
*/
const u1Array & CardCache::ReadFile( std::string const & path )
{
   //Log::log( "***** CardCache::ReadFile - path <%s>", path.c_str( ) );

   // V2+ cards may throw OutOfMemoryException from ReadFile, however
   // it may recover from this by forcing the garbage collection to
   // occur. In fact as a result of a ReadFile command that throws
   // OutOfMemoryException, GC has already occured, so the command may
   // be re-tried with high chance of success.

   map<string, u1Array>::const_iterator ifile = _fileCache.find( path );
   if( ifile == _fileCache.end( ) )
   {
      //Log::log( "****** CardCache::ReadFile - read card" );

      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ntry++;
            auto_ptr< u1Array > data( _mscm->ReadFile( const_cast< std::string* >( &path ), 0 ) );
            ManageGC( );
            _fileCache[ path ] = *data;
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "CardCache::ReadFile", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
         catch( ... )
         {
            throw CkError( CKR_FUNCTION_FAILED );
         }
      }
   }

   return _fileCache[ path ];
}


/* ClearFile
Erase a file from the cache
*/
void CardCache::ClearFile( std::string const &path )
{
   _fileCache.erase( path );
}


/* ReadContainer
Read the contained pointed by the incoming index from the smartcard
and compute an instance into the cache
*/
const CardCache::Container& CardCache::ReadContainer( int const &ctrIndex ) const
{
   map< int, Container >::const_iterator icont = _contCache.find( ctrIndex );
   if( icont == _contCache.end( ) )
   {
      try
      {
         Container cont;
         auto_ptr< u1Array > cInfo( _mscm->GetCAPIContainer( ctrIndex ) );
         u4 offset = 2;
         for( int ikeySpec = 0; ikeySpec < 2 ; ++ikeySpec )
         {
            if( offset < cInfo->GetLength( ) )
            {
               u1 keySpec = cInfo->ReadU1At( offset );
               offset += 2;
               u1 expontLen = cInfo->ReadU1At( offset );
               offset++;
               u1Array publicExponent( expontLen );
               memcpy( publicExponent.GetBuffer( ), cInfo->GetBuffer( ) + offset, expontLen );
               offset += ( expontLen + 1 );
               u4 modulusLen = cInfo->ReadU1At( offset ) << 4; // Modulus Len
               offset++;
               u1Array modulus( modulusLen );
               memcpy( modulus.GetBuffer( ), cInfo->GetBuffer( ) + offset, modulusLen );

               if( keySpec == KEYSPEC_KEYEXCHANGE )
               {
                  cont.exchModulus = modulus;
                  cont.exchPublicExponent = publicExponent;
               }
               else if( keySpec == KEYSPEC_SIGNATURE )
               {
                  cont.signModulus = modulus;
                  cont.signPublicExponent = publicExponent;
               }
               offset += modulusLen;
               offset += 2;
            }
         }
         _contCache[ ctrIndex ] = cont;
      }
      catch( ... )
      {
         _contCache[ ctrIndex ] = Container( ); // Empty
      }
   }
   return _contCache[ ctrIndex ];
}


/* ClearContainer
Erase the container pointed by the incoming index from the cache
*/
void CardCache::ClearContainer( int const &ctrIndex )
{
   _contCache.erase( ctrIndex );
}


/* FileList
Retreive the list of the files contained into the incoming directory path
and returns a string vectors
*/
const vector< std::string > & CardCache::FileList( std::string const &dir )
{
   map< std::string, vector< std::string > >::const_iterator idir = _fileList.find( dir );
   if( idir == _fileList.end( ) )
   {
      vector< std::string > vfile;
      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ntry++;
            auto_ptr<StringArray> files( _mscm->GetFiles( const_cast<string*>( &dir ) ) );
            ManageGC( );
            for( u4 i = 0; i < files->GetLength( ) ; i++ )
            {
               vfile.push_back( *files->GetStringAt( i ) );
            }
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "CardCache::FileList", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
         catch( ... )
         {
            throw CkError( CKR_FUNCTION_FAILED );
         }
      }
      _fileList[ dir ] = vfile;
   }

   return _fileList[ dir ];
}


/* ClearFileList
Erase the dir from the cache
*/
void CardCache::ClearFileList( std::string const & dir )
{
   _fileList.erase( dir );
}


/* ClearAll
Erase all cache
*/
void CardCache::ClearAll( )
{
   _fileCache.clear( );
   _contCache.clear( );
   _fileList.clear( );
}
