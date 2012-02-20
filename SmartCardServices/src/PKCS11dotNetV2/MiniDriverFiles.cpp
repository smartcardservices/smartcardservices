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


#include <boost/foreach.hpp>
#include <fstream>
#include <memory>
#include "MiniDriverFiles.hpp"
#include "MiniDriverException.hpp"
#include "Log.hpp"
#include "util.h"
#include "Array.hpp"
#include<boost/tokenizer.hpp>
#include "Timer.hpp"
#include "Device.hpp"

#include "PCSCMissing.h"


const int MAX_RETRY = 2;


/* Constructor
*/
MiniDriverFiles::MiniDriverFiles( ) { 

    m_ContainerMapFile.setMiniDriverFiles( this );

    m_stPathCertificateRoot = szROOT_STORE_FILE;

	s_stPathSeparator = "\\";

	s_stPathMscp = szBASE_CSP_DIR;
}


/*
*/
void MiniDriverFiles::hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) {

    Log::begin( "MiniDriverFiles::hasChanged" );
    Timer t;
    t.start( );

    try {

        // Check if the smart card content read from the disk is still up to date
        a_Pins = MiniDriverCardCacheFile::NONE;
        a_Containers = MiniDriverCardCacheFile::NONE;
        a_Files = MiniDriverCardCacheFile::NONE;
        m_CardCacheFile.hasChanged( a_Pins, a_Containers, a_Files );

        // Reset objects content if the cache has changed
        if( MiniDriverCardCacheFile::NONE != a_Pins ) {
        }

        if( ( MiniDriverCardCacheFile::NONE != a_Containers ) || ( MiniDriverCardCacheFile::NONE != a_Files ) ) {

            m_BinaryFiles.clear( );

            m_Directories.clear( );

            m_ContainerMapFile.clear( );

            m_ContainerMapFile.containerRead( );
        }

    } catch( ... ) { }

    t.stop( "MiniDriverFiles::hasChanged" );
    Log::end( "MiniDriverFiles::hasChanged" );
}


/* Write the incoming data into the incoming pointed path into the smartcard and then into the cache
*/
void MiniDriverFiles::writeFile( const std::string& a_stDirectory, const std::string& a_stFile, Marshaller::u1Array* a_pData, const bool& a_bAddToCache, const bool& a_bUpdateContainerCounter ) {

    Log::begin( "MiniDriverFiles::writeFile" );
    Log::log( "MiniDriverFiles::writeFile - Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) );
    Timer t;
    t.start( );


    int ntry = 0;

    std::string stPath = a_stDirectory + s_stPathSeparator + a_stFile;

    while( ntry < MAX_RETRY ) {

        try {

            ntry++;

            // Write to the smart card
            if( !m_CardModule ) {

                throw MiniDriverException( SCARD_E_NO_SMARTCARD );
            }
            m_CardModule->writeFile( (std::string*)&stPath, a_pData );

            break;

        } catch( MiniDriverException& x ) {

            Log::error( "MiniDriverFiles::writeFile", "WriteFile failed" );

            unsigned long ulError = x.getError( );

            if ( SCARD_E_NO_MEMORY == ulError ) {

                // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                // be re-tried with high chance of success.
                if( ntry >= MAX_RETRY ) {

                    m_BinaryFiles.erase( a_stFile );

                    throw MiniDriverException( SCARD_E_NO_MEMORY );
                }

            } else {

                throw MiniDriverException( x );
            }
        }
    }

    // Add the file to the directory cache
    DIRECTORIES::iterator directoryIterator =  m_Directories.find( a_stDirectory );

    if( directoryIterator != m_Directories.end( ) ) {

        directoryIterator->second->insert( a_stFile );
    } 

    // Prepare the binary file content
    Marshaller::u1Array* f = new Marshaller::u1Array( a_pData->GetLength( ) );
    
    f->SetBuffer( a_pData->GetBuffer( ) );

    FILES_BINARY::iterator filesIterator = m_BinaryFiles.find( a_stFile );

    if( filesIterator == m_BinaryFiles.end( ) ) {
    
        // Add the new file to the cache
        std::string stFile = a_stFile;
        m_BinaryFiles.insert( stFile, f );
    
    } else {
    
        // Update the new file to the cache
        m_BinaryFiles[ a_stFile ] = *f;
    }

    m_CardCacheFile.notifyChange( MiniDriverCardCacheFile::FILES );

    if( a_bUpdateContainerCounter ) {
    
        m_CardCacheFile.notifyChange( MiniDriverCardCacheFile::CONTAINERS );
    }

    std::string s = "";
    Log::toString( a_pData->GetBuffer( ), a_pData->GetLength( ), s );
    Log::log( "MiniDriverFiles::writeFile - path <%s> (Added to cache) - data <%s>", a_stFile.c_str( ), s.c_str( ) );

    t.stop( "MiniDriverFiles::writeFile" );
    Log::end( "MiniDriverFiles::writeFile" );
}


/*
*/
void MiniDriverFiles::cacheDisableWrite( void ) {

    BOOST_FOREACH( const std::string& s, m_FilesToNotCache ) {
        
        m_BinaryFiles.erase( s );
    }
}


/* Retreive the list of the files contained into the incoming directory path and returns a string vectors
*/
MiniDriverFiles::FILES_NAME & MiniDriverFiles::enumFiles( const std::string& a_stDirectory ) {

    Log::begin( "MiniDriverFiles::enumFiles" );
    Log::log( "MiniDriverFiles::enumFiles - Directory <%s>", a_stDirectory.c_str( ) );
    Timer t;
    t.start( );


    // Log
    std::string stFrom = "cache";

    DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );

    if( i == m_Directories.end( ) ) {

        // Log
        stFrom = "!! CARD !!";

        int ntry = 0;

        while( ntry < MAX_RETRY ) {

            try {

                ntry++;

                // Read the directory files from the smart card
                if( !m_CardModule ) {

                    throw MiniDriverException( SCARD_E_NO_SMARTCARD );
                }
                boost::shared_ptr< Marshaller::StringArray > f( m_CardModule->getFiles( (std::string*)&a_stDirectory ) );

                // Fill the cache with the list of the files of this directory
                size_t l = f->GetLength( );

                // Create a new list of this directory files
                FILES_NAME fs;

                // Populate the list of files
                for( u4 i = 0; i < l ; ++i ) {

                    fs.insert( *(f->GetStringAt( i )) );
                }

                // Register the list of files into the list of directory
                m_Directories[ a_stDirectory ] = fs;

                break;

            } catch( MiniDriverException& x ) {

                Log::error( "MiniDriverFiles::enumFiles", "getFiles failed" );

                unsigned long ulError = x.getError( );
                if ( SCARD_E_NO_MEMORY == ulError ) {

                    // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                    // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                    // be re-tried with high chance of success.
                    if( ntry >= MAX_RETRY ) {

                        throw MiniDriverException( SCARD_E_NO_MEMORY );
                    }

                } else {

                    throw MiniDriverException( x );
                }
            }
        } 
    }

    // Log
    std::string msg = "";
    BOOST_FOREACH( const std::string& s, m_Directories[ a_stDirectory ] ) {

        msg += s;
        msg += " ";
    }
    Log::log( "MiniDriverFiles::enumFiles - path <%s> (Read from %s) - data <%s>", a_stDirectory.c_str( ), stFrom.c_str( ), msg.c_str( ) );

    t.stop( "MiniDriverFiles::enumFiles" );
    Log::end( "MiniDriverFiles::enumFiles" );

    return m_Directories[ a_stDirectory ];
}


/* clearCache
Remove elements from the cache according the required type
*/
void MiniDriverFiles::clear( const MiniDriverCardCacheFile::ChangeType& a_ChangeType ) {

    if( MiniDriverCardCacheFile::NONE == a_ChangeType ) {

        return;
    }

    // ??? TO DO ???
    if( MiniDriverCardCacheFile::PINS == a_ChangeType ) {
        
        return;
    }

    if( MiniDriverCardCacheFile::FILES == a_ChangeType ) {

        m_BinaryFiles.clear( );

        m_Directories.clear( );
    }

    if( MiniDriverCardCacheFile::CONTAINERS == a_ChangeType ) {

        std::string s( szCONTAINER_MAP_FILE );
        m_BinaryFiles.erase( s );

        m_ContainerMapFile.clear( );

        m_ContainerMapFile.containerRead( );
    }
}


/*
*/
void MiniDriverFiles::createDirectory( const std::string& a_stDirectoryParent, const std::string& a_stDirectory ) {

    Log::begin( "MiniDriverFiles::createDirectory" );
    Log::log( "MiniDriverFiles::createDirectory - Directory <%s>", a_stDirectory.c_str( ) );
    Timer t;
    t.start( );

    if( !m_CardModule ) {

        throw MiniDriverException( SCARD_E_NO_SMARTCARD );
    }

    // Add first the current directory as a file owned by its parent directory
    DIRECTORIES::const_iterator iteratorDirectoryParent = m_Directories.find( a_stDirectoryParent );
    
    if( iteratorDirectoryParent != m_Directories.end( ) ) {

        ((FILES_NAME*)iteratorDirectoryParent->second)->insert( a_stDirectory );
    }

    // Add the current directory as also a stand alone directory
    DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );

    if( i == m_Directories.end( ) ) {

        Marshaller::u1Array ac( 3 );

        // Administrator access condition
        ac.GetBuffer( )[ 0 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;

        // User access condition
        ac.GetBuffer( )[ 1 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;

        // Everyone access condition
        ac.GetBuffer( )[ 2 ] = CARD_PERMISSION_READ;

        // Create directory into the smart card
        int ntry = 0;
        while( ntry < MAX_RETRY ) {

            try {

                ntry++;

                // Create directory into the smart card
                if( !m_CardModule ) {

                    throw MiniDriverException( SCARD_E_NO_SMARTCARD );
                }
                m_CardModule->createDirectory( (std::string*)&a_stDirectory, &ac );

                break;

            } catch( MiniDriverException& x ) {

                Log::error( "MiniDriverFiles::createDirectory", "createDirectory failed" );

                unsigned long ulError = x.getError( );
                if ( SCARD_E_NO_MEMORY == ulError ) {

                    // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                    // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                    // be re-tried with high chance of success.
                    if( ntry >= MAX_RETRY ) {

                        throw MiniDriverException( SCARD_E_NO_MEMORY );
                    }

                } else {

                    throw MiniDriverException( x );
                }
            }
        }

        // Add the directory into the directory cache
        std::string s = a_stDirectory;
        m_Directories.insert( s, new FILES_NAME );

        // Update the minidriver cache file
        m_CardCacheFile.notifyChange( MiniDriverCardCacheFile::FILES );
    }

    t.stop( "MiniDriverFiles::createDirectory" );
    Log::end( "MiniDriverFiles::createDirectory" );
}


/*
*/
void MiniDriverFiles::createFile( const std::string& a_stDirectory, const std::string& a_stFile, Marshaller::u1Array* a_pAccessConditions ) {

    Log::begin( "MiniDriverFiles::createFile" );
    Log::log( "MiniDriverFiles::createFile - Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) );
    Timer t;
    t.start( );


    // Build the full file path
    std::string sFilePath = a_stDirectory + s_stPathSeparator + a_stFile;

    // Create the file into the smart card file structure
    int ntry = 0;
    while( ntry < MAX_RETRY ) {

        try {

            ntry++;

            // Create the file into the smart card file structure
            if( !m_CardModule ) {

                throw MiniDriverException( SCARD_E_NO_SMARTCARD );
            }
            m_CardModule->createFile( (std::string*)&sFilePath, a_pAccessConditions, 0 );

            break;

        } catch( MiniDriverException& x ) {

            Log::error( "MiniDriverFiles::createFile", "createFile failed" );

            unsigned long ulError = x.getError( );

            if ( SCARD_E_NO_MEMORY == ulError ) {

                // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                // be re-tried with high chance of success.
                if( ntry >= MAX_RETRY ) {

                    throw MiniDriverException( SCARD_E_NO_MEMORY );
                }

            } else {

                throw MiniDriverException( x );
            }
        }
    }

    // Add the file into the directory cache
    DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );
    if( i != m_Directories.end( ) ) {

        ((FILES_NAME*)i->second)->insert( a_stFile );

    } else {

        // Add the directory into the directory cache
        std::string s = a_stDirectory;
        m_Directories.insert( s, new FILES_NAME );

        // Add the file into the directory
        DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );
        ((FILES_NAME*)i->second)->insert( a_stFile );
    }

    // Prepare the binary file content
    Marshaller::u1Array* f = new Marshaller::u1Array( 0 );

    FILES_BINARY::iterator filesIterator = m_BinaryFiles.find( a_stFile );

    if( filesIterator == m_BinaryFiles.end( ) ) {
    
        // Add the new file to the cache
        std::string stFile = a_stFile;
        m_BinaryFiles.insert( stFile, f );
    
    } else {
    
        // Update the new file to the cache
        m_BinaryFiles[ a_stFile ] = *f;
    }

    // Update the minidriver cache file
    m_CardCacheFile.notifyChange( MiniDriverCardCacheFile::FILES );

    t.stop( "MiniDriverFiles::createFile" );
    Log::end( "MiniDriverFiles::createFile" );
}


/*
*/
void  MiniDriverFiles::deleteFile( const std::string& a_stDirectory, const std::string& a_stFile ) { 

    Log::begin( "MiniDriverFiles::deleteFile" );
    Log::log( "MiniDriverFiles::deleteFile - Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) );
    Timer t;
    t.start( );

    if( a_stFile.empty( ) ) {
    
        Log::error( "MiniDriverFiles::deleteFile", "no file name supplied" );
        return;
    }

    std::string s = a_stDirectory + s_stPathSeparator + a_stFile; 

    int ntry = 0;
    while( ntry < MAX_RETRY ) {

        try {

            ntry++;

            if( !m_CardModule ) {

                throw MiniDriverException( SCARD_E_NO_SMARTCARD );
            }
            m_CardModule->deleteFile( (std::string*)&s ); 

            break;

        } catch( MiniDriverException& x ) {

            Log::error( "MiniDriverFiles::deleteFile", "deleteFile failed" );

            unsigned long ulError = x.getError( );

            if ( SCARD_E_NO_MEMORY == ulError ) {

                // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                // be re-tried with high chance of success.
                if( ntry >= MAX_RETRY ) {

                    throw MiniDriverException( SCARD_E_NO_MEMORY );
                }

            } else {

                throw MiniDriverException( x );
            }
        }
    }

    // Delete the file from the directory cache
    DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );
    
    if( i != m_Directories.end( ) ) {
        
        if( i->second ) {
        
            ((FILES_NAME*)i->second)->erase( a_stFile );
        }
    }

    // Delete the file from the binary file cache
    m_BinaryFiles.erase( a_stFile ); 

    for( std::vector< std::string >::iterator it = m_FilesToNotCache.begin( ); it != m_FilesToNotCache.end( ) ; ++it ) {

        if( 0 == (*it).compare( a_stFile ) ) {
        
            m_FilesToNotCache.erase( it );
            break;
        }
    }

    // Update the minidriver cache file
    m_CardCacheFile.notifyChange( MiniDriverCardCacheFile::FILES );

    t.stop( "MiniDriverFiles::deleteFile" );
    Log::end( "MiniDriverFiles::deleteFile" );
}


/*
*/
void MiniDriverFiles::deleteFileStructure( void ) {

    Log::begin( "MiniDriverFiles::deleteFileStructure" );
    Timer t;
    t.start( );

    std::string stCMapFile( szCONTAINER_MAP_FILE );
    std::string stPath = "";
    FILES_NAME fs = enumFiles( s_stPathMscp ); 
    BOOST_FOREACH( const std::string& f, fs ) {

        if( 0 == f.compare( stCMapFile ) ) {

            continue;
        }

        deleteFile( s_stPathMscp, f );
    }

    t.stop( "MiniDriverFiles::deleteFileStructure" );
    Log::end( "MiniDriverFiles::deleteFileStructure" );
}


/*
*/
void MiniDriverFiles::certificateDelete( unsigned char& a_ucContainerIndex ) {

    Log::begin( "MiniDriver::certificateDelete" );
    Timer t;
    t.start( );

    // Get the container information
    MiniDriverContainer c = containerGet( a_ucContainerIndex );

    if( c.empty( ) ) {

        throw MiniDriverException( SCARD_E_NO_SUCH_CERTIFICATE );
    }

    // Build the certificate name to associate it to the container 
    std::string stCertificateName = ( c.getKeyExchangeSizeBits( ) ? std::string ( szUSER_KEYEXCHANGE_CERT_PREFIX ) : std::string( szUSER_SIGNATURE_CERT_PREFIX ) );
    Util::toStringHex( a_ucContainerIndex, stCertificateName );

    // Delete the file
    deleteFile( std::string( szBASE_CSP_DIR ) , stCertificateName );

    t.stop( "MiniDriver::certificateDelete" );
    Log::end( "MiniDriver::certificateDelete" );
}


/*
*/
bool MiniDriverFiles::containerGetMatching( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const Marshaller::u1Array* a_pPublicKeyModulus ) {

    bool bRet = m_ContainerMapFile.containerGetMatching( a_ucContainerIndex, a_ucKeySpec, a_pPublicKeyModulus );

    // Build the public key name to associate it to the container 
    if( bRet ) {

        // Add the same as associated certificate prefix
        a_stFileName = ( a_ucKeySpec ? std::string ( szUSER_KEYEXCHANGE_CERT_PREFIX ) : std::string( szUSER_SIGNATURE_CERT_PREFIX ) );

        // Add the index
        Util::toStringHex( a_ucContainerIndex, a_stFileName );
    }

    return bRet;
}


/*
*/
void MiniDriverFiles::renameFile( const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName ) {

    // First read the old file
    Marshaller::u1Array* p = readFile( a_stOldFileDirectory, a_stOldFileName );

    // Compute the access conditions for the new file
    Marshaller::u1Array ac( 3 );

    // Administrator access condition
    ac.GetBuffer( )[ 0 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;

    // User access condition
    ac.GetBuffer( )[ 1 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;

    // Everyone access condition
    ac.GetBuffer( )[ 2 ] = CARD_PERMISSION_READ;

    // Create the new file
    createFile( a_stNewFileDirectory, a_stNewFileName, &ac );

    // Write the new file
    writeFile( a_stNewFileDirectory, a_stNewFileName, p );

    // Delete the old file
  	deleteFile( a_stOldFileDirectory, a_stOldFileName );
}


void MiniDriverFiles::print( void ) {

    Log::begin( "MiniDriverFiles::print" );

    m_ContainerMapFile.print( );
    
    std::string stFileContent;
    for( FILES_BINARY::const_iterator i = m_BinaryFiles.begin( ) ; i != m_BinaryFiles.end( ) ; ++i ) {
    
        stFileContent = "";
        Log::toString( i->second->GetBuffer( ), i->second->GetLength( ), stFileContent );
        Log::log( "Binary files <%s> <%s>", i->first.c_str( ), stFileContent.c_str( ) );
    }

    std::string s = "";
    for( DIRECTORIES::const_iterator i = m_Directories.begin( ) ; i != m_Directories.end( ) ; ++i ) {
        s = "";
        for( FILES_NAME::iterator j = i->second->begin( ); j != i->second->end( ); ++j ) {
            s += *j;
            s += " ";
        }
        Log::log( "Directories <%s> - Files <%s>", i->first.c_str( ), s.c_str( ) );
    }

    m_CardCacheFile.print( );
    s = "";
    for( std::vector< std::string >::const_iterator i = m_FilesToNotCache.begin( ) ; i != m_FilesToNotCache.end( ) ; ++i ) {
    
        s += (*i);
        s += " ";
    }
    Log::log( "FilesToNotCache <%s>", s.c_str( ) );

    Log::end( "MiniDriverFiles::print" );
}


/*
*/
unsigned char MiniDriverFiles::containerGetFreeRoot( void ) {

    // Scan the mscp directory to find a free root index
    std::string a_stDirectory( szBASE_CSP_DIR );

    MiniDriverFiles::FILES_NAME f = enumFiles( a_stDirectory );

    unsigned char ucContainerMax = m_ContainerMapFile.containerCount( );

    unsigned char ucIndexMax = 0;
    
    unsigned char ucIndexCourant = 0;

    BOOST_FOREACH( const std::string& v, f ) {
    
        if( v.substr( 0, 3).compare( "kxc" ) ) {
        
            continue;
        }

        ucIndexCourant = computeIndex( v );

        if( ucIndexCourant > ucIndexMax ) {
         
            ucIndexMax = ucIndexCourant;
        }
    }

    if( ucIndexMax <= ucContainerMax ) {

        ucIndexMax = ucContainerMax;
    }
    ++ucIndexMax;

    return ucIndexMax;
}


/*
*/
unsigned char MiniDriverFiles::computeIndex( const std::string& a_stFileName ) {

    // Get the container index set into the file name
    unsigned char h1 = a_stFileName[ a_stFileName.length( ) - 2 ];
    unsigned char h2 = a_stFileName[ a_stFileName.length( ) - 1 ];

    unsigned char a = ( ( h1 >= 0x41 ) ? ( h1 - 0x41 + 10 ) : ( h1 - 0x30 ) ) * 16;
    unsigned char b = ( h2 >= 0x41 ) ? ( h2 - 0x41 + 10 ) : ( h2 - 0x30 );

    unsigned char ucKeyContainerIndexInFileName = a + b;

    return ucKeyContainerIndexInFileName;
}


/*
*/
Marshaller::u1Array* MiniDriverFiles::readFileWithoutCheck( const std::string& a_stDirectory, const std::string& a_stFile ) {

    Log::begin( "MiniDriverFiles::readFileWithoutCheck" );
    Log::log( "MiniDriverFiles::readFileWithoutCheck - Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) );
    Timer t;
    t.start( );

    Marshaller::u1Array* f = NULL;

    int ntry = 0;

    std::string stPath = a_stDirectory + s_stPathSeparator + a_stFile;
    if( a_stDirectory.empty( ) ) {

        stPath = a_stFile;
    }

    while( ntry < MAX_RETRY ) {

        try {

            ntry++;

            if( !m_CardModule ) {

                throw MiniDriverException( SCARD_E_NO_SMARTCARD );
            }

            f = m_CardModule->readFileWithoutMemoryCheck( (std::string*)&stPath );
            
            break;

        } catch( MiniDriverException& x ) {

            Log::error( "MiniDriverFiles::readFileWithoutCheck", "readFile failed" );

            unsigned long ulError = x.getError( );

            if ( SCARD_E_COMM_DATA_LOST == ulError ) {
            
                if( ntry >= MAX_RETRY ) {

                    throw MiniDriverException( SCARD_E_COMM_DATA_LOST );
                }

            } else if ( SCARD_E_NO_MEMORY == ulError ) {

                // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                // be re-tried with high chance of success.
                if( ntry >= MAX_RETRY ) {

                    throw MiniDriverException( SCARD_E_NO_MEMORY );
                }

            } else if( SCARD_E_FILE_NOT_FOUND == ulError ) {

                // Delete the file from the directory cache
                DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );

                if( i != m_Directories.end( ) ) {

                    if( i->second ) {

                        ((FILES_NAME*)i->second)->erase( a_stFile );
                    }
                }

                // Delete the file from the binary file cache
                m_BinaryFiles.erase( a_stFile ); 

                for( std::vector< std::string >::iterator it = m_FilesToNotCache.begin( ); it != m_FilesToNotCache.end( ) ; ++it ) {

                    if( 0 == (*it).compare( a_stFile ) ) {

                        m_FilesToNotCache.erase( it );
                        break;
                    }
                }
            }

            throw MiniDriverException( x );
        }
    }

    // Log
    if( f ) {
    
        std::string s = "";
    
        Log::toString( f->GetBuffer( ), f->GetLength( ), s );
    
        Log::log( "MiniDriverFiles::readFileWithoutCheck - path <%s> - data <%s>", a_stFile.c_str( ), s.c_str( ) );
    }

    t.stop( "MiniDriverFiles::readFileWithoutCheck" );
    Log::end( "MiniDriverFiles::readFileWithoutCheck" );

    return f;
}


/* ReadFile
*/
Marshaller::u1Array* MiniDriverFiles::readFile( const std::string& a_stDirectory, const std::string& a_stFile ) {

    Log::begin( "MiniDriverFiles::readFile" );
    Log::log( "MiniDriverFiles::readFile - Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) );
    Timer t;
    t.start( );

    // Log
    std::string stFrom = "cache"; 

    FILES_BINARY::const_iterator i = m_BinaryFiles.find( a_stFile );

    if( i == m_BinaryFiles.end( ) ) {

        //Log
        stFrom = "!! CARD !!"; 

        int ntry = 0;

        std::string stPath = a_stDirectory + s_stPathSeparator + a_stFile;

        while( ntry < MAX_RETRY ) {

            try {

                ntry++;

                 if( !m_CardModule ) {

                    throw MiniDriverException( SCARD_E_NO_SMARTCARD );
                }
               Marshaller::u1Array* f = m_CardModule->readFile( (std::string*)&stPath );

                // Store the binary file content
                FILES_BINARY::iterator filesIterator = m_BinaryFiles.find( a_stFile );

                if( filesIterator == m_BinaryFiles.end( ) ) {
    
                    // Add the new file to the cache
                    std::string stFile = a_stFile;
                    m_BinaryFiles.insert( stFile, f );
    
                } else {
    
                    // Update the new file to the cache
                    m_BinaryFiles[ a_stFile ] = *f;
                }

                break;

            } catch( MiniDriverException& x ) {

                Log::error( "MiniDriverFiles::readFile", "readFile failed" );

                unsigned long ulError = x.getError( );
            if ( SCARD_E_COMM_DATA_LOST == ulError ) {
            
                if( ntry >= MAX_RETRY ) {

                    throw MiniDriverException( SCARD_E_COMM_DATA_LOST );
                }

            } else if ( SCARD_E_NO_MEMORY == ulError ) {

                    // V2+ cards may throw OutOfMemoryException from ReadFile, however it may recover from this by forcing the garbage collection to
                    // occur. In fact as a result of a ReadFile command that throws OutOfMemoryException, GC has already occured, so the command may
                    // be re-tried with high chance of success.
                    if( ntry >= MAX_RETRY ) {

                        throw MiniDriverException( SCARD_E_NO_MEMORY );
                    }

                } else {

                    if( SCARD_E_FILE_NOT_FOUND == ulError ) {
                    
                        // Delete the file from the directory cache
                        DIRECTORIES::const_iterator i = m_Directories.find( a_stDirectory );
    
                        if( i != m_Directories.end( ) ) {
        
                            if( i->second ) {
        
                                ((FILES_NAME*)i->second)->erase( a_stFile );
                            }
                        }

                        // Delete the file from the binary file cache
                        m_BinaryFiles.erase( a_stFile ); 

                        for( std::vector< std::string >::iterator it = m_FilesToNotCache.begin( ); it != m_FilesToNotCache.end( ) ; ++it ) {

                            if( 0 == (*it).compare( a_stFile ) ) {
        
                                m_FilesToNotCache.erase( it );
                                break;
                            }
                        }
                    }

                    throw MiniDriverException( x );
                }
            }
        }
    }

    // Log
    std::string s = "";
    Log::toString( m_BinaryFiles[ a_stFile ].GetBuffer( ), m_BinaryFiles[ a_stFile ].GetLength( ), s );
    Log::log( "MiniDriverFiles::readFile - path <%s> (Read from %s) - data <%s>", a_stFile.c_str( ), stFrom.c_str( ), s.c_str( ) );

    t.stop( "MiniDriverFiles::readFile" );
    Log::end( "MiniDriverFiles::readFile" );

    return &m_BinaryFiles[ a_stFile ];
}
