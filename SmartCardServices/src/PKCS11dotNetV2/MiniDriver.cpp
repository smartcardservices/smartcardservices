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


#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/shared_array.hpp>
#include <boost/foreach.hpp>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include "MiniDriver.hpp"
#include "Log.hpp"
#include "Except.h"
#include "MiniDriverException.hpp"
#include "util.h"
#include "zlib.h"
#include "SmartCardReader.hpp"
#ifdef WIN32 
#include <shlobj.h> // For SHGetFolderPath
#else
#endif
#include <fstream>

#include "PCSCMissing.h"


const unsigned MiniDriver::s_iMinLengthKeyRSA = 512;
const unsigned MiniDriver::s_iMaxLengthKeyRSA = 2048;

#define BLOCK_SIZE 1024


/*
*/
void MiniDriver::read( const bool& a_bEnableCache ) {

    Log::begin( "MiniDriver::read" );
    Timer t;
    t.start( );

    m_bEnableCache = a_bEnableCache;

    try {

        // Read the smart card serial number
        getSerialNumber( );
        
        if( !m_u1aSerialNumber ) {
        
            m_stFileName = "";

            m_bEnableCache = false;
        }

		if( m_bEnableCache ) {

#ifdef WIN32 

        // For each user (roaming) data, use the CSIDL_APPDATA value. 
        // This defaults to the following path: "\Documents and Settings\All Users\Application Data" 
        TCHAR szPath[MAX_PATH];

        SHGetFolderPath( NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, szPath );

        std::string stCacheDirectoryPath = std::string( szPath ) + std::string( "/Gemalto/DotNet PKCS11" );

#else
		char *home = getenv( "HOME" );
		std::string stCacheDirectoryPath;
		if (home)
			stCacheDirectoryPath = std::string(home) + std::string( "/.cache/Gemalto/DotNet PKCS11/" );
		else
			stCacheDirectoryPath = std::string( "/tmp/Gemalto/DotNet PKCS11/" );
#endif
			
			boost::filesystem::path cacheDirectoryPath( stCacheDirectoryPath );
			
			if( ! boost::filesystem::exists( cacheDirectoryPath ) ) {

				try {

					boost::filesystem::create_directories( cacheDirectoryPath );
				
                } catch (...) {
				
                    std::string msg = "";

                    Log::toString( msg, "Cache directory creation failed <%s>", stCacheDirectoryPath.c_str( ) );
                    
                    Log::error( "MiniDriver::read", msg.c_str( ) );

                    m_bEnableCache = false;
				}
			}
			
            if( m_bEnableCache ) {

			    // Build the cache file name
			    std::string stCacheFileName = "";

			    toString( m_u1aSerialNumber->GetBuffer( ), m_u1aSerialNumber->GetLength( ), stCacheFileName );
			    
                stCacheFileName += std::string( ".p11" );
			
			    m_stFileName = stCacheDirectoryPath + std::string( "/" ) + stCacheFileName;
			    
                Log::log( "MiniDriver::read - Cache file <%s>", m_stFileName.c_str( ) );
			
			    // Read the cache from the disk
			    cacheDeserialize( );
            }
		}

        MiniDriverCardCacheFile::ChangeType p = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType c = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType f = MiniDriverCardCacheFile::NONE;
        m_Files.hasChanged( p, c, f );

        m_Authentication.read( );

    } catch( ... ) {

		Log::log("MiniDriver::read - Exception");
    }

    t.stop( "MiniDriver::read" );
    Log::end( "MiniDriver::read" );
}


/* Store the files, the file list and the containers into a disk file
*/
void MiniDriver::cacheSerialize( void ) {

    // Cache enabled/disbled
    if( !m_bEnableCache ) {

        return;
    }

    // Name of the cache
    if( m_stFileName.empty( ) ) {

        return;
    }

    //m_Files.print( );
    //m_Authentication.print( );

    m_Files.cacheDisableWrite( );

    Log::begin( "MiniDriver::cacheSerialize" );
    Timer t;
    t.start( );

    std::ofstream ofs( m_stFileName.c_str( ), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc );

    if( ofs.is_open( ) ) {

        // Write class instance to archive. Writing seems to work ok.
        boost::archive::text_oarchive oa( ofs );

        const MiniDriver& m = (MiniDriver&)*this;

        oa << m;

        ofs.flush( );

        ofs.close( );
    }

    boost::crc_32_type::value_type computedValue = 0;
    
    std::ifstream ifs( m_stFileName.c_str( ), std::ios::in | std::ios::binary );
    
    if( ifs.is_open( ) ) {

        // Get the length of the file
        ifs.seekg( 0, std::ios::end );
        
        unsigned int l = (unsigned int)ifs.tellg( );

        // Read the whole file
        ifs.seekg( 0, std::ios::beg );
        
        std::auto_ptr< char > p( new char[ l ] );
        
        ifs.read( p.get( ), l );

        // Compute the CRC of the file
        boost::crc_32_type computedCRC; 
        
        computedCRC.process_bytes( p.get( ), l );
        
        computedValue = computedCRC.checksum( ); 

        ifs.close( );
    }

    // Add the CRC to the file
    ofs.open( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

    if( ofs.is_open( ) ) {

        ofs.seekp( 0, std::ios::end );
        
        //ofs << computedValue;
        ofs.write( (char*)&computedValue, sizeof( computedValue ) );

        ofs.flush( );

        ofs.close( );
    }

    //m_Files.print( );
    //m_Authentication.print( );

    t.stop( "MiniDriver::cacheSerialize" );
    Log::end( "MiniDriver::cacheSerialize" );
}


/* Load the files, the file list and the containers from a disk file
*/
void MiniDriver::cacheDeserialize( void ) {

    if( !m_bEnableCache ) {
        return;
    }

    if( m_stFileName.empty( ) ) {
        return;
    }

    Log::begin( "MiniDriver::cacheDeserialize" );
    Timer t;
    t.start( );

    boost::crc_32_type::value_type readValue = 0; 

    std::ifstream ifs( m_stFileName.c_str( ), std::ios::in | std::ios::binary );

    if( ifs.is_open( ) ) {

        try {

			boost::archive::text_iarchive ia( ifs );

			MiniDriver& m = (MiniDriver&)*this;

            // Read the cache from the file
            ia >> m;

            // Read the CRC from the file
            ifs.seekg( 0, std::ios::end );
            unsigned int l = (unsigned int)ifs.tellg( ) - 4;
            ifs.seekg( l, std::ios::beg );

            ifs.read( (char*)&readValue, sizeof( readValue ) );

            ifs.close( );
        
        } catch( ... ) {
        
            Log::error( "MiniDriver::cacheDeserialize", "deserialization failed" );

            m_Files.clear( MiniDriverCardCacheFile::PINS );
            m_Files.clear( MiniDriverCardCacheFile::FILES );
            m_Files.clear( MiniDriverCardCacheFile::CONTAINERS );
                       
            ifs.close( );

            std::remove( m_stFileName.c_str( ) );
        }
    }

    // Compute the CRC of the file
    boost::crc_32_type::value_type computedValue = 0;
    
    ifs.open( m_stFileName.c_str( ), std::ios::in | std::ios::binary );
    
    if( ifs.is_open( ) ) {

        // Get the length of the file
        ifs.seekg( 0, std::ios::end );
        
        unsigned int l = (unsigned int)ifs.tellg( ) - 4;

        // Read the whole file
        ifs.seekg( 0, std::ios::beg );
        
        std::auto_ptr< char > p( new char[ l ] );
        
        ifs.read( p.get( ), l );

        // Compute the CRC of the file
        boost::crc_32_type computedCRC; 
        
        computedCRC.process_bytes( p.get( ), l );
        
        computedValue = computedCRC.checksum( ); 

        ifs.close( );
    }

    // Check the both CRC
    if( computedValue != readValue ) {
    
        // Clear the cache
        m_Files.clear( MiniDriverCardCacheFile::PINS );

        m_Files.clear( MiniDriverCardCacheFile::FILES );
        
        m_Files.clear( MiniDriverCardCacheFile::CONTAINERS );

        // Remove the cache file
        std::remove( m_stFileName.c_str( ) );
    }

    //m_Files.print( );
    //m_Authentication.print( );

    t.stop( "MiniDriver::cacheDeserialize" );
    Log::end( "MiniDriver::cacheDeserialize" );
}


/*
*/
Marshaller::u1Array* MiniDriver::getSerialNumber( void ) {

    Log::begin( "MiniDriver::getSerialNumber" );
    Timer t;
    t.start( );

    if( !m_u1aSerialNumber.get( ) ) {

        try {

            // Read the cardid file containing a unique 16-byte binary identifier for the smart card (GUID).
            std::string s( szCARD_IDENTIFIER_FILE );

            //std::auto_ptr< Marshaller::u1Array > f( m_CardModule->readFile( &s ) );
            
            std::string stDirectory;

            std::auto_ptr< Marshaller::u1Array > f( m_Files.readFileWithoutCheck( stDirectory, s ) );
            
            // Get the 12th last bytes as serial number
            m_u1aSerialNumber.reset( new Marshaller::u1Array( *f, 4, 12 ) );
            
            
            Log::logCK_UTF8CHAR_PTR( "MiniDriver::getSerialNumber - Serial number", m_u1aSerialNumber->GetBuffer( ), m_u1aSerialNumber->GetLength( ) );
            
        } catch( MiniDriverException& ) {
        
            int i = 0;
        }

        //// Try first to load the serial number in a V2+ way
        //try {

        //    m_u1aSerialNumber.reset( m_CardModule->getCardProperty( CARD_SERIAL_NUMBER, 0 ) );

        //    Log::log( "MiniDriver::getSerialNumber - GetCardProperty" );

        //} catch( MiniDriverException& ) {

        //    Log::error( " MiniDriver::getSerialNumber", "No card property for the serial number" );

        //    try {

        //        // Try at last to get the serial number in a old V2 way
        //        m_u1aSerialNumber.reset( m_CardModule->getSerialNumber( ) );

        //        Log::log( "MiniDriver::getSerialNumber - getSerialNumber" );

        //    } catch( ... ) {

        //        Log::error( " MiniDriver::getSerialNumber", "Impossible to get the serial number" );
        //    }
        //}
    }

    t.stop( "MiniDriver::getSerialNumber" );
    Log::end( "MiniDriver::getSerialNumber" );

    return m_u1aSerialNumber.get( );
}


/*
*/
void MiniDriver::createFile(  const std::string& a_stDirectory, const std::string& a_stFile, const bool& a_bIsReadProtected ) {

    Log::begin( "MiniDriver::createFile" );
    Timer t;
    t.start( );

    Marshaller::u1Array ac( 3 );

    // Administrator access condition
    ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // User access condition
    ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // Everyone access condition
    ac.GetBuffer( )[ 2 ] = ( a_bIsReadProtected ? 0 : MiniDriverFiles::CARD_PERMISSION_READ );

    m_Files.createFile( a_stDirectory, a_stFile, &ac );

    cacheSerialize( );

    t.stop( "MiniDriver::createFile" );
    Log::end( "MiniDriver::createFile" );
}


/* If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
The keyspec will also be updated. The file name will anyway build automaticaly
*/
void MiniDriver::createCertificate( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stCertificateName, Marshaller::u1Array* a_pValue, Marshaller::u1Array* a_pModulus, const bool& a_bSmartCardLogon ) {

    Log::begin( "MiniDriver::createCertificate" );
    Timer t;
    t.start( );

    a_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    // Try to find a container using the same public key modulus. 
    // In this case the index & the key spec are updated and must be used.
    m_Files.containerGetMatching( a_ucContainerIndex, a_ucKeySpec, a_stCertificateName, a_pModulus );

    // No existing container uses that public key modulus. 
    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_ucContainerIndex ) {

        // Find an empty container
        m_Files.containerSearch( a_ucContainerIndex );

        // No empty container 
        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_ucContainerIndex ) {

            throw MiniDriverException( SCARD_E_WRITE_TOO_MANY );
        }
    }

    // Build the certificate name to associate it to the container 
    a_stCertificateName = ( MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec ) ? std::string( szUSER_KEYEXCHANGE_CERT_PREFIX ) : std::string( szUSER_SIGNATURE_CERT_PREFIX );
    Util::toStringHex( a_ucContainerIndex, a_stCertificateName );

    // compress the certificate
    unsigned long ccLen = a_pValue->GetLength( );

    boost::shared_array< unsigned char > cc( new unsigned char[ ccLen + 4 ] );
    cc[ 0 ] = 0x01;
    cc[ 1 ] = 0x00;
    cc[ 2 ] = (BYTE)( ccLen & 0xff ); // Put the low byte of the word
    cc[ 3 ] = (BYTE)( ( ccLen & 0xff00 ) >> 8 ); // Put the high byte of the word

    // Set compression level at 6, same as Minidriver
    compress2( (unsigned char*)&cc[ 4 ], &ccLen, a_pValue->GetBuffer( ), ccLen, 6 );

    Marshaller::u1Array compressedCert( ccLen + 4 );

    compressedCert.SetBuffer( cc.get( ) );

    Marshaller::u1Array ac( 3 );

    // Administrator access conditions
    ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // User access conditions
    ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // Everyone access conditions
    ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

    m_Files.createFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &ac );

    m_Files.writeFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &compressedCert );

    // Set the default certificate
    m_Files.containerSetDefault( a_ucContainerIndex, a_bSmartCardLogon );

    cacheSerialize( );

    t.stop( "MiniDriver::createCertificate" );
    Log::end( "MiniDriver::createCertificate" );
}


/*
*/
void MiniDriver::readCertificate( const std::string& a_stFile, boost::shared_ptr< Marshaller::u1Array >& a_pCertificateValue ) {

    Log::begin( "MiniDriver::readCertificate" );
    Timer t;
    t.start( );

    // Read certificate file
    Marshaller::u1Array* pCompressedCertificate = m_Files.readFile( std::string( szBASE_CSP_DIR ), a_stFile );

    // Decompress the certificate
    unsigned long ulOrigLen = pCompressedCertificate->ReadU1At( 3 ) * 256 + pCompressedCertificate->ReadU1At( 2 );

    a_pCertificateValue.reset( new Marshaller::u1Array( ulOrigLen ) );

    uncompress( a_pCertificateValue->GetBuffer( ), &ulOrigLen, pCompressedCertificate->GetBuffer( ) + 4, pCompressedCertificate->GetLength( ) - 4 );

    t.stop( "MiniDriver::readCertificate" );
    Log::end( "MiniDriver::readCertificate" );
}


/*
*/
void MiniDriver::createCertificateRoot( std::string& a_stCertificateName, Marshaller::u1Array* a_pValue ) {

    Log::begin( "MiniDriver::createCertificateRoot" );
    Timer t;
    t.start( );

    // Try to find a free container index out of the range of the containers managed by the MniDriver
    unsigned char ucContainerIndex = m_Files.containerGetFreeRoot( );

    // Build the certificate name to associate it to the container 
    a_stCertificateName = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
    Util::toStringHex( ucContainerIndex, a_stCertificateName );

    // compress the certificate
    unsigned long ccLen = a_pValue->GetLength( );

    boost::shared_array< unsigned char > cc( new unsigned char[ ccLen + 4 ] );
    cc[ 0 ] = 0x01;
    cc[ 1 ] = 0x00;
    cc[ 2 ] = (BYTE)( ccLen & 0xff ); // Put the low byte of the word
    cc[ 3 ] = (BYTE)( ( ccLen & 0xff00 ) >> 8 ); // Put the high byte of the word

    // Set compression level at 6, same as Minidriver
    compress2( (unsigned char*)&cc[ 4 ], &ccLen, a_pValue->GetBuffer( ), ccLen, 6 );

    Marshaller::u1Array compressedCert( ccLen + 4 );

    compressedCert.SetBuffer( cc.get( ) );

    Marshaller::u1Array ac( 3 );

    // Administrator access conditions
    ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // User access conditions
    ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    // Everyone access conditions
    ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

    m_Files.createFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &ac );

    m_Files.writeFile( std::string( szBASE_CSP_DIR ), a_stCertificateName, &compressedCert );

    cacheSerialize( );
    
    //std::string stPathCertificateRoot( szROOT_STORE_FILE );
    //std::auto_ptr< Marshaller::u1Array > pRoots;

    //try {

    //    pRoots.reset( m_Files.readFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot ) );
    //
    //} catch( ... ) {
    //
    //    // The msroot file does not exist. Create it.

    //     Marshaller::u1Array ac( 3 );

    //    // Administrator access conditions
    //    ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    //    // User access conditions
    //    ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

    //    // Everyone access conditions
    //    ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

    //   m_Files.createFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot, &ac );
    //}

    //unsigned char ucIndex = 0;

    //// Parse the msroot file to get the index of the new root certificate to insert
    //if( *pRoots ) {
    //
    //    unsigned int uiSize = pRoots->GetLength( );

    //    unsigned int uiOffset = 4;

    //    while( uiOffset < uiSize ) {

    //        unsigned char ucTagP7 = pRoots->ReadU1At( uiOffset );
    //        unsigned char ucTagSize = pRoots->ReadU1At( uiOffset + 1 );
    //        unsigned int uiSize = 0;
    //        if( 0x80 == ucTagSize ) {
    //        
    //            uiSize = pRoots->ReadU1At( uiOffset + 2 );
    //        
    //        } else if( 0x82 == ucTagSize ) {
    //        
    //            uiSize = pRoots->ReadU1At( uiOffset + 2 ) * 256 + pRoots->ReadU1At( uiOffset + 3 );
    //        }

    //        ++ucIndex;
    //    }
    //}

    //// Compute the root certificate index file
    //    Util::toStringHex( ucIndex, a_stCertificateName );


    //// Prepare the new msroot file


    //// compress the certificate
    //unsigned long ccLen = a_pValue->GetLength( );

    //boost::shared_array< unsigned char > cc( new unsigned char[ ccLen + 4 ] );
    //cc[ 0 ] = 0x01;
    //cc[ 1 ] = 0x00;
    //cc[ 2 ] = (BYTE)( ccLen & 0xff ); // Put the low byte of the word
    //cc[ 3 ] = (BYTE)( ( ccLen & 0xff00 ) >> 8 ); // Put the high byte of the word

    //// Set compression level at 6, same as Minidriver
    //compress2( (unsigned char*)&cc[ 4 ], &ccLen, a_pValue->GetBuffer( ), ccLen, 6 );

    //Marshaller::u1Array compressedCert( ccLen + 4 );

    //compressedCert.SetBuffer( cc.get( ) );

    //std::auto_ptr< Marshaller::u1Array > pNewRoots;
    //if( *pRoots ) {
    //
    //    pNewRoots.reset( new Marshaller::u1Array( compressedCert.GetLength( ) + pRoots->GetLength( ) ) );

    //    pNewRoots += compressedCert;

    //} else {
    //
    //    // Populate the msroots file for the first time.
    //    // The msroots file structure that you need to follow:
    //    // [01 00]
    //    // [2 bytes] - the lengths of the following data
    //    // [data]
    //    // where [data]  = [compressed PKCS7 empty signature of certificates]
    //    // The compression algo is ZLIB. The msroots file store all the intermediate and root certificates.

    //    pNewRoots.reset( new Marshaller::u1Array( compressedCert.GetLength( ) + 4 ) );
    //    pNewRoots->SetU1At( 0, 0x01 );
    //    pNewRoots->SetU1At( 1, 0x00 );
    //    unsigned int iSize = compressedCert.GetLength( );
    //    if ( iSize > 0xFF ) {
    //    
    //    } else {

    //        pNewRoots->SetU1At( 2, 0x00 );
    //        pNewRoots->SetU1At( 3, (unsigned char) iSize );
    //    }

    //    pNewRoots += compressedCert;
    //}

    //// Write the msroot file
    //m_Files.writeFile( std::string( szBASE_CSP_DIR ), stPathCertificateRoot, *pNewRoots );

    //cacheSerialize( );

    t.stop( "MiniDriver::createCertificateRoot" );
    Log::end( "MiniDriver::createCertificateRoot" );
}


/*
*/
void MiniDriver::unblockPin( Marshaller::u1Array* a_PinSo, Marshaller::u1Array* a_PinUser ) {

    Log::begin( "MiniDriver::unblockPin" );
    Timer t;
    t.start( );

    m_Authentication.unblockPin( a_PinSo, a_PinUser );

    if( isAuthenticated( ) ) {
    
        // Update the MiniDriver Card Cache File
        m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
    
    } else {

        verifyPin( a_PinUser );
  
        // Update the MiniDriver Card Cache File
        if( !isReadOnly( ) ) {

            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
        }
        logOut( );

        if( administratorIsAuthenticated( ) ) {

            administratorLogin( a_PinSo );
        }
    }
    
    cacheSerialize( );

    t.stop( "MiniDriver::unblockPin" );
    Log::end( "MiniDriver::unblockPin" );
}


/*
*/
void MiniDriver::administratorChangeKey( Marshaller::u1Array* a_OldKey, Marshaller::u1Array* a_NewKey ) {

    Log::begin( "MiniDriver::administratorChangeKey" );
    Timer t;
    t.start( );

    m_Authentication.administratorChangeKey( a_OldKey, a_NewKey );

    //// Update the MiniDriver Card Cache File
    //m_Files.notifyChange( MiniDriverCardCacheFile::PINS );

    cacheSerialize( );

    t.stop( "MiniDriver::administratorChangeKey" );
    Log::end( "MiniDriver::administratorChangeKey" );
}


/*
*/
void MiniDriver::changePin( Marshaller::u1Array* a_pOldPIN, Marshaller::u1Array* a_pNewPIN ) {

    Log::begin( "MiniDriver::changePin" );
    Timer t;
    t.start( );

    m_Authentication.changePin( a_pOldPIN, a_pNewPIN );

        if( isAuthenticated( ) ) {
    
        // Update the MiniDriver Card Cache File
        if( !isReadOnly( ) ) {
        
            m_Files.notifyChange( MiniDriverCardCacheFile::PINS );
        }
    
    } else {

        verifyPin( a_pNewPIN );
  
        // Update the MiniDriver Card Cache File
        m_Files.notifyChange( MiniDriverCardCacheFile::PINS );

        logOut( );
    }

    cacheSerialize( );

    t.stop( "MiniDriver::changePin" );
    Log::end( "MiniDriver::changePin" );
}


/*
*/
void MiniDriver::toString( const unsigned char* buffer, std::size_t size, std::string &result ) {

    if( !buffer || ( size <= 0 ) ) {

        result = "";

        return;
    }

    std::ostringstream oss;

    oss.rdbuf( )->str( "" );

    // Display hexadeciaml uppercase character
    oss << std::hex << std::uppercase;

    // No blank but zero instead
    oss << std::setfill('0');

    for( std::size_t i = 0; i < size; ++i ) {

        oss << std::setw( 2 ) << static_cast< int >( buffer[ i ] );
    }

    result.assign( oss.str( ) );
}


/*
*/
void MiniDriver::setSmartCardReader( SmartCardReader* a_pSmartCardReader ) { 

    if( a_pSmartCardReader ) {

        m_Authentication.setSmartCardReader( a_pSmartCardReader ); 

        const std::string& a_stReaderName = a_pSmartCardReader->getReaderName( ); 

        m_CardModule.reset( new CardModuleService( a_stReaderName ) );

//        bool bFalse = false;
//        m_CardModule->DoTransact( bFalse );

        m_Authentication.setCardModule( m_CardModule.get( ) ); 

        m_Files.setCardModuleService( m_CardModule.get( ) ); 

    }
}
