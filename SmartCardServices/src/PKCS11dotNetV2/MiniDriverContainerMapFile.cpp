/*
*  PKCS#11 library for .Net smart cards
*  Copyright (C) 2007-2009 Gemalto <support@gemalto->com>
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


#include <cstdio>
#include <boost/foreach.hpp>
#include <memory>
#include "cardmod.h"
#include "MiniDriverContainerMapFile.hpp"
#include "MiniDriverFiles.hpp"
#include "Log.hpp"
#include "Timer.hpp"
#include "MiniDriverException.hpp"
#include "sha1.h"
/*
 #ifdef __APPLE__
#include "PCSC/winscard.h"
#else
#include "winscard.h"
#endif
*/

#include "PCSCMissing.h"

const int g_iContainerSize = 0x56; //sizeof( CONTAINER_MAP_RECORD );
unsigned char MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID = 0xFF;
const int CARD_PROPERTY_CONTAINER_TYPE = 0x80;
const int CARD_PROPERTY_PIN_IDENTIFIER = 0x01;


/*
*/
void MiniDriverContainerMapFile::containerRead( void ) {

    Log::begin( "MiniDriverContainerMapFile::containerRead" );
    Timer t;
    t.start( );

    if( !m_MiniDriverFiles ) {
    
        Log::error( "MiniDriverContainerMapFile::containerRead", "Invalid file system object" );
        return;
    }

    CardModuleService* m = m_MiniDriverFiles->getCardModuleService( );

    if( !m ) {
         
        Log::error( "MiniDriverContainerMapFile::containerRead", "Invalid card module service object" );

        return;
    }

    // Reset the stored containers table
    BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

        c.clear( );
    }

    // Read the CMap file
    m_ContainerMapFileBinary.reset( m_MiniDriverFiles->readFile( std::string( szBASE_CSP_DIR ), std::string( szCONTAINER_MAP_FILE ) ) );

    // Populate the container Map records
    unsigned int uiLen = m_ContainerMapFileBinary.GetLength( );

    bool bContainerPresent = false;

    for( unsigned int i = 0 ; i < uiLen ; ++i ) {
    
        if( m_ContainerMapFileBinary.ReadU1At( i ) ) {

            bContainerPresent = true;

            break;
        }
    }

    if( uiLen && bContainerPresent ) {

        unsigned char iContainersCount = ( unsigned char )( uiLen / g_iContainerSize );

        unsigned char* b = m_ContainerMapFileBinary.GetBuffer( );

        for( unsigned char i = 0; i < iContainersCount; ++i ) {
        
            try {

                // Populate the container info (throws if the container is empty)
                boost::shared_ptr< Marshaller::u1Array > ci( m->getContainer( i ) );

                std::string stContainer;
                Log::toString( ci->GetBuffer( ), ci->GetLength( ), stContainer );
                Log::log( "MiniDriverContainerMapFile::containerRead - index <%d> - container <%s>", i, stContainer.c_str( ) );

                m_Containers[ i ].setContainerInformation( ci );

                // Populate the container map record
                m_Containers[ i ].setContainerMapRecord( (CONTAINER_MAP_RECORD*)( b + ( i * g_iContainerSize ) ) );

                CardModuleService* cms = m_MiniDriverFiles->getCardModuleService( );
                if( cms ) {

                    unsigned char f = 0;
                    
                    std::auto_ptr< Marshaller::u1Array > containerType( cms->getContainerProperty( i, CARD_PROPERTY_CONTAINER_TYPE, f ) );
                    
                    if( containerType.get( ) ) {

                        m_Containers[ i ].setContainerTypeForSignatureKey( containerType->ReadU1At( 0 ) );
                        
                        m_Containers[ i ].setContainerTypeForExchangeKey( containerType->ReadU1At( 1 ) );
                    }

                    f = 0;

                    std::auto_ptr< Marshaller::u1Array > containerPinIdentifier( cms->getContainerProperty( i, CARD_PROPERTY_PIN_IDENTIFIER, f ) );
                    
                    if( containerPinIdentifier.get( ) ) {
                    
                        MiniDriverAuthentication::ROLES r = (MiniDriverAuthentication::ROLES)containerPinIdentifier->ReadU1At( 0 );
                    
                        m_Containers[ i ].setPinIdentifier( r );
                    }
                }

            } catch( MiniDriverException& x ) {

                // The container is empty
                Log::error( "MiniDriverContainerMapFile::containerRead", "Unable to read the container" );
                
                switch( x.getError( ) ) {
                
                case SCARD_E_INVALID_PARAMETER:
                    // The container does not exist
                    m_Containers[ i ].clear( );
                    break;

                default:
                    // The container cannot be read
                    throw;
                }
            }
        }
    }

    //print( );
    t.stop( "MiniDriverContainerMapFile::containerRead" );
    Log::end( "MiniDriverContainerMapFile::containerRead" );
}


/*
*/
void MiniDriverContainerMapFile::write( void ) {

    Log::begin( "MiniDriverContainerMapFile::write" );
    Timer t;
    t.start( );

        if( !m_MiniDriverFiles ) {
    
        Log::error( "MiniDriverContainerMapFile::write", "Invalid file system object" );
        return;
    }

    //print( );

    // Create a new CMap file
    Marshaller::u1Array* p = new Marshaller::u1Array( );

    // Populate the new CMap file
    int iOffset = 0;

    unsigned int sz = (unsigned int)m_Containers.size( );

    int i = 0;

    bool bMoreRecordToWrite = false;

    CONTAINER_MAP_RECORD cmr;

    BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

        // Try to locate a record to write after the current one
        bMoreRecordToWrite = false;

        for( unsigned int j = i + 1 ; j < sz; ++j ) {

            if( !m_Containers.at( j ).empty( ) ) {

                bMoreRecordToWrite = true;
                break;
            }
        }

        Marshaller::u1Array b( g_iContainerSize );

        if( c.empty( ) ) {
            
            if( bMoreRecordToWrite ) {

                // The current record is empty but one the following records is not
                // Add an empty one to guaranrty that the CMapFile parsing based on the
                // jump of the record size will work
                *p += b;
            }

        } else {

            cmr = c.getContainerMapRecord( );
            
            memcpy( b.GetBuffer( ), &cmr, g_iContainerSize );

            *p += b;
        }

        // No more record to write after the current one
        if( !bMoreRecordToWrite ) {

            // So the operation is stopped here to avoid to add empty records into the CMapFile
            break;
        }

        iOffset += g_iContainerSize;

        ++i;
    }

    // No record to write.
    if( !p->GetLength( ) ) {
    
        // Add an empty record to get a valid CMapFile
        Marshaller::u1Array b( g_iContainerSize );
        *p += b;
    }

    // Store the new CMap file
    m_ContainerMapFileBinary.reset( p );

    std::string s;
    Log::toString( p->GetBuffer( ), p->GetLength( ), s );
    Log::log( " CMapfile <%s>", s.c_str( ) );

    // Check the CMapFile exists
    std::string stCMapFile( szCONTAINER_MAP_FILE );
    
    std::string stMscpDirectory( szBASE_CSP_DIR );

    MiniDriverFiles::FILES_NAME fs = m_MiniDriverFiles->enumFiles( stMscpDirectory );
    
    MiniDriverFiles::FILES_NAME::const_iterator it = fs.find( stCMapFile );
    
    if( it == fs.end( ) ) {
    
        // The CMapFile does not exist. It must be create before to write the content
        // Create the access conditions for the CMapFile
         Marshaller::u1Array ac( 3 );

        // Administrator access condition
        ac.GetBuffer( )[ 0 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

        // User access condition
        ac.GetBuffer( )[ 1 ] = MiniDriverFiles::CARD_PERMISSION_READ | MiniDriverFiles::CARD_PERMISSION_WRITE;

        // Everyone access condition
        ac.GetBuffer( )[ 2 ] = MiniDriverFiles::CARD_PERMISSION_READ;

        m_MiniDriverFiles->createFile( stMscpDirectory, stCMapFile, &ac );
    }

    // Write the new CMap file
    m_MiniDriverFiles->writeFile( stMscpDirectory, stCMapFile, p, true, true );

    //print( );
    t.stop( "MiniDriverContainerMapFile::write" );
    Log::end( "MiniDriverContainerMapFile::write" );
}


/*
*/
void MiniDriverContainerMapFile::containerDelete( const unsigned char& a_ucContainerIndex ) {

    Log::begin( "MiniDriverContainerMapFile::containerDelete" );
    Timer t;
    t.start( );

    if( a_ucContainerIndex >= m_Containers.size( ) ) {

        Log::error( "MiniDriverContainerMapFile::containerDelete", "Invalid container index" );

        return;
    }

    if( !m_MiniDriverFiles ) {
    
        Log::error( "MiniDriverContainerMapFile::containerDelete", "Invalid file system object" );

        return;
    }

    CardModuleService * p = m_MiniDriverFiles->getCardModuleService( );
    
    if( !p ) {
    
        Log::error( "MiniDriverContainerMapFile::containerDelete", "Invalid card module service object" );

        return;
    }

    // Check the flag of this record to know if the default certificate is going to be removed
    unsigned char ucFlags = m_Containers[ a_ucContainerIndex ].getFlags( );

    // Clear the record
    m_Containers[ a_ucContainerIndex ].clear( );

    // Delete the oncard container  
    p->deleteContainer( a_ucContainerIndex );

    // Set a new default container
    if( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT == ucFlags ) {

        containerSetDefault( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID, false );
    }

    // write the new cmap file
    write( );

    //print( );
    t.stop( "MiniDriverContainerMapFile::containerDelete" );
    Log::end( "MiniDriverContainerMapFile::containerDelete" );
}


/*
*/
void MiniDriverContainerMapFile::containerCreate( unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, Marshaller::u1Array* a_pKeyModulus, const int& a_KeySize, Marshaller::u1Array* a_pKeyValue ) {

    Log::begin( "MiniDriverContainerMapFile::containerCreate" );
    Timer t;
    t.start( );

    if( !m_MiniDriverFiles ) {
    
        Log::error( "MiniDriverContainerMapFile::containerCreate", "Invalid file system object" );
                
        throw MiniDriverException( SCARD_E_UNEXPECTED );

        //return;
    }

    CardModuleService * p = m_MiniDriverFiles->getCardModuleService( );
    
    if( !p ) {
    
        Log::error( "MiniDriverContainerMapFile::containerCreate", "Invalid card module service object" );

        throw MiniDriverException( SCARD_E_UNEXPECTED );
        //return;
    }

// LCA: Remove this!
/*
// DOUBLE IMPORT
    // Check if an existing container using the same public key modulus exists
    containerGetMatching( a_ucContainerIndex, a_ucKeySpec, a_pKeyModulus );

    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != a_ucContainerIndex ) {

        // A container already uses this publick key modulus
        return;
    }
// DOUBLE IMPORT
*/

    // Search for a free container
    containerSearch( a_ucContainerIndex );

    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_ucContainerIndex ) {

        // No free container
        throw MiniDriverException( SCARD_E_WRITE_TOO_MANY );
        //return;
    }

    // Create the key pair container into the smart card to import or generate the private key
    p->createContainer( a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_KeySize, a_pKeyValue );

    // Populate the container info
    
    MiniDriverContainer& c = m_Containers[ a_ucContainerIndex ];

    c.setFlags( MiniDriverContainer::CMAPFILE_FLAG_VALID );

    if( MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec ) {

        c.setKeyExchangeSizeBits( (WORD)a_KeySize );

        c.setKeySignatureSizeBits( 0 );

    } else {

        c.setKeyExchangeSizeBits( 0 );

        c.setKeySignatureSizeBits( (WORD)a_KeySize );
    }

    // Load the information from the smart card
    boost::shared_ptr< Marshaller::u1Array > ci( p->getContainer( a_ucContainerIndex ) );

    std::string stContainer;
    Log::toString( ci->GetBuffer( ), ci->GetLength( ), stContainer );
    Log::log( "MiniDriverContainerMapFile::containerWrite - index <%d> - container <%s>", a_ucContainerIndex, stContainer.c_str( ) );

    c.setContainerInformation( ci );

    std::string stContainerName;
    
    if( MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec ) {

        stContainerName = computeContainerName( c.getExchangePublicKeyModulus( )->GetBuffer( ), c.getExchangePublicKeyModulus( )->GetLength( ) );
    
    } else {
    
        stContainerName = computeContainerName( c.getSignaturePublicKeyModulus( )->GetBuffer( ), c.getSignaturePublicKeyModulus( )->GetLength( ) );    
    }

    c.setGUID( stContainerName );

    // write the new cmap file
    write( );

    //print( );
    t.stop( "MiniDriverContainerMapFile::containerCreate" );
    Log::end( "MiniDriverContainerMapFile::containerCreate" );
}


/*
*/
void MiniDriverContainerMapFile::containerSearch( unsigned char& a_ucContainerIndex ) {

    Log::begin( "MiniDriverContainerMapFile::containerSearch" );
    Timer t;
    t.start( );

    // The index is false. A new index has to be found.
    a_ucContainerIndex = 0;

    // Find an empty container
    BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

        if( c.empty( ) ) {

            Log::log( "container <%d> is empty", a_ucContainerIndex );

            return;
        }
        Log::log( "container <%d> <%#02x>", a_ucContainerIndex, c.getFlags( ) );

        ++a_ucContainerIndex;
    }

    if( a_ucContainerIndex >= m_Containers.size( ) ) {

        a_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
    }

    t.stop( "MiniDriverContainerMapFile::containerSearch" );
    Log::end( "MiniDriverContainerMapFile::containerSearch" );
}


/* Retreive the first certificate with the Smart Card Logn OID or anyone if not found update the CMapFile to set as default the choosen certificate
*/
void MiniDriverContainerMapFile::containerSetDefault( const unsigned char& a_ucIndex, const bool& a_IsSmartCardLogon ) {

    Log::begin( " **************** MiniDriverContainerMapFile::containerSetDefault" );
    Timer t;
    t.start( );

    //print( );

    bool bJobDone = false;

    bool bWrite = false;

    // A new container has been created. We need to know if this is the new default one.
    if( a_IsSmartCardLogon && ( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != a_ucIndex ) ) {

        // Does a default container exist ? In this case put it to a valid state
        BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

            if( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT == c.getFlags( ) ) {

                c.setFlags( MiniDriverContainer::CMAPFILE_FLAG_VALID );
            }
        }
            
        // Set the smart card logon flag for the new container
        m_Containers[ a_ucIndex ].setFlagSmartCardLogon( a_IsSmartCardLogon );

        // Declare the new valid & default container
        m_Containers[ a_ucIndex ].setFlags( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT );

        Log::log( "MiniDriverContainerMapFile::containerSetDefault - A new default container has been declared <%d>", a_ucIndex );

        bJobDone = true;
        
        bWrite = true;
    }

    // A container has been deleted OR the new container is not able to become the default one.
    // We may be need to find a new default one.

    if( !bJobDone ) {

        // Does a default container exist ?
        BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

            if( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT == c.getFlags( ) ) {

                Log::log( "MiniDriverContainerMapFile::containerSetDefault - Found a default container already existing" );

                // A valid container already default
                bJobDone = true;

                break;  
            }
        }
    }

    if( !bJobDone ) {

        // Does a container associated to a certificate with Smart Card Logon OID exists ?
        BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

            //Log::log( "MiniDriverContainerMapFile::UpdateCMap - Certificate - Name <%s> - Container index <%ld> - Smart card logon <%ld>", c->_certName.c_str( ), s4CMapFileIndex, bIsSmartCardLogon );
            if( c.getFlagSmartCardLogon( ) ) {

                // Set the new default certificate
                c.setFlags( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT );

                Log::log( "MiniDriverContainerMapFile::containerSetDefault - Set the new default certificate" );

                bJobDone = true;

                bWrite = true;

                break;
            }
        }
    }
 
    if( !bJobDone ) {

        // Does a default container exist ?
        BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

            if( MiniDriverContainer::CMAPFILE_FLAG_VALID == c.getFlags( ) ) {

                //Log::log( "MiniDriverContainerMapFile::UpdateCMap - Found a valid container - Associated record <%ld> - old flags <%ld> - NEW Flags <%ld>", i, u1CMapFileRecordFlags, CMAPFILE_FLAG_VALID_AND_DEFAULT );

                // Take the first valid container
                c.setFlags( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT );

                Log::log( "MiniDriverContainerMapFile::containerSetDefault - Take the first valid container" );

                bWrite = true;

                bJobDone = true;

                break;  
            }
        }
    }

    if( bJobDone && bWrite ) {
    
        // write the new cmap file
        write( );
    }

    //print( );
    t.stop( "MiniDriverContainerMapFile::containerSetDefault" );
    Log::end( "MiniDriverContainerMapFile::containerSetDefault" );
}


/*
*/
void MiniDriverContainerMapFile::clear( void ) { 

    m_ContainerMapFileBinary.reset( ); 

    BOOST_FOREACH( MiniDriverContainer& c, m_Containers ) {

        c.clear( ); 
    }
}


/*
*/
void MiniDriverContainerMapFile::print( void ) {

    Log::begin( "MiniDriverContainerMapFile" );

    int i = 0;
    BOOST_FOREACH( MiniDriverContainer c, m_Containers ){

        unsigned char ucFlags = c.getFlags( );

        if( MiniDriverContainer::CMAPFILE_FLAG_VALID_AND_DEFAULT == ucFlags )
        {
            Log::log( "index <%ld> - flags <%ld> [DEFAULT]", i, ucFlags );
        }
        else
        {
            Log::log( "index <%ld> - flags <%ld>", i, ucFlags );
        }

        ++i;		
    }

    Log::end( "MiniDriverContainerMapFile" );
}


/*
*/
bool MiniDriverContainerMapFile::containerGetMatching( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, const Marshaller::u1Array* a_pPublicKeyModulus ) {

    Log::begin( "MiniDriverContainerMapFile::containerGetMatching" );
    Timer t;
    t.start( );

    bool bRet = false;

    a_ucContainerIndex = CONTAINER_INDEX_INVALID;

    if( !a_pPublicKeyModulus ) {
     
        return bRet;
    }

    unsigned char i = 0;

    unsigned char* p = (unsigned char*)a_pPublicKeyModulus->GetBuffer( );

    unsigned int l = a_pPublicKeyModulus->GetLength( );
    
    std::string stIncomingExchangePublicKeyModulus;
    Log::toString( p, l, stIncomingExchangePublicKeyModulus );
    Log::log( "MiniDriverContainerMapFile::containerGetMatching - incoming  <%s>", stIncomingExchangePublicKeyModulus.c_str( ) );
    
    std::string stMscpDirectory( szBASE_CSP_DIR );

    MiniDriverFiles::FILES_NAME fs = m_MiniDriverFiles->enumFiles( stMscpDirectory );

    char szCertX[ 10 ];

    char szCertS[ 10 ];

    BOOST_FOREACH( MiniDriverContainer c, m_Containers ) {

        if( MiniDriverContainer::CMAPFILE_FLAG_EMPTY == c.getFlags( ) ) {

            ++i;		

            continue;
        }

        // LCA: Skip container if already has a certificate attached
        memset( szCertX, 0, sizeof( szCertX ) );

        memset( szCertS, 0, sizeof( szCertX ) );

        sprintf( szCertX, "kxc%02x", i );

        sprintf( szCertS, "ksc%02x", i );
        
        std::string stCertX(szCertX);
        
        std::string stCertS(szCertS);
                
        MiniDriverFiles::FILES_NAME::const_iterator itX = fs.find( stCertX );
        
        MiniDriverFiles::FILES_NAME::const_iterator itS = fs.find( stCertS );

        if( ( itX != fs.end( ) ) || ( itS != fs.end( ) ) ) {

            ++i;		
            
            continue;
        }
        
        if( c.getKeyExchangeSizeBits( ) ) {

            std::string stContainerExchangePublicKeyModulus;
            Log::toString( c.getExchangePublicKeyModulus( )->GetBuffer( ), c.getExchangePublicKeyModulus( )->GetLength( ), stContainerExchangePublicKeyModulus );
            Log::log( "MiniDriverContainerMapFile::containerGetMatching - container <%s>", stContainerExchangePublicKeyModulus.c_str( ) );
 
            if( 0 == memcmp( p, c.getExchangePublicKeyModulus( )->GetBuffer( ), l ) ) {

                bRet = true;

                a_ucContainerIndex = i;

                a_ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

                break;
            }

        } else if( c.getKeySignatureSizeBits( ) ) {

            std::string stContainerSignaturePublicKeyModulus;
            Log::toString( c.getSignaturePublicKeyModulus( )->GetBuffer( ), c.getSignaturePublicKeyModulus( )->GetLength( ), stContainerSignaturePublicKeyModulus );
            Log::log( "MiniDriverContainerMapFile::containerGetMatching - container <%s>", stContainerSignaturePublicKeyModulus.c_str( ) );

            if( 0 == memcmp( p, c.getSignaturePublicKeyModulus( )->GetBuffer( ), l ) ) {

                bRet = true;

                a_ucContainerIndex = i;

                a_ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

                break;            
            }
        }

        ++i;		
}

    t.stop( "MiniDriverContainerMapFile::containerGetMatching" );
    Log::end( "MiniDriverContainerMapFile::containerGetMatching" );

    return bRet;
}


/*
*/
std::string MiniDriverContainerMapFile::computeContainerName( const unsigned char* a_pBuffer, const size_t& a_BufferLength ) {

    // Hash the buffer
    unsigned char hash[ 20 ];

    memset( &hash[ 0 ], 0, sizeof( hash ) ) ;
    
    CSHA1 sha1;
    
    sha1.hashCore( const_cast< CK_BYTE_PTR >( a_pBuffer ), 0, static_cast< CK_LONG >( a_BufferLength ) );
    
    sha1.hashFinal( hash );


    // Format a string from the hash
    char name[ 40 ]; memset( name, 0, sizeof( name ) );

    unsigned char* id = hash;

    int i, n = 0;

    char *c = name;

    for( i = 0 ; i < 4 ; ++i ) {

        sprintf( c, "%02x", id[ n ] );
    
        n++;
        
        c += 2;
    }

    sprintf(c,"-");

    c++;

    for( i = 0; i < 2 ; ++i ) {

        sprintf( c, "%02x", id[ n ] );
        
        n++; 
        
        c += 2;
    }

    sprintf( c, "-" );
    
    c++;
    
    for( i = 0 ; i < 2 ; ++i ) {

        sprintf( c, "%02x", id[ n ] );
        
        n++;
        
        c += 2;
    }

    sprintf( c, "-" );

    c++;
    
    for( i = 0 ; i < 2 ; ++i ) {

        sprintf( c, "%02x", id [ n ] );
        
        n++; 
        
        c += 2;
    }

    sprintf( c, "-" );
    
    c++;

    for( i = 0 ; i < 6 ; ++i ) {

        sprintf( c, "%02x", id[ n ] );

        n++; 
        
        c += 2;
    }

    return std::string(name);
}


/*
*/
unsigned char MiniDriverContainerMapFile::containerGetFree( void ) {

    unsigned char i = 0;
    
    bool bFound = false;

    BOOST_FOREACH( MiniDriverContainer c, m_Containers ) {

        if( MiniDriverContainer::CMAPFILE_FLAG_EMPTY == c.getFlags( ) ) {
         
            bFound = true;
            break;
        }

        ++i;
    }

    if( !bFound ) {
    
        i = CONTAINER_INDEX_INVALID;
    }

    return i;
}
