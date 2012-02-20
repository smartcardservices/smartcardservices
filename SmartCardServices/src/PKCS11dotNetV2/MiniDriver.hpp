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


#ifndef __GEMALTO_MINIDRIVER_FACADE__
#define __GEMALTO_MINIDRIVER_FACADE__


#include <boost/serialization/serialization.hpp>
#include <boost/ptr_container/serialize_ptr_map.hpp>
#include <boost/shared_ptr.hpp>
#include "MiniDriverFiles.hpp"
#include "MiniDriverContainerMapFile.hpp"
#include "MiniDriverAuthentication.hpp"
#include "MiniDriverException.hpp"


class SmartCardReader;
class CardModuleService;


/*
*/
class MiniDriver {

public:

    const static unsigned int s_iMinLengthKeyRSA;

    const static unsigned int s_iMaxLengthKeyRSA;

    inline virtual ~MiniDriver( ) { }

    inline void saveCache( void ) { try { cacheSerialize( ); } catch( ... ) { } }

    void read( const bool& );


    // Smart card management

    // Initialize the object managing the communication with the smart card
    void setSmartCardReader( SmartCardReader* a_pSmartCardReader  );

    inline const CardModuleService* getCardModule( void ) { return m_CardModule.get( ); }

    inline SCARDHANDLE getCardHandle( void ) { if( m_CardModule.get( ) ) return m_CardModule->getCardHandle( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    Marshaller::u1Array* getSerialNumber( void );

    inline void forceGarbageCollection( void ) { try { if( m_CardModule.get( ) ) { m_CardModule->forceGarbageCollector( ); } } catch( ... ) { } }

    inline bool isV2Plus( void ) {  try { if( m_CardModule.get( ) ) { return m_CardModule->isV2Plus( ); } } catch( ... ) { } return false; }

    inline void beginTransaction( void ) { if( m_CardModule.get( ) ) { m_CardModule->beginTransaction( ); } }

    inline void endTransaction( void ) { if( m_CardModule.get( ) ) { m_CardModule->endTransaction( ); } }

    inline bool isReadOnly( void ) { bool bRet = false; Marshaller::u1Array* a = getCardProperty( CARD_READ_ONLY, 0 ); if( a ) { bRet = ( 1 == a->ReadU1At( 0 ) ); } return bRet; } 


    // Authentification management

    inline unsigned char getPinMaxPinLength( void ) { return m_Authentication.getPinMaxPinLength( ); }

    inline unsigned char getPinMinPinLength( void ) { return m_Authentication.getPinMinPinLength( ); }

    inline bool isPinInitialized( void ) { return m_Authentication.isPinInitialized( ); } 

    inline bool isSSO( void ) { return m_Authentication.isSSO( ); }

    inline bool isNoPin( void ) { return m_Authentication.isNoPin( ); }

    inline bool isAuthenticated( void ) { return m_Authentication.isAuthenticated( ); }

    inline bool isExternalPin( void ) { return m_Authentication.isExternalPin( ); }

    inline bool isModePinOnly( void ) { return m_Authentication.isModePinOnly( ); }

    inline bool isModeNotPinOnly( void ) { return m_Authentication.isModeNotPinOnly( ); }

    inline bool isModePinOrBiometry( void ) { return m_Authentication.isModePinOrBiometry( ); }

    void changePin( Marshaller::u1Array* a_pOldPIN, Marshaller::u1Array* a_pNewPIN );

    void unblockPin( Marshaller::u1Array* a_PinSo, Marshaller::u1Array* a_PinUser );

    inline void verifyPin( Marshaller::u1Array* a_Pin ) { m_Authentication.login( a_Pin ); }

    inline void logOut( void ) { m_Authentication.logOut( ); }

    inline int getTriesRemaining( void ) { return m_Authentication.getTriesRemaining( ); }

    inline void administratorLogin( Marshaller::u1Array* a_pAdministratorKey ) { m_Authentication.administratorLogin( a_pAdministratorKey ); }

    inline void administratorLogout( void ) { m_Authentication.administratorLogout( ); }

    void administratorChangeKey( Marshaller::u1Array* a_OldKey, Marshaller::u1Array* a_NewKey );

    inline unsigned char administratorGetTriesRemaining( void ) { return m_Authentication.administratorGetTriesRemaining( ); }

    inline bool administratorIsAuthenticated( void ) { return m_Authentication.administratorIsAuthenticated( ); }


    // Files management

    inline void hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files ) { m_Files.hasChanged( a_Pins, a_Containers, a_Files ); }

    inline MiniDriverFiles::FILES_NAME& enumFiles( const std::string& a_DirectoryPath ) { return m_Files.enumFiles( a_DirectoryPath ); }

    inline Marshaller::u1Array* readFile( const std::string& a_stDirectory, const std::string& a_stFile ) { return m_Files.readFile( a_stDirectory, a_stFile ); }

    inline void writeFile( const std::string& a_stDirectory, const std::string& a_stFile, Marshaller::u1Array* a_FileData, const bool& a_bAddToCache = true ) { { Log::begin( "MiniDriver::writeFile" ); Log::log( "Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) ); m_Files.writeFile( a_stDirectory, a_stFile, a_FileData, a_bAddToCache ); cacheSerialize( ); Log::end( "MiniDriver::writeFile" ); } }

    void createFile( const std::string&, const std::string&, const bool& );

    inline void deleteFile( const std::string& a_stDirectory, const std::string& a_stFile ) { { Log::begin( "MiniDriver::deleteFile" ); Log::log( "Directory <%s> - File <%s>", a_stDirectory.c_str( ), a_stFile.c_str( ) ); m_Files.deleteFile( a_stDirectory, a_stFile ); cacheSerialize( ); Log::end( "MiniDriver::deleteFile" ); } }

    inline void createDirectory( const std::string& a_stDirectoryParent, const std::string& a_stDirectory ) { { Log::begin( "MiniDriver::createDirectory" ); Log::log( "Directory <%s> - Parent <%s>", a_stDirectory.c_str( ), a_stDirectoryParent.c_str( ) ); m_Files.createDirectory( a_stDirectoryParent, a_stDirectory ); cacheSerialize( ); Log::end( "MiniDriver::createDirectory" ); } }

    void createCertificate( unsigned char&, unsigned char&, std::string&, Marshaller::u1Array*, Marshaller::u1Array*, const bool& );

    void createCertificateRoot( std::string& a_stCertificateName, Marshaller::u1Array* a_pValue );

    void readCertificate( const std::string&, boost::shared_ptr< Marshaller::u1Array >& );

    inline void deleteFileStructure( void ) { m_Files.deleteFileStructure( ); }

    inline void certificateDelete( unsigned char& a_ucContainerIndex ) { m_Files.certificateDelete( a_ucContainerIndex ); }

    inline void cacheDisable( const std::string& a_stFileName ) { m_Files.cacheDisable( a_stFileName ); }

    inline void renameFile( const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName ) { m_Files.renameFile( a_stOldFileDirectory, a_stOldFileName, a_stNewFileDirectory, a_stNewFileName ); } 


    // Containers management

    inline const MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { return m_Files.containerGet( a_ucContainerIndex ); }

    inline void containerDelete( const unsigned char& a_ucContainerIndex ) { m_Files.containerDelete( a_ucContainerIndex ); }

    inline void containerCreate( unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, Marshaller::u1Array* a_pPublicKeyModulus, const int& a_KeySize, Marshaller::u1Array* a_pKeyValue ) { m_Files.containerCreate( a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_pPublicKeyModulus, a_KeySize, a_pKeyValue ); }

    inline unsigned char containerCount( void ) { return m_Files.containerCount( ); }

    inline bool containerGetMatching( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const Marshaller::u1Array* a_pPublicKeyModulus ) { return m_Files.containerGetMatching( a_ucContainerIndex, a_ucKeySpec, a_stFileName, a_pPublicKeyModulus ); }

    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { return m_Files.containerIsImportedExchangeKey( a_ucContainerIndex ); }

    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { return m_Files.containerIsImportedSignatureKey( a_ucContainerIndex ); }

    inline unsigned char containerGetFree( void ) { return m_Files.containerGetFree( ); }

    
    // Cryptography management

    inline boost::shared_ptr< Marshaller::u1Array > privateKeyDecrypt( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, Marshaller::u1Array* a_pDataToDecrypt ) { if( m_CardModule.get( ) ) { /*m_CardModule->manageGarbageCollector( ); */m_pDataDecrypted.reset( m_CardModule->privateKeyDecrypt( a_ucContainerIndex, a_ucKeySpec, a_pDataToDecrypt ) ); return m_pDataDecrypted; } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    // Property management
    inline Marshaller::u1Array* getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags ) { if( m_CardModule.get( ) ) { return m_CardModule->getCardProperty( a_ucProperty, a_ucFlags ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void setCardProperty( const unsigned char& a_ucProperty, Marshaller::u1Array* a_Data, const unsigned char& a_ucFlags ) { if( m_CardModule.get( ) ) { m_CardModule->setCardProperty( a_ucProperty, a_Data, a_ucFlags ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


private:    

    void toString( const unsigned char* buffer, std::size_t size, std::string &result );

    boost::shared_ptr< Marshaller::u1Array > m_pDataDecrypted;

    boost::shared_ptr< Marshaller::u1Array > m_u1aSerialNumber;

    boost::shared_ptr< CardModuleService > m_CardModule;

    MiniDriverFiles m_Files;

    MiniDriverAuthentication m_Authentication;

    // Name of the file on the computer disk containing the image of the cache
    std::string m_stFileName;

    // Enable/disable the on disk serialization/deserialization
    bool m_bEnableCache;

    void cacheDeserialize( void );

    void cacheSerialize( void );

    // Disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {

        //Log::begin( "MiniDriver::serialize" );

        // Append the files information
        ar & m_Files;

        // Append the authentication information
        ar & m_Authentication;

        //Log::end( "MiniDriver::serialize" );
    }

};


BOOST_CLASS_VERSION( MiniDriver, 1 )


#endif // __GEMALTO_MINIDRIVER__
