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


#ifndef __GEMALTO_READER__
#define __GEMALTO_READER__


#include <string>
#include <boost/shared_ptr.hpp>
#include "MiniDriver.hpp"
#include "SmartCardReader.hpp"
#include "MiniDriverException.hpp"
#include "Timer.hpp"
//#include "PCSC.h"


/* This class is a facade exporting all smart card & reader features
*/
class Device {

public:

    static bool s_bEnableCache;

    Device( const SCARD_READERSTATE&, const unsigned char& );

    virtual ~Device( );

    unsigned char getDeviceID( void ) { return m_ucDeviceID; }

    void clear( void );

    inline void saveCache( void ) { if( Device::s_bEnableCache && m_MiniDriver.get( ) ) { m_MiniDriver->saveCache( ); } }

    // Smart card reader operations

    inline const std::string& getReaderName( void ) { if( m_SmartCardReader.get( ) ) return m_SmartCardReader->getReaderName( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isSmartCardPresent( void ) { /*if( !m_MiniDriver.get( ) ) { return false; }*/ return ( ( m_DeviceState.dwCurrentState & SCARD_STATE_PRESENT ) ? true : false ); }

    inline bool isSmartCardMute( void ) { return ( ( m_DeviceState.dwCurrentState & SCARD_STATE_MUTE ) ? true : false ); }
        
    inline const SCARD_READERSTATE& getReaderState( void ) { return m_DeviceState; }

    void set( const SCARD_READERSTATE& );

    void put( SCARD_READERSTATE& );

    void update( const SCARD_READERSTATE& );

    void addMiniDriver( void );

    void removeMiniDriver( void );

    unsigned long getHandle( void );

    inline bool isVerifyPinSecured( void ) { return m_SmartCardReader->isVerifyPinSecured( ); }

    inline void verifyPinSecured( const unsigned char& a_ucRole ) { m_SmartCardReader->verifyPinSecured( a_ucRole ); }

    inline bool isV2Plus( void ) {  if( m_MiniDriver.get( ) ) { return m_MiniDriver->isV2Plus( ); } else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void beginTransaction( void ) { if( m_MiniDriver.get( ) ) { m_MiniDriver->beginTransaction( ); } }

    inline void endTransaction( void ) { if( m_MiniDriver.get( ) ) { m_MiniDriver->endTransaction( ); } }

    // Smart card operations

    void hasChanged( MiniDriverCardCacheFile::ChangeType& a_Pins, MiniDriverCardCacheFile::ChangeType& a_Containers, MiniDriverCardCacheFile::ChangeType& a_Files );

    Marshaller::u1Array* getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags );

    void setCardProperty( const unsigned char& a_ucProperty, Marshaller::u1Array* a_Data, const unsigned char& a_ucFlags );

    inline const Marshaller::u1Array* getSerialNumber( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getSerialNumber( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    boost::shared_ptr< Marshaller::u1Array > privateKeyDecrypt( const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec, Marshaller::u1Array* a_pDataToDecrypt ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->privateKeyDecrypt( a_ucContainerIndex, a_ucKeySpec, a_pDataToDecrypt ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline const CardModuleService* getCardModule( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getCardModule( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void forceGarbageCollection( void ) { try { if( m_MiniDriver.get( ) ) { m_MiniDriver->forceGarbageCollection( ); } } catch( ... ) { } }

    inline bool isReadOnly( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isReadOnly( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinInitialized( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isPinInitialized( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    // PIN operations

    inline unsigned char getPinMaxPinLength( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinMaxPinLength( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char getPinMinPinLength( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getPinMinPinLength( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isSSO( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isSSO( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isNoPin( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isNoPin( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    bool isAuthenticated( void );

    inline bool isExternalPin( void ) {if( m_MiniDriver.get( ) ) return m_MiniDriver->isExternalPin( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModePinOnly( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModePinOnly( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModeNotPinOnly( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModeNotPinOnly( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isModePinOrBiometry( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->isModePinOrBiometry( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void changePin( Marshaller::u1Array* a_pOldPIN, Marshaller::u1Array* a_pNewPIN ) { if( m_MiniDriver.get( ) ) m_MiniDriver->changePin( a_pOldPIN, a_pNewPIN ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void unblockPin( Marshaller::u1Array* a_PinSo, Marshaller::u1Array* a_PinUser ) { if( m_MiniDriver.get( ) ) m_MiniDriver->unblockPin( a_PinSo, a_PinUser ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void verifyPin( Marshaller::u1Array* a_Pin );

    void logOut( void );

    inline int getTriesRemaining( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->getTriesRemaining( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    inline void administratorLogin( Marshaller::u1Array* a_pAdministratorKey ) { if( m_MiniDriver.get( ) ) m_MiniDriver->administratorLogin( a_pAdministratorKey ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void administratorLogout( void ) { if( m_MiniDriver.get( ) ) m_MiniDriver->administratorLogout( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void administratorChangeKey( Marshaller::u1Array* a_OldKey, Marshaller::u1Array* a_NewKey ) {  if( m_MiniDriver.get( ) ) m_MiniDriver->administratorChangeKey( a_OldKey, a_NewKey ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char administratorGetTriesRemaining( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->administratorGetTriesRemaining( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool administratorIsAuthenticated( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->administratorIsAuthenticated( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    // Files operations

    inline void createDirectory( const std::string& a_stDirectoryParent, const std::string& a_stDirectory ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->createDirectory( a_stDirectoryParent, a_stDirectory ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createFile(  const std::string& a_stDirectory, const std::string& a_stFile, const bool& a_bIsReadProtected ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createFile( a_stDirectory, a_stFile, a_bIsReadProtected ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void deleteFile( const std::string& a_stDirectory, const std::string& a_stFile ) { if( m_MiniDriver.get( ) ) m_MiniDriver->deleteFile( a_stDirectory, a_stFile ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void readCertificate( const std::string& a_stPath, boost::shared_ptr< Marshaller::u1Array >& a_pCertificateValue ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->readCertificate( a_stPath, a_pCertificateValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline MiniDriverFiles::FILES_NAME& enumFiles( const std::string& a_DirectoryPath ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->enumFiles( a_DirectoryPath ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline Marshaller::u1Array* readFile( const std::string& a_stDirectory, const std::string& a_stFile ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->readFile( a_stDirectory, a_stFile ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void writeFile( const std::string& a_stDirectory, const std::string& a_stFile, Marshaller::u1Array* a_FileData, const bool& a_bAddToCache = true ) { if( m_MiniDriver.get( ) ) m_MiniDriver->writeFile( a_stDirectory, a_stFile, a_FileData, a_bAddToCache ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createCertificate( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stCertificateName, Marshaller::u1Array* a_pValue, Marshaller::u1Array* a_pModulus, const bool& a_bSmartCardLogon ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createCertificate( a_ucContainerIndex, a_ucKeySpec, a_stCertificateName, a_pValue, a_pModulus, a_bSmartCardLogon ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void createCertificateRoot( std::string& a_stCertificateName, Marshaller::u1Array* a_pValue ) { if( m_MiniDriver.get( ) ) m_MiniDriver->createCertificateRoot( a_stCertificateName, a_pValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void deletePrivateKey( const unsigned char& a_ucContainerIndex );

    inline void deleteFileStructure( void ) { if( m_MiniDriver.get( ) ) m_MiniDriver->deleteFileStructure( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void certificateDelete( unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) m_MiniDriver->certificateDelete( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void cacheDisable( const std::string& a_stFileName ) { if( m_MiniDriver.get( ) ) m_MiniDriver->cacheDisable( a_stFileName ); }

    inline void renameFile( const std::string& a_stOldFileDirectory, const std::string& a_stOldFileName, const std::string& a_stNewFileDirectory, const std::string& a_stNewFileName ) { if( m_MiniDriver.get( ) ) m_MiniDriver->renameFile( a_stOldFileDirectory, a_stOldFileName, a_stNewFileDirectory, a_stNewFileName ); } 


    // Container operations
    inline void containerCreate( unsigned char& a_ucContainerIndex, const bool& a_bKeyImport, unsigned char& a_ucKeySpec, Marshaller::u1Array* a_pPublicKeyModulus, const int& a_KeySize, Marshaller::u1Array* a_pKeyValue ) { if( m_MiniDriver.get( ) ) m_MiniDriver->containerCreate( a_ucContainerIndex, a_bKeyImport, a_ucKeySpec, a_pPublicKeyModulus, a_KeySize, a_pKeyValue ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void containerDelete( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) m_MiniDriver->containerDelete( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline const MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGet( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char containerCount( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerCount( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerGetMatching( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, std::string& a_stFileName, const Marshaller::u1Array* a_pPublicKeyModulus ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGetMatching( a_ucContainerIndex, a_ucKeySpec, a_stFileName, a_pPublicKeyModulus ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerIsImportedExchangeKey( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerIsImportedSignatureKey( a_ucContainerIndex ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline unsigned char containerGetFree( void ) { if( m_MiniDriver.get( ) ) return m_MiniDriver->containerGetFree( ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

private:

    // Reader
    boost::shared_ptr< SmartCardReader > m_SmartCardReader;

    SCARD_READERSTATE m_DeviceState;

    boost::shared_ptr< MiniDriver > m_MiniDriver;

    //boost::shared_ptr< PCSC > m_PCSC;

    unsigned char m_ucDeviceID;

    Timer m_TimerLastChange;
    
    Timer m_TimerLastAuth;

    bool m_bIsLastAuth;

};

#endif // __GEMALTO_READER__
