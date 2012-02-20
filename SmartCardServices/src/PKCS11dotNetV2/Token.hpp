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


#ifndef __GEMALTO_TOKEN__
#define __GEMALTO_TOKEN__


#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/random.hpp>
#include <string>
#include <vector>
#include "MiniDriver.hpp"
#include "Device.hpp"
#include "Session.hpp"
#include "Pkcs11ObjectStorage.hpp"
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"
#include "MiniDriverException.hpp"
#include "Pkcs11ObjectKeyPublicRSA.hpp"

class Slot;


/*
*/
class Token {

public:

    typedef boost::ptr_map< CK_OBJECT_HANDLE, StorageObject > TOKEN_OBJECTS;

    static const unsigned long FLAG_OBJECT_TOKEN = 0x00000000;

    static const unsigned long MASK_OBJECT_TOKEN = 0x00FF0000;

    Token( Slot*, Device* );

    inline virtual ~Token( ) { clear( ); }


    void login( const CK_ULONG&, Marshaller::u1Array* );

    void logout( void );

    void generateRandom( CK_BYTE_PTR, const CK_ULONG& );

    void addObject( StorageObject*, CK_OBJECT_HANDLE_PTR, const bool& a_bRegisterObject = true );

    void addObjectPrivateKey( RSAPrivateKeyObject*, CK_OBJECT_HANDLE_PTR );

    void addObjectCertificate( X509PubKeyCertObject*, CK_OBJECT_HANDLE_PTR );

    void addObjectPublicKey( Pkcs11ObjectKeyPublicRSA*, CK_OBJECT_HANDLE_PTR );

    void deleteObject( const CK_OBJECT_HANDLE& );

    // === TEST
    //inline void findObjectsInit( void ) { m_TokenObjectsReturnedInSearch.clear( ); synchronizeIfSmartCardContentHasChanged( ); }
    inline void findObjectsInit( void ) { m_TokenObjectsReturnedInSearch.clear( ); try{ synchronizeIfSmartCardContentHasChanged( ); } catch( ... ){} }

    void findObjects( Session*, CK_OBJECT_HANDLE_PTR, const CK_ULONG&, CK_ULONG_PTR );

    void getAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void setAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void generateKeyPair( Pkcs11ObjectKeyPublicRSA*, RSAPrivateKeyObject*, CK_OBJECT_HANDLE_PTR , CK_OBJECT_HANDLE_PTR );

    StorageObject* getObject( const CK_OBJECT_HANDLE& );

    void sign( const RSAPrivateKeyObject*, Marshaller::u1Array*, const CK_ULONG&, CK_BYTE_PTR );

    void decrypt( const StorageObject*, Marshaller::u1Array*, const CK_ULONG&, CK_BYTE_PTR , CK_ULONG_PTR );

    void verify( const StorageObject*, Marshaller::u1Array*, const CK_ULONG&, Marshaller::u1Array* );

    void encrypt( const StorageObject*, Marshaller::u1Array*, const CK_ULONG&,CK_BYTE_PTR );

    void initToken( Marshaller::u1Array*, Marshaller::u1Array* );

    void initPIN( Marshaller::u1Array*, Marshaller::u1Array* );

    void setPIN( Marshaller::u1Array*, Marshaller::u1Array* );

    inline const CK_ULONG& getLoggedRole( void ) { return m_RoleLogged; }

    inline void setLoggedRole( const CK_ULONG& r ) { m_RoleLogged = r; }

    inline CK_TOKEN_INFO& getTokenInfo( void ) { return m_TokenInfo; }

    inline bool isToken( const CK_OBJECT_HANDLE& a_hObject ) { return ( ( a_hObject & MASK_OBJECT_TOKEN ) == FLAG_OBJECT_TOKEN ); }

    bool synchronizeIfSmartCardContentHasChanged( void );
        
    static CK_RV checkException( MiniDriverException& );


private:

    typedef std::vector< StorageObject* > OBJECTS;

    std::string g_stPathPKCS11;

    std::string g_stPathTokenInfo;

    std::string g_stPrefixData;

    std::string g_stPrefixKeyPublic;

    std::string g_stPrefixKeyPrivate;

    std::string g_stPrefixPublicObject;

    std::string g_stPrefixPrivateObject;

    std::string g_stPrefixRootCertificate;

    bool checkSmartCardContent( void );
    bool m_bCheckSmartCardContentDone;

    void initializeObjectIndex( void );

    void checkTokenInfo( void );

    void setTokenInfo( void );

    void writeTokenInfo( void );

    void readTokenInfo( void );

    void createTokenInfo( void );

    //void initializeTokenInfo( void );

    CK_OBJECT_HANDLE computeObjectHandle( const CK_OBJECT_CLASS&, const bool& );

    inline void clear( void ) { m_Objects.clear( ); }

    void authenticateUser( Marshaller::u1Array* );

    void authenticateAdmin( Marshaller::u1Array* );

    Marshaller::u1Array* PadRSAPKCS1v15( Marshaller::u1Array*, const CK_ULONG& );

    Marshaller::u1Array* PadRSAX509( Marshaller::u1Array*, const CK_ULONG& );

    Marshaller::u1Array* EncodeHashForSigning( Marshaller::u1Array*, const CK_ULONG&, const CK_ULONG& );

    void verifyRSAPKCS1v15( Marshaller::u1Array*, Marshaller::u1Array*, const unsigned int& );

    void verifyRSAX509( Marshaller::u1Array*, Marshaller::u1Array*, const unsigned int& );

    void verifyHash( Marshaller::u1Array*, Marshaller::u1Array*, const unsigned int&, const CK_ULONG& );

    void deleteObjectFromCard( StorageObject* );

    void computeObjectFileName( StorageObject*, std::string& );

    void writeObject( StorageObject* );

    CK_OBJECT_HANDLE registerStorageObject( StorageObject* );

    void unregisterStorageObject( const CK_OBJECT_HANDLE& );

    CK_OBJECT_HANDLE computeObjectHandle( void );

    void synchronizeObjects( void );

    void synchronizePublicObjects( void );

    void synchronizePrivateObjects( void );

    void synchronizePIN( void );

    void synchronizePublicCertificateAndKeyObjects( void );

    void synchronizePrivateCertificateAndKeyObjects( void );

    void synchronizePublicDataObjects( void );

    void synchronizePrivateDataObjects( void );

    void synchronizePrivateKeyObjects( void );

    void synchronizeRootCertificateObjects( void );

    void synchronizeEmptyContainers( void );

    void createCertificateFromMiniDriverFile( const std::string&, const unsigned char&, const unsigned char& );

    void createCertificateFromPKCS11ObjectFile( const std::string&, const std::string& );

    void createPublicKeyFromPKCS11ObjectFile( const std::string& );

    void createPublicKeyFromMiniDriverFile( const std::string&, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, Marshaller::u1Array*, Marshaller::u1Array* );

    void createPrivateKeyFromPKCS11ObjectFile( const std::string& );

    void createPrivateKeyFromMiniDriverFile( const std::string&, const unsigned char&, const unsigned int&, Marshaller::u1Array*, Marshaller::u1Array* );

    bool isPrivate( const CK_OBJECT_HANDLE& a_ObjectHandle ) { return ( ( ( a_ObjectHandle >> 8 ) & 0x000000FF ) >= 0x00000010 ); }

    void checkAuthenticationStatus( CK_ULONG, MiniDriverException& );

    void printObject( StorageObject* );

    Marshaller::u1Array* computeSHA1( const unsigned char* a_pData, const size_t& a_uiLength );

    boost::mt19937 m_RandomNumberGenerator;

    Device* m_Device;

    TOKEN_OBJECTS m_Objects;

    std::vector< StorageObject* > m_ObjectsToCreate;

    //std::vector< std::string > m_ObjectsToDelete;

    CK_TOKEN_INFO m_TokenInfo;

    CK_ULONG m_RoleLogged;

    unsigned char m_uiObjectIndex;

    bool m_bCreateDirectoryP11;

    bool m_bCreateTokenInfoFile;

    bool m_bWriteTokenInfoFile;

    bool m_bSynchronizeObjectsPublic;

    bool m_bSynchronizeObjectsPrivate;

    std::set< CK_OBJECT_HANDLE > m_TokenObjectsReturnedInSearch;

    Slot* m_pSlot;

    unsigned char computeIndex( const std::string& );

    void generateDefaultAttributesCertificate( X509PubKeyCertObject* );

    void generateDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublicRSA* );

    void generateDefaultAttributesKeyPrivate( RSAPrivateKeyObject* );

    void generateLabel( boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>& );

    void generateID(boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>& );

    void generateSubject( boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>& );

    void generateSerialNumber( boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>& );

    void generateIssuer( boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>& );

    void generatePublicKeyModulus( boost::shared_ptr< Marshaller::u1Array>&, boost::shared_ptr< Marshaller::u1Array>&, u8& );

    void generateRootAndSmartCardLogonFlags( boost::shared_ptr< Marshaller::u1Array>&, bool&, unsigned long&, bool& );

    void searchContainerIndex( boost::shared_ptr< Marshaller::u1Array>&, unsigned char&, unsigned char& );

    void setDefaultAttributesCertificate( X509PubKeyCertObject* );

    void setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublicRSA* );

    void setDefaultAttributesKeyPrivate( RSAPrivateKeyObject* );

    void setContainerIndexToCertificate( boost::shared_ptr< Marshaller::u1Array>&, const unsigned char&, const unsigned char& );

    void setContainerIndexToKeyPublic( boost::shared_ptr< Marshaller::u1Array>&, const unsigned char&, const unsigned char& );

    void computeObjectNameData( std::string&, /*const*/ StorageObject* );

    void computeObjectNamePublicKey( std::string&, /*const*/ StorageObject* );
    
    void computeObjectNamePrivateKey( std::string&, /*const*/ StorageObject* );

    void computeObjectNameCertificate( std::string&, /*const*/ StorageObject* );

    void incrementObjectIndex( void );

    bool isObjectNameValid( const std::string&, const MiniDriverFiles::FILES_NAME& );

};


#endif // __GEMALTO_TOKEN__
