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


#ifndef __GEMALTO_SESSION__
#define __GEMALTO_SESSION__


#include "Template.hpp"
#include "digest.h"
#include "Pkcs11ObjectStorage.hpp"
#include <set>
#include <vector>
#include <boost/smart_ptr.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include "Array.hpp"
#include "cryptoki.h"


class Slot;


/*
*/
class CryptoOperation {

    CK_ULONG m_ulMechanism;

    CK_OBJECT_HANDLE m_hObject;
    //StorageObject* m_pObject;

public:

    //CryptoOperation( const CK_ULONG& a_ulMechanism, StorageObject* a_pObject ) : m_ulMechanism( a_ulMechanism ), m_pObject( a_pObject ) { }
    CryptoOperation( const CK_ULONG& a_ulMechanism, const CK_OBJECT_HANDLE& a_hObject ) : m_ulMechanism( a_ulMechanism ), m_hObject( a_hObject ) { }

    //virtual ~CryptoOperation( ) { };

public:

    inline const CK_ULONG& getMechanism( void ) { return m_ulMechanism; }

    //inline StorageObject* getObject( void ) { return m_pObject; }
    inline CK_OBJECT_HANDLE& getObject( void ) { return m_hObject; }

};



/*
*/
class Session {

public:

    typedef std::set< CK_OBJECT_HANDLE > EXPLORED_HANDLES;

    typedef boost::ptr_map< CK_OBJECT_HANDLE, StorageObject > SESSION_OBJECTS;

    Session( Slot*, const CK_SESSION_HANDLE&, const CK_BBOOL& );

    //inline virtual ~Session( ) { }

    inline CK_BBOOL isReadWrite( void ) { return m_bIsReadWrite; }

    inline CK_FLAGS getFlags( void ) { return ( ( m_bIsReadWrite ? CKF_RW_SESSION : 0 ) | CKF_SERIAL_SESSION ); }

    CK_STATE getState( void ); // { return m_ulState; }

    CDigest* getDigest( void ) { return m_Digest.get( ); }

    inline Marshaller::u1Array* getPinSO( void ) { return m_PinSO.get( ); }

    inline void setSearchTemplate( Template* templ ) { _searchTempl.reset( templ ); m_bIsSearchActive = true; m_SessionObjectsReturnedInSearch.clear( ); }

    inline void removeSearchTemplate( void ) {_searchTempl.reset( ); m_bIsSearchActive = false; }

    inline bool isDecryptionActive( void ) { return (bool)_decryption; }

    inline bool isSignatureActive( void ) { return (bool)m_Signature; }

    void updateState( const CK_ULONG& );

    inline bool isSearchActive( void ) { return m_bIsSearchActive; }

    inline bool isDigestActive( void ) { return m_bIsDigestActive; }

    inline bool isDigestActiveRSA( void ) { return m_bIsDigestActiveRSA; }

    inline bool isDigestVerificationActiveRSA( void ) { return m_bIsDigestVerificationActiveRSA; }

    void addObject( StorageObject*, CK_OBJECT_HANDLE_PTR );

    void deleteObject( const CK_OBJECT_HANDLE& );

    void findObjects( CK_OBJECT_HANDLE_PTR, const CK_ULONG&, CK_ULONG_PTR);

    void getAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    void setAttributeValue( const CK_OBJECT_HANDLE&, CK_ATTRIBUTE_PTR, const CK_ULONG& );

    inline void setSlot( boost::shared_ptr< Slot > a_pSlot ) { m_Slot = a_pSlot.get( ); }

    StorageObject* getObject( const CK_OBJECT_HANDLE& a_hObject );

    inline boost::shared_ptr< CryptoOperation >& getSignature( void ) { return m_Signature; }

    inline void setEncryptionOperation( CryptoOperation *encryption ) { _encryption.reset( encryption ); }

    inline void removeEncryptionOperation( void ) { _encryption.reset( ); }

    inline bool isEncryptionActive( void ) { return (_encryption.get( ) != NULL_PTR); }

    inline void setVerificationOperation( CryptoOperation *verification ) { _verification.reset( verification ); }

    inline void removeVerificationOperation( void ) { _verification.reset( ); }

    inline bool isVerificationActive( void ) { return (_verification.get( ) != NULL_PTR); }

    inline void setDecryptionOperation( CryptoOperation *decryption ) { _decryption.reset( decryption ); }

    inline void removeDecryptionOperation( void ) { _decryption.reset( ); }

    inline void setSignatureOperation( const boost::shared_ptr< CryptoOperation >& co ) { m_Signature = co; }

    inline void removeSignatureOperation( void ) { m_Signature.reset( ); }

    inline void setPinSO( Marshaller::u1Array& a ) { m_PinSO.reset( new Marshaller::u1Array( a.GetLength( ) ) ); m_PinSO->SetBuffer( a.GetBuffer( ) ); }

    inline void setDigest(CDigest *digest) { m_Digest.reset( digest ); m_bIsDigestActive = true; }

    inline void removeDigest( void ) { m_Digest.reset( ); m_bIsDigestActive = false; }

    inline void setDigestRSA( CDigest *digest ) { _digestRSA.reset( digest ); m_bIsDigestActiveRSA = true; }

    inline void removeDigestRSA( void ) { _digestRSA.reset( ); m_bIsDigestActiveRSA = false; }

    inline void setDigestRSAVerification( CDigest *digest ) { _digestRSAVerification.reset( digest ); m_bIsDigestVerificationActiveRSA = true; }

    inline void removeDigestRSAVerification( void ) { _digestRSAVerification.reset( ); m_bIsDigestVerificationActiveRSA = false; }

    //private:
    static unsigned char s_ucSessionObjectIndex;

    CK_OBJECT_HANDLE computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ); 

    CK_BBOOL m_bIsReadWrite;

    CK_ULONG m_ulState;

    SESSION_OBJECTS m_Objects;

    boost::shared_ptr< Template > _searchTempl;

    boost::shared_ptr< CDigest > m_Digest;

    boost::shared_ptr< CDigest > _digestRSA;

    boost::shared_ptr< CDigest > _digestRSAVerification;

    EXPLORED_HANDLES m_SessionObjectsReturnedInSearch;

    boost::shared_ptr< CryptoOperation > m_Signature;

    boost::shared_ptr< CryptoOperation > _decryption;

    boost::shared_ptr< CryptoOperation > _verification;

    boost::shared_ptr< CryptoOperation > _encryption;

    bool m_bIsSearchActive;

    bool m_bIsDigestActive;

    bool m_bIsDigestActiveRSA;

    bool m_bIsDigestVerificationActiveRSA;

    CK_ULONG m_ulId;

    Slot* m_Slot;

    boost::shared_ptr< Marshaller::u1Array > m_AccumulatedDataToSign;

    boost::shared_ptr< Marshaller::u1Array > m_AccumulatedDataToVerify;

    // The CardModule interface requires cryptogram as part of ChangeReferenceData method whereas
    // PKCS#11 first log SO in and then call InitPIN. InitPIN does not have any information about 
    // SO PIN so what we do here is to cache it momentarily. Basically during Login (as SO) we 
    // cache it and destroy it during closing of session
    boost::shared_ptr< Marshaller::u1Array > m_PinSO;

};

#endif // __GEMALTO_SESSION__
