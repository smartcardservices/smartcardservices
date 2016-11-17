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


#include "Slot.hpp"
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/array.hpp>
#include "cryptoki.h"
#include "Template.hpp"
#include "digest.h"
#include "sha1.h"
#include "sha256.h"
#include "md5.h"
#include "Pkcs11ObjectData.hpp"
#include "Pkcs11ObjectKeyPrivateRSA.hpp"
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "Pkcs11ObjectCertificateX509PublicKey.hpp"
#include "Log.hpp"


CK_MECHANISM_TYPE g_mechanismList[ ] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, // 0
    CKM_RSA_PKCS,              // 1
    CKM_RSA_X_509,             // 2
    CKM_MD5_RSA_PKCS,          // 3
    CKM_SHA1_RSA_PKCS,         // 4
    CKM_SHA256_RSA_PKCS,       // 5
    CKM_MD5,                   // 6
    CKM_SHA_1,                 // 7
    CKM_SHA256,                // 8
};

CK_MECHANISM_INFO g_mechanismInfo[] = {
    {/* 0 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_GENERATE_KEY_PAIR },
    {/* 1 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT },
    {/* 2 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT },
    {/* 3 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 4 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 5 */  MiniDriver::s_iMinLengthKeyRSA, MiniDriver::s_iMaxLengthKeyRSA, CKF_HW | CKF_SIGN | CKF_VERIFY },
    {/* 6 */  0,0, CKF_DIGEST },
    {/* 7 */  0,0, CKF_DIGEST },
    {/* 8 */  0,0, CKF_DIGEST },
};

const int g_iLabelSize = 32;

// Index used to compute the session handle. The first session handle must start from 1 because 0 is used for an unvalid handle
unsigned char Slot::s_ucSessionIndex = 0;


/*
*/
Slot::Slot( const boost::shared_ptr < Device >& a_pDevice ) {

    Log::begin( "Slot::Slot" ); 

    // LCA: used to remember card insertion
    m_isTokenInserted = false;

    //m_SessionState = CKS_RO_PUBLIC_SESSION;

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;

    m_stEmpty = "";

    m_ucEventSlotId = 0xFF;

    m_bEvent = false;

    // Store a pointer to the device instance
    m_Device = a_pDevice;

    try {

        // Create a token instance if a smart card is present into the reader
        if( m_Device.get( ) && m_Device->isSmartCardPresent( ) ) {

            Log::log( "Slot::Slot - Reader Name <%s> - SmartCard present <%d>", m_Device->getReaderName( ).c_str( ), m_Device->isSmartCardPresent( ) );

            //m_Token.reset( new Token( this, m_Device.get( ) ) );

            //// Analyse the current state of the smart card to consider the slot as connected or not
            //if( m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_Device->isAuthenticated( ) ) ) {

            //    Log::log( "Slot::Slot - No PIN or SSO activated" );

            //    m_ulUserType = CKU_USER;
            //}

            tokenInserted( );
        }

    } catch( MiniDriverException& ) {

        m_Token.reset( );

        Log::error( "Slot::Slot", "MiniDriverException" );
    }

    // Initialize the slot info
    memset( &m_SlotInfo, 0, sizeof( CK_SLOT_INFO ) );

    m_SlotInfo.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;

    memset( m_SlotInfo.slotDescription, ' ', sizeof( m_SlotInfo.slotDescription ) );

    if( m_Device.get( ) ) {

        memcpy( m_SlotInfo.slotDescription, m_Device->getReaderName( ).c_str( ), m_Device->getReaderName( ).length( ) );
    }

    memset( m_SlotInfo.manufacturerID, ' ', sizeof( m_SlotInfo.manufacturerID ) );

    m_SlotInfo.manufacturerID[0] = 'U';
    m_SlotInfo.manufacturerID[1] = 'n';
    m_SlotInfo.manufacturerID[2] = 'k';
    m_SlotInfo.manufacturerID[3] = 'n';
    m_SlotInfo.manufacturerID[4] = 'o';
    m_SlotInfo.manufacturerID[5] = 'w';
    m_SlotInfo.manufacturerID[6] = 'n';

    Log::end( "Slot::Slot" ); 
}


/*
*/
inline void Slot::tokenCreate( void ) { 
        
    m_ulUserType = CK_UNAVAILABLE_INFORMATION; 
        
    m_Token.reset( new Token( this, m_Device.get( ) ) ); 
   
    try { 

        // Analyse the current state of the smart card to consider the slot as connected or not
        if( m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_Device->isAuthenticated( ) ) ) {

            Log::log( "Slot::Slot - No PIN or SSO activated" );

            m_ulUserType = CKU_USER;
        }
                    
        if( !Device::s_bEnableCache && m_Device.get( ) ) { 
                
            m_Device->forceGarbageCollection( ); 
        } 
            
        updateAllSessionsState( ); 
        
    } catch( ... ) { } 
}

	
/*
*/
void Slot::finalize( void ) {

    Log::begin( "Slot::finalize" ); 

    //m_SessionState = CKS_RO_PUBLIC_SESSION;

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;

    try {

        closeAllSessions( );

        if( m_Device.get( ) ) {

            if( m_Device->isSmartCardPresent( ) ) {

                m_Device->logOut( );

                m_Device->administratorLogout( );

                if( !Device::s_bEnableCache ) {

                    m_Device->forceGarbageCollection( );
                }
            }

            m_Device->saveCache( );
        }

    } catch( ... ) { }

    Log::end( "Slot::finalize" ); 
}


/*
*/
void Slot::checkTokenInsertion( void ) {

    if( m_isTokenInserted ) {

        tokenCreate( );

        m_isTokenInserted = false;

        m_Device->saveCache( );
    }
}


/*
*/
void Slot::getInfo( CK_SLOT_INFO_PTR p ) {

    if( !p ) {

        return;
    }

    memcpy( p->slotDescription, m_SlotInfo.slotDescription, sizeof( p->slotDescription ) );

    memcpy( p->manufacturerID, m_SlotInfo.manufacturerID, sizeof( p->manufacturerID ) );

    p->hardwareVersion.major = m_SlotInfo.hardwareVersion.major;

    p->hardwareVersion.minor = m_SlotInfo.hardwareVersion.minor;

    p->firmwareVersion.major = m_SlotInfo.firmwareVersion.major;

    p->firmwareVersion.minor = m_SlotInfo.firmwareVersion.minor;

    // No card in reader
    m_SlotInfo.flags &= ~CKF_TOKEN_PRESENT;


// LCA: Token inserted?
    checkTokenInsertion( );

    try {

        if( getToken( ).get( ) ) { //m_Device.get( ) && m_Device->isSmartCardPresent( ) ) {

            // we found a card in this reader
            m_SlotInfo.flags |= CKF_TOKEN_PRESENT;
        } 

    } catch( ... ) { }

    p->flags = m_SlotInfo.flags;
}


/*
*/
void Slot::getTokenInfo( CK_TOKEN_INFO_PTR p ) {

    if( !p ) {

        return;
    }

    // LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    //Log::begin( "Slot::GetTokenInfo" );

    try {

        p->firmwareVersion.major = m_Token->getTokenInfo( ).firmwareVersion.major;
        p->firmwareVersion.minor = m_Token->getTokenInfo( ).firmwareVersion.minor;
        p->hardwareVersion.major = m_Token->getTokenInfo( ).hardwareVersion.major;
        p->hardwareVersion.minor = m_Token->getTokenInfo( ).hardwareVersion.minor;

        memcpy( p->label, m_Token->getTokenInfo( ).label, sizeof( p->label ) );

        memcpy( p->manufacturerID, m_Token->getTokenInfo( ).manufacturerID, sizeof( p->manufacturerID ) );

        memcpy( p->model, m_Token->getTokenInfo( ).model, sizeof( p->model ) );

        memcpy( p->serialNumber, m_Token->getTokenInfo( ).serialNumber, sizeof( p->serialNumber ) );

        //Log::logCK_UTF8CHAR_PTR( "Slot::GetTokenInfo - m_TokenInfo.serialNumber", m_Token->getTokenInfo( ).serialNumber, sizeof( m_Token->getTokenInfo( ).serialNumber ) );

        p->ulFreePrivateMemory  = m_Token->getTokenInfo( ).ulFreePrivateMemory;
        p->ulFreePublicMemory   = m_Token->getTokenInfo( ).ulFreePublicMemory;
        p->ulMaxPinLen          = m_Token->getTokenInfo( ).ulMaxPinLen;
        p->ulMinPinLen          = m_Token->getTokenInfo( ).ulMinPinLen;
        p->ulMaxRwSessionCount  = CK_EFFECTIVELY_INFINITE;
        p->ulSessionCount       = 0;
        p->ulMaxSessionCount    = CK_EFFECTIVELY_INFINITE;
        p->ulRwSessionCount     = 0;
        p->ulTotalPrivateMemory = m_Token->getTokenInfo( ).ulTotalPrivateMemory;
        p->ulTotalPublicMemory  = m_Token->getTokenInfo( ).ulTotalPublicMemory;

        BOOST_FOREACH( const MAP_SESSIONS::value_type& s, m_Sessions ) {

            // Count the number of opened sessions
            ++p->ulSessionCount;

            if( s.second->isReadWrite( ) ) {

                ++p->ulRwSessionCount;
            }
        }

        memcpy( p->utcTime, m_Token->getTokenInfo( ).utcTime, sizeof( p->utcTime ) );

        if( !m_Device.get( ) ) {

            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
        }

        try {

            //Log::log( "Slot::GetTokenInfo - isNoPinSupported <%d>", m_Device->isNoPin( ) );
            //Log::log( "Slot::GetTokenInfo - IsSSO <%d>", m_Device->isSSO( ) );
            //Log::log( "Slot::GetTokenInfo - IsAuthenticated <%d>", bIsAuthenticated );

            // Check if the smart card is in SSO mode
            if(  m_Device->isNoPin( ) || ( m_Device->isSSO( ) && isAuthenticated( ) ) ) {

                m_Token->getTokenInfo( ).flags &= ~CKF_LOGIN_REQUIRED;
                //Log::log( "Slot::GetTokenInfo - No login required" );

            } else {

                m_Token->getTokenInfo( ).flags |= CKF_LOGIN_REQUIRED;
                //Log::log( "Slot::GetTokenInfo - Login required" );
            }

        } catch( MiniDriverException& x ) {

            Log::error( "Slot::getTokenInfo", "MiniDriverException" );
            throw PKCS11Exception( Token::checkException( x ) );
        }

        p->flags = m_Token->getTokenInfo( ).flags;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    //Log::end( "Slot::GetTokenInfo" );
}


/*
*/
void Slot::getMechanismList( CK_MECHANISM_TYPE_PTR a_pMechanismList, CK_ULONG_PTR a_pulCount ) {

    size_t l = sizeof( g_mechanismList ) / sizeof( CK_ULONG );

    if( *a_pulCount < l ) {

        *a_pulCount = l;
        
        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    if( a_pMechanismList ) {
    
        for( size_t i = 0 ; i < l ; ++i ) {

            a_pMechanismList[ i ] = g_mechanismList[ i ];
        }
     }
  
    *a_pulCount = l;
}


/*
*/
void Slot::getMechanismInfo( const CK_MECHANISM_TYPE& t, CK_MECHANISM_INFO_PTR p ) {

    //if( !p ) {

    //    return;
    //}

    size_t i = 0;

    bool found = false;

    size_t l = sizeof( g_mechanismList ) / sizeof( CK_ULONG );

    for( ; i < l ; ++i ) {

        if( g_mechanismList[ i ] == t ) {

            found = true;

            break;
        }
    }

    if( !found ) {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    p->ulMinKeySize = g_mechanismInfo[ i ].ulMinKeySize;

    p->ulMaxKeySize = g_mechanismInfo[ i ].ulMaxKeySize;

    p->flags = g_mechanismInfo[ i ].flags;
}


/*
*/
void Slot::initToken( CK_UTF8CHAR_PTR pPin, const CK_ULONG& ulPinLen, CK_UTF8CHAR_PTR pLabel ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check if we have an open session
    if( m_Sessions.size( ) ) {

        throw PKCS11Exception( CKR_SESSION_EXISTS );
    }

    Marshaller::u1Array p( ulPinLen );
    p.SetBuffer( pPin );

    Marshaller::u1Array l( g_iLabelSize );
    l.SetBuffer( pLabel );

    try {

        m_Token->initToken( &p, &l );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::checkAccessException( const PKCS11Exception& a_Exception ) {

    if( CKR_USER_NOT_LOGGED_IN == a_Exception.getError( ) ) {

        Log::log( "Slot::checkAccessException - !! User desauthenticated !!" );

        m_ulUserType = CK_UNAVAILABLE_INFORMATION;

        // Update the state of all sessions because write access is no more allowed
        updateAllSessionsState( );
    }
}


/*
*/
void Slot::openSession( const CK_FLAGS& flags, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR phSession ) {

    bool bIsReadWrite = ( ( flags & CKF_RW_SESSION ) == CKF_RW_SESSION );


// LCA: Token inserted?
    checkTokenInsertion( );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }


    // if admin is logged we can not open R/O session because R/O session is not allowed for SO
    if( administratorIsAuthenticated( ) && !bIsReadWrite ) {

        throw PKCS11Exception( CKR_SESSION_READ_WRITE_SO_EXISTS );
    }

    // Create the session
    *phSession = addSession( bIsReadWrite );
}


/*
*/
void Slot::closeAllSessions( void ) {

    try {

        // The user or SO must be desauthenticated
        if( isAuthenticated( ) || administratorIsAuthenticated( ) ) {
        
            if( m_Device.get( ) && m_Device->isSmartCardPresent( ) ) {

                if( m_Token.get( ) ) {

                    m_Token->logout( );
                }
            }
        }

    } catch( ... ) { }

    m_Sessions.clear( );

    //m_SessionState = CKS_RO_PUBLIC_SESSION;
    m_ulUserType = CK_UNAVAILABLE_INFORMATION;
}


/*
*/
void Slot::closeSession( const CK_SESSION_HANDLE& a_hSession ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    getSession( a_hSession );

    m_Sessions.erase( a_hSession );

    try {

        // Last session ? The user or SO must be desauthenticated
        if( !m_Sessions.size( ) && ( isAuthenticated( ) || administratorIsAuthenticated( ) ) ) {

            m_Token->logout( );

            //m_SessionState = CKS_RO_PUBLIC_SESSION;

            m_ulUserType = CK_UNAVAILABLE_INFORMATION;
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::getSessionInfo( const CK_SESSION_HANDLE& a_hSession, CK_SESSION_INFO_PTR a_pInfo ) {

    Session* s = getSession( a_hSession );

    // Return the session information
    unsigned char ucDeviceID = 0xFF;

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        ucDeviceID = m_Device->getDeviceID( );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::getSessionInfo", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    a_pInfo->slotID = ucDeviceID;

    //// Lead Firefox to crash when it is called from the "Certificate Manager"
    //// when the smart card was previously logged in by Firefox but is now logged 
    //// out by another application than Firefox:
    //// Check that the user is still logged in
    if( m_ulUserType == CKU_USER ) {

        if ( m_Device.get( ) && !m_Device->isAuthenticated( ) ) {
        
            m_ulUserType = CK_UNAVAILABLE_INFORMATION;

            // Update the state of all sessions because write access is no more allowed
            updateAllSessionsState( );
        }
    }

    a_pInfo->state = s->getState( );

    a_pInfo->flags = s->getFlags( );

    a_pInfo->ulDeviceError = CKR_OK;
}


/*
*/
void Slot::login( const CK_SESSION_HANDLE& a_hSession, const CK_USER_TYPE& a_UserType, CK_UTF8CHAR_PTR a_pPin, const CK_ULONG& a_ulPinLen ) {

    if( !m_Token.get(  ) || !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        // The smart card is configured in "no pin" mode
        if( m_Device->isNoPin( ) && !administratorIsAuthenticated( ) ) {

            //m_SessionState = s->isReadWrite( ) ? ( ( CKU_USER == a_UserType ) ? CKS_RW_USER_FUNCTIONS : CKS_RW_SO_FUNCTIONS ) : ( ( CKU_USER == a_UserType ) ? CKS_RO_USER_FUNCTIONS : CKS_RW_SO_FUNCTIONS );

            m_ulUserType = a_UserType;

            updateAllSessionsState( );

            return;
        }

        // The smart card is configured in "sso" mode and the end-user is already logged in
        if( m_Device->isSSO( ) && isAuthenticated( ) ) {

            m_ulUserType = a_UserType;

            updateAllSessionsState( );

            return;
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::login", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );
    }

    // The SO wants to log in but a session exists
    if( ( CKU_SO == a_UserType ) && hasReadOnlySession( ) ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY_EXISTS );
    }

    CK_ULONG ulPinLen = a_ulPinLen;

    if( !a_pPin ) {

        ulPinLen = 0;
    }

    Marshaller::u1Array pPin( a_ulPinLen );

    pPin.SetBuffer( a_pPin );

    try {

        m_Token->login( a_UserType, &pPin );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( CKU_SO == a_UserType ) {

        // cache SO PIN for the duration of this session        
        if( s ) {

            s->setPinSO( pPin );
        }
    }

    m_ulUserType = a_UserType;

    // Update the state of all sessions because write access is now allowed
    updateAllSessionsState( );
}


/*
*/
void Slot::logout( const CK_SESSION_HANDLE& a_hSession ) {

    if( !m_Device.get( ) || !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    getSession( a_hSession );

    try {

        // Log out from the smart card
        m_Token->logout( );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_ulUserType = CK_UNAVAILABLE_INFORMATION;

    // Analyse the current stae of the smart card to consider the slot as connected or not
    if( m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_Device->isAuthenticated( ) ) ) {

        m_ulUserType = CKU_USER;
    }

    // Update the state of all sessions because write access is no more allowed
    updateAllSessionsState( );
}


/*
*/
void Slot::updateAllSessionsState( void ) {

    //CK_ULONG ulRole = CK_UNAVAILABLE_INFORMATION;
    //
    //    if( isAuthenticated( ) ) {

    //        ulRole = CKU_USER;

    //    } else if( administratorIsAuthenticated( ) ) {

    //        ulRole = CKU_SO;
    //    }

    BOOST_FOREACH( const MAP_SESSIONS::value_type& i, m_Sessions ) {

        if( i.second ) {

            i.second->updateState( m_ulUserType );
        }
    }
}


/*
*/
void Slot::initPIN( const CK_SESSION_HANDLE& a_hSession, CK_UTF8CHAR_PTR a_pPin, const CK_ULONG& a_ulPinLen ) {

    Session* s = getSession( a_hSession );

    if( CKS_RW_SO_FUNCTIONS != s->getState( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    Marshaller::u1Array p( a_ulPinLen );
    p.SetBuffer( a_pPin );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Token->initPIN( s->getPinSO( ), &p );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setPIN( const CK_SESSION_HANDLE& a_hSession, CK_UTF8CHAR_PTR a_pOldPin, const CK_ULONG& a_ulOldLen, CK_UTF8CHAR_PTR a_pNewPin, const CK_ULONG& a_ulNewLen ) {

    Session* s = getSession( a_hSession );

    CK_ULONG ulState = s->getState( );

    if( ( CKS_RW_PUBLIC_SESSION != ulState ) && ( CKS_RW_SO_FUNCTIONS != ulState ) && ( CKS_RW_USER_FUNCTIONS != ulState ) ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY );
    }

    Marshaller::u1Array o( a_ulOldLen );
    o.SetBuffer( a_pOldPin );

    Marshaller::u1Array n( a_ulNewLen );
    n.SetBuffer( a_pNewPin );

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Token->setPIN( &o, &n );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::findObjectsInit( const CK_SESSION_HANDLE& a_hSession, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( s->isSearchActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    Template* searchTmpl = NULL_PTR;

    if( a_ulCount ) {

        searchTmpl = new Template( a_pTemplate, a_ulCount );
    }

    s->removeSearchTemplate( );

    s->setSearchTemplate( searchTmpl );

    if( !m_Token ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Token->findObjectsInit( );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::closeSession", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::findObjects( const CK_SESSION_HANDLE& a_hSession, CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( !s->isSearchActive( )  ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    *a_pulObjectCount = 0;

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Find the token objects matching the template
        m_Token->findObjects( s, a_phObject, a_ulMaxObjectCount, a_pulObjectCount );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the session objects matching the template
    s->findObjects( a_phObject, a_ulMaxObjectCount, a_pulObjectCount );
}


/*
*/
void Slot::findObjectsFinal( const CK_SESSION_HANDLE& a_hSession ) {

    Session* s = getSession( a_hSession );

    // check if search is active for this session or not
    if( !s->isSearchActive( )  ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    s->removeSearchTemplate( );
}


/*
*/
void Slot::createObject( const CK_SESSION_HANDLE& a_hSession, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount, CK_OBJECT_HANDLE_PTR a_phObject ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check template consistency
    Template t;
    t.checkTemplate( a_pTemplate, a_ulCount, Template::MODE_CREATE );

    bool bIsToken = t.isToken( a_pTemplate, a_ulCount );

    // if this is a readonly session and user is not logged 
    // then only public session objects can be created
    Session* s = getSession( a_hSession );

    if( !s->isReadWrite( ) && bIsToken ) {

        throw PKCS11Exception( CKR_SESSION_READ_ONLY );
    }

    StorageObject* o = 0;

    CK_ULONG ulClass = t.getClass( a_pTemplate, a_ulCount );

    switch( ulClass ) {

    case CKO_DATA:
        o = new DataObject( );
        break;

    case CKO_PUBLIC_KEY:
        o = new Pkcs11ObjectKeyPublicRSA( );
        break;

    case CKO_PRIVATE_KEY:
        o = new RSAPrivateKeyObject( );
        break;

    case CKO_CERTIFICATE:
        o = new X509PubKeyCertObject( );
        break;

    default:
        throw PKCS11Exception( CKR_ATTRIBUTE_TYPE_INVALID );
    }

    for( CK_BYTE idx = 0; idx < a_ulCount; ++idx ) {

        o->setAttribute( a_pTemplate[ idx ], true );
    }

    switch( ulClass ) {

    case CKO_PUBLIC_KEY:
        if(((Pkcs11ObjectKeyPublicRSA*)o)->_keyType != CKK_RSA) {

            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        }
        break;

    case CKO_PRIVATE_KEY:
        if(((RSAPrivateKeyObject*)o)->_keyType != CKK_RSA) {

            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        }
        break;
    }

    if( bIsToken ) {

        switch( ulClass ) {

        case CKO_PUBLIC_KEY:
            m_Token->addObjectPublicKey( (Pkcs11ObjectKeyPublicRSA*)o, a_phObject );
            break;

        case CKO_PRIVATE_KEY:
            m_Token->addObjectPrivateKey( (RSAPrivateKeyObject*)o, a_phObject );
            break;

        case CKO_CERTIFICATE:
            m_Token->addObjectCertificate( (X509PubKeyCertObject*)o, a_phObject );
            break;

        default:
            m_Token->addObject( o, a_phObject );
            break;
        }

    } else {

        s->addObject( o, a_phObject );
    }
}


/*
*/
void Slot::destroyObject( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        // from object handle we can determine if it is a token object or session object
        if( m_Token->isToken( a_hObject ) ) {

            // if this is a readonly session and user is not logged then only public session objects can be created
            if( !s->isReadWrite( ) ) {

                throw PKCS11Exception( CKR_SESSION_READ_ONLY );
            }

            m_Token->deleteObject( a_hObject );

        } else {

            s->deleteObject( a_hObject );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::getAttributeValue( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        if( m_Token->isToken( a_hObject ) ) {

            m_Token->getAttributeValue( a_hObject, a_pTemplate, a_ulCount );

        } else {

            m_Sessions.at( a_hSession ).getAttributeValue( a_hObject, a_pTemplate, a_ulCount );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setAttributeValue( const CK_SESSION_HANDLE& a_hSession, const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    try {

        if( m_Token->isToken( a_hObject ) ) {

            if( !s->isReadWrite( ) ) {

                throw PKCS11Exception( CKR_SESSION_READ_ONLY );
            }

            m_Token->setAttributeValue( a_hObject, a_pTemplate, a_ulCount );

        } else {

            s->setAttributeValue( a_hObject, a_pTemplate, a_ulCount );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::generateKeyPair( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR /*a_pMechanism*/, CK_ATTRIBUTE_PTR a_pPublicKeyTemplate, const CK_ULONG& a_ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR a_pPrivateKeyTemplate, const CK_ULONG& a_ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR a_phPublicKey,CK_OBJECT_HANDLE_PTR a_phPrivateKey ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    // Check Public Template Consitency
    Template t;
    t.checkTemplate( a_pPublicKeyTemplate, a_ulPublicKeyAttributeCount, Template::MODE_GENERATE_PUB );

    // Check Private Template Consitency
    t.checkTemplate( a_pPrivateKeyTemplate, a_ulPrivateKeyAttributeCount, Template::MODE_GENERATE_PRIV );

    // Create the PKCS11 public key
    Pkcs11ObjectKeyPublicRSA* rsaPubKey = new Pkcs11ObjectKeyPublicRSA( );

    // Create the PKCS11 private key
    RSAPrivateKeyObject* rsaPrivKey = new RSAPrivateKeyObject( );

    // Populate the PKCS11 public key
    try {

        for( unsigned long i = 0 ; i < a_ulPublicKeyAttributeCount ; ++i ) {

            rsaPubKey->setAttribute( a_pPublicKeyTemplate[ i ], true );
        }

        // Populate the PKCS11 private key
        for( unsigned long i = 0 ; i < a_ulPrivateKeyAttributeCount ; ++i ) {

            rsaPrivKey->setAttribute( a_pPrivateKeyTemplate[ i ], true );
        }

        // Generate the key pair on cars
        if( rsaPrivKey->isToken( ) ) {

            m_Token->generateKeyPair( rsaPubKey, rsaPrivKey, a_phPublicKey, a_phPrivateKey );

        } else {

            // We do not support generation of key pair in the session
            throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
        }

        // Create the PKCS11 public key object on cache if it is not a token object
        if( rsaPubKey && !rsaPubKey->isToken( ) ) {

            s->addObject( rsaPubKey, a_phPublicKey );
        }

    } catch( MiniDriverException& x ) {

        // the generation failed
        delete rsaPrivKey;
        delete rsaPubKey;
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        // We do not support generation of key pair in the session
        delete rsaPrivKey;
        delete rsaPubKey;
        throw;

    } catch( ... ) {

        delete rsaPrivKey;
        delete rsaPubKey;
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::digestInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    switch( a_pMechanism->mechanism ) {

    case CKM_SHA_1:
        s->setDigest( new CSHA1( ) );
        break;

    case CKM_SHA256:
        s->setDigest( new CSHA256( ) );
        break;

    case CKM_MD5:
        s->setDigest( new CMD5( ) );
        break;

    default:
        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }
}


/*
*/
void Slot::digest( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pDigest, CK_ULONG_PTR a_pulDigestLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CDigest* digest = s->getDigest( );
    if( !digest ) {
        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }


    if((*a_pulDigestLen < (CK_ULONG)digest->hashLength( )) && a_pDigest ) {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );

    } else if(!a_pDigest) {

        *a_pulDigestLen = digest->hashLength( );

    } else {

        digest->hashCore(a_pData, 0, a_ulDataLen);

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        if( a_pDigest ) {
            digest->hashFinal(a_pDigest);

            s->removeDigest( );
        }
    }
}


/*
*/
void Slot::digestUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    s->getDigest( )->hashCore( a_pPart, 0, a_ulPartLen );
}


/*
*/
void Slot::digestFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pDigest, CK_ULONG_PTR a_pulDigestLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDigestActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CDigest* digest = s->getDigest( );
    if( !digest ) {
        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if((*a_pulDigestLen < (CK_ULONG)digest->hashLength( )) && a_pDigest ) {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );

    } else if( !a_pDigest ) {

        *a_pulDigestLen = digest->hashLength( );

    } else {

        *a_pulDigestLen = (CK_ULONG)digest->hashLength( );

        if ( a_pDigest ){

            digest->hashFinal( a_pDigest );

            s->removeDigest( );
        }
    }
}


/*
*/
void Slot::signInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    Session* s = getSession( a_hSession );

    if( s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_SIGN );

    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // from object handle we can determine
        // if it is a token object or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_SIGN );

    // Initialize this crypto operation
    boost::shared_ptr< CryptoOperation > co( new CryptoOperation( a_pMechanism->mechanism, a_hKey ) );

    s->setSignatureOperation( co );

    if( CKM_SHA1_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestRSA( new CSHA1( ) );

    } else if( CKM_SHA256_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestRSA( new CSHA256( ) );

    } else if( CKM_MD5_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestRSA( new CMD5( ) );
    }
}


/*
*/
void Slot::sign( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pSignature, CK_ULONG_PTR a_pulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    // Get the RSA private key object ot perform the signature
    RSAPrivateKeyObject *o = (RSAPrivateKeyObject*) m_Token->getObject( s->getSignature( )->getObject( ) );
    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    // Get the PKCS11 mechanism to use
    CK_ULONG m = s->getSignature( )->getMechanism( );

    // TBD : Private key may not necessarily have the modulus or modulus bits
    // if that is the case then we need to locate the corresponding public key
    // or may be I should always put the modulus bits in private key attributes

    Marshaller::u1Array* u = o->m_pModulus.get( );
    if( !u ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( ( ( m == CKM_RSA_PKCS ) && ( a_ulDataLen > u->GetLength( ) - 11 ) ) || ( ( m == CKM_RSA_X_509 ) && ( a_ulDataLen > u->GetLength( ) ) ) ) {

        throw PKCS11Exception( CKR_DATA_LEN_RANGE );
    }

    if( !a_pSignature ) {

        *a_pulSignatureLen = u->GetLength();

        return;

    } else if( *a_pulSignatureLen < u->GetLength( ) ) {

        *a_pulSignatureLen = u->GetLength();

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    boost::shared_ptr< Marshaller::u1Array > dataToSign;

    if( s->isDigestActiveRSA( ) ) {

        if( !s->_digestRSA ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* d = s->_digestRSA.get( );

        if( !d ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_BYTE_PTR h = new CK_BYTE[ d->hashLength( ) ];
        d->hashCore( a_pData, 0, a_ulDataLen );
        d->hashFinal( h );

        dataToSign.reset( new Marshaller::u1Array( d->hashLength( ) ) );
        dataToSign->SetBuffer( h );

        delete[ ] h;

    } else {

        // Sign Only
        dataToSign.reset( new Marshaller::u1Array( a_ulDataLen ) );
        dataToSign->SetBuffer( a_pData );
    }

    try {

        m_Token->sign( o, dataToSign.get( ), m, a_pSignature );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    *a_pulSignatureLen = u->GetLength( );

    s->removeDigestRSA( );

    s->removeSignatureOperation( );

    // Check if the user is still logged in
    // If the smart card is configured in "always PIN" mode
    // the PIN is automatically invalidated after a sign operation
    try {

        if( m_Device.get( ) && !m_Device->isAuthenticated( ) ) {

            // No user connected
            m_ulUserType = CK_UNAVAILABLE_INFORMATION;

            // Update the state of all sessions because write access is no more allowed
            updateAllSessionsState( );
        }

    } catch( ... ) { }
}


/* update the hash or if hashing is not getting used we just accumulate it
*/
void Slot::signUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( s->isDigestActiveRSA( ) ) {

        if( !s->_digestRSA ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        s->_digestRSA->hashCore( a_pPart, 0, a_ulPartLen );

    } else { // Sign Only

        if( s->m_AccumulatedDataToSign ) {

            // just accumulate the data
            Marshaller::u1Array* updatedData = new Marshaller::u1Array( s->m_AccumulatedDataToSign->GetLength() + a_ulPartLen);

            memcpy(updatedData->GetBuffer(),s->m_AccumulatedDataToSign->GetBuffer(),s->m_AccumulatedDataToSign->GetLength());

            memcpy((u1*)&updatedData->GetBuffer()[s->m_AccumulatedDataToSign->GetLength()], a_pPart, a_ulPartLen);

            s->m_AccumulatedDataToSign.reset( updatedData );

        } else {

            s->m_AccumulatedDataToSign.reset( new Marshaller::u1Array( a_ulPartLen ) );

            s->m_AccumulatedDataToSign->SetBuffer( a_pPart );
        }

        CK_ULONG m = s->getSignature( )->getMechanism( );

        StorageObject* o = NULL;

        try {

            o = m_Token->getObject( s->getSignature( )->getObject( ) );

        } catch( MiniDriverException& x ) {

            throw PKCS11Exception( Token::checkException( x ) );

        } catch( PKCS11Exception& x ) {

            checkAccessException( x );

            throw;

        } catch( ... ) {

            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
        }

        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        Marshaller::u1Array* u = ((RSAPrivateKeyObject*)o)->m_pModulus.get( );

        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if( ( ( m == CKM_RSA_PKCS ) && ( s->m_AccumulatedDataToSign->GetLength( ) > u->GetLength( ) - 11 ) ) ||
            ( ( m == CKM_RSA_X_509 ) && ( s->m_AccumulatedDataToSign->GetLength( ) > u->GetLength( ) ) ) ) {

                throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }
    }
}


/*
*/
void Slot::signFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pSignature, CK_ULONG_PTR a_pulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isSignatureActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    RSAPrivateKeyObject* o = (RSAPrivateKeyObject*) m_Token->getObject( s->getSignature( )->getObject( ) );
    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    // TBD : Private key may not necessarily have the modulus or modulus bits
    // if that is the case then we need to locate the corresponding public key
    // or may be I should always put the modulus bits in private key attributes

    Marshaller::u1Array* u = o->m_pModulus.get( );
    if( !u ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( !a_pSignature ) {

        *a_pulSignatureLen = u->GetLength( );

        return;

    } else if( *a_pulSignatureLen < u->GetLength( ) ) {

        *a_pulSignatureLen = u->GetLength( );

        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }

    boost::shared_ptr< Marshaller::u1Array > dataToSign;

    if( s->isDigestActiveRSA( ) ) {

        if( !s->_digestRSA ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* d = s->_digestRSA.get( );
        if( !d ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_BYTE_PTR h = new CK_BYTE[ d->hashLength( ) ];

        d->hashFinal( h );

        dataToSign.reset( new Marshaller::u1Array( d->hashLength( ) ) );

        dataToSign->SetBuffer( h );

    } else {

        // Sign Only
        dataToSign = s->m_AccumulatedDataToSign;
    }

    if( !s->m_Signature ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    m_Token->sign( o, dataToSign.get( ), s->m_Signature->getMechanism( ), a_pSignature );

    *a_pulSignatureLen = u->GetLength( );

    s->removeDigestRSA( );

    s->removeSignatureOperation( );

    s->m_AccumulatedDataToSign.reset( );
}


/*
*/
void Slot::encryptInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isEncryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_ENCRYPT );

    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    try {

        // from object handle we can determine
        // if it is a token object or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_ENCRYPT );

    // let's initialize this crypto operation
    s->setEncryptionOperation( new CryptoOperation( a_pMechanism->mechanism, a_hKey ) );
}


/*
*/
void Slot::encrypt( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pEncryptedData, CK_ULONG_PTR a_pulEncryptedDataLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isEncryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    StorageObject* o = NULL;

    Marshaller::u1Array* u = NULL;

    try {

        if( !s->_encryption ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        o = m_Token->getObject( s->_encryption->getObject( ) );
        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        u = ((Pkcs11ObjectKeyPublicRSA*)o)->m_pModulus.get( );
        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if( !a_pEncryptedData ) {

            *a_pulEncryptedDataLen = u->GetLength();

            return;

        } else {

            if( *a_pulEncryptedDataLen < u->GetLength( ) ) {

                *a_pulEncryptedDataLen = u->GetLength();

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }

        boost::shared_ptr< Marshaller::u1Array > dataToEncrypt( new Marshaller::u1Array( a_ulDataLen ) );
        dataToEncrypt->SetBuffer( a_pData );

        if( !s->_encryption ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        m_Token->encrypt( o, dataToEncrypt.get( ), s->_encryption->getMechanism( ), a_pEncryptedData );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    *a_pulEncryptedDataLen = u->GetLength( );

    s->removeEncryptionOperation( );
}


/*
*/
void Slot::decryptInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( ) /*|| !m_Device.get( )*/ ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isDecryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_DECRYPT );

    //try {

    //    if( !m_Device->isAuthenticated( ) ) {

    //        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    //    }

    //} catch( MiniDriverException& x ) {

    //    Log::error( "Slot::decryptInit", "MiniDriverException" );
    //    throw PKCS11Exception( Token::checkException( x ) );
    //}
    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    // from object handle we can know if it is a token or session object
    try {

        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey );

        } else {

            o = s->getObject( a_hKey );
        }

    } catch( PKCS11Exception& ) {

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_DECRYPT );

    // let's initialize this crypto operation
    s->setDecryptionOperation( new CryptoOperation( a_pMechanism->mechanism, a_hKey ) );
}


/*
*/
void Slot::decrypt( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pEncryptedData, const CK_ULONG& a_ulEncryptedDataLen, CK_BYTE_PTR a_pData, CK_ULONG_PTR a_pulDataLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isDecryptionActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( !s->_decryption ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    StorageObject* o = m_Token->getObject( s->_decryption->getObject( ) );
    if( !o ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CK_ULONG m = s->_decryption->getMechanism( );

    Marshaller::u1Array* u = ( (RSAPrivateKeyObject*) o)->m_pModulus.get( );
    if( !u ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    unsigned long l = (unsigned long)u->GetLength( );

    if( m == CKM_RSA_PKCS ) {

        // Can't know exact size of returned value before decryption has been done
        if( !a_pData ) {

            *a_pulDataLen = l - 11;

            return;
        }
    } else if( m == CKM_RSA_X_509 ) {

        if( !a_pData ) {

            *a_pulDataLen = l;

            return;

        } else {

            if( *a_pulDataLen < l ) {

                *a_pulDataLen = l;

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }
    } else {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }

    if( a_ulEncryptedDataLen != l ) {

        throw PKCS11Exception( CKR_ENCRYPTED_DATA_LEN_RANGE );
    }

    boost::shared_ptr< Marshaller::u1Array > dataToDecrypt( new Marshaller::u1Array( a_ulEncryptedDataLen ) );

    dataToDecrypt->SetBuffer( a_pEncryptedData );

    try {

        m_Token->decrypt( o, dataToDecrypt.get( ), m, a_pData, a_pulDataLen );

    } catch( MiniDriverException& x ) {

        s->removeDecryptionOperation( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        s->removeDecryptionOperation( );

        checkAccessException( x );

        throw;

    } catch( ... ) {

        s->removeDecryptionOperation( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    s->removeDecryptionOperation( );

    // Check if the user is still logged in
    // If the smart card is configured in "always PIN" mode
    // the PIN is automatically invalidated after a sign operation
    try {

        if( m_Device.get( ) && !m_Device->isAuthenticated( ) ) {

            // No user connected
            m_ulUserType = CK_UNAVAILABLE_INFORMATION;

            // Update the state of all sessions because write access is no more allowed
            updateAllSessionsState( );
        }

    } catch( ... ) { }
}


/*
*/
void Slot::verifyInit( const CK_SESSION_HANDLE& a_hSession, CK_MECHANISM_PTR a_pMechanism, const CK_OBJECT_HANDLE& a_hKey ) {

    if( !m_Token.get( )/* || !m_Device.get( )*/ ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_ACTIVE );
    }

    isValidMechanism( a_pMechanism->mechanism, CKF_VERIFY );

    /*   try {

    if( !m_Device->isAuthenticated( ) ) {

    throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    } catch( MiniDriverException& x ) {

    Log::error( "Slot::verifyInit", "MiniDriverException" );
    throw PKCS11Exception( Token::checkException( x ) );
    }*/
    if( !isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    // get the corresponding object
    StorageObject* o = 0;

    try {

        // from object handle we can know if it is a token or session object
        if( m_Token->isToken( a_hKey ) ) {

            o = m_Token->getObject( a_hKey);

        } else {

            o = s->getObject( a_hKey );

        }

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw PKCS11Exception( CKR_KEY_HANDLE_INVALID );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    isValidCryptoOperation( o, CKF_VERIFY );

    // Initialize this crypto operation
    s->setVerificationOperation( new CryptoOperation( a_pMechanism->mechanism, a_hKey ) );

    if( CKM_SHA1_RSA_PKCS == a_pMechanism->mechanism ) {

        s->setDigestRSAVerification( new CSHA1( ) );

    } else if( CKM_SHA256_RSA_PKCS == a_pMechanism->mechanism ) {

        s->setDigestRSAVerification( new CSHA256( ) );

    } else if(CKM_MD5_RSA_PKCS == a_pMechanism->mechanism ){

        s->setDigestRSAVerification( new CMD5( ) );
    }
}


/*
*/
void Slot::verify( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pData, const CK_ULONG& a_ulDataLen, CK_BYTE_PTR a_pSignature, const CK_ULONG a_ulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( !s->_verification ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    CK_ULONG m = s->_verification->getMechanism( );

    try {

        StorageObject* o = m_Token->getObject( s->_verification->getObject( ) );
        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        Marshaller::u1Array* u = ( (Pkcs11ObjectKeyPublicRSA*) o )->m_pModulus.get( );
        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if( ( ( m == CKM_RSA_PKCS ) && (a_ulDataLen > u->GetLength( ) - 11 ) ) || ( ( m == CKM_RSA_X_509 ) && ( a_ulDataLen > u->GetLength( ) ) ) ) {

            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }

        boost::shared_ptr< Marshaller::u1Array > dataToVerify;

        if( s->isDigestVerificationActiveRSA( ) ) {

            if( !s->_digestRSAVerification ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }

            // require hashing also
            CDigest* d = s->_digestRSAVerification.get( );
            if( !d ) {

                throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
            }

            CK_BYTE_PTR h = new CK_BYTE[ d->hashLength( ) ];

            d->hashCore( a_pData, 0, a_ulDataLen );

            d->hashFinal( h );

            dataToVerify.reset( new Marshaller::u1Array( d->hashLength( ) ) );

            dataToVerify->SetBuffer( h );

            delete[ ] h;

        } else { // Sign Only

            dataToVerify.reset( new Marshaller::u1Array( a_ulDataLen ) );

            dataToVerify->SetBuffer( a_pData );
        }

        boost::shared_ptr< Marshaller::u1Array > signature( new Marshaller::u1Array( a_ulSignatureLen ) );

        signature->SetBuffer( a_pSignature );

        m_Token->verify( o, dataToVerify.get( ), m, signature.get( ) );

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

    } catch( MiniDriverException& x ) {

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        throw;

    } catch( ... ) {

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*	Update the hash or if hashing is not getting used we just accumulate it
*/
void Slot::verifyUpdate( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pPart, const CK_ULONG& a_ulPartLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ){

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    if( s->isDigestVerificationActiveRSA( ) ) {

        if( !s->_digestRSAVerification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CDigest* digest = s->_digestRSAVerification.get( );
        if( !digest ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        digest->hashCore( a_pPart, 0, a_ulPartLen );

    } else { 

        // Sign Only

        if( s->m_AccumulatedDataToVerify.get( ) ) { 

            // just accumulate the data
            Marshaller::u1Array* pAccumulatedDataToVerify = s->m_AccumulatedDataToVerify.get( );

            Marshaller::u1Array* updatedData = new Marshaller::u1Array( pAccumulatedDataToVerify->GetLength( ) + a_ulPartLen );

            memcpy( updatedData->GetBuffer( ), pAccumulatedDataToVerify->GetBuffer( ), pAccumulatedDataToVerify->GetLength( ) );

            memcpy( (u1*)&updatedData->GetBuffer()[ pAccumulatedDataToVerify->GetLength( )], a_pPart, a_ulPartLen );

            s->m_AccumulatedDataToVerify.reset( updatedData );

        } else {

            s->m_AccumulatedDataToVerify.reset( new Marshaller::u1Array( a_ulPartLen ) );

            s->m_AccumulatedDataToVerify->SetBuffer( a_pPart );
        }

        if( !s->_verification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_ULONG m = s->_verification->getMechanism( );

        StorageObject* o = NULL;

        try {

            o = m_Token->getObject( s->_verification->getObject( ) );

        } catch( MiniDriverException& x ) {

            throw PKCS11Exception( Token::checkException( x ) );

        } catch( PKCS11Exception& x ) {

            checkAccessException( x );

            throw;

        } catch( ... ) {

            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
        }

        if( !o ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        Marshaller::u1Array* u = ( (Pkcs11ObjectKeyPublicRSA*) o )->m_pModulus.get( );

        if( !u ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        if((( m == CKM_RSA_PKCS) && (s->m_AccumulatedDataToVerify->GetLength() > u->GetLength() - 11)) ||
            (( m == CKM_RSA_X_509) && (s->m_AccumulatedDataToVerify->GetLength() > u->GetLength())))
        {
            throw PKCS11Exception( CKR_DATA_LEN_RANGE );
        }
    }
}


/*
*/
void Slot::verifyFinal( const CK_SESSION_HANDLE& a_hSession, CK_BYTE_PTR a_pSignature, const CK_ULONG& a_ulSignatureLen ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    Session* s = getSession( a_hSession );

    if( !s->isVerificationActive( ) ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    boost::shared_ptr< Marshaller::u1Array > dataToVerify;

    if( s->isDigestVerificationActiveRSA( ) ) {

        if( !s->_digestRSAVerification ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        // require hashing also
        CDigest* digest = s->_digestRSAVerification.get( );

        if( !digest ) {

            throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
        }

        CK_BYTE_PTR hash = new CK_BYTE[ digest->hashLength( ) ];

        digest->hashFinal( hash );

        dataToVerify.reset( new Marshaller::u1Array( digest->hashLength( ) ) );

        dataToVerify->SetBuffer( hash );

        delete[ ] hash;

    } else {

        // Sign Only
        dataToVerify = s->m_AccumulatedDataToVerify;
    }

    boost::shared_ptr< Marshaller::u1Array > signature( new Marshaller::u1Array( a_ulSignatureLen ) );

    signature->SetBuffer( a_pSignature );

    if( !s->_verification ) {

        throw PKCS11Exception( CKR_OPERATION_NOT_INITIALIZED );
    }

    try {

        StorageObject* o = m_Token->getObject( s->_verification->getObject( ) );

        m_Token->verify( o, dataToVerify.get( ), s->_verification->getMechanism( ), signature.get( ) );

    } catch( MiniDriverException& x ) {

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        checkAccessException( x );

        throw;

    } catch( ... ) {

        s->removeDigestRSAVerification( );

        s->removeVerificationOperation( );

        s->m_AccumulatedDataToVerify.reset( );

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    s->removeDigestRSAVerification( );

    s->removeVerificationOperation( );

    s->m_AccumulatedDataToVerify.reset( );
}


/*
*/
CK_SESSION_HANDLE Slot::addSession( const bool& a_bIsReadWrite ) {

    // Prepare a unique session id
    CK_SESSION_HANDLE h = computeSessionHandle( a_bIsReadWrite );

    // Create & store the session instance
    m_Sessions.insert( h, new Session( this, h, a_bIsReadWrite ) );

    // Return the session handle
    return h;
}


/*
*/
CK_SESSION_HANDLE Slot::computeSessionHandle( const bool& a_bIsReadWrite ) {

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // A session handle is a 4 or more bytes long unsigned data.
    CK_SESSION_HANDLE h = 0x00000000;

    // He here the convention to compute the session handle:

    // byte #1: session index. We do not accept to open more than 255 sessions.
    h |= ++s_ucSessionIndex;

    // byte #2: session properties has R/W or R/O
    h |= ( a_bIsReadWrite << 8 );

    // byte #3: slot index associated to this session
    unsigned char ucDeviceID = 0xFF;

    try {

        ucDeviceID = m_Device->getDeviceID( );

    } catch( MiniDriverException& x ) {

        Log::error( "Slot::computeSessionHandle", "MiniDriverException" );
        throw PKCS11Exception( Token::checkException( x ) );

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    h |= ( ucDeviceID << 16 );

    // byte #4: RFU and set to 0x00

    return h;
}


/*
*/
void Slot::removeSession( const CK_SESSION_HANDLE& a_ulSessionId ) {

    if( !m_Token.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_Sessions.erase( a_ulSessionId );

    try {

        // if this was the last session to be removed then the login 
        // state of token for application returns to public sessions
        if( !m_Sessions.size( ) ) {

            m_Token->setLoggedRole( CK_UNAVAILABLE_INFORMATION );
        }

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& ) {

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
bool Slot::hasReadOnlySession( void ) {

    BOOST_FOREACH( const MAP_SESSIONS::value_type& i, m_Sessions ) {

        if( i.second && !i.second->isReadWrite( ) ) {

            return true;
        }
    }

    return false;
}


/*
*/
void Slot::isValidMechanism( const CK_ULONG& a_mechanism, const CK_ULONG& a_Operation )
{
    bool bFound = false;

    size_t max = sizeof( g_mechanismList ) / sizeof( CK_ULONG );

    for( size_t i = 0; i < max ; ++i ) {

        if( g_mechanismList[ i ] == a_mechanism ){

            if( ( g_mechanismInfo[ i ].flags & a_Operation ) != a_Operation ) {

                throw PKCS11Exception( CKR_MECHANISM_INVALID );
            }

            bFound = true;

            break;
        }
    }

    if( !bFound ) {

        throw PKCS11Exception( CKR_MECHANISM_INVALID );
    }
}


/*
*/
void Slot::isValidCryptoOperation( StorageObject* a_pObject, const CK_ULONG& a_ulOperation ) {

    if( !a_pObject ) {

        throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
    }

    CK_OBJECT_CLASS c = a_pObject->getClass( );

    // Check if key is consistent
    switch( a_ulOperation ) {
    case CKF_ENCRYPT:
    case CKF_VERIFY:
    case CKF_VERIFY_RECOVER:
        if(c != CKO_PUBLIC_KEY && c != CKO_SECRET_KEY){
            throw PKCS11Exception(  CKR_KEY_TYPE_INCONSISTENT );
        }
        break;

    case CKF_DECRYPT:
    case CKF_SIGN:
    case CKF_SIGN_RECOVER:
        if( ( c != CKO_PRIVATE_KEY ) && ( c != CKO_SECRET_KEY ) ) {

            throw PKCS11Exception( CKR_KEY_TYPE_INCONSISTENT );
        }
        break;
    }

    // Check if key supports the operation
    switch( a_ulOperation )
    {
    case CKF_ENCRYPT:
        if(((c == CKO_PUBLIC_KEY)&&(!((Pkcs11ObjectKeyPublicRSA*)a_pObject)->_encrypt)) ){
            throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_DECRYPT:
        if(((c == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)a_pObject)->_decrypt))	){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_VERIFY:
        if(((c == CKO_PUBLIC_KEY)&&(!((Pkcs11ObjectKeyPublicRSA*)a_pObject)->_verify)) ){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_VERIFY_RECOVER:
        if(((c == CKO_PUBLIC_KEY)&&(!((Pkcs11ObjectKeyPublicRSA*)a_pObject)->_verifyRecover))){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_SIGN:
        if(((c == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)a_pObject)->_sign)) ){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;

    case CKF_SIGN_RECOVER:
        if(((c == CKO_PRIVATE_KEY)&&(!((RSAPrivateKeyObject*)a_pObject)->_signRecover))){
            throw PKCS11Exception(  CKR_KEY_FUNCTION_NOT_PERMITTED );
        }
        break;
    }
}


/*
*/
bool Slot::isSessionOwner( const CK_SESSION_HANDLE& a_hSession ) {

    MAP_SESSIONS::iterator i = m_Sessions.find( a_hSession );

    if( m_Sessions.end( ) == i ) {

        return false;
    }

    return true;
}


/*
*/
Session* Slot::getSession( const CK_SESSION_HANDLE& a_hSession ) { 

    MAP_SESSIONS::iterator i = m_Sessions.find( a_hSession );

    if( i == m_Sessions.end( ) ) {

        throw PKCS11Exception( CKR_SESSION_HANDLE_INVALID ); 
    } 

    return i->second; 
}


/*
*/
void Slot::getCardProperty( CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG_PTR a_pValueLen ) {

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        Marshaller::u1Array* pPropertyValue = m_Device->getCardProperty( a_ucProperty, a_ucFlags );

        if( !pPropertyValue ) {

            *a_pValueLen = 0;

            return;
        }

        if( !a_pValue ) {

            // If the incoming buffer pointer is null then only return the expected size
            *a_pValueLen = pPropertyValue->GetLength( );

            return;

        } else {

            // If the incoming buffer is too smal then throw an error
            if( *a_pValueLen < pPropertyValue->GetLength( ) ) {

                *a_pValueLen = pPropertyValue->GetLength( );

                throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
            }
        }

        memcpy( a_pValue, pPropertyValue->GetBuffer( ), pPropertyValue->GetLength( ) );

        *a_pValueLen = pPropertyValue->GetLength( );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}


/*
*/
void Slot::setCardProperty( CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG a_ulValueLen ) {

    if( !m_Device.get( ) ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        Marshaller::u1Array prop( a_ulValueLen );

        prop.SetBuffer( a_pValue );

        m_Device->setCardProperty( a_ucProperty, &prop, a_ucFlags );

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( Token::checkException( x ) );

    } catch( PKCS11Exception& x ) {

        checkAccessException( x );

        throw;

    } catch( ... ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }
}
