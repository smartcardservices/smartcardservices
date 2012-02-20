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


#include <boost/foreach.hpp>
#include <ctime>
#include <utility>
#include <list>
#include <map>
#include <memory>
#include "cryptoki.h"
#include "symmalgo.h"
#include "util.h"
#include "x509cert.h"
#include "attrcert.h"
#include "Pkcs11ObjectKeyPublicRSA.hpp"
#include "Pkcs11ObjectData.hpp"
#include "PKCS11Exception.hpp"
#include "md5.h"
#include "Log.hpp"
#include "cr_rsa.h"
#include "Token.hpp"
#include "MiniDriverException.hpp"
#include "sha1.h"
#include "cardmod.h"
#include "Slot.hpp"
#include "PCSCMissing.h"

const unsigned char g_ucPKCS_EMEV15_PADDING_TAG = 0x02;

/*
*/
Token::Token( Slot* a_pSlot, Device* a_pDevice ) {

    Log::begin( "Token::Token" );
    Timer t;
    t.start( );

    m_uiObjectIndex = 0;

    m_bCheckSmartCardContentDone = false;

    m_pSlot = a_pSlot;

    // Initialize a random engine with current time as seed for the generator
    m_RandomNumberGenerator.seed( static_cast< unsigned int >( std::time( 0 ) ) );

    m_bCreateDirectoryP11 = false;

    m_bCreateTokenInfoFile = false;

    m_bWriteTokenInfoFile = false;

    g_stPathPKCS11 = "p11";

    g_stPathTokenInfo = "tinfo";

    g_stPrefixData = "dat";
    g_stPrefixKeyPublic = "puk";
    g_stPrefixKeyPrivate = "prk";
    // Use the default key exchange certificate extension as root certificate extension
    g_stPrefixRootCertificate = szUSER_KEYEXCHANGE_CERT_PREFIX;

    g_stPrefixPublicObject = "pub";
    g_stPrefixPrivateObject = "pri";

    m_Device = a_pDevice;

    // Set the seed for the random generator
    Marshaller::u1Array challenge( 8 );
    generateRandom( challenge.GetBuffer( ), 8 );
    Util::SeedRandom( challenge );

    // Set the default role 
    m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    // Check if the PKCS11 directory and the token information file are present
    checkTokenInfo( );

    try {

        // Populate the token info structure
        setTokenInfo( );

        // Populate the pulic and private objects
        m_bSynchronizeObjectsPublic = true;
        synchronizePublicObjects( );

        m_bSynchronizeObjectsPrivate = true;
        synchronizePrivateObjects( );

        initializeObjectIndex( );

    } catch( ... ) {

    }

    t.stop( "Token::Token" );
    Log::end( "Token::Token" );
}


/*
*/
void Token::initializeObjectIndex( void ) {

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    MiniDriverFiles::FILES_NAME fs( m_Device->enumFiles( g_stPathPKCS11 ) );

    m_uiObjectIndex = m_Device->containerCount( ) + 1;

    unsigned char idx = 0xFF;

    BOOST_FOREACH( const std::string& s, fs ) {

        if( s.find( g_stPrefixData ) != std::string::npos ) {

            idx = computeIndex( s );

            if( idx > m_uiObjectIndex ) {

                m_uiObjectIndex = idx;
            }
        }
    }

    Log::log( "Token::initializeObjectIndex - Index <%ld>", m_uiObjectIndex );
}


/*
*/
void Token::incrementObjectIndex( void ) {

    if( 0xFF == m_uiObjectIndex ) {

        m_uiObjectIndex = m_Device->containerCount( ) + 1;

    } else {

        ++m_uiObjectIndex;
    }
}


/*
*/
void Token::checkTokenInfo( void ) {

    Log::begin( "Token::checkTokenInfo" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    MiniDriverFiles::FILES_NAME fs;

    try {

        if( m_Device->isV2Plus( ) ) {

            // Check if the P11 directory is present by listing the root directory content
            std::string s( "root" );

            fs = m_Device->enumFiles( s );

            MiniDriverFiles::FILES_NAME::iterator i = fs.find( g_stPathPKCS11 );

            if( fs.end( ) == i ) {

                m_bCreateDirectoryP11 = true;
                m_bCreateTokenInfoFile = true;
                m_bWriteTokenInfoFile = true;
            }

        } else {

            // Check if the P11 directory is present by listing the directory content
            fs = m_Device->enumFiles( g_stPathPKCS11 );
        }

    } catch( MiniDriverException& x ) {

        // The token info file does not exist
        switch( x.getError( ) ) {

            // because the PKCS11 directory is not present
        case SCARD_E_DIR_NOT_FOUND:
            m_bCreateDirectoryP11 = true;
            m_bCreateTokenInfoFile = true;
            m_bWriteTokenInfoFile = true;
            break;

        case SCARD_E_NO_SMARTCARD:
            throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );

        default:
            break;
        }
    }

    // Check if the token information file is present
    if( !m_bCreateDirectoryP11 ) {

        try {

            fs = m_Device->enumFiles( g_stPathPKCS11 );

            MiniDriverFiles::FILES_NAME::iterator i = fs.find( g_stPathTokenInfo );

            if( fs.end( ) != i ) {

                try {

                    m_Device->readFile( g_stPathPKCS11, g_stPathTokenInfo );

                } catch( MiniDriverException& x ) {

                    // The token info file does not exist
                    switch( x.getError( ) ) {

                        // because the token information file is not present
                    case SCARD_E_FILE_NOT_FOUND:
                        m_bCreateDirectoryP11 = false;
                        m_bCreateTokenInfoFile = true;
                        m_bWriteTokenInfoFile = true;

                    default:
                        break;
                    }
                }

            } else {

                m_bCreateDirectoryP11 = false;
                m_bCreateTokenInfoFile = true;
                m_bWriteTokenInfoFile = true;      
            }
        
        } catch( ... ) { }
    }

    t.stop( "Token::checkTokenInfo" );
    Log::end( "Token::checkTokenInfo" );
}


/* SerializeTokenInfo
*/
void Token::writeTokenInfo( void ) {

    if( !m_bWriteTokenInfoFile ) {

        return;
    }

    Log::begin( "Token::writeTokenInfo" );
    Timer t;
    t.start( );

    std::vector< unsigned char > v;

    // Version
    CK_BBOOL _version = 1;
    Util::PushBBoolInVector( &v, _version );

    // Label
    Marshaller::u1Array l( sizeof( m_TokenInfo.label ) );
    l.SetBuffer( m_TokenInfo.label );
    Util::PushByteArrayInVector( &v, &l );

    size_t z = v.size( );

    Marshaller::u1Array objData( z );

    for( unsigned int i = 0 ; i < z ; ++i ) {

        objData.SetU1At( i, v.at( i ) );
    }

    if( !m_Device ) {

        return;
    }

    try {

        m_Device->writeFile( g_stPathPKCS11, g_stPathTokenInfo, &objData );

    } catch( MiniDriverException& x ) {

        Log::log( "## Error ## Token::SerializeTokenInfo - writeFile failed" );
        throw PKCS11Exception( checkException( x ) );
    }

    m_bWriteTokenInfoFile = false;

    t.stop( "Token::writeTokenInfo" );
    Log::end( "Token::writeTokenInfo" );
}


/* Only read the label
*/
void Token::readTokenInfo( void ) {

    if( m_bCreateTokenInfoFile ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    Log::begin( "Token::readTokenInfo" );
    Timer t;
    t.start( );

    try {

        Marshaller::u1Array* fileData = m_Device->readFile( g_stPathPKCS11, g_stPathTokenInfo );

        std::vector< unsigned char > v;

        unsigned int l = fileData->GetLength( );

        if( !l ) {

            // The file exists but is empty
            m_bWriteTokenInfoFile = true;

            return;
        }

        for( unsigned int u = 0 ; u < l ; ++u ) {

            v.push_back( fileData->GetBuffer( )[ u ] );
        }

        CK_ULONG idx = 0;

        // Format version. Shall be 0 for this version
        /*CK_BBOOL _version =*/ Util::ReadBBoolFromVector( v, &idx );

        // label
        std::auto_ptr< Marshaller::u1Array > label( Util::ReadByteArrayFromVector( v, &idx ) );

        memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );

        memcpy( m_TokenInfo.label, label->GetBuffer( ), label->GetLength( ) );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::readTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::readTokenInfo" );
    Log::end( "Token::readTokenInfo" );
}


/*
*/
void Token::createTokenInfo( void ) {

    Log::begin( "Token::createTokenInfo" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    if( m_bCreateDirectoryP11 ) {

        // Create the P11 directory into the smart card
        try {

            m_Device->createDirectory( std::string( "root" ), g_stPathPKCS11 );

            m_bCreateDirectoryP11 = false;

        } catch( MiniDriverException& x ) {

            Log::error( "Token::createTokenInfo", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    if( m_bCreateTokenInfoFile ) {

        // Create the P11 token information file
        try {

            m_Device->createFile( g_stPathPKCS11, g_stPathTokenInfo, false );

            m_bCreateTokenInfoFile = false;

            m_bWriteTokenInfoFile = true;

        } catch( MiniDriverException& x ) {

            Log::error( "Token::createTokenInfo", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    t.stop( "Token::createTokenInfo" );
    Log::end( "Token::createTokenInfo" );
}



/*
*/
/*
void Token::initializeTokenInfo( void ) {

    Log::begin( "Token::initializeTokenInfo" );
    Timer t;
    t.start( );

    // flush TokenInfo
    memset( &m_TokenInfo, 0, sizeof( CK_TOKEN_INFO ) );

    // Set serial number
    memset( m_TokenInfo.serialNumber, ' ', sizeof( m_TokenInfo.serialNumber ) );

    // Set the default label
    memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );
    m_TokenInfo.label[0] = '.';
    m_TokenInfo.label[1] = 'N';
    m_TokenInfo.label[2] = 'E';
    m_TokenInfo.label[3] = 'T';
    m_TokenInfo.label[4] = ' ';
    m_TokenInfo.label[5] = '#';
    memcpy( &m_TokenInfo.label[6], m_TokenInfo.serialNumber, sizeof( m_TokenInfo.serialNumber ) );

    // Set manufacturer id
    memset( m_TokenInfo.manufacturerID, ' ', sizeof( m_TokenInfo.manufacturerID ) );
    m_TokenInfo.manufacturerID[0] = 'G';
    m_TokenInfo.manufacturerID[1] = 'e';
    m_TokenInfo.manufacturerID[2] = 'm';
    m_TokenInfo.manufacturerID[3] = 'a';
    m_TokenInfo.manufacturerID[4] = 'l';
    m_TokenInfo.manufacturerID[5] = 't';
    m_TokenInfo.manufacturerID[6] = 'o';

    // Set model
    memset( m_TokenInfo.model, ' ', sizeof( m_TokenInfo.model ) );
    m_TokenInfo.model[0] = '.';
    m_TokenInfo.model[1] = 'N';
    m_TokenInfo.model[2] = 'E';
    m_TokenInfo.model[3] = 'T';
    m_TokenInfo.model[4] = ' ';
    m_TokenInfo.model[5] = 'C';
    m_TokenInfo.model[6] = 'a';
    m_TokenInfo.model[7] = 'r';
    m_TokenInfo.model[8] = 'd';

    // Set flags
    m_TokenInfo.flags  =  CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED; // | CKF_RNG
    
    try {

            if( !m_Device->isPinInitialized( ) ) {

                Log::log( "Token::setTokenInfo - Disable CKF_USER_PIN_INITIALIZED" );
                m_TokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;
            }

            // Is login required ?
            if(  m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_pSlot->isAuthenticated( ) ) ) {

                m_TokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
                Log::log( "Token::setTokenInfo - No login required" );
            }

            // Check if the CKF_PROTECTED_AUTHENTICATION_PATH flag must be raised
            if( m_Device->isExternalPin( ) || ( ( m_Device->isModePinOnly( ) && m_Device->isVerifyPinSecured( ) ) || m_Device->isModeNotPinOnly( ) ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_PROTECTED_AUTHENTICATION_PATH" );
                m_TokenInfo.flags  |= CKF_PROTECTED_AUTHENTICATION_PATH;
            }
        }

    // Set the sessions information
    m_TokenInfo.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxPinLen = 255;
    m_TokenInfo.ulMinPinLen = 4;

    // Set the memory information
    m_TokenInfo.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

    // Set the version of the Card Operating system
    m_TokenInfo.hardwareVersion.major  = 0;
    m_TokenInfo.hardwareVersion.minor  = 0;

    // Set the version of Card Module application
    m_TokenInfo.firmwareVersion.major  = 0;
    m_TokenInfo.firmwareVersion.minor  = 0;

    t.stop( "Token::setTokenInfo" );
    Log::end( "Token::setTokenInfo" );
}
*/

/*
*/
void Token::setTokenInfo( void )
{
    Log::begin( "Token::setTokenInfo" );
    Timer t;
    t.start( );

    // flush TokenInfo
    memset( &m_TokenInfo, 0, sizeof( CK_TOKEN_INFO ) );

    // Set serial number
    memset( m_TokenInfo.serialNumber, ' ', sizeof( m_TokenInfo.serialNumber ) );

    // If serial number length is too big to fit in 16 (hex) digit field, then use the 8 first bytes of MD5 hash of the original serial number.
    const Marshaller::u1Array* sn = NULL;

    try {

        if( m_Device ) {

            sn = m_Device->getSerialNumber( );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    if( sn ) {

        unsigned int l = sn->GetLength( );

        unsigned char* p = (unsigned char*) sn->GetBuffer( );

        if( l > 8 ) {

            CMD5 md5;
            CK_BYTE hash[ 16 ];
            md5.hashCore( p, 0, l );
            md5.hashFinal( hash );
            Util::ConvAscii( hash, 8, m_TokenInfo.serialNumber );

        } else {

            Util::ConvAscii( p, l, m_TokenInfo.serialNumber );
        }
    } else {

        CK_CHAR emptySerialNumber[ ] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 }; 

        memcpy( m_TokenInfo.serialNumber, emptySerialNumber, sizeof( emptySerialNumber ) );
    }

    // Set the default label
    memset( m_TokenInfo.label, ' ', sizeof( m_TokenInfo.label ) );
    m_TokenInfo.label[0] = '.';
    m_TokenInfo.label[1] = 'N';
    m_TokenInfo.label[2] = 'E';
    m_TokenInfo.label[3] = 'T';
    m_TokenInfo.label[4] = ' ';
    m_TokenInfo.label[5] = '#';
    memcpy( &m_TokenInfo.label[6], m_TokenInfo.serialNumber, sizeof( m_TokenInfo.serialNumber ) );

    // Try to read the token information from the smart card (only read the label)
    try {

        readTokenInfo( );

    } catch( MiniDriverException& ) {

        m_bCreateTokenInfoFile = true;
        m_bWriteTokenInfoFile = true;
    }

    // Set manufacturer id
    memset( m_TokenInfo.manufacturerID, ' ', sizeof( m_TokenInfo.manufacturerID ) );
    m_TokenInfo.manufacturerID[0] = 'G';
    m_TokenInfo.manufacturerID[1] = 'e';
    m_TokenInfo.manufacturerID[2] = 'm';
    m_TokenInfo.manufacturerID[3] = 'a';
    m_TokenInfo.manufacturerID[4] = 'l';
    m_TokenInfo.manufacturerID[5] = 't';
    m_TokenInfo.manufacturerID[6] = 'o';

    // Set model
    memset( m_TokenInfo.model, ' ', sizeof( m_TokenInfo.model ) );
    m_TokenInfo.model[0] = '.';
    m_TokenInfo.model[1] = 'N';
    m_TokenInfo.model[2] = 'E';
    m_TokenInfo.model[3] = 'T';
    m_TokenInfo.model[4] = ' ';
    m_TokenInfo.model[5] = 'C';
    m_TokenInfo.model[6] = 'a';
    m_TokenInfo.model[7] = 'r';
    m_TokenInfo.model[8] = 'd';

    // Set flags
    m_TokenInfo.flags  = /*CKF_RNG |*/ CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED /*| CKF_USER_PIN_INITIALIZED*/;

    try {

        if( m_Device && m_pSlot ) {

            Log::log( "Token::Token - No Pin <%d>", m_Device->isNoPin( ) );
            Log::log( "Token::Token - SSO <%d>", m_Device->isSSO( ) );
            Log::log( "Token::Token - External <%d>", m_Device->isExternalPin( ) );
            Log::log( "Token::Token - isAuthenticated <%d>", m_pSlot->isAuthenticated( ) );
            Log::log( "Token::Token - isReadOnly <%d>", m_Device->isReadOnly( ) );
            Log::log( "Token::Token - isPinInitialized <%d>", m_Device->isPinInitialized( ) );
            Log::log( "Token::Token - isVerifyPinSecured <%d>", m_Device->isVerifyPinSecured( ) );

            if( m_Device->isReadOnly( ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_WRITE_PROTECTED" );
                m_TokenInfo.flags |= CKF_WRITE_PROTECTED;
            }

            if( m_Device->isPinInitialized( ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_USER_PIN_INITIALIZED" );
                m_TokenInfo.flags |= CKF_USER_PIN_INITIALIZED;
            }

            // Is login required ?
            if(  m_Device->isNoPin( ) || ( m_Device->isSSO( ) && m_pSlot->isAuthenticated( ) ) ) {

                m_TokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
                Log::log( "Token::setTokenInfo - No login required" );
            }

            // Check if the CKF_PROTECTED_AUTHENTICATION_PATH flag must be raised
            if( m_Device->isExternalPin( ) || ( ( m_Device->isModePinOnly( ) && m_Device->isVerifyPinSecured( ) ) || m_Device->isModeNotPinOnly( ) ) ) {

                Log::log( "Token::setTokenInfo - Enable CKF_PROTECTED_AUTHENTICATION_PATH" );
                m_TokenInfo.flags  |= CKF_PROTECTED_AUTHENTICATION_PATH;
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    // Set the sessions information
    m_TokenInfo.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    m_TokenInfo.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulMaxPinLen = 255;
    m_TokenInfo.ulMinPinLen = 4;
    try {
        if( m_Device ) {

            m_TokenInfo.ulMaxPinLen = m_Device->getPinMaxPinLength( );

            m_TokenInfo.ulMinPinLen = m_Device->getPinMinPinLength( );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setTokenInfo", "MiniDriverException" );

        throw PKCS11Exception( checkException( x ) );
    }

    // Set the memory information
    m_TokenInfo.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    m_TokenInfo.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

    // Set the version of the Card Operating system
    m_TokenInfo.hardwareVersion.major  = 0;
    m_TokenInfo.hardwareVersion.minor  = 0;

    // Set the version of Card Module application
    m_TokenInfo.firmwareVersion.major  = 0;
    m_TokenInfo.firmwareVersion.minor  = 0;

    t.stop( "Token::setTokenInfo" );
    Log::end( "Token::setTokenInfo" );
}


/*
*/
void Token::authenticateUser( Marshaller::u1Array* a_pPin ) {

    Log::begin( "Token::authenticateUser" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Device->verifyPin( a_pPin );

        m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
        m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
        m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

        m_RoleLogged = CKU_USER;

    } catch( MiniDriverException& x ) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        checkAuthenticationStatus( CKU_USER, x );
    }

    t.stop( "Token::authenticateUser" );
    Log::end( "Token::authenticateUser" );
}


/*
*/
void Token::checkAuthenticationStatus( CK_ULONG a_ulRole, MiniDriverException& a_Exception ) {

    switch( a_Exception.getError( ) ) {

    case SCARD_W_CARD_NOT_AUTHENTICATED:
    case SCARD_W_WRONG_CHV:
        {
            // Authentication failed due to an incorrect PIN
            int triesRemaining = 0;

            try {

                triesRemaining = ( ( CKU_USER == a_ulRole ) ? m_Device->getTriesRemaining( ) : m_Device->administratorGetTriesRemaining( ) );                  

            } catch( MiniDriverException& x ) {

                Log::error( "Token::checkAuthenticationStatus", "MiniDriverException" );
                throw PKCS11Exception( checkException( x ) );
            }

            // Update the token information structure
            if( 0 == triesRemaining ) {

                // PIN / Admin key is blocked
                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags |= CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags |= CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
                }

                throw PKCS11Exception( CKR_PIN_LOCKED );

            } else if( 1 == triesRemaining ) {

                // Last retry
                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
                }
            } else { //if(triesRemaining < MAX_USER_PIN_TRIES)

                if( CKU_USER == a_ulRole ) {

                    m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
                    m_TokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
                    m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

                } else {

                    m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
                    m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
                    m_TokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;
                }
            }

            throw PKCS11Exception ( CKR_PIN_INCORRECT );
        }
        break;

    case SCARD_W_CANCELLED_BY_USER:
    case SCARD_E_TIMEOUT:
        throw PKCS11Exception( CKR_FUNCTION_CANCELED );

    default:
        throw PKCS11Exception( checkException( a_Exception ) );
    }

}


/*
*/
void Token::authenticateAdmin( Marshaller::u1Array* a_pPin ) {

    Log::begin( "Token::authenticateAdmin" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        m_Device->administratorLogin( a_pPin );

        m_RoleLogged = CKU_SO;

    } catch( MiniDriverException& x ) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        checkAuthenticationStatus( CKU_SO, x );
    }

    t.stop( "Token::authenticateAdmin" );
    Log::end( "Token::authenticateAdmin" );
}


/*
*/
void Token::logout( void ) {

    Log::begin( "Token::logout" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        Log::log( "Token::logout - Token not present" );
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    try {

        if( m_pSlot->isAuthenticated( ) ) {

            m_Device->logOut( );

        } else if( m_pSlot->administratorIsAuthenticated( ) ) {

            m_Device->administratorLogout( );

        } else {

            Log::log( "Token::logout - user not logged in" );
            throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
        }    

    } catch( MiniDriverException& x ) {

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::logout" );
    Log::end( "Token::logout" );
}


/*
*/
void Token::login( const CK_ULONG& a_ulUserType, Marshaller::u1Array* a_pPin ) {

    Log::begin( "Token::login" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        if( CKU_USER == a_ulUserType ) {

            if( ( m_TokenInfo.flags & CKF_USER_PIN_INITIALIZED ) != CKF_USER_PIN_INITIALIZED ) {

                throw PKCS11Exception( CKR_USER_PIN_NOT_INITIALIZED );
            }

            if( m_pSlot->administratorIsAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ANOTHER_ALREADY_LOGGED_IN );
            }

            if( m_pSlot->isAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ALREADY_LOGGED_IN );
            }

            if( !m_pSlot->isAuthenticated( ) ) {

                authenticateUser( a_pPin );
                m_pSlot->setUserType( a_ulUserType );
            }

        } else if( CKU_SO == a_ulUserType ) {

            if( m_pSlot->administratorIsAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ALREADY_LOGGED_IN );
            }

            if( m_pSlot->isAuthenticated( ) ) {

                throw PKCS11Exception( CKR_USER_ANOTHER_ALREADY_LOGGED_IN );
            }

            if( !m_pSlot->administratorIsAuthenticated( ) ) {

                authenticateAdmin( a_pPin );

                m_pSlot->setUserType( a_ulUserType );
            }

        } else {

            throw PKCS11Exception( CKR_USER_TYPE_INVALID );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::login", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    try {

        // The smart card is checked to avoid to have empty containers with certificates
        if( checkSmartCardContent( ) ) {

            m_ObjectsToCreate.clear( );

            synchronizeObjects( );
        } 

        BOOST_FOREACH( StorageObject* p, m_ObjectsToCreate ) {

            Log::log( "Token::login - *** CREATE LATER *** <%s>", p->m_stFileName.c_str( ) );

            try {

                writeObject( p );

            } catch( ... ) {

            }
        }

        m_ObjectsToCreate.clear( );

        // After a successfull login, the cache has to be updated to get all private objects
        synchronizePrivateObjects( );
        //}

    } catch( ... ) { 

    }

    if( !Log::s_bEnableLog ) {

        Log::log(" Token::login - <<<<< P11 OBJ LIST >>>>>");
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) { printObject( o.second ); }
        Log::log(" Token::login - <<<<< P11 OBJ LIST >>>>>");
    }

    t.stop( "Token::login" );
    Log::end( "Token::login" );
}


/*
*/
void Token::generateRandom( CK_BYTE_PTR a_pRandomData, const CK_ULONG& a_ulLen ) {

    Log::begin( "Token::generateRandom" );
    Timer t;
    t.start( );

    // Initialize the range from the 0 to 255 for the generator
    boost::uniform_smallint< > range( 0, 255 );

    // initialize the generator
    boost::variate_generator< boost::mt19937&, boost::uniform_smallint< > > generator( m_RandomNumberGenerator, range );

    // Generate the random buffer
    for( CK_ULONG i = 0 ; i < a_ulLen ; ++i ) {

        a_pRandomData[ i ] = (CK_BYTE)generator( );
    }

    t.stop( "Token::generateRandom" );
    Log::end( "Token::generateRandom" );
}


/*
*/
void Token::findObjects( Session* a_pSession, CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {

    //Log::begin( "Token::findObjects" );
    //Timer t;

    //t.start( );

    bool bUserAuthenticated = false;

    if( m_pSlot ) {

        bUserAuthenticated = m_pSlot->isAuthenticated( );

    }

    // For each P11 object
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

        // Check if the search has reached the allowed maximum of objects to search 
        if( *a_pulObjectCount >= a_ulMaxObjectCount ) {

            break;
        }

        // Check if this object has been already compared to the search template
        if( m_TokenObjectsReturnedInSearch.end( ) != m_TokenObjectsReturnedInSearch.find( o->first ) ) {

            // This object has already been analysed by a previous call of findObjects for this template
            continue;
        }

        // If the object is private and the user is not logged in
        if( ( !bUserAuthenticated ) && o->second->isPrivate( ) )
        {
            // Then avoid this element. 
            // Do not add it the list of already explored objects (may be a C_Login can occur)
            continue;
        }

        // Add the object to the list of the objects compared to the search template
        m_TokenObjectsReturnedInSearch.insert( o->first );

        // If the template is NULL then return all objects
        if( !a_pSession->_searchTempl ) {

            a_phObject[ *a_pulObjectCount ] = o->first;

            ++(*a_pulObjectCount);

        } else {
            // The template is not NULL.

            bool match = true;

            // In this case the template attributes have to be compared to the objects ones.
            BOOST_FOREACH( CK_ATTRIBUTE& t, a_pSession->_searchTempl->getAttributes( ) ) {

                if( ! o->second->compare( t ) ) {

                    match = false;

                    break;
                }
            }

            // The attributes match
            if( match ) {

                // Add the object handle to the outgoing list
                a_phObject[ *a_pulObjectCount ] = o->first;

                // Increment the number of found objects
                ++(*a_pulObjectCount);
            }
        }
    }

    //t.stop( "Token::findObjects" );
    //Log::end( "Token::findObjects" );
}


/*
*/
void Token::computeObjectFileName( StorageObject* a_pObject, std::string& a_stFileName ) {

    Log::begin( "Token::computeObjectFileName" );
    Timer t;
    t.start( );

    // Add the public or private prefix
    std::string stName /*a_stFileName*/ = "";//( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    switch( a_pObject->getClass ( ) ) {

    case CKO_DATA:
        computeObjectNameData( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_PUBLIC_KEY:
        computeObjectNamePublicKey( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_PRIVATE_KEY:
        computeObjectNamePrivateKey( /*a_stFileName*/stName, a_pObject );
        break;

    case CKO_CERTIFICATE:
        computeObjectNameCertificate( /*a_stFileName*/stName, a_pObject );
        break;

    default:
        throw PKCS11Exception( CKR_FUNCTION_FAILED );
    }

    a_stFileName = stName;
    
    Log::log( "Token::computeObjectFileName - Name <%s>", a_stFileName.c_str( ) );
    t.stop( "Token::computeObjectFileName" );
    Log::end( "Token::computeObjectFileName" );
}


/*
*/
void Token::computeObjectNameData( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the prefix
    a_stFileName.append( g_stPrefixData );

    MiniDriverFiles::FILES_NAME filesPKCS11;
    
    if( !m_bCreateDirectoryP11 ) {
        
        filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );
    }

    bool bGoodNameFound = false;

    std::string s;

    do {
        
        s = a_stFileName;
        
        incrementObjectIndex( );

        // Add the index of the data object
        Util::toStringHex( m_uiObjectIndex, s );

        if( isObjectNameValid( s, filesPKCS11 ) ) {
        
            bGoodNameFound = true;

            a_stFileName = s;
        }

    } while( !bGoodNameFound );
}


/*
*/
bool Token::isObjectNameValid( const std::string& a_stFileName, const MiniDriverFiles::FILES_NAME& a_filesList ) {

    bool bReturn = true;

    BOOST_FOREACH( const std::string& s, a_filesList ) {

        if( s.compare( a_stFileName ) == 0 ) {

            bReturn = false;

            break;
        }
    }

    return bReturn;
}


/*
*/
void Token::computeObjectNamePublicKey( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the prefix
    a_stFileName.append( g_stPrefixKeyPublic );

    unsigned char ucContainerIndex = ( (Pkcs11ObjectKeyPublicRSA*) a_pObject )->m_ucContainerIndex;

    MiniDriverFiles::FILES_NAME filesPKCS11;
    
    if( !m_bCreateDirectoryP11 ) {
        
        filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );
    }

    bool bGoodNameFound = false;

    std::string s;

    // The container index excists the file name must have the same name
    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != ucContainerIndex ) {

        Util::toStringHex( ucContainerIndex, a_stFileName );

    } else {

        unsigned int uiStartIndex = m_Device->containerCount( );

        // In the case of the public is created before te private key, there is no container index available
        do {
        
            s = a_stFileName;
        
            incrementObjectIndex( );

            // Add the index of the data object
            Util::toStringHex( uiStartIndex + m_uiObjectIndex, s );

            if( isObjectNameValid( s, filesPKCS11 ) ) {
        
                bGoodNameFound = true;

                a_stFileName = s;
            }

        } while( !bGoodNameFound );
    }
}


/*
*/
void Token::computeObjectNamePrivateKey( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

        // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    // Add the key suffix
    a_stFileName.append( g_stPrefixKeyPrivate );

    unsigned char ucContainerIndex = ( (RSAPrivateKeyObject*) a_pObject )->m_ucContainerIndex;

    // Add the index of MiniDriver key container associated to this PKCS11 key object
    Util::toStringHex( ucContainerIndex, a_stFileName );
}


/*
*/
void Token::computeObjectNameCertificate( std::string& a_stFileName, /*const*/ StorageObject* a_pObject ) {

    // Add the public or private prefix
    a_stFileName = ( a_pObject->isPrivate( ) ? g_stPrefixPrivateObject : g_stPrefixPublicObject );

    a_stFileName.append( a_pObject->m_stFileName );
}


/* WriteObject
*/
void Token::writeObject( StorageObject* a_pObject ) {

    Log::begin( "Token::writeObject" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Compute this attribute for backward compatibility with odl version of P11 library
    a_pObject->_uniqueId = Util::MakeUniqueId( );

    // Build the content of the file
    std::vector< unsigned char > to;
    a_pObject->serialize( &to );

    Marshaller::u1Array o( to );

    try {

        if( m_pSlot->isAuthenticated( ) ) {

            if( m_bCreateDirectoryP11 ) {

                m_Device->createDirectory( std::string( "root" ), g_stPathPKCS11 );
            }

            try {

                // If the user is authenticated then create the file on card
                m_Device->createFile( g_stPathPKCS11, a_pObject->m_stFileName, a_pObject->isPrivate( ) );

            } catch( MiniDriverException& e ) {

                // The file may be already created. In this case the file must only be written.
                // It could be the case for the public key which is created 
                // but not deleted by the application (for example Firefox)
                if( SCARD_E_WRITE_TOO_MANY != e.getError( ) ) {

                    // Otherwise the error must be thrown
                    throw;
                }
            }

            if ( ( CKO_DATA == a_pObject->getClass( ) ) && a_pObject->isPrivate( ) ) {

                m_Device->cacheDisable( a_pObject->m_stFileName );
            }

            m_Device->writeFile( g_stPathPKCS11, a_pObject->m_stFileName, &o );

            Log::log( "Token::writeObject - Create & write <%s>", a_pObject->m_stFileName.c_str( ) );

        } else {

            Log::log( "Token::writeObject - *** CREATE LATER *** <%s>", a_pObject->m_stFileName.c_str( ) );

            // If the user is not authenticated then store the object to create it later
            m_ObjectsToCreate.push_back( a_pObject );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::writeObject", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::writeObject" );
    Log::end( "Token::writeObject" );
}


/* Create an object required by the PKCS11 API (C_CreateObject
*/
void Token::addObject( StorageObject* a_pObject, CK_OBJECT_HANDLE_PTR a_pHandle, const bool& a_bRegisterObject ) {

    Log::begin( "Token::addObject" );
    Timer t;
    t.start( );

    *a_pHandle = CK_UNAVAILABLE_INFORMATION;

    try {

        // Build the name of the file
        computeObjectFileName( a_pObject, a_pObject->m_stFileName );

        // Write the file into the smart card
        writeObject( a_pObject );

        // Add the object into the list of managed objects
        if( a_bRegisterObject ) {

            *a_pHandle = registerStorageObject( a_pObject );
        }

    } catch( MiniDriverException &x ) {

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::addObject" );
    Log::end( "Token::addObject" );
}


/* AddPrivateKeyObject
*/
void Token::addObjectPrivateKey( RSAPrivateKeyObject* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectPrivateKey" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // No private key for public object
    if( !a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Public key modulus is mandatory
    if( !a_pObject->m_pModulus ) {

        throw PKCS11Exception( CKR_TEMPLATE_INCOMPLETE );
    }

    // Check the modulus length
    unsigned int uiModulusLength = a_pObject->m_pModulus->GetLength( );

    if( ( ( uiModulusLength * 8 ) < MiniDriver::s_iMinLengthKeyRSA ) || ( (uiModulusLength * 8 ) > MiniDriver::s_iMaxLengthKeyRSA ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Get the middle size
    unsigned int uiKeyHalfSize = uiModulusLength / 2;

    // Check the Prime P (PKCS11 prime 1 attribute) size
    unsigned int uiPrimePLength = a_pObject->m_pPrime1->GetLength( );

    if( uiPrimePLength > uiKeyHalfSize ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiPrimePLength < uiKeyHalfSize ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiKeyHalfSize );

        memset( val->GetBuffer( ), 0, uiKeyHalfSize );

        size_t i = uiKeyHalfSize - uiPrimePLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pPrime1->GetBuffer( ), uiPrimePLength );

        a_pObject->m_pPrime1.reset( val );

        uiPrimePLength = uiKeyHalfSize;
    }

    // Check the Prime Q (PKCS11 prime 2 attribute) size
    unsigned int uiPrimeQLength = a_pObject->m_pPrime2->GetLength( );

    if( uiPrimeQLength > uiKeyHalfSize ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiPrimeQLength < uiKeyHalfSize ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiKeyHalfSize );

        memset( val->GetBuffer( ), 0, uiKeyHalfSize );

        size_t i = uiKeyHalfSize - uiPrimeQLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pPrime2->GetBuffer( ), uiPrimeQLength );

        a_pObject->m_pPrime2.reset( val );

        uiPrimeQLength = uiKeyHalfSize;
    }

    // Check the Inverse Q (PKCS11 coefficient attribute) size
    unsigned int uiInverseQLength = a_pObject->m_pCoefficient->GetLength( );

    if( uiInverseQLength > uiKeyHalfSize ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiInverseQLength < uiKeyHalfSize ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiKeyHalfSize );

        memset( val->GetBuffer( ), 0, uiKeyHalfSize );

        size_t i = uiKeyHalfSize - uiInverseQLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pCoefficient->GetBuffer( ), uiInverseQLength );

        a_pObject->m_pCoefficient.reset( val );

        uiInverseQLength = uiKeyHalfSize;
    }

    // Check the DP Length (PKCS11 CKA_EXPONENT_1 attribute) size
    unsigned int uiDPLength = a_pObject->m_pExponent1->GetLength( );

    if( uiDPLength > uiKeyHalfSize ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiDPLength < uiKeyHalfSize ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiKeyHalfSize );

        memset( val->GetBuffer( ), 0, uiKeyHalfSize );

        size_t i = uiKeyHalfSize - uiDPLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pExponent1->GetBuffer( ), uiDPLength );

        a_pObject->m_pExponent1.reset( val );

        uiDPLength = uiKeyHalfSize;
    }

    // Check the DQ Length (PKCS11 CKA_EXPONENT_2 attribute) size
    unsigned int uiDQLength = a_pObject->m_pExponent2->GetLength( );

    if( uiDQLength > uiKeyHalfSize ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiDQLength < uiKeyHalfSize ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiKeyHalfSize );

        memset( val->GetBuffer( ), 0, uiKeyHalfSize );

        size_t i = uiKeyHalfSize - uiDQLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pExponent2->GetBuffer( ), uiDQLength );

        a_pObject->m_pExponent2.reset( val );

        uiDQLength = uiKeyHalfSize;
    }

    // Check the Private Exponent Length (PKCS11 CKA_PRIVATE_EXPONENT attribute) size
    unsigned int uiPrivateExponentLength = a_pObject->m_pPrivateExponent->GetLength( );

    if( uiPrivateExponentLength > uiModulusLength ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    if( uiPrivateExponentLength < uiModulusLength ) {

        // Pad with zeros in the front since big endian
        Marshaller::u1Array* val = new Marshaller::u1Array( uiModulusLength );

        memset( val->GetBuffer( ), 0, uiPrivateExponentLength );

        size_t i = uiModulusLength - uiPrivateExponentLength;

        memcpy( val->GetBuffer( ) + i, a_pObject->m_pPrivateExponent->GetBuffer( ), uiPrivateExponentLength );

        a_pObject->m_pPrivateExponent.reset( val );

        uiPrivateExponentLength = uiModulusLength;
    }

    // Check the public exponent size
    unsigned int uiPublicExponentLength = a_pObject->m_pPublicExponent->GetLength( );

    if( ( uiPublicExponentLength < 1 ) || ( uiPublicExponentLength > 4 ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Check the public key exponent size    
    Marshaller::u1Array* pPublicExponent = a_pObject->m_pPublicExponent.get( );

    if( uiPublicExponentLength < 4 ) {

        // Pad with zeros in the front since big endian
        pPublicExponent = new Marshaller::u1Array( 4 );

        memset( pPublicExponent->GetBuffer( ), 0, 4 );

        size_t i = 4 - uiPublicExponentLength;

        memcpy( pPublicExponent->GetBuffer( ) + i, a_pObject->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );

        uiPublicExponentLength = 4;
    }

    //if( uiPublicExponentLength < 4 ) {

    //    // Pad with zeros in the front since big endian
    //    Marshaller::u1Array* exp = new Marshaller::u1Array( 4 );

    //    memset( exp->GetBuffer( ), 0, 4 );

    //    size_t i = 4 - uiPublicExponentLength;

    //    memcpy( exp->GetBuffer( ) + i, a_pObject->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );

    //    a_pObject->m_pPublicExponent.reset( exp );

    //    uiPublicExponentLength = 4;
    //}

    // compute the total length;
    unsigned int uiKeyLength = uiPrimePLength + uiPrimeQLength + uiInverseQLength + uiDPLength + uiDQLength + uiPrivateExponentLength + uiModulusLength + 4;

    // Prepare the keyValue
    Marshaller::u1Array keyValue( uiKeyLength );

    unsigned char* p = keyValue.GetBuffer( );

    memset( p, 0, uiKeyLength );

    // Add the Prime P
    memcpy( p, a_pObject->m_pPrime1->GetBuffer( ), uiPrimePLength );

    int offset = uiPrimePLength;

    // Add the the Prime Q
    memcpy( p + offset, a_pObject->m_pPrime2->GetBuffer( ), uiPrimeQLength );

    offset += uiPrimeQLength;

    // Add the inverse Q
    memcpy( p + offset, a_pObject->m_pCoefficient->GetBuffer( ), uiInverseQLength );

    offset += uiInverseQLength;

    // Add the DP
    memcpy( p + offset, a_pObject->m_pExponent1->GetBuffer( ), uiDPLength );

    offset += uiDPLength;

    // Add the DQ
    memcpy( p + offset, a_pObject->m_pExponent2->GetBuffer( ), uiDQLength );

    offset += uiDQLength;

    // Addt he private exponent D
    memcpy( p + offset, a_pObject->m_pPrivateExponent->GetBuffer( ), uiPrivateExponentLength );

    offset += uiPrivateExponentLength;

    // Add the modulus
    memcpy( p + offset, a_pObject->m_pModulus->GetBuffer( ), uiModulusLength );

    offset += uiModulusLength;

    // Add the public exponent
    //memcpy( p + offset, a_pObject->m_pPublicExponent->GetBuffer( ), uiPublicExponentLength );
    memcpy( p + offset, pPublicExponent->GetBuffer( ), uiPublicExponentLength );

    // Specify what is able to do the key (sign only or sign & decrypt)
    a_pObject->m_ucKeySpec = (unsigned char)( a_pObject->_decrypt ? MiniDriverContainer::KEYSPEC_EXCHANGE : MiniDriverContainer::KEYSPEC_SIGNATURE );

    // Create the on card key container
    // This method checks if a certificate with the same public key exists.
    // In this case this new key must be imported into the key container already associated with this certificate and the key spec is also updated
    a_pObject->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    try {

        m_Device->containerCreate( a_pObject->m_ucContainerIndex, true, a_pObject->m_ucKeySpec, a_pObject->m_pModulus.get( ), ( uiModulusLength * 8 ), &keyValue );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::addObjectPrivateKey", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    if( a_pObject->m_ucContainerIndex == MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID ) {

        // No free container available
        Log::error( "Token::AddPrivateKeyObject", "no index available - Return CKR_DEVICE_MEMORY" );

        throw PKCS11Exception( CKR_DEVICE_MEMORY );
    }

    setDefaultAttributesKeyPrivate( a_pObject );

    a_pObject->_local = CK_FALSE;

    // Create the associated PKCS#11 key object
    addObject( a_pObject, a_phObject ); 

    t.stop( "Token::addObjectPrivateKey" );
    Log::end( "Token::addObjectPrivateKey" );
}


/*
*/
void Token::addObjectCertificate( X509PubKeyCertObject* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectCertificate" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Private certificate object is not allowed
    if( !a_pObject || a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Set the certificate with sign & decrypt purposes by default
    a_pObject->m_ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

    // Set the certificate container as invalid
    a_pObject->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    // Actually the certificates attributes have been provided by the creation template.
    // But some of then can be not set.
    // Get all empty attributes from the certificate
    // Set the same CKA_LABEL, CKA_ID and CKA_SUBJECT for this certificate 
    // than an existing private key using the same public key modulus attribute
    setDefaultAttributesCertificate( a_pObject );

    Log::log( "Token::addObjectCertificate - Smart card logon <%d>", a_pObject->m_bIsSmartCardLogon );
    Log::log( "Token::addObjectCertificate - root <%d>", a_pObject->m_bIsRoot );
    Log::log( "Token::addObjectCertificate - index <%d>", a_pObject->m_ucContainerIndex );

    //unsigned char ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
    //unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
    std::string stFileName = "";
    m_Device->containerGetMatching( a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, stFileName, a_pObject->m_pModulus.get( ) );
    Log::log( "Token::addObjectCertificate - m_ucContainerIndex <%d>", a_pObject->m_ucContainerIndex );
    Log::log( "Token::addObjectCertificate - m_ucKeySpec <%d>", a_pObject->m_ucKeySpec );
    Log::log( "Token::addObjectCertificate - stFileName <%s>", stFileName.c_str( ) );

    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID != a_pObject->m_ucContainerIndex ) {

        Log::log( "Token::addObjectCertificate - Create a certificate associated to a key pair container" );

        // Create the certificate into the smart card
        try {

            // If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
            // The keyspec will also be updated
            // The file name will anyway built automaticaly
            m_Device->createCertificate( a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, a_pObject->m_stFileName, a_pObject->m_pValue.get( ), a_pObject->m_pModulus.get( ), a_pObject->m_bIsSmartCardLogon );

            a_pObject->m_stCertificateName = a_pObject->m_stFileName;//.substr( 3, 5 );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectCertificate", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }

    } else {

        Log::log( "Token::addObjectCertificate - Create a ROOT certificate" );

        // Create the ROOT certificate into the smart card
        try {

            m_Device->createCertificateRoot( a_pObject->m_stFileName, a_pObject->m_pValue.get( ) );

            a_pObject->m_stCertificateName = a_pObject->m_stFileName;

        } catch( MiniDriverException& x ) {

            Log::error( "Token::addObjectCertificate", "MiniDriverException" );

            throw PKCS11Exception( checkException( x ) );
        }
    }

    // Write the PKCS#11 certificate object into the smart card
    addObject( a_pObject, a_phObject );

    t.stop( "Token::addObjectCertificate" );
    Log::end( "Token::addObjectCertificate" );
}


/*
*/
void Token::addObjectPublicKey( Pkcs11ObjectKeyPublicRSA* a_pObject, CK_OBJECT_HANDLE_PTR a_phObject ) {

    Log::begin( "Token::addObjectPublicKey" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Private public key object is not allowed
    if( a_pObject->isPrivate( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_VALUE_INVALID );
    }

    // Create the certificate into the smart card
    try {

        // If a container already exists using the same public key modulus then the container index will be updated with the index of this container.
        // The keyspec will also be updated
        // The file name will anyway be build automaticaly
        m_Device->containerGetMatching( a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec, a_pObject->m_stFileName, a_pObject->m_pModulus.get( ) );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::addObjectPublicKey", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    setDefaultAttributesKeyPublic( a_pObject );

    a_pObject->_local = CK_FALSE;

    // Write the PKCS#11 certificate object into the smart card
    addObject( a_pObject, a_phObject );

    t.stop( "Token::addObjectPublicKey" );
    Log::end( "Token::addObjectPublicKey" );
}


/*
*/
void Token::deleteObject( const CK_OBJECT_HANDLE& a_hObject ) {

    Log::begin( "Token::deleteObject" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Are we allowed to delete objects ? We must be logged in
    if( !m_Device->isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    StorageObject* o = getObject( a_hObject );

    printObject( o );

    // Delete the PKCS#11 object & MiniDriver file/container from card
    deleteObjectFromCard( o );

    // Delete the PKCS#11 object from inner list of managed objects
    unregisterStorageObject( a_hObject );

    t.stop( "Token::deleteObject" );
    Log::end( "Token::deleteObject" );
}


/*
*/
void Token::deleteObjectFromCard( StorageObject* a_pObject ) {

    Log::begin( "Token::deleteObjectFromCard" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Delete the file from the MiniDriver file system
        switch( a_pObject->getClass( ) ) {

        case CKO_CERTIFICATE:
            {
                CertificateObject* t = static_cast< CertificateObject* >( a_pObject );

                // Delete the certificate file
                //try {

                try {
                    
                    // Check if the container is still valid. Throw an exception if not.
                    MiniDriverContainer c = m_Device->containerGet( t->m_ucContainerIndex );
                
                    // Delete the associated certificate
                    m_Device->certificateDelete( t->m_ucContainerIndex );

                } catch( MiniDriverException ) {
                
                    // The container is not associated to this certitifcate object
                    // Delete the MiniDriver file from the PKCS11 object file name
                    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                }

                //if( 0xFF == t->m_ucContainerIndex ) {

                //    // The container is not associated to this certitifcate object
                //    // Delete the MiniDriver file from the PKCS11 object file name
                //    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                //} else {

                //    m_Device->certificateDelete( t->m_ucContainerIndex );
                //}

                ////} catch( MiniDriverException& ex ) {

                ////    // The container is not associated to this certitifcate object
                ////    // Delete the MiniDriver file from the PKCS11 object file name
                ////    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), t->m_stCertificateName );

                ////    throw ex;
                ////}
            }
            break;

        case CKO_PRIVATE_KEY:
            {
                RSAPrivateKeyObject * v = static_cast< RSAPrivateKeyObject* >( a_pObject );

                // Delete the key container
                m_Device->containerDelete( v->m_ucContainerIndex );
            }
            break;

        default:
            break;
        }

        // Delete the PKCS#11 file from card
        if( !a_pObject->m_stFileName.empty( ) && !a_pObject->m_bOffCardObject ) {

            m_Device->deleteFile( g_stPathPKCS11, a_pObject->m_stFileName );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::deleteObjectFromCard", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::deleteObjectFromCard" );
    Log::end( "Token::deleteObjectFromCard" );
}


/*
*/
void Token::getAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    //Log::begin( "Token::getAttributeValue" );
    //Timer t;
    //t.start( );

    if( !m_pSlot) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    StorageObject* o = getObject( a_hObject );


    // Check if we are allowed to retreive the queried attributes
    if( o->isPrivate( ) && !m_pSlot->isAuthenticated( ) ) {

        for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

            a_pTemplate[ i ].ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }

        throw PKCS11Exception(CKR_USER_NOT_LOGGED_IN);
    }


    // Get the attributes from the object
    for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

        o->getAttribute( &a_pTemplate[ i ] );
    }

    //t.stop( "Token::getAttributeValue" );
    //Log::end( "Token::getAttributeValue" );
}


/*
*/
void Token::setAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    // ??? TODO : verify the new attribute is different from the existing attribute. If both are the same do nothing

    Log::begin( "Token::setAttributeValue" );
    Timer t;
    t.start( );

    if( !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    StorageObject* o = getObject( a_hObject );

    // Check if we are allowed to write
    if( /*o->isPrivate( ) && 	*/ !m_pSlot->isAuthenticated( ) ) {

        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
    }

    for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

        o->setAttribute( a_pTemplate[ i ], false );
    }

    // Check if the object is not read-only
    if( ! o->isModifiable( ) ) {

        throw PKCS11Exception( CKR_ATTRIBUTE_READ_ONLY );
    }

    // Compute this attribute for backward compatibilit with old version of the P11 library
    o->_uniqueId = Util::MakeUniqueId();

    // Get the object buffer
    std::vector< unsigned char > v;
    o->serialize( &v );
    size_t l =  v.size( );
    Marshaller::u1Array d( l );
    for( unsigned int i = 0 ; i <l ; ++i ) {

        d.SetU1At( i, v.at( i ) );
    }

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        if( o->m_bOffCardObject ) {

            m_Device->createFile( g_stPathPKCS11, o->m_stFileName, ( o->m_Private == CK_TRUE ) );

            o->m_bOffCardObject = false;
        }

        m_Device->writeFile( g_stPathPKCS11, o->m_stFileName, &d );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::setAttributeValue", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    printObject( o );

    t.stop( "Token::setAttributeValue" );
    Log::end( "Token::setAttributeValue" );
}


/*
*/
void Token::generateKeyPair( Pkcs11ObjectKeyPublicRSA* a_pObjectPublicKeyRSA, RSAPrivateKeyObject* a_pObjectPrivateKeyRSA, CK_OBJECT_HANDLE_PTR a_pHandlePublicKeyRSA, CK_OBJECT_HANDLE_PTR a_pHandlePrivateKeyRSA ) {

    Log::begin( "Token::generateKeyPair" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    if( ( a_pObjectPublicKeyRSA->m_ulModulusBits < MiniDriver::s_iMinLengthKeyRSA ) || ( a_pObjectPublicKeyRSA->m_ulModulusBits > MiniDriver::s_iMaxLengthKeyRSA ) ) {

        throw PKCS11Exception(CKR_ATTRIBUTE_VALUE_INVALID);
    }

    // Create a smart card container to generate and store the new key pair
    unsigned char ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

    unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

    try {

        m_Device->containerCreate( ucContainerIndex, false, ucKeySpec, a_pObjectPublicKeyRSA->m_pModulus.get( ), a_pObjectPublicKeyRSA->m_ulModulusBits, 0 );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::generateKeyPair", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    if( ucContainerIndex == MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID ) {

        throw PKCS11Exception( CKR_DEVICE_MEMORY );
    }

    a_pObjectPrivateKeyRSA->m_ucContainerIndex = ucContainerIndex;

    a_pObjectPrivateKeyRSA->m_ucKeySpec = ucKeySpec;

    a_pObjectPublicKeyRSA->m_ucContainerIndex = ucContainerIndex;

    a_pObjectPublicKeyRSA->m_ucKeySpec = ucKeySpec;

    try {

        // Populate these objects with the new key material
        MiniDriverContainer c = m_Device->containerGet( ucContainerIndex );

        // Fill the PKCS#11 object with the information about the new key pair
        a_pObjectPublicKeyRSA->_local = CK_TRUE;

        ///// ???
        //a_pObjectPublicKeyRSA->m_pPublicExponent = c.getExchangePublicKeyExponent( );

        a_pObjectPublicKeyRSA->m_pModulus = c.getExchangePublicKeyModulus( );

        // Copy these modulus and exponent in the private key component also
        a_pObjectPrivateKeyRSA->_local = CK_TRUE;

        //// ???
        //a_pObjectPrivateKeyRSA->m_pPublicExponent = c.getExchangePublicKeyExponent( );

        a_pObjectPrivateKeyRSA->m_pModulus = c.getExchangePublicKeyModulus( );

        setDefaultAttributesKeyPrivate( a_pObjectPrivateKeyRSA );

        setDefaultAttributesKeyPublic( a_pObjectPublicKeyRSA );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::generateKeyPair", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    // The public key may be a session object, in that case, don't save it.
    if( a_pObjectPublicKeyRSA->isToken( ) ) {

        addObject( a_pObjectPublicKeyRSA, a_pHandlePublicKeyRSA );
    }

    try {

        addObject( a_pObjectPrivateKeyRSA, a_pHandlePrivateKeyRSA );

    } catch( MiniDriverException& x ) {

        if( a_pObjectPublicKeyRSA->isToken( ) ) {

            deleteObject( *a_pHandlePublicKeyRSA );

            try {

                m_Device->containerDelete( ucContainerIndex );

            } catch( MiniDriverException& ) {

                Log::error( "Token::generateKeyPair", "MiniDriverException" );
            }

            throw PKCS11Exception( checkException( x ) );
        }
    }

    t.stop( "Token::generateKeyPair" );
    Log::end( "Token::generateKeyPair" );
}


/*
*/
void Token::encrypt( const StorageObject* pubObj, Marshaller::u1Array* dataToEncrypt, const CK_ULONG& mechanism, CK_BYTE_PTR pEncryptedData ) {

    Pkcs11ObjectKeyPublicRSA* object = ( Pkcs11ObjectKeyPublicRSA* )pubObj;

    if(mechanism == CKM_RSA_PKCS){
        // first do the length checks
        if(dataToEncrypt->GetLength() > (object->m_pModulus->GetLength() - 11)){
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        rsaPublicKey_t key;

        key.modulus = object->m_pModulus->GetBuffer() ;
        key.modulusLength = object->m_pModulus->GetLength() * 8 ;
        key.publicExponent = object->m_pPublicExponent->GetBuffer();
        key.publicExponentLength =  object->m_pPublicExponent->GetLength() * 8;

        unsigned int outLength = object->m_pModulus->GetLength();

        //DWORD rv ;
        DWORD size ;
        DWORD pubSize ;
        R_RSA_PUBLIC_KEY	rsaKeyPublic ;

        rsaKeyPublic.bits = key.modulusLength ;

        size = (key.modulusLength + 7) / 8 ;
        memcpy(rsaKeyPublic.modulus, key.modulus, size) ;

        pubSize = (key.publicExponentLength + 7) / 8 ;
        memset(rsaKeyPublic.exponent, 0, size) ;
        memcpy(&rsaKeyPublic.exponent[size - pubSize], key.publicExponent, pubSize) ;

        R_RANDOM_STRUCT & randomStruct = Util::RandomStruct();

        RSAPublicEncrypt(
            pEncryptedData,
            &outLength,
            (unsigned char*)dataToEncrypt->GetBuffer(),
            dataToEncrypt->GetLength(),
            &rsaKeyPublic,
            &randomStruct);

    }else{

        unsigned int modulusLen = object->m_pModulus->GetLength();

        if(dataToEncrypt->GetLength() > (modulusLen)){
            throw PKCS11Exception(CKR_DATA_LEN_RANGE);
        }

        // pre-pad with zeros
        Marshaller::u1Array messageToEncrypt(modulusLen);
        memset(messageToEncrypt.GetBuffer(),0,modulusLen);

        s4 offsetMsgToEncrypt = modulusLen - dataToEncrypt->GetLength();

        unsigned int l = dataToEncrypt->GetLength( );
        for( unsigned int i = 0, j = offsetMsgToEncrypt ; i < l ; ++i, ++j ) {

            messageToEncrypt.GetBuffer()[j] = dataToEncrypt->GetBuffer()[i];
        }

        // just block transform now
        s4 size ;
        s4 pubSize ;
        R_RSA_PUBLIC_KEY	rsaKeyPublic ;

        //Build the RSA public key context
        rsaKeyPublic.bits = object->m_pModulus->GetLength() * 8;

        size = (rsaKeyPublic.bits  + 7) / 8 ;
        memcpy(rsaKeyPublic.modulus,object->m_pModulus->GetBuffer(),size) ;

        pubSize = ((object->m_pPublicExponent->GetLength() * 8) + 7) / 8 ;
        memset(rsaKeyPublic.exponent, 0, size) ;
        memcpy(&rsaKeyPublic.exponent[size - pubSize], object->m_pPublicExponent->GetBuffer(), pubSize) ;

        unsigned int outputLen = size;

        RSAPublicBlock(pEncryptedData,&outputLen,messageToEncrypt.GetBuffer(),size,&rsaKeyPublic);
    }
}


/*
*/
void Token::decrypt( const StorageObject* privObj, Marshaller::u1Array* dataToDecrypt, const CK_ULONG& mechanism, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen ) {

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    RSAPrivateKeyObject* rsaKey = (RSAPrivateKeyObject*)privObj;

    boost::shared_ptr< Marshaller::u1Array > data;

    try {

        data = m_Device->privateKeyDecrypt( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, dataToDecrypt );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::decrypt", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    if( !data ) {

        throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );
    }

    unsigned int l = data->GetLength( );

    unsigned char* p = (unsigned char*)data->GetBuffer( );

    if( CKM_RSA_PKCS == mechanism ) {

        unsigned char* decryptedMessage = p;

        if( decryptedMessage[ 0 ] || ( g_ucPKCS_EMEV15_PADDING_TAG != decryptedMessage[ 1 ] ) ) {

            // invalid message padding
            throw PKCS11Exception( CKR_ENCRYPTED_DATA_INVALID );

        } else {

            // seach message padding separator
            unsigned int mPos = 2 + 8;

            while( decryptedMessage[ mPos ] && (mPos < l ) ) {

                ++mPos;
            }

            // point on message itself.
            ++mPos;

            l = l - mPos;

            data.reset( new Marshaller::u1Array( l ) );

            p = data->GetBuffer( );

            memcpy( p, (unsigned char*)&decryptedMessage[ mPos ],  l );
        }
    }
    // else... CKM_RSA_X_509: Ignore padding

    if( data ) {

        if ( *pulDataLen >= l ) {

            memset( pData, 0, *pulDataLen );

            memcpy( pData, p, l );

            *pulDataLen = l;
        } else {

            *pulDataLen = l;

            throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
        }
    }
}


/*
*/
void Token::verify( const StorageObject* pubObj, Marshaller::u1Array* dataToVerify, const CK_ULONG& mechanism, Marshaller::u1Array* signature) {

    Pkcs11ObjectKeyPublicRSA* o = (Pkcs11ObjectKeyPublicRSA*)pubObj;

    if(((mechanism == CKM_RSA_PKCS) && (dataToVerify->GetLength() > (o->m_pModulus->GetLength() - 11))) ||
        ((mechanism == CKM_RSA_X_509) && (dataToVerify->GetLength() > o->m_pModulus->GetLength())))
    {
        throw PKCS11Exception(CKR_DATA_LEN_RANGE);
    }

    if( signature->GetLength( ) != o->m_pModulus->GetLength( ) ){

        throw PKCS11Exception(CKR_SIGNATURE_LEN_RANGE);
    }

    s4 size;
    s4 pubSize;
    R_RSA_PUBLIC_KEY rsaKeyPublic ;

    //Build the RSA public key context
    rsaKeyPublic.bits = o->m_pModulus->GetLength() * 8;

    size = (rsaKeyPublic.bits  + 7) / 8 ;
    memcpy(rsaKeyPublic.modulus, o->m_pModulus->GetBuffer(),size) ;

    pubSize = ((o->m_pPublicExponent->GetLength() * 8) + 7) / 8 ;
    memset(rsaKeyPublic.exponent, 0, size) ;
    memcpy(&rsaKeyPublic.exponent[size - pubSize], o->m_pPublicExponent->GetBuffer(), pubSize) ;

    unsigned int messageToVerifyLen = size;
    Marshaller::u1Array messageToVerify( messageToVerifyLen );

    RSAPublicBlock(messageToVerify.GetBuffer(),&messageToVerifyLen,signature->GetBuffer(),size,&rsaKeyPublic);

    switch(mechanism){

    case CKM_RSA_PKCS:
        verifyRSAPKCS1v15( &messageToVerify,dataToVerify,size);
        break;

    case CKM_RSA_X_509:
        verifyRSAX509( &messageToVerify,dataToVerify,size);
        break;


    case CKM_SHA1_RSA_PKCS:
        verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA_1);
        break;

    case CKM_SHA256_RSA_PKCS:
        verifyHash( &messageToVerify,dataToVerify,size,CKM_SHA256);
        break;

    case CKM_MD5_RSA_PKCS:
        verifyHash( &messageToVerify,dataToVerify,size,CKM_MD5);
        break;

    default:
        throw PKCS11Exception( CKR_GENERAL_ERROR );
    }
}


/*
*/
void Token::verifyHash( Marshaller::u1Array* messageToVerify, Marshaller::u1Array* dataToVerify, const unsigned int& modulusLen, const CK_ULONG& hashAlgo ) {

    const unsigned char* msg  = messageToVerify->GetBuffer( );

    // Check the decoded value against the expected data.
    if( ( msg[ 0 ] != 0x00 ) || ( msg[ 1 ] != 0x01 ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }
    unsigned char DER_SHA1_Encoding[]   = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
    unsigned char DER_SHA256_Encoding[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
    unsigned char DER_MD5_Encoding[]    = {0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10};

    s4  DER_Encoding_Len = 0;

    switch(hashAlgo){
    case CKM_SHA_1:
        DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
        break;

    case CKM_SHA256:
        DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
        break;

    case CKM_MD5:
        DER_Encoding_Len = sizeof(DER_MD5_Encoding);
        break;

    }

    const unsigned char* hash = dataToVerify->GetBuffer();
    unsigned int hashLen = dataToVerify->GetLength();

    s4 posn = modulusLen - DER_Encoding_Len - hashLen;

    for(s4 i = 2; i < (posn - 1); i++)
    {
        if(msg[i] != 0xFF){
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }

    if(msg[posn - 1] != 0x00){
        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }

    for (unsigned int i = 0; i < hashLen; ++i){
        if (msg[posn + i + DER_Encoding_Len] != hash[i]){
            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }
}


/*
*/
void Token::verifyRSAX509( Marshaller::u1Array* messageToVerify, Marshaller::u1Array* dataToVerify, const unsigned int& modulusLen ) {

    // Reach the first non-zero bytes in data
    unsigned int usDataLen = dataToVerify->GetLength( );
    unsigned int pos1=0;
    const unsigned char* pData = dataToVerify->GetBuffer( );
    for( ; pos1 < usDataLen ; ++pos1 ) {

        if( pData[ pos1 ] ) {

            break;
        }
    }

    // Reach the first non-zero bytes in decrypted signature
    unsigned int usMessageLen = messageToVerify->GetLength( );
    const unsigned char* pMessage = messageToVerify->GetBuffer( );
    unsigned int pos2=0;
    for( ; pos2 < usMessageLen ; ++pos2 ) {

        if( pMessage[ pos2 ] ) {

            break;
        }
    }

    if( ( usDataLen - pos1 ) != ( modulusLen - pos2 ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }


    for( unsigned int i = pos1, j = pos2 ; i < ( modulusLen - pos2 ) ; ++i, ++j ) {

        if( pData[ i ] != pMessage[ j ] ) {

            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }
}


/*
*/
void Token::verifyRSAPKCS1v15( Marshaller::u1Array* messageToVerify, Marshaller::u1Array* dataToVerify, const unsigned int& modulusLen ) {

    // Skip the PKCS block formatting data
    unsigned int pos = 2;
    const unsigned char* pMessage = messageToVerify->GetBuffer( ); 
    for( ; pos < modulusLen ; ++pos) {

        if( !pMessage[ pos ] ) { //== 0x00

            ++pos;
            break;
        }
    }

    if( dataToVerify->GetLength( ) != ( modulusLen - pos ) ) {

        throw PKCS11Exception( CKR_SIGNATURE_INVALID );
    }

    const unsigned char* pData = dataToVerify->GetBuffer( ); 
    for( unsigned int i = 0, j = pos ; i < ( modulusLen - pos ) ; ++i, ++j ) {

        if( pData[ i ] != pMessage[ j ] ) {

            throw PKCS11Exception( CKR_SIGNATURE_INVALID );
        }
    }
}


/*
*/
void Token::sign( const RSAPrivateKeyObject* privObj, Marshaller::u1Array* dataToSign, const CK_ULONG& mechanism, CK_BYTE_PTR pSignature ) {

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    boost::shared_ptr< Marshaller::u1Array > messageToSign;

    RSAPrivateKeyObject* rsaKey = ( RSAPrivateKeyObject* ) privObj;

    if( !(rsaKey->m_pModulus) ) {

        throw PKCS11Exception( CKR_KEY_FUNCTION_NOT_PERMITTED );
    }

    CK_ULONG modulusLen = rsaKey->m_pModulus->GetLength( );

    if( ( ( mechanism == CKM_RSA_PKCS ) && ( dataToSign->GetLength( ) > ( modulusLen - 11 ) ) ) || ( ( mechanism == CKM_RSA_X_509 ) && ( dataToSign->GetLength( ) > modulusLen ) ) ) {

        throw PKCS11Exception( CKR_DATA_LEN_RANGE );
    }

    switch( mechanism ) {

    case CKM_RSA_PKCS:
        messageToSign.reset( PadRSAPKCS1v15( dataToSign, modulusLen ) );
        break;

    case CKM_RSA_X_509:
        messageToSign.reset( PadRSAX509( dataToSign, modulusLen ) );
        break;

    case CKM_SHA1_RSA_PKCS:
        messageToSign.reset( EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA_1 ) );
        break;

    case CKM_SHA256_RSA_PKCS:
        messageToSign.reset( EncodeHashForSigning( dataToSign, modulusLen, CKM_SHA256 ) );
        break;

    case CKM_MD5_RSA_PKCS:
        messageToSign.reset( EncodeHashForSigning( dataToSign, modulusLen, CKM_MD5 ) );
        break;
    }

    boost::shared_ptr< Marshaller::u1Array > signatureData;

    try {

        signatureData = m_Device->privateKeyDecrypt( rsaKey->m_ucContainerIndex, rsaKey->m_ucKeySpec, messageToSign.get( ) );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::sign", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    if( !signatureData ) {

        throw PKCS11Exception( CKR_FUNCTION_FAILED );
    }

    memcpy( pSignature, signatureData->GetBuffer( ), signatureData->GetLength( ) );
}


/*
*/
Marshaller::u1Array* Token::PadRSAPKCS1v15( Marshaller::u1Array* dataToSign, const CK_ULONG& modulusLen ) {

    Marshaller::u1Array* messageToSign = new Marshaller::u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    messageToSign->SetU1At( 1, 1 );

    s4 offsetMessageToSign = modulusLen - dataToSign->GetLength( ) - 3;

    for( s4 i = 0 ; i < offsetMessageToSign ; ++i ) {

        messageToSign->SetU1At( 2 + i, 0xFF );
    }

    offsetMessageToSign += 3;

    memcpy( (unsigned char*)&messageToSign->GetBuffer( )[ offsetMessageToSign ], dataToSign->GetBuffer( ), dataToSign->GetLength( ) );

    return messageToSign;
}


/*
*/
Marshaller::u1Array* Token::PadRSAX509( Marshaller::u1Array* dataToSign, const CK_ULONG& modulusLen ) {

    Marshaller::u1Array* messageToSign = new Marshaller::u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    s4 offsetMessageToSign = modulusLen - dataToSign->GetLength( );

    memcpy( (unsigned char*)&messageToSign->GetBuffer( )[ offsetMessageToSign ], dataToSign->GetBuffer( ), dataToSign->GetLength( ) );

    return messageToSign;
}


/*
*/
Marshaller::u1Array* Token::EncodeHashForSigning( Marshaller::u1Array* hashedData, const CK_ULONG& modulusLen, const CK_ULONG& hashAlgo ) {

    unsigned char DER_SHA1_Encoding[ ]   = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };

    unsigned char DER_SHA256_Encoding[ ] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

    unsigned char DER_MD5_Encoding[ ]    = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

    unsigned char* DER_Encoding = NULL_PTR;

    s4 DER_Encoding_Len = 0;

    switch( hashAlgo ) {

    case CKM_SHA_1:
        DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_SHA1_Encoding,DER_Encoding_Len);
        break;

    case CKM_SHA256:
        DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_SHA256_Encoding,DER_Encoding_Len);
        break;

    case CKM_MD5:
        DER_Encoding_Len = sizeof(DER_MD5_Encoding);
        DER_Encoding = new unsigned char[DER_Encoding_Len]; //(unsigned char*)malloc(DER_Encoding_Len);
        memcpy(DER_Encoding,DER_MD5_Encoding,DER_Encoding_Len);
        break;

    }

    Marshaller::u1Array* messageToSign = new Marshaller::u1Array( modulusLen );

    memset( messageToSign->GetBuffer( ), 0, modulusLen );

    messageToSign->SetU1At( 1, 1 );

    // caluclate pos
    int pos = modulusLen - DER_Encoding_Len - hashedData->GetLength( );

    for( int i = 2 ; i < (pos - 1) ; ++i ) {

        messageToSign->SetU1At( i, 0xFF );
    }

    memcpy((unsigned char*)&messageToSign->GetBuffer()[pos],DER_Encoding,DER_Encoding_Len);
    memcpy((unsigned char*)&messageToSign->GetBuffer()[pos+DER_Encoding_Len],hashedData->GetBuffer(),hashedData->GetLength());

    delete DER_Encoding;

    return messageToSign;
}


/* Add a PKCS11 object to the token object list
*/ 
CK_OBJECT_HANDLE Token::registerStorageObject( StorageObject* a_pObject ) {

    Log::begin( "Token::registerStorageObject" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        Log::error( "Token::registerStorageObject", "Invalid object" );
        return CK_UNAVAILABLE_INFORMATION;
    }

    // increment the object index
    CK_OBJECT_HANDLE h = computeObjectHandle( a_pObject->getClass( ), a_pObject->isPrivate( ) );

    // Expand the object list
    m_Objects.insert( h, a_pObject );

    Log::log( "registerStorageObject - Handle <%#02x> - Type <%ld> - File <%s>", h, a_pObject->getClass( ), a_pObject->m_stFileName.c_str( ) );
    printObject( a_pObject );

    t.stop( "Token::registerStorageObject" );
    Log::end( "Token::registerStorageObject" );

    // Return the object index
    return h;
}


/*
*/
void Token::printObject( StorageObject* a_pObject ) {

    if( !Log::s_bEnableLog ) {

        return;
    }

    Log::log( "    ====" );

    switch( a_pObject->getClass( ) ) {

    case CKO_DATA:
        Log::log( "Object CKO_DATA" );
        ( (DataObject*) a_pObject )->print( );
        break;

    case CKO_CERTIFICATE:
        Log::log( "Object CKO_CERTIFICATE" );
        ( (X509PubKeyCertObject*) a_pObject )->print( );
        break;

    case CKO_PRIVATE_KEY:
        Log::log( "Object CKO_PRIVATE_KEY" );
        ( (RSAPrivateKeyObject*) a_pObject )->print( );
        break;

    case CKO_PUBLIC_KEY:
        Log::log( "Object CKO_PUBLIC_KEY" );
        ( (Pkcs11ObjectKeyPublicRSA*) a_pObject )->print( );
        break;
    };

    Log::log( "    ====" );

}


/*
*/
void Token::unregisterStorageObject( const CK_OBJECT_HANDLE& a_pObject ) {

    Log::begin( "Token::unregisterStorageObject" );
    Timer t;
    t.start( );

    TOKEN_OBJECTS::iterator i = m_Objects.find( a_pObject );

    if( i != m_Objects.end( ) ) {

        m_Objects.erase( i );

        Log::log( "unregisterStorageObject - Handle <%#02x> erased", a_pObject );
    }

    t.stop( "Token::unregisterStorageObject" );
    Log::end( "Token::unregisterStorageObject" );
}


/*
*/
void Token::initPIN( Marshaller::u1Array* a_PinSo, Marshaller::u1Array* a_PinUser ) {

    Log::begin( "Token::initPIN" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Initialize the PIN
        m_Device->unblockPin( a_PinSo, a_PinUser );

        // ??? TO DO ??? Utiliser la proprieté card pin initalize
        m_TokenInfo.flags |= CKF_USER_PIN_INITIALIZED;

        // Reset some User PIN flags
        m_TokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
        m_TokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
        m_TokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

    } catch( MiniDriverException& ) {

        // incorrect pin
        unsigned char triesRemaining = 0;

        try {

            triesRemaining = m_Device->administratorGetTriesRemaining( );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::initPIN", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        // blocked
        if(triesRemaining == 0) {

            // update tokeninfo flahs
            m_TokenInfo.flags |= CKF_SO_PIN_LOCKED;
            m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
            m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;

        } else if( triesRemaining == 1 ) {

            m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
            m_TokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
            m_TokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;

        }else /*if( triesRemaining < MAX_SO_PIN_TRIES )*/ {

            m_TokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
            m_TokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
            m_TokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;

        }

        throw PKCS11Exception( CKR_PIN_INCORRECT );
    }

    t.stop( "Token::initPIN" );
    Log::end( "Token::initPIN" );
}


/*
*/
void Token::setPIN( Marshaller::u1Array* a_pOldPIN, Marshaller::u1Array* a_pNewPIN ) {

    Log::begin( "Token::setPIN" );
    Timer t;
    t.start( );

    if( !m_Device || !m_pSlot ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // According the logical state of the slot the PIN is set for the user or the administrator
    // The logical state is based on the PKCS11 state of the slot's sessions
    try {

        if( m_pSlot->isAuthenticated( ) ) {

            m_Device->changePin( a_pOldPIN, a_pNewPIN );

        } else if( m_pSlot->administratorIsAuthenticated( ) ) {

            m_Device->administratorChangeKey( a_pOldPIN, a_pNewPIN );

        } else {

            throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
        }

    } catch( MiniDriverException& x ) {

        checkAuthenticationStatus( m_RoleLogged, x );
    }

    t.stop( "Token::setPIN" );
    Log::end( "Token::setPIN" );
}


/*
*/
void Token::initToken( Marshaller::u1Array* a_pinSO, Marshaller::u1Array* a_label ) {

    Log::begin( "Token::initToken" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Check that label does not contain null-characters
    unsigned int l = a_label->GetLength( );

    for( unsigned int i = 0 ; i < l; ++i ) {

        if( !a_label->ReadU1At( i ) ) {

            throw PKCS11Exception( CKR_ARGUMENTS_BAD );
        }
    }

    // actual authentication
    authenticateAdmin( a_pinSO );

    try
    {
        // Destroy all the token objects present into the PKCS11 directory
        // Note that when the private key is destroyed the associated container is also deleted
        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

            // Delete the PKCS#11 object file from card
            deleteObjectFromCard( o->second );
        }

        // Destroy all PKCS11 objects from the inner list of objects to manage
        m_Objects.clear( );

        // Destroy all the token objects present into the MSCP directory
        try {

            m_Device->deleteFileStructure( );

        } catch( MiniDriverException& x ) {

            Log::error( "Token::initToken", "MiniDriverException" );
            throw PKCS11Exception( checkException( x ) );
        }

        // Update the token's label and flags attribute.
        m_TokenInfo.flags |= CKF_TOKEN_INITIALIZED;

        m_TokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;

        memcpy( m_TokenInfo.label, a_label->GetBuffer( ), sizeof( m_TokenInfo.label ) );

        createTokenInfo( );

        // Write the new token information file into the smart card
        m_bWriteTokenInfoFile = true;

        writeTokenInfo( );

        // Log out
        m_Device->administratorLogout( );

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

    } catch( MiniDriverException& x) {

        m_RoleLogged = CK_UNAVAILABLE_INFORMATION;

        try { m_Device->administratorLogout( ); } catch(...) {}

        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::initToken" );
    Log::end( "Token::initToken" );
}


/*
*/
CK_OBJECT_HANDLE Token::computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ) { 

    // Increment the object counter
    incrementObjectIndex( );

    // Register the token object id (value from 0 to 255)
    unsigned char ucByte1 = m_uiObjectIndex;

    // Register the object class and if the object is private:
    // Private Data	        1000 [08] = set class to CKO_DATA (0x00) and Private to TRUE (0x08)
    // Public Data	        0000 [00] = set class to CKO_DATA (0x00) and Private to FALSE (0x00)	
    // Private Certificate	1001 [09] = set class to CKO_CERTIFICATE (0x01) and Private to TRUE (0x08)
    // Public Certificate	0001 [01] = set class to CKO_CERTIFICATE (0x01) and Private to FALSE (0x00)		
    // Private Public Key	1010 [0A] = set class to CKO_PUBLIC_KEY (0x02) and Private to TRUE (0x08)
    // Public Public Key	0010 [02] = set class to CKO_PUBLIC_KEY (0x02) and Private to FALSE (0x00)    
    // Private Private Key	1011 [0B] = set class to CKO_PRIVATE_KEY (0x03) and Private to TRUE (0x08)			
    // Public Private Key	0011 [03] = set class to CKO_PRIVATE_KEY (0x03) and Private to FALSE (0x00)
    unsigned char ucByte2 = (unsigned char)a_ulClass | ( a_bIsPrivate ? 0x10 : 0x00 );

    // Register if the object is owned by the token (value 0) or the session (value corresponding to the session id from 1 to 255)
    unsigned char ucByte3 = 0;

    // Register the slot id
    unsigned char ucByte4 = 0xFF;
    try {

        if( m_Device ) {

            ucByte4 = (unsigned char) ( 0x000000FF & m_Device->getDeviceID( ) );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::computeObjectHandle", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    // Compute the object handle: byte4 as Slot Id, byte3 as Token/Session, byte2 as attributes and byte1 as object Id					
    CK_OBJECT_HANDLE h = ( ucByte4 << 24 ) + ( ucByte3 << 16 ) + ( ucByte2 << 8 )+ ucByte1;

    return h; 
}


/*
*/
StorageObject* Token::getObject( const CK_OBJECT_HANDLE& a_hObject ) {

    TOKEN_OBJECTS::iterator i = m_Objects.find( a_hObject );

    if( i == m_Objects.end( ) ) {

        throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
    }

    return i->second;
}


/*
*/
bool isFileExists( const std::string& a_stFileName, const MiniDriverFiles::FILES_NAME& a_stFilesList ) {

    // Look if the file name is present intot the list
    BOOST_FOREACH( const std::string& fileName, a_stFilesList ) {

        // The file name has been found
        if( std::string::npos != a_stFileName.find( fileName ) ) {

            return true;
        }
    }

    return false;
}


/*
*/
void Token::synchronizeObjects( void ) {

    Log::begin( "Token::synchronizeObjects" );
    Timer t;
    t.start( );

    try {

        initializeObjectIndex( );

        // PIN changed, so re-synchronize
        synchronizePIN( );		

        // Remove all PKCS11 objects
        m_Objects.clear( );

        // Files changed, so re-synchronize
        m_bSynchronizeObjectsPublic = true;
        synchronizePublicObjects( );

        m_bSynchronizeObjectsPrivate = true;
        synchronizePrivateObjects( );	

    } catch( ... ) {

    }

    t.stop( "Token::synchronizeObjects" );
    Log::end( "Token::synchronizeObjects" );
}


/*
*/
bool Token::synchronizeIfSmartCardContentHasChanged( void ) {

    Log::begin( "Token::synchronizeIfSmartCardContentHasChanged" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    bool bSynchronizationPerformed = false;

    try {

        // Check if the smart card content has changed
        MiniDriverCardCacheFile::ChangeType pins = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType containers = MiniDriverCardCacheFile::NONE;
        MiniDriverCardCacheFile::ChangeType files = MiniDriverCardCacheFile::NONE;
        m_Device->hasChanged( pins, containers, files );

        if( MiniDriverCardCacheFile::PINS == pins ) {

            // PIN changed, so re-synchronize
            synchronizePIN( );		
        }

        if( ( MiniDriverCardCacheFile::CONTAINERS == containers ) || ( MiniDriverCardCacheFile::FILES == files ) ) {

            synchronizeObjects( );

            bSynchronizationPerformed = true;
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizeIfSmartCardContentHasChanged", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );

    }

    t.stop( "Token::synchronizeIfSmartCardContentHasChanged" );
    Log::end( "Token::synchronizeIfSmartCardContentHasChanged" );

    return bSynchronizationPerformed;
}


/* Synchronise the cache with the smart card content
*/
void Token::synchronizePublicObjects( void ) {

    try {

        if( !m_bSynchronizeObjectsPublic ) {

            return;
        }
        m_bSynchronizeObjectsPublic = false;

        Log::begin( "Token::synchronizeObjectsPublic" );
        Timer t;
        t.start( );

        synchronizeRootCertificateObjects( );

        synchronizePublicDataObjects( );

        synchronizePublicCertificateAndKeyObjects( );

        t.stop( "Token::synchronizePublicObjects" );
        Log::end( "Token::synchronizePublicObjects" );

    } catch( ... ) {

    }
}


/*
*/
void Token::synchronizePrivateObjects( void ) {

    if( !m_bSynchronizeObjectsPrivate ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Synchronization of the private objects is only possible is the user is logged in
        
        //========= TEST
        if( m_pSlot && !m_pSlot->isAuthenticated( ) ) {
        //if( !m_Device->isAuthenticated( ) ) {

            return;
        }

        Log::begin( "Token::synchronizeObjectsPrivate" );
        Timer t;
        t.start( );

        synchronizePrivateDataObjects( );

        synchronizePrivateKeyObjects( );

        m_bSynchronizeObjectsPrivate = false;

        t.stop( "Token::synchronizeObjectsPrivate" );
        Log::end( "Token::synchronizeObjectsPrivate" );

    } catch( ... ) {

        m_bSynchronizeObjectsPrivate = true;
    }

    //m_bSynchronizeObjectsPrivate = false;
}


/*
*/
void Token::synchronizePIN( void ) {

    try {

        Log::begin( "Token::synchronizePIN" );
        Timer t;
        t.start( );

        // ??? TO DO ???

        t.stop( "Token::synchronizePIN" );
        Log::end( "Token::synchronizePIN" );

    } catch( ... ) {

    }
}


/*
*/
void Token::synchronizeRootCertificateObjects( void ) {

    Log::begin( "Token::synchronizeRootCertificateObjects" );
    Timer t;
    t.start( );

    // No directory ? So object to load
    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    unsigned char ucIndex = 0;
    unsigned char ucIndexMax = m_Device->containerCount( );

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stPrefixMiniDriver = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );

        std::string stPrefixPKCS11 = g_stPrefixPublicObject + g_stPrefixRootCertificate;

        std::string stFilePKCS11 = "";

        BOOST_FOREACH( const std::string& stFileMiniDriver, filesMiniDriver ) {

            // All files must begin with a fixed prefix for public objects
            if( stFileMiniDriver.find( stPrefixMiniDriver ) != 0 ) {

                // Only deal with objects corresponding to the incoming prefix
                continue;
            }

            // The index of a root certificate is out of the range of the valid MiniDriver containers
            ucIndex = computeIndex( stFileMiniDriver );
            if ( ucIndex <= ucIndexMax ) {

                continue;
            }

            stFilePKCS11 = stPrefixPKCS11;
            Util::toStringHex( ucIndex, stFilePKCS11 );

            MiniDriverFiles::FILES_NAME::iterator it = filesPKCS11.find( stFilePKCS11 );

            if( it != filesPKCS11.end( ) ) {

                // The PKCS11 object exists. Load it.
                createCertificateFromPKCS11ObjectFile( stFilePKCS11, stFileMiniDriver );

            } else {

                // The PKCS11 object does not exists. Create a memory object from the MiniDriver file.
                createCertificateFromMiniDriverFile( stFileMiniDriver, MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID,  MiniDriverContainer::KEYSPEC_SIGNATURE );
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizeRootCertificateObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizeRootCertificateObjects" );
    Log::end( "Token::synchronizeRootCertificateObjects" );
}


/* Read all public data
*/
void Token::synchronizePublicDataObjects( void ) {

    Log::begin( "Token::synchronizePublicDataObjects" );
    Timer t;
    t.start( );

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME files = m_Device->enumFiles( g_stPathPKCS11 );

        std::string a_stPrefix = g_stPrefixPublicObject + g_stPrefixData;

        BOOST_FOREACH( const std::string& s, files ) {

            // All files must begin with a fixed prefix for public objects
            if( s.find( a_stPrefix ) != 0 ) {

                // Only deal with objects corresponding to the incoming prefix
                continue;
            }

            // Read the file
            Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, s );

            // Construct the PKCS11 object attributes from the file
            std::vector< unsigned char > attributes;

            unsigned int l = f->GetLength( );

            for( unsigned int u = 0 ; u < l ; ++u ) {

                attributes.push_back( f->GetBuffer( )[ u ] );
            }

            // Create the PKCS11 object
            DataObject* o = new DataObject( );

            // Put the file content into the object
            CK_ULONG idx = 0;
            o->deserialize( attributes, &idx );

            // Save the fileName in the object 
            o->m_stFileName = s;

            Log::log( "Found %s - Public data object created", s.c_str( ) );

            registerStorageObject( o );
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePublicDataObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePublicDataObjects" );
    Log::end( "Token::synchronizePublicDataObjects" );
}


/* Read all private data
*/
void Token::synchronizePrivateDataObjects( void ) {

    Log::begin( "Token::synchronizePrivateDataObjects" );
    Timer t;
    t.start( );

    if( m_bCreateDirectoryP11 ) {

        return;
    }

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME files = m_Device->enumFiles( g_stPathPKCS11 );

        std::string a_stPrefix = g_stPrefixPrivateObject + g_stPrefixData;

        BOOST_FOREACH( const std::string& s, files ) {

            // All files must begin with a fixed prefix for public objects
            if( s.find( a_stPrefix ) != 0 ) {

                // Only deal with objects corresponding to the incoming prefix
                continue;
            }

            // Read the file
            Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, s );

            // Construct the PKCS11 object attributes from the file
            std::vector< unsigned char > attributes;

            unsigned int l = f->GetLength( );

            for( unsigned int u = 0 ; u < l ; ++u ) {

                attributes.push_back( f->GetBuffer( )[ u ] );
            }

            // Create the PKCS11 object
            DataObject* o = new DataObject( );

            // Put the file content into the object
            CK_ULONG idx = 0;
            o->deserialize( attributes, &idx );

            // Save the fileName in the object 
            o->m_stFileName = s;

            Log::log( "Found %s - Private data created", s.c_str( ) );

            registerStorageObject( o );

            m_Device->cacheDisable( s );
        }

    } catch( MiniDriverException& ) {

        Log::error( "Token::synchronizePrivateDataObjects", "MiniDriverException" );
    }

    t.stop( "Token::synchronizePrivateDataObjects" );
    Log::end( "Token::synchronizePrivateDataObjects" );
}


/*
*/
bool Token::checkSmartCardContent( void ) {

    Log::begin( "Token::checkSmartCardContent" );
    Timer t;
    t.start( );

    if( m_bCheckSmartCardContentDone ) {
     
        return false;
    }

    Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj BEFORE P11 clean");
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

        printObject( o.second );
    }
    Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj BEFORE P11 clean");


    bool bReturn = false;

    if( !m_Device ) {

        return bReturn;
    }

    // Get all PKCS11 object files from the PKCS11 directory into the smart card
    MiniDriverFiles::FILES_NAME filesPKCS11;

    if( !m_bCreateDirectoryP11 ) {

        try {

            filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

        } catch( ... ) { }
    }

    // Get all certificate files from the smart card
    MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

    std::string stContainerIndex = "";
    unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
    unsigned int uiKeySize = 0;
    std::string stPrefix = "";
    std::string stCertificateFileName = "";
    std::string stObjectPKCS11 = "";
    std::string stPublicCertificateExchange = g_stPrefixPublicObject + std::string( szUSER_KEYEXCHANGE_CERT_PREFIX );
    std::string stPublicCertificateSignature = g_stPrefixPublicObject + std::string( szUSER_SIGNATURE_CERT_PREFIX );
    std::string stPublicKey = g_stPrefixPublicObject + g_stPrefixKeyPublic;
    std::string stPrivateKey = g_stPrefixPrivateObject + g_stPrefixKeyPrivate;
    unsigned char ucKeyContainerIndexReal = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
    std::string stFileName = "";

    try {

        // Explore each smart card key container to fix any CMapFile anomaly or wrong associated certificate
        unsigned char ucContainerCount = m_Device->containerCount( );

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );

            // Get the current container
            MiniDriverContainer cont = m_Device->containerGet( ucContainerIndex );

            Log::log( "=========" );
            Log::log( "Token::checkSmartCardContent - Container <%d>", ucContainerIndex );

            unsigned char flags = cont.getFlags( );
            if ( flags == MiniDriverContainer::CMAPFILE_FLAG_EMPTY ) {

                // The current container is empty

                // Check that none P11 object is associated to this container
                // If a P11 object using this index then it must be associated to the good container or be deleted

                // Check that none MiniDriver certificate is associated to this container
                // If a MiniDriver certificate exists then it must be associated to the good contained or be deleted
                // It could also be a root certificate enrolled by an old P11 version

                // Check the container properties is compliant with the CMapFile state
                // If the CMapFile state shows a type (signature/exchange), a size (1024/2048) or a state (empty/valid/valid & default) different 
                // from the information given by the container property then the CMapFile must be changed

                Log::log( "Token::checkSmartCardContent - This container is empty" );

                stCertificateFileName = szUSER_KEYEXCHANGE_CERT_PREFIX;
                stCertificateFileName += stContainerIndex;
                Log::log( "Token::checkSmartCardContent - Check if the certificate <%s> is present", stCertificateFileName.c_str( ) );

                MiniDriverFiles::FILES_NAME::iterator it = filesMiniDriver.find( stCertificateFileName );

                if( it != filesMiniDriver.end( ) ) {

                    // The container is empty but a certificate is associated into the MiniDriver file structure.
                    // That certificate must be moved from the MiniDriver file structure to the PKCS11 one.

                    // Create a new root certificate
                    X509PubKeyCertObject* pNewCertificate = new X509PubKeyCertObject( );

                    pNewCertificate->m_stCertificateName = "";

                    pNewCertificate->m_stFileName = "";

                    pNewCertificate->m_ucContainerIndex = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;

                    try {

                        // Read the file
                        m_Device->readCertificate( stCertificateFileName, pNewCertificate->m_pValue );

                    } catch( MiniDriverException& ) {

                        // Unable to read the on card certificate.
                        // The P11 object creation is skipped.
                        Log::error( "Token::createCertificateFromMiniDriverFile", "Unable to read the certificate" );
                        continue;
                    }

                    if( pNewCertificate->m_pValue.get( ) ) {

                        generatePublicKeyModulus( pNewCertificate->m_pValue, pNewCertificate->m_pModulus, pNewCertificate->_checkValue );

                        generateRootAndSmartCardLogonFlags( pNewCertificate->m_pValue, pNewCertificate->m_bIsRoot, pNewCertificate->_certCategory, pNewCertificate->m_bIsSmartCardLogon );
                    }

                    // Delete the old certificate from the MiniDriver file structure
                    m_Device->deleteFile( std::string( szBASE_CSP_DIR ), stCertificateFileName );
                    Log::log( "Token::checkSmartCardContent - delete <%s> in MSCP dir", stCertificateFileName.c_str( ) );
                    bReturn = true;

                    // Remove the previous PKCS11 certificate associated to the MiniDriver certificate
                    std::string stIndex = stCertificateFileName.substr( stCertificateFileName.length( ) - 2, 2 );
                    std::string stPKCS11CertificateName = stPublicCertificateExchange + stIndex;
                    m_Device->deleteFile( g_stPathPKCS11, stPKCS11CertificateName );
                    Log::log( "Token::checkSmartCardContent - delete <%s> in P11 dir", stPKCS11CertificateName.c_str( ) );

                    //// Delete the PKCS#11 object from inner list of managed objects
                    //unregisterStorageObject( p );
                    //Log::log( "Token::checkSmartCardContent - delete <%s> in MSCP dir", stCertificateFileName.c_str( ) );

                    // Create the new root certificate intot the MniDriver & PKCS11 file structures
                    CK_OBJECT_HANDLE h = CK_UNAVAILABLE_INFORMATION;
                    addObjectCertificate( pNewCertificate, &h );
                    Log::log( "Token::checkSmartCardContent - add new P11 root certificate <%s>", pNewCertificate->m_stFileName.c_str( ) );

                    pNewCertificate->m_stCertificateName = pNewCertificate->m_stFileName.substr( 3, 5 );

                    // Delete the container from the MiniDriver file structure
                    m_Device->containerDelete( ucContainerIndex );
                    Log::log( "Token::checkSmartCardContent - delete container <%d>", ucContainerIndex );

                    // Check if a private or a public key was associated to this container
                    std::string stPrefix = stPrivateKey;

                    do {

                        stObjectPKCS11 = stPrefix + stIndex;

                        MiniDriverFiles::FILES_NAME::iterator it = filesPKCS11.find( stObjectPKCS11 );

                        if( it != filesPKCS11.end( ) ) {

                            // The PKCS11 private/public key exists.
                            // Check the public key modulus to find a new container to associate with

                            // Read the file
                            Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, stObjectPKCS11 );

                            // Construct the PKCS11 object attributes from the file
                            std::vector< unsigned char > attributes;

                            unsigned int l = f->GetLength( );

                            for( unsigned int u = 0 ; u < l ; ++u ) {

                                attributes.push_back( f->GetBuffer( )[ u ] );
                            }

                            // Create the PKCS11 object from the file content
                            boost::shared_ptr< StorageObject > oldObjectOnCard;

                            CK_ULONG idx = 0;

                            if( stPrefix.compare( stPublicKey ) == 0 ) {

                                oldObjectOnCard.reset( new Pkcs11ObjectKeyPublicRSA ); 

                                ( ( Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );

                            } else {

                                oldObjectOnCard.reset( new RSAPrivateKeyObject );

                                ( ( RSAPrivateKeyObject* ) oldObjectOnCard.get( ) )->deserialize( attributes, &idx );
                            }

                            // Set the old file name
                            oldObjectOnCard->m_stFileName = stObjectPKCS11;

                            // Get the container index written into the object
                            unsigned char ucKeyContainerIndexInObject = ( ( KeyObject* ) oldObjectOnCard.get( ) )->m_ucContainerIndex;
                            Log::log( "Token::checkSmartCardContent - Container index found into the P11 object <%d>", ucKeyContainerIndexInObject );

                            // Get the container index set into the file name
                            unsigned char ucKeyContainerIndexInFileName = computeIndex( stIndex );
                            Log::log( "Token::checkSmartCardContent - Container index found into the P11 file name <%d>", ucKeyContainerIndexInFileName );

                            // Get the public key modulus
                            Marshaller::u1Array* pPublicKeyModulus = NULL;

                            if( 0 == stPrefix.compare( stPublicKey ) ) {

                                pPublicKeyModulus = ( ( Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) )->m_pModulus.get( );

                            } else {

                                pPublicKeyModulus = ( ( RSAPrivateKeyObject* ) oldObjectOnCard.get( ) )->m_pModulus.get( );
                            }

                            if( pPublicKeyModulus ) {

                                Log::logCK_UTF8CHAR_PTR( "Token::checkSmartCardContent - File Public key modulus", pPublicKeyModulus->GetBuffer( ), pPublicKeyModulus->GetLength( ) );

                                // Search for a container using the same public key container
                                ucKeyContainerIndexReal = MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID;
                                ucKeySpec = 0xFF;
                                stFileName = "";
                                m_Device->containerGetMatching( ucKeyContainerIndexReal, ucKeySpec, stFileName, pPublicKeyModulus );
                                Log::log( "Token::checkSmartCardContent - Real container index found comparing the public key modulus of each container with the P11 object one <%d>", ucKeyContainerIndexReal );

                                // Compare the container index defined in the PKCS11 object with the container index using that public key modulus
                                if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == ucKeyContainerIndexReal ) {

                                    // No container exists into the smart card matching with the public key set into the P11 object
                                    // This object should be deleted
                                    Log::log( "Token::checkSmartCardContent - No inner container index for <%s>", stObjectPKCS11.c_str( ) );

                                } else if( ucKeyContainerIndexInFileName != ucKeyContainerIndexReal ) {

                                    // The both index are different !

                                    CK_OBJECT_HANDLE h = CK_UNAVAILABLE_INFORMATION;
                                    if( stPrefix.compare( stPublicKey ) == 0 ) { 

                                        Pkcs11ObjectKeyPublicRSA* pNewKey = new Pkcs11ObjectKeyPublicRSA( ( const Pkcs11ObjectKeyPublicRSA* ) oldObjectOnCard.get( ) );

                                        // Set the good container index into the PKCS11 object
                                        pNewKey->m_ucContainerIndex = ucKeyContainerIndexReal;

                                        // Set the good file name in to the PKCS11 object
                                        pNewKey->m_stFileName = stPrefix;
                                        Util::toStringHex( ucKeyContainerIndexReal, pNewKey->m_stFileName );

                                        // Create the new root certificate
                                        addObject( pNewKey, &h );

                                        //m_bSynchronizeObjectsPublic = true;

                                        Log::log( "Token::checkSmartCardContent - add new P11 public key <%s>", pNewKey->m_stFileName.c_str( ) );

                                    } else {

                                        RSAPrivateKeyObject* pNewKey = new RSAPrivateKeyObject( ( const RSAPrivateKeyObject* ) oldObjectOnCard.get( ) );

                                        // Set the good container index into the PKCS11 object
                                        pNewKey->m_ucContainerIndex = ucKeyContainerIndexReal;

                                        // Set the good file name in to the PKCS11 object
                                        pNewKey->m_stFileName = stPrefix;
                                        Util::toStringHex( ucKeyContainerIndexReal, pNewKey->m_stFileName );

                                        // Create the new root certificate
                                        addObject( pNewKey, &h ); 

                                        //m_bSynchronizeObjectsPrivate = true;

                                        Log::log( "Token::checkSmartCardContent - add new P11 private key <%s>", pNewKey->m_stFileName.c_str( ) );
                                    }

                                    // Delete the old PKCS#11 object & MiniDriver file/container from card
                                    m_Device->deleteFile( g_stPathPKCS11, oldObjectOnCard->m_stFileName );
                                    Log::log( "Token::checkSmartCardContent - delete old P11 key <%s>", oldObjectOnCard->m_stFileName.c_str( ) );

                                    // Delete the old PKCS#11 object from inner list of managed objects
                                    TOKEN_OBJECTS::iterator i = m_Objects.begin( );
                                    while( i != m_Objects.end( ) ) {

                                        if( 0 == i->second->m_stFileName.compare( oldObjectOnCard->m_stFileName ) ) {

                                            m_Objects.erase( i );

                                            break;
                                        }

                                        ++i;
                                    }	
                                }

                            } else {

                                // The public key modulus is missing. The public/private key is not well formated
                                Log::log( "Token::checkSmartCardContent - No modulus for <%s>", stObjectPKCS11.c_str( ) );
                            }
                        }

                        if( stPrefix.compare( stPrivateKey ) == 0 ) {

                            stPrefix = stPublicKey;

                        } else if( stPrefix.compare( stPublicKey ) == 0 ) {

                            stPrefix ="";
                            break;
                        }

                    } while( 0 != stPrefix.compare( "" ) );
                }
            }
        }
    } catch( MiniDriverException& ) {

        Log::error( "Token::checkSmartCardContent", "MiniDriverException" );
    }

    Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj after P11 clean");
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& o, m_Objects ) {

        printObject( o.second );
    }
    Log::log(" Token::checkSmartCardContent -$$$$$$$$$$$$$ Obj after P11 clean");

    t.stop( "Token::checkSmartCardContent" );
    Log::end( "Token::checkSmartCardContent" );

    m_bCheckSmartCardContentDone = true;

    return bReturn;
}


/*
*/
void Token::synchronizePublicCertificateAndKeyObjects( void ) {

    Log::begin( "Token::synchronizePublicCertificateAndKeyObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11;

        if( !m_bCreateDirectoryP11 ) {

            try {

                filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

            } catch( ... ) {

            }
        }

        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stContainerIndex = "";
        unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
        unsigned int uiKeySize = 0;
        std::string stPrefix = "";
        std::string stCertificateFileName = "";
        std::string stObjectPKCS11 = "";

        // Explore each smart card key container
        unsigned char ucContainerCount = m_Device->containerCount( );

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );

            // Get the current container
            MiniDriverContainer c = m_Device->containerGet( ucContainerIndex );

            // Only deal with valid containers
            if( MiniDriverContainer::CMAPFILE_FLAG_EMPTY != c.getFlags( ) ) {

                // Get the key information
                ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

                uiKeySize = c.getKeyExchangeSizeBits( );

                boost::shared_ptr< Marshaller::u1Array > pPublicKeyExponent = c.getExchangePublicKeyExponent( );

                boost::shared_ptr< Marshaller::u1Array > pPublicKeyModulus = c.getExchangePublicKeyModulus( );

                stPrefix = szUSER_KEYEXCHANGE_CERT_PREFIX; 

                if( !uiKeySize ) {

                    ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

                    uiKeySize = c.getKeySignatureSizeBits( );

                    pPublicKeyExponent = c.getSignaturePublicKeyExponent( );

                    pPublicKeyModulus = c.getSignaturePublicKeyModulus( );

                    stPrefix = szUSER_SIGNATURE_CERT_PREFIX;
                }

                Log::log( "Token::synchronizePublicCertificateAndKeyObjects - <%d> valid container", ucContainerIndex );

                // Build the certificate file name associated to this container
                stCertificateFileName = stPrefix + stContainerIndex;

                // Locate the associated certificate into the MiniDriver file structure
                bool bExistsMSCPFile = isFileExists( stCertificateFileName, filesMiniDriver );

                //??? TO ??? si le fichier n'existe pas il faut supprimer le container

                Log::log( "Token::synchronizePublicCertificateAndKeyObjects - check for <%s> - Exists in MSCP <%d>", stCertificateFileName.c_str( ), bExistsMSCPFile );

                // A public PKCS11 certificate object must exist on cache and on card to represent this MiniDriver certificate
                stObjectPKCS11 = g_stPrefixPublicObject + stCertificateFileName;

                // Does this certificate also exist as a PKCS11 object ?
                bool bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );

                Log::log( "Token::synchronizePublicCertificateAndKeyObjects - check for <%s> - Exists in P11 <%d>", stObjectPKCS11.c_str( ), bExistsPKCS11Object );

                if( bExistsMSCPFile ) { 

                    // The associated certificate exists into the mscp directory

                    if( bExistsPKCS11Object ) { 

                        // The PCKS11 certificate object exists

                        // Load the PKCS11 object from the already existing PKCS11 file
                        try {

                            createCertificateFromPKCS11ObjectFile( stObjectPKCS11, stCertificateFileName );

                        } catch( ... ) {

                            Log::log( "**************************************************** CASE #1 [P11 cert exists but not possible read] - <%s> <%s>", stObjectPKCS11.c_str( ), stCertificateFileName.c_str( ) );

                            // Create the PKCS11 object from the MSCP file
                            createCertificateFromMiniDriverFile( stCertificateFileName, ucContainerIndex, ucKeySpec ); 

                            //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                        }

                    } else { 

                        // The PKCS11 file does not exist

                        // Create the PKCS11 object from the MSCP file
                        createCertificateFromMiniDriverFile( stCertificateFileName, ucContainerIndex, ucKeySpec );
                    }

                } else { 

                    // The associated certificate does not exist into the mscp directory

                    // If a old corresponding PKCS11 object exists then delete it
                    if( bExistsPKCS11Object ) {

                        Log::log( "**************************************************** CASE #2 [P11 cert exists but no associated KXC] - <%s> <%s>", stObjectPKCS11.c_str( ), stCertificateFileName.c_str( ) );

                        // NO DELETE
                        //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                    }
                }

                // Locate the associated PUBLIC key
                // Build the public key file name associated to this container
                stObjectPKCS11 = g_stPrefixPublicObject + g_stPrefixKeyPublic + stContainerIndex;

                // Does this public key also exist as a PKCS11 object ?
                bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );

                if( bExistsPKCS11Object ) { 

                    // The PCKS11 public key object exists
                    // Create the PKCS11 object from the already existing PKCS11 file
                    try {

                        createPublicKeyFromPKCS11ObjectFile( stObjectPKCS11 );

                    } catch( ... ) {

                        Log::log( "**************************************************** CASE #3 [P11 pub key exists but no read possible] - <%s>", stObjectPKCS11.c_str( ) );

                        createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );

                        //stObjectPKCS11 = g_stPrefixPublicObject + std::string( szUSER_SIGNATURE_CERT_PREFIX ) + stContainerIndex;
                        //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                    }

                } else { 

                    // The PKCS11 public key object does not exist
                    // Create the PKCS11 object from the MSCP key container
                    createPublicKeyFromMiniDriverFile( stObjectPKCS11, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );
                }

            } else { 

                // The container is empty
                // Search for an old corresponding PKCS11 object to delete it
                Log::log( "Token::synchronizePublicCertificateAndKeyObjects - <%d> empty container", ucContainerIndex );

                //// Build the certificate file name associated to this container
                //stObjectPKCS11 = g_stPrefixPublicObject + std::string( szUSER_SIGNATURE_CERT_PREFIX ) + stContainerIndex;
                //bool bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );
                //if( bExistsPKCS11Object ) {

                //    // NO DELETE
                //    //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                //    Log::log( "**************************************************** CASE #4.1 [P11 obj exists] - <%s>", stObjectPKCS11.c_str( ) );
                //}

                //stObjectPKCS11 = g_stPrefixPublicObject + std::string( szUSER_KEYEXCHANGE_CERT_PREFIX ) + stContainerIndex;
                //bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );
                //if( bExistsPKCS11Object ) {

                //    // NO DELETE
                //    //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                //    Log::log( "**************************************************** CASE #4.2 [P11 obj exists] - <%s>", stObjectPKCS11.c_str( ) );
                //}

                //stObjectPKCS11 = g_stPrefixPublicObject + g_stPrefixKeyPublic + stContainerIndex;
                //bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );
                //if( bExistsPKCS11Object ) {

                //    // NO DELETE
                //    //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                //    Log::log( "**************************************************** CASE #4.3 [P11 obj exists] - <%s>", stObjectPKCS11.c_str( ) );
                //}

                //stObjectPKCS11 = g_stPrefixPrivateObject + g_stPrefixKeyPrivate + stContainerIndex;
                //bExistsPKCS11Object = isFileExists( stObjectPKCS11, filesPKCS11 );
                //if( bExistsPKCS11Object ) {

                //    // NO DELETE
                //    //m_ObjectsToDelete.push_back( stObjectPKCS11 );
                //    Log::log( "**************************************************** CASE #4.4 [P11 obj exists] - <%s>", stObjectPKCS11.c_str( ) );
                //}
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePublicCertificateAndKeyObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePublicCertificateAndKeyObjects" );
    Log::end( "Token::synchronizePublicCertificateAndKeyObjects" );
}


/*
*/
void Token::synchronizePrivateKeyObjects( void ) {

    Log::begin( "Token::synchronizePrivateKeyObjects" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        return;
    }

    try {

        // Get all PKCS11 object files from the PKCS11 directory into the smart card
        MiniDriverFiles::FILES_NAME filesPKCS11;

        if( !m_bCreateDirectoryP11 ) {

            try {

                filesPKCS11 = m_Device->enumFiles( g_stPathPKCS11 );

            } catch( ... ) {

            }
        }

        // Get all certificate files from the smart card
        MiniDriverFiles::FILES_NAME filesMiniDriver = m_Device->enumFiles( std::string( szBASE_CSP_DIR ) );

        std::string stContainerIndex = "";
        unsigned char ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;
        unsigned int uiKeySize = 0;
        std::string stPrefix = "";
        std::string stCertificateFileName = "";
        std::string stKeyFileName = "";
        bool bExistsPKCS11Object = false;

        // Explore each smart card key container
        unsigned char ucContainerCount = m_Device->containerCount( );

        for( unsigned char ucContainerIndex = 0 ; ucContainerIndex < ucContainerCount ; ++ucContainerIndex ) {

            // Get the current container
            MiniDriverContainer c = m_Device->containerGet( ucContainerIndex );

            // Build the certificate file name associated to this container
            stContainerIndex = "";
            Util::toStringHex( ucContainerIndex, stContainerIndex );

            // Locate the associated PRIVATE key
            // Build the private key file name associated to this container
            stKeyFileName = g_stPrefixPrivateObject + g_stPrefixKeyPrivate + stContainerIndex;

            // Does this private key also exist as a PKCS11 object ?
            bExistsPKCS11Object = isFileExists( stKeyFileName, filesPKCS11 );

            // Only deal with valid containers
            if( MiniDriverContainer::CMAPFILE_FLAG_EMPTY != c.getFlags( ) ) {

                // Get the key information
                ucKeySpec = MiniDriverContainer::KEYSPEC_EXCHANGE;

                uiKeySize = c.getKeyExchangeSizeBits( );

                boost::shared_ptr< Marshaller::u1Array > pPublicKeyExponent = c.getExchangePublicKeyExponent( );

                boost::shared_ptr< Marshaller::u1Array > pPublicKeyModulus = c.getExchangePublicKeyModulus( );

                stPrefix = std::string( szUSER_KEYEXCHANGE_CERT_PREFIX ); 

                if( !uiKeySize ) {

                    ucKeySpec = MiniDriverContainer::KEYSPEC_SIGNATURE;

                    uiKeySize = c.getKeySignatureSizeBits( );

                    pPublicKeyExponent = c.getSignaturePublicKeyExponent( );

                    pPublicKeyModulus = c.getSignaturePublicKeyModulus( );

                    stPrefix = std::string( szUSER_SIGNATURE_CERT_PREFIX );
                } 

                if( bExistsPKCS11Object ) { 

                    // The PCKS11 key object exists
                    // Create the PKCS11 object from the already existing PKCS11 file
                    try {

                        createPrivateKeyFromPKCS11ObjectFile( stKeyFileName );

                    } catch( ... ) {

                        // Create the PKCS11 object from the MSCP key container
                        createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );
                    }

                } else { 

                    // The PKCS11 private key object does not exist
                    // Create the PKCS11 object from the MSCP key container
                    createPrivateKeyFromMiniDriverFile( stKeyFileName, ucContainerIndex, ucKeySpec, pPublicKeyExponent.get( ), pPublicKeyModulus.get( ) );
                }

            } else { 

                // The container is empty
            }
        }

    } catch( MiniDriverException& x ) {

        Log::error( "Token::synchronizePrivateKeyObjects", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::synchronizePrivateKeyObjects" );
    Log::end( "Token::synchronizePrivateKeyObjects" );
}


/* Create the PKCS11 certifcate object associated to the MiniDriver certificate file
*/
void Token::createCertificateFromPKCS11ObjectFile( const std::string& a_CertificateFileP11, const std::string& a_CertificateFileMiniDriver ) {

    Log::begin( "Token::createCertificateFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, a_CertificateFileP11 );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        // Create the PKCS11 object
        X509PubKeyCertObject* o = new X509PubKeyCertObject( );

        // Put the file content into the object
        CK_ULONG idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object 
        o->m_stFileName = a_CertificateFileP11;

        o->m_stCertificateName = a_CertificateFileMiniDriver;

        // Read the file
        m_Device->readCertificate( a_CertificateFileMiniDriver, o->m_pValue );

        if( o->m_pValue ) {

            generateRootAndSmartCardLogonFlags( o->m_pValue, o->m_bIsRoot, o->_certCategory, o->m_bIsSmartCardLogon );

            generatePublicKeyModulus( o->m_pValue, o->m_pModulus, o->_checkValue );
        }

        if( o->m_pModulus && ( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) ) {

            searchContainerIndex( o->m_pModulus, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        // As the PKCS11 file exists on card, the PKCS11 object has just to be added to the list of the PKCS11 managed object list.
        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createCertificateFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createCertificateFromPKCS11ObjectFile" );
    Log::end( "Token::createCertificateFromPKCS11ObjectFile" );
}


/* Create the PKCS11 certifcate object associated to the MiniDriver certificate file
*/
void Token::createCertificateFromMiniDriverFile( const std::string& a_CertificateFile, const unsigned char& a_ucIndex, const unsigned char& a_ucKeySpec ) {

    Log::begin( "Token::createCertificateFromMiniDriverFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Create the PKCS11 object
    X509PubKeyCertObject* o = new X509PubKeyCertObject( );

    o->m_ucKeySpec = a_ucKeySpec;

    o->m_ucContainerIndex = a_ucIndex;

    o->m_bOffCardObject = true;

    o->m_Token = CK_TRUE;

    o->m_Private = CK_FALSE;

    o->m_Modifiable = CK_TRUE;

    // No PKCS#11 certificate name for an offcard object. There is only a MiniDriver certificate into the smart card
    o->m_stFileName = ""; 

    o->m_stCertificateName = a_CertificateFile;

    try {

        // Read the file
        m_Device->readCertificate( a_CertificateFile, o->m_pValue );

    } catch( MiniDriverException& x ) {

        // Unable to read the on card certificate.
        // The P11 object creation is skipped.
        Log::error( "Token::createCertificateFromMiniDriverFile", "Unable to read the certificate" );

        delete o;

        throw PKCS11Exception( checkException( x ) );
    }

    // Get object attributes from the parsed certificate
    generateDefaultAttributesCertificate( o );

    // Register this PKCS11 object into the list of the PKCS11 managed objects
    registerStorageObject( o );

    t.stop( "Token::createCertificateFromMiniDriverFile" );
    Log::end( "Token::createCertificateFromMiniDriverFile" );
}


/* Create the PKCS11 public key object associated to the PKCS11 public key file stored into the smart card
*/
void Token::createPublicKeyFromPKCS11ObjectFile( const std::string& a_PKCS11PublicKeyFile ) {

    Log::begin( "Token::createPublicKeyFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, a_PKCS11PublicKeyFile );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        // Create the PKCS11 object
        Pkcs11ObjectKeyPublicRSA* o = new Pkcs11ObjectKeyPublicRSA( );

        // Put the file content into the object
        CK_ULONG idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object 
        o->m_stFileName = a_PKCS11PublicKeyFile;

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) {

            searchContainerIndex( o->m_pModulus, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createPublicKeyFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createPublicKeyFromPKCS11ObjectFile" );
    Log::end( "Token::createPublicKeyFromPKCS11ObjectFile" );
}


/* Create the PKCS11 public key object associated to the MiniDriver container
*/
void Token::createPublicKeyFromMiniDriverFile( const std::string& a_stKeyFileName, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, Marshaller::u1Array* a_pPublicKeyExponent, Marshaller::u1Array* a_pPublicKeyModulus ) {

    Log::begin( "Token::createPublicKeyFromMiniDriverFile" );
    Timer t;
    t.start( );

    // Create the PKCS11 object
    Pkcs11ObjectKeyPublicRSA* o = new Pkcs11ObjectKeyPublicRSA( );

    o->m_stFileName = ""; // No PKCS#11 key file into the smart card. This object is build for a off card usage using the information given by the container //a_stKeyFileName;

    o->m_Token = CK_TRUE;

    o->m_Private = CK_FALSE;

    o->m_Modifiable = CK_TRUE;

    o->m_ucContainerIndex = a_ucIndex;

    o->m_ucKeySpec = (unsigned char)a_ucKeySpec;

    o->m_bOffCardObject = true;

    o->_wrap = CK_FALSE;

    o->_trusted = CK_TRUE;

    o->_derive = CK_FALSE;

    o->_local = CK_FALSE;

    o->_verifyRecover = CK_FALSE;

    if( MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec ) {

        o->_verify = CK_TRUE;

        o->_encrypt = CK_TRUE;

        if( m_Device ) {

            if( !m_Device->containerIsImportedExchangeKey( a_ucIndex ) ) {

                o->_local = CK_TRUE;
            }
        }

    } else {

        o->_verify = CK_TRUE;

        o->_encrypt = CK_FALSE;

        if( m_Device ) {

            if( !m_Device->containerIsImportedSignatureKey( a_ucIndex ) ) {

                o->_local = CK_TRUE;
            }
        }    
    }

    o->m_pPublicExponent.reset( new Marshaller::u1Array( a_pPublicKeyExponent->GetLength( ) ) );

    o->m_pPublicExponent->SetBuffer( a_pPublicKeyExponent->GetBuffer( ) );

    o->m_pModulus.reset( new Marshaller::u1Array( a_pPublicKeyModulus->GetLength( ) ) );

    o->m_pModulus->SetBuffer( a_pPublicKeyModulus->GetBuffer( ) );

    o->m_ulModulusBits = a_pPublicKeyModulus->GetLength( ) * 8;

    generateDefaultAttributesKeyPublic( o );

    registerStorageObject( o );

    t.stop( "Token::createPublicKeyFromMiniDriverFile" );
    Log::end( "Token::createPublicKeyFromMiniDriverFile" );
}


/* Create the PKCS11 public key object associated to the PKCS11 public key file stored into the smart card
*/
void Token::createPrivateKeyFromPKCS11ObjectFile( const std::string& a_PKCS11PrivateKeyFile ) {

    Log::begin( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Timer t;
    t.start( );

    if( !m_Device ) {

        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    try {

        // Read the file
        Marshaller::u1Array* f = m_Device->readFile( g_stPathPKCS11, a_PKCS11PrivateKeyFile );

        // Construct the PKCS11 object attributes from the file
        std::vector< unsigned char > attributes;

        unsigned int l = f->GetLength( );

        for( unsigned int u = 0 ; u < l ; ++u ) {

            attributes.push_back( f->GetBuffer( )[ u ] );
        }

        // Create the PKCS11 object
        RSAPrivateKeyObject* o = new RSAPrivateKeyObject( );

        // Put the file content into the object
        CK_ULONG idx = 0;
        o->deserialize( attributes, &idx );

        // Save the fileName in the object 
        o->m_stFileName = a_PKCS11PrivateKeyFile;

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == o->m_ucContainerIndex ) {

            searchContainerIndex( o->m_pModulus, o->m_ucContainerIndex, o->m_ucKeySpec );
        }

        // Compatibility with old P11
        o->_checkValue = Util::MakeCheckValue( o->m_pModulus->GetBuffer( ), o->m_pModulus->GetLength( ) );

        setContainerIndexToCertificate( o->m_pModulus, o->m_ucContainerIndex, o->m_ucKeySpec );

        setContainerIndexToKeyPublic( o->m_pModulus, o->m_ucContainerIndex, o->m_ucKeySpec );

        registerStorageObject( o );

    } catch( MiniDriverException& x ) {

        Log::error( "Token::createPrivateKeyFromPKCS11ObjectFile", "MiniDriverException" );
        throw PKCS11Exception( checkException( x ) );
    }

    t.stop( "Token::createPrivateKeyFromPKCS11ObjectFile" );
    Log::end( "Token::createPrivateKeyFromPKCS11ObjectFile" );
}


/* Create the PKCS11 public key object associated to the MiniDriver container
*/
void Token::createPrivateKeyFromMiniDriverFile( const std::string& a_stKeyFileName, const unsigned char& a_ucIndex, const unsigned int& a_ucKeySpec, Marshaller::u1Array* a_pPublicKeyExponent, Marshaller::u1Array* a_pPublicKeyModulus ) {

    Log::begin( "Token::createPrivateKeyFromMiniDriverFile" );
    Timer t;
    t.start( );

    // Create the PKCS11 object
    RSAPrivateKeyObject* o = new RSAPrivateKeyObject( );

    o->m_stFileName = ""; // No PKCS#11 key file into the smart card. This object is build for a off card usage using the information given by the container

    o->m_Token = CK_TRUE;

    o->m_Private = CK_TRUE;

    o->m_Modifiable = CK_TRUE;

    o->m_bOffCardObject = true;

    o->m_ucKeySpec = (unsigned char)a_ucKeySpec;

    o->_sensitive = CK_TRUE;

    o->_signRecover = false;

    o->_unwrap = CK_FALSE;

    o->_extractable = false;

    o->_alwaysSensitive = CK_TRUE;

    o->_neverExtractable = CK_TRUE;

    o->_wrapWithTrusted = false;

    o->_alwaysAuthenticate = false;

    o->_derive = false;

    o->_local = CK_FALSE;

    if( MiniDriverContainer::KEYSPEC_EXCHANGE == a_ucKeySpec ) {

        o->_decrypt = true;

        o->_sign = true;

    } else {

        o->_decrypt = false;

        o->_sign = true;
    }

    o->m_ucContainerIndex = a_ucIndex;

    o->m_pPublicExponent.reset( new Marshaller::u1Array( a_pPublicKeyExponent->GetLength( ) ) );
    o->m_pPublicExponent->SetBuffer( a_pPublicKeyExponent->GetBuffer( ) );

    o->m_pModulus.reset( new Marshaller::u1Array( a_pPublicKeyModulus->GetLength( ) ) );
    o->m_pModulus->SetBuffer( a_pPublicKeyModulus->GetBuffer( ) );

    //setDefaultAttributes( o, true );
    generateDefaultAttributesKeyPrivate( o );

    // Add the object into the cache
    registerStorageObject( o );

    t.stop( "Token::createPrivateKeyFromMiniDriverFile" );
    Log::end( "Token::createPrivateKeyFromMiniDriverFile" );
}


/*
*/
CK_RV Token::checkException( MiniDriverException& x ) {

    CK_RV rv = CKR_GENERAL_ERROR;

    switch( x.getError( ) ) {

    case SCARD_E_INVALID_PARAMETER:
        rv = CKR_ARGUMENTS_BAD;
        break;

    case SCARD_E_UNEXPECTED:
    case SCARD_F_INTERNAL_ERROR:
        rv = CKR_FUNCTION_FAILED;
        break;
#ifdef WIN32
    case SCARD_E_UNSUPPORTED_FEATURE:
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        break;
#endif
    case SCARD_W_CARD_NOT_AUTHENTICATED:
        rv = CKR_USER_NOT_LOGGED_IN;
        break;

    case SCARD_W_CHV_BLOCKED:
        rv = CKR_PIN_LOCKED;
        break;

    case SCARD_W_WRONG_CHV:
        rv = CKR_PIN_INCORRECT;
        break;

    case SCARD_E_INVALID_CHV:
        rv = CKR_PIN_INVALID;
        break;

    case SCARD_E_NO_SMARTCARD:
        rv = CKR_DEVICE_REMOVED;
        break;

    case SCARD_E_TIMEOUT:
    case SCARD_W_CANCELLED_BY_USER:
    case SCARD_E_CANCELLED:
        rv = CKR_FUNCTION_CANCELED;
        break;

    case SCARD_E_NO_MEMORY:
    case SCARD_E_DIR_NOT_FOUND:
    case SCARD_E_FILE_NOT_FOUND:
    case SCARD_E_CERTIFICATE_UNAVAILABLE:
    case SCARD_E_NO_ACCESS:
        rv = CKR_DEVICE_MEMORY;
        break;

    default:
        rv = CKR_GENERAL_ERROR;
        break;
    }

    return rv;
}


/*
*/
Marshaller::u1Array* Token::computeSHA1( const unsigned char* a_pData, const size_t& a_uiLength ) {

    CSHA1 sha1;

    Marshaller::u1Array* pHash = new Marshaller::u1Array( SHA1_HASH_LENGTH );

    sha1.hashCore( (unsigned char*)a_pData, 0, a_uiLength );

    sha1.hashFinal( pHash->GetBuffer( ) );

    return pHash;
}


/*
*/
unsigned char Token::computeIndex( const std::string& a_stFileName ) {

    if( a_stFileName.length( ) < 2 ) {
     
        return 0xFF;
    }

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
void Token::generateDefaultAttributesCertificate( X509PubKeyCertObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesCertificate" );
    Timer t;
    t.start( );

    if( !a_pObject && !a_pObject->m_pValue ) {

        return;
    }

    // Parse the certifcate value to extract the PKCS11 attribute values not already set
    try {

        // Generate the root and smart card logon flags
        generateRootAndSmartCardLogonFlags( a_pObject->m_pValue, a_pObject->m_bIsRoot, a_pObject->_certCategory, a_pObject->m_bIsSmartCardLogon );

        // Generate the serial number
        generateSerialNumber( a_pObject->m_pValue, a_pObject->m_pSerialNumber );

        // Generate the issuer
        generateIssuer( a_pObject->m_pValue, a_pObject->m_pIssuer );

        // Get the certificate public key modulus
        generatePublicKeyModulus( a_pObject->m_pValue, a_pObject->m_pModulus, a_pObject->_checkValue );

        // Generate the certicate label
        generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );

        // Generate the ID
        generateID( a_pObject->m_pModulus, a_pObject->m_pID );

        // Generate the subject
        generateSubject( a_pObject->m_pValue, a_pObject->m_pSubject );
    
    } catch( ... ) {

        // If a parsing error occurs then these attributes can't be set.
    }
}


/*
*/
void Token::generateDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublicRSA* a_pObject ) {

    Log::begin( "Token::generateDefaultAttributesKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pObject && !a_pObject->m_pModulus ) {

        return;
    }

    int l = a_pObject->m_pModulus->GetLength( );

    unsigned char* p = a_pObject->m_pModulus->GetBuffer( );

    // Search for a private key using the same public key exponent to set the same container index
    if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

            if( CKO_PRIVATE_KEY == obj->second->getClass( ) ) {

                RSAPrivateKeyObject* objPrivateKey = (RSAPrivateKeyObject*) obj->second;

                if( 0 == memcmp( objPrivateKey->m_pModulus->GetBuffer( ), p, l ) ) {

                    // Set the same CKA_ID
                    if( objPrivateKey->m_pID.get( ) ) {

                        a_pObject->m_pID.reset( new Marshaller::u1Array( *( objPrivateKey->m_pID.get( ) ) ) );
                    }

                    // Set the same CKA_LABEL
                    if( objPrivateKey->m_pLabel.get( ) ) {

                        a_pObject->m_pLabel.reset( new Marshaller::u1Array( *( objPrivateKey->m_pLabel.get( ) ) ) );
                    }

                    // Set the same CKA_SUBJECT
                    if( objPrivateKey->m_pSubject.get( ) ) {

                        a_pObject->m_pSubject.reset( new Marshaller::u1Array( *( objPrivateKey->m_pSubject.get( ) ) ) );
                    }

                    a_pObject->m_ucContainerIndex = objPrivateKey->m_ucContainerIndex;

                    a_pObject->m_ucKeySpec = objPrivateKey->m_ucKeySpec;

                    break;
                }
            }
        }
    }

    // If no private key has been found then generate the attributes

    // Get the certificate subject if it is still empty
    if( !a_pObject->m_pSubject.get( ) ) {

        BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

            if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

                X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

                if( !objCertificate && !objCertificate->m_pValue ) {

                    continue;
                }

                X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

                // Get the certificate public key modulus
                BEROctet::Blob modulus = x509cert.Modulus( );

                Marshaller::u1Array m( modulus.size( ) );

                m.SetBuffer( modulus.data( ) );

                // Check if the both certificate and public key share the same modulus
                if( 0 == memcmp( m.GetBuffer( ), p, l ) ) {

                    if( objCertificate->m_pSubject.get( ) ) {

                        // Copyt the certificate subject
                        a_pObject->m_pSubject.reset( new Marshaller::u1Array( *( objCertificate->m_pSubject.get( ) ) ) );

                    } else {

                        // Generate the subject
                        BEROctet::Blob sb( x509cert.Subject( ) );

                        a_pObject->m_pSubject.reset( new Marshaller::u1Array( static_cast< s4 >( sb.size( ) ) ) );

                        a_pObject->m_pSubject->SetBuffer( const_cast< unsigned char* >( sb.data( ) ) );
                    }

                    // By the way copy the certificate ID
                    if( objCertificate->m_pID.get( ) && !a_pObject->m_pID.get( ) ) {

                        a_pObject->m_pID.reset( new Marshaller::u1Array( *( objCertificate->m_pID.get( ) ) ) );
                    }

                    if( objCertificate->m_pLabel.get( ) && !a_pObject->m_pLabel.get( ) ) {

                        a_pObject->m_pLabel.reset( new Marshaller::u1Array( *( objCertificate->m_pLabel.get( ) ) ) );
                    }

                    break;
                }
            }
        }
    }

    // Generate the id 
    if( !a_pObject->m_pID.get( ) ) {

        generateID( a_pObject->m_pModulus, a_pObject->m_pID );
    }

    // Generate the label from the public key modulus
    if( !a_pObject->m_pLabel.get( ) ) {

        generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );
    }

    t.stop( "Token::generateDefaultAttributesKeyPublic" );
    Log::end( "Token::generateDefaultAttributesKeyPublic" );
}


/*
*/
void Token::generateDefaultAttributesKeyPrivate( RSAPrivateKeyObject* a_pObject ) {

    Log::begin( "Token::generateDefaultAttributesKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pObject && !a_pObject->m_pModulus ) {

        return;
    }

    unsigned int l = a_pObject->m_pModulus->GetLength( );

    unsigned char* p = a_pObject->m_pModulus->GetBuffer( );

    // Compatibility with old P11
    a_pObject->_checkValue = Util::MakeCheckValue( p, l );

    // Generate a default id from the public key modulus if not found in previous certificate or public key search
    generateID( a_pObject->m_pModulus, a_pObject->m_pID );

    // Generate a default label from the public key modulus if not found in previous certificate or public key search
    generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );

    // Give the same container index of the private key to the associated certificate
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

            X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

            if( objCertificate->m_pValue.get( ) ) {

                X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

                // Get the certificate public key modulus
                BEROctet::Blob modulus = x509cert.Modulus( );

                Marshaller::u1Array m( modulus.size( ) );

                m.SetBuffer( modulus.data( ) );

                if( 0 == memcmp( m.GetBuffer( ), p, l ) ) {

                    // Give the same container index of the private key to the certificate
                    objCertificate->m_ucContainerIndex = a_pObject->m_ucContainerIndex;

                    objCertificate->m_ucKeySpec = a_pObject->m_ucKeySpec;

                    if( objCertificate->m_pSubject.get( ) ) {

                        a_pObject->m_pSubject.reset( new Marshaller::u1Array( objCertificate->m_pSubject->GetLength( ) ) );

                        a_pObject->m_pSubject->SetBuffer( objCertificate->m_pSubject->GetBuffer( ) );

                    } else {

                        // Get the certificate subject
                        BEROctet::Blob sb( x509cert.Subject( ) );

                        a_pObject->m_pSubject.reset( new Marshaller::u1Array( static_cast< s4 >( sb.size( ) ) ) );

                        a_pObject->m_pSubject->SetBuffer( const_cast< unsigned char* >( sb.data( ) ) );
                    }

                    break;
                }
            }
        }
    }

    //// Give the same container index of the private key to the associated public key
    //BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

    //    if( CKO_PUBLIC_KEY == obj->second->getClass( ) ) {

    //        Pkcs11ObjectKeyPublicRSA* objPublicKey = (Pkcs11ObjectKeyPublicRSA*) obj->second;

    //        if( 0 == memcmp( objPublicKey->m_pModulus->GetBuffer( ), p, l ) ) {

    //            // Give the same container index of the private key to the certificate
    //            objPublicKey->m_ucContainerIndex = o->m_ucContainerIndex;

    //            objPublicKey->m_ucKeySpec = o->m_ucKeySpec;

    //            // By the way, if the previous search for a certificate failed
    //            // try to get the same CKA_ID, CKA_LABEL and CKA_SUBJECT as the associated public key
    //            //if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pSubject.get( ) && !o->m_pSubject.get( ) ) {

    //            //    o->m_pSubject.reset( new Marshaller::u1Array( objPublicKey->m_pSubject->GetLength( ) ) );

    //            //    o->m_pSubject->SetBuffer( objPublicKey->m_pSubject->GetBuffer( ) );
    //            //}

    //            if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pID.get( ) && !o->m_pID.get( ) ) {

    //                o->m_pID.reset( new Marshaller::u1Array( objPublicKey->m_pID->GetLength( ) ) );

    //                o->m_pID->SetBuffer( objPublicKey->m_pID->GetBuffer( ) );
    //            }

    //            if( /*o->m_bOffCardObject &&*/ objPublicKey->m_pLabel.get( ) && !o->m_pLabel.get( ) ) {

    //                o->m_pLabel.reset( new Marshaller::u1Array( objPublicKey->m_pLabel->GetLength( ) ) );

    //                o->m_pLabel->SetBuffer( objPublicKey->m_pLabel->GetBuffer( ) );
    //            }

    //            break;
    //        }
    //    }
    //}

    t.stop( "Token::generateDefaultAttributesKeyPublic" );
    Log::end( "Token::generateDefaultAttributesKeyPublic" );
}


/* Generate a default label from the public key modulus
*/
void Token::generateLabel( boost::shared_ptr< Marshaller::u1Array>& a_pModulus, boost::shared_ptr< Marshaller::u1Array>& a_pLabel ) {

    if( !a_pModulus ) {

        return;
    }

    std::string stLabel = CAttributedCertificate::DerivedUniqueName( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) );

    a_pLabel.reset( new Marshaller::u1Array( stLabel.size( ) ) );

    a_pLabel->SetBuffer( reinterpret_cast< const unsigned char* >( stLabel.c_str( ) ) );

    // Generate the certificate label from the certificate value
    //std::string stLabel;
    //std::vector<std::string> vs = x509cert.UTF8SubjectCommonName( );
    //BOOST_FOREACH( const std::string& s, vs ) {
    //    if( !stLabel.empty( ) ) {
    //        stLabel += " ";
    //    }
    //    stLabel += s;
    //}
    //a_pObject->m_pLabel.reset( new Marshaller::u1Array( stLabel.size( ) ) );
    //a_pObject->m_pLabel->SetBuffer( reinterpret_cast< const unsigned char* >( stLabel.c_str( ) ) );
}


/* Generate a default id from the public key modulus
*/
void Token::generateID( boost::shared_ptr< Marshaller::u1Array>& a_pModulus, boost::shared_ptr< Marshaller::u1Array>& a_pID ) {

    if( !a_pModulus ) {

        return;
    }

    a_pID.reset( computeSHA1( a_pModulus->GetBuffer( ), a_pModulus->GetLength( ) ) );
}


/* Get the certificate serial number
*/
void Token::generateSerialNumber( boost::shared_ptr< Marshaller::u1Array>& a_pCertificateValue, boost::shared_ptr< Marshaller::u1Array>& a_pSerialNumber ) {

    X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

    BEROctet::Blob b( x509cert.SerialNumber( ) );

    a_pSerialNumber.reset( new Marshaller::u1Array( static_cast< s4 >( b.size( ) ) ) );

    a_pSerialNumber->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
}


/* Get the certificate issuer from the certifcate value
*/
void Token::generateIssuer( boost::shared_ptr< Marshaller::u1Array>& a_pCertificateValue, boost::shared_ptr< Marshaller::u1Array>& a_pIssuer ) {

    X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

    BEROctet::Blob b( x509cert.Issuer( ) );

    a_pIssuer.reset( new Marshaller::u1Array( static_cast< s4 >( b.size( ) ) ) );

    a_pIssuer->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
}


/* Get the certificate subject from the certifcate value
*/
void Token::generateSubject( boost::shared_ptr< Marshaller::u1Array>& a_pCertificateValue, boost::shared_ptr< Marshaller::u1Array>& a_pSubject ) {

    X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

    BEROctet::Blob b( x509cert.Subject( ) );

    a_pSubject.reset( new Marshaller::u1Array( static_cast< s4 >( b.size( ) ) ) );

    a_pSubject->SetBuffer( const_cast< unsigned char* >( b.data( ) ) );
}


/* Get the public key modulus
*/
void Token::generatePublicKeyModulus( boost::shared_ptr< Marshaller::u1Array>& a_pCertificateValue, boost::shared_ptr< Marshaller::u1Array>& a_pModulus, u8& a_u8CheckValue ) {

    X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

    BEROctet::Blob modulus = x509cert.Modulus( );

    a_pModulus.reset( new Marshaller::u1Array( modulus.size( ) ) );

    a_pModulus->SetBuffer( modulus.data( ) );

    // Compatibility with old P11
    a_u8CheckValue = Util::MakeCheckValue( modulus.data( ), static_cast< unsigned int >( modulus.size( ) ) );
}


/* Get the public key modulus
*/
void Token::generateRootAndSmartCardLogonFlags( boost::shared_ptr< Marshaller::u1Array>& a_pCertificateValue, bool& a_bIsRoot, unsigned long& a_ulCertificateCategory, bool& a_bIsSmartCardLogon ) {

    X509Cert x509cert( a_pCertificateValue->GetBuffer( ), a_pCertificateValue->GetLength( ) );

    a_bIsRoot = ( x509cert.IsCACert( ) || x509cert.IsRootCert( ) );

    // CKA_CERTIFICATE_CATEGORY attribute set to "authority" (2) is the certificate is a root or CA one
    a_ulCertificateCategory = a_bIsRoot ? 2 : 1; 

    // Look for the Windows Smart Card Logon OID
    a_bIsSmartCardLogon = x509cert.isSmartCardLogon( );
    //Log::log( "SmartCardLogon <%d>", a_pObject->m_bIsSmartCardLogon );
}


/* Search for a private key using the same public key exponent to set the same container index
*/
void Token::searchContainerIndex( boost::shared_ptr< Marshaller::u1Array>& a_pModulus, unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec ) {

    if( !a_pModulus ) {

        return;
    }

    int l = a_pModulus->GetLength( );

    unsigned char* p = a_pModulus->GetBuffer( );

    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_PRIVATE_KEY == obj->second->getClass( ) ) {

            RSAPrivateKeyObject* objPrivateKey = (RSAPrivateKeyObject*) obj->second;

            if( 0 == memcmp( objPrivateKey->m_pModulus->GetBuffer( ), p, l ) ) {

                a_ucContainerIndex = objPrivateKey->m_ucContainerIndex;

                a_ucKeySpec = objPrivateKey->m_ucKeySpec;
            }

            break;
        }
    }
}


/*
*/
void Token::setDefaultAttributesCertificate( X509PubKeyCertObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesCertificate" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if( !a_pObject->m_pValue ) {

        return;
    }

    // Parse the certifcate value to extract the PKCS11 attribute values not already set
    try {

        generateRootAndSmartCardLogonFlags( a_pObject->m_pValue, a_pObject->m_bIsRoot, a_pObject->_certCategory, a_pObject->m_bIsSmartCardLogon );

        generatePublicKeyModulus( a_pObject->m_pValue, a_pObject->m_pModulus, a_pObject->_checkValue );

        if( a_pObject->m_pModulus ) {

            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

                searchContainerIndex( a_pObject->m_pModulus, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );
            }

            if( !a_pObject->m_pLabel ) {

                generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );
            }

            if( !a_pObject->m_pID ) {

                generateID( a_pObject->m_pModulus, a_pObject->m_pID );
            }

            if( !a_pObject->m_pSubject ) {

                generateSubject( a_pObject->m_pValue, a_pObject->m_pSubject );
            }

            if( !a_pObject->m_pIssuer ) {

                generateIssuer( a_pObject->m_pValue, a_pObject->m_pIssuer );
            }

            if( !a_pObject->m_pSerialNumber ) {

                generateSerialNumber( a_pObject->m_pValue, a_pObject->m_pSerialNumber );
            }
        }

    } catch( ... ) {

    }

    t.stop( "Token::setDefaultAttributesCertificate" );
    Log::end( "Token::setDefaultAttributesCertificate" );
}


/*
*/
void Token::setDefaultAttributesKeyPublic( Pkcs11ObjectKeyPublicRSA* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if( !a_pObject->m_pModulus ) {

        return;
    }

    try {

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

            searchContainerIndex( a_pObject->m_pModulus, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );
        }

        if( !a_pObject->m_pLabel ) {

            generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );
        }

        if( !a_pObject->m_pID ) {

            generateID( a_pObject->m_pModulus, a_pObject->m_pID );
        }

    } catch( ... ) {

    }

    t.stop( "Token::setDefaultAttributesKeyPublic" );
    Log::end( "Token::setDefaultAttributesKeyPublic" );
}


/*
*/
void Token::setDefaultAttributesKeyPrivate( RSAPrivateKeyObject* a_pObject ) {

    Log::begin( "Token::setDefaultAttributesKeyPrivate" );
    Timer t;
    t.start( );

    if( !a_pObject ) {

        return;
    }

    if( !a_pObject->m_pModulus ) {

        return;
    }

    try {

        if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == a_pObject->m_ucContainerIndex ) {

            searchContainerIndex( a_pObject->m_pModulus, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );
        }

        // Compatibility with old P11
        unsigned char* p = a_pObject->m_pModulus->GetBuffer( );
        unsigned int l = a_pObject->m_pModulus->GetLength( );

        a_pObject->_checkValue = Util::MakeCheckValue( p, l );

        setContainerIndexToCertificate( a_pObject->m_pModulus, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );

        setContainerIndexToKeyPublic( a_pObject->m_pModulus, a_pObject->m_ucContainerIndex, a_pObject->m_ucKeySpec );

        if( !a_pObject->m_pLabel ) {

            generateLabel( a_pObject->m_pModulus, a_pObject->m_pLabel );
        }

        if( !a_pObject->m_pID ) {

            generateID( a_pObject->m_pModulus, a_pObject->m_pID );
        }

    } catch( ... ) {

    }

    t.stop( "Token::setDefaultAttributesKeyPrivate" );
    Log::end( "Token::setDefaultAttributesKeyPrivate" );
}


/*
*/
void Token::setContainerIndexToCertificate( boost::shared_ptr< Marshaller::u1Array>& a_pModulus, const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec ) {

    Log::begin( "Token::setContainerIndexToCertificate" );
    Timer t;
    t.start( );

    if( !a_pModulus ) {

        return;
    }

    unsigned char* p = a_pModulus->GetBuffer( );

    unsigned int l = a_pModulus->GetLength( );

    // Give the same container index of the private key to the associated certificate
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        if( CKO_CERTIFICATE == obj->second->getClass( ) ) {

            X509PubKeyCertObject* objCertificate = (X509PubKeyCertObject*) obj->second;

            if( objCertificate->m_pValue.get( ) ) {

                X509Cert x509cert( objCertificate->m_pValue->GetBuffer( ), objCertificate->m_pValue->GetLength( ) );

                // Get the certificate public key modulus
                BEROctet::Blob modulus = x509cert.Modulus( );

                Marshaller::u1Array m( modulus.size( ) );

                m.SetBuffer( modulus.data( ) );

                if( 0 == memcmp( m.GetBuffer( ), p, l ) ) {

                    // Give the same container index of the private key to the certificate
                    objCertificate->m_ucContainerIndex = a_ucContainerIndex;

                    objCertificate->m_ucKeySpec = a_ucKeySpec;

                    break;
                }
            }
        }
    }

    t.stop( "Token::setContainerIndexToCertificate" );
    Log::begin( "Token::setContainerIndexToCertificate" );
}


/* Search for an associated public key created before the private key to rename it properly using the index of the created container
*/
void Token::setContainerIndexToKeyPublic( boost::shared_ptr< Marshaller::u1Array>& a_pModulus, const unsigned char& a_ucContainerIndex, const unsigned char& a_ucKeySpec ) {

    Log::begin( "Token::setContainerIndexToKeyPublic" );
    Timer t;
    t.start( );

    if( !a_pModulus ) {

        return;
    }

    unsigned char* p = a_pModulus->GetBuffer( );

    unsigned int l = a_pModulus->GetLength( );

    // Give the same container index of the private key to the associated public key
    BOOST_FOREACH( const TOKEN_OBJECTS::value_type& obj, m_Objects ) {

        // Search for a PKCS11 public key object
        if( CKO_PUBLIC_KEY == obj->second->getClass( ) ) {

            Pkcs11ObjectKeyPublicRSA* objPublicKey = (Pkcs11ObjectKeyPublicRSA*) obj->second;

           // When the public key is created first the index is not set
            if( MiniDriverContainerMapFile::CONTAINER_INDEX_INVALID == objPublicKey->m_ucContainerIndex ) {

                // Search for the same modulus as the private key
                if( 0 == memcmp( objPublicKey->m_pModulus->GetBuffer( ), p, l ) ) {

                    // Delete the old object
                    deleteObjectFromCard( objPublicKey );

                    // Compute a new name regardiong the new index for the public key
                    std::string stNewName = objPublicKey->m_stFileName.substr( 0, objPublicKey->m_stFileName.length( ) - 2 );
                    Util::toStringHex( a_ucContainerIndex, stNewName );
                    
                    // Update the inner object's properties
                    objPublicKey->m_stFileName = stNewName;

                    objPublicKey->m_ucContainerIndex = a_ucContainerIndex;

                    // Save the new object
                    writeObject( objPublicKey );

                    break;
                }
            }
        }
    }

    t.stop( "Token::setContainerIndexToKeyPublic" );
    Log::end( "Token::setContainerIndexToKeyPublic" );
}
