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


#include "MiniDriverAuthentication.hpp"
#include "SmartCardReader.hpp"
#include "tdes.h"
#include "Log.hpp"
#ifdef WIN32
#include "BioMan.h"
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif
#include "PCSCMissing.h"


bool MiniDriverAuthentication::isSSO( void ) { 
    
    return ( m_PinPolicy.getAllowSSO( ) != 0 ); 

}

 
/*
*/
MiniDriverAuthentication::MiniDriverAuthentication( ) {

    //Log::begin( "MiniDriverAuthentication::MiniDriverAuthentication" );

    // Set the role to use for authentication (default is user)
    setRole( PIN_USER );

    // Set the default role 
    m_bIsRoleLogged = false;

    m_bIsAdministratorLogged = false;

    m_wActiveMode = UVM_PIN_ONLY;

    m_ucTypePIN = PIN_TYPE_REGULAR;

    //Log::end( "MiniDriverAuthentication::MiniDriverAuthentication" );
}


/*
*/
void MiniDriverAuthentication::read( void ) {

    Log::begin( "MiniDriverAuthentication::read" );
    Timer t;
    t.start( );

    if( m_PinPolicy.empty( ) ) {
        
        try {
                // Read the PIN policy
                m_PinPolicy.read( );

        } catch( ... ) {
    
        }
    }

    // Read the PIN info ex property
    // Get the active mode (PIN only, Biometry only, PIN and Biometry, PIN or Biometry)
    // and get the PIN type (external for biometry or secured reader, regular or no pin)
    if( m_PinInfoEx.IsNull( ) ) {

        try {

            m_PinInfoEx.reset( m_CardModule->getCardProperty( CARD_PROPERTY_PIN_INFO_EX, m_ucRole ) );

            if( !m_PinInfoEx.IsNull( ) ) {

                m_wActiveMode = (unsigned short)( m_PinInfoEx.GetBuffer( )[ 12 ] + ( ( m_PinInfoEx.GetBuffer( )[ 13 ] ) << 8 ) );
                //Log::log( "Token::getCardMode - Active mode <%ld>", wActiveMode );

                m_ucTypePIN = (unsigned char)m_PinInfoEx.GetBuffer( )[ 0 ];

                //DWORD dwFlagsEx = (DWORD)(
                //   ba->GetBuffer( )[ 12 ] +
                //   ( ( ba->GetBuffer( )[ 13 ] ) << 8 ) +
                //   ( ( ba->GetBuffer( )[ 14 ] ) << 16 ) +
                //   ( ( ba->GetBuffer( )[ 15 ] ) << 24 )
                //   );
                //Log::log( "Token::getCardMode - dwFlagsEx <%#08x>", dwFlagsEx );
            }

        } catch( ... ) {

            Log::error( "MiniDriverAuthentication::MiniDriverAuthentication", "PIN_INFO_EX not supported - Default values used" );

            m_PinInfoEx.reset( );

            m_wActiveMode = UVM_PIN_ONLY;

            m_ucTypePIN = PIN_TYPE_REGULAR;
        }
    }

    t.stop( "MiniDriverAuthentication::read" );
    Log::end( "MiniDriverAuthentication::read" );
}


/*
*/
void MiniDriverAuthentication::login( Marshaller::u1Array* a_pPin/*, const unsigned char& a_ucRole*/ ) {

    Log::begin( "MiniDriverAuthentication::login" );
    Timer t;
    t.start( );

    switch( howToAuthenticate( (unsigned char)a_pPin->GetLength( ) ) ) {

    case g_ucAuthenticateRegular:
        Log::log( "MiniDriverAuthentication::login - Normal login" );
        verifyPin( a_pPin );
        break;

    case g_ucAuthenticateSecure:
        Log::log( "MiniDriverAuthentication::login - PinPad" );
        m_SmartCardReader->verifyPinSecured( m_ucRole );
        break;

    case g_AuthenticateBiometry:
#ifdef WIN32
        Log::log( "MiniDriverAuthentication::login - BIO" );
        verifyPinWithBio( );
#else
        Log::log( "MiniDriverAuthentication::AuthenticateUser - BIO not supported !!" );
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
#endif
        break;

    default:
        Log::log( "MiniDriverAuthentication::login - Unknown !!" );
        throw MiniDriverException( SCARD_F_INTERNAL_ERROR );
        break;
    }

    m_bIsRoleLogged = true;

    t.stop( "MiniDriverAuthentication::login" );
    Log::end( "MiniDriverAuthentication::login" );
}


/*
*/
unsigned char MiniDriverAuthentication::howToAuthenticate( unsigned char bPinLen ) {

    Log::begin( "MiniDriverAuthentication::howToAuthenticate" );
    Timer t;
    t.start( );

    unsigned char bRet = g_ucAuthenticateRegular;

    Log::log( "MiniDriverAuthentication::AuthenticateUser - PIN type <%ld> (0 = regular ; 1 = external)", isExternalPin( ) );
    Log::log( "MiniDriverAuthentication::AuthenticateUser - Card mode <%ld> (1 = pin only ; 2 = fp only ; 3 = fp or pin ; 4 = fp and pin)", getPinMode( ) );
    Log::log( "MiniDriverAuthentication::AuthenticateUser - PIN len <%ld>", bPinLen );

    if( isExternalPin( ) )
    {
        if( isModePinOnly( ) )
        {
            if( m_SmartCardReader->isVerifyPinSecured( ) ) {

                if( 0 == bPinLen ) {

                    Log::log( "MiniDriverAuthentication::AuthenticateUser - External PIN && UVM1 && PINpad support && null len -> PIN pad" );
                    bRet = g_ucAuthenticateSecure;

                } else {

                    Log::log( "MiniDriverAuthentication::AuthenticateUser - External PIN && UVM1 && PINpad support && valid len -> PIN normal" );
                    bRet = g_ucAuthenticateRegular;

                }
            } else {

                Log::log( "MiniDriverAuthentication::AuthenticateUser - External PIN && UVM1 && NO PINpad support -> ERROR !!!" );
                bRet = g_ucAuthenticateError;
            }
        } else {

            Log::log( "MiniDriverAuthentication::AuthenticateUser - External PIN && (UVM2 || UVM3 || UVM4) -> Bio" );
            bRet = g_AuthenticateBiometry;
        }
    } else {

        if( bPinLen && ( isModePinOnly( ) || isModePinOrBiometry( ) ) ) {

            Log::log( "MiniDriverAuthentication::AuthenticateUser - Regular PIN && (UVM1 || UVM3)  && valid len -> PIN normal" );
            bRet = g_ucAuthenticateRegular;

        } else {

            Log::log( "MiniDriverAuthentication::AuthenticateUser - Regular PIN && (UVM2 || UVM4)  && NO valid len -> ERROR !!!" );
            bRet = g_ucAuthenticateError;
        }
    }

    t.stop( "MiniDriverAuthentication::howToAuthenticate" );
    Log::end( "MiniDriverAuthentication::howToAuthenticate" );

    return bRet;
}


/*
*/
void MiniDriverAuthentication::verifyPinWithBio( void ) {

    Log::begin( "MiniDriverAuthentication::verifyPinWithBio" );

    long rv = SCARD_F_INTERNAL_ERROR;

#ifdef WIN32
    // Get the current OS version
    OSVERSIONINFO osvi;
    memset( &osvi, 0, sizeof( OSVERSIONINFO ) );
    osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
    GetVersionEx(&osvi);
    // Check if the Os is W7 or W2K8R2
    if( ( 6 == osvi.dwMajorVersion ) && ( osvi.dwMinorVersion >= 1 ) )
    {
        Log::log( "MiniDriverAuthentication::verifyPinWithBio - Os is W7 or W2K8R2" );

        //		CardEndTransaction( );

        // The OS is W7 or W2K8R2
        HMODULE hDll = NULL;
        LRESULT lRes = GSC_OK;
        LRESULT (WINAPI *ptr_SetUITitles) (WCHAR*, WCHAR*);
        LRESULT (WINAPI *ptr_AuthenticateUserCard) ();

        // Load DLL
        hDll = LoadLibraryA("GemSelCert.dll");
        Log::log( "MiniDriverAuthentication::verifyPinWithBio - load lib" );

        if( 0 != hDll )
        {
            // Set UI Titles
            ptr_SetUITitles = (LRESULT (WINAPI *) (WCHAR*, WCHAR*))GetProcAddress(hDll,"SetUITitles");
            if( NULL != ptr_SetUITitles )
            {
                ptr_SetUITitles(L"Smartcard Security", L"User MiniDriverAuthentication");
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - ptr_SetUITitles" );

                // Authenticate Card User
                ptr_AuthenticateUserCard = (LRESULT (WINAPI *)())GetProcAddress(hDll,"AuthenticateUserCard");
                if( NULL != ptr_AuthenticateUserCard )
                {
                    lRes = ptr_AuthenticateUserCard();
                    Log::log( "MiniDriverAuthentication::verifyPinWithBio - ptr_AuthenticateUserCard" );

                    switch(lRes)
                    {
                    case GSC_OK:
                        rv = SCARD_S_SUCCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_S_SUCCESS" );
                        break;

                    case GSC_CANCEL:
                        rv = SCARD_E_CANCELLED;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CANCELLED" );
                        break;

                    case GSC_NO_CERT:
                        rv = SCARD_E_CERTIFICATE_UNAVAILABLE;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CERTIFICATE_UNAVAILABLE" );
                        break;

                    case GSC_NO_CARD:
                        rv = SCARD_E_NO_SMARTCARD;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_SMARTCARD" );
                        break;

                    case GSC_WRONG_PIN:
                        rv = SCARD_W_WRONG_CHV;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_WRONG_CHV" );
                        break;

                    case GSC_READ_CARD:
                        rv = SCARD_E_NO_ACCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_ACCESS" );
                        break;

                    case GSC_WRITE_CARD:
                        rv = SCARD_E_NO_ACCESS;
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_NO_ACCESS" );
                        break;

                    default:
                        Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_F_INTERNAL_ERROR" );
                        rv = SCARD_F_INTERNAL_ERROR;
                        break;
                    }
                }
            }

            // Release DLL
            FreeLibrary(hDll);
            Log::log( "MiniDriverAuthentication::verifyPinWithBio - FreeLibrary" );

            //		CardBeginTransaction( );
        }
        // The OS is Vista or XP
        else
        {
            Log::log( "MiniDriverAuthentication::verifyPinWithBio - Os is Vista or XP" );

            CBioMan* pBioMan = NULL;
            DWORD dwRes = BIO_ERR_NOT_SUPPORTED;

            // Init BioMan helper
            pBioMan = new CBioMan( m_CardModule );

            // Biometrics Verification
            dwRes = pBioMan->VerifyBio( );

            delete pBioMan;

            // Error ?
            switch( dwRes )
            {
            case BIO_ERR_SUCCESS:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - CKR_OK" );
                rv = SCARD_S_SUCCESS;
                break;

            case BIO_ERR_NO_CARD:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - CKR_TOKEN_NOT_PRESENT" );
                rv = SCARD_E_NO_SMARTCARD;
                break;

            case BIO_ERR_NOT_SUPPORTED:
            case BIO_ERR_NO_FINGER:
            case BIO_ERR_BIO_NOT_CHECKED:
            case BIO_ERR_PIN_NOT_CHECKED:
            case BIO_ERR_BIO_LAST:
            case BIO_ERR_PIN_LAST:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_WRONG_CHV" );
                rv = SCARD_W_WRONG_CHV;
                break;

            case BIO_ERR_BLOCKED:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_W_CHV_BLOCKED" );
                rv = SCARD_W_CHV_BLOCKED;
                break;

            case BIO_ERR_ABORT:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_E_CANCELLED" );
                rv = SCARD_E_CANCELLED;
                break;

            default:
                Log::log( "MiniDriverAuthentication::verifyPinWithBio - SCARD_F_INTERNAL_ERROR" );
                rv = SCARD_F_INTERNAL_ERROR;
                break;
            }
        }
    }
#endif

    Log::log( "MiniDriverAuthentication::verifyPinWithBio - <END>" );

    if( SCARD_S_SUCCESS != rv ) {

        throw MiniDriverException( rv );
    } 
}


/*
*/
bool MiniDriverAuthentication::isLoggedIn( void ) {

    if( m_bIsRoleLogged ) {

        return true;
    }

    if(  isSSO( ) && isAuthenticated( ) ) {

        return true;
    }

    if( isNoPin( ) ) {

        return true;
    }

    return false;
}


/*
*/
void MiniDriverAuthentication::synchronizePIN( void ) {
}


/*
*/
void MiniDriverAuthentication::unblockPin( Marshaller::u1Array* a_PinSo, Marshaller::u1Array* a_PinUser ) {

    Log::begin( "MiniDriverAuthentication::unblockPin" );
    std::string stPinSo;
    Log::toString( a_PinSo->GetBuffer( ), a_PinSo->GetLength( ), stPinSo );
    std::string stPinUser;
    Log::toString( a_PinUser->GetBuffer( ), a_PinUser->GetLength( ), stPinUser );
    Log::log( "User PIN <%s> - Administrator Key <%s>", stPinUser.c_str( ), stPinSo.c_str( ) );

    Timer t;
    t.start( );

    // Get a challenge from the smart card
    boost::shared_ptr< Marshaller::u1Array > pChallenge( m_CardModule->getChallenge( ) );

    // compute a 3DES cryptogramm from the challenge using the administrator key
    computeCryptogram( pChallenge.get( ), a_PinSo );

    // Unblock the user PIN. The retry counter value is not modified (-1)
    m_CardModule->changeReferenceData( MODE_UNBLOCK_PIN, PIN_USER, &m_Cryptogram, a_PinUser, -1 );

    t.stop( "MiniDriverAuthentication::unblockPin" );
    Log::end( "MiniDriverAuthentication::unblockPin" );
}


/// ADMINISTRATOR


/*
*/
void MiniDriverAuthentication::administratorChangeKey( Marshaller::u1Array* a_OldKey, Marshaller::u1Array* a_NewKey ) {

    Log::begin( "MiniDriverAuthentication::administratorChangeKey" );
    Timer t;
    t.start( );

    // Get the challenge from the smart card
    boost::shared_ptr< Marshaller::u1Array > pChallenge( m_CardModule->getChallenge( ) );

    // Compute the 3DES cryptogram from the challeng using the current adminsitrator key
    computeCryptogram( pChallenge.get( ), a_OldKey );

    // The new administrator key has to be 24 bytes. if not we just pad rest of bytes as zeros
    Marshaller::u1Array a( 24 );

    memset( a.GetBuffer( ), 0, 24 );

    memcpy( a.GetBuffer( ), a_NewKey->GetBuffer( ), a_NewKey->GetLength( ) );

    // Change the administrator key
    m_CardModule->changeReferenceData( MODE_CHANGE_PIN, PIN_ADMIN, &m_Cryptogram, &a, -1 );

    t.stop( "MiniDriverAuthentication::administratorChangeKey" );
    Log::end( "MiniDriverAuthentication::administratorChangeKey" );
}


/*
*/
void MiniDriverAuthentication::administratorLogin( Marshaller::u1Array* a_pAdministratorKey ) {

    Log::begin( "MiniDriverAuthentication::authenticateAdministrator" );
    Timer t;
    t.start( );

    // Get a challenge
    boost::shared_ptr< Marshaller::u1Array > challenge( m_CardModule->getChallenge( ) );

    // Compute a cryptopgram from the challenge using the administror key
    computeCryptogram( challenge.get( ), a_pAdministratorKey );

    try {

        // Perform the administrator authentication
        m_CardModule->externalAuthenticate( &m_Cryptogram );

    } catch( MiniDriverException& ) {

        Log::error( "MiniDriverAuthentication::administratorLogin", "externalAuthenticate failed" );

        // first check if pin is locked or not blocked
        if( !administratorGetTriesRemaining( ) ) {

            throw MiniDriverException( SCARD_W_CHV_BLOCKED );
        }

        throw;
    }

    t.stop( "MiniDriverAuthentication::authenticateAdministrator" );
    Log::end( "MiniDriverAuthentication::authenticateAdministrator" );
}


/* Only accept correct length, otherwise return a zero valued response that is sure to fail authentication.
*/
void MiniDriverAuthentication::computeCryptogram( Marshaller::u1Array* a_challenge, Marshaller::u1Array* a_pin ) {

    Log::begin( "MiniDriverAuthentication::computeCryptogram" );
    Timer t;
    t.start( );

    m_Cryptogram.reset( );

    if( 24 == a_pin->GetLength( ) ) {

        // compute the response
        CK_BYTE iv[ 8 ];
        memset( iv, 0, sizeof( iv ) );

        CTripleDES tdes;

        tdes.SetEncryptMode( ENCRYPT );

        tdes.SetIV( iv );

        tdes.SetCipherMode( CIPHER_MODE_ECB );

        tdes.SetPaddingMode( PADDING_MODE_NONE );

        tdes.SetKey( a_pin->GetBuffer( ), 24 );

        m_Cryptogram.reset( new Marshaller::u1Array( 8 ) );

        tdes.TransformFinalBlock( a_challenge->GetBuffer( ), 0, 8, m_Cryptogram.GetBuffer( ), 0 );

    }

    t.stop( "MiniDriverAuthentication::computeCryptogram" );
    Log::end( "MiniDriverAuthentication::computeCryptogram" );
}


/*
*/
void MiniDriverAuthentication::print( void ) {
   
    Log::begin( "MiniDriverAuthentication::print" );

    Log::log( "m_wActiveMode <%ld>", m_wActiveMode );

    Log::log( "m_ucTypePIN <%ld>", m_ucTypePIN );

    m_PinPolicy.print( );

    Log::logCK_UTF8CHAR_PTR( "m_PinInfoEx", m_PinInfoEx.GetBuffer( ), m_PinInfoEx.GetLength( ) );

    Log::log( "m_ucRole <%ld>", m_ucRole );

    Log::end( "MiniDriverAuthentication::print" );
}


bool MiniDriverAuthentication::administratorIsAuthenticated( void ) { 
    
    bool b = false; 
    
    if( m_CardModule ) {  
        
        b = m_CardModule->isAuthenticated( PIN_ADMIN ); 
        
        Log::log( "MiniDriverAuthentication - administratorIsAuthenticated <%d>", b ); 
    
    } else {
        
        throw MiniDriverException( SCARD_E_NO_SMARTCARD ); 
    }

    return b; 

}

