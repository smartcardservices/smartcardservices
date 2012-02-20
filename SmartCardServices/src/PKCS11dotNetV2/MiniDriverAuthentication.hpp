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


#ifndef __GEMALTO_MINIDRIVER_AUTHENTICATION__
#define __GEMALTO_MINIDRIVER_AUTHENTICATION__


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include "MiniDriverPinPolicy.hpp"
#include "Array.hpp"
#include "MiniDriverException.hpp"


class SmartCardReader;


const unsigned char CARD_PROPERTY_PIN_INFO_EX = 0x87;


/*
*/
class MiniDriverAuthentication {

public:

    typedef enum { PIN_NONE = 0x00, PIN_USER = 0x01, PIN_ADMIN = 0x02, PIN_3 = 0x04, PIN_4 = 0x08, PIN_5 = 0x10, PIN_6 = 0x20, PIN_7 = 0x40 } ROLES;

    typedef enum { MODE_CHANGE_PIN = 0x00, MODE_UNBLOCK_PIN = 0x01 } CHANGE_REFERENCE_DATA_MODES;

    typedef enum { UVM_PIN_ONLY = 1, UVM_FP_ONLY, UVM_PIN_OR_FP, UVM_PIN_AND_FP } UVM_MODES;

    typedef enum { PIN_TYPE_REGULAR = 0, PIN_TYPE_EXTERNAL, PIN_TYPE_CHALLENGE_RESPONSE, PIN_TYPE_NO_PIN } PIN_TYPES;

    static const unsigned char g_ucAuthenticateError = 0;
    static const unsigned char g_ucAuthenticateRegular = 1;
    static const unsigned char g_ucAuthenticateSecure = 2;
    static const unsigned char g_AuthenticateBiometry = 3;

    MiniDriverAuthentication( );

    inline void setCardModule( CardModuleService* a_pCardModule ) { m_CardModule = a_pCardModule; m_PinPolicy.setCardModuleService( m_CardModule ); }

    inline void setSmartCardReader( SmartCardReader* a_pSmartCardReader ) { m_SmartCardReader = a_pSmartCardReader; }

    inline void setRole( const unsigned char& a_ucRole = PIN_USER ) { m_ucRole = a_ucRole; m_PinPolicy.setRole( m_ucRole ); }

    void read( void );


    // User role management

    bool isSSO( void );

    inline bool isNoPin( void ) { return ( m_ucTypePIN == PIN_TYPE_NO_PIN ); }

    inline bool isAuthenticated( void ) { if( m_CardModule ) return m_CardModule->isAuthenticated( m_ucRole ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline bool isPinInitialized( void ) { bool bRet = true; Marshaller::u1Array* a = 0; if( m_CardModule ) { try { a = m_CardModule->getCardProperty( CARD_CHANGE_PIN_FIRST, m_ucRole ); } catch( ... ) { a = 0; } if( a ) { bRet = ( 0 == a->ReadU1At( 0 ) ); } } return bRet; }

    inline bool isExternalPin( void ) { return ( m_ucTypePIN == PIN_TYPE_EXTERNAL ); }

    inline bool isModePinOnly( void ) { return ( m_wActiveMode == UVM_PIN_ONLY ); }

    inline bool isModeNotPinOnly( void ) { return ( m_wActiveMode != UVM_PIN_ONLY ); }

    inline bool isModePinOrBiometry( void ) { return ( m_wActiveMode == UVM_PIN_OR_FP ); }

    void login( Marshaller::u1Array* );

    inline void verifyPin( Marshaller::u1Array* a_Pin ) { if( m_CardModule ) m_CardModule->verifyPin( m_ucRole, a_Pin ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void changePin( Marshaller::u1Array* a_pOldPIN, Marshaller::u1Array* a_pNewPIN ) { if( m_CardModule ) m_CardModule->changeReferenceData( MODE_CHANGE_PIN, m_ucRole, a_pOldPIN, a_pNewPIN, -1 ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    inline void logOut( void ) { if( m_CardModule ) m_CardModule->logOut( m_ucRole ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void unblockPin( Marshaller::u1Array*, Marshaller::u1Array* );

    bool isLoggedIn( void );

    void synchronizePIN( void );

    inline unsigned char getPinMinPinLength( void ) { return m_PinPolicy.getPinMinLength( ); }

    inline unsigned char getPinMaxPinLength( void ) { return m_PinPolicy.getPinMaxLength( ); }

    inline unsigned char getPinMaxAttempts( void ) { return m_PinPolicy.getMaxAttemps( ); }

    inline unsigned char getPinType( void ) { return m_ucTypePIN; }

    // Get the card mode (1=PIN, 2=FingerPrint, 3=PIN or FP, 4=PIN and FP). The default mode is PIN
    inline unsigned short getPinMode( void ) { return m_wActiveMode; }

    inline unsigned char getTriesRemaining( void ) { if( m_CardModule ) return (unsigned char)m_CardModule->getTriesRemaining( m_ucRole ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }


    // Administrator key management

    void administratorLogin( Marshaller::u1Array* );

    inline void administratorLogout( void ) {if( m_CardModule ) m_CardModule->logOut( PIN_ADMIN ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    void administratorChangeKey( Marshaller::u1Array*, Marshaller::u1Array* );

    inline unsigned char administratorGetTriesRemaining( void ) { if( m_CardModule ) return (unsigned char)m_CardModule->getTriesRemaining( PIN_ADMIN ); else throw MiniDriverException( SCARD_E_NO_SMARTCARD ); }

    bool administratorIsAuthenticated( void );

    void print( void );
    
private:

    void verifyPinWithBio( void );

    void computeCryptogram( Marshaller::u1Array*, Marshaller::u1Array* );

    unsigned char howToAuthenticate( unsigned char bPinLen );

    void authenticateUser( Marshaller::u1Array* );

    void authenticateAdmin( Marshaller::u1Array* );

    unsigned short m_wActiveMode;

    unsigned char m_ucTypePIN;

    MiniDriverPinPolicy m_PinPolicy;

    CardModuleService* m_CardModule;

    SmartCardReader* m_SmartCardReader;

    Marshaller::u1Array m_PinInfoEx;

    Marshaller::u1Array m_Cryptogram;

    bool m_bIsRoleLogged;

    bool m_bIsAdministratorLogged;

    unsigned char m_ucRole;

    // Disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {
       
        //Log::begin( "MiniDriverAuthentication::serialize" );

        ar & m_ucRole;

        ar & m_PinInfoEx;

        ar & m_PinPolicy;

        ar & m_wActiveMode;

        ar & m_ucTypePIN;

        //Log::log( "Role <%ld>", m_ucRole );
        //Log::logCK_UTF8CHAR_PTR( "PIN info Ex %s", m_PinInfoEx.GetBuffer( ), m_PinInfoEx.GetLength( ) );
        //m_PinPolicy.print( );
        //Log::log( "Active mode <%ld>", m_wActiveMode );
        //Log::log( "PIN type <%ld>", m_ucTypePIN );

        //Log::end( "MiniDriverAuthentication::serialize" );
    }

};


BOOST_CLASS_VERSION( MiniDriverAuthentication, 1 )


#endif // __GEMALTO_MINIDRIVER_AUTHENTICATION__
