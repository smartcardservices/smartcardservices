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


#include <boost/shared_ptr.hpp>
#include "CardModuleService.hpp"
#include "Log.hpp"
#include "MiniDriverException.hpp"
#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "PCSCMissing.h"

const char* ERROR_MEMORY = "Persistent";
const unsigned char CARD_PROPERTY_AUTHENTICATED_ROLES = 0x09;
const unsigned int LOW_FREE_MEMORY_ALLOWED = 30000;

#define TIMER_DURATION 2.0


CardModuleService::SMARTCARD_TYPE CardModuleService::getVersion( void ) { 
    
    Timer t; 
    t.start( ); 
    
    m_ucSmartCardType = SMART_CARD_TYPE_V2PLUS; 

    try {

        std::auto_ptr< Marshaller::u1Array > s( getCardProperty( CARD_VERSION_INFO, 0 ) );

        if( s.get( )  ) { 
      
            Log::log( "CardModuleService::getVersion - %d.%d.%d.%d", s->ReadU1At( 0 ), s->ReadU1At( 1 ), s->ReadU1At( 2 ), s->ReadU1At( 3 ) );

            if( s->ReadU1At( 0 ) != 0x07) {

                m_ucSmartCardType = SMART_CARD_TYPE_V2; 
            }
        }
    
    } catch( ... ) { 
    
        m_ucSmartCardType = SMART_CARD_TYPE_V2;
    }

    //try { 
    //    // Call the V5 get version method
    //    Invoke( 0, 0xDEEC, MARSHALLER_TYPE_RET_STRING, &s );  
    //
    //} catch( Marshaller::Exception& x ) { 
    //    
    //    checkException( x ); 
    //} 
    
    switch( m_ucSmartCardType ) {

    case SMART_CARD_TYPE_V2:
        Log::log( "CardModuleService::getVersion - V2" );
        break;

    case SMART_CARD_TYPE_V2PLUS:
        Log::log( "CardModuleService::getVersion - V2+" );
        break;

    case SMART_CARD_TYPE_V1:
        Log::log( "CardModuleService::getVersion - V1" );
        break;

    default:
        Log::log( "CardModuleService::getVersion - unknown" );
        break;
    }

    t.stop( ">> CardModuleService::getVersion" ); 
    
    return m_ucSmartCardType; 
}


/* checkException
*/
void CardModuleService::checkException( Marshaller::Exception &x ) {

    if( x.what( ) ) {

        if( 0 == strcmp( x.what( ), ERROR_MEMORY ) ) {

            Log::error( "CardModuleService::checkException", "Memory Error" );

            forceGarbageCollector( );

            // Not enough memory available to complete this command.
            throw MiniDriverException( SCARD_E_NO_MEMORY );
        }
    }

    if( dynamic_cast< Marshaller::UnauthorizedAccessException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " UnauthorizedAccessException" );

        // No PIN was presented to the smart card.
        throw MiniDriverException( SCARD_W_CARD_NOT_AUTHENTICATED );
    }

    if( dynamic_cast< Marshaller::OutOfMemoryException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " OutOfMemoryException" );

        // Not enough memory available to complete this command.
        throw MiniDriverException( SCARD_E_NO_MEMORY );
    }

    if( dynamic_cast< Marshaller::DirectoryNotFoundException* >( &x ) ) {

        Log::error( "CardModuleService::checkException", " DirectoryNotFoundException" );

        // The identified directory does not exist in the smart card.
        throw MiniDriverException( SCARD_E_DIR_NOT_FOUND );
    }

    if( dynamic_cast< Marshaller::FileNotFoundException * >( &x ) ) {

        Log::error( "CardModuleService::checkException", " FileNotFoundException" );

        // The identified file does not exist in the smart card.
        throw MiniDriverException( SCARD_E_FILE_NOT_FOUND );
    }

    if( dynamic_cast< Marshaller::IOException * >( &x ) ) {

        Log::error( "CardModuleService::checkException", " IOException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_WRITE_TOO_MANY );
    }

    if( dynamic_cast< Marshaller::TypeLoadException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " TypeLoadException" );

        //m_ucSmartCardType = SMART_CARD_TYPE_V2;

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< Marshaller::VerificationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " VerificationException" );

        // The supplied PIN is incorrect.
        throw MiniDriverException( SCARD_E_INVALID_CHV );
    }

    if( dynamic_cast< Marshaller::RemotingException * >( &x ) ) {

        // Can occur after when the computer wakes up after sleep
        Log::error( "CardModuleService::checkException", " RemotingException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_NO_SMARTCARD );
        // Other possibilities: SCARD_F_COMM_ERROR SCARD_E_COMM_DATA_LOST SCARD_W_REMOVED_CARD
    }

    if( dynamic_cast< Marshaller::CryptographicException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " CryptographicException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::SystemException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SystemException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::ArgumentException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< Marshaller::ArgumentNullException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentNullException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< Marshaller::ArgumentOutOfRangeException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArgumentOutOfRangeException" );

        // A communications error with the smart card has been detected. Retry the operation.
        throw MiniDriverException( SCARD_E_COMM_DATA_LOST );
    }

    if( dynamic_cast< Marshaller::IndexOutOfRangeException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " IndexOutOfRangeException" );

        // One or more of the supplied parameters could not be properly interpreted.
        throw MiniDriverException( SCARD_E_INVALID_PARAMETER );
    }

    if( dynamic_cast< Marshaller::InvalidCastException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " InvalidCastException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::InvalidOperationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " InvalidOperationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::NotImplementedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NotImplementedException" );

        // This smart card does not support the requested feature.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< Marshaller::NotSupportedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NotSupportedException" );

        // This smart card does not support the requested feature.
        throw MiniDriverException( SCARD_E_UNSUPPORTED_FEATURE );
    }

    if( dynamic_cast< Marshaller::NullReferenceException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " NullReferenceException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::ObjectDisposedException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ObjectDisposedException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::ApplicationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ApplicationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::ArithmeticException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArithmeticException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::ArrayTypeMismatchException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " ArrayTypeMismatchException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::BadImageFormatException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " BadImageFormatException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::DivideByZeroException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " DivideByZeroException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::FormatException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " FormatException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::RankException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " RankException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::StackOverflowException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " StackOverflowException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::MemberAccessException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MemberAccessException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::MissingFieldException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingFieldException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::MissingMemberException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingMemberException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::MissingMethodException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " MissingMethodException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::OverflowException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " OverflowException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::SecurityException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SecurityException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    if( dynamic_cast< Marshaller::SerializationException *>( &x ) ) {

        Log::error( "CardModuleService::checkException", " SerializationException" );

        // An unexpected card error has occurred.
        throw MiniDriverException( SCARD_E_UNEXPECTED );
    }

    // An unexpected card error has occurred.
    throw MiniDriverException( SCARD_E_UNEXPECTED );
}


/*
*/
void CardModuleService::forceGarbageCollector( void ) { 

    if( SMART_CARD_TYPE_V2PLUS != m_ucSmartCardType ) { 

        return; 
    } 

    Timer t; 
    t.start( ); 

    try { 

        Invoke( 0, 0x3D38, MARSHALLER_TYPE_RET_VOID ); 

        Log::log( "_______________  _______________ !!!!!!! CardModuleService::forceGarbageCollector - force garbage !!!!!" );

    //} catch( Marshaller::Exception& x ) { 

    //    if( dynamic_cast< Marshaller::TypeLoadException *>( &x ) ) {

    //        Log::log( "CardModuleService::forceGarbageCollector - force garbage collection not supported" );

    //        m_ucSmartCardType = SMART_CARD_TYPE_V2;
    //    }

    } catch( ... ) {

    }

    m_Timer.start( ); 
    t.stop( ">> CardModuleService::forceGarbageCollector"); 
}


/*
*/
void CardModuleService::manageGarbageCollector( void ) {

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        if( m_Timer.getCurrentDuration( ) < TIMER_DURATION ) {

            return;
        }

        try {
            int i = getMemory( );

            //Log::log( "CardModuleService::manageGarbageCollector - memory <%ld>", i );

            if( i < LOW_FREE_MEMORY_ALLOWED ) {

                Log::error( "CardModuleService::manageGarbageCollector", "Low memory" );

                forceGarbageCollector( );
            }

        } catch( ... ) {

            //m_ucSmartCardType = SMART_CARD_TYPE_V2;
        }

        m_Timer.start( );
    }
}


/*
*/
unsigned int CardModuleService::getMemory( void ) { 

    Timer t; 
    t.start( ); 

    u4 uiRemainingMemory = 0;

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        try {

            // Try the "getMemory" command
            Invoke( 0, 0x1DB4, MARSHALLER_TYPE_RET_S4, &uiRemainingMemory) ;

        } catch( Marshaller::Exception& ) {

            //m_ucSmartCardType = SMART_CARD_TYPE_V2;

            // Try the "getFreeSpace" command
            try { 

                std::auto_ptr< Marshaller::s4Array > a;

                Invoke(0, 0x00E5, MARSHALLER_TYPE_RET_S4ARRAY, &a ); 

                if( a.get( ) && ( a->GetLength( ) > 2 ) ) {

                    uiRemainingMemory = a->ReadU4At( 2 );
                }

            } catch( Marshaller::Exception& x ) { 

                checkException( x ); 
            }
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        try { 

            std::auto_ptr< Marshaller::s4Array > a;

            Invoke(0, 0x00E5, MARSHALLER_TYPE_RET_S4ARRAY, &a ); 

            if( a.get( ) && ( a->GetLength( ) > 2 ) ) {

                uiRemainingMemory = a->ReadU4At( 2 );
            }

        } catch( Marshaller::Exception& x ) { 

            checkException( x ); 
        }
    }

    Log::log( ">> CardModuleService::getMemory - memory <%ld>", uiRemainingMemory );
    t.stop( ">> CardModuleService::getMemory" );

    return uiRemainingMemory; 
}


/*
*/
bool CardModuleService::isAuthenticated( const unsigned char& a_ucRole ) { 

    Timer t; 
    t.start( ); 

    bool bIsAuthenticated = false;

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to get the flag using the card properties
        try {

            boost::shared_ptr< Marshaller::u1Array > p( getCardProperty( CARD_PROPERTY_AUTHENTICATED_ROLES, 0 ) );

            Log::log( "MiniDriverAuthentication - isAuthenticated <%#02x>", p->ReadU1At( 0 ) );

            bIsAuthenticated = ( ( (unsigned char)( p->ReadU1At( 0 ) & a_ucRole ) ) == a_ucRole ); 

        } catch( Marshaller::Exception& ) {

            //// The card properties are not supported
            //m_ucSmartCardType = SMART_CARD_TYPE_V2;

            // Try the get the flag from a command
            try {

                Invoke(1, 0x9B0B, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_RET_BOOL, &bIsAuthenticated ); 

            } catch( Marshaller::Exception& x ) { 

                checkException( x ); 
            }
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            Invoke(1, 0x9B0B, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_RET_BOOL, &bIsAuthenticated ); 

        } catch( Marshaller::Exception& x ) { 

            checkException( x ); 
        }
    }

    t.stop( ">> CardModuleService::isAuthenticated" );

    return bIsAuthenticated; 
}


/*
*/
void CardModuleService::verifyPin( const unsigned char& a_ucRole, Marshaller::u1Array* a_pPin ) { 

    Timer t; 
    t.start( ); 

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to authentication using authenticateEx
        try {

            authenticateEx( 0, a_ucRole, a_pPin ); 

        } catch( Marshaller::Exception& ) {

            //// The authenticaqteEx is not supported
            //m_ucSmartCardType = SMART_CARD_TYPE_V2;

            // Try the authentication using verify PIN
            try {

                Invoke( 2, 0x506B, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_IN_U1ARRAY, a_pPin, MARSHALLER_TYPE_RET_VOID );

            } catch( Marshaller::Exception& x ) { 

                checkException( x ); 
            }  
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            Invoke( 2, 0x506B, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_IN_U1ARRAY, a_pPin, MARSHALLER_TYPE_RET_VOID );

        } catch( Marshaller::Exception& x ) { 

            checkException( x ); 
        }
    }

    t.stop( ">> CardModuleService::verifyPin" );
}


/*
*/
void CardModuleService::logOut( const unsigned char& a_ucRole ) {

    Timer t; 
    t.start( ); 

    if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) {

        // Try to deauthentication using deauthenticateEx
        try {

            deauthenticateEx( a_ucRole );

        } catch( Marshaller::Exception& ) {

            //// The authenticaqteEx is not supported
            //m_ucSmartCardType = SMART_CARD_TYPE_V2;

            // Try the deauthentication using logout
            try {

                Invoke( 1, 0xC4E4, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_RET_VOID );

            } catch( Marshaller::Exception& x ) { 

                checkException( x ); 
            }  
        }

    } else if( SMART_CARD_TYPE_V2 == m_ucSmartCardType ) {

        // Try the get the flag from a command
        try {

            Invoke( 1, 0xC4E4, MARSHALLER_TYPE_IN_U1, a_ucRole, MARSHALLER_TYPE_RET_VOID );

        } catch( Marshaller::Exception& x ) { 

            checkException( x ); 
        }
    }

    t.stop( ">> CardModuleService::logOut" );
}    


/*
*/
Marshaller::u1Array* CardModuleService::getCardProperty( const unsigned char& a_ucProperty, const unsigned char& a_ucFlags ) {

    if( SMART_CARD_TYPE_V2PLUS != m_ucSmartCardType ) { 

        return NULL; 
    } 

    Log::log( ">> CardModuleService::getCardProperty - property <%#02x>", a_ucProperty ); 

    if( ( CARD_FREE_SPACE != a_ucProperty ) && ( CARD_AUTHENTICATED_ROLES != a_ucProperty ) && ( CARD_CHANGE_PIN_FIRST != a_ucProperty ) ) {

        PROPERTIES::iterator i = m_Properties.find( a_ucProperty );

        if( m_Properties.end( ) != i ) {

            return i->second;
        }
    }

    Timer t; 
    t.start( ); 

    boost::shared_ptr< Marshaller::u1Array > p( new Marshaller::u1Array( ) );

    try {  

        Invoke( 2, 0x8187, MARSHALLER_TYPE_IN_U1, a_ucProperty, MARSHALLER_TYPE_IN_U1, a_ucFlags, MARSHALLER_TYPE_RET_U1ARRAY, &p ); 

        m_Properties[ a_ucProperty ] = *p;

    } catch( Marshaller::Exception& x ) {
        
        //m_ucSmartCardType = SMART_CARD_TYPE_V2;

        p.reset( );

        checkException( x );
    } 

    t.stop( ">> CardModuleService::getCardProperty"); 

    return p.get( ); 
}


/*
*/
void CardModuleService::setCardProperty( const unsigned char& a_ucProperty, Marshaller::u1Array* a_pData, const unsigned char& a_ucFlags ) {

    if( SMART_CARD_TYPE_V2PLUS != m_ucSmartCardType ) { return; }

    Log::log( ">> CardModuleService::setCardProperty - property <%#02x>", a_ucProperty );

    Timer t; 
    t.start( ); 

    try {

        Invoke( 3, 0xB0E4, MARSHALLER_TYPE_IN_U1, a_ucProperty, MARSHALLER_TYPE_IN_U1ARRAY, a_pData, MARSHALLER_TYPE_IN_U1, a_ucFlags, MARSHALLER_TYPE_RET_VOID );

        boost::shared_ptr< Marshaller::u1Array > p( new Marshaller::u1Array( *a_pData ) );

        m_Properties[ a_ucProperty ] = *p;

    } catch( Marshaller::Exception& x ) { 

        checkException( x );
    }

    t.stop( ">> CardModuleService::setCardProperty" );
}
