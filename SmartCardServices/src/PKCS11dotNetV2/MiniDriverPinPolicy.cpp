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


#include <memory>
#include "MiniDriverPinPolicy.hpp"
#include "MiniDriverException.hpp"
#include "Log.hpp"


const unsigned char CP_CARD_PIN_POLICY = 0x80;


/*
*/
void MiniDriverPinPolicy::write( void ) { 
    
    Marshaller::u1Array b( g_PolicyLenght );

    b.SetBuffer( m_ucaPinPolicy.c_array( ) );

    try {

        m_CardModule->setCardProperty( CP_CARD_PIN_POLICY, &b, m_ucRole );
    
    } catch( MiniDriverException& ) {
    
            Log::error( "MiniDriverPinPolicy::write", "setCardProperty 0x80 failed" );

        // PIN policy not supported
        //m_ucaPinPolicy.fill( 0 );
    }
}

    
/*
*/
void MiniDriverPinPolicy::read( void ) { 
    
    std::auto_ptr< Marshaller::u1Array > b;

    try {

        b.reset( m_CardModule->getCardProperty( CP_CARD_PIN_POLICY, m_ucRole ) );
    
        if( b.get( ) ) {

            memcpy( m_ucaPinPolicy.c_array( ), b->GetBuffer( ), m_ucaPinPolicy.size( ) );
        }

    } catch( MiniDriverException& ) {

        Log::error( "MiniDriverPinPolicy::read", "getCardProperty 0x80 failed" );

        // PIN policy not supported
        reset( );
    }
}


/*
*/
void MiniDriverPinPolicy::print( void ) {

   unsigned char a_ucParameterValue = get( PARAMETER_KEY_MAX_ATTEMPS );
   Log::log( "PARAMETER_KEY_MAX_ATTEMPS <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_MIN_LENGTH );
   Log::log( "PARAMETER_KEY_MIN_LENGTH <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_MAX_LENGTH );
   Log::log( "PARAMETER_KEY_MAX_LENGTH <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_CHAR_SET );
   Log::log( "PARAMETER_KEY_CHAR_SET <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_COMPLEXITY_RULE_1 );
   Log::log( "PARAMETER_KEY_COMPLEXITY_RULE_1 <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_COMPLEXITY_RULE_2 );
   Log::log( "PARAMETER_KEY_COMPLEXITY_RULE_2 <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_ADJACENT_ALLOWED );
   Log::log( "PARAMETER_KEY_ADJACENT_ALLOWED <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_HISTORY );
   Log::log( "PARAMETER_KEY_HISTORY <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_ALLOW_UNBLOCK );
   Log::log( "PARAMETER_KEY_ALLOW_UNBLOCK <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_ALLOW_SSO );
   Log::log( "PARAMETER_KEY_ALLOW_SSO <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_ONE_OF_EACH_CHAR_SET );
   Log::log( "PARAMETER_KEY_ONE_OF_EACH_CHAR_SET <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_MANDATORY_CHAR_SET );
   Log::log( "PARAMETER_KEY_MANDATORY_CHAR_SET <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_MAX_SEQUENCE_LEN );
   Log::log( "PARAMETER_KEY_MAX_SEQUENCE_LEN <%#02x>", a_ucParameterValue );

   a_ucParameterValue = get( PARAMETER_KEY_MAX_ADJACENT_NB );
   Log::log( "PARAMETER_KEY_MAX_ADJACENT_NB <%#02x>", a_ucParameterValue );
}
