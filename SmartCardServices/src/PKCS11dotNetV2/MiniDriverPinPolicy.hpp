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


#ifndef __GEMALTO_PIN_POLICY__
#define __GEMALTO_PIN_POLICY__


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/array.hpp>
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#include <memory>
#include "CardModuleService.hpp"


const unsigned char g_PolicyLenght = 14;
const unsigned char PARAMETER_KEY_MAX_ATTEMPS  = 0;
const unsigned char PARAMETER_KEY_MIN_LENGTH  = 1;
const unsigned char PARAMETER_KEY_MAX_LENGTH  = 2;
const unsigned char PARAMETER_KEY_CHAR_SET  = 3;
const unsigned char PARAMETER_KEY_COMPLEXITY_RULE_1  = 4;
const unsigned char PARAMETER_KEY_COMPLEXITY_RULE_2  = 5;
const unsigned char PARAMETER_KEY_ADJACENT_ALLOWED = 6;
const unsigned char PARAMETER_KEY_HISTORY = 7;
const unsigned char PARAMETER_KEY_ALLOW_UNBLOCK = 8;
const unsigned char PARAMETER_KEY_ALLOW_SSO = 9;
const unsigned char PARAMETER_KEY_ONE_OF_EACH_CHAR_SET = 10;
const unsigned char PARAMETER_KEY_MANDATORY_CHAR_SET = 11;
const unsigned char PARAMETER_KEY_MAX_SEQUENCE_LEN = 12;
const unsigned char PARAMETER_KEY_MAX_ADJACENT_NB = 13;


/*
*/
class MiniDriverPinPolicy {

public:

    MiniDriverPinPolicy( ) { reset( ); }

    inline void setCardModuleService( CardModuleService* a_pCardModule ) { m_CardModule = a_pCardModule; }

    inline void setRole( unsigned char const &a_ucRole ) { m_ucRole = a_ucRole; }

    void read( void );

    inline const unsigned char& getMaxAttemps( void ) { return get( PARAMETER_KEY_MAX_ATTEMPS ); }

    inline const unsigned char& getPinMinLength( void ) { return get( PARAMETER_KEY_MIN_LENGTH ); }

    inline const unsigned char& getPinMaxLength(  void ) { return get( PARAMETER_KEY_MAX_LENGTH ); }

    inline const unsigned char& getCharSet( void ) { return get( PARAMETER_KEY_CHAR_SET ); }

    inline const unsigned char& getComplexityRule1( void ) { return get( PARAMETER_KEY_COMPLEXITY_RULE_1 ); }

    inline const unsigned char& getComplexityRule2( void ) { return get( PARAMETER_KEY_COMPLEXITY_RULE_2 ); }

    inline const unsigned char& getAdjacentAllowed( void ) { return get( PARAMETER_KEY_ADJACENT_ALLOWED ); }

    inline const unsigned char& getHistory( void ) { return get( PARAMETER_KEY_HISTORY ); }

    inline const unsigned char& getAllowUnblock( void ) { return get( PARAMETER_KEY_ALLOW_UNBLOCK ); }

    inline const unsigned char& getAllowSSO( void ) { return get( PARAMETER_KEY_ALLOW_SSO ); }

    inline const unsigned char& getOneCharForEachCharSet( void ) { return get( PARAMETER_KEY_ONE_OF_EACH_CHAR_SET ); }

    inline const unsigned char& getMandatoryCharSet( void ) { return get( PARAMETER_KEY_MANDATORY_CHAR_SET ); }

    inline const unsigned char& getMaxSequenceLen( void ) { return get( PARAMETER_KEY_MAX_SEQUENCE_LEN ); }

    inline const unsigned char& getMaxAdjacent( void ) { return get( PARAMETER_KEY_MAX_ADJACENT_NB ); }

    inline bool empty( void ) { BOOST_FOREACH( unsigned char& e, m_ucaPinPolicy ) { if( e ) { return false; } } return true; }

    void print( void );

    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {

        //Log::begin( "MiniDriverPinPolicy::serialize" );

        ar & m_ucRole;

        ar & m_ucaPinPolicy;

        //Log::log( "Role <%ld>", m_ucRole );
        //Log::logCK_UTF8CHAR_PTR( "Pin policy", m_ucaPinPolicy.c_array( ), m_ucaPinPolicy.size( ) );
        //Log::end( "MiniDriverPinPolicy::serialize" );
    }

protected:

    inline void reset( void ) { memset( m_ucaPinPolicy.c_array( ), 0, sizeof( m_ucaPinPolicy ) ); }

    inline void set( unsigned char const & a_ucParameterIndex, unsigned char const & a_ucParameterValue ) { m_ucaPinPolicy[ a_ucParameterIndex ] = a_ucParameterValue; }

    inline unsigned char & get( unsigned char const &a_ucParameterIndex ) { return m_ucaPinPolicy[ a_ucParameterIndex ]; }

    void write( void );

    CardModuleService* m_CardModule;

    boost::array< unsigned char, g_PolicyLenght > m_ucaPinPolicy;

    unsigned char m_ucRole;

};


BOOST_CLASS_VERSION( MiniDriverPinPolicy, 1 )


#endif // __GEMALTO_PIN_POLICY__
