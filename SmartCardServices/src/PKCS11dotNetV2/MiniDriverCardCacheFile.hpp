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


#ifndef __GEMALTO_MINIDRIVER_CARD_CACHE_FILE_
#define __GEMALTO_MINIDRIVER_CARD_CACHE_FILE_


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/shared_ptr.hpp>
#include "CardModuleService.hpp"


/*
*/
class MiniDriverCardCacheFile {

public:

    typedef enum { NONE = 0, PINS = 4, CONTAINERS = 8, FILES = 16 } ChangeType;

    inline MiniDriverCardCacheFile( ) { m_ucVersion = 0; m_ucPinsFreshness = 0; m_wContainersFreshness = 0; m_wFilesFreshness = 0; }

    inline void setCardModuleService( CardModuleService* const a_pMiniDriver ) { m_pCardModuleService = a_pMiniDriver; }

    void write( void ); 

    void notifyChange( const ChangeType& a_change );

    void hasChanged( ChangeType& a_Pins, ChangeType& a_Containers, ChangeType& a_Files );

    void print( void );

private:

    unsigned char m_ucVersion;

    unsigned char m_ucPinsFreshness;

    unsigned short m_wContainersFreshness;

    unsigned short m_wFilesFreshness;

    CardModuleService* m_pCardModuleService;

    // On computer disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {

        //Log::begin( "MiniDriverCardCacheFile::serialize" );

        ar & m_ucVersion;

        ar & m_ucPinsFreshness;

        ar & m_wContainersFreshness;

        ar & m_wFilesFreshness;

        //Log::log( "Version <%ld>", m_ucVersion );
        //Log::log( "Pins Freshness <%ld>", m_ucPinsFreshness );
        //Log::log( "Containers Freshness <%ld>", m_wContainersFreshness );
        //Log::log( "Files Freshness <%ld>", m_wFilesFreshness );

        //Log::end( "MiniDriverCardCacheFile::serialize" );
    }

};

BOOST_CLASS_VERSION( MiniDriverCardCacheFile, 1 )

#endif // __GEMALTO_MINIDRIVER_CARD_CACHE_FILE_
