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


#ifndef __GEMALTO_MINIDRIVER_CONTAINER_MAP_FILE__
#define __GEMALTO_MINIDRIVER_CONTAINER_MAP_FILE__


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/array.hpp>
#include <boost/array.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include "MiniDriverContainer.hpp"
#include "Array.hpp"
#include "CardModuleService.hpp"


const int g_MaxContainer = 15;


class MiniDriverFiles;


/*
*/
class MiniDriverContainerMapFile {

public:

    static unsigned char CONTAINER_INDEX_INVALID;

    typedef boost::array< MiniDriverContainer, g_MaxContainer > ARRAY_CONTAINERS;

    MiniDriverContainerMapFile( ) { }

    inline void setMiniDriverFiles( MiniDriverFiles* p ) { m_MiniDriverFiles = p; }

    void clear( void );

    void containerDelete( const unsigned char& );

    inline const MiniDriverContainer& containerGet( const unsigned char& a_ucContainerIndex ) { if( a_ucContainerIndex > m_Containers.size( ) ) { throw MiniDriverException( ); } return m_Containers[ a_ucContainerIndex ]; }

    void containerSearch( unsigned char& );

    inline const ARRAY_CONTAINERS& containerGet( void ) { return m_Containers; }

    void containerRead( void );

    void containerCreate( unsigned char&, const bool&, unsigned char&, Marshaller::u1Array*, const int&, Marshaller::u1Array* );

    void containerSetDefault( const unsigned char&, const bool& );

    bool containerGetMatching( unsigned char& a_ucContainerIndex, unsigned char& a_ucKeySpec, const Marshaller::u1Array* a_pPublicKeyModulus );

    inline unsigned char containerCount( void ) { return (unsigned char)m_Containers.size( ); }

    inline void containerSetTypeForSignatureKey( const unsigned char& a_ucContainerIndex, const unsigned char& a_ContainerTypeForSignatureKey ) { m_Containers[ a_ucContainerIndex ].setContainerTypeForSignatureKey( a_ContainerTypeForSignatureKey ); }

    inline void containerSetTypeForExchangeKey( const unsigned char& a_ucContainerIndex, const unsigned char& a_ContainerTypeForExchangeKey ) { m_Containers[ a_ucContainerIndex ].setContainerTypeForExchangeKey( a_ContainerTypeForExchangeKey ); }

    inline void containerSetPinIdentifier( const unsigned char& a_ucContainerIndex, const MiniDriverAuthentication::ROLES& a_ContainerPinIdentifier ) { m_Containers[ a_ucContainerIndex ].setPinIdentifier( a_ContainerPinIdentifier ); }

    inline bool containerIsImportedSignatureKey( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].isImportedSignatureKey( ); }

    inline bool containerIsImportedExchangeKey( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].isImportedExchangeKey( ); }

    inline MiniDriverAuthentication::ROLES containerGetPinIdentifier( const unsigned char& a_ucContainerIndex ) { return m_Containers[ a_ucContainerIndex ].getPinIdentifier( ); }

    unsigned char containerGetFree( void );
 
    void print( void );

private:

    std::string computeContainerName( const unsigned char* a_pBuffer, const size_t& a_BufferLength );

    void write( void );

    // Containers managed by the MiniDriver
    ARRAY_CONTAINERS m_Containers;

    Marshaller::u1Array m_ContainerMapFileBinary;

    MiniDriverFiles* m_MiniDriverFiles;

    // Disk serialization and deserialization
    friend class boost::serialization::access;

    template< class Archive > void serialize( Archive &ar, const unsigned int /*version*/ ) {

        //Log::begin( "MiniDriverContainerMapFile::serialize" );

        ar & m_Containers;
        //print( );

        ar & m_ContainerMapFileBinary;
        //Log::logCK_UTF8CHAR_PTR( "Container Map File Binary", m_ContainerMapFileBinary.GetBuffer( ), m_ContainerMapFileBinary.GetLength( ) );

        //Log::end( "MiniDriverContainerMapFile::serialize" );
    }

};

BOOST_CLASS_VERSION( MiniDriverContainerMapFile, 1 )


#endif // __GEMALTO_CARD_CACHE__
