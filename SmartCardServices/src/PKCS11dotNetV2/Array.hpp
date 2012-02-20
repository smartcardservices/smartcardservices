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


#ifndef __GEMALTO_ARRAY__
#define __GEMALTO_ARRAY__


#include <string>
#include <string.h>
#include <vector>
#include <boost/serialization/split_member.hpp>
#include <boost/serialization/version.hpp>
#include "MarshallerCfg.h"
#include "Except.h"


MARSHALLER_NS_BEGIN


/*
*/
class SMARTCARDMARSHALLER_DLLAPI StringArray
{

private:
	
    std::string** buffer;
	
    unsigned int _length;

public:
	
    inline StringArray( ) { _length = 0; buffer = NULL; }

    inline StringArray( const unsigned int& n ) { _length = n; buffer = new std::string*[ _length ]; for( unsigned int i = 0 ; i < _length ; ++i ) { buffer[ i ] = NULL; } }

    inline StringArray( const StringArray& a ) { _length = a._length; buffer = new std::string*[ _length ]; for( unsigned int i = 0 ; i < _length ; ++i ) { buffer[ i ] = a.buffer[ i ]; } }

    inline virtual ~StringArray( ) { for( unsigned int i = 0 ; i < _length; ++i ) { delete buffer[ i ]; } delete[ ] buffer; }

   	inline bool IsNull( void ) const { return !_length; }

    inline unsigned int GetLength( void ) const { return _length; }
 
	inline std::string* GetStringAt( const unsigned int& i ) { if( i >= _length ) { throw ArgumentOutOfRangeException((lpCharPtr)""); } return buffer[ i ]; }

    inline void SetStringAt( const unsigned int& i, std::string* s ) { if( i >= _length ) { throw ArgumentOutOfRangeException((lpCharPtr)""); } buffer[ i ] = s; }

};





#define s8Array u8Array
class SMARTCARDMARSHALLER_DLLAPI u8Array
{

private:
	u8* buffer;
	s4 _length;

public:
	u8Array(s4 nelement);
	u8Array(const u8Array &rhs);
	~u8Array(void);

	u1 IsNull(void);
	u4 GetLength(void);

	void  SetBuffer(u8* buffer);
	u8*   GetBuffer(void);

	u8 ReadU8At(u4 pos);
	void SetU8At(u4 pos, u8 val);

	u8Array& operator +(u8 val);
	u8Array& operator +=(u8 val);
	u8Array& operator +(u8Array &cArray);
	u8Array& operator +=(u8Array &cArray);

};






#define s4Array u4Array
class SMARTCARDMARSHALLER_DLLAPI u4Array
{

private:
	u4* buffer;
	s4 _length;

public:
	u4Array(s4 nelement);
	u4Array(const u4Array &rhs);
	~u4Array(void);

	u1 IsNull(void);
	u4 GetLength(void);

	void  SetBuffer(u4* buffer);
	u4*   GetBuffer(void);

	u4 ReadU4At(u4 pos);
	void SetU4At(u4 pos, u4 val);

	u4Array& operator +(u4 val);
	u4Array& operator +=(u4 val);
	u4Array& operator +(u4Array &cArray);
	u4Array& operator +=(u4Array &cArray);
};





#define s2Array u2Array
#define charArray u2Array
class SMARTCARDMARSHALLER_DLLAPI u2Array
{

private:
	u2* buffer;
	s4 _length;

public:
	u2Array(s4 nelement);
	u2Array(const u2Array &rhs);
	~u2Array(void);

	u1    IsNull(void);
	u4    GetLength(void);

	void  SetBuffer(u2* buffer);
	u2*   GetBuffer(void);

	u2    ReadU2At(u4 pos);
	void  SetU2At(u4 pos, u2 val);

	u2Array& operator +(u2 val);
	u2Array& operator +=(u2 val);
	u2Array& operator +(u2Array &cArray);
	u2Array& operator +=(u2Array &cArray);
};





#define s1Array u1Array
#define MemoryStream u1Array
class SMARTCARDMARSHALLER_DLLAPI u1Array
{

private:
	
    unsigned char* buffer;

	unsigned int _length;

public:
	
    inline u1Array( ) { _length = 0; buffer = 0; }

	inline u1Array( const unsigned int& n ) { _length = n; buffer = new unsigned char[ _length ]; memset( buffer, 0, _length ); }

    inline u1Array( const u1Array& a ) { _length = a._length; buffer = new unsigned char[ _length ]; memcpy( buffer, a.buffer, _length ); }

    inline u1Array( const u1Array &a, const unsigned int& o, const unsigned int& l ) { if( (o + l) > a.GetLength( ) ) { throw ArgumentOutOfRangeException((lpCharPtr)" u1Array constructor (1)"); } _length = l; buffer = new unsigned char[ _length ]; memcpy( buffer, a.buffer + o, _length ); }

    inline u1Array( const std::vector< unsigned char >& a ) { _length = a.size( ); buffer = new unsigned char[ _length ]; for( unsigned int i = 0 ; i < _length ; ++i ) { buffer[ i ] = a.at( i ); } }

	inline virtual ~u1Array( ) { delete[ ] buffer; }

	inline bool IsNull( void ) const { return !_length; }

    inline unsigned int GetLength( void ) const { return _length; }
    
    inline void SetBuffer( const unsigned char* b ) { if( b ) { memcpy( buffer, b, _length ); } }

	inline unsigned char ReadU1At( const unsigned int& p ) const { if( p >= _length ) { throw ArgumentOutOfRangeException((lpCharPtr)"u1Array::ReadU1At"); } return buffer[ p ]; }

    inline void SetU1At( const unsigned int& p, const unsigned char& v ) { if( p >= _length ) { throw ArgumentOutOfRangeException((lpCharPtr)"u1Array::SetU1At"); } buffer[ p ] = v; }

	u1Array& Append( std::string* );

	u1Array& Append( const char* );

    inline unsigned char* GetBuffer( void ) { return buffer; }

    inline const unsigned char* GetBuffer( void ) const { return buffer; }

    u1Array& operator +( const unsigned char& );

	u1Array& operator +=( const unsigned char& );

	u1Array& operator +( const u2& );

	u1Array& operator +=( const u2& );

	u1Array& operator +( const u4& );

	u1Array& operator +=( const u4& );

	u1Array& operator +( const u8& );

	u1Array& operator +=( const u8& );

	u1Array& operator =( const u1Array& );

	u1Array& operator +( const u1Array& );

	u1Array& operator +=( const u1Array& );

	inline void reset( void ) { delete[ ] buffer; buffer = NULL; _length = 0; }

    inline void reset( unsigned int a_uiLength ) { delete[ ] buffer; _length = a_uiLength; buffer = new unsigned char[ a_uiLength ]; memset( buffer, 0, _length ); }

    inline void reset( Marshaller::u1Array* a_pArray ) { delete[ ] buffer; _length = 0; if( a_pArray ) { _length = a_pArray->_length; buffer = new unsigned char[ _length ]; memcpy( buffer, a_pArray->buffer, _length ); } }

	// Boost serialization of the array

	friend class boost::serialization::access;

	template< class Archive > void save( Archive& ar, const unsigned int /*version*/ ) const {

		ar << _length;

		//Log::log( "Array::save - length <%ld>", _length );

		ar.save_binary( buffer, _length );

        //Log::logCK_UTF8CHAR_PTR( "Array::save - buffer", buffer, _length );
	}

	template< class Archive > void load( Archive& ar, const unsigned int /*version*/ ) {

		ar >> _length;
		        
        //Log::log( "Array::load - length <%ld>", _length );
        buffer = 0;

        if( _length > 0 ) {

		    buffer = new unsigned char[ _length ];
		
		    ar.load_binary( buffer, _length );
        }

        //Log::logCK_UTF8CHAR_PTR( "Array::load - buffer", buffer, _length );
	}

	BOOST_SERIALIZATION_SPLIT_MEMBER( )
};


extern u2 ComputeUTF8Length(M_SAL_IN lpCharPtr str);

extern void UTF8Encode(M_SAL_IN lpCharPtr str, u1Array &utf8Data);

extern u2 ComputeLPSTRLength(u1Array &array, u4 offset, u4 len);

extern void UTF8Decode(u1Array &array, u4 offset, u4 len, M_SAL_INOUT lpCharPtr &charData);

MARSHALLER_NS_END

BOOST_CLASS_VERSION( Marshaller::u1Array, 1 )

#endif // __GEMALTO_ARRAY__
