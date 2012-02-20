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

#include <cstring>
#include <memory>
#ifdef WIN32
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable:4201)
#endif

#include "Array.hpp"

// Determine Processor Endianess
#include <limits.h>
#if (UINT_MAX == 0xffffffffUL)
   typedef unsigned int _u4;
#else
#  if (ULONG_MAX == 0xffffffffUL)
     typedef unsigned long _u4;
#  else
#    if (USHRT_MAX == 0xffffffffUL)
       typedef unsigned short _u4;
#    endif
#  endif
#endif

_u4 _endian = 1;

bool isLittleEndian = (*((unsigned char *)(&_endian))) ? true  : false;
bool isBigEndian    = (*((unsigned char *)(&_endian))) ? false : true;


const size_t g_sizeU1 = sizeof( u1 );
const size_t g_sizeU2 = sizeof( u2 );
const size_t g_sizeU4 = sizeof( u4 );
const size_t g_sizeU8 = sizeof( u8 );


MARSHALLER_NS_BEGIN


static u4 ToBigEndian(u4 v)
{
    if (isBigEndian)
    {
	    return v;
    }
    else
    {
        u4 res;
        res =  v << 24;
        res |= (v << 8) & 0x00FF0000;
        res |= (v >> 8) & 0x0000FF00;
        res |= v >> 24;

        return res;
    }
}

static u2 ToBigEndian(u2 v)
{
    if (isBigEndian)
    {
    	return v;
    }
    else
    {
        return (u2)((v << 8) | (v >> 8));
    }
}

static u8 ToBigEndian(u8 v)
{
    if (isBigEndian)
    {
    	return v;
    }
    else
    {
	    u4 v1 = (u4)(v >> 32);
	    u4 v2 = (u4)v;

        v1 = ToBigEndian(v1);
        v2 = ToBigEndian(v2);

	    return (u8)(((u8)v2 << 32) | v1);
    }
}

u2 ComputeUTF8Length(M_SAL_IN lpCharPtr str)
{
    u4 nCharProcessed = 0;
    u4 pair;
    u4 count;
    u2 leftOver;
    u4 charIndex;

    count = 0;
    leftOver = 0;
    charIndex = 0;

    while (nCharProcessed < (u4)strlen(str)) {
        u2 ch = (u2)str[charIndex++];

        if (leftOver == 0) {
			if ((ch >= 0xD800) && (ch <= 0xDBFF)) {
				// This is a low-part of a surrogate pair.
				leftOver = (u2)ch;
                nCharProcessed++;
				continue;
			} else {
				// This is a regular character.
				pair = (u4)ch;
			}
		} else if ((ch >= 0xDC00) && (ch <= 0xDFFF)) {
			// This is a high-part of a surrogate pair. We now have a complete surrogate pair.
			pair = ((leftOver - (u4)0xD800) << 10) + (((u4)ch) - (u4)0xDC00) + (u4)0x10000;
			leftOver = 0;
		} else {
            goto error;
		}

        // Encode the character pair vue.
		if (pair < (u4)0x0080) {
            count++;
		} else if (pair < (u4)0x0800) {
            count += 2;
		} else if (pair < (u4)0x10000) {
            count += 3;
		} else {
            count += 4;
		}

        nCharProcessed++;
    }

    if (leftOver != 0) {
        goto error;
    }

	return (u2)count;

error:;
    throw Exception("Error while compute UTF8 encoding length");
}

void UTF8Encode(M_SAL_IN lpCharPtr str, u1Array &utf8Data)
{
    u4 nCharProcessed = 0;
    u4 pair;
    u2 leftOver;
    u1* bytes = utf8Data.GetBuffer( );
    u4 byteCount;
    u4 byteIndex = 0;
    u4 charIndex = 0;

    byteCount = utf8Data.GetLength( );

    leftOver = 0;

    while (nCharProcessed < (u4)strlen(str)) {
        u2 ch = str[charIndex++];

        if (leftOver == 0) {
			if ((ch >= 0xD800) && (ch <= 0xDBFF)) {
				// This is a low-part of a surrogate pair.
				leftOver = (u2)ch;
                nCharProcessed++;
				continue;
			} else {
				// This is a regular character.
				pair = (u4)ch;
			}
		} else if ((ch >= 0xDC00) && (ch <= 0xDFFF)) {
			// This is a high-part of a surrogate pair. We now have a complete surrogate pair.
			pair = ((leftOver - (u4)0xD800) << 10) + (((u4)ch) - (u4)0xDC00) + (u4)0x10000;
			leftOver = 0;
		} else {
            goto error;
		}

        // Encode the character pair vue.
		if (pair < (u4)0x0080) {
            if (byteIndex >= byteCount) {
                goto end;
			}
            bytes[byteIndex++] = (u1)pair;
		} else if (pair < (u4)0x0800) {
            if ((byteIndex + 2) > byteCount) {
                goto end;
			}
            bytes[byteIndex++] = (u1)(0xC0 | (pair >> 6));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));
		} else if (pair < (u4)0x10000) {
            if ((byteIndex + 3) > byteCount) {
                goto end;
			}
            bytes[byteIndex++] = (u1)(0xE0 | (pair >> 12));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 6) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));
		} else {
            if ((byteIndex + 4) > byteCount) {
                goto end;
			}
            bytes[byteIndex++] = (u1)(0xF0 | (pair >> 18));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 12) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | ((pair >> 6) & 0x3F));
			bytes[byteIndex++] = (u1)(0x80 | (pair & 0x3F));
		}

        nCharProcessed++;
    }

end:;
    // we do accept byteIndex <= byteCount (dest buffer length > what is really necessary).
    if (byteIndex > byteCount) {
        goto error;
    }

    if (leftOver != 0) {
        goto error;
    }

    return;

error:;
    throw Exception("Error while performing UTF8 encoding");
}

u2 ComputeLPSTRLength(u1Array &array, u4 offset, u4 len)
{
	if ((u8)(offset + len) > (u8)array.GetLength( ) ) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	} else {
		u2 charlen = 0;
		u4 i;
		u1* buff = array.GetBuffer();

		for (i = 0; i < len;) {
			if ((buff[i + offset] & 0x80) == 0) {
				i += 1;
			}
			else if ((buff[i + offset] & 0xE0) == 0xC0) {
				i += 2;
			}
			else if ((buff[i + offset] & 0xF0) == 0xE0) {
				i += 3;
			}
			else {
				throw Exception("Error parsing UTF-8 bytes");
			}
			charlen++;
		}
		return charlen;
	}
}

void UTF8Decode(u1Array &array, u4 offset, u4 len, M_SAL_INOUT lpCharPtr &charData)
{
	if ((u8)(offset + len) > (u8)array.GetLength( )) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	} else {
		u4 i = 0;
		u4 pos = 0;
		u1* buff = array.GetBuffer();

		for (i = 0; i < len;) {
			if ((buff[i + offset] & 0x80) == 0) {
				charData[pos] = buff[i + offset];
				i += 1;
			}
			else if ((buff[i + offset] & 0xE0) == 0xC0) {
				charData[pos] = ((buff[i + offset] & 0x1F) << 6) | (buff[i+1 + offset] & 0x3F);
				i += 2;
			}
			else if ((buff[i + offset] & 0xF0) == 0xE0) {
				charData[pos] = ((buff[i + offset] & 0x0F) << 12) | ((buff[i+1 + offset] & 0x3F) << 6) | (buff[i+2 + offset] & 0x3F);
				i += 3;
			}
			else{
				throw Exception("Error parsing UTF-8 bytes");
			}
			pos++;
		}
	}
}




// *******************
// Byte Array class
// *******************


/* 1 byte add
*/
u1Array& u1Array::operator +( const u1& v ) {

    u1Array* newArray = new u1Array( _length + g_sizeU1 );

    memcpy( newArray->buffer, buffer, _length );
    
    memcpy( &newArray->buffer[ _length ], &v, g_sizeU1 );
    
    return *newArray;
}


/*
*/
u1Array& u1Array::operator +=( const u1& v ) {

    u1* t = new u1[ _length + g_sizeU1 ];

    memcpy( t, buffer, _length );
    
    memcpy(&t[ _length ], &v, g_sizeU1 );
    
    delete[ ] buffer;
    
    buffer = t;
    
    _length += g_sizeU1;
    
    return *this;
}


/* 2 bytes add
*/
u1Array& u1Array::operator +( const u2& v ) {

    u2 vbe = ToBigEndian( v );

    u1Array* newArray = new u1Array( _length + g_sizeU2 );
    
    memcpy( newArray->buffer, buffer, _length );
    
    memcpy( &newArray->buffer[ _length ], &vbe, g_sizeU2 );
    
    return *newArray;
}


/*
*/
u1Array& u1Array::operator +=( const u2& v ) {

    u2 vbe = ToBigEndian( v );
    
    u1* t = new u1[ _length + g_sizeU2 ];

    memcpy( t, buffer, _length );

    memcpy( &t[ _length ], &vbe, g_sizeU2 );
    
    delete[] buffer;
    
    buffer = t;
    
    _length += g_sizeU2;
    
    return *this;
}


/* 4 bytes add
*/
u1Array& u1Array::operator +( const u4& v ) {

    u4 vbe = ToBigEndian( v );

    u1Array* a = new u1Array( _length + g_sizeU4 );
    
    memcpy( a->buffer, buffer, _length );
    
    memcpy( &a->buffer[ _length ], &vbe, g_sizeU4 );
    
    return *a;
}


/*
*/
u1Array& u1Array::operator +=(const u4& v ) {

    u4 vbe = ToBigEndian( v );

    u1* t = new u1[ _length + g_sizeU4 ];
    
    memcpy( t, buffer, _length );

    memcpy( &t[ _length ], &vbe, g_sizeU4);

    delete[ ] buffer;

    buffer = t;

    _length += g_sizeU4;

    return *this;
}


/* 8 bytes add
*/
u1Array& u1Array::operator +( const u8& v ) {

	u8 vbe = ToBigEndian( v );

    u1Array* n = new u1Array( _length + g_sizeU8 );
    
    memcpy( n->buffer, buffer, _length );

    memcpy( &n->buffer[ _length ], &vbe, g_sizeU8 );

    return *n;
}


/*
*/
u1Array& u1Array::operator +=(const u8& v ) {

	u8 vbe = ToBigEndian( v );

	u1* t = new u1[ _length + g_sizeU8 ];
    
    memcpy( t, buffer, _length);
    
    memcpy( &t[ _length ], &vbe, g_sizeU8 );
    
    delete[ ] buffer;
    
    buffer = t;
    
    _length += g_sizeU8;
    
    return *this;
}


/* bytes array add
*/
u1Array& u1Array::operator =( const u1Array& a ) {

    delete[ ] buffer; 
    
    _length = a._length;
    
    buffer = new u1[ _length ];

    memcpy( buffer, a.buffer, _length );

    return *this;
}


/*
*/
u1Array& u1Array::operator +( const u1Array& a ) {
    
    u1Array* n = new u1Array( _length + a._length );
    
    memcpy( n->buffer, buffer, _length );
    
    memcpy( &n->buffer[ _length ], a.buffer, a._length );
    
    return *n;
}


/*
*/
u1Array& u1Array::operator +=( const u1Array& a ) {

    u1* t = new u1[ _length + a._length ];

    memcpy( t, buffer, _length );
    
    memcpy( &t[ _length ], a.buffer, a._length );

    delete[ ] buffer;

    buffer = t;
	
    _length += a._length;

    return *this;
}


/*
*/
u1Array& u1Array::Append( std::string* s ) {

	if( !s ) {

        *this += (u2)0xFFFF; // ?????
    
    } else {
	
        u2 strLen = ComputeUTF8Length( (lpCharPtr)s->c_str( ) );
        
        *this += strLen;
        
        u1Array strArray( strLen );
		
        UTF8Encode( (lpCharPtr)s->c_str( ), strArray );
        
        *this += strArray;
    }

    return *this;
}



/*
*/
u1Array& u1Array::Append( const char * s ) {

	if( !s ) {

        *this += (u2)0xFFFF; // ?????
    
    } else {
	
        u2 strLen = strlen(s);
        
        *this += strLen;
        
        u1Array strArray( strLen );
		
        UTF8Encode( (char *)s, strArray );
        
        *this += strArray;
    }

    return *this;
}






// *******************
// UShort Array class
// *******************
u2Array::u2Array(s4 nelement)
{
	_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    buffer = new u2[nelement];
}

u2Array::u2Array(const u2Array &rhs)
{
    s4 len = rhs._length;
    _length = len;
    if (len < 0) {
        len = 0;
    }
    buffer = new u2[len];
    memcpy(buffer, rhs.buffer, len * g_sizeU2);
}

u2Array::~u2Array(void)
{
    delete[] buffer;
}

u1 u2Array::IsNull(void)
{
    return (_length < 0);
}

void u2Array::SetU2At(u4 pos, u2 v)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    buffer[pos] = v;
}

u2 u2Array::ReadU2At(u4 pos)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return buffer[pos];
}

u4 u2Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)_length;
    }
}

void u2Array::SetBuffer(u2* a_buffer)
{
    memcpy(buffer, a_buffer, _length * g_sizeU2);
}

u2* u2Array::GetBuffer(void)
{
    return buffer;
}

// 2 bytes add
u2Array& u2Array::operator +(u2 v)
{
    u2Array* newArray = new u2Array(_length + 1);
    memcpy(newArray->buffer, buffer, _length * g_sizeU2);
	newArray->buffer[_length] = v;
    return *newArray;
}

u2Array& u2Array::operator +=(u2 v)
{
    u2* tempBuffer = new u2[_length + 1];
    memcpy(tempBuffer, buffer, _length * g_sizeU2);
	tempBuffer[_length] = v;
    delete[] buffer;
    buffer = tempBuffer;
    _length = _length + 1;
    return *this;
}

// Char array add
u2Array& u2Array::operator +(u2Array &cArray)
{
    s4 len;
	if (IsNull() && cArray.IsNull()) {
        len = -1;
    } else {
        len = _length + cArray._length;
    }
    u2Array* newArray = new u2Array(len);
    memcpy(newArray->buffer, buffer, _length * g_sizeU2);
    memcpy(&newArray->buffer[_length * g_sizeU2], cArray.buffer, cArray._length * g_sizeU2);
    return *newArray;
}

u2Array& u2Array::operator +=(u2Array &cArray)
{
    u2* tempBuffer = new u2[_length + cArray._length];
    memcpy(tempBuffer, buffer, _length * g_sizeU2);
    memcpy(&tempBuffer[_length * g_sizeU2], cArray.buffer, cArray._length * g_sizeU2);
    delete[] buffer;
    buffer = tempBuffer;
	if (IsNull() && cArray.IsNull()) {
        _length = -1;
    } else {
        _length = _length + cArray._length;
    }
    return *this;
}

// *******************
// Int Array class
// *******************
u4Array::u4Array(s4 nelement)
{
	_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    buffer = new u4[nelement];
}

u4Array::u4Array(const u4Array &rhs)
{
    s4 len = rhs._length;
    _length = len;
    if (len < 0) {
        len = 0;
    }
    buffer = new u4[len];
    memcpy(buffer, rhs.buffer, len * g_sizeU4);
}

u4Array::~u4Array(void)
{
    delete[] buffer;
}

u1 u4Array::IsNull(void)
{
    return (_length < 0);
}

void u4Array::SetU4At(u4 pos, u4 v)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    buffer[pos] = v;
}

u4 u4Array::ReadU4At(u4 pos)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return buffer[pos];
}

u4 u4Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)_length;
    }
}

void u4Array::SetBuffer(u4* a_buffer)
{
    memcpy(buffer, a_buffer, _length * g_sizeU4);
}

u4* u4Array::GetBuffer(void)
{
    return buffer;
}

// 4 bytes add
u4Array& u4Array::operator +(u4 v)
{
    u4Array* newArray = new u4Array(_length + 1);
    memcpy(newArray->buffer, buffer, _length * g_sizeU4);
	newArray->buffer[_length] = v;
    return *newArray;
}

u4Array& u4Array::operator +=(u4 v)
{
    u4* tempBuffer = new u4[_length + 1];
    memcpy(tempBuffer, buffer, _length * g_sizeU4);
	tempBuffer[_length] = v;
    delete[] buffer;
    buffer = tempBuffer;
    _length = _length + 1;
    return *this;
}

// UInt array add
u4Array& u4Array::operator +(u4Array &iArray)
{
    s4 len;
	if (IsNull() && iArray.IsNull()) {
        len = -1;
    } else {
        len = _length + iArray._length;
    }
    u4Array* newArray = new u4Array(len);
    memcpy(newArray->buffer, buffer, _length * g_sizeU4);
    memcpy(&newArray->buffer[_length * g_sizeU4], iArray.buffer, iArray._length * g_sizeU4);
    return *newArray;
}

u4Array& u4Array::operator +=(u4Array &iArray)
{
    u4* tempBuffer = new u4[_length + iArray._length];
    memcpy(tempBuffer, buffer, _length * g_sizeU4);
    memcpy(&tempBuffer[_length * g_sizeU4], iArray.buffer, iArray._length * g_sizeU4);
    delete[] buffer;
    buffer = tempBuffer;
	if (IsNull() && iArray.IsNull()) {
        _length = -1;
    } else {
        _length = _length + iArray._length;
    }
    return *this;
}


// *******************
// Long Array class
// *******************
u8Array::u8Array(s4 nelement)
{
	_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    buffer = new u8[nelement];
}

u8Array::u8Array(const u8Array &rhs)
{
    s4 len = rhs._length;
    _length = len;
    if (len < 0) {
        len = 0;
    }
    buffer = new u8[len];
    memcpy(buffer, rhs.buffer, len * g_sizeU8);
}

u8Array::~u8Array(void)
{
    delete[] buffer;
}

u1 u8Array::IsNull(void)
{
    return (_length < 0);
}

void u8Array::SetU8At(u4 pos, u8 v)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    buffer[pos] = v;
}

u8 u8Array::ReadU8At(u4 pos)
{
	if (pos >= (u4)_length) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return buffer[pos];
}

u4 u8Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)_length;
    }
}

void u8Array::SetBuffer(u8* a_buffer)
{
    memcpy(buffer, a_buffer, _length * g_sizeU8);
}

u8* u8Array::GetBuffer(void)
{
    return buffer;
}

u8Array& u8Array::operator +(u8 v)
{
    u8Array* newArray = new u8Array(_length + 1);
    memcpy(newArray->buffer, buffer, _length * g_sizeU8);
	newArray->buffer[_length] = v;
    return *newArray;
}

u8Array& u8Array::operator +=(u8 v)
{
    u8* tempBuffer = new u8[_length + 1];
    memcpy(tempBuffer, buffer, _length * g_sizeU8);
	tempBuffer[_length] = v;
    delete[] buffer;
    buffer = tempBuffer;
    _length = _length + 1;
    return *this;
}

u8Array& u8Array::operator +(u8Array &iArray)
{
    s4 len;
	if (IsNull() && iArray.IsNull()) {
        len = -1;
    } else {
        len = _length + iArray._length;
    }
    u8Array* newArray = new u8Array(len);
    memcpy(newArray->buffer, buffer, _length * g_sizeU8);
    memcpy(&newArray->buffer[_length * g_sizeU8], iArray.buffer, iArray._length * g_sizeU8);
    return *newArray;
}

u8Array& u8Array::operator +=(u8Array &iArray)
{
    u8* tempBuffer = new u8[_length + iArray._length];
    memcpy(tempBuffer, buffer, _length * g_sizeU8);
    memcpy(&tempBuffer[_length * g_sizeU8], iArray.buffer, iArray._length * g_sizeU8);
    delete[] buffer;
    buffer = tempBuffer;
	if (IsNull() && iArray.IsNull()) {
        _length = -1;
    } else {
        _length = _length + iArray._length;
    }
    return *this;
}

MARSHALLER_NS_END

