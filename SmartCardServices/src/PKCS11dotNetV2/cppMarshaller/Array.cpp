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

#ifdef WIN32
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable:4201)
#endif

#include <string.h>
#include <winscard.h>
#include <stdexcept>
#include "MarshallerCfg.h"
#include "Except.h"
#include "Array.h"

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
MARSHALLER_NS_BEGIN


static u4 ToBigEndian(u4 val)
{
    if (isBigEndian)
    {
	    return val;
    }
    else
    {
        u4 res;
        res =  val << 24;
        res |= (val << 8) & 0x00FF0000;
        res |= (val >> 8) & 0x0000FF00;
        res |= val >> 24;

        return res;
    }
}

static u2 ToBigEndian(u2 val)
{
    if (isBigEndian)
    {
    	return val;
    }
    else
    {
        return (u2)((val << 8) | (val >> 8));
    }
}

static u8 ToBigEndian(u8 val)
{
    if (isBigEndian)
    {
    	return val;
    }
    else
    {
	    u4 val1 = (u4)(val >> 32);
	    u4 val2 = (u4)val;

        val1 = ToBigEndian(val1);
        val2 = ToBigEndian(val2);

	    return (u8)(((u8)val2 << 32) | val1);
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

        // Encode the character pair value.
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
    u1* bytes = utf8Data.GetBuffer();
    u4 byteCount;
    u4 byteIndex = 0;
    u4 charIndex = 0;

    byteCount = utf8Data.GetLength();

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

        // Encode the character pair value.
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
	if ((u8)(offset + len) > (u8)array.GetLength()) {
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
	if ((u8)(offset + len) > (u8)array.GetLength()) {
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
// String Array class
// *******************
StringArray::StringArray(s4 nelement)
{
    this->_length = nelement;

	if (nelement < 0) {
        nelement = 0;
    }

	this->buffer = new std::string*[nelement];

	// we need to initialize the buffer to zeros
	for(s4 i=0;i<nelement;i++)
		this->buffer[i] = NULL;

}

StringArray::StringArray(const StringArray &rhs)
{
	s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;
    }

	this->buffer = new std::string*[len];

	for(s4 i=0;i<len;i++)
		this->buffer[i] = rhs.buffer[i];

}

StringArray::~StringArray(void)
{
    // delete the strings in the StringArray
    for(u4 i = 0; i < GetLength(); i++){
        if (buffer[i] != NULL) {
            delete buffer[i];
            buffer[i] = NULL;
        }
    }

	delete[] buffer;
}

u1 StringArray::IsNull(void)
{
    return (this->_length < 0);
}

u4 StringArray::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

std::string* StringArray::GetStringAt(u4 index)
{
	if (index >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return this->buffer[index];
}

void StringArray::SetStringAt(u4 index, M_SAL_IN std::string* str)
{
	if (index >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
	this->buffer[index] = str;
}

// *******************
// Byte Array class
// *******************

u1Array::u1Array()
{
  this->_length = 0;
// JCD
  this->buffer = NULL;//new u1[0];
// JCD
}

u1Array::u1Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u1[nelement];
}

u1Array::u1Array(const u1Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;
    }
    this->buffer = new u1[len];
    memcpy(this->buffer, rhs.buffer, len);
}

u1Array::u1Array(u1Array &array, u4 offset, u4 len)
{
	if ((u8)(offset + len) > array.GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	} else {
		this->_length = len;
		this->buffer = new u1[len];
		memcpy(this->buffer, array.buffer + offset, len);
	}
}

u1Array::~u1Array(void)
{
    if (this->buffer != NULL) {
        delete[] this->buffer;
        this->buffer = NULL;
    }
}

u1 u1Array::IsNull(void) const
{
    return (this->_length < 0);
}

void u1Array::SetU1At(u4 pos, u1 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    this->buffer[pos] = val;
}


u1 u1Array::ReadU1At(u4 pos) const
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return this->buffer[pos];
}

u4 u1Array::GetLength(void) const
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u1Array::SetBuffer(const u1* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength());
}

const u1* u1Array::GetBuffer(void) const
{
    return this->buffer;
}

u1* u1Array::GetBuffer(void)
{
    return this->buffer;
}

// 1 byte add
u1Array& u1Array::operator +(u1 val)
{
    u1Array* newArray = new u1Array(this->GetLength() + sizeof(u1));
    memcpy(newArray->buffer, this->buffer, this->GetLength());
    memcpy(&newArray->buffer[this->GetLength()], &val, sizeof(u1));
    return *newArray;
}

u1Array& u1Array::operator +=(u1 val)
{
    u1* tempBuffer = new u1[this->GetLength() + sizeof(u1)];
    memcpy(tempBuffer, this->buffer, this->GetLength());
    memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u1));
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + sizeof(u1);
    return *this;
}

// 2 bytes add
u1Array& u1Array::operator +(u2 val)
{
    val = ToBigEndian(val);
    u1Array* newArray = new u1Array(this->GetLength() + sizeof(u2));
    memcpy(newArray->buffer, this->buffer, this->GetLength());
    memcpy(&newArray->buffer[this->GetLength()], &val, sizeof(u2));
    return *newArray;
}

u1Array& u1Array::operator +=(u2 val)
{
    val = ToBigEndian(val);
    u1* tempBuffer = new u1[this->GetLength() + sizeof(u2)];
    memcpy(tempBuffer, this->buffer, this->GetLength());
    memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u2));
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + sizeof(u2);
    return *this;
}

// 4 bytes add
u1Array& u1Array::operator +(u4 val)
{
    val = ToBigEndian(val);
    u1Array* newArray = new u1Array(this->GetLength() + sizeof(u4));
    memcpy(newArray->buffer, this->buffer, this->GetLength());
    memcpy(&newArray->buffer[this->GetLength()], &val, sizeof(u4));
    return *newArray;
}

u1Array& u1Array::operator +=(u4 val)
{
    val = ToBigEndian(val);
    u1* tempBuffer = new u1[this->GetLength() + sizeof(u4)];
    memcpy(tempBuffer, this->buffer, this->GetLength());
    memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u4));
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + sizeof(u4);
    return *this;
}

// 8 bytes add
u1Array& u1Array::operator +(u8 val)
{
	val = ToBigEndian(val);
    u1Array* newArray = new u1Array(this->GetLength() + sizeof(u8));
    memcpy(newArray->buffer, this->buffer, this->GetLength());
    memcpy(&newArray->buffer[this->GetLength()], &val, sizeof(u8));
    return *newArray;
}

u1Array& u1Array::operator +=(u8 val)
{
	val = ToBigEndian(val);
	u1* tempBuffer = new u1[this->GetLength() + sizeof(u8)];
    memcpy(tempBuffer, this->buffer, this->GetLength());
    memcpy(&tempBuffer[this->GetLength()], &val, sizeof(u8));
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + sizeof(u8);
    return *this;
}


// bytes array add
u1Array& u1Array::operator =(const u1Array &bArray)
{
    delete[] buffer; buffer = 0;
    _length = bArray._length;
    buffer = new u1[_length > 0 ? _length : 0];
    if(_length>0)
        memcpy(buffer, bArray.buffer, _length);
    return *this;
}

u1Array& u1Array::operator +(u1Array &bArray)
{
    s4 len;
    if (IsNull() && bArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + bArray.GetLength();
    }
    u1Array* newArray = new u1Array(len);
    memcpy(newArray->buffer, this->buffer, this->GetLength());
    memcpy(&newArray->buffer[this->GetLength()], bArray.buffer, bArray.GetLength());
    return *newArray;
}

u1Array& u1Array::operator +=(u1Array &bArray)
{
    u1* tempBuffer = new u1[this->GetLength() + bArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength());
    memcpy(&tempBuffer[this->GetLength()], bArray.buffer, bArray.GetLength());
    delete[] this->buffer;
    this->buffer = tempBuffer;
	if (IsNull() && bArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + bArray.GetLength();
    }
    return *this;
}

u1Array& u1Array::Append(std::string* str)
{
	if (str == NULL) {
        *this += (u2)0xFFFF;
    } else {
		u2 strLen = ComputeUTF8Length((lpCharPtr)str->c_str());
        *this += strLen;
        u1Array strArray(strLen);
		UTF8Encode((lpCharPtr)str->c_str(), strArray);
        *this += strArray;
    }
    return *this;
}

// *******************
// UShort Array class
// *******************
u2Array::u2Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u2[nelement];
}

u2Array::u2Array(const u2Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;
    }
    this->buffer = new u2[len];
    memcpy(this->buffer, rhs.buffer, len * sizeof(u2));
}

u2Array::~u2Array(void)
{
    delete[] this->buffer;
}

u1 u2Array::IsNull(void)
{
    return (this->_length < 0);
}

void u2Array::SetU2At(u4 pos, u2 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    this->buffer[pos] = val;
}

u2 u2Array::ReadU2At(u4 pos)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return this->buffer[pos];
}

u4 u2Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u2Array::SetBuffer(u2* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u2));
}

u2* u2Array::GetBuffer(void)
{
    return this->buffer;
}

// 2 bytes add
u2Array& u2Array::operator +(u2 val)
{
    u2Array* newArray = new u2Array(this->GetLength() + 1);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u2));
	newArray->buffer[this->GetLength()] = val;
    return *newArray;
}

u2Array& u2Array::operator +=(u2 val)
{
    u2* tempBuffer = new u2[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u2));
	tempBuffer[this->GetLength()] = val;
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + 1;
    return *this;
}

// Char array add
u2Array& u2Array::operator +(u2Array &cArray)
{
    s4 len;
	if (IsNull() && cArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + cArray.GetLength();
    }
    u2Array* newArray = new u2Array(len);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u2));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u2)], cArray.buffer, cArray.GetLength() * sizeof(u2));
    return *newArray;
}

u2Array& u2Array::operator +=(u2Array &cArray)
{
    u2* tempBuffer = new u2[this->GetLength() + cArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u2));
    memcpy(&tempBuffer[this->GetLength() * sizeof(u2)], cArray.buffer, cArray.GetLength() * sizeof(u2));
    delete[] this->buffer;
    this->buffer = tempBuffer;
	if (IsNull() && cArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + cArray.GetLength();
    }
    return *this;
}

// *******************
// Int Array class
// *******************
u4Array::u4Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u4[nelement];
}

u4Array::u4Array(const u4Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;
    }
    this->buffer = new u4[len];
    memcpy(this->buffer, rhs.buffer, len * sizeof(u4));
}

u4Array::~u4Array(void)
{
    delete[] this->buffer;
}

u1 u4Array::IsNull(void)
{
    return (this->_length < 0);
}

void u4Array::SetU4At(u4 pos, u4 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    this->buffer[pos] = val;
}

u4 u4Array::ReadU4At(u4 pos)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return this->buffer[pos];
}

u4 u4Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u4Array::SetBuffer(u4* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u4));
}

u4* u4Array::GetBuffer(void)
{
    return this->buffer;
}

// 4 bytes add
u4Array& u4Array::operator +(u4 val)
{
    u4Array* newArray = new u4Array(this->GetLength() + 1);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u4));
	newArray->buffer[this->GetLength()] = val;
    return *newArray;
}

u4Array& u4Array::operator +=(u4 val)
{
    u4* tempBuffer = new u4[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u4));
	tempBuffer[this->GetLength()] = val;
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + 1;
    return *this;
}

// UInt array add
u4Array& u4Array::operator +(u4Array &iArray)
{
    s4 len;
	if (IsNull() && iArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + iArray.GetLength();
    }
    u4Array* newArray = new u4Array(len);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u4));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u4)], iArray.buffer, iArray.GetLength() * sizeof(u4));
    return *newArray;
}

u4Array& u4Array::operator +=(u4Array &iArray)
{
    u4* tempBuffer = new u4[this->GetLength() + iArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u4));
    memcpy(&tempBuffer[this->GetLength() * sizeof(u4)], iArray.buffer, iArray.GetLength() * sizeof(u4));
    delete[] this->buffer;
    this->buffer = tempBuffer;
	if (IsNull() && iArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + iArray.GetLength();
    }
    return *this;
}


// *******************
// Long Array class
// *******************
u8Array::u8Array(s4 nelement)
{
	this->_length = nelement;
    if (nelement < 0) {
        nelement = 0;
    }
    this->buffer = new u8[nelement];
}

u8Array::u8Array(const u8Array &rhs)
{
    s4 len = rhs._length;
    this->_length = len;
    if (len < 0) {
        len = 0;
    }
    this->buffer = new u8[len];
    memcpy(this->buffer, rhs.buffer, len * sizeof(u8));
}

u8Array::~u8Array(void)
{
    delete[] this->buffer;
}

u1 u8Array::IsNull(void)
{
    return (this->_length < 0);
}

void u8Array::SetU8At(u4 pos, u8 val)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    this->buffer[pos] = val;
}

u8 u8Array::ReadU8At(u4 pos)
{
	if (pos >= GetLength()) {
		throw ArgumentOutOfRangeException((lpCharPtr)"");
	}
    return this->buffer[pos];
}

u4 u8Array::GetLength(void)
{
    if (IsNull()) {
        return (u4)0;
    } else {
        return (u4)this->_length;
    }
}

void u8Array::SetBuffer(u8* buffer)
{
    memcpy(this->buffer, buffer, this->GetLength() * sizeof(u8));
}

u8* u8Array::GetBuffer(void)
{
    return this->buffer;
}

u8Array& u8Array::operator +(u8 val)
{
    u8Array* newArray = new u8Array(this->GetLength() + 1);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u8));
	newArray->buffer[this->GetLength()] = val;
    return *newArray;
}

u8Array& u8Array::operator +=(u8 val)
{
    u8* tempBuffer = new u8[this->GetLength() + 1];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u8));
	tempBuffer[this->GetLength()] = val;
    delete[] this->buffer;
    this->buffer = tempBuffer;
    this->_length = this->GetLength() + 1;
    return *this;
}

u8Array& u8Array::operator +(u8Array &iArray)
{
    s4 len;
	if (IsNull() && iArray.IsNull()) {
        len = -1;
    } else {
        len = this->GetLength() + iArray.GetLength();
    }
    u8Array* newArray = new u8Array(len);
    memcpy(newArray->buffer, this->buffer, this->GetLength() * sizeof(u8));
    memcpy(&newArray->buffer[this->GetLength() * sizeof(u8)], iArray.buffer, iArray.GetLength() * sizeof(u8));
    return *newArray;
}

u8Array& u8Array::operator +=(u8Array &iArray)
{
    u8* tempBuffer = new u8[this->GetLength() + iArray.GetLength()];
    memcpy(tempBuffer, this->buffer, this->GetLength() * sizeof(u8));
    memcpy(&tempBuffer[this->GetLength() * sizeof(u8)], iArray.buffer, iArray.GetLength() * sizeof(u8));
    delete[] this->buffer;
    this->buffer = tempBuffer;
	if (IsNull() && iArray.IsNull()) {
        this->_length = -1;
    } else {
        this->_length = this->GetLength() + iArray.GetLength();
    }
    return *this;
}

MARSHALLER_NS_END

