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

#ifndef _include_marshaller_array_h
#define _include_marshaller_array_h

MARSHALLER_NS_BEGIN

class SMARTCARDMARSHALLER_DLLAPI StringArray
{

private:
	std::string** buffer;
    s4 _length;

public:
    StringArray(s4 nelement);
    StringArray(const StringArray &rhs);
    ~StringArray(void);

    u1 IsNull(void);
    u4 GetLength(void);

	std::string* GetStringAt(u4 index);
	void  SetStringAt(u4 index,M_SAL_IN std::string* str);
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
    u1* buffer;
    s4 _length;

public:
    u1Array();
    u1Array(s4 nelement);
    u1Array(const u1Array &rhs);
	u1Array(u1Array &array, u4 offset, u4 len);
    ~u1Array(void);

    u1  IsNull(void) const;
    u4  GetLength(void) const;

    void  SetBuffer(const u1* buffer);
    const u1*  GetBuffer(void) const;
    u1*  GetBuffer(void);

    u1   ReadU1At(u4 pos) const;
	void SetU1At(u4 pos, u1 val);

	u1Array& Append(std::string* str);

    u1Array& operator +(u1 val);
    u1Array& operator +=(u1 val);
    u1Array& operator +(u2 val);
    u1Array& operator +=(u2 val);
    u1Array& operator +(u4 val);
    u1Array& operator +=(u4 val);
	u1Array& operator +(u8 val);
    u1Array& operator +=(u8 val);
    u1Array& operator =(const u1Array &bArray);
    u1Array& operator +(u1Array &bArray);
    u1Array& operator +=(u1Array &bArray);
};

extern u2 ComputeUTF8Length(M_SAL_IN lpCharPtr str);
extern void UTF8Encode(M_SAL_IN lpCharPtr str, u1Array &utf8Data);
extern u2 ComputeLPSTRLength(u1Array &array, u4 offset, u4 len);
extern void UTF8Decode(u1Array &array, u4 offset, u4 len, M_SAL_INOUT lpCharPtr &charData);

MARSHALLER_NS_END

#endif

