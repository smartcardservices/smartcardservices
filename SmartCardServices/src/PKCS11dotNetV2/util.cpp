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

#include "stdafx.h"
#include "platconfig.h"
#include "config.h"
#include "digest.h"
#include "sha1.h"
#include "error.h"
#include "util.h"

R_RANDOM_STRUCT Util::_randomStruct;

void Util::SeedRandom(u1Array const & seed)
{
    InitRandomStruct(&_randomStruct);
    R_RandomUpdate(&_randomStruct, const_cast<unsigned char*>(seed.GetBuffer()), seed.GetLength());
}

R_RANDOM_STRUCT & Util::RandomStruct()
{
    return _randomStruct;
}

CK_ULONG Util::MakeULong(CK_BYTE_PTR buffer,CK_ULONG offset)
{
    return (CK_ULONG)(((CK_ULONG)buffer[offset] << 24) | ((CK_ULONG)buffer[offset+1] << 16) | ((CK_ULONG)buffer[offset+2] << 8) | buffer[offset+3]);
}

CK_BBOOL Util::CompareByteArrays(CK_BYTE_PTR abuffer,CK_BYTE_PTR bbuffer,CK_ULONG len)
{
    for(CK_ULONG i=0;i<len;i++){
        if(abuffer[i] != bbuffer[i])
            return CK_FALSE;
    }


    return CK_TRUE;
}

CK_BBOOL Util::CompareU1Arrays(u1Array* abuffer,CK_VOID_PTR bbuffer,CK_ULONG len)
{
    if((abuffer == NULL_PTR) && (bbuffer == NULL_PTR)){
        return CK_TRUE;
    }

    if((abuffer != NULL_PTR) && (bbuffer != NULL_PTR)){
        if(len == abuffer->GetLength()){
            return Util::CompareByteArrays(abuffer->GetBuffer(),(CK_BYTE_PTR)bbuffer,len);
        }
    }

    return CK_FALSE;
}


CK_BBOOL Util::CompareU4Arrays(u4Array* abuffer,CK_VOID_PTR bbuffer,CK_ULONG len)
{
    if((abuffer == NULL_PTR) && (bbuffer == NULL_PTR)){
        return CK_TRUE;
    }

    if((abuffer != NULL_PTR) && (bbuffer != NULL_PTR)){
        if(len == abuffer->GetLength()){
            return Util::CompareByteArrays((u1*)abuffer->GetBuffer(),(CK_BYTE_PTR)bbuffer,len);
        }
    }

    return CK_FALSE;
}

void Util::PushULongInVector(vector<u1>* to, CK_ULONG value)
{
    to->push_back((u1)(value >> 24));
    to->push_back((u1)(value >> 16));
    to->push_back((u1)(value >> 8));
    to->push_back((u1)(value));
}

void Util::PushULongLongInVector(vector<u1>* to, u8 value)
{
    to->push_back((u1)(value >> 56));
    to->push_back((u1)(value >> 48));
    to->push_back((u1)(value >> 40));
    to->push_back((u1)(value >> 32));
    to->push_back((u1)(value >> 24));
    to->push_back((u1)(value >> 16));
    to->push_back((u1)(value >> 8));
    to->push_back((u1)(value));
}

void Util::PushBBoolInVector(std::vector<u1>* to, CK_BBOOL value)
{
    // push the value
    to->push_back(value);
}

void Util::PushByteArrayInVector(std::vector<u1>* to, u1Array *value)
{
    if((value == NULL_PTR) || value->GetLength() == 0){
        to->push_back(0);
    }else{
        Util::PushLengthInVector(to,value->GetLength());
        for(u4 i=0;i<value->GetLength();i++){
            to->push_back(value->GetBuffer()[i]);
        }
    }
}

void Util::PushIntArrayInVector(std::vector<u1>* to, u4Array *value)
{
    if((value == NULL_PTR) || value->GetLength() == 0){
        to->push_back(0);
    }else{
        Util::PushLengthInVector(to,(value->GetLength() * 4));
        u1* buffer = (u1*)value->GetBuffer();
        for(u4 i=0;i<(value->GetLength() * 4);i++){
            to->push_back(buffer[i]);
        }
    }
}

u1Array* Util::ReadByteArrayFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG len = Util::ReadLengthFromVector(from,idx);

    if(len == 0){
        return NULL_PTR;
    }

    u1Array* val = new u1Array(len);

    for(u4 i=0;i<len;i++){
        val->SetU1At(i,from.at(*idx));
        *idx = *idx + 1;
    }

    return val;
}

u4Array* Util::ReadIntArrayFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG len = Util::ReadLengthFromVector(from,idx);

    if(len == 0){
        return NULL_PTR;
    }

    u4Array* val = new u4Array(len/4);

    for(u4 i=0;i<(len/4);i++){

        u1 a = from.at(*idx);
        u1 b = from.at(*idx + 1);
        u1 c = from.at(*idx + 2);
        u1 d = from.at(*idx + 3);

        // make an int
        u4 anInt = (u4)(((u4)a << 24) | ((u4)b << 16) | ((u4)c << 8) | d);

        val->SetU4At(i,anInt);

        *idx = *idx + 4;
    }

    return val;
}

void Util::PushLengthInVector(std::vector<u1>* to, CK_USHORT len)
{
    if(len < (CK_USHORT)0x80){
        to->push_back(len & 0x7F);
    }else if(len <= (CK_USHORT)0xFF){
        to->push_back(0x81);
        to->push_back(len & 0xFF);
    }else{
        to->push_back(0x82);
        to->push_back((u1)((len >> 8) & 0x00FF));
        to->push_back((u1)(len));
    }
}

CK_ULONG Util::ReadLengthFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_USHORT val = (CK_USHORT)from.at(*idx);

    if(val < (CK_USHORT)0x80){
        *idx = *idx + 1;
        return val;
    }else if(val == 0x81){
        *idx = *idx + 1;
        val = from.at(*idx);
        *idx = *idx + 1;
        return val;
    }else if(val == 0x82){
        *idx = *idx + 1;
        val = (u2)(((u2)from.at(*idx)) << 8);
        *idx = *idx + 1;
        val = val | (u2)from.at(*idx);
        *idx = *idx + 1;
        return val;
    }

    PKCS11_ASSERT(CK_FALSE);

    return 0;
}

CK_BBOOL Util::ReadBBoolFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_BBOOL val = (CK_BBOOL)from.at(*idx);
    *idx = *idx + 1;

    return val;
}

CK_ULONG Util::ReadULongFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG offset = *idx;

    CK_ULONG val = (CK_ULONG)(((CK_ULONG)from.at(offset) << 24) | ((CK_ULONG)from.at(offset+1) << 16) | ((CK_ULONG)from.at(offset+2) << 8) | from.at(offset+3));

    *idx = *idx + 4;

    return val;
}

u8 Util::ReadULongLongFromVector(std::vector<u1> from, CK_ULONG_PTR idx)
{
    CK_ULONG offset = *idx;

    u8 val = (u8)(((u8)from.at(offset  ) << 56) | ((u8)from.at(offset+1) << 48) |
                  ((u8)from.at(offset+2) << 40) | ((u8)from.at(offset+3) << 32) |
                  ((u8)from.at(offset+4) << 24) | ((u8)from.at(offset+5) << 16) |
                  ((u8)from.at(offset+6) <<  8) | from.at(offset+7));

    *idx = *idx + 8;

    return val;
}

void Util::ConvAscii(u1 *pIn, u4 dwLen,u1 *pOut)
{
   #define tohex(x)  (((x) >= 0xA) ? ((x) - 0xA + 'A') : ((x) + '0'))
   register u4 i;

   for(i=0; i < dwLen; i++)
   {
      pOut[i*2] = tohex((pIn[i] >> 4) & 0xF);
      pOut[i*2+1] =  tohex(pIn[i] & 0xF);
   }
   #undef tohex
}

char* Util::ItoA(s4 value, char* str, s4 radix)
{

#ifdef WIN32

    return _itoa(value,str,radix);

#else

    s4  rem = 0;
    s4  pos = 0;
    char ch  = '!' ;

    do
    {
        rem    = value % radix ;
        value /= radix;
        if ( 16 == radix )
        {
            if( rem >= 10 && rem <= 15 )
            {
                switch( rem )
                {
                    case 10:
                        ch = 'a' ;
                        break;
                    case 11:
                        ch ='b' ;
                        break;
                    case 12:
                        ch = 'c' ;
                        break;
                    case 13:
                        ch ='d' ;
                        break;
                    case 14:
                        ch = 'e' ;
                        break;
                    case 15:
                        ch ='f' ;
                        break;
                }
            }
        }
        if( '!' == ch )
        {
            str[pos++] = (char) ( rem + 0x30 );
        }
        else
        {
            str[pos++] = ch ;
        }
    }while( value != 0 );

    str[pos] = '\0' ;

    int i = strlen(str);
    int t = !(i%2)? 1 : 0;      // check the length of the string .

    for(int j = i-1 , k = 0 ; j > (i/2 -t) ; j-- )
    {
        char ch2  = str[j];
        str[j]   = str[k];
        str[k++] = ch2;
    }

    return str;

#endif

}

u8 Util::MakeCheckValue(const unsigned char * pBuf, unsigned int length)
{
    CSHA1 sha1;
    u1 hash[20];
    sha1.HashCore(const_cast<unsigned char *>(pBuf), 0, length);
    sha1.HashFinal(hash);
    u8 val = 0;
    for(size_t i = 0; i< sizeof(u8); ++i)
        val = (val << 8) | hash[i];
    return val;
}

u8 Util::MakeUniqueId()
{
    unsigned char buf[8];
    if(R_GenerateBytes(buf, 8, &_randomStruct))
        throw CkError(CKR_FUNCTION_FAILED);
    u8 * value = reinterpret_cast<u8*>(buf);
    return *value;
}

string Util::MakeIntString(unsigned int number, int width)
{
    if(width < 1)
        return string();
    char temp[16];
    sprintf(temp, "%011d", number);
    string s(temp);
    return s.substr(s.size()-width, width);
}
