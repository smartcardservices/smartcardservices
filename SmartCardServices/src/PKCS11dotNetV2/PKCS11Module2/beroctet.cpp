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

// This implementation is based on X.690 specification. Access to this
// specification is a pre-requisite to understand the logic. The spec
// can be purchased from International Telecommunication Union (ITU)
// at http://www.itu.int

// This code is based on class in ACS baseline.

#include <string.h>
#include <stdlib.h>
#include "beroctet.h"

using namespace std;

BEROctet::BEROctet() : m_tcClass(tcUniversal),
                       m_fConstructed(fBerPcPrimitive),
                       m_dwTag(dwBerUnivZero),
                       m_fDefinite(true),
                       m_fModified(true)
{
}

BEROctet::BEROctet(BEROctet const &oct)
{
    *this = oct;
}

BEROctet::BEROctet(Blob const &blb)
{
    Decode(blb);
}

BEROctet::BEROctet(TagClass tcClass, bool fConstructed, unsigned int dwTag, bool fDefinite) :
                                                                       m_tcClass(tcClass),
                                                                       m_fConstructed(fConstructed),
                                                                       m_dwTag(dwTag),
                                                                       m_fDefinite(fDefinite),
                                                                       m_fModified(true)
{
    if(!m_fDefinite && !m_fConstructed)
        throw runtime_error("BERPrimitiveIndefiniteLength");
}

BEROctet::~BEROctet(void)
{
    for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
        delete m_SubOctetList[i];
}

BEROctet& BEROctet::operator=(BEROctet const &Oct)
{

    for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
        delete m_SubOctetList[i];

    m_SubOctetList.resize(0);
    m_blbData.resize(0);

    m_fModified    = Oct.m_fModified;
    m_blbOrigOctet = Oct.m_blbOrigOctet;

    m_fConstructed = Oct.m_fConstructed;
    m_tcClass      = Oct.m_tcClass;
    m_dwTag        = Oct.m_dwTag;
    m_fDefinite    = Oct.m_fDefinite;


    if(m_fConstructed)
    {
        for(std::vector<BEROctet const*>::size_type i=0; i<Oct.m_SubOctetList.size(); i++)
            m_SubOctetList.push_back(new BEROctet(*Oct.m_SubOctetList[i]));
    }
    else
        m_blbData = Oct.m_blbData;

    return *this;
}

// Returns a the data part of the octet

BEROctet::Blob BEROctet::Data() const
{

    if(m_fConstructed)
    {

        // Traverse the tree

        Blob data;

        for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
            data += m_SubOctetList[i]->Octet();

        return data;
    }
    else
        return m_blbData;

}

// Sets the data part of the octet

void BEROctet::Data(Blob const &blb)
{

    if(m_fConstructed)
        throw runtime_error("BERInconsistentOperation");

    m_blbData = blb;
    m_fModified = true;

}

// If the octet is a constructed type, this returns list of sub-octets

vector<BEROctet*> BEROctet::SubOctetList() const
{
    if(!m_fConstructed)
        throw runtime_error("BERInconsistentOperation");

    return m_SubOctetList;
}

// Insert an octet as a sub-octet of a constructed octet

void BEROctet::Insert(BEROctet const &oct)
{
    if(!m_fConstructed)
        throw runtime_error("BERInconsistentOperation");

    BEROctet *pOct = new BEROctet(oct);
    m_SubOctetList.push_back(pOct);
    m_fModified = true;

}

// Returns the whole octet

BEROctet::Blob BEROctet::Octet() const
{
    if(Modified())
    {

        Blob blbOct = IdentOctets(m_tcClass, m_fConstructed, m_dwTag);
        Blob blbData = Data();

        if(m_fDefinite)
            blbOct += LengthOctets(static_cast<unsigned int>(blbData.size()));
        else
            blbOct += 0x80;    // Indefinite length octet

        blbOct += blbData;

        if(!m_fDefinite)
        {

            // Terminate with end-of-contents octet

            BEROctet blbZero;
            blbOct += blbZero.Octet();
        }

        return blbOct;
    }
    else
        return m_blbOrigOctet;

}

// Returns the class of the octet

TagClass BEROctet::Class() const
{
    return m_tcClass;
}

// Returns true if the octet is constructet, false otherwise

bool BEROctet::Constructed() const
{
    return m_fConstructed;
}

// Returns the tag of the octet

unsigned int BEROctet::Tag() const
{
    return m_dwTag;
}

// Decode the contents of an OID

string BEROctet::ObjectID() const
{

    if(m_tcClass!=tcUniversal || m_dwTag!=dwBerUnivObjectIdent)
        throw runtime_error("BERInconsistentOperation");

    if(!m_blbData.size())
        throw runtime_error("BEREmptyOctet");

    string OID;

    // The scratch buffer "text" below needs to be large enough to hold
    // the decimal encoding of two 32 bit integers, including a space
    // and the terminating zero.

    char text[40];

    unsigned int subid;
    const unsigned char *c = m_blbData.data();
    const unsigned char *Last = c + m_blbData.size();
    bool First = true;

    while(c<Last)
    {
        subid = (*c)&0x7F;
        while((*c)&0x80)
        {
            c++;
            if(c>=Last)
                throw runtime_error("BERUnexpectedEndOfOctet");
            if(subid>0x01FFFFFF)
                throw runtime_error("BEROIDSubIdentifierOverflow");
            subid = (subid<<7) | ((*c)&0x7F);
        }
        if(First)
        {
            unsigned int X,Y;
            if(subid<40)
                X=0;
            else if(subid<80)
                X=1;
            else
                X=2;
            Y = subid-X*40;
            sprintf(text,"%d %d",X,Y);
            OID = text;
            First = false;
        }
        else
        {
            sprintf(text," %d",subid);
            OID += text;
        }
        c++;
    }

    return OID;
}

// Encode an OID

void BEROctet::ObjectID(string const &str)
{

    if(m_tcClass!=tcUniversal)
        throw runtime_error("BERInconsistentOperation");

    if(m_dwTag==dwBerUnivZero)
        m_dwTag = dwBerUnivObjectIdent;

    if(m_dwTag!=dwBerUnivObjectIdent)
        throw runtime_error("BERInconsistentOperation");

    char *oid = 0;

    try
    {
#if defined(_WIN32)
        oid = _strdup(str.c_str());
#else
        oid = strdup(str.c_str());
#endif
        char *s;

        if(0==(s = strtok(oid," ")))
            throw runtime_error("BERIllegalObjectIdentifier");

        unsigned int X,Y,dwSubOID;

        if(sscanf(s,"%u",&X)!=1)
            throw runtime_error("BERIllegalObjectIdentifier");

        if(X>2)
            throw runtime_error("BERIllegalObjectIdentifier");

        if(0==(s = strtok(0," ")))
            throw runtime_error("BERIllegalObjectIdentifier");

        if(sscanf(s,"%u",&Y)!=1)
            throw runtime_error("BERIllegalObjectIdentifier");

        if(X<2 && Y>39)
            throw runtime_error("BERIllegalObjectIdentifier");

        dwSubOID = X*40;
        if(Y>0xFFFFFFFF-dwSubOID)
            throw runtime_error("BERDataOverflow");

        dwSubOID += Y;

        Blob blbData;

        while(true)
        {

            unsigned char buf[2*sizeof(dwSubOID)];
            int n=0;
            while(dwSubOID>0x7F)
            {
                buf[n] = static_cast<unsigned char>(dwSubOID & 0x7F);
                dwSubOID >>=7;
                n++;
            }
            buf[n] = static_cast<unsigned char>(dwSubOID & 0x7F);
            n++;

            for(int i=0; i<n; i++)
            {
                unsigned char b = buf[n-i-1];
                if((i+1)<n) b |= 0x80;
                blbData += b;
            }

            if(0==(s = strtok(0," ")))
                break;
            if(sscanf(s,"%u",&dwSubOID)!=1)
                break;
        }

        Data(blbData);

    }
    catch(...)
    {
        if(oid)
            free(oid);
        throw;
    }

    if(oid)
        free(oid);

}

// Decode a Time octet. Output format: "YYYYMMDDHHMMSS"

// We here apply the convention from RFC 2459 that the 2 digit year
// encoded in UTCTime is in the range 1950-2049.

string BEROctet::Time() const
{

    static const Blob::size_type UnivUTCTimeSize = 13;
    static const Blob::size_type UnivGenTimeSize = 15;

    if(m_tcClass!=tcUniversal)
        throw runtime_error("BERInconsistentOperation");

    if(m_dwTag==dwBerUnivUTCTime)
    {
        // UTCTime

        if(m_blbData.size()!=UnivUTCTimeSize)
            throw runtime_error("BERInconsistentDataLength");

        string strCentury, strYear((char*)m_blbData.data(),2);
        int iYear;
        if(sscanf(strYear.c_str(),"%d",&iYear)!=1)
            throw runtime_error("FormatDecodingError");

        if(iYear>=50) strCentury = "19";
        else strCentury = "20";

        // Add century and strip off the 'Z'

        return strCentury + string((char*)m_blbData.data(),UnivUTCTimeSize-1);
    }
    else if(m_dwTag==dwBerUnivGenTime)
    {
        // GeneralizedTime

        if(m_blbData.size()!=UnivGenTimeSize)
            throw runtime_error("BERInconsistentDataLength");

        // Return the string as is, stripping off the 'Z'

        return string((char*)m_blbData.data(),UnivGenTimeSize-1);
    }
    else
        throw runtime_error("BERInconsistentOperation");

}

// Encode a Time. Input format: "YYYYMMDDHHMMSS"

// If the Tag is not set to be either UTC Time or Generalized Time,
// we apply the convention from RFC 2459 where years in the range
// 1950-2049 are encoded as UTC Time and years later are encoded as
// Generalized time. In this case, years < 1950 are not allowed.

void BEROctet::Time(string const &str)
{
    static const Blob::size_type ExpectedSize = 14;

    if(m_tcClass!=tcUniversal)
        throw runtime_error("BERInconsistentOperation");

    if(str.size()!=ExpectedSize)
        throw runtime_error("IllegalParameter");

    // If m_dwTag is zero, chose appropriate tag according to year

    int iYear;
    if(sscanf(str.substr(0,4).c_str(),"%d",&iYear)!=1)
        throw runtime_error("IllegalParameter");

    if(m_dwTag==dwBerUnivZero)
    {
        if(iYear<1950)
            throw runtime_error("IllegalParameter");
        else if(iYear<2050)
            m_dwTag = dwBerUnivUTCTime;
        else
            m_dwTag = dwBerUnivGenTime;
    }

    Blob blbData;

    if(m_dwTag==dwBerUnivUTCTime)
        blbData.assign(((unsigned char*)str.data()+2),str.size()-2);

    else if(m_dwTag==dwBerUnivGenTime)
        blbData.assign((unsigned char*)str.data(),str.size());

    else
        throw runtime_error("BERInconsistentOperation");

    blbData += 'Z';

    Data(blbData);

}

// SearchOID returns all the constructed octets that contain a particular OID

void BEROctet::SearchOID(string const &OID, vector<BEROctet const*> &result) const
{

    for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
    {

        if(m_SubOctetList[i]->Class()==tcUniversal &&
           m_SubOctetList[i]->Tag()==dwBerUnivObjectIdent)
        {
            if(OID==m_SubOctetList[i]->ObjectID())
                result.push_back(this);
        }
        else if(m_SubOctetList[i]->Constructed())
            m_SubOctetList[i]->SearchOID(OID,result);
    }

    return;

}

// SearchOIDNext returns all the octets following a particular OID

void BEROctet::SearchOIDNext(string const &OID, vector<BEROctet const*> &result) const
{
    for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
    {
        if(m_SubOctetList[i]->Class()==tcUniversal &&
           m_SubOctetList[i]->Tag()==dwBerUnivObjectIdent)
        {
            if(OID==m_SubOctetList[i]->ObjectID())
            {
                if((i+1) < m_SubOctetList.size())
                    result.push_back(m_SubOctetList[i+1]);
            }
        }
        else if(m_SubOctetList[i]->Constructed())
            m_SubOctetList[i]->SearchOIDNext(OID,result);
    }

    return;

}

// Construct the Identifier octets

BEROctet::Blob BEROctet::IdentOctets(TagClass tcClass, bool fConstructed, unsigned int dwTag)
{

    unsigned char bLeadingOct;
    switch(tcClass)
    {

    case tcUniversal:
        bLeadingOct = 0x00;
        break;

    case tcApplication:
        bLeadingOct = 0x40;
        break;

    case tcContext:
        bLeadingOct = 0x80;
        break;

    case tcPrivate:
        bLeadingOct = 0xC0;
        break;

    default:
        throw runtime_error("BERIllegalClass");
    }

    if(fConstructed)
        bLeadingOct |= 0x20;

    int n = 0;
    unsigned char buf[sizeof(dwTag)];

    if(dwTag<=30)
        bLeadingOct |= dwTag;

    else
    {
        bLeadingOct |= 0x1F;
        while(dwTag>0)
        {
            buf[n] = static_cast<unsigned char>(dwTag & 0x000000FF);
            dwTag >>= 8;
            n++;
        }
    }

    Blob IdentOcts(&bLeadingOct,1);

    for(int i=0; i<n; i++)
        IdentOcts +=buf[n-i-1];

    return IdentOcts;

}

// Construct the Length octets

BEROctet::Blob BEROctet::LengthOctets(unsigned int dwLength)
{

    int n = 0;
    unsigned char buf[sizeof(dwLength)];
    unsigned char bLeadingOct;

    if(dwLength<=0x7F)
        bLeadingOct = static_cast<unsigned char>(dwLength);
    else
    {
        bLeadingOct = 0x80;
        while(dwLength>0)
        {
            buf[n] = static_cast<unsigned char>(dwLength & 0x000000FF);
            dwLength >>= 8;
            n++;
        }
        bLeadingOct |= n;
    }

    Blob LengthOcts(&bLeadingOct,1);
    for(int i=0; i<n; i++)
        LengthOcts +=buf[n-i-1];

    return LengthOcts;

}

// Decodes recursively a BER octet.

void BEROctet::Decode(Blob const &blb)
{

    if(!blb.size())
        throw runtime_error("BEREmptyOctet");

    size_t BufferSize = blb.size();

    m_fConstructed = (blb[0]&0x20) ? true : false;

    switch(blb[0]&0xC0)
    {

    case 0x00:
        m_tcClass = tcUniversal;
        break;

    case 0x40:
        m_tcClass = tcApplication;
        break;

    case 0x80:
        m_tcClass = tcContext;
        break;

    case 0xC0:
        m_tcClass = tcPrivate;
        break;

    default:
        throw runtime_error("BERIllegalClass");
    }

    const unsigned char *c = blb.data();
    const unsigned char *Last = c + blb.size() - 1;
    m_dwTag = *c & 0x1F;

    if(m_dwTag>30)
    {
        m_dwTag = 0;

        c++;
        if(c>Last)
            throw runtime_error("BERUnexpectedEndOfOctet");

        while (*c & 0x80)
        {
            m_dwTag = (m_dwTag << 7) | ((*c) & 0x7F);
            c++;
            if(c>Last)
                throw runtime_error("BERUnexpectedEndOfOctet");
        }

        if(m_dwTag > 0x01FFFFFF)
            throw runtime_error("BERTagValueOverflow");

        m_dwTag = (m_dwTag << 7) | ((*c) & 0x7F);

    }

    c++;
    if(c>Last)
        throw runtime_error("BERUnexpectedEndOfOctet");

    size_t DataSize;

    if((*c)&0x80)
    {
        int n = (*c) & 0x7F;
        if(n)
        {
            DataSize = 0;
            for(int i=0; i<n; i++)
            {
                c++; if(c>Last)
                    throw runtime_error("BERUnexpectedEndOfOctet");
                if(DataSize>0x007FFFFF)
                    throw runtime_error("BERDataOverflow");
                DataSize = (DataSize<<8) | (*c);
            }
        }
        else
            throw runtime_error("BERUnexpectedIndefiniteLength");
    }
    else DataSize = *c;

    c++;

    const unsigned char *bpData = c;

    size_t OctetSize = DataSize + (bpData-blb.data());

    m_blbOrigOctet = blb.substr(0,OctetSize);
    m_fModified = false;

    if(OctetSize>static_cast<unsigned int>(BufferSize))
        throw runtime_error("BERInconsistentDataLength");

    for(std::vector<BEROctet const*>::size_type  i=0; i<m_SubOctetList.size(); i++)
        delete m_SubOctetList[i];

    m_SubOctetList.resize(0);
    m_blbData = Blob();

    if(m_fConstructed)
    {

        // Constructed type

        while(DataSize)
        {

            BEROctet *suboct = new BEROctet(Blob(bpData,DataSize));

            m_SubOctetList.push_back(suboct);

            Blob blbSubOct = suboct->Octet();

            bpData += blbSubOct.size();
            DataSize -= blbSubOct.size();
        }
    }
    else
        m_blbData = Blob(bpData,DataSize);

}

bool BEROctet::Modified() const
{
    if(m_fModified)
        return true;

    if(m_fConstructed)
        for(std::vector<BEROctet const*>::size_type i=0; i<m_SubOctetList.size(); i++)
            if(m_SubOctetList[i]->Modified()) return true;

    return false;

}
