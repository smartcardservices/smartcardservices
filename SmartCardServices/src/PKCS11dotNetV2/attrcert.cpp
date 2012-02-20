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

// This code is based on class in ACS baseline.

//#pragma warning(disable : 4251)

#include <cstdio>
#include "cryptoki.h"
#include <numeric>
#include <functional>
#include "attrcert.h"
#include "digest.h"
#include "sha1.h"


namespace
{

    class JoinWith
        : public std::binary_function<std::string, std::string, std::string>
    {
    public:

        explicit
        JoinWith(second_argument_type const &rGlue)
            : m_Glue(rGlue)
        {}


        result_type
        operator()(std::string const &rFirst,
                   std::string const &rSecond) const
        {
            return rFirst + m_Glue + rSecond;
        }

    private:

        second_argument_type const m_Glue;
    };

    std::string
    Combine(std::vector<std::string> const &rvsNames)
    {
        static std::string::value_type const cBlank = ' ';
        static std::string const sBlank(1, cBlank);

        if(!rvsNames.empty())
            return accumulate(rvsNames.begin() + 1, rvsNames.end(),
                              *rvsNames.begin(), JoinWith(sBlank));
        else
            return std::string();
    }

} // namespace

CAttributedCertificate::CAttributedCertificate(BEROctet::Blob const &cert) : m_x509cert(cert)
{
}

CAttributedCertificate::CAttributedCertificate(const unsigned char * cert, size_t length)
                                            : m_x509cert(cert, static_cast<unsigned long>(length))
{
}

CAttributedCertificate::~CAttributedCertificate()
{
}

BEROctet::Blob
CAttributedCertificate::Modulus() const
{
    return m_x509cert.Modulus();
}

BEROctet::Blob
CAttributedCertificate::PublicExponent() const
{
    return m_x509cert.PublicExponent();
}

BEROctet::Blob
CAttributedCertificate::Subject() const
{
    return m_x509cert.Subject();
}

BEROctet::Blob
CAttributedCertificate::Issuer() const
{
    return m_x509cert.Issuer();
}

BEROctet::Blob
CAttributedCertificate::SerialNumber() const
{
    return m_x509cert.SerialNumber();
}

std::string
CAttributedCertificate::DerivedName() const
{
    std::string sDerivedName(Combine(m_x509cert.UTF8SubjectCommonName()));
    if(sDerivedName.empty())
        sDerivedName.assign("Smart Card User");
    return sDerivedName;
}

std::string
CAttributedCertificate::DerivedLabel() const
{
    return Combine(m_x509cert.SubjectCommonName());
}

BEROctet::Blob
CAttributedCertificate::DerivedId() const
{
    return DerivedId(m_x509cert.Modulus());
}

BEROctet::Blob
CAttributedCertificate::DerivedId(BEROctet::Blob const & data)
{
    return DerivedId(data.c_str(), data.size());
}

BEROctet::Blob
CAttributedCertificate::DerivedId(unsigned char const * data, size_t length)
{
    CSHA1 sha1;
    unsigned char hash[20];
    sha1.hashCore(const_cast<CK_BYTE_PTR>(data), 0, static_cast<CK_LONG>(length));
    sha1.hashFinal(hash);

    return BEROctet::Blob(hash, 20);
}

std::string
CAttributedCertificate::DerivedUniqueName() const
{
    return DerivedUniqueName(m_x509cert.Modulus());
}

std::string
CAttributedCertificate::DerivedUniqueName(BEROctet::Blob const & data)
{
    return DerivedUniqueName(data.c_str(), data.size());
}

std::string
CAttributedCertificate::DerivedUniqueName(unsigned char const * data, size_t length)
{
    CSHA1 sha1;
    unsigned char hash[20];
    sha1.hashCore(const_cast<CK_BYTE_PTR>(data), 0, static_cast<CK_LONG>(length));
    sha1.hashFinal(hash);

    // Format as a GUID

    char name[40];

    unsigned char *id = hash;

    int i, n = 0;
    char *c = name;

    for(i=0; i<4; i++) {
        sprintf(c,"%02x",id[n]);
        n++; c+=2;
    }
    sprintf(c,"-");
    c++;
    for(i=0; i<2; i++) {
        sprintf(c,"%02x",id[n]);
        n++; c+=2;
    }
    sprintf(c,"-");
    c++;
    for(i=0; i<2; i++) {
        sprintf(c,"%02x",id[n]);
        n++; c+=2;
    }
    sprintf(c,"-");
    c++;
    for(i=0; i<2; i++) {
        sprintf(c,"%02x",id[n]);
        n++; c+=2;
    }
    sprintf(c,"-");
    c++;
    for(i=0; i<6; i++) {
        sprintf(c,"%02x",id[n]);
        n++; c+=2;
    }

    return std::string(name);
}
