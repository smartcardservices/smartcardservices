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

#ifndef _include_attrcert_h
#define _include_attrcert_h

#include "x509cert.h"


class CAttributedCertificate
{

public:
    explicit CAttributedCertificate(BEROctet::Blob const &cert);
    CAttributedCertificate(const unsigned char * cert, size_t length);

    virtual ~CAttributedCertificate();

    BEROctet::Blob
    Modulus() const;

    BEROctet::Blob
    PublicExponent() const;

    BEROctet::Blob
    Subject() const;

    BEROctet::Blob
    Issuer() const;

    BEROctet::Blob
    SerialNumber() const;

    std::string
    DerivedName() const;

    std::string
    DerivedLabel() const;

    BEROctet::Blob
    DerivedId() const;

    static BEROctet::Blob
    DerivedId(BEROctet::Blob const & data);

    static BEROctet::Blob
    DerivedId(unsigned char const * data, size_t length);

    std::string
    DerivedUniqueName() const;

    static std::string
    DerivedUniqueName(BEROctet::Blob const & data);

    static std::string
    DerivedUniqueName(unsigned char const * data, size_t length);

private:
    X509Cert m_x509cert;

};


#endif // _include_attrcert_h

