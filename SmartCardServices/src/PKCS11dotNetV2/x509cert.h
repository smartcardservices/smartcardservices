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


#ifndef _include_x509cert_h
#define _include_x509cert_h

#include <string>
#include <vector>

#include "beroctet.h"

class X509Cert
{

public:
   X509Cert();
   X509Cert(const X509Cert &cert);
   X509Cert(const BEROctet::Blob &buffer);
   X509Cert(const unsigned char *buffer, const unsigned long size);
   X509Cert& operator=(const X509Cert &cert);
   X509Cert& operator=(const BEROctet::Blob &buffer);

   BEROctet::Blob SerialNumber() const;
   BEROctet::Blob Issuer() const;
   BEROctet::Blob UTF8Issuer() const;
   std::vector<std::string> IssuerOrg() const;
   std::vector<std::string> UTF8IssuerOrg() const;
   std::string ValidityNotBefore() const;
   std::string ValidityNotAfter() const;
   BEROctet::Blob Subject() const;
   BEROctet::Blob UTF8Subject() const;
   std::vector<std::string> SubjectCommonName() const;
   std::vector<std::string> UTF8SubjectCommonName() const;
   BEROctet::Blob Modulus() const;
   BEROctet::Blob RawModulus() const;
   BEROctet::Blob PublicExponent() const;
   BEROctet::Blob RawPublicExponent() const;

   unsigned long KeyUsage() const;
   bool ExtendedKeyUsage(std::string const &strOID) const;
   bool IsCACert() const;
   bool IsRootCert() const;
   bool isSmartCardLogon( void ) const;

private:
   void Decode();

   BEROctet::Blob ToUTF8( unsigned int dwTag, const BEROctet::Blob &blbData ) const;

private:
   BEROctet m_Cert;
   BEROctet m_SerialNumber;
   BEROctet m_Issuer;
   BEROctet m_Validity;
   BEROctet m_Subject;
   BEROctet m_SubjectPublicKeyInfo;
   BEROctet m_Extensions;
   bool     m_bCACert;
   bool     m_bRootCert;


};

// Key Usage flags from X.509 spec

const unsigned long digitalSignature = 0x80000000;
const unsigned long nonRepudiation   = 0x40000000;
const unsigned long keyEncipherment  = 0x20000000;
const unsigned long dataEncipherment = 0x10000000;
const unsigned long keyAgreement     = 0x08000000;
const unsigned long keyCertSign      = 0x04000000;
const unsigned long cRLSign          = 0x02000000;
const unsigned long encipherOnly     = 0x01000000;
const unsigned long decipherOnly     = 0x00800000;


#endif //_include_x509cert_h
