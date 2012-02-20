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

// This implementation is based on RFC 2459 which can be fetched from
// http://www.ietf.org.

// This code is based on class in ACS baseline.

//#include "slbPki.h"
#include "x509cert.h"

using namespace std;

X509Cert::X509Cert()
{
}

X509Cert::X509Cert(const X509Cert &cert)
{
   *this = cert;
}

X509Cert::X509Cert(const BEROctet::Blob &buffer)
{
   *this = buffer;
}

X509Cert::X509Cert(const unsigned char *buffer, const unsigned long size)
{
   m_Cert = BEROctet(BEROctet::Blob(buffer,size));
   if(size != m_Cert.Octet().size())
      throw runtime_error("X509CertFormatError");

   Decode();
}

X509Cert& X509Cert::operator=(const X509Cert &cert)
{
   m_Cert = cert.m_Cert;
   Decode();

   return *this;
}

X509Cert& X509Cert::operator=(const BEROctet::Blob &buffer)
{
   m_Cert = BEROctet(buffer);
   if(buffer.size() != m_Cert.Octet().size())
      throw runtime_error("X509CertFormatError");
   Decode();

   return *this;
}

// Returns whole DER string of Serial Number.

BEROctet::Blob X509Cert::SerialNumber() const
{
   return m_SerialNumber.Octet();
}

// Returns whole DER string of Issuer

BEROctet::Blob X509Cert::Issuer() const
{
   return m_Issuer.Octet();
}

// Returns whole string of Issuer in UTF8.

BEROctet::Blob X509Cert::UTF8Issuer() const
{
   return ToUTF8(m_Issuer.Tag(), m_Issuer.Octet() );
}


// Returns list of attributes in Issuer matching id-at-organizationName.
// List will be invalidated when object changes.

std::vector<std::string> X509Cert::IssuerOrg() const
{

   std::vector<std::string> orgNames;
   std::vector<BEROctet const*> orgOcts;

   m_Issuer.SearchOIDNext(OID_id_at_organizationName,orgOcts);

   for(unsigned long i=0; i<orgOcts.size(); i++)
      orgNames.push_back(string((char*)orgOcts[i]->Data().data(),orgOcts[i]->Data().size()));

   return orgNames;

}

// Returns list of attributes in Issuer matching id-at-organizationName.
// List will be invalidated when object changes.
// the string in the list is in UTF8 format.

std::vector<std::string> X509Cert::UTF8IssuerOrg() const
{

   std::vector<std::string> orgNames;
   std::vector<BEROctet const*> orgOcts;

   m_Issuer.SearchOIDNext(OID_id_at_organizationName,orgOcts);

   for(unsigned long i=0; i<orgOcts.size(); i++)
   {
      BEROctet::Blob blbData = ToUTF8(orgOcts[i]->Tag(), orgOcts[i]->Data());
      orgNames.push_back(string((char*)blbData.data(),blbData.size()));
   }

   return orgNames;
}


// Returns Validity notBefore attribute as "YYYYMMDDHHMMSS"

string X509Cert::ValidityNotBefore() const
{

   if(m_Validity.SubOctetList().size()!=2)
      throw runtime_error("X509CertFormatError");

   return m_Validity.SubOctetList()[0]->Time();

}

// Returns Validity notAfter attribute as "YYYYMMDDHHMMSS"

string X509Cert::ValidityNotAfter() const
{

   if(m_Validity.SubOctetList().size()!=2)
      throw runtime_error("X509CertFormatError");

   return m_Validity.SubOctetList()[1]->Time();

}


// Returns whole DER string of Subject

BEROctet::Blob X509Cert::Subject() const
{
   return m_Subject.Octet();
}

// Returns Subject in UTF8 format.

BEROctet::Blob X509Cert::UTF8Subject() const
{
   return ToUTF8(m_Subject.Tag(), m_Subject.Octet());
}

// Returns list of attributes in Subject matching id-at-commonName
// List will be invalidated when object changes.

std::vector<std::string> X509Cert::SubjectCommonName() const
{

   std::vector<std::string> cnNames;
   std::vector<BEROctet const*> cnOcts;

   m_Subject.SearchOIDNext(OID_id_at_commonName,cnOcts);

   for(std::vector<BEROctet const*>::size_type i=0; i<cnOcts.size(); i++)
      cnNames.push_back(string((char*)cnOcts[i]->Data().data(),cnOcts[i]->Data().size()));

   return cnNames;

}

// Returns list of attributes in Subject matching id-at-commonName
// List will be invalidated when object changes.
// string in list is in UTF8.

std::vector<std::string> X509Cert::UTF8SubjectCommonName() const
{

   std::vector<std::string> cnNames;
   std::vector<BEROctet const*> cnOcts;

   m_Subject.SearchOIDNext(OID_id_at_commonName,cnOcts);

   for(std::vector<BEROctet const*>::size_type i=0; i<cnOcts.size(); i++)
   {
      BEROctet::Blob blbData = ToUTF8(cnOcts[i]->Tag(), cnOcts[i]->Data());
      cnNames.push_back(string((char*)blbData.data(),blbData.size()));
   }

   return cnNames;

}

// Returns modulus from SubjectPublicKeyInfo, stripped for any leading zero(s).

BEROctet::Blob X509Cert::Modulus() const
{

   BEROctet::Blob RawMod = RawModulus();

   unsigned long i = 0;
   while(!RawMod[i] && i<RawMod.size()) i++; // Skip leading zero(s).

   return BEROctet::Blob(&RawMod[i],RawMod.size()-i);

}

// Returns public exponent from SubjectPublicKeyInfo, possibly with leading zero(s).

BEROctet::Blob X509Cert::RawModulus() const
{

   if(m_SubjectPublicKeyInfo.SubOctetList().size()!=2)
      throw runtime_error("X509CertFormatError");

   BEROctet PubKeyString = *(m_SubjectPublicKeyInfo.SubOctetList()[1]);

   BEROctet::Blob KeyBlob = PubKeyString.Data();

   if(KeyBlob[0])                                 // Expect number of unused bits in
      throw runtime_error("X509CertFormatError");    // last octet to be zero.



   BEROctet PubKeyOct(KeyBlob.substr(1,BEROctet::Blob::npos));

   if(PubKeyOct.SubOctetList().size()!=2) throw runtime_error("X509CertFormatError");

   return PubKeyOct.SubOctetList()[0]->Data();

}

// Returns public exponent from SubjectPublicKeyInfo, stripped for any leading zero(s).

BEROctet::Blob X509Cert::PublicExponent() const
{

   BEROctet::Blob RawPubExp = RawPublicExponent();

   unsigned long i = 0;
   while(!RawPubExp[i] && i<RawPubExp.size()) i++; // Skip leading zero(s).

   return BEROctet::Blob(&RawPubExp[i],RawPubExp.size()-i);

}
// Returns public exponent from SubjectPublicKeyInfo, possibly with leading zero(s).

BEROctet::Blob X509Cert::RawPublicExponent() const
{

   if(m_SubjectPublicKeyInfo.SubOctetList().size()!=2)
      throw runtime_error("X509CertFormatError");

   BEROctet PubKeyString = *(m_SubjectPublicKeyInfo.SubOctetList()[1]);

   BEROctet::Blob KeyBlob = PubKeyString.Data();

   if(KeyBlob[0])                                  // Expect number of unused bits
      throw runtime_error("X509CertFormatError");     // in last octet to be zero.


   BEROctet PubKeyOct(KeyBlob.substr(1,BEROctet::Blob::npos));

   if(PubKeyOct.SubOctetList().size()!=2) throw runtime_error("X509CertFormatError");

   return PubKeyOct.SubOctetList()[1]->Data();

}

// Returns KeyUsage attribute, left justified with most significant bit as first bit (BER convention)

unsigned long X509Cert::KeyUsage() const
{

   if(!m_Extensions.Data().size())
      throw runtime_error("X509CertExtensionNotPresent");

   unsigned long ReturnKeyUsage = 0;

   const unsigned char UnusedBitsMask[]  = {0xFF,0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};

   std::vector<BEROctet const*> ExtensionList;

   m_Extensions.SearchOID(OID_id_ce_keyUsage,ExtensionList);

   if(ExtensionList.size()!=1)
      throw runtime_error("X509CertExtensionNotPresent"); // One and only one instance

   BEROctet const* Extension = ExtensionList[0];
   BEROctet* extnValue = 0;
   if(Extension->SubOctetList().size()==2)
      extnValue = Extension->SubOctetList()[1];  // No "critical" attribute present

   else if(Extension->SubOctetList().size()==3)
      extnValue = Extension->SubOctetList()[2];  // A "critical" attribute present

   else
      throw runtime_error("X509CertFormatError");    // "Extensions" must contain either 2 or 3 octets

   BEROctet KeyUsage(extnValue->Data());
   BEROctet::Blob KeyUsageBitString = KeyUsage.Data();

   unsigned char UnusedBits = KeyUsageBitString[0];
   size_t NumBytes = KeyUsageBitString.size()-1;
   if(NumBytes>4)
   {
      NumBytes = 4; // Truncate to fit the ulong, should be plenty though
      UnusedBits = 0;
   }

   unsigned long Shift = 24;
   for(unsigned long i=0; i<NumBytes-1; i++)
   {
      ReturnKeyUsage |= (((unsigned long)KeyUsageBitString[i+1]) << Shift);
      Shift -= 8;
   }

   ReturnKeyUsage |= ( (KeyUsageBitString[NumBytes] & UnusedBitsMask[UnusedBits]) << Shift );

   return ReturnKeyUsage;

}

bool X509Cert::ExtendedKeyUsage(string const &strOID) const
{
   if(!m_Extensions.Data().size())
      return false;

   vector<BEROctet const*> veku;

   m_Extensions.SearchOIDNext(OID_id_ce_extKeyUsage, veku);
   if(veku.size() != 1)
      return false;

   try
   {
      BEROctet berEKU(veku[0]->Data());
      vector<BEROctet const*> ekuOcts;
      berEKU.SearchOID(strOID,ekuOcts);
      if(ekuOcts.size() > 0)
         return true;
      else
         return false;
   }
   catch(...)
   {
      return false;
   }
}

bool X509Cert::IsCACert() const
{
   return m_bCACert;
}

bool X509Cert::IsRootCert() const
{
   return m_bRootCert;
}

void X509Cert::Decode()
{

   const unsigned int dwTagVersion         = 0;
   //const unsigned int dwTagIssuerUniqueID  = 1;
   //const unsigned int dwTagSubjectUniqueID = 2;
   const unsigned int dwTagExtensions      = 3;

   if(m_Cert.SubOctetList().size()!=3)  throw runtime_error("X509CertFormatError");

   BEROctet *tbsCert = m_Cert.SubOctetList()[0];
   size_t Size = tbsCert->SubOctetList().size();
   if(!Size) throw runtime_error("X509CertFormatError");

   std::vector<BEROctet const*>::size_type  i = 0;
   BEROctet *first = tbsCert->SubOctetList()[i];
   if((first->Class()==tcContext) && (first->Tag()==dwTagVersion)) i++; // Version

   if(Size < static_cast<unsigned long>(6+i))
      throw runtime_error("X509CertFormatError");

   m_SerialNumber = *(tbsCert->SubOctetList()[i]); i++;            // SerialNumber
   i++;                                                            // Signature (algorithm)
   m_Issuer = *(tbsCert->SubOctetList()[i]); i++;                  // Issuer
   m_Validity = *(tbsCert->SubOctetList()[i]); i++;                // Validity
   m_Subject = *(tbsCert->SubOctetList()[i]); i++;                 // Subject
   m_SubjectPublicKeyInfo = *(tbsCert->SubOctetList()[i]);    i++; // SubjectPublicKeyInfo

   m_Extensions = BEROctet();
   while(i<Size) {
      BEROctet *oct = tbsCert->SubOctetList()[i];
      if((oct->Class()==tcContext) && (oct->Tag()==dwTagExtensions)) {
         m_Extensions = *oct;
         break;
      }
      i++;
   }

   m_bCACert = false;
   std::vector<BEROctet const*> ExtensionList;
   m_Extensions.SearchOID(OID_id_ce_basicConstraints, ExtensionList);


   if(1 == ExtensionList.size())
   {
      BEROctet const* Extension = ExtensionList[0];
      BEROctet* extnValue = 0;
      if(Extension->SubOctetList().size()==2)
         extnValue = Extension->SubOctetList()[1];  // No "critical" attribute present

      else if(Extension->SubOctetList().size()==3)
         extnValue = Extension->SubOctetList()[2];  // A "critical" attribute present

      if (extnValue)
      {
         BEROctet BasicContrainsts(extnValue->Data());
         std::vector<BEROctet*> bcMembers(BasicContrainsts.SubOctetList());
         if(bcMembers.size()>0 && bcMembers[0]->Tag() == dwBerUnivBool)
         {
            BEROctet::Blob flag(bcMembers[0]->Data());
            if(flag.size()==1)
               m_bCACert = flag[0] ? true : false;
         }
      }
   }

   m_bRootCert = false;
   if (Issuer() == Subject())
   {
      m_bRootCert = true;
   }
}


BEROctet::Blob X509Cert::ToUTF8( unsigned int dwTag, const BEROctet::Blob &blbData ) const
{
   BEROctet::Blob blbReturn;
   size_t cUnicode = 0;
   bool bConvert = false;
   switch(dwTag)
   {
   case dwBerBMPString:
      //string in 2 byte Unicode Big Endian format.
      cUnicode = 2;
      bConvert = true;
      break;
   case dwBerUniversalString:
   case dwBerCharacterString:
      //string in ISO10646, 4 byte unicode big endian format.
      //this is hardly used but we never know.
      cUnicode = 4;
      bConvert = true;
      break;
   default:
      //return as is.
      blbReturn = blbData;
   }

   if(bConvert)
   {
      unsigned char bAppend = 0;
      for(size_t i = 0; i < blbData.size() / cUnicode; i++ )
      {
         unsigned int dwUnicode = 0;
         unsigned int dwTemp = 0;
         int nBytesInUTF8 = 0;

         //first get the Unicode unsigned int from BIG ENDIAN BYTES.
         for(size_t j = 0; j < cUnicode; j++)
         {
            dwTemp = blbData.at(i*cUnicode + j);
            dwUnicode += dwTemp << (8*(cUnicode-(j+1)));
         }

         //now calculate the number of bytes required to represent
         // the unicode value in UTF8
         if( dwUnicode <= 0x0000007F )
         {
            nBytesInUTF8 = 1;
         }
         else if( dwUnicode <= 0x000007FF )
         {
            nBytesInUTF8 = 2;
         }
         else if( dwUnicode <= 0x0000FFFF )
         {
            nBytesInUTF8 = 3;
         }
         else if( dwUnicode <= 0x001FFFFF )
         {
            nBytesInUTF8 = 4;
         }
         else if( dwUnicode <= 0x03FFFFFF )
         {
            nBytesInUTF8 = 5;
         }
         else if( dwUnicode <= 0x7FFFFFFF )
         {
            nBytesInUTF8 = 6;
         }

         //The bitwise & code is 0x7F (7 bits) when there is only one byte
         // Otherwise the & code is 0x3f ( 6 bits)
         // when there are more that one UTF8 bytes required,
         // Ideally the MS unsigned char has to be & with less than 6 bits,
         // but it does not matter since the other bits
         // will be zero, so it is safe to & 6 bits.

         unsigned char bBitWiseAndCode = 0x3f;
         if( nBytesInUTF8 == 1)
         {
            bBitWiseAndCode = 0x7f;
         }


         // Shift in the multiples of 6 starting with maximum.
         // This way the MSB will be appended first and then the rest.
         // Add to MS Byte the bits which indicates number of bytes coded for UTF8
         // for all other bytes add 0x80.
         for( int k = nBytesInUTF8 - 1; k >= 0; k--)
         {
            unsigned char bytAdd = 0;
            if( nBytesInUTF8 > 1 )
            {
               if( k == nBytesInUTF8 - 1 )
               {
                  bytAdd = ( 0xFF << (8 - nBytesInUTF8 ) );
               }
               else
               {
                  bytAdd = 0x80;
               }

            }
            bAppend = static_cast<unsigned char>( ((dwUnicode >> k*6) & bBitWiseAndCode));
            bAppend  += bytAdd;
            blbReturn.append( &bAppend, 1);
         }
      }
      //append the NULL char.
      bAppend = 0;
      blbReturn.append( &bAppend, 1);
   }
   return blbReturn;
}
