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

#ifndef _include_beroctet_h
#define _include_beroctet_h

#include <string>
#include <vector>
#include <stdexcept>

enum TagClass {tcAny = -1, tcUniversal = 0, tcApplication = 1, tcContext = 2, tcPrivate = 3};

// Defined tags

const unsigned int dwBerUnivZero          = 0;
const unsigned int dwBerUnivBool          = 1;
const unsigned int dwBerUnivInteger       = 2;
const unsigned int dwBerUnivBitString     = 3;
const unsigned int dwBerUnivOctetString   = 4;
const unsigned int dwBerUnivNull          = 5;
const unsigned int dwBerUnivObjectIdent   = 6;
const unsigned int dwBerUnivObjectDesc    = 7;
const unsigned int dwBerUnivReal          = 9;
const unsigned int dwBerUnivEnum          = 10;
const unsigned int dwBerUnivUTF8String    = 12;
const unsigned int dwBerUnivSequence      = 16;
const unsigned int dwBerUnivSet           = 17;
const unsigned int dwBerUnivPrintString   = 19;
const unsigned int dwBerUnivIA5String     = 22;
const unsigned int dwBerUnivUTCTime       = 23;
const unsigned int dwBerUnivGenTime       = 24;
const unsigned int dwBerGraphicString     = 25;
const unsigned int dwBerISO646String      = 26;
const unsigned int dwBerGeneralString     = 27;
const unsigned int dwBerUniversalString   = 28;
const unsigned int dwBerCharacterString   = 29;
const unsigned int dwBerBMPString         = 30;
const unsigned int dwBerDate              = 31;
const unsigned int dwBerTimeOfDay         = 32;
const unsigned int dwBerDateTime          = 33;
const unsigned int dwBerDuration          = 34;

const char OID_pkcs1[]                            = "1 2 840 113549 1 1";
const char OID_pkcs1_rsaEncryption[]              = "1 2 840 113549 1 1 1";
const char OID_pkcs1_md2WithRSAEncryption[]       = "1 2 840 113549 1 1 2";
const char OID_pkcs1_md4WithRSAEncryption[]       = "1 2 840 113549 1 1 3";
const char OID_pkcs1_md5WithRSAEncryption[]       = "1 2 840 113549 1 1 4";
const char OID_pkcs1_sha1WithRSAEncryption[]      = "1 2 840 113549 1 1 5";
const char OID_pkcs1_sha256WithRSAEncryption[]    = "1 2 840 113549 1 1 11";

const char OID_pkcs7_data[]                       = "1 2 840 113549 1 7 1";
const char OID_pkcs7_signedData[]                 = "1 2 840 113549 1 7 2";
const char OID_pkcs7_envelopedData[]              = "1 2 840 113549 1 7 3";
const char OID_pkcs7_signedAndEnvelopedData[]     = "1 2 840 113549 1 7 4";
const char OID_pkcs7_digestedData[]               = "1 2 840 113549 1 7 5";
const char OID_pkcs7_encryptedData[]              = "1 2 840 113549 1 7 6";

const char OID_pkcs9_emailAddress[]               = "1 2 840 113549 1 9 1";
const char OID_pkcs9_unstructuredName[]           = "1 2 840 113549 1 9 2";
const char OID_pkcs9_contentType[]                = "1 2 840 113549 1 9 3";
const char OID_pkcs9_messageDigest[]              = "1 2 840 113549 1 9 4";
const char OID_pkcs9_signingTime[]                = "1 2 840 113549 1 9 5";
const char OID_pkcs9_countersignature[]           = "1 2 840 113549 1 9 6";
const char OID_pkcs9_challengePassword[]          = "1 2 840 113549 1 9 7";
const char OID_pkcs9_unstructuredAddress[]        = "1 2 840 113549 1 9 8";
const char OID_pkcs9_extendedCertificateAttr[]    = "1 2 840 113549 1 9 9";
const char OID_pkcs9_sMIMECapabilities[]          = "1 2 840 113549 1 9 15";
const char OID_pkcs9_id_smime[]                   = "1 2 840 113549 1 9 16";

const char OID_digestAlogrithm_md2[]              = "1 2 840 113549 2 2";
const char OID_digestAlogrithm_md4[]              = "1 2 840 113549 2 4";
const char OID_digestAlogrithm_md5[]              = "1 2 840 113549 2 5";

const char OID_RC2_CBC[]                          = "1 2 840 113549 3 2";
const char OID_dES_EDE3_CBC[]                     = "1 2 840 113549 3 7";

const char OID_ms_enrollmentAgent[]               = "1 3 6 1 4 1 311 20 2 1";
const char OID_ms_smartCardLogin[]                = "1 3 6 1 4 1 311 20 2 2";

const char OID_id_kp_serverAuth[]                 = "1 3 6 1 5 5 7 3 1";
const char OID_id_kp_clientAuth[]                 = "1 3 6 1 5 5 7 3 2";
const char OID_id_kp_codeSigning[]                = "1 3 6 1 5 5 7 3 3";
const char OID_id_kp_emailProtection[]            = "1 3 6 1 5 5 7 3 4";
const char OID_id_kp_ipsecEndSystem[]             = "1 3 6 1 5 5 7 3 5";
const char OID_id_kp_ipsecTunnel[]                = "1 3 6 1 5 5 7 3 6";
const char OID_id_kp_ipsecUser[]                  = "1 3 6 1 5 5 7 3 7";
const char OID_id_kp_timeStamping[]               = "1 3 6 1 5 5 7 3 8";

const char OID_md4WithRSA[]                       = "1 3 14 3 2 2";
const char OID_md5WithRSA[]                       = "1 3 14 3 2 3";
const char OID_md4WithRSAEncryption[]             = "1 3 14 3 2 4";
const char OID_desECB[]                           = "1 3 14 3 2 6";
const char OID_desCBC[]                           = "1 3 14 3 2 7";
const char OID_desOFB[]                           = "1 3 14 3 2 8";
const char OID_desCFB[]                           = "1 3 14 3 2 9";
const char OID_desMAC[]                           = "1 3 14 3 2 10";
const char OID_rsaSignature[]                     = "1 3 14 3 2 11";
const char OID_mdc2WithRSASignature[]             = "1 3 14 3 2 14";
const char OID_shaWithRSASignature[]              = "1 3 14 3 2 15";
const char OID_desEDE[]                           = "1 3 14 3 2 17";
const char OID_sha[]                              = "1 3 14 3 2 18";
const char OID_rsaKeyTransport[]                  = "1 3 14 3 2 22";
const char OID_md2WithRSASignature[]              = "1 3 14 3 2 24";
const char OID_md5WithRSASignature[]              = "1 3 14 3 2 25";
const char OID_sha1[]                             = "1 3 14 3 2 26";
const char OID_sha1WithRSASignature[]             = "1 3 14 3 2 29";

const char OID_id_at_organizationName[]           = "2 5 4 10";
const char OID_id_at_organizationalUnitName[]     = "2 5 4 11";
const char OID_id_at_commonName[]                 = "2 5 4 3";
const char OID_id_at_countryName[]                = "2 5 4 6";
const char OID_id_at_localityName[]               = "2 5 4 7";
const char OID_id_at_stateOrProvinceName[]        = "2 5 4 8";
const char OID_id_ce_subjectDirectoryAttributes[] = "2 5 29 9";
const char OID_id_ce_subjectKeyIdentifier[]       = "2 5 29 14";
const char OID_id_ce_keyUsage[]                   = "2 5 29 15";
const char OID_id_ce_privateKeyUsagePeriod[]      = "2 5 29 16";
const char OID_id_ce_subjectAltName[]             = "2 5 29 17";
const char OID_id_ce_issuerAltName[]              = "2 5 29 18";
const char OID_id_ce_basicConstraints[]           = "2 5 29 19";
const char OID_id_ce_cRLNumber[]                  = "2 5 29 20";
const char OID_id_ce_reasonCode[]                 = "2 5 29 21";
const char OID_id_ce_instructionCode[]            = "2 5 29 23";
const char OID_id_ce_invalidityDate[]             = "2 5 29 24";
const char OID_id_ce_deltaCRLIndicator[]          = "2 5 29 27";
const char OID_id_ce_issuingDistributionPoint[]   = "2 5 29 28";
const char OID_id_ce_certificateIssuer[]          = "2 5 29 29";
const char OID_id_ce_nameConstraints[]            = "2 5 29 30";
const char OID_id_ce_cRLDistributionPoints[]      = "2 5 29 31";
const char OID_id_ce_certificatePolicies[]        = "2 5 29 32";
const char OID_id_ce_policyMappings[]             = "2 5 29 33";
const char OID_id_ce_policyConstraints[]          = "2 5 29 36";
const char OID_id_ce_authorityKeyIdentifier[]     = "2 5 29 35";
const char OID_id_ce_extKeyUsage[]                = "2 5 29 37";

const char OID_sha256[]                           = "2 16 840 1 101 3 4 2 1";
const char OID_Netscape_certificate_type[]        = "2 16 840 1 113730 1 1";
//
////

const bool fBerPcPrimitive = false;
const bool fBerPcConstructed = true;

class BEROctet
{

public:
    typedef std::basic_string<unsigned char> Blob;

    BEROctet();
    BEROctet(BEROctet const &oct);
    BEROctet(Blob const &blb);
    BEROctet(TagClass tcClass, bool fConstructed, unsigned int dwTag, bool fDefinite=true);
    ~BEROctet();

    BEROctet& operator=(BEROctet const &oct);

    Blob Data() const;
    void Data(Blob const &data);
    std::vector<BEROctet*> SubOctetList() const;
    void Insert(BEROctet const &oct);

    Blob Octet() const;

    TagClass Class() const;
    bool Constructed() const;
    unsigned int Tag() const;

    std::string ObjectID() const;
    void ObjectID(std::string const &str);

    std::string Time() const;
    void Time(std::string const &str);

    void SearchOID(std::string const &OID, std::vector<BEROctet const*> &result) const;
    void SearchOIDNext(std::string const &OID, std::vector<BEROctet const*> &result) const;

private:
    static Blob IdentOctets(TagClass tcClass, bool fConstructed, unsigned int dwTag);
    static Blob LengthOctets(unsigned int dwLength);

    void Decode(Blob const &blb);
    bool Modified() const;               // =true if octet or sub-octets are modified since decoding

    Blob m_blbOrigOctet;            // Original octet that was decoded

    TagClass m_tcClass;                  // Tag class
    bool m_fConstructed;                 // =true if a constructed octed, false if primitive
    unsigned int m_dwTag;                       // Tag
    bool m_fDefinite;                    // =true for definite form of length octet, false if indefinite
    bool m_fModified;                    // =true if octet is modified since decoded, false otherwise

    Blob m_blbData;                 // Data octets (When primitive)
    std::vector<BEROctet*> m_SubOctetList;  // List of sub-octets (when constructed)

};


#endif // _include_beroctet_h



