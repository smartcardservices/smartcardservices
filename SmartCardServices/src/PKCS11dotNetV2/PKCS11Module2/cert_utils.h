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

#pragma once

#define CERT_TYPE_UNKNOWN     (0)
#define CERT_TYPE_USER        (1)
#define CERT_TYPE_CA_ROOT     (2)

#define CERT_USAGE_UNKNOWN    (0)
#define CERT_USAGE_EXCHANGE   (AT_KEYEXCHANGE)
#define CERT_USAGE_SIGNATURE  (AT_SIGNATURE)

// Errors code
#define RV_SUCCESS					0	// Info
#define RV_COMPRESSION_FAILED		1	// Warning
#define RV_MALLOC_FAILED			2	// Error
#define RV_BAD_DICTIONARY			3	// Error
#define RV_INVALID_DATA				4	// Error
#define RV_BLOC_TOO_LONG			5	// Warning
#define RV_FILE_OPEN_FAILED         6	// Error
#define RV_BUFFER_TOO_SMALL         7	// Error

#define TAG_OPTION_VERSION          0xA0

/*------------------------------------------------------------------------------
                          Types definitions
------------------------------------------------------------------------------*/
typedef unsigned char   TAG;
typedef TAG*            TAG_PTR;
typedef BYTE*           BYTE_PTR;

typedef struct
{
   USHORT   usLen;
   BYTE_PTR pData;
} BLOC, * BLOC_PTR;

typedef struct
{
   BLOC Asn1;
   BLOC Content;
   TAG  Tag;
} ASN1, * ASN1_PTR;


class CCertUtils
{
public:
   CCertUtils(void);
   ~CCertUtils(void);

void MemReverse                 (BYTE *pbOut,
                                 BYTE *pbIn,
                                 DWORD dwLen
                                );

void ConvAscii                  (BYTE  *pIn,
                                 DWORD  dwLen,
                                 BYTE  *pOut
                                );

void ConvHex                    (BYTE  *pIn,
                                 DWORD  dwLen,
                                 BYTE  *pOut
                                );

BYTE *GetDERLength              (BYTE  *content,
                                 DWORD *len
                                );

bool ParseCertificateValue      (BYTE                   *pCert,
                                 DWORD                  dwCertLen,
                                 BYTE                   *pSerialNumber,
                                 DWORD                  *pdwSerialNumberLen,
                                 BYTE                   *pIssuer,
                                 DWORD                  *pdwIssuerLen,
                                 BYTE                   *pSubject,
                                 DWORD                  *pdwSubjectLen
                                );

bool MakeCertificateLabel       (BYTE                   *pCert,
                                 DWORD                  dwCertLen,
                                 BYTE                   *pLabel,
                                 DWORD                  *pdwLabelLen
                                );

bool MakeCertificateLabelEx     (BYTE                   *pCert,
                                 DWORD                  dwCertLen,
                                 BYTE                   *pLabel,
                                 DWORD                  *pdwLabelLen
                                );


private:
int ExtractContent       (ASN1 *pAsn1);

bool IsSequence          (BYTE *content);

bool IsInteger           (BYTE *content);
};

