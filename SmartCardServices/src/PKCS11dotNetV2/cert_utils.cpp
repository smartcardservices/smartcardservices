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

#include <cstdio>
#include <cstring>

#include "cert_utils.h"


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
CCertUtils::CCertUtils(void)
{
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
CCertUtils::~CCertUtils(void)
{
}

// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
bool CCertUtils::IsSequence(BYTE *content)
{
   return (content[0] == 0x30);
}


// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
bool CCertUtils::IsInteger(BYTE *content)
{
   return (content[0] == 0x02);
}


//------------------------------------------------------------------------------
// int ExtractContent(ASN1 *pAsn1)
//
// Description : Extract contents of a Asn1 block 'pAsn1->Asn1' and place it
//              in 'pAsn1->Content'.
//
// Remarks     : Field Asn1.pData is allocated by calling function.
//
// In          : pAsn1->Asn1.pData
//
// Out         : This fileds are filled (if RV_SUCCESS) :
//                - Tag
//                - Asn1.usLen
//                - Content.usLen
//                - Content.pData
//
// Responses   : RV_SUCCESS : All is OK.
//               RV_INVALID_DATA : Asn1 block format not supported.
//
//------------------------------------------------------------------------------
int CCertUtils::ExtractContent(ASN1 *pAsn1)

{
   BYTE
      *pData;
   int
      NbBytes,
      i;

   pData = pAsn1->Asn1.pData;

   if ((pData[0] & 0x1F) == 0x1F)
   {
      // High-tag-number : not supported
      return(RV_INVALID_DATA);
   }
   else
   {
      pAsn1->Tag = pData[0];
   }

   if (pData[1] == 0x80)
   {
      // Constructed, indefinite-length method : not supported
      return(RV_INVALID_DATA);
   }
   else if (pData[1] > 0x82)
   {
      // Constructed, definite-length method : too long
      return(RV_INVALID_DATA);
   }
   else if (pData[1] < 0x80)
   {
      // Primitive, definite-length method

      pAsn1->Content.usLen = pData[1];
      pAsn1->Content.pData = &pData[2];

      pAsn1->Asn1.usLen = ( USHORT )( pAsn1->Content.usLen + 2 );
   }
   else
   {
      // Constructed, definite-length method

      NbBytes = pData[1] & 0x7F;

      pAsn1->Content.usLen = 0;
      for (i = 0; i < NbBytes; i++)
      {
          pAsn1->Content.usLen = ( USHORT )( ( pAsn1->Content.usLen << 8 ) + pData[ 2 + i ] );
      }
      pAsn1->Content.pData = &pData[2+NbBytes];

      pAsn1->Asn1.usLen = ( USHORT )( pAsn1->Content.usLen + 2 + NbBytes );
   }

   return(RV_SUCCESS);
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void CCertUtils::MemReverse(BYTE *pbOut, BYTE *pbIn, DWORD dwLen)
{
   DWORD i;

   for (i = 0; i < dwLen; i++)
   {
      pbOut[i] = pbIn[dwLen - i -1];
   }
}


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void CCertUtils::ConvAscii (BYTE  *pIn,
                          DWORD  dwLen,
                          BYTE  *pOut
                         )
{
#define tohex(x)  (((x) >= 0xA) ? ((x) - 0xA + 'A') : ((x) + '0'))
   register DWORD i;

   for(i=0; i < dwLen; i++)
   {
      pOut[ i * 2 ] = ( BYTE )( tohex( ( pIn[ i ] >> 4)  & 0x0F ) );
      pOut[ i * 2 + 1 ] =  ( BYTE )( tohex( pIn[ i ] & 0x0F ) );
   }
}


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void CCertUtils::ConvHex (BYTE  *pIn,
                        DWORD  dwLen,
                        BYTE  *pOut
                       )
{
#define fromhex(x) (x-((x>='0')&&(x<='9')?'0':((x>='A')&&(x<='F')?'7':'W')))
   register DWORD i;

   for(i=0; i < dwLen; i+=2)
   {
      pOut[ i / 2 ] = ( BYTE )( ( fromhex( pIn[ i ] ) << 4 ) + fromhex( pIn[ i + 1 ] ) );
   }
}


// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
BYTE* CCertUtils::GetDERLength(BYTE *content, DWORD *len)
{
   DWORD NBBytesForLength = 0;
   unsigned short usLen = 0,i=0;


   if(content == NULL){
      *len = 0;
      return NULL;
   }
   if(content[1] < 0x80){
      *len = content[1];
      return &content[2];
   }

   NBBytesForLength = ( DWORD )( content[ 1 ] & 0x7F );

   usLen = 0;
   for (i = 0; i < NBBytesForLength; i++)
   {
       usLen = ( unsigned short )( ( usLen << 8 ) + content[ 2 + i ] );
   }

   *len = usLen;
   return &content[2+NBBytesForLength];

}


//------------------------------------------------------------------------------
// bool ParseCertificateValue(BYTE *pCert,          DWORD  dwCertLen,
//                            BYTE *pSerialNumber,  DWORD *pdwSerialNumberLen,
//                            BYTE *pIssuer,        DWORD *pdwIssuerLen,
//                            BYTE *pSubject,       DWORD *pdwSubjectLen
//                           )
//
// In          : pCert : Value of a valid X509 certificate.
//               dwCertLen : Length of value.
//
// Out         : pSerialNumber : Field 'SerialNumber'
//               pusSerialNumberLen : Serial number length
//               pIssuer : Field 'Issuer'
//               pusIssuerLen : Issuer length
//               pSubject : Field 'Subject'
//               pusSubjectLen : Subject length
//
// Responses   : true: All is OK.
//               false: Parsing fails.
//
//------------------------------------------------------------------------------
bool CCertUtils::ParseCertificateValue(BYTE *pCert,         DWORD /*dwCertLen*/,
                                       BYTE *pSerialNumber, DWORD *pdwSerialNumberLen,
                                       BYTE *pIssuer,       DWORD *pdwIssuerLen,
                                       BYTE *pSubject,      DWORD *pdwSubjectLen
                                      )

{
   ASN1
      Value,
      tbsCert,
      serialNumberPart,
      signaturePart,
      issuerPart,
      validityPart,
      subjectPart;
   bool
      bValuesToBeReturned;
   BYTE
      *pCurrent;
   int
      rv;
   DWORD
      SerialNumberLen,
      IssuerLen,
      SubjectLen;


   bValuesToBeReturned =   (pSerialNumber != NULL)
                        && (pIssuer != NULL)
                        && (pSubject != NULL);


   Value.Asn1.pData = pCert;
   rv = ExtractContent(&Value);
   if (rv != RV_SUCCESS) return false;

   tbsCert.Asn1.pData = Value.Content.pData;
   rv = ExtractContent(&tbsCert);
   if (rv != RV_SUCCESS) return false;


   pCurrent = tbsCert.Content.pData;
   if (pCurrent[0] == TAG_OPTION_VERSION)
   {
      // We have A0 03 02 01 vv  where vv is the version
      pCurrent += 5;
   }

   serialNumberPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&serialNumberPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = serialNumberPart.Content.pData + serialNumberPart.Content.usLen;

   signaturePart.Asn1.pData = pCurrent;
   rv = ExtractContent(&signaturePart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = signaturePart.Content.pData + signaturePart.Content.usLen;

   issuerPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&issuerPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = issuerPart.Content.pData + issuerPart.Content.usLen;

   validityPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&validityPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = validityPart.Content.pData + validityPart.Content.usLen;

   subjectPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&subjectPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = subjectPart.Content.pData + subjectPart.Content.usLen;


   SerialNumberLen = serialNumberPart.Content.usLen;
   IssuerLen = issuerPart.Asn1.usLen;
   SubjectLen = subjectPart.Asn1.usLen;

   if (bValuesToBeReturned)
   {
      if (    (*pdwSerialNumberLen < SerialNumberLen)
           || (*pdwIssuerLen < IssuerLen)
           || (*pdwSubjectLen < SubjectLen)
         )
      {
         return(false);
      }
      memcpy(pSerialNumber, serialNumberPart.Content.pData, SerialNumberLen);
      memcpy(pIssuer, issuerPart.Asn1.pData, IssuerLen);
      memcpy(pSubject, subjectPart.Asn1.pData, SubjectLen);
      *pdwSerialNumberLen = SerialNumberLen;
      *pdwIssuerLen = IssuerLen;
      *pdwSubjectLen = SubjectLen;
   }
   else
   {
      *pdwSerialNumberLen = SerialNumberLen;
      *pdwIssuerLen = IssuerLen;
      *pdwSubjectLen = SubjectLen;
   }

   return(true);
}


// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
bool CCertUtils::MakeCertificateLabel(BYTE  *pCert,
                                      DWORD  /*dwCertLen*/,
                                      BYTE  *pLabel,
                                      DWORD *pdwLabelLen
                                     )
{
   ASN1
        AttributeTypePart,
        AttributeValuePart,
        AVA,
        RDN,
      Value,
      tbsCert,
      serialNumberPart,
      signaturePart,
      issuerPart,
      validityPart,
      subjectPart;
    BLOC
        OrganizationName,
        CommonName;
   bool
      bValuesToBeReturned;
   BYTE
      *pCurrentRDN,
      *pCurrent;
   int
      rv;

    OrganizationName.pData = NULL;
    OrganizationName.usLen = 0;
    CommonName.pData = NULL;
    CommonName.usLen = 0;

    bValuesToBeReturned =   (pLabel != NULL);

   Value.Asn1.pData = pCert;
   rv = ExtractContent(&Value);
   if (rv != RV_SUCCESS) return false;

   tbsCert.Asn1.pData = Value.Content.pData;
   rv = ExtractContent(&tbsCert);
   if (rv != RV_SUCCESS) return false;


   pCurrent = tbsCert.Content.pData;
   if (pCurrent[0] == TAG_OPTION_VERSION)
   {
      /* We have A0 03 02 01 vv  where vv is the version                      */
      pCurrent += 5;
   }

   serialNumberPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&serialNumberPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = serialNumberPart.Content.pData + serialNumberPart.Content.usLen;

   signaturePart.Asn1.pData = pCurrent;
   rv = ExtractContent(&signaturePart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = signaturePart.Content.pData + signaturePart.Content.usLen;

   issuerPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&issuerPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = issuerPart.Content.pData + issuerPart.Content.usLen;

   validityPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&validityPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = validityPart.Content.pData + validityPart.Content.usLen;

   subjectPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&subjectPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = subjectPart.Content.pData + subjectPart.Content.usLen;


    // Search field 'OrganizationName' in 'Issuer'
   pCurrent = issuerPart.Content.pData;

   while (pCurrent < issuerPart.Content.pData + issuerPart.Content.usLen)
   {
      RDN.Asn1.pData = pCurrent;
      rv = ExtractContent(&RDN);
      if (rv != RV_SUCCESS) return false;

        pCurrentRDN = RDN.Content.pData;

        while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
        {
            AVA.Asn1.pData = pCurrentRDN;
            rv = ExtractContent(&AVA);
            if (rv != RV_SUCCESS) return false;

            AttributeTypePart.Asn1.pData = AVA.Content.pData;
            rv = ExtractContent(&AttributeTypePart);
            if (rv != RV_SUCCESS) return false;

            AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                    + AttributeTypePart.Content.usLen;
            rv = ExtractContent(&AttributeValuePart);
            if (rv != RV_SUCCESS) return false;

            // Search 'OrganisationName'
            if (!memcmp("\x55\x04\x0A",
                            AttributeTypePart.Content.pData,
                            AttributeTypePart.Content.usLen)
                )
            {
                OrganizationName = AttributeValuePart.Content;
            }

            pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
        }

        pCurrent = RDN.Content.pData + RDN.Content.usLen;
   }

   // If no 'OrganizationName' is 'Issuer' search for 'CommonName' in 'Subject'
   if (OrganizationName.usLen == 0)
   {
      pCurrent = issuerPart.Content.pData;

      while (pCurrent < issuerPart.Content.pData + issuerPart.Content.usLen)
      {
         RDN.Asn1.pData = pCurrent;
         rv = ExtractContent(&RDN);
         if (rv != RV_SUCCESS) return false;

         pCurrentRDN = RDN.Content.pData;

         while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
         {
               AVA.Asn1.pData = pCurrentRDN;
               rv = ExtractContent(&AVA);
               if (rv != RV_SUCCESS) return false;

               AttributeTypePart.Asn1.pData = AVA.Content.pData;
               rv = ExtractContent(&AttributeTypePart);
               if (rv != RV_SUCCESS) return false;

               AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                      + AttributeTypePart.Content.usLen;
               rv = ExtractContent(&AttributeValuePart);
               if (rv != RV_SUCCESS) return false;

               // Search 'CommonName'
               if (!memcmp("\x55\x04\x03",
                              AttributeTypePart.Content.pData,
                              AttributeTypePart.Content.usLen)
                  )
               {
                  OrganizationName = AttributeValuePart.Content;
               }

               pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
         }

         pCurrent = RDN.Content.pData + RDN.Content.usLen;
      }
   }

   // Search 'CommonName' in 'Subject'
   pCurrent = subjectPart.Content.pData;

   while (pCurrent < subjectPart.Content.pData + subjectPart.Content.usLen)
   {
      RDN.Asn1.pData = pCurrent;
      rv = ExtractContent(&RDN);
      if (rv != RV_SUCCESS) return false;

        pCurrentRDN = RDN.Content.pData;

        while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
        {
            AVA.Asn1.pData = pCurrentRDN;
            rv = ExtractContent(&AVA);
            if (rv != RV_SUCCESS) return false;

            AttributeTypePart.Asn1.pData = AVA.Content.pData;
            rv = ExtractContent(&AttributeTypePart);
            if (rv != RV_SUCCESS) return false;

            AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                    + AttributeTypePart.Content.usLen;
            rv = ExtractContent(&AttributeValuePart);
            if (rv != RV_SUCCESS) return false;

            // Search 'CommonName'
            if (!memcmp("\x55\x04\x03",
                            AttributeTypePart.Content.pData,
                            AttributeTypePart.Content.usLen)
                )
            {
                CommonName = AttributeValuePart.Content;
            }

            pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
        }

        pCurrent = RDN.Content.pData + RDN.Content.usLen;
   }

    if (bValuesToBeReturned)
    {
        if (    (*pdwLabelLen < (DWORD)(OrganizationName.usLen + CommonName.usLen))
           )
        {
            return(false);
        }

        if (CommonName.usLen > 0)
        {
           memcpy(pLabel,
                CommonName.pData,
                CommonName.usLen
               );
           memcpy(&pLabel[CommonName.usLen],
                "'s ",
                3
               );
           memcpy(&pLabel[CommonName.usLen+3],
                OrganizationName.pData,
                OrganizationName.usLen
               );
           memcpy(&pLabel[CommonName.usLen+3+OrganizationName.usLen],
                " ID",
                3
               );

           *pdwLabelLen = ( DWORD )( OrganizationName.usLen + CommonName.usLen + 6 );
        }
        else
        {
           memcpy(pLabel,
                OrganizationName.pData,
                OrganizationName.usLen
               );
           memcpy(&pLabel[OrganizationName.usLen],
                " ID",
                3
               );

           *pdwLabelLen = ( DWORD )( OrganizationName.usLen + 3 );
        }
    }
    else
    {
        if (CommonName.usLen > 0)
        {
           *pdwLabelLen = OrganizationName.usLen + CommonName.usLen + 6;
        }
        else
        {
           *pdwLabelLen = ( DWORD )( OrganizationName.usLen + 3 );
        }
    }

    return(true);
}


// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
bool CCertUtils::MakeCertificateLabelEx(BYTE  *pCert,
                                        DWORD  /*dwCertLen*/,
                                        BYTE  *pLabel,
                                        DWORD *pdwLabelLen
                                       )
{
   ASN1
        AttributeTypePart,
        AttributeValuePart,
        AVA,
        RDN,
      Value,
      tbsCert,
      serialNumberPart,
      signaturePart,
      issuerPart,
      validityPart,
      subjectPart;
    BLOC
        OrganizationName,
        CommonName;
   bool
      bValuesToBeReturned;
   BYTE
      *pCurrentRDN,
      *pCurrent,
      szSerialNumber[256] = "";
   int
      rv;

    OrganizationName.pData = NULL;
    OrganizationName.usLen = 0;
    CommonName.pData = NULL;
    CommonName.usLen = 0;

    bValuesToBeReturned =   (pLabel != NULL);

   Value.Asn1.pData = pCert;
   rv = ExtractContent(&Value);
   if (rv != RV_SUCCESS) return false;

   tbsCert.Asn1.pData = Value.Content.pData;
   rv = ExtractContent(&tbsCert);
   if (rv != RV_SUCCESS) return false;


   pCurrent = tbsCert.Content.pData;
   if (pCurrent[0] == TAG_OPTION_VERSION)
   {
      /* We have A0 03 02 01 vv  where vv is the version                      */
      pCurrent += 5;
   }

   serialNumberPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&serialNumberPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = serialNumberPart.Content.pData + serialNumberPart.Content.usLen;

   memset(szSerialNumber, 0x00, sizeof(szSerialNumber));

   ConvAscii(serialNumberPart.Asn1.pData, serialNumberPart.Asn1.usLen, szSerialNumber);

   signaturePart.Asn1.pData = pCurrent;
   rv = ExtractContent(&signaturePart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = signaturePart.Content.pData + signaturePart.Content.usLen;

   issuerPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&issuerPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = issuerPart.Content.pData + issuerPart.Content.usLen;

   validityPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&validityPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = validityPart.Content.pData + validityPart.Content.usLen;

   subjectPart.Asn1.pData = pCurrent;
   rv = ExtractContent(&subjectPart);
   if (rv != RV_SUCCESS) return false;
   pCurrent = subjectPart.Content.pData + subjectPart.Content.usLen;


    // Search field 'OrganizationName' in 'Issuer'
   pCurrent = issuerPart.Content.pData;

   while (pCurrent < issuerPart.Content.pData + issuerPart.Content.usLen)
   {
      RDN.Asn1.pData = pCurrent;
      rv = ExtractContent(&RDN);
      if (rv != RV_SUCCESS) return false;

        pCurrentRDN = RDN.Content.pData;

        while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
        {
            AVA.Asn1.pData = pCurrentRDN;
            rv = ExtractContent(&AVA);
            if (rv != RV_SUCCESS) return false;

            AttributeTypePart.Asn1.pData = AVA.Content.pData;
            rv = ExtractContent(&AttributeTypePart);
            if (rv != RV_SUCCESS) return false;

            AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                    + AttributeTypePart.Content.usLen;
            rv = ExtractContent(&AttributeValuePart);
            if (rv != RV_SUCCESS) return false;

            // Search 'OrganisationName'
            if (!memcmp("\x55\x04\x0A",
                            AttributeTypePart.Content.pData,
                            AttributeTypePart.Content.usLen)
                )
            {
                OrganizationName = AttributeValuePart.Content;
            }

            pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
        }

        pCurrent = RDN.Content.pData + RDN.Content.usLen;
   }

   // If no 'OrganizationName' is 'Issuer' search for 'CommonName' in 'Subject'
   if (OrganizationName.usLen == 0)
   {
      pCurrent = issuerPart.Content.pData;

      while (pCurrent < issuerPart.Content.pData + issuerPart.Content.usLen)
      {
         RDN.Asn1.pData = pCurrent;
         rv = ExtractContent(&RDN);
         if (rv != RV_SUCCESS) return false;

         pCurrentRDN = RDN.Content.pData;

         while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
         {
               AVA.Asn1.pData = pCurrentRDN;
               rv = ExtractContent(&AVA);
               if (rv != RV_SUCCESS) return false;

               AttributeTypePart.Asn1.pData = AVA.Content.pData;
               rv = ExtractContent(&AttributeTypePart);
               if (rv != RV_SUCCESS) return false;

               AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                      + AttributeTypePart.Content.usLen;
               rv = ExtractContent(&AttributeValuePart);
               if (rv != RV_SUCCESS) return false;

               // Search 'CommonName'
               if (!memcmp("\x55\x04\x03",
                              AttributeTypePart.Content.pData,
                              AttributeTypePart.Content.usLen)
                  )
               {
                  OrganizationName = AttributeValuePart.Content;
               }

               pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
         }

         pCurrent = RDN.Content.pData + RDN.Content.usLen;
      }
   }

   // Search 'CommonName' in 'Subject'
   pCurrent = subjectPart.Content.pData;

   while (pCurrent < subjectPart.Content.pData + subjectPart.Content.usLen)
   {
      RDN.Asn1.pData = pCurrent;
      rv = ExtractContent(&RDN);
      if (rv != RV_SUCCESS) return false;

        pCurrentRDN = RDN.Content.pData;

        while (pCurrentRDN < RDN.Content.pData + RDN.Content.usLen)
        {
            AVA.Asn1.pData = pCurrentRDN;
            rv = ExtractContent(&AVA);
            if (rv != RV_SUCCESS) return false;

            AttributeTypePart.Asn1.pData = AVA.Content.pData;
            rv = ExtractContent(&AttributeTypePart);
            if (rv != RV_SUCCESS) return false;

            AttributeValuePart.Asn1.pData = AttributeTypePart.Content.pData
                                                    + AttributeTypePart.Content.usLen;
            rv = ExtractContent(&AttributeValuePart);
            if (rv != RV_SUCCESS) return false;

            // Search 'CommonName'
            if (!memcmp("\x55\x04\x03",
                            AttributeTypePart.Content.pData,
                            AttributeTypePart.Content.usLen)
                )
            {
                CommonName = AttributeValuePart.Content;
            }

            pCurrentRDN = AVA.Content.pData + AVA.Content.usLen;
        }

        pCurrent = RDN.Content.pData + RDN.Content.usLen;
   }

    if (bValuesToBeReturned)
    {
        if (    (*pdwLabelLen < (DWORD)(OrganizationName.usLen + CommonName.usLen))
           )
        {
            return(false);
        }

        if (CommonName.usLen > 0)
        {
           memcpy(pLabel,
                CommonName.pData,
                CommonName.usLen
               );
           memcpy(&pLabel[CommonName.usLen],
                "'s ",
                3
               );
           memcpy(&pLabel[CommonName.usLen+3],
                OrganizationName.pData,
                OrganizationName.usLen
               );
           memcpy(&pLabel[CommonName.usLen+3+OrganizationName.usLen],
                " ID - ",
                6
               );
           memcpy(&pLabel[CommonName.usLen+3+OrganizationName.usLen+6],
                szSerialNumber,
                strlen((char *)szSerialNumber)
               );

           *pdwLabelLen = OrganizationName.usLen + CommonName.usLen + (DWORD)strlen((char *)szSerialNumber) + 9;
        }
        else
        {
           memcpy(pLabel,
                OrganizationName.pData,
                OrganizationName.usLen
               );
           memcpy(&pLabel[OrganizationName.usLen],
                " ID - ",
                6
               );
           memcpy(&pLabel[OrganizationName.usLen+6],
                szSerialNumber,
                strlen((char *)szSerialNumber)
               );

           *pdwLabelLen = OrganizationName.usLen + (DWORD)strlen((char *)szSerialNumber) + 6;
        }
    }
    else
    {
        if (CommonName.usLen > 0)
        {
           *pdwLabelLen = OrganizationName.usLen + CommonName.usLen + (DWORD)strlen((char *)szSerialNumber) + 9;
        }
        else
        {
           *pdwLabelLen = OrganizationName.usLen + (DWORD)strlen((char *)szSerialNumber) + 6;
        }
    }

    return(true);
}


