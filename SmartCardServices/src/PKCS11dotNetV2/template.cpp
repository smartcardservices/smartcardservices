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
#include "template.h"

Template::Template(CK_ATTRIBUTE_PTR attrTemplate,CK_ULONG ulCount){


   for(CK_ULONG i=0;i<ulCount;i++){
      CK_ATTRIBUTE attribute;

      attribute.type = attrTemplate[i].type;
      attribute.ulValueLen = attrTemplate[i].ulValueLen;
      attribute.pValue = NULL_PTR;

      if(attribute.ulValueLen > 0) {
         attribute.pValue = malloc(attribute.ulValueLen);
         memcpy(attribute.pValue, attrTemplate[i].pValue, attribute.ulValueLen);
      }

      this->_attributes.push_back(attribute);
   }
}


Template::~Template( )
{
   std::vector<CK_ATTRIBUTE>::size_type sz = _attributes.size( );
   for( std::vector<CK_ATTRIBUTE>::size_type i = 0 ; i < sz ; i++ )
   {
      if( NULL_PTR != _attributes[ i ].pValue )
      {
         free( _attributes[ i ].pValue );
      }
   }
}


void Template::FixEndianness(CK_ATTRIBUTE attrTemplate)
{
   // Only for Little Endian processors
   if (IS_LITTLE_ENDIAN)
   {
      // we need to fix the endianness if
      // we are dealing with data on 2 or 4 or 8 bytes
      switch(attrTemplate.ulValueLen)
      {
      case 2:
      case 4:
      case 8:
         {
            // fix up needs to be done for specific
            // attributes. Byte arrays may have sizes of 2,4 or 8
            switch(attrTemplate.type)
            {
               // CK_ULONG data types
            case CKA_CLASS:
            case CKA_CERTIFICATE_TYPE:
            case CKA_JAVA_MIDP_SECURITY_DOMAIN:
            case CKA_KEY_TYPE:
            case CKA_KEY_GEN_MECHANISM:
            case CKA_MODULUS_BITS:
               {
                  PKCS11_ASSERT(attrTemplate.ulValueLen == sizeof(CK_ULONG));
                  CK_BYTE b1 = ((CK_BYTE_PTR)attrTemplate.pValue)[0];
                  CK_BYTE b2 = ((CK_BYTE_PTR)attrTemplate.pValue)[1];
                  CK_BYTE b3 = ((CK_BYTE_PTR)attrTemplate.pValue)[2];
                  CK_BYTE b4 = ((CK_BYTE_PTR)attrTemplate.pValue)[3];
                  ((CK_BYTE_PTR)attrTemplate.pValue)[3] = b1;
                  ((CK_BYTE_PTR)attrTemplate.pValue)[2] = b2;
                  ((CK_BYTE_PTR)attrTemplate.pValue)[1] = b3;
                  ((CK_BYTE_PTR)attrTemplate.pValue)[0] = b4;
               }
               break;
            }
         }
         break;

      default:
         break;
      }
   }
}

CK_ULONG Template::FindClassFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount)
{
   CK_ULONG idx = 0;

   for(idx=0;idx<ulCount;idx++)
   {
      if(pTemplate[idx].type == CKA_CLASS)
      {
         return *(CK_ULONG*)pTemplate[idx].pValue;
      }
   }

   return (CK_ULONG)-1;
}

CK_ULONG Template::FindCertTypeFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount)
{
   CK_ULONG idx = 0;

   for(idx=0;idx<ulCount;idx++)
   {
      if(pTemplate[idx].type == CKA_CERTIFICATE_TYPE)
      {
         return *(CK_ULONG*)pTemplate[idx].pValue;
      }
   }

   return (CK_ULONG)-1;
}

CK_BBOOL Template::FindTokenFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount)
{
   CK_ULONG idx = 0;

   for(idx=0;idx<ulCount;idx++)
   {
      if(pTemplate[idx].type == CKA_TOKEN)
      {
         return *(CK_BBOOL*)pTemplate[idx].pValue;
      }
   }

   return CK_FALSE;
}

CK_BBOOL Template::IsAttrInTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_ATTRIBUTE_TYPE AttrType)
{
   CK_ULONG idx = 0;

   for(idx=0;idx<ulCount;idx++)
   {
      if(pTemplate[idx].type == AttrType)
      {
         return CK_TRUE;
      }
   }

   return CK_FALSE;
}

CK_RV Template::CheckTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_BYTE bMode)
{
   CK_OBJECT_CLASS     ObjClass = (CK_ULONG)-1;
   CK_CERTIFICATE_TYPE CertType = (CK_ULONG)-1;

   // Get Object Class
   ObjClass = FindClassFromTemplate(pTemplate, ulCount);

   // Get Cert Type
   if (ObjClass == CKO_CERTIFICATE)
   {
      CertType = FindCertTypeFromTemplate(pTemplate, ulCount);
   }

   // Check Creation Template
   if (bMode == MODE_CREATE)
   {
      switch (ObjClass)
      {
      case CKO_DATA:
         {
            if (IsAttrInTemplate(pTemplate, ulCount, CKA_CLASS))
            {
               return CKR_OK;
            }
         }
         break;

      case CKO_CERTIFICATE:
         {
            if (CertType == CKC_X_509)
            {
               if (  (IsAttrInTemplate(pTemplate, ulCount, CKA_CLASS))
                  &&(IsAttrInTemplate(pTemplate, ulCount, CKA_SUBJECT))
                  &&(IsAttrInTemplate(pTemplate, ulCount, CKA_VALUE))
                  )
               {
                  return CKR_OK;
               }
            }

            else if (CertType == CKC_X_509_ATTR_CERT)
            {
               if (  (IsAttrInTemplate(pTemplate, ulCount, CKA_CLASS))
                  &&(IsAttrInTemplate(pTemplate, ulCount, CKA_OWNER))
                  &&(IsAttrInTemplate(pTemplate, ulCount, CKA_VALUE))
                  )
               {
                  return CKR_OK;
               }
            }

            else
            {
               return CKR_TEMPLATE_INCONSISTENT;
            }
         }
         break;

      case CKO_PUBLIC_KEY:
         {
            if (  ( IsAttrInTemplate(pTemplate, ulCount, CKA_CLASS))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_TYPE))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_LOCAL))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_GEN_MECHANISM))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS_BITS))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_PUBLIC_EXPONENT))
               )
            {
               return CKR_OK;
            }
         }
         break;

      case CKO_PRIVATE_KEY:
         {
            if (  ( IsAttrInTemplate(pTemplate, ulCount, CKA_CLASS))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_TYPE))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_LOCAL))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_GEN_MECHANISM))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_ALWAYS_SENSITIVE))
               &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_NEVER_EXTRACTABLE))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_PRIVATE_EXPONENT))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_PRIME_1))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_PRIME_2))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_EXPONENT_1))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_EXPONENT_2))
               &&( IsAttrInTemplate(pTemplate, ulCount, CKA_COEFFICIENT))
               )
            {
               return CKR_OK;
            }
         }
         break;

      default:
         return CKR_TEMPLATE_INCONSISTENT;
      }
   }

   // Check Public Key Generation Template
   else if (bMode == MODE_GENERATE_PUB)
   {
      if (  (!IsAttrInTemplate(pTemplate, ulCount, CKA_LOCAL))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_GEN_MECHANISM))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS))
         &&( IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS_BITS))
         &&( IsAttrInTemplate(pTemplate, ulCount, CKA_PUBLIC_EXPONENT))
         )
      {
         return CKR_OK;
      }
   }

   // Check Private Key Generation Template
   else if (bMode == MODE_GENERATE_PRIV)
   {
      if (  (!IsAttrInTemplate(pTemplate, ulCount, CKA_LOCAL))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_KEY_GEN_MECHANISM))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_ALWAYS_SENSITIVE))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_NEVER_EXTRACTABLE))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_MODULUS))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_PUBLIC_EXPONENT))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_PRIVATE_EXPONENT))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_PRIME_1))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_PRIME_2))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_EXPONENT_1))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_EXPONENT_2))
         &&(!IsAttrInTemplate(pTemplate, ulCount, CKA_COEFFICIENT))
         )
      {
         return CKR_OK;
      }
   }

   return CKR_TEMPLATE_INCONSISTENT;
}
