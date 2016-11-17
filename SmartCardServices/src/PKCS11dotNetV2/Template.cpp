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


#include "Template.hpp"
#include <boost/foreach.hpp>
#include "PKCS11Exception.hpp"
#include "Log.hpp"


extern bool IS_LITTLE_ENDIAN;


/*
*/
Template::Template( CK_ATTRIBUTE_PTR a_Template, const CK_ULONG& a_ulCount ) {

    for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

        CK_ATTRIBUTE a;

        a.type = a_Template[ i ].type;

        a.ulValueLen = a_Template[ i ].ulValueLen;

        a.pValue = NULL_PTR;

        if( a.ulValueLen > 0 ) {

            a.pValue = new CK_BYTE[ a.ulValueLen ];
            
            memcpy( a.pValue, a_Template[ i ].pValue, a.ulValueLen );
        }

        m_Attributes.push_back( a );
    }
}


/*
*/
Template::~Template( ) {

    BOOST_FOREACH( CK_ATTRIBUTE& a, m_Attributes ) {

        if( 1 == a.ulValueLen ) {

            delete ( ( CK_BYTE* ) a.pValue );

        } else if( a.ulValueLen > 1 ) {
        
            delete[ ] ( ( CK_BYTE* ) a.pValue );
        }
    }
}


/*
*/
void Template::fixEndianness( CK_ATTRIBUTE& a_attribute ) {

    // Only for Little Endian processors
    if( IS_LITTLE_ENDIAN ) {

        // we need to fix the endianness if we are dealing with data on 2 or 4 or 8 bytes
        switch( a_attribute.ulValueLen ) {

        case 2:
        case 4:
        case 8:
            {
                // fix up needs to be done for specific attributes. Byte arrays may have sizes of 2,4 or 8
                switch( a_attribute.type ) {

                    // CK_ULONG data types
                case CKA_CLASS:
                case CKA_CERTIFICATE_TYPE:
                case CKA_JAVA_MIDP_SECURITY_DOMAIN:
                case CKA_KEY_TYPE:
                case CKA_KEY_GEN_MECHANISM:
                case CKA_MODULUS_BITS:
                    {
                        //PKCS11_ASSERT(attrTemplate.ulValueLen == sizeof(CK_ULONG));
                        CK_BYTE b1 = ((CK_BYTE_PTR)a_attribute.pValue)[0];
                        CK_BYTE b2 = ((CK_BYTE_PTR)a_attribute.pValue)[1];
                        CK_BYTE b3 = ((CK_BYTE_PTR)a_attribute.pValue)[2];
                        CK_BYTE b4 = ((CK_BYTE_PTR)a_attribute.pValue)[3];
                        ((CK_BYTE_PTR)a_attribute.pValue)[3] = b1;
                        ((CK_BYTE_PTR)a_attribute.pValue)[2] = b2;
                        ((CK_BYTE_PTR)a_attribute.pValue)[1] = b3;
                        ((CK_BYTE_PTR)a_attribute.pValue)[0] = b4;
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


/*
*/
CK_OBJECT_CLASS Template::getClass( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    for( CK_ULONG idx = 0; idx < a_ulCount ; ++idx ) {

        if( CKA_CLASS == a_pTemplate[ idx ].type ) {

            return (*(CK_ULONG*)a_pTemplate[ idx ].pValue);
        }
    }

    return CK_UNAVAILABLE_INFORMATION;
}


/*
*/
CK_CERTIFICATE_TYPE Template::getCertificateType( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    for( CK_ULONG idx = 0; idx < a_ulCount ; ++idx ) {

        if( CKA_CERTIFICATE_TYPE == a_pTemplate[ idx ].type ) {

            return (*(CK_ULONG*)a_pTemplate[ idx ].pValue);
        }
    }

    return CK_UNAVAILABLE_INFORMATION;
}


/*
*/
bool Template::isToken( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    for( CK_ULONG idx = 0; idx < a_ulCount ; ++idx ) {

        if( CKA_TOKEN == a_pTemplate[ idx ].type ) {

            return (*(bool*)a_pTemplate[ idx ].pValue);
        }
    }

    return false;
}


/*
*/
bool Template::isPrivate( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    for( CK_ULONG idx = 0; idx < a_ulCount ; ++idx ) {

        if( CKA_PRIVATE == a_pTemplate[ idx ].type ) {

            return (*(bool*)a_pTemplate[ idx ].pValue);
        }
    }

    return false;
}


/*
*/
bool Template::isPresent( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount, const CK_ATTRIBUTE_TYPE& a_ulType ) {

    for( CK_ULONG idx = 0; idx < a_ulCount ; ++idx ) {

        if( a_ulType == a_pTemplate[ idx ].type ) {

            return true;
        }
    }

    return false;
}


/*
*/
void Template::checkTemplate( CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount, const CK_BYTE& a_bMode ) {

    // Get Object Class
    CK_OBJECT_CLASS c = getClass( a_pTemplate, a_ulCount );

    // Get Cert Type
    CK_CERTIFICATE_TYPE t = CK_UNAVAILABLE_INFORMATION;
    if( CKO_CERTIFICATE == c ) {

        t = getCertificateType( a_pTemplate, a_ulCount );
    }

    // Check Creation Template
    if( MODE_CREATE == a_bMode ) {

        switch( c ) {

        case CKO_DATA:
            {
                if( isPresent( a_pTemplate, a_ulCount, CKA_CLASS ) ) {
                    return;
                }
            }
            break;

        case CKO_CERTIFICATE:
            {
                if( ( CKC_X_509 == t ) && isPresent( a_pTemplate, a_ulCount, CKA_CLASS ) && isPresent( a_pTemplate, a_ulCount, CKA_SUBJECT ) && isPresent( a_pTemplate, a_ulCount, CKA_VALUE ) ) {

                    return;

                } else if( ( CKC_X_509_ATTR_CERT == t ) && isPresent( a_pTemplate, a_ulCount, CKA_CLASS ) && isPresent( a_pTemplate, a_ulCount, CKA_OWNER ) && isPresent( a_pTemplate, a_ulCount, CKA_VALUE ) ) {

                    return;

                } else {
                    throw PKCS11Exception( CKR_TEMPLATE_INCONSISTENT );
                }
            }
            break;

        case CKO_PUBLIC_KEY:
            {
                if(  isPresent( a_pTemplate, a_ulCount, CKA_CLASS ) && isPresent( a_pTemplate, a_ulCount, CKA_KEY_TYPE ) && !isPresent( a_pTemplate, a_ulCount, CKA_LOCAL ) && !isPresent( a_pTemplate, a_ulCount, CKA_KEY_GEN_MECHANISM )
                    && isPresent( a_pTemplate, a_ulCount, CKA_MODULUS ) && !isPresent( a_pTemplate, a_ulCount, CKA_MODULUS_BITS ) && isPresent(a_pTemplate, a_ulCount, CKA_PUBLIC_EXPONENT ) ) {

                        return;
                }
            }
            break;

        case CKO_PRIVATE_KEY:
            {
                if (  ( isPresent(a_pTemplate, a_ulCount, CKA_CLASS))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_KEY_TYPE))
                    &&(!isPresent(a_pTemplate, a_ulCount, CKA_LOCAL))
                    &&(!isPresent(a_pTemplate, a_ulCount, CKA_KEY_GEN_MECHANISM))
                    &&(!isPresent(a_pTemplate, a_ulCount, CKA_ALWAYS_SENSITIVE))
                    &&(!isPresent(a_pTemplate, a_ulCount, CKA_NEVER_EXTRACTABLE))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_MODULUS))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_PRIVATE_EXPONENT))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_PRIME_1))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_PRIME_2))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_EXPONENT_1))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_EXPONENT_2))
                    &&( isPresent(a_pTemplate, a_ulCount, CKA_COEFFICIENT))
                    )
                {
                    return;
                }
            }
            break;

        default:
            throw PKCS11Exception( CKR_TEMPLATE_INCONSISTENT );

        }
    }

    // Check Public Key Generation Template
    else if (a_bMode == MODE_GENERATE_PUB)
    {
        if (  (!isPresent(a_pTemplate, a_ulCount, CKA_LOCAL))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_KEY_GEN_MECHANISM))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_MODULUS))
            &&( isPresent(a_pTemplate, a_ulCount, CKA_MODULUS_BITS))
            &&( isPresent(a_pTemplate, a_ulCount, CKA_PUBLIC_EXPONENT))
            )
        {
            return;
        }
    }

    // Check Private Key Generation Template
    else if (a_bMode == MODE_GENERATE_PRIV)
    {
        if (  (!isPresent(a_pTemplate, a_ulCount, CKA_LOCAL))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_KEY_GEN_MECHANISM))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_ALWAYS_SENSITIVE))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_NEVER_EXTRACTABLE))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_MODULUS))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_PUBLIC_EXPONENT))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_PRIVATE_EXPONENT))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_PRIME_1))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_PRIME_2))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_EXPONENT_1))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_EXPONENT_2))
            &&(!isPresent(a_pTemplate, a_ulCount, CKA_COEFFICIENT))
            )
        {
            return;
        }
    }

    throw PKCS11Exception( CKR_TEMPLATE_INCONSISTENT );

}
