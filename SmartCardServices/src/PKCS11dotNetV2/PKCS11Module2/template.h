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

#ifndef _include_template_h
#define _include_template_h

#include <list>
#include <vector>

using namespace std;

#define MODE_CREATE        0x01
#define MODE_GENERATE_PUB  0x02
#define MODE_GENERATE_PRIV 0x03

class Template
{

public:
    vector<CK_ATTRIBUTE> _attributes;

public:
    Template(CK_ATTRIBUTE_PTR temp,CK_ULONG ulCount);
    ~Template();

    static void FixEndianness(CK_ATTRIBUTE attrTemplate);

    static CK_ULONG FindClassFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
    static CK_ULONG FindCertTypeFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
    static CK_BBOOL FindTokenFromTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
    static CK_BBOOL IsAttrInTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_ATTRIBUTE_TYPE AttrType);
    static CK_RV CheckTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_BYTE bMode);

};



#endif

