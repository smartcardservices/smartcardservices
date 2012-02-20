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

#ifndef _include_publickeyobject_h
#define _include_publickeyobject_h

#include "keyobject.h"

class PublicKeyObject : public KeyObject
{

public:
    u1Array*     _subject;
    CK_BBOOL     _encrypt;
    CK_BBOOL     _verify;
    CK_BBOOL     _verifyRecover;
    CK_BBOOL     _wrap;
    CK_BBOOL     _trusted;

    // extra fields which are not part of PKCS#11
    // but are needed as extra information in card
    CK_BYTE     _ctrIndex;
    CK_BYTE     _keySpec;

public:
    PublicKeyObject();
    virtual ~PublicKeyObject();

    virtual CK_BBOOL Compare(CK_ATTRIBUTE attribute);
    virtual CK_RV SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation);
    virtual CK_RV GetAttribute(CK_ATTRIBUTE_PTR attribute);

    virtual void Serialize(vector<u1>* to);
    virtual void Deserialize(vector<u1> from,CK_ULONG_PTR idx);

};

#endif

