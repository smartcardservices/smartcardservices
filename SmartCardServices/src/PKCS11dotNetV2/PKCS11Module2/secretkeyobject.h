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

#ifndef _include_secretkeyobject_h
#define _include_secretkeyobject_h

#include "keyobject.h"

class SecretKeyObject : public KeyObject
{

public:
    CK_BBOOL    _sensitive;
    CK_BBOOL    _encrypt;
    CK_BBOOL    _decrypt;
    CK_BBOOL    _sign;
    CK_BBOOL    _verify;
    CK_BBOOL    _wrap;
    CK_BBOOL    _unwrap;
    CK_BBOOL    _extractable;
    CK_BBOOL    _alwaysSensitive;
    CK_BBOOL    _neverExtractable;
    u1Array*    _checkSum;
    CK_BBOOL    _wrapWithTrusted;
    CK_BBOOL    _trusted;

    u1Array*    _value;
    CK_ULONG    _valueLength;

public:
    SecretKeyObject();
    ~SecretKeyObject();

    CK_BBOOL Compare(CK_ATTRIBUTE attribute);
    CK_RV SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation);
    CK_RV GetAttribute(CK_ATTRIBUTE_PTR attribute);

    void Serialize(vector<u1>* to);
    void Deserialize(vector<u1> from,CK_ULONG_PTR idx);

};

#endif

