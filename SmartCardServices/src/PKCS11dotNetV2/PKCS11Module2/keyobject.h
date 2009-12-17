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

#ifndef _include_keyobject_h
#define _include_keyobject_h

#include "storageobject.h"

class KeyObject : public StorageObject
{
public:
    CK_ULONG    _keyType;
    u1Array*    _id;
    u1Array*    _startDate;
    u1Array*    _endDate;
    CK_BBOOL    _derive;
    CK_BBOOL    _local;
    CK_ULONG    _mechanismType;
    u4Array*    _allowedMechanism;

public:
    KeyObject();
    virtual ~KeyObject();

    virtual CK_BBOOL Compare(CK_ATTRIBUTE attribute);
    virtual CK_RV SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation);
    virtual CK_RV GetAttribute(CK_ATTRIBUTE_PTR attribute);

    virtual void Serialize(vector<u1>* to);
    virtual void Deserialize(vector<u1> from,CK_ULONG_PTR idx);

};

#endif

