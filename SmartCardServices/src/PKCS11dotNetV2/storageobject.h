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

#ifndef _include_storageobject_h
#define _include_storageobject_h

#include <string>
#include <MarshallerCfg.h>
#include <Array.h>
#include <vector>

using namespace std;
using namespace Marshaller;

class StorageObject {


public:
    CK_BBOOL        _version;       // Version is used to manage evolution of the storage.
    u8              _uniqueId;      // A random number that identifies this object
    CK_ULONG		_class;
    CK_BBOOL		_tokenObject;
    CK_BBOOL		_private;
    CK_BBOOL		_modifiable;
    u1Array*		_label;

    // extra fields (not part of PKCS#11 spec
    std::string     _fileName;      // name of the file in the card which contains this object

    StorageObject();
    virtual ~StorageObject();

    virtual bool IsEqual(const StorageObject * that) const;
    virtual CK_BBOOL Compare(CK_ATTRIBUTE attribute);
    virtual CK_RV SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation);
    virtual CK_RV GetAttribute(CK_ATTRIBUTE_PTR attribute);

    virtual void Serialize(vector<u1>* to);
    virtual void Deserialize(vector<u1> from,CK_ULONG_PTR idx);

protected:
    static CK_RV PutU1ArrayInAttribute(u1Array* value,CK_ATTRIBUTE_PTR attribute);
    static CK_RV PutU4ArrayInAttribute(u4Array* value,CK_ATTRIBUTE_PTR attribute);
    static CK_RV PutULongInAttribute(CK_ULONG value, CK_ATTRIBUTE_PTR attribute);
    static CK_RV PutBBoolInAttribute(CK_BBOOL value, CK_ATTRIBUTE_PTR attribute);

    static CK_BBOOL ReadBBoolFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv);
    static CK_ULONG ReadULongFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv);
    static u1Array* ReadU1ArrayFromAttribute(CK_ATTRIBUTE attribute);
    static u1Array* ReadDateFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv);
    static u1Array* ReadStringFromAttribute(CK_ATTRIBUTE attribute,CK_RV* rv);
};



#endif

