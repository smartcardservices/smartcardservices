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

#ifndef _include_dataobject_h
#define _include_dataobject_h

#include "storageobject.h"

class DataObject : public StorageObject
{

public:
    u1Array* _appName;
    u1Array* _objId;
    u1Array* _objValue;

public:

    DataObject();
    ~DataObject();

    CK_BBOOL Compare(CK_ATTRIBUTE attribute);
    CK_RV SetAttribute(CK_ATTRIBUTE attribute,CK_BBOOL objCreation);
    CK_RV GetAttribute(CK_ATTRIBUTE_PTR attribute);

    void Serialize(vector<u1>* to);
    void Deserialize(vector<u1> from,CK_ULONG_PTR idx);


};


#endif

