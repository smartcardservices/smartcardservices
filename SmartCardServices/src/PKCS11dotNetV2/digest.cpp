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
#include "digest.h"

CDigest::CDigest(){
    this->_counter       = 0;
    this->_workingOffset = 0;
    this->_workingLength = 0;
}

CDigest::~CDigest(){
    free(this->_hashValue);
    free(this->_workingBuffer);
}

void CDigest::HashCore(CK_BYTE_PTR data,CK_LONG offset,CK_LONG count)
{
    while (count > 0)
    {
        // prepare working buffer.
        if ((_workingOffset + count) >= this->_blockLength){
            _workingLength = this->_blockLength - _workingOffset;
        }
        else{
            _workingLength = count;
        }

        memcpy(&_workingBuffer[_workingOffset],&data[offset],_workingLength);

        _workingOffset += _workingLength;
        count -= _workingLength;
        offset += _workingLength;

        if ((_workingOffset == this->_blockLength) && (count > 0)){

            TransformBlock(_workingBuffer,_counter,_hashValue);

            _counter += this->_blockLength;
            _workingOffset = 0;
        }
    }
}

void CDigest::HashFinal(CK_BYTE_PTR hash)
{
    TransformFinalBlock(_workingBuffer,_workingOffset,_counter,_hashValue);
    memcpy(hash,_hashValue,this->_hashLength);
}

CK_LONG CDigest::HashLength(void)
{
    return this->_hashLength;
}

