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

//#include "stdafx.h"
#include "cryptoki.h"
//#include "symmalgo.h"
#include "des.h"

CDES::CDES(){
    _blockSize = 8;
}

CDES::~CDES(){
}

void CDES::TransformBlockInternal(CK_BYTE_PTR iv,CK_BYTE_PTR key,CK_LONG encryptMode,
                                  CK_BYTE_PTR input,CK_LONG input_offset,
                                  CK_BYTE_PTR output,CK_LONG output_offset)
{
    // encryprtMode == ENCRYPT then we need to XOR input with iv
    if(iv != NULL_PTR && _encryptMode == ENCRYPT){
        for(CK_LONG i=0;i<8;i++){
            input[input_offset+i] ^= iv[i];
        }
    }

    algo_DES_DESProcess(key,&input[input_offset],&output[output_offset],(u1)encryptMode);

    if(iv != NULL_PTR && _encryptMode == DECRYPT){
        for(CK_LONG i=0;i<8;i++){
            output[output_offset+i] ^= iv[i];
        }
    }


}

