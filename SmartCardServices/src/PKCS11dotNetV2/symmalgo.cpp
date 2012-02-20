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
#include "symmalgo.h"

CSymmAlgo::CSymmAlgo(){
    this->_cipherMode  = CIPHER_MODE_CBC;
    this->_paddingMode = PADDING_MODE_PKCS7;
    this->_iv          = NULL_PTR;
    this->_key         = NULL_PTR;
}

CSymmAlgo::~CSymmAlgo(){
    if(this->_key != NULL_PTR)
        free(this->_key);
}

void CSymmAlgo::SetKey(CK_BYTE_PTR key,CK_LONG keyLength){
    this->_key       = (CK_BYTE_PTR)malloc(keyLength);
    this->_keyLength = keyLength;

    memcpy(this->_key,key,keyLength);
}

void CSymmAlgo::SetIV(CK_BYTE_PTR iv){
    this->_iv = iv;
}

void CSymmAlgo::SetEncryptMode(CK_LONG mode){
    this->_encryptMode = mode;
}

void CSymmAlgo::SetCipherMode(CK_LONG cmode){
    this->_cipherMode = cmode;
}

void CSymmAlgo::SetPaddingMode(CK_LONG pmode){
    this->_paddingMode = pmode;
}

CK_LONG CSymmAlgo::GetOutputLength(CK_LONG input_count){

    CK_LONG outputLen;

    if(this->_encryptMode == ENCRYPT){
        outputLen = input_count & -this->_blockSize;

        switch(this->_paddingMode){

            case PADDING_MODE_ISO9797M2:
            case PADDING_MODE_PKCS7:
                // atleast 1 padding byte will be needed
                if(input_count >= outputLen){
                    outputLen += this->_blockSize;
                }
                break;

            case PADDING_MODE_ZEROS:
                if(input_count > outputLen){
                    outputLen += this->_blockSize;
                }
                break;

            case PADDING_MODE_NONE:
                outputLen = input_count;
                break;
        }
    }else{
        outputLen = input_count;
    }

    return outputLen;
}

CK_LONG CSymmAlgo::TransformBlock(CK_BYTE_PTR input,CK_LONG input_offset,CK_LONG input_count,
                                  CK_BYTE_PTR output,CK_LONG output_offset)
{
    CK_LONG res = 0;
    while (res != input_count)
    {
        TransformBlockInternal(_iv,_key,_encryptMode,input,input_offset,output,output_offset);

        if (_cipherMode == CIPHER_MODE_CBC)
        {
            if (_encryptMode == ENCRYPT){
                // last block of output becomes icv for next round.
                memcpy(_iv,&output[output_offset],_blockSize);
            }
            else {
                // last block of input becomes icv for next round.
                memcpy(_iv,&input[input_offset],_blockSize);
            }
        }

        // adjust offsets
        input_offset += _blockSize;
        res += _blockSize;
        output_offset += _blockSize;
    }

    return res;
}

CK_LONG CSymmAlgo::TransformFinalBlock(CK_BYTE_PTR input,CK_LONG input_offset,CK_LONG input_count,
                                       CK_BYTE_PTR output,CK_LONG output_offset)
{
    CK_LONG workingLength;

    if (((this->_paddingMode == PADDING_MODE_NONE) ||
         (this->_encryptMode == DECRYPT)) &&
         (input_count % _blockSize != 0))
    {
        PKCS11_ASSERT(CK_FALSE);
    }

    // prepare outbuffer in case of encryption
    if (this->_encryptMode == ENCRYPT)
    {
        // ~ round_down(inputCount, _blockSizeByte)
        workingLength = input_count & -_blockSize;
    }
    else
    {
        // we're in Decrypt mode, hence workingLength is % _blockSizeByte
        workingLength = input_count;
    }

    if (workingLength > 0)
    {
        // compute the workingLength length part (% _blockSizeByte)
        TransformBlock(input,input_offset, workingLength,output,output_offset);

        input_offset += workingLength;
        output_offset += workingLength;
        input_count -= workingLength;
    }

    if (this->_encryptMode == DECRYPT)
    {
        switch (this->_paddingMode)
        {
            case PADDING_MODE_PKCS7:
                // check the padding value make sense
                if (output[output_offset - 1] > _blockSize){
                    PKCS11_ASSERT(CK_FALSE);
                }
                workingLength -= output[output_offset - 1];
                break;

            case PADDING_MODE_ISO9797M2:
                // remove trailing zeros
                while (output[output_offset - 1] == 0x00){
                    workingLength--;
                    output_offset--;
                }
                // check initial byte is 0x80
                if (output[output_offset - 1] != 0x80){
                    PKCS11_ASSERT(CK_FALSE);
                }
                workingLength--;
                break;

            // note when PaddingMode.Zeros is used, we do not remove the 0s (no way to differentiate from the actual data)
        }
    }
    else
    {
        if ((this->_paddingMode == PADDING_MODE_PKCS7)
            || (this->_paddingMode == PADDING_MODE_ISO9797M2)
            || ((this->_paddingMode == PADDING_MODE_ZEROS) && (input_count > 0)))
        {
            CK_BYTE_PTR paddedIntput = (CK_BYTE_PTR)malloc(_blockSize);
            memset(paddedIntput,0,_blockSize);

            memcpy(paddedIntput,&input[input_offset],input_count);

            // add padding information in buffer if relevant
            switch (this->_paddingMode)
            {
                // set first bit to 1, all other bits already set to 0
                case PADDING_MODE_ISO9797M2:
                    paddedIntput[input_count] = 0x80;
                    break;

                case PADDING_MODE_PKCS7:
                    CK_BYTE paddingValue = (CK_BYTE)(_blockSize - input_count);
                    for (CK_LONG i = input_count; i < _blockSize; i++){
                        paddedIntput[i] = paddingValue;
                    }
                    break;
            }

            // compute last block
            TransformBlock(paddedIntput, 0, _blockSize, output, output_offset);

            workingLength += _blockSize;

            free(paddedIntput);
        }
    }

    // over, let's return.
    return workingLength;
}

