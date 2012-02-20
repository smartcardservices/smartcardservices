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


#include <cstdlib>
#include <cstring>

#include "symmalgo.h"
#include <memory>


CSymmAlgo::CSymmAlgo( ) {

    _cipherMode  = CIPHER_MODE_CBC;
    
    _paddingMode = PADDING_MODE_PKCS7;
    
    _iv          = NULL;
    
    _key         = NULL;
}


/*
*/
CSymmAlgo::~CSymmAlgo( ) {

    if( _key )
        free(_key);
}


/*
*/
void CSymmAlgo::SetKey( unsigned char* key, long keyLength ) {

    _key = (unsigned char*)malloc(keyLength);
    
    _keyLength = keyLength;

    memcpy(_key,key,keyLength);
}

void CSymmAlgo::SetIV(unsigned char* iv){
    _iv = iv;
}

void CSymmAlgo::SetEncryptMode(long mode){
    _encryptMode = mode;
}

void CSymmAlgo::SetCipherMode(long cmode){
    _cipherMode = cmode;
}

void CSymmAlgo::SetPaddingMode(long pmode){
    _paddingMode = pmode;
}

long CSymmAlgo::GetOutputLength(long input_count){

    long outputLen;

    if(_encryptMode == ENCRYPT){
        outputLen = input_count & -_blockSize;

        switch(_paddingMode){

            case PADDING_MODE_ISO9797M2:
            case PADDING_MODE_PKCS7:
                // atleast 1 padding byte will be needed
                if(input_count >= outputLen){
                    outputLen += _blockSize;
                }
                break;

            case PADDING_MODE_ZEROS:
                if(input_count > outputLen){
                    outputLen += _blockSize;
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

long CSymmAlgo::TransformBlock(unsigned char* input,long input_offset,long input_count,
                                  unsigned char* output,long output_offset)
{
    long res = 0;
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

long CSymmAlgo::TransformFinalBlock(unsigned char* input,long input_offset,long input_count,
                                       unsigned char* output,long output_offset)
{
    long workingLength;

    //if (((_paddingMode == PADDING_MODE_NONE) ||
    //     (_encryptMode == DECRYPT)) &&
    //     (input_count % _blockSize != 0))
    //{
    //    PKCS11_ASSERT(CK_FALSE);
    //}

    // prepare outbuffer in case of encryption
    if (_encryptMode == ENCRYPT)
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

    if (_encryptMode == DECRYPT)
    {
        switch (_paddingMode)
        {
            case PADDING_MODE_PKCS7:
                //// check the padding value make sense
                //if (output[output_offset - 1] > _blockSize){
                //    PKCS11_ASSERT(CK_FALSE);
                //}
                workingLength -= output[output_offset - 1];
                break;

            case PADDING_MODE_ISO9797M2:
                // remove trailing zeros
                while (output[output_offset - 1] == 0x00){
                    workingLength--;
                    output_offset--;
                }
                // check initial byte is 0x80
                //if (output[output_offset - 1] != 0x80){
                //    PKCS11_ASSERT(CK_FALSE);
                //}
                workingLength--;
                break;

            // note when PaddingMode.Zeros is used, we do not remove the 0s (no way to differentiate from the actual data)
        }
    }
    else
    {
        if ((_paddingMode == PADDING_MODE_PKCS7)
            || (_paddingMode == PADDING_MODE_ISO9797M2)
            || ((_paddingMode == PADDING_MODE_ZEROS) && (input_count > 0)))
        {
            unsigned char* paddedIntput = (unsigned char*)malloc(_blockSize);
            memset(paddedIntput,0,_blockSize);

            memcpy(paddedIntput,&input[input_offset],input_count);

            // add padding information in buffer if relevant
            switch (_paddingMode)
            {
                // set first bit to 1, all other bits already set to 0
                case PADDING_MODE_ISO9797M2:
                    paddedIntput[input_count] = 0x80;
                    break;

                case PADDING_MODE_PKCS7:
                    unsigned char paddingValue = (unsigned char)(_blockSize - input_count);
                    for (long i = input_count; i < _blockSize; i++){
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

