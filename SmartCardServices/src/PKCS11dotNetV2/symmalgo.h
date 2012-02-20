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


#ifndef __GEMALTO_SYMMETRIC_ALGO__
#define __GEMALTO_SYMMETRIC_ALGO__


//#include "cryptoki.h"

#define PADDING_MODE_ISO9797M2 1
#define PADDING_MODE_NONE      2
#define PADDING_MODE_PKCS7     3
#define PADDING_MODE_ZEROS     4

#define ENCRYPT 1
#define DECRYPT 2

#define CIPHER_MODE_CBC 1
#define CIPHER_MODE_ECB 2


/*
*/
class CSymmAlgo {

protected:
    
    unsigned char* _iv;
    unsigned char* _key;
    long     _keyLength;
    long     _blockSize;
    long     _cipherMode;
    long     _paddingMode;
    long     _encryptMode;

    virtual void TransformBlockInternal(unsigned char* iv,unsigned char* key,long encryptMode, unsigned char* input,long input_offset, unsigned char* output,long output_offset) = 0;

public:

    CSymmAlgo( );
    
    virtual ~CSymmAlgo( );

    void SetKey( unsigned char* key, long keyLength );

    void SetIV( unsigned char* iv );
    
    void SetEncryptMode( long mode );
    
    void SetCipherMode( long cmode );
    
    void SetPaddingMode( long pmode );

    long GetOutputLength( long input_count );

    long TransformBlock( unsigned char* input, long input_offset,long input_count, unsigned char* output,long output_offset);

    long TransformFinalBlock(unsigned char* input,long input_offset,long input_count, unsigned char* output,long output_offset);
};

#endif // 
