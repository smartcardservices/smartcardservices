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

#ifndef _include_symmalgo_h
#define _include_symmalgo_h

#define PADDING_MODE_ISO9797M2 1
#define PADDING_MODE_NONE      2
#define PADDING_MODE_PKCS7     3
#define PADDING_MODE_ZEROS     4

#define ENCRYPT 1
#define DECRYPT 2

#define CIPHER_MODE_CBC 1
#define CIPHER_MODE_ECB 2

class CSymmAlgo
{

protected:
    CK_BYTE_PTR _iv;
    CK_BYTE_PTR _key;
    CK_LONG     _keyLength;
    CK_LONG     _blockSize;
    CK_LONG     _cipherMode;
    CK_LONG     _paddingMode;
    CK_LONG     _encryptMode;

protected:
    virtual void TransformBlockInternal(CK_BYTE_PTR iv,CK_BYTE_PTR key,CK_LONG encryptMode,
                                           CK_BYTE_PTR input,CK_LONG input_offset,
                                           CK_BYTE_PTR output,CK_LONG output_offset) = 0;

public:
    CSymmAlgo();
    virtual ~CSymmAlgo();

    void SetKey(CK_BYTE_PTR key,CK_LONG keyLength);
    void SetIV(CK_BYTE_PTR iv);
    void SetEncryptMode(CK_LONG mode);
    void SetCipherMode(CK_LONG cmode);
    void SetPaddingMode(CK_LONG pmode);

    CK_LONG GetOutputLength(CK_LONG input_count);

    CK_LONG TransformBlock(CK_BYTE_PTR input,CK_LONG input_offset,CK_LONG input_count,
                           CK_BYTE_PTR output,CK_LONG output_offset);

    CK_LONG TransformFinalBlock(CK_BYTE_PTR input,CK_LONG input_offset,CK_LONG input_count,
                                CK_BYTE_PTR output,CK_LONG output_offset);
};

#endif

