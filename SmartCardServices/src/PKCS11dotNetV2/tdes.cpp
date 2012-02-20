
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


#include "tdes.h"


void CTripleDES::TransformBlockInternal( unsigned char* iv, unsigned char* key, long encryptMode, unsigned char* input, long input_offset, unsigned char* output, long output_offset ) {

    // encryprtMode == ENCRYPT then we need to XOR input with iv
    if( iv && ( _encryptMode == ENCRYPT ) ) {

        for( long i = 0 ; i < 8 ; ++i ) {

            input[ input_offset + i ] ^= iv[ i ];
        }
    }

    algo_DES_3DESProcess( (unsigned char)_keyLength, key, &input[ input_offset ], &output[ output_offset ], (unsigned char)encryptMode );

    if( iv && ( _encryptMode == DECRYPT) ) {

        for( long i = 0 ; i < 8 ; ++i ) {

            output[ output_offset + i ] ^= iv[ i ];
        }
    }
}
