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

#ifndef _CR_RANDOM_H_
#define _CR_RANDOM_H_


/**
 * RSA Random structure.
 */
typedef struct {
    unsigned int  bytesNeeded;
    unsigned char state[16];
    unsigned int  outputAvailable;
    unsigned char output[16];
} R_RANDOM_STRUCT;


int  R_GenerateBytes(unsigned char *, unsigned int, R_RANDOM_STRUCT *);

int  R_RandomInit(R_RANDOM_STRUCT *randomStruct) ;
void InitRandomStruct(R_RANDOM_STRUCT *randomStruct) ;
int  R_GetRandomBytesNeeded(unsigned int *bytesNeeded, R_RANDOM_STRUCT *randomStruct) ;
int  R_RandomUpdate(R_RANDOM_STRUCT *randomStruct, unsigned char *block, unsigned int blockLen) ;
void R_RandomFinal(R_RANDOM_STRUCT *randomStruct) ;


#endif

