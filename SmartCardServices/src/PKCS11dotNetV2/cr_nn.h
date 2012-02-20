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

#ifndef _CR_NN_H_
#define _CR_NN_H_


/**
 * Type definitions.
 */
typedef UINT4 NN_DIGIT;
typedef UINT2 NN_HALF_DIGIT;

/**
 * Constants:
 *
 * Note: MAX_NN_DIGITS is long enough to hold any RSA modulus, plus
 * one more digit as required by R_GeneratePEMKeys (for n and phiN,
 * whose lengths must be even). All natural numbers have at most
 * MAX_NN_DIGITS digits, except for double-length intermediate values
 * in NN_Mult (t), NN_ModMult (t), NN_ModInv (w), and NN_Div (c).
 */

/**
 * Length of digit in bits
 */
#define NN_DIGIT_BITS		32
#define NN_HALF_DIGIT_BITS	16

/**
 * Length of digit in bytes
 */
#define NN_DIGIT_LEN		(NN_DIGIT_BITS / 8)

/**
 * Maximum length in digits
 */
#define MAX_NN_DIGITS \
  ((MAX_RSA_MODULUS_LEN + NN_DIGIT_LEN - 1) / NN_DIGIT_LEN + 1)

/**
 *  Maximum digits
 */
#define MAX_NN_DIGIT		0xffffffff
#define MAX_NN_HALF_DIGIT	0xffff

/**
 * Some macros:
 */
#define LOW_HALF(x) ((x) & MAX_NN_HALF_DIGIT)
#define HIGH_HALF(x) (((x) >> NN_HALF_DIGIT_BITS) & MAX_NN_HALF_DIGIT)
#define TO_HIGH_HALF(x) (((NN_DIGIT)(x)) << NN_HALF_DIGIT_BITS)
#define DIGIT_MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 1)) & 1)
#define DIGIT_2MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 2)) & 3)

#define NN_ASSIGN_DIGIT(a, b, digits) {NN_AssignZero (a, digits); a[0] = b;}
#define NN_EQUAL(a, b, digits) (! NN_Cmp (a, b, digits))
#define NN_EVEN(a, digits) (((digits) == 0) || ! (a[0] & 1))


/**
 * Declaration of conversion functions:
 *
   NN_Decode (a, digits, b, len)   Decodes character string b into a.
   NN_Encode (a, len, b, digits)   Encodes a into character string b.

   ASSIGNMENTS
   NN_Assign (a, b, digits)        Assigns a = b.
   NN_ASSIGN_DIGIT (a, b, digits)  Assigns a = b, where b is a digit.
   NN_AssignZero (a, b, digits)    Assigns a = 0.
   NN_Assign2Exp (a, b, digits)    Assigns a = 2^b.

   ARITHMETIC OPERATIONS
   NN_Add (a, b, c, digits)        Computes a = b + c.
   NN_Sub (a, b, c, digits)        Computes a = b - c.
   NN_Mult (a, b, c, digits)       Computes a = b * c.
   NN_LShift (a, b, c, digits)     Computes a = b * 2^c.
   NN_RShift (a, b, c, digits)     Computes a = b / 2^c.
   NN_Div (a, b, c, cDigits, d, dDigits)  Computes a = c div d and b = c mod d.

   NUMBER THEORY
   NN_Mod (a, b, bDigits, c, cDigits)  Computes a = b mod c.
   NN_ModMult (a, b, c, d, digits) Computes a = b * c mod d.
   NN_ModExp (a, b, c, cDigits, d, dDigits)  Computes a = b^c mod d.
   NN_ModInv (a, b, c, digits)     Computes a = 1/b mod c.
   NN_Gcd (a, b, c, digits)        Computes a = gcd (b, c).

   OTHER OPERATIONS
   NN_EVEN (a, digits)             Returns 1 iff a is even.
   NN_Cmp (a, b, digits)           Returns sign of a - b.
   NN_EQUAL (a, digits)            Returns 1 iff a = b.
   NN_Zero (a, digits)             Returns 1 iff a = 0.
   NN_Digits (a, digits)           Returns significant length of a in digits.
   NN_Bits (a, digits)             Returns significant length of a in bits.
 *
 */

/**
 * The third parameter changed from 'unsigned char *'
 */
void NN_Decode(NN_DIGIT *, unsigned int, const unsigned char *, unsigned int);

void NN_Encode(unsigned char *, unsigned int, NN_DIGIT *, unsigned int);

void NN_Assign(NN_DIGIT *, NN_DIGIT *, unsigned int);
void NN_AssignZero(NN_DIGIT *, unsigned int);
void NN_Assign2Exp(NN_DIGIT *, unsigned int, unsigned int);

NN_DIGIT NN_Add(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);
NN_DIGIT NN_Sub(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);
void NN_Mult(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);
void NN_Div(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT *, unsigned int);
NN_DIGIT NN_LShift(NN_DIGIT *, NN_DIGIT *, unsigned int, unsigned int);
NN_DIGIT NN_RShift(NN_DIGIT *, NN_DIGIT *, unsigned int, unsigned int);

void NN_Mod(NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT *, unsigned int);
void NN_ModMult(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);
void NN_ModExp(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT *, unsigned int);
void NN_ModInv(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);
void NN_Gcd(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int);

int NN_Cmp(NN_DIGIT *, NN_DIGIT *, unsigned int);
int NN_Zero(NN_DIGIT *, unsigned int);
unsigned int NN_Bits(NN_DIGIT *, unsigned int);
unsigned int NN_Digits(NN_DIGIT *, unsigned int);


#endif /* _CR_NN_H_ */


