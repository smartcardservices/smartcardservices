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
#include "cr_global.h"
#include "cr_nn.h"
#include "cr_digit.h"

/**
 * Computes a = b * c, where b and c are digits.
 *
 * Lengths: a[2].
 */
void NN_DigitMult (NN_DIGIT a[2], NN_DIGIT b, NN_DIGIT c)
{
    NN_DIGIT t, u;
    NN_HALF_DIGIT bHigh, bLow, cHigh, cLow;

    bHigh = (NN_HALF_DIGIT)HIGH_HALF (b);
    bLow = (NN_HALF_DIGIT)LOW_HALF (b);
    cHigh = (NN_HALF_DIGIT)HIGH_HALF (c);
    cLow = (NN_HALF_DIGIT)LOW_HALF (c);

    a[0] = (NN_DIGIT)bLow * (NN_DIGIT)cLow;
    t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh;
    u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow;
    a[1] = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh;

    if ((t += u) < u)
        a[1] += TO_HIGH_HALF (1);
    u = TO_HIGH_HALF (t);

    if ((a[0] += u) < u)
        a[1]++;
    a[1] += HIGH_HALF (t);

    return ;
}

/**
 * Sets a = b / c, where a and c are digits.
 *
 * Lengths: b[2].
 * Assumes b[1] < c and HIGH_HALF (c) > 0. For efficiency, c should be
 * normalized.
 */
void NN_DigitDiv (NN_DIGIT *a, NN_DIGIT b[2], NN_DIGIT c)
{
    NN_DIGIT t[2], u, v;
    NN_HALF_DIGIT aHigh, aLow, cHigh, cLow;

    cHigh = (NN_HALF_DIGIT)HIGH_HALF (c);
    cLow = (NN_HALF_DIGIT)LOW_HALF (c);

    t[0] = b[0];
    t[1] = b[1];

    /**
     * Underestimate high half of quotient and subtract.
     */
    if (cHigh == MAX_NN_HALF_DIGIT)
        aHigh = (NN_HALF_DIGIT)HIGH_HALF (t[1]);
    else
        aHigh = (NN_HALF_DIGIT)(t[1] / (cHigh + 1));

    u = (NN_DIGIT)aHigh * (NN_DIGIT)cLow;
    v = (NN_DIGIT)aHigh * (NN_DIGIT)cHigh;
    if ((t[0] -= TO_HIGH_HALF (u)) > (MAX_NN_DIGIT - TO_HIGH_HALF (u)))
        t[1]--;
    t[1] -= HIGH_HALF (u);
    t[1] -= v;

    /**
     * Correct estimate.
     */
    while ((t[1] > cHigh) ||
         ((t[1] == cHigh) && (t[0] >= TO_HIGH_HALF (cLow))))
    {
        if ((t[0] -= TO_HIGH_HALF (cLow)) > MAX_NN_DIGIT - TO_HIGH_HALF (cLow))
            t[1]--;
        t[1] -= cHigh;
        aHigh++;
    }

    /**
     * Underestimate low half of quotient and subtract.
     */
    if (cHigh == MAX_NN_HALF_DIGIT)
        aLow = (NN_HALF_DIGIT)LOW_HALF (t[1]);
    else
        aLow = (NN_HALF_DIGIT)((TO_HIGH_HALF (t[1]) + HIGH_HALF (t[0])) / (cHigh + 1));

    u = (NN_DIGIT)aLow * (NN_DIGIT)cLow;
    v = (NN_DIGIT)aLow * (NN_DIGIT)cHigh;
    if ((t[0] -= u) > (MAX_NN_DIGIT - u))
        t[1]--;
    if ((t[0] -= TO_HIGH_HALF (v)) > (MAX_NN_DIGIT - TO_HIGH_HALF (v)))
        t[1]--;
    t[1] -= HIGH_HALF (v);

    /**
     * Correct estimate.
     */
    while ((t[1] > 0) || ((t[1] == 0) && t[0] >= c))
    {
        if ((t[0] -= c) > (MAX_NN_DIGIT - c))
            t[1]--;
        aLow++;
    }

    *a = TO_HIGH_HALF (aHigh) + aLow;

    return ;
}

