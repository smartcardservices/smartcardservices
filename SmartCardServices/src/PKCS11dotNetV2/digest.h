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


#ifndef __GEMALTO_DIGEST__
#define __GEMALTO_DIGEST__

#include <cstdlib>

class CDigest {

protected:
    
	unsigned char*  _workingBuffer;
    long      _workingOffset;
    size_t      _workingLength;
    long      _counter;
    unsigned char*  _hashValue;
    size_t      _hashLength;
    long      _blockLength;

    virtual void TransformBlock(unsigned char* data, long counter, unsigned char* result) = 0;

    virtual void TransformFinalBlock (unsigned char* data, long length, long counter, unsigned char* result) = 0;

public:
    
	CDigest( );

    virtual ~CDigest( );
 
    void hashCore( unsigned char*, const long&, const long& );

    void hashFinal( unsigned char* );

	inline long hashLength( void ) { return _hashLength; }

};

#endif // __GEMALTO_DIGEST__
