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

#ifndef _include_error_h
#define _include_error_h

#include <string>
#include <stdexcept>
#include "cardmoduleservice.h"
#include "platconfig.h"
#include "Except.h"

class PcscError : public std::runtime_error
{
public:
    PcscError() : std::runtime_error(""), _err(0) {}
    PcscError(unsigned long err) : std::runtime_error(""), _err(err) {}
    PcscError(const std::string & message, unsigned long err = 0) : std::runtime_error(message), _err(err) {}

    unsigned long Error() const {return _err;}

private:
    unsigned long _err;

};


class CkError : public std::runtime_error
{
public:
    CkError() : std::runtime_error(""), _err(0) {}
    CkError(CK_RV err) : std::runtime_error(""), _err(err) {}
    CkError(const std::string & message, unsigned long err = 0) : std::runtime_error(message), _err(err) {}

    CK_RV Error() const {return _err;}

    static CK_RV CheckMarshallerException( Marshaller::Exception & x );

private:
    unsigned long _err;

};

#endif // _include_error_h

