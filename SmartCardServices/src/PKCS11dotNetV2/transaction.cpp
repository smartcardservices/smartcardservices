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
#include "transaction.h"
#include "cardmoduleservice.h"

#include "platconfig.h"
#include "config.h"
#include "thread.h"
#include "event.h"
#include "session.h"
#include "slot.h"
#include "sctoken.h"
#include "error.h"


Transaction::Transaction(Slot * slot) : _slot(slot)
{

    if(!slot || !slot->_token)
        throw CkError(CKR_FUNCTION_FAILED);

    _slot->_token->BeginTransaction();

    // As a result of card re-set, user may have been logged out
    _slot->UpdateSessionState();
}

Transaction::~Transaction() throw()
{
    if(!_slot || !_slot->_token)
        return;

    try
    {
        _slot->_token->EndTransaction();
    }
    catch(...) {}
}
