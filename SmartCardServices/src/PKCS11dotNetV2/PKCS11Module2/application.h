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

#ifndef _include_application_h
#define _include_application_h

#include <vector>
#include <list>

#ifdef _XCL_
#include <xcl_utils.h>
#endif // _XCL_

using namespace std;

class Application {

public:
   static CK_ULONG _numSlots;
   static Slot* _slotCache[CONFIG_MAX_SLOT];
   static SCARDCONTEXT _hContext;

#ifdef _XCL_
    static xCL_DeviceHandle _deviceHandle;
#endif // _XCL_

public:
   static CK_RV InitApplication(void);

   static CK_RV Enumerate(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

   static CK_RV GetSlotFromSlotId(CK_SLOT_ID slotId, Slot** slot);

//   static void AddSlotToCache(Slot* slot);
	static void addSlot( Slot* slot );

   static void ClearCache();

   static void Release( void );
   static void End( void );
   //static void ReleaseThreads( void );

   static void deleteSlot( int i );
   static CK_RV addSlot( std::string& a_readerName );

};

#endif

