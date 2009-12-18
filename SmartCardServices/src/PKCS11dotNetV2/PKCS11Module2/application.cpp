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

#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif
#include "cardmoduleservice.h"

#include <string>

#include <assert.h>
#include "stdafx.h"
#include "platconfig.h"
#include "config.h"
#include "thread.h"
#include "event.h"
#include "session.h"
#include "slot.h"
#include "application.h"
#include "log.h"

#ifdef _XCL_
#include <xcl_utils.h>
#endif // _XCL_

#ifdef __sun
typedef LPSTR LPTSTR;
#endif

// Initialization of Static fields
SCARDCONTEXT Application::_hContext = 0;

Slot* Application::_slotCache[CONFIG_MAX_SLOT] = {
   NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,
   NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR,NULL_PTR
};

CK_ULONG Application::_numSlots = 0;

#ifdef _XCL_
xCL_DeviceHandle Application::_deviceHandle = 0; // asadali
#endif // _XCL_


/*
*/
#ifndef _XCL_
CK_RV Application::InitApplication( )
{
   Log::begin( "Application::InitApplication" );

   // do the enumeration of slots
   CK_ULONG hResult = SCardEstablishContext( SCARD_SCOPE_USER, NULL, NULL, &Application::_hContext );

   Log::log( "Application::InitApplication - SCardEstablishContext <%#02x>", hResult );
   Log::log( "Application::InitApplication - Application::_hContext <%#02x>", Application::_hContext );

   if( SCARD_S_SUCCESS != hResult )
   {
      return CKR_GENERAL_ERROR;
   }

#ifdef __APPLE__
   /* Apple bug 5256035 */
   {
      SCARDHANDLE h;
      DWORD p;
      SCardConnect(Application::_hContext, "fake reader", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &h, &p);
   }
#endif

   Log::end( "Application::InitApplication" );

   return CKR_OK;
}

#else // _XCL_

CK_RV Application::InitApplication( )
{
    Log::begin( "Application::InitApplication" );
    u4 deviceID;
    u4 rv;
    xCL_DevicePtr deviceList;
    xCL_DevicePtr device;
    u4 numberOfDevices;
    u4 i;

    PRINT_MSG("IN Application::Init");

    rv = xCL_InterfaceInit();

    rv = xCL_DiscoverDevices(&deviceList, &numberOfDevices);
    if (rv == 0 && numberOfDevices != 0)
    {
        // Pick the first device, with ID=0
        device = deviceList + 0;
        deviceID = device->deviceID ;
        PRINT_DATA(NULL, 0, (char*)device->uniqueName);

        // Create device handle
        rv = xCL_CreateHandleFromDeviceID(deviceID, &Application::_deviceHandle);
        if (rv == 0)
        {
            PRINT_MSG("IN Application::Init , device handle created");
        }

        // Free memory for all devices
        for (i=0; i<numberOfDevices; i++)
        {
            rv = xCL_FreeDeviceMemory(deviceList + i);
        }
    }
    return CKR_OK;
}

#endif // _XCL_


/*
*/

#ifndef _XCL_

CK_RV Application::Enumerate( CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount )
{
   Log::begin( "Application::Enumerate" );

   CK_ULONG   slotNb              = 0;
   LPTSTR     pReader             = NULL;
   CK_LONG    hResult             = 0;
   CK_SLOT_ID sid                 = 0;

   if( NULL_PTR == pulCount )
   {
      Log::error( "Application::Enumerate", "CKR_ARGUMENTS_BAD" );
      return CKR_ARGUMENTS_BAD;
   }

   // Get the supported readers from the current cache
   std::string currentCache[ CONFIG_MAX_SLOT ];
   for( CK_SLOT_ID i = 0; i < CONFIG_MAX_SLOT; i++ )
   {
      currentCache[ i ] = "";
      if( NULL_PTR != Application::_slotCache[ i ] )
      {
         currentCache[ i ] = *(Application::_slotCache[ i ]->_readerName);
         Log::log( "Application::Enumerate - currentCache[ %d ] <%s>", i, currentCache[ i ].c_str( ) );
      }
   }

   // Get the readers from the PCSC layer
   DWORD readerListCharLength = 0;
   hResult = SCardListReaders( Application::_hContext, NULL, NULL, &readerListCharLength );
   Log::log( "Application::Enumerate - readerListCharLength <%#02x>", readerListCharLength );
   Log::log( "Application::Enumerate - SCardListReaders <%#02x>", hResult );
   if( SCARD_S_SUCCESS != hResult )
   {
      Log::error( "Application::Enumerate", "CKR_GENERAL_ERROR" );
      return CKR_GENERAL_ERROR;
   }

   LPTSTR pReaderList = (lpCharPtr)malloc( sizeof(char) * readerListCharLength );
   if( NULL == pReaderList )
   {
      Log::error( "Application::Enumerate", "CKR_HOST_MEMORY" );
      return CKR_HOST_MEMORY;
   }
   memset( pReaderList, 0, sizeof(char) * readerListCharLength );

   hResult = SCardListReaders( Application::_hContext, NULL, pReaderList, &readerListCharLength);
   Log::log( "Application::Enumerate - SCardListReaders 2 <%#02x>", hResult );
   if( SCARD_S_SUCCESS != hResult )
   {
      free( pReaderList );
      Log::error( "Application::Enumerate", "CKR_GENERAL_ERROR" );
      return CKR_GENERAL_ERROR;
   }

   // Construct the PCSC reader list
   std::string currentPcscList[ CONFIG_MAX_SLOT ];
   for( CK_SLOT_ID i = 0; i < CONFIG_MAX_SLOT; i++ )
   {
      currentPcscList[ i ] = "";
   }
   pReader = pReaderList; //readers;
   int i = 0;
   while( pReader && ( '\0' != *pReader ) )
   {
      currentPcscList[ i ] = pReader;
      Log::log( "Application::Enumerate - PCSC List[ %d ] <%s>", i, currentPcscList[ i ].c_str( ) );
      i++;
      if( i > CONFIG_MAX_SLOT )
      {
         /*
         free( pReaderList );
         Log::error( "Application::Enumerate", "CKR_HOST_MEMORY" );
         return CKR_HOST_MEMORY;
         */
         break;
      }

      // Advance to the next value.
      size_t readerNameLen = strlen( (const char*)pReader );
      pReader = (lpTCharPtr)((lpTCharPtr)pReader + readerNameLen + 1);
   }
   free( pReaderList );

   // Does a reader desappeared ?
   for( CK_SLOT_ID i = 0; i < CONFIG_MAX_SLOT; i++ )
   {
      if( NULL_PTR != Application::_slotCache[ i ] )
      {
         //printf( "Application::_slotCache[ %lu ]->_readerName <%s>\n", i, Application::_slotCache[ i ]->_readerName->c_str( ) );

         bool bFound = false;
         for( int j = 0 ; j < CONFIG_MAX_SLOT; j++ )
         {
            //printf( "currentPcscList[ %d ] <%s>\n", j, currentPcscList[ j ].c_str( ) );

            if( 0 == (Application::_slotCache[ i ]->_readerName)->compare( currentPcscList[ j ] ) )
            {
               bFound = true;
               //printf( "!! Found !!\n" );
               break;
            }
         }
         if( false == bFound )
         {
            // Not found into the PCSC reader list
            deleteSlot( i );
            //printf( "!! Not Found -> delete !!\n" );
         }
      }
   }

   // Does a new reader appears ?
   //printf( "\n\nDoes a new reader appears ?\n" );
   for( int i = 0; i < CONFIG_MAX_SLOT; i++ )
   {
      if( false == currentPcscList[ i ].empty( ) )
      {
         //printf( "currentPcscList[ %d ] <%s>\n", i, currentPcscList[ i ].c_str( ) );

         bool bFound = false;
         for( int j = 0 ; j < CONFIG_MAX_SLOT; j++ )
         {
            if( 0 != Application::_slotCache[ j ] )
            {
               //printf( "   Application::_slotCache[ %d ] <%s>\n", j, Application::_slotCache[ j ]->_readerName->c_str( ) );
               if( 0 == ( currentPcscList[ i ].compare( *(Application::_slotCache[ j ]->_readerName) ) ) )
               {
                  bFound = true;
                  //printf( "   !! Found !!\n" );
                  break;
               }
            }
         }
         if( false == bFound )
         {
            //printf( "!! Not Found -> add !!\n" );

            CK_RV rv = addSlot( currentPcscList[ i ] );
            if( CKR_OK != rv )
            {
               Log::error( "Application::Enumerate", "addSlot failed" );
               return rv;
            }
         }
      }
   }


   // Scan Reader List
   slotNb = 0;
   Application::_numSlots = 0;
   for (int i = 0; i < CONFIG_MAX_SLOT; i++)
   {
      // Existing Slots only are scanned
      if (Application::_slotCache[i] != NULL_PTR)
      {
         //Log::log( "Application::Enumerate - New Cache[ %d ] <%s>", i, Application::_slotCache[ i ]->_readerName->c_str( ) );
         Application::_numSlots++;

         SCARD_READERSTATE readerStates;
         memset( &readerStates, 0, sizeof( SCARD_READERSTATE ) );
         readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
         readerStates.szReader = Application::_slotCache[i]->_readerName->c_str();

         // Lets check if token is present or not
         if (SCardGetStatusChange(Application::_hContext, 100, &readerStates, 1) == SCARD_S_SUCCESS)
         {
            if ((readerStates.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT)
            {
               // We found a card in this reader
               Application::_slotCache[i]->_slotInfo.flags |= CKF_TOKEN_PRESENT;
               Log::log( "Application::Enumerate - New Cache[ %d ] - Name <%s> - Token present", i, Application::_slotCache[ i ]->_readerName->c_str( ) );
            }
            else
            {
               // No card in this reader
               Application::_slotCache[i]->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
               Log::log( "Application::Enumerate - New Cache[ %d ] - Name <%s> - Token NOT present", i, Application::_slotCache[ i ]->_readerName->c_str( ) );
            }
         }

         // Slots with Token Present
         if((tokenPresent == TRUE) &&
            (Application::_slotCache[i]->_slotInfo.flags & CKF_TOKEN_PRESENT))
         {
            slotNb++;
         }
         // All slots
         else if (tokenPresent == FALSE)
         {
            slotNb++;
         }
      }
   }

   // If pSlotList is not NULL then *pulCount contains the buffer size of pSlotList
   // so we need to check if size passed is valid or not.
   if((pSlotList != NULL_PTR)&&(*pulCount < slotNb))
   {
      *pulCount = slotNb;
      Log::error( "Application::Enumerate", "CKR_BUFFER_TOO_SMALL" );
      return CKR_BUFFER_TOO_SMALL;
   }

   *pulCount = slotNb;

   // Fill slot list if not NULL
   if (pSlotList != NULL_PTR)
   {
      for (int i = 0; i < CONFIG_MAX_SLOT; i++)
      {
         // Existing Slots only are scanned
         if (Application::_slotCache[i] != NULL_PTR)
         {
            CK_BBOOL IsFound = FALSE;

            // Slots with Token Present
            if((tokenPresent == TRUE) &&
               (Application::_slotCache[i]->_slotInfo.flags & CKF_TOKEN_PRESENT))
            {
               IsFound = TRUE;
            }

            // All slots
            else if (tokenPresent == FALSE)
            {
               IsFound = TRUE;
            }

            // Fill Slot List
            if(IsFound == TRUE)
            {
               pSlotList[sid++] = Application::_slotCache[i]->_slotId;
            }
         }
      }
   }

   Log::end( "Application::Enumerate" );

   return CKR_OK;
}

#else // _XCL_

CK_RV Application::Enumerate( CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount )
{
    PRINT_MSG("IN Application::Enumerate");

    LPTSTR     pReaderList         = NULL;
    CK_SLOT_ID slotIdx             = 0;
    CK_ULONG   slotNb              = 0;
    LPTSTR     pReader             = NULL;
    CK_LONG    hResult             = 0;
    CK_SLOT_ID sid                 = 0;

    if(pulCount == NULL_PTR){
        return CKR_ARGUMENTS_BAD;
    }

    DWORD readerListCharLength = SCARD_AUTOALLOCATE;

    // asadali
    // Get reader list, For now only ONE SEG-Lite token ...
    pReaderList = (char *) malloc(64);
    strcpy(pReaderList, "xCL_Token");
    readerListCharLength = strlen(pReaderList);
    *(pReaderList + readerListCharLength) = '\0';
    *(pReaderList + readerListCharLength + 1) = '\0';

    // Get Reader List if not already Get
    if (Application::_numSlots == 0)
    {
        // clear the slot cache
        //CSlot::ClearCache();

        pReader = pReaderList;

        while ('\0' != *pReader )
        {
            size_t readerNameLen = strlen((const char*)pReader);
            size_t sd;

            Slot* slot         = new Slot();
            slot->_slotId      = slotIdx++;

            // fill in the slot description
            for(sd = 0; sd < readerNameLen; sd++)
            {
                slot->_slotInfo.slotDescription[sd] = pReader[sd];
            }

            if(slotIdx > CONFIG_MAX_SLOT){
                return CKR_HOST_MEMORY;
            }

            slotNb++;

            slot->_readerName  = new std::string(pReader);

// GD            Application::AddSlotToCache(slot);
                Application::addSlot (slot);

            // Advance to the next value.
            pReader = (lpTCharPtr)((lpTCharPtr)pReader + readerNameLen + 1);
        }

        free(pReaderList);
        Application::_numSlots = slotNb;
    }

    // Scan Reader List
    slotNb = 0;

    for (int i = 0; i < CONFIG_MAX_SLOT; i++)
    {
        // Existing Slots only are scanned
        if (Application::_slotCache[i] != NULL_PTR)
        {
            SCARD_READERSTATE readerStates;

            readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
            readerStates.szReader = Application::_slotCache[i]->_readerName->c_str();

            // Lets check if token is present or not

            // asadali
            if (xCL_IsTokenPresent())
            {
                // We found a card in this reader
                Application::_slotCache[i]->_slotInfo.flags |= CKF_TOKEN_PRESENT;
            }
            else
            {
                // No card in reader
                Application::_slotCache[i]->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
            }

            // Slots with Token Present
            if((tokenPresent == TRUE) &&
               (Application::_slotCache[i]->_slotInfo.flags & CKF_TOKEN_PRESENT))
            {
                slotNb++;
            }
            // All slots
            else if (tokenPresent == FALSE)
            {
                slotNb++;
            }
        }
    }

    // If pSlotList is not NULL then *pulCount contains the buffer size of pSlotList
    // so we need to check if size passed is valid or not.
    if((pSlotList != NULL_PTR)&&(*pulCount < slotNb))
    {
        *pulCount = slotNb;
        return CKR_BUFFER_TOO_SMALL;
    }

    *pulCount = slotNb;

    // Fill slot list if not NULL
    if (pSlotList != NULL_PTR)
    {
        for (int i = 0; i < CONFIG_MAX_SLOT; i++)
        {
            // Existing Slots only are scanned
            if (Application::_slotCache[i] != NULL_PTR)
            {
                CK_BBOOL IsFound = FALSE;

                // Slots with Token Present
                if((tokenPresent == TRUE) &&
                   (Application::_slotCache[i]->_slotInfo.flags & CKF_TOKEN_PRESENT))
                {
                    IsFound = TRUE;
                }

                // All slots
                else if (tokenPresent == FALSE)
                {
                    IsFound = TRUE;
                }

                // Fill Slot List
                if(IsFound == TRUE)
                {
                    pSlotList[sid++] = Application::_slotCache[i]->_slotId;
                }
            }
        }
    }

    return CKR_OK;
}

#endif // _XCL_

/*
*/
CK_RV Application::GetSlotFromSlotId( CK_SLOT_ID slotId, Slot** slot )
{
   if(((int)slotId < 0) || (slotId >= CONFIG_MAX_SLOT))
   {
      return CKR_SLOT_ID_INVALID;
   }

   if (Application::_slotCache[slotId] != NULL_PTR)
   {
      *slot = Application::_slotCache[slotId];
      return CKR_OK;
   }

   return CKR_SLOT_ID_INVALID;
}


/*
*/
void Application::ClearCache(void)
{
   // initialize the slot cache
   CK_SLOT_ID sid = 0;
   for(;sid<CONFIG_MAX_SLOT;sid++)
   {
      if(Application::_slotCache[sid] != NULL_PTR)
      {
         Slot* slot = Application::_slotCache[sid];
#ifdef INCLUDE_EVENTING
         if(slot->_tracker != NULL_PTR)
         {
            slot->_tracker->stop();
         }
#endif

         delete slot;
         Application::_slotCache[sid] = NULL_PTR;
      }
   }

   // set the number of actual slots present to zero
   Application::_numSlots = 0;

#ifdef INCLUDE_EVENTING
   // we should just signal all the events
   CryptokiEvent.Signal();
#endif
}


/*
*/
void Application::Release( void )
{
   if( 0 != Application::_hContext )
   {
#ifndef _XCL_
      SCardReleaseContext( Application::_hContext );
#endif // _XCL_
      Application::_hContext = 0;
   }
}


/*
*/
void Application::End( void )
{
   Application::ClearCache( );
   Application::Release( );
}


/*
*/
void Application::deleteSlot( int i )
{
   if( NULL_PTR != Application::_slotCache[ i ] )
   {
#ifdef INCLUDE_EVENTING
      if( NULL_PTR != (Application::_slotCache[ i ]->_tracker) )
      {
         (Application::_slotCache[ i ])->_tracker->stop( );
      }
#endif
      delete (Application::_slotCache[ i ]);
      Application::_slotCache[ i ] = NULL_PTR;

#ifdef INCLUDE_EVENTING
      // we should just signal all the events
      CryptokiEvent.Signal( );
#endif

   }
}


/*
*/

#ifndef _XCL_

CK_RV Application::addSlot( std::string& a_readerName )
{
   int iSlotID = -1;
   for( int j = 0 ; j < CONFIG_MAX_SLOT ; j++ )
   {
      if( NULL_PTR == Application::_slotCache[ j ] )
      {
         iSlotID = j;
         break;
      }
   }
   if( -1 == iSlotID )
   {
      return CKR_HOST_MEMORY;
   }

   Slot* slot = new Slot( );
   slot->_readerName  = new std::string( a_readerName );

   // Fill in the slot description
   size_t l = ( a_readerName.length( ) > sizeof( slot->_slotInfo.slotDescription ) ) ? sizeof( slot->_slotInfo.slotDescription ) : a_readerName.length( );
   for( size_t i = 0 ; i < l ; i++ )
   {
      slot->_slotInfo.slotDescription[ i ] = a_readerName[ i ];
   }

   // Add Slot in Cache
   slot->_slotId = iSlotID;
   Application::_slotCache[ iSlotID ] = slot;

#ifdef INCLUDE_EVENTING
   SCARD_READERSTATE readerStates;

   readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
   readerStates.szReader = slot->_readerName->c_str();

   if (SCardGetStatusChange(Application::_hContext, 0, &readerStates, 1) == SCARD_S_SUCCESS)
   {
      if ((readerStates.dwEventState & SCARD_STATE_PRESENT) != SCARD_STATE_PRESENT)
      {
         // we not found a card in this reader
         slot->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
      }
      else
      {
         // we found a card in this reader
         slot->_slotInfo.flags |= CKF_TOKEN_PRESENT;
      }
   }

   // Start the monitoring also
   slot->_tracker = new CardMonitoringThread(slot->_readerName->c_str());
   slot->_tracker->SetSlot(slot);
   slot->_tracker->start();

#endif

   return CKR_OK;
}

#else // _XCL_

void Application::addSlot( Slot* slot )
{
    PRINT_MSG("IN Application::AddslotToCache");

    // Add Slot in Cache
    Application::_slotCache[slot->_slotId] = slot;

#ifdef INCLUDE_EVENTING
    SCARD_READERSTATE readerStates;

    readerStates.dwCurrentState = SCARD_STATE_UNAWARE;
    readerStates.szReader = slot->_readerName->c_str();

    // asadali
    if (xCL_IsTokenPresent())
    {
        // we found a card in this reader
        slot->_slotInfo.flags |= CKF_TOKEN_PRESENT;
    }
    else
    {
        // No card in reader
        slot->_slotInfo.flags &= ~CKF_TOKEN_PRESENT;
    }

    // Start the monitoring also
    slot->_tracker = new CardMonitoringThread(slot->_readerName->c_str());
    slot->_tracker->SetSlot(slot);
    slot->_tracker->start();
#endif
}

#endif // _XCL_
