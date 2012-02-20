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


#define CRYPTOKIVERSION_INTERFACE_MAJOR  0x02
#define CRYPTOKIVERSION_INTERFACE_MINOR  0x14


#include <string>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/foreach.hpp>
#include <boost/array.hpp>
#include "cryptoki.h"
#include "Application.hpp"
#include "Log.hpp"
#include "PKCS11Exception.hpp"
#include "version.hpp"


boost::condition_variable g_WaitForSlotEventCondition;

boost::mutex g_WaitForSlotEventMutex;

bool g_bWaitForSlotEvent = false;

// Must be a 32 max length string
const CK_UTF8CHAR g_stManufacturedId[ ] = "Gemalto";

// Must be a 32 max length string
const CK_UTF8CHAR g_stLibraryDescription[ ] = "Gemalto .NET PKCS11";

boost::mutex io_mutex;

Application g_Application;

CK_BBOOL g_isInitialized = FALSE;


static const CK_FUNCTION_LIST FunctionList = {

    { CRYPTOKIVERSION_LIBRARY_MAJOR, CRYPTOKIVERSION_LIBRARY_MINOR },

#undef CK_PKCS11_FUNCTION_INFO
#undef CK_NEED_ARG_LIST

#define CK_PKCS11_FUNCTION_INFO(func) func,

#include "pkcs11f.h"

#undef CK_PKCS11_FUNCTION_INFO
#undef CK_NEED_ARG_LIST
};


extern "C"
{
    /**
    * C_GetCardProperty retreives a property value from the smart card.
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetCardProperty )( CK_SLOT_ID ulSlotID, CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG_PTR a_pValueLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetCardProperty" );
        Log::in( "C_GetCardProperty" );
        Log::log( "C_GetCardProperty - slotID <%#02x>", ulSlotID );
        Log::log( "C_GetCardProperty - property <%#02x>", a_ucProperty );
        Log::log( "C_GetCardProperty - flags <%#02x>", a_ucFlags );
        if( *a_pValueLen ) {

            Log::logCK_UTF8CHAR_PTR( "C_GetCardProperty - value", a_pValue, *a_pValueLen );
            Log::log( "C_GetCardProperty - value len <%#02x>", *a_pValueLen );
        }
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            /*} else if( !(*a_pValueLen) ) {

                rv =  CKR_ARGUMENTS_BAD;
                */
            } else {

                s = g_Application.getSlot( ulSlotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    s->m_Device->beginTransaction( );

                    s->getCardProperty( a_ucProperty, a_ucFlags, a_pValue, a_pValueLen );
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetCardProperty" );
        Log::logCK_RV( "C_GetCardProperty", rv );
        Log::out( "C_GetCardProperty" );
        if( *a_pValueLen ) {

            Log::logCK_UTF8CHAR_PTR( "C_GetCardProperty - value", a_pValue, *a_pValueLen );
            Log::log( "C_GetCardProperty - value len <%#02x>", *a_pValueLen );
        }
        Log::end( "C_GetCardProperty" );

        return rv;
    }


    /**
    * C_SetCardProperty sets a property value into the smart card.
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SetCardProperty )( CK_SLOT_ID ulSlotID, CK_BYTE a_ucProperty, CK_BYTE a_ucFlags, CK_BYTE_PTR a_pValue, CK_ULONG a_ulValueLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SetCardProperty" );
        Log::in( "C_SetCardProperty" );
        Log::log( "C_SetCardProperty - slotID <%#02x>", ulSlotID );
        Log::log( "C_SetCardProperty - property <%#02x>", a_ucProperty );
        Log::log( "C_SetCardProperty - flags <%#02x>", a_ucFlags );
        Log::logCK_UTF8CHAR_PTR( "C_SetCardProperty - value", a_pValue, a_ulValueLen );
        Log::log( "C_SetCardProperty - value len <%#02x>", a_ulValueLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !a_pValue || !a_ulValueLen ) {

                rv =  CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( ulSlotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    s->m_Device->beginTransaction( );

                    s->setCardProperty( a_ucProperty, a_ucFlags, a_pValue, a_ulValueLen );
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SetCardProperty" );
        Log::logCK_RV( "C_SetCardProperty", rv );
        Log::end( "C_SetCardProperty" );

        return rv;
    }


    /**
    * C_Initialize initializes the Cryptoki library.
    *
    * @param pInitArgs
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Initialize )( CK_VOID_PTR a_pInitArgs ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Initialize" );
        Log::in( "C_Initialize" );
        Log::log( "C_Initialize - pInitArgs <%#02x>", a_pInitArgs );
        Log::start( );

        try {

            // Already Initialized
            if( g_isInitialized ) {

                Log::error( "C_Initialize", "CKR_CRYPTOKI_ALREADY_INITIALIZED" );
                rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;

            } else if( a_pInitArgs ) {

                CK_C_INITIALIZE_ARGS initArgs = *(CK_C_INITIALIZE_ARGS_PTR)a_pInitArgs;

                Log::logCK_C_INITIALIZE_ARGS_PTR( "C_Initialize", (CK_C_INITIALIZE_ARGS_PTR)a_pInitArgs );

                if( initArgs.pReserved ) {

                    Log::error( "C_Initialize", "CKR_ARGUMENTS_BAD" );
                    rv = CKR_ARGUMENTS_BAD;

                } else if( initArgs.flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS ) {

                    Log::error( "C_Initialize", "CKR_NEED_TO_CREATE_THREADS" );
                    rv = CKR_NEED_TO_CREATE_THREADS;

                } else if( initArgs.flags & CKF_OS_LOCKING_OK ) {

                    if( initArgs._CreateMutex || initArgs.DestroyMutex || initArgs.LockMutex || initArgs.UnlockMutex ) {

                        Log::error( "C_Initialize", "CKR_CANT_LOCK" );
                        rv = CKR_CANT_LOCK;
                    }

                } else if( initArgs._CreateMutex || initArgs.DestroyMutex || initArgs.LockMutex || initArgs.UnlockMutex ) {

                    if( !initArgs._CreateMutex || !initArgs.DestroyMutex || !initArgs.LockMutex || !initArgs.UnlockMutex ) {

                        Log::error( "C_Initialize", "CKR_ARGUMENTS_BAD" );
                        rv = CKR_ARGUMENTS_BAD;

                    } else if( !( initArgs.flags & CKF_OS_LOCKING_OK ) ) {

                        Log::error( "C_Initialize", "CKR_CANT_LOCK" );
                        rv = CKR_CANT_LOCK;
                    }
                }
            }

            if ( CKR_OK == rv ) {

                g_isInitialized = TRUE;

                g_Application.initialize( );
            }

            Log::log( "C_Initialize - isInitialized <%#02x>", g_isInitialized );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        Log::stop( "C_Initialize" );
        Log::logCK_RV( "C_Initialize", rv );
        Log::end( "C_Initialize" );
        return rv;
    }


    /**
    * C_Finalize indicates that an application is done with the
    * Cryptoki library.
    *
    * @param pReserved reserved.Should be NULL_PTR
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Finalize )( CK_VOID_PTR a_pReserved ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Finalize" );
        Log::in( "C_Finalize" );
        Log::log( "C_Finalize - pReserved <%#02x>", a_pReserved );
        Log::start( );

        try {

            // Not Initialized
            if( !g_isInitialized ) {

                Log::error( "C_Finalize", "CKR_CRYPTOKI_NOT_INITIALIZED" );

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( a_pReserved ) {

                Log::error( "C_Finalize", "CKR_ARGUMENTS_BAD" );

                rv = CKR_ARGUMENTS_BAD;

            } else {

                g_WaitForSlotEventCondition.notify_all( );

                g_isInitialized = FALSE;

                g_Application.finalize( );
            }

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        Log::stop( "C_Finalize" );
        Log::logCK_RV( "C_Finalize", rv );
        Log::end( "C_Finalize" );

        return rv;
    }


    /**
    * C_GetInfo returns general information about Cryptoki.
    *
    * @param pInfo location that receives information
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetInfo )( CK_INFO_PTR pInfo ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;
        Log::begin( "C_GetInfo" );
        Log::in( "C_GetInfo" );
        Log::logCK_INFO( "C_GetInfo", pInfo );
        Log::start( );

        if( !g_isInitialized ) {

            rv = CKR_CRYPTOKI_NOT_INITIALIZED;

        } else if( !pInfo ) {

            rv = CKR_ARGUMENTS_BAD;

        } else {

            pInfo->cryptokiVersion.major = CRYPTOKIVERSION_INTERFACE_MAJOR;
            pInfo->cryptokiVersion.minor = CRYPTOKIVERSION_INTERFACE_MINOR;
            pInfo->flags = 0;
            memset( pInfo->libraryDescription, ' ', sizeof( pInfo->libraryDescription ) );
            memcpy( pInfo->libraryDescription, g_stLibraryDescription, sizeof( g_stLibraryDescription ) - 1 );
            memset( pInfo->manufacturerID, ' ', sizeof( pInfo->manufacturerID ) );
            memcpy( pInfo->manufacturerID, g_stManufacturedId, sizeof( g_stManufacturedId ) - 1 );
            pInfo->libraryVersion.major  = CRYPTOKIVERSION_LIBRARY_MAJOR;
            pInfo->libraryVersion.minor  = CRYPTOKIVERSION_LIBRARY_MINOR;
        }

        Log::stop( "C_GetInfo" );
        Log::logCK_RV( "C_GetInfo", rv );
        Log::out( "C_GetInfo" );
        Log::logCK_INFO( "C_GetInfo", pInfo );
        Log::end( "C_GetInfo" );
        return rv;
    }


    /**
    * C_GetFunctionList returns the function list.
    *
    * @param ppFunctionList receives pointer to function list
    */
    CK_DEFINE_FUNCTION( CK_RV,C_GetFunctionList )( CK_FUNCTION_LIST_PTR_PTR ppFunctionList ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;
        Log::begin( "C_GetFunctionList" );
        Log::in( "C_GetFunctionList" );
        Log::log( "C_GetFunctionList - CK_FUNCTION_LIST_PTR_PTR <%#02x>", ppFunctionList );
        Log::start( );

        if( !ppFunctionList ) {

            rv = CKR_ARGUMENTS_BAD;

        } else {

            // this is the only function which an application can call before calling C_Initialize
            *ppFunctionList = (CK_FUNCTION_LIST_PTR)&FunctionList;
        }

        Log::stop( "C_GetFunctionList" );
        Log::logCK_RV( "C_GetFunctionList", rv );
        Log::out( "C_GetFunctionList" );
        Log::log( "C_GetFunctionList - CK_FUNCTION_LIST_PTR_PTR <%#02x>", ppFunctionList );
        Log::end( "C_GetFunctionList" );
        return rv;
    }


    /**
    * C_GetSlotList obtains a list of slots in the system.
    *
    * @param tokenPresent only slots with tokens
    * @param pSlotList    receives array of slot IDs
    * @param pulCount     receives number of slots
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetSlotList )( CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetSlotList" );
        Log::in( "C_GetSlotList" );
        Log::log( "C_GetSlotList - tokenPresent <%d>", tokenPresent );
        Log::logCK_SLOT_ID_PTR( "C_GetSlotList", pSlotList, pulCount );
        Log::start( );

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( pulCount ) {

                g_Application.getSlotList( tokenPresent, pSlotList, pulCount );

            } else {

                rv = CKR_ARGUMENTS_BAD;
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );
        }

        Log::stop( "C_GetSlotList" );
        Log::logCK_RV( "C_GetSlotList", rv );
        Log::out( "C_GetSlotList" );
        Log::logCK_SLOT_ID_PTR( "C_GetSlotList", pSlotList, pulCount );
        Log::end( "C_GetSlotList" );

        return rv;
    }


    /**
    * C_GetSlotInfo obtains information about a particular slot in
    * the system.
    *
    * @param slotId the ID of the slot
    * @param pInfo  received the slot information
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetSlotInfo )( CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo )
    {
        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetSlotInfo" );
        Log::in( "C_GetSlotInfo" );
        Log::log( "C_GetSlotInfo - slotID <%ld>", slotID );
        Log::logCK_SLOT_INFO_PTR( "C_GetSlotInfo", pInfo );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pInfo ) {

                rv =  CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    s->m_Device->beginTransaction( );
               
                    s->getInfo( pInfo );
                }
            }

        } catch( PKCS11Exception& x ) {


            rv = x.getError( );
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetSlotInfo" );
        Log::logCK_RV( "C_GetSlotInfo", rv );
        Log::out( "C_GetSlotInfo" );
        Log::logCK_SLOT_INFO_PTR( "C_GetSlotInfo", pInfo );
        Log::end( "C_GetSlotInfo" );

        return rv;
    }


    /**
    * C_GetTokenInfo obtains information about a particular token
    * in the system.
    *
    * @param slotID ID of the token's slot
    * @param pInfo  receives the token information
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetTokenInfo )( CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetTokenInfo" );
        Log::in( "C_GetTokenInfo" );
        Log::log( "C_GetTokenInfo - slotID <%ld>", slotID );
        Log::logCK_TOKEN_INFO_PTR( "C_GetTokenInfo", pInfo );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pInfo ) {

                rv =  CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    //if( ! s->getToken( ).get( ) ) {
                    if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {

                        s->m_Device->beginTransaction( );
                
                        s->getTokenInfo( pInfo );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetTokenInfo" );
        Log::logCK_RV( "C_GetTokenInfo", rv );
        Log::out( "C_GetTokenInfo" );
        Log::logCK_TOKEN_INFO_PTR( "C_GetTokenInfo", pInfo );
        Log::end( "C_GetTokenInfo" );

        return rv;
    }


    /**
    * C_GetMechanismList obtains a list of mechanism types
    * supported by a token.
    *
    * @param slotID ID of token's slot
    * @param pMechanismList gets mech. array
    * @param pulCount get number of mechs
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetMechanismList )( CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetMechanismList" );
        Log::in( "C_GetMechanismList" );
        Log::log( "C_GetMechanismList - slotID <%#02x>", slotID );
        Log::logCK_MECHANISM_TYPE( "C_GetMechanismList", pMechanismList, pulCount );
        Log::start( );

        boost::shared_ptr< Slot > s; 

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pulCount ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
               
                        s->getMechanismList( pMechanismList, pulCount );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetMechanismList" );
        Log::logCK_RV( "C_GetMechanismList", rv );
        Log::out( "C_GetMechanismList" );
        Log::logCK_MECHANISM_TYPE( "C_GetMechanismList", pMechanismList, pulCount );
        Log::end( "C_GetMechanismList" );

        return rv;
    }


    /**
    * C_GetMechanismInfo obtains information about a particular
    * mechanism possibly supported by a token.
    *
    * @param slotID ID of the token's slot
    * @param type  type of mechanism
    * @param pInfo receives mechanism info
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetMechanismInfo )( CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetMechanismInfo" );
        Log::in( "C_GetMechanismInfo" );
        Log::log( "C_GetMechanismInfo - slotID <%#02x>", slotID );
        Log::logCK_MECHANISM_TYPE( "C_GetMechanismInfo", type );
        Log::logCK_MECHANISM_INFO_PTR( "C_GetMechanismInfo", pInfo );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pInfo ) {

                rv =  CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->getMechanismInfo( type, pInfo );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetMechanismInfo" );
        Log::logCK_RV( "C_GetMechanismInfo", rv );
        Log::out( "C_GetMechanismInfo" );
        Log::logCK_MECHANISM_INFO_PTR( "C_GetMechanismInfo", pInfo );
        Log::end( "C_GetMechanismInfo" );

        return rv;
    }


    /**
    * C_InitToken initializes a token.
    *
    * @param slotID ID of the token's slot
    * @param pPin   the SO's initial PIN
    * @param ulPinLen length in bytes of the PIN
    * @param pLabel 32-byte token label (blank padded) pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10
    */
    CK_DEFINE_FUNCTION( CK_RV, C_InitToken )( CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_InitToken" );
        Log::in( "C_InitToken" );
        Log::log( "C_InitToken - slotID <%#02x>", slotID );
        Log::logCK_UTF8CHAR_PTR( "C_InitToken - pPin", pPin, ulPinLen );
        Log::logCK_UTF8CHAR_PTR( "C_InitToken - pLabel", pLabel, 32 );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPin ||  !ulPinLen || !pLabel ) {

                rv =  CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->initToken( pPin, ulPinLen, pLabel );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_InitToken" );
        Log::logCK_RV( "C_InitToken", rv );
        Log::end( "C_InitToken" );

        return rv;
    }


    /**
    * C_InitPIN initializes the normal user's PIN.
    *
    * @param hSession the session's handle
    * @param pPin the noraml user's PIN
    * @param ulPinLen length in bytes of the PIN
    */
    CK_DEFINE_FUNCTION( CK_RV,C_InitPIN )( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_InitPIN" );
        Log::in( "C_InitPIN" );
        Log::log( "C_InitPIN - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_InitPIN - pPin", pPin, ulPinLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPin ||  !ulPinLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {

                        s->m_Device->beginTransaction( );
                
                        s->initPIN( hSession, pPin, ulPinLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_InitPIN" );
        Log::logCK_RV( "C_InitPIN", rv );
        Log::end( "C_InitPIN" );

        return rv;
    }


    /**
    * C_SetPIN modifies the PIN of the user who is logged in.
    *
    * @param hSession   the session's handle
    * @param pOldPin     the old PIN
    * @param ulOldPin    length of the old PIN
    * @param pNewPin     the new PIN
    * @param ulNewLen    length of the new PIN
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SetPIN )( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SetPIN" );
        Log::in( "C_SetPIN" );
        Log::log( "C_SetPIN - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_SetPIN - pOldPin", pOldPin, ulOldLen );
        Log::logCK_UTF8CHAR_PTR( "C_SetPIN - pNewPin", pNewPin, ulNewLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pOldPin || !ulOldLen || !pNewPin || !ulNewLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );
               
                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
               
                        s->setPIN( hSession, pOldPin, ulOldLen, pNewPin, ulNewLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SetPIN" );
        Log::logCK_RV( "C_SetPIN", rv );
        Log::end( "C_SetPIN" );

        return rv;
    }


    /**
    * C_OpenSession opens a session between an application and a
    * token.
    *
    * @param slotID       the slot's ID
    * @param flags        from CK_SESSION_INFO
    * @param pApplication passed to callback
    * @param Notify       callback function
    * @param phSession    gets session handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_OpenSession )( CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_OpenSession" );
        Log::in( "C_OpenSession" );
        Log::log( "C_OpenSession - slotID <%#02x>", slotID );
        Log::logSessionFlags( "C_OpenSession", flags );
        Log::log( "C_OpenSession - pApplication <%#02x>", pApplication );
        Log::log( "C_OpenSession - Notify <%#02x>", Notify );
        Log::log( "C_OpenSession - phSession <%#02x> (%#02x)", phSession, ( ( NULL_PTR != phSession ) ? *phSession : 0 ) );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !phSession ) {

                rv = CKR_ARGUMENTS_BAD;
            }

            if ( ( flags & CKF_SERIAL_SESSION ) != CKF_SERIAL_SESSION ) {

                rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
            }

            if( CKR_OK == rv ) {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
              
                        s->openSession( flags, pApplication, Notify, phSession );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_OpenSession" );
        Log::logCK_RV( "C_OpenSession", rv );
        Log::out( "C_OpenSession" );
        Log::log( "C_OpenSession - phSession <%#02x> (%ld)", phSession, ( ( NULL_PTR != phSession ) ? *phSession : 0 ) );
        Log::end( "C_OpenSession" );

        return rv;
    }


    /**
    * C_CloseSession closes a session between an application and a
    * token.
    *
    * @param hSession the session's handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_CloseSession )( CK_SESSION_HANDLE hSession ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_CloseSession" );
        Log::in( "C_CloseSession" );
        Log::log( "C_CloseSession - hSession <%#02x>", hSession );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !hSession ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->closeSession( hSession );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_CloseSession" );
        Log::logCK_RV( "C_CloseSession", rv );
        Log::end( "C_CloseSession" );

        return rv;
    }


    /**
    * C_CloseAllSessions closes all sessions with a token.
    *
    * @param slotID the token's slot
    */
    CK_DEFINE_FUNCTION( CK_RV, C_CloseAllSessions )( CK_SLOT_ID slotID ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_CloseAllSessions" );
        Log::in( "C_CloseAllSessions" );
        Log::log( "C_CloseAllSessions - slotID <%#02x>", slotID );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else {

                s = g_Application.getSlot( slotID );

                if( s.get( ) && s->m_Device.get( ) ) {

                    ////===== TEST
                    // if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    //
                    //    rv = CKR_TOKEN_NOT_PRESENT;
                    //
                    //} else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->closeAllSessions( );
                    //}
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_CloseAllSessions" );
        Log::logCK_RV( "C_CloseAllSessions", rv );
        Log::end( "C_CloseAllSessions" );

        return rv;
    }


    /**
    * C_GetSessionInfo obtains information about the session.
    *
    * @param hSession the session's handle
    * @param receives session info
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetSessionInfo )( CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetSessionInfo" );
        Log::in( "C_GetSessionInfo" );
        Log::log( "C_GetSessionInfo - hSession <%#02x>", hSession );
        Log::logCK_SESSION_INFO_PTR( "C_GetSessionInfo", pInfo );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pInfo ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->getSessionInfo( hSession, pInfo );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetSessionInfo" );
        Log::logCK_RV( "C_GetSessionInfo", rv );
        Log::out( "C_GetSessionInfo" );
        Log::logCK_SESSION_INFO_PTR( "C_GetSessionInfo", pInfo );
        Log::end( "C_GetSessionInfo" );

        return rv;
    }


    /**
    * C_Login logs a user into a token.
    *
    * @param hSession the session's handle
    * @param userType the user type
    * @param pPin the user's PIN
    * @param ulPinLen the length of the PIN
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Login )( CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Login" );
        Log::in( "C_Login" );
        Log::log( "C_Login - hSession <%#02x>", hSession );
        Log::logCK_USER_TYPE( "C_Login", userType );
        Log::logCK_UTF8CHAR_PTR( "C_Login - pPin", pPin, ulPinLen );
        Log::log( "C_Login - ulPinLen <%ld>", ulPinLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPin && ulPinLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
               
                        s->login( hSession, userType, pPin, ulPinLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Login" );
        Log::logCK_RV( "C_Login", rv );
        Log::end( "C_Login" );

        return rv;
    }


    /**
    * C_Logout logs a user out from a token.
    *
    * @param hSession the session's handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Logout )( CK_SESSION_HANDLE hSession ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Logout" );
        Log::in( "C_Logout" );
        Log::log( "C_Logout - hSession <%#02x>", hSession );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else {

                s = g_Application.getSlotFromSession( hSession );


                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
              
                        s->logout( hSession );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Logout" );
        Log::logCK_RV( "C_Logout", rv );
        Log::end( "C_Logout" );

        return rv;
    }


    /**
    * C_CreateObject creates a new object.
    *
    * @param hSession  the session's handle
    * @param pTemplate the object's template
    * @param ulCount   attributes in template
    * @param phObject  gets new object's handle.
    */
    CK_DEFINE_FUNCTION( CK_RV, C_CreateObject )( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_CreateObject" );
        Log::in( "C_CreateObject" );
        Log::log( "C_CreateObject - hSession <%#02x>", hSession );
        Log::logCK_ATTRIBUTE_PTR( "C_CreateObject", pTemplate, ulCount );
        Log::log( "C_CreateObject - phObject <%#02x>", phObject );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pTemplate || !ulCount || !phObject ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->createObject( hSession, pTemplate, ulCount, phObject );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_CreateObject" );
        Log::logCK_RV( "C_CreateObject", rv );
        Log::out( "C_CreateObject" );
        Log::log( "C_CreateObject - phObject <%#02x> (%#02x)", phObject, ( ( NULL_PTR != phObject ) ? *phObject : 0 ) );
        Log::end( "C_CreateObject" );

        return rv;
    }


    /**
    * C_DestroyObject destroys an object.
    *
    * @param hSession the session's handle
    * @param hObject the object's handle
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DestroyObject )( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_DestroyObject" );
        Log::in( "C_DestroyObject" );
        Log::log( "C_DestroyObject - hSession <%#02x>", hSession );
        Log::log( "C_DestroyObject - hObject <%#02x>", hObject );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->destroyObject( hSession, hObject );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_DestroyObject" );
        Log::logCK_RV( "C_DestroyObject", rv );
        Log::end( "C_DestroyObject" );

        return rv;
    }


    /**
    * C_GetAttributeValue obtains the value of one or more object
    * attributes.
    *
    * @param hSession    the session's handle
    * @param hObject     the object's handle
    * @param pTemplate   specifies attrs; gets vals
    * @param ulCount     attributes in template
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetAttributeValue )( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GetAttributeValue" );
        Log::in( "C_GetAttributeValue" );
        Log::log( "C_GetAttributeValue - hSession <%#02x>", hSession );
        Log::logCK_ATTRIBUTE_PTR( "C_GetAttributeValue", pTemplate, ulCount );
        Log::log( "C_GetAttributeValue - hObject <%#02x>", hObject );
        Log::start( );

        boost::shared_ptr< Slot > s;
        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pTemplate || !ulCount ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->getAttributeValue( hSession, hObject, pTemplate, ulCount );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {
            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GetAttributeValue" );
        Log::logCK_RV( "C_GetAttributeValue", rv );
        Log::out( "C_GetAttributeValue" );
        Log::logCK_ATTRIBUTE_PTR( "C_GetAttributeValue", pTemplate, ulCount );
        Log::end( "C_GetAttributeValue" );

        return rv;
    }


    /**
    * C_SetAttributeValue modifies the value of one or more object
    * attributes
    *
    * @param   hSession    the session's handle
    * @param   hObject     the object's handle
    * @param   pTemplate   specifies attrs and values
    * @param   ulCount     attributes in template
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SetAttributeValue )( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SetAttributeValue" );
        Log::in( "C_SetAttributeValue" );
        Log::log( "C_SetAttributeValue - hSession <%#02x>", hSession );
        Log::logCK_ATTRIBUTE_PTR( "C_SetAttributeValue", pTemplate, ulCount );
        Log::log( "C_SetAttributeValue - hObject <%#02x>", hObject );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pTemplate || !ulCount ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
               
                        s->setAttributeValue( hSession, hObject, pTemplate, ulCount );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );
        }
        catch( ... )
        {
            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SetAttributeValue" );
        Log::logCK_RV( "C_SetAttributeValue", rv );
        Log::end( "C_SetAttributeValue" );

        return rv;
    }


    /**
    * C_FindObjectsInit initializes a search for token and session
    * objects that match a template.
    *
    * @param hSession the session's handle
    * @param pTemplate attribute values to match
    * @param ulCount atrs in search template
    */
    CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsInit )( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_FindObjectsInit" );
        Log::in( "C_FindObjectsInit" );
        Log::log( "C_FindObjectsInit - hSession <%#02x>", hSession );
        Log::logCK_ATTRIBUTE_PTR( "C_FindObjectsInit", pTemplate, ulCount );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pTemplate && ulCount ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->findObjectsInit( hSession, pTemplate, ulCount );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_FindObjectsInit" );
        Log::logCK_RV( "C_FindObjectsInit", rv );
        Log::end( "C_FindObjectsInit" );

        return rv;
    }


    /**
    * C_FindObjects continues a search for token and session
    * objects that match a template, obtaining additional object
    * handles.
    *
    * @param hSession                session's handle
    * @param phObject                gets obj. handles
    * @param ulMaxObjectCount        max handles to get
    * @param pulObjectCount          actual # returned
    */
    CK_DEFINE_FUNCTION( CK_RV, C_FindObjects )(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_FindObjects" );
        Log::in( "C_FindObjects" );
        Log::log( "C_FindObjects - hSession <%#02x>", hSession );
        Log::log( "C_FindObjects - phObject <%#02x> (%#02x)", phObject, ( ( NULL_PTR != phObject ) ? *phObject : 0 ) );
        Log::log( "C_FindObjects - ulMaxObjectCount <%#02x>", ulMaxObjectCount );
        Log::log( "C_FindObjects - pulObjectCount <%#02x> (%#02x)", pulObjectCount, ( ( NULL_PTR != pulObjectCount ) ? *pulObjectCount : 0 ) );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !phObject || !pulObjectCount ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->findObjects( hSession, phObject, ulMaxObjectCount, pulObjectCount );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_FindObjects" );
        Log::logCK_RV( "C_FindObjects", rv );
        Log::out( "C_FindObjects" );
        Log::log( "C_FindObjects - phObject <%#02x> (%#02x)", phObject, ( ( NULL_PTR != phObject ) ? *phObject : 0 ) );
        Log::log( "C_FindObjects - pulObjectCount <%#02x> (%#02x)", pulObjectCount, ( ( NULL_PTR != pulObjectCount ) ? *pulObjectCount : 0 ) );
        Log::end( "C_FindObjects" );

        return rv;
    }


    /**
    * C_FindObjectsFinal finishes a search for token and session objects
    *
    * @param hSession the session's handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsFinal )( CK_SESSION_HANDLE hSession ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_FindObjectsFinal" );
        Log::in( "C_FindObjectsFinal" );
        Log::log( "C_FindObjectsFinal - hSession <%#02x>", hSession );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->findObjectsFinal( hSession );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_FindObjectsFinal" );
        Log::logCK_RV( "C_FindObjectsFinal", rv );
        Log::end( "C_FindObjectsFinal" );

        return rv;
    }


    /**
    * C_EncryptInit initializes an encryption operation.
    *
    * @param hSession          the session's handle
    * @param pMechanism        the encryption mechanism
    * @param hKey              handle of encryption key
    */
    CK_DEFINE_FUNCTION( CK_RV, C_EncryptInit )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_EncryptInit" );
        Log::in( "C_EncryptInit" );
        Log::log( "C_EncryptInit - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_EncryptInit", pMechanism );
        Log::log( "C_EncryptInit - hKey <%#02x>", hKey );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( pMechanism ) {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->encryptInit( hSession, pMechanism, hKey );
                    }
                }

            } else {

                rv = CKR_ARGUMENTS_BAD;
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_EncryptInit" );
        Log::logCK_RV( "C_EncryptInit", rv );
        Log::end( "C_EncryptInit" );

        return rv;
    }


    /**
    * C_Encrypt encrypts single-part data.
    *
    * @param hSession               session's handle
    * @param pData                  the plaintext data
    * @param ulDataLen              bytes of plaintext
    * @param pEncryptedData         gets ciphertext
    * @param pulEncryptedData Len   gets c-text size
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Encrypt )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Encrypt" );
        Log::in( "C_Encrypt" );
        Log::log( "C_Encrypt - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_Encrypt - pData", pData, ulDataLen );
        Log::logCK_UTF8CHAR_PTR( "C_Encrypt - pEncryptedData", pEncryptedData, (NULL_PTR == pulEncryptedDataLen) ? 0 : *pulEncryptedDataLen );
        Log::start( );      

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pData || !ulDataLen || !pulEncryptedDataLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->encrypt( hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen );
                    }
                 }
           }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {
            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Encrypt" );
        Log::logCK_RV( "C_Encrypt", rv );
        Log::out( "C_Encrypt" );
        Log::logCK_UTF8CHAR_PTR( "C_Encrypt - pEncryptedData", pEncryptedData, (NULL_PTR == pulEncryptedDataLen) ? 0 : *pulEncryptedDataLen );
        Log::end( "C_Encrypt" );

        return rv;
    }


    /**
    * C_DecryptInit initializes a decryption operation.
    *
    * @param hSession the session's handle
    * @param pMechanism the decryption mechanism
    * @param hKey handle of decrypting key
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DecryptInit )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_DecryptInit" );
        Log::in( "C_DecryptInit" );
        Log::log( "C_DecryptInit - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_DecryptInit", pMechanism );
        Log::log( "C_DecryptInit - hKey <%#02x>", hKey );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( pMechanism ) {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->decryptInit( hSession, pMechanism, hKey );
                    }
                }

            } else {

                rv = CKR_ARGUMENTS_BAD;
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_DecryptInit" );
        Log::logCK_RV( "C_DecryptInit", rv );
        Log::end( "C_DecryptInit" );

        return rv;
    }


    /**
    * C_Decrypt decrypts encrypted data in a single part.
    *
    * @param hSession                   session's handle
    * @param pEncryptedData             ciphertext
    * @param ulEncryptedDataLen         ciphertext length
    * @param pData                      gets plaintext
    * @param pulDataLen                 gets p-text size
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Decrypt )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Decrypt" );
        Log::in( "C_Decrypt" );
        Log::log( "C_Decrypt - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_Decrypt - pEncryptedData", pEncryptedData, ulEncryptedDataLen );
        Log::logCK_UTF8CHAR_PTR( "C_Decrypt - pData", pData, (NULL_PTR == pulDataLen) ? 0 : *pulDataLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pEncryptedData || !ulEncryptedDataLen || !pulDataLen ) {

                rv  = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->decrypt( hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Decrypt" );
        Log::logCK_RV( "C_Decrypt", rv );
        Log::out( "C_Decrypt" );
        Log::logCK_UTF8CHAR_PTR( "C_Decrypt - pData", pData, (NULL_PTR == pulDataLen) ? 0 : *pulDataLen );
        Log::end( "C_Decrypt" );

        return rv;
    }


    /**
    * C_DigestInit initializes a message-digesting operation.
    *
    * @param hSession the session's handle
    * @param pMechanism the digesting mechanism
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DigestInit )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_DigestInit" );
        Log::in( "C_DigestInit" );
        Log::log( "C_DigestInit - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_DigestInit", pMechanism );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pMechanism ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->digestInit( hSession, pMechanism );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_DigestInit" );
        Log::logCK_RV( "C_DigestInit", rv );
        Log::end( "C_DigestInit" );

        return rv;
    }


    /**
    * C_Digest digests data in a single part.
    *
    * @param hSession      the session's handle
    * @param pData         data to be digested
    * @param ulDataLen     bytes of data to digest
    * @param pDigest       gets the message digest
    * @param pulDigestLen  gets digest length
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Digest )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Digest" );
        Log::in( "C_Digest" );
        Log::log( "C_Digest - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_Digest - pData", pData, ulDataLen );
        Log::logCK_UTF8CHAR_PTR( "C_Digest - pDigest", pDigest, (NULL_PTR == pulDigestLen) ? 0 : *pulDigestLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pData ||  !ulDataLen ||  !pulDigestLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );
                
                        s->digest( hSession, pData, ulDataLen, pDigest, pulDigestLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Digest" );
        Log::logCK_RV( "C_Digest", rv );
        Log::out( "C_Digest" );
        Log::logCK_UTF8CHAR_PTR( "C_Digest - pDigest", pDigest, (NULL_PTR == pulDigestLen) ? 0 : *pulDigestLen );
        Log::end( "C_Digest" );

        return rv;
    }


    /**
    * C_DigestUpdate continues a multiple-part message-digesting
    * operation.
    *
    * @param hSession       the session's handle
    * @param pPart          data to be digested
    * @param ulPartLen      bytes of data to be digested
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DigestUpdate )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_DigestUpdate" );
        Log::in( "C_DigestUpdate" );
        Log::log( "C_DigestUpdate - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_DigestUpdate - pPart", pPart, ulPartLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPart || !ulPartLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->digestUpdate( hSession, pPart, ulPartLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_DigestUpdate" );
        Log::logCK_RV( "C_DigestUpdate", rv );
        Log::end( "C_DigestUpdate" );

        return rv;
    }


    /**
    * C_DigestFinal finishes a multiple-part message-digesting
    * operation.
    *
    * @param hSession       the session's handle
    * @param pDigest        gets the message digest
    * @param pulDigestLen   gets byte count of digest
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DigestFinal )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_DigestFinal" );
        Log::in( "C_DigestFinal" );
        Log::log( "C_DigestFinal - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_DigestFinal - pDigest", pDigest, (NULL_PTR == pulDigestLen) ? 0 : *pulDigestLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pulDigestLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->digestFinal( hSession, pDigest, pulDigestLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_DigestFinal" );
        Log::logCK_RV( "C_DigestFinal", rv );
        Log::out( "C_DigestFinal" );
        Log::logCK_UTF8CHAR_PTR( "C_DigestFinal - pDigest", pDigest, (NULL_PTR == pulDigestLen) ? 0 : *pulDigestLen );
        Log::end( "C_DigestFinal" );

        return rv;
    }


    /**
    * C_SignInit initializes a signature (private key encryption)
    * operation, where the signature is (will be) an appendix to
    * the data, and plaintext cannot be recovered from the
    * signature.
    *
    * @param hSession           the session's handle
    * @param pMechanism         the signature mechanism
    * @param hKey               handle of signature key
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SignInit )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SignInit" );
        Log::in( "C_SignInit" );
        Log::log( "C_SignInit - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_SignInit", pMechanism );
        Log::log( "C_SignInit - hKey <%#02x>", hKey );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pMechanism ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->signInit( hSession, pMechanism, hKey );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SignInit" );
        Log::logCK_RV( "C_SignInit", rv );
        Log::end( "C_SignInit" );

        return rv;
    }


    /**
    * C_Sign signs (encrypts with private key) data in a single
    * part, where the signature is (will be) an appendix to the
    * data, and plaintext cannot be recovered from the signature.
    *
    * @param hSession          the session's handle
    * @param pData             the data to sign
    * @param ulDataLen         count of bytes to sign
    * @param pSignature        gets the signature
    * @param pulSignatureLen   gets signature length
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Sign )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Sign" );
        Log::in( "C_Sign" );
        Log::log( "C_Sign - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_Sign - pData", pData, ulDataLen );
        Log::logCK_UTF8CHAR_PTR( "C_Sign - pSignature", pSignature, (NULL_PTR == pulSignatureLen) ? 0 : *pulSignatureLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pData || !ulDataLen || !pulSignatureLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->sign( hSession, pData, ulDataLen, pSignature, pulSignatureLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Sign" );
        Log::logCK_RV( "C_Sign", rv );
        Log::out( "C_Sign" );
        Log::logCK_UTF8CHAR_PTR( "C_Sign - pSignature", pSignature, (NULL_PTR == pulSignatureLen) ? 0 : *pulSignatureLen );
        Log::end( "C_Sign" );
        return rv;
    }


    /**
    * C_SignUpdate continues a multiple-part signature operation,
    * where the signature is (will be) an appendix to the data,
    * and plaintext cannot be recovered from the signature.
    *
    * @param hSession       the session's handle
    * @param pPart          the data to sign
    * @param ulPartLen      count of bytes to sign
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SignUpdate )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SignUpdate" );
        Log::in( "C_SignUpdate" );
        Log::log( "C_SignUpdate - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_SignUpdate - pPart", pPart, ulPartLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPart || !ulPartLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->signUpdate( hSession, pPart, ulPartLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SignUpdate" );
        Log::logCK_RV( "C_SignUpdate", rv );
        Log::end( "C_SignUpdate" );

        return rv;
    }


    /**
    * C_SignFinal finishes a multiple-part signature operation,
    * returning the signature.
    *
    * @param hSession           the session's handle
    * @param pSignature         gets the signature
    * @param pulSignatureLen    gets signature length
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SignFinal )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_SignFinal" );
        Log::in( "C_SignFinal" );
        Log::log( "C_SignFinal - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_SignFinal - pSignature", pSignature, (NULL_PTR == pulSignatureLen) ? 0 : *pulSignatureLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pulSignatureLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->signFinal( hSession, pSignature, pulSignatureLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_SignFinal" );
        Log::logCK_RV( "C_SignFinal", rv );
        Log::out( "C_SignFinal" );
        Log::logCK_UTF8CHAR_PTR( "C_SignFinal - pSignature", pSignature, (NULL_PTR == pulSignatureLen) ? 0 : *pulSignatureLen );
        Log::end( "C_SignFinal" );

        return rv;
    }


    /**
    * C_VerifyInit initializes a verification operation, where the
    * signature is an appendix to the data, and plaintext cannot
    * cannot be recovered from the signature (e.g. DSA).
    *
    * @param hSession      the session's handle
    * @param pMechanism    the verification mechanism
    * @param hKey          verification key
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_VerifyInit )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_VerifyInit" );
        Log::in( "C_VerifyInit" );
        Log::log( "C_VerifyInit - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_VerifyInit", pMechanism );
        Log::log( "C_VerifyInit - hKey <%#02x>", hKey );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pMechanism ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->verifyInit( hSession, pMechanism, hKey );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_VerifyInit" );
        Log::logCK_RV( "C_VerifyInit", rv );
        Log::end( "C_VerifyInit" );

        return rv;
    }


    /**
    * C_Verify verifies a signature in a single-part operation,
    * where the signature is an appendix to the data, and plaintext
    * cannot be recovered from the signature.
    *
    * @param hSession           the session's handle
    * @param pData              signed data
    * @param ulDataLen          length of signed data
    * @param pSignature         signature
    * @param ulSignatureLen     signature length
    */
    CK_DEFINE_FUNCTION( CK_RV, C_Verify )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_Verify" );
        Log::in( "C_Verify" );
        Log::log( "C_Verify - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_Verify - pData", pData, ulDataLen );
        Log::logCK_UTF8CHAR_PTR( "C_Verify - pSignature", pSignature, ulSignatureLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pData || !ulDataLen || !pSignature || !ulSignatureLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->verify( hSession, pData, ulDataLen, pSignature, ulSignatureLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_Verify" );
        Log::logCK_RV( "C_Verify", rv );
        Log::out( "C_Verify" );
        Log::logCK_UTF8CHAR_PTR( "C_Verify - pSignature", pSignature, ulSignatureLen );
        Log::end( "C_Verify" );

        return rv;
    }


    /* C_VerifyUpdate continues a multiple-part verification
    * operation, where the signature is an appendix to the data,
    * and plaintext cannot be recovered from the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_VerifyUpdate )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_VerifyUpdate" );
        Log::in( "C_VerifyUpdate" );
        Log::log( "C_VerifyUpdate - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_VerifyUpdate - pPart", pPart, ulPartLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pPart || !ulPartLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->verifyUpdate( hSession, pPart, ulPartLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_VerifyUpdate" );
        Log::logCK_RV( "C_VerifyUpdate", rv );
        Log::end( "C_VerifyUpdate" );

        return rv;
    }


    /* C_VerifyFinal finishes a multiple-part verification
    * operation, checking the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_VerifyFinal )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_VerifyFinal" );
        Log::in( "C_VerifyFinal" );
        Log::log( "C_VerifyFinal - hSession <%#02x>", hSession );
        Log::logCK_UTF8CHAR_PTR( "C_VerifyFinal - pSignature", pSignature, ulSignatureLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pSignature ||  !ulSignatureLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->verifyFinal( hSession, pSignature, ulSignatureLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_VerifyFinal" );
        Log::logCK_RV( "C_VerifyFinal", rv );
        Log::end( "C_VerifyFinal" );

        return rv;
    }


    /**
    * C_GenerateKeyPair generates a public-key/private-key pair, creating new key objects
    *
    * @param hSession,                    session handle
    * @param pMechanism,                  key-gen mech.
    * @param pPublicKeyTemplate,          template for pub. key
    * @param ulPublicKeyAttributeCount,   # pub. attrs.
    * @param pPrivateKeyTemplate,         template for priv. key
    * @param ulPrivateKeyAttributeCount,  # priv. attrs.
    * @param phPublicKey,                 gets pub. key handle
    * @param phPrivateKey                 gets priv key handle
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GenerateKeyPair )( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GenerateKeyPair" );
        Log::in( "C_GenerateKeyPair" );
        Log::log( "C_GenerateKeyPair - hSession <%#02x>", hSession );
        Log::logCK_MECHANISM_PTR( "C_GenerateKeyPair", pMechanism );
        Log::logCK_ATTRIBUTE_PTR( "C_GenerateKeyPair", pPublicKeyTemplate, ulPublicKeyAttributeCount );
        Log::logCK_ATTRIBUTE_PTR( "C_GenerateKeyPair", pPrivateKeyTemplate, ulPrivateKeyAttributeCount );
        Log::log( "C_GenerateKeyPair - phPublicKey <%#02x>", (phPublicKey == NULL_PTR) ? 0 : *phPublicKey );
        Log::log( "C_GenerateKeyPair - phPrivateKey <%#02x>", (phPrivateKey == NULL_PTR) ? 0 : *phPrivateKey );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try {

            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pMechanism || !pPublicKeyTemplate || !ulPublicKeyAttributeCount || !phPublicKey || !phPrivateKey ) {

                rv = CKR_ARGUMENTS_BAD;

            } else if( pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN ) {

                rv = CKR_MECHANISM_INVALID;
            }

            if( CKR_OK == rv ) {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->generateKeyPair( hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GenerateKeyPair" );
        Log::logCK_RV( "C_GenerateKeyPair", rv );
        Log::out( "C_GenerateKeyPair" );
        Log::log( "C_GenerateKeyPair - phPublicKey <%#02x>", (phPublicKey == NULL_PTR) ? 0 : *phPublicKey );
        Log::log( "C_GenerateKeyPair - phPrivateKey <%#02x>", (phPrivateKey == NULL_PTR) ? 0 : *phPrivateKey );
        Log::end( "C_GenerateKeyPair" );

        return rv;
    }


    /**
    * C_GenerateRandom generates random data.
    *
    * @param hSession       the session's handle
    * @param RandomData     receives the random data
    * @param ulRandomLen    # of bytes to generate
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GenerateRandom )( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen ) {

        boost::mutex::scoped_lock lock( io_mutex );

        CK_RV rv = CKR_OK;

        Log::begin( "C_GenerateRandom" );
        Log::in( "C_GenerateRandom" );
        Log::logCK_UTF8CHAR_PTR( "C_GenerateRandom", pRandomData, ulRandomLen );
        Log::start( );

        boost::shared_ptr< Slot > s;

        try
        {
            if( !g_isInitialized ) {

                rv = CKR_CRYPTOKI_NOT_INITIALIZED;

            } else if( !pRandomData || !ulRandomLen ) {

                rv = CKR_ARGUMENTS_BAD;

            } else {

                s = g_Application.getSlotFromSession( hSession );

                if( s.get( ) && s->m_Device.get( ) ) {

                     if( !s->getToken( ).get( ) && !s->isTokenInserted( ) ) { //->getToken( ).get( ) ) {
                    
                        rv = CKR_TOKEN_NOT_PRESENT;
                    
                    } else {
                        
                        s->m_Device->beginTransaction( );

                        s->generateRandom( hSession, pRandomData, ulRandomLen );
                    }
                }
            }

        } catch( PKCS11Exception& x ) {

            rv = x.getError( );

        } catch( ... ) {

            rv = CKR_GENERAL_ERROR;
        }

        if( s.get( ) && s->m_Device.get( ) ) {

            s->m_Device->endTransaction( );
        }

        Log::stop( "C_GenerateRandom" );
        Log::logCK_RV( "C_GenerateRandom", rv );
        Log::out( "C_GenerateRandom" );
        Log::logCK_UTF8CHAR_PTR( "C_GenerateRandom", pRandomData, ulRandomLen );
        Log::end( "C_GenerateRandom" );

        return rv;
    }


    /**
    * C_WaitForSlotEvent waits for a slot event (token insertion, removal, etc.) to occur.
    *
    * @param flags      blocking/nonblocking flag
    * @param pSlot      location that receives the slot ID
    * @param pReserved  reserved.  Should be NULL_PTR
    */
    CK_DEFINE_FUNCTION( CK_RV, C_WaitForSlotEvent )( CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved ) {
        
        CK_RV rv = CKR_NO_EVENT;

        Log::begin( "C_WaitForSlotEvent" );
        Log::in( "C_WaitForSlotEvent" );
        Log::log( "C_WaitForSlotEvent - flags <%ld> (1:CKF_DONT_BLOCK)", flags );
        Log::log( "C_WaitForSlotEvent - pSlot <%ld>", *pSlot );
        Log::log( "C_WaitForSlotEvent - pReserved <%#02x>", pReserved );

        // Not Initialized
        if( !g_isInitialized ) {

            rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        
        } else if( pReserved || !pSlot  ) {

            rv = CKR_ARGUMENTS_BAD;
        
        } else {

            // Block all other incoming calls to C_WaitForSlotEvent
            {
                boost::mutex::scoped_lock lock( io_mutex );

                // Search for a state change into the known slots
                Application::ARRAY_SLOTS sl = g_Application.getSlotList( );
            
                BOOST_FOREACH( const boost::shared_ptr< Slot >& s, sl ) {

                    if( s.get( ) && s->getEvent( ) ) {

                        *pSlot = s->getEventSlotId( );

                        s->setEvent( false, 0xFF );

                        Log::log( "C_WaitForSlotEvent -     slot <%ld>", *pSlot );
                    
                        rv = CKR_OK;
                        
                        break;
                    }
                }
            }

            if( ( CKR_OK != rv ) && ( CKF_DONT_BLOCK != ( flags & CKF_DONT_BLOCK ) ) ) {

                Log::log( "C_WaitForSlotEvent -     Block until new smart card or reader event..." );

                // Initialize the mutex to block the thread until a slot event arrives
                boost::unique_lock<boost::mutex> lock( g_WaitForSlotEventMutex );

                // Block and wait
                g_WaitForSlotEventCondition.wait( lock );
                Log::log( "WaitForSlotEvent -   Unblocked" );

                if( g_bWaitForSlotEvent ) {

                    // ??? TODO ??? lock this code section to modify the varaible in thread-safe mode
                    g_bWaitForSlotEvent = false;

                    Log::log( "WaitForSlotEvent -   Received a new event..." );

                    // Block all other incoming calls to C_WaitForSlotEvent
                    {
                        boost::mutex::scoped_lock lock2( io_mutex );

                        // Search for a state change into the known slots
                        Application::ARRAY_SLOTS as = g_Application.getSlotList( );

                        *pSlot = CK_UNAVAILABLE_INFORMATION;

                        BOOST_FOREACH( const boost::shared_ptr< Slot >& s, as ) {

                            if( s.get( ) && s->getEvent( ) ) {

                                *pSlot = s->getEventSlotId( );

                                s->setEvent( false, 0xFF );

                                break;
                            }
                        }

                        Log::log( "C_WaitForSlotEvent -     slot (Mode blocked) <%ld>", *pSlot );
                                 
                        rv = CKR_OK;
                    }
                }
            }
        }

        Log::logCK_RV( "C_WaitForSlotEvent", rv );
        Log::out( "C_WaitForSlotEvent" );
        Log::log( "C_WaitForSlotEvent - flags <%ld> (1:CKF_DONT_BLOCK)", flags );
        Log::log( "C_WaitForSlotEvent - pSlot <%ld>", *pSlot );
        Log::log( "C_WaitForSlotEvent - pReserved <%#02x>", pReserved );
        Log::end( "C_WaitForSlotEvent" );

        return rv;
    }


    //// FUNCTION NOT SUPPORTED ////


    /**
    * C_GetFunctionStatus is a legacy function; it obtains an
    * updated status of a function running in parallel with an
    * application.
    *
    * @param hSession the session's handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetFunctionStatus )( CK_SESSION_HANDLE ) {

        Log::begin( "C_GetFunctionStatus" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_GetFunctionStatus", rv );
        Log::end( "C_GetFunctionStatus" );
        return rv;
    }


    /**
    * C_CancelFunction is a legacy function; it cancels a function
    * running in parallel.
    *
    * @param hSession the session's handle
    */
    CK_DEFINE_FUNCTION( CK_RV, C_CancelFunction )( CK_SESSION_HANDLE ) {

        Log::begin( "C_CancelFunction" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_CancelFunction", rv );
        Log::end( "C_CancelFunction" );
        return rv;
    }


    /**
    * C_GetOperationState obtains the state of the cryptographic operation
    * in a session.
    *
    * @param hSession session's handle
    * @param pOperationState gets State
    * @param pulOperationStateLen gets state length
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GetOperationState )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_GetOperationState" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }
        Log::logCK_RV( "C_GetOperationState", rv );
        Log::end( "C_GetOperationState" );
        return rv;
    }


    /**
    * C_SetOperationState restores the state of the cryptographic
    * operation in a session.
    *
    * @param hSession session's handle
    * @param pOperationState hold state
    * @param ulOperationStateLen holds state length
    * @param hEncryptionKey en/decryption key
    * @param hAuthenticationKey sig/verify key
    */
    CK_DEFINE_FUNCTION( CK_RV, C_SetOperationState )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE ) {

        Log::begin( "C_SetOperationState" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }
        Log::logCK_RV( "C_SetOperationState", rv );
        Log::end( "C_SetOperationState" );
        return rv;
    }


    /**
    * C_WrapKey wraps (i.e., encrypts) a key.
    *
    * @param hSession              the session's handle
    * @param pMechanism            the wrapping mechanism
    * @param hWrappingKey          wrapping key
    * @param hKey                  key to be wrapped
    * @param pWrapperKey           gets wrapped key
    * @param pulWrappedKeyLen      gets wrapped key size
    */
    CK_DEFINE_FUNCTION( CK_RV, C_WrapKey )( CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_WrapKey" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_WrapKey", rv );
        Log::end( "C_WrapKey" );
        return rv;
    }


    /**
    * C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
    * key object.
    *
    * @param   hSession           session's handle
    * @param   pMechanism         unwrapping mech.
    * @param   hUnwrappingKey     unwrapping key
    * @param   pWrappedKey        the wrapped key
    * @param   ulWrappedKeyLen    wrapped key len
    * @param   pTemplate          new key template
    * @param   ulAttributeCount   template length
    * @param   phKey              gets new handle
    *
    */
    CK_DEFINE_FUNCTION( CK_RV,C_UnwrapKey )(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR ) {
        Log::begin( "C_UnwrapKey" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_UnwrapKey", rv );
        Log::end( "C_UnwrapKey" );
        return rv;
    }


    /**
    * C_DeriveKey derives a key from a base key, creating a new key
    * object.
    *
    * @param hSession              session's handle
    * @param pMechanism            key deriv. mech.
    * @param hBaseKey              base key
    * @param pTemplate             new key template
    * @param ulAttributeCount      template length
    * @param phKey                 gets new handle
    *
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DeriveKey )( CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR ) {

        Log::begin( "C_DeriveKey" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DeriveKey", rv );
        Log::end( "C_DeriveKey" );
        return rv;
    }


    /**
    * C_SeedRandom mixes additional seed material into the token's
    * random number generator.
    *
    * @param hSession   the session's handle
    * @param pSeed      the seed material
    * @param ulSeedLen  length of seed material
    */
    CK_DEFINE_FUNCTION( CK_RV,C_SeedRandom )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG ) {

        Log::begin( "C_SeedRandom" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_RANDOM_SEED_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_SeedRandom", rv );
        Log::end( "C_SeedRandom" );
        return rv;
    }


    /* C_VerifyRecoverInit initializes a signature verification operation, where the data is recovered from the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_VerifyRecoverInit )( CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE ) {

        Log::begin( "C_VerifyRecoverInit" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_VerifyRecoverInit", rv );
        Log::end( "C_VerifyRecoverInit" );
        return rv;
    }


    /* C_VerifyRecover verifies a signature in a single-part
    * operation, where the data is recovered from the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_VerifyRecover )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_VerifyRecover" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_VerifyRecover", rv );
        Log::end( "C_VerifyRecover" );
        return rv;
    }


    /* C_DigestEncryptUpdate continues a multiple-part digesting and encryption operation. */
    CK_DEFINE_FUNCTION( CK_RV, C_DigestEncryptUpdate )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_DigestEncryptUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DigestEncryptUpdate", rv );
        Log::end( "C_DigestEncryptUpdate" );
        return rv;
    }


    /* C_DecryptDigestUpdate continues a multiple-part decryption and digesting operation. */
    CK_DEFINE_FUNCTION( CK_RV, C_DecryptDigestUpdate )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_DecryptDigestUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DecryptDigestUpdate", rv );
        Log::end( "C_DecryptDigestUpdate" );
        return rv;
    }


    /* C_SignEncryptUpdate continues a multiple-part signing and encryption operation. */
    CK_DEFINE_FUNCTION( CK_RV, C_SignEncryptUpdate )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_SignEncryptUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_SignEncryptUpdate", rv );
        Log::end( "C_SignEncryptUpdate" );
        return rv;
    }


    /**
    * C_DecryptVerifyUpdate continues a multiple-part decryption and verify operation. */
    CK_DEFINE_FUNCTION( CK_RV, C_DecryptVerifyUpdate )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR , CK_ULONG_PTR ) {

        Log::begin( "C_DecryptVerifyUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DecryptVerifyUpdate", rv );
        Log::end( "C_DecryptVerifyUpdate" );
        return rv;
    }


    /**
    * C_GenerateKey generates a secret key, creating a new key object.
    *
    * @param    hSession,    the session's handle
    * @param    pMechanism   key generation mech.
    * @param    pTemplate    template for new key
    * @param    ulCount      # of attrs in template
    * @param    phKey        gets handle of new key
    */
    CK_DEFINE_FUNCTION( CK_RV, C_GenerateKey )( CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR ) {

        Log::begin( "C_GenerateKey" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_GenerateKey", rv );
        Log::end( "C_GenerateKey" );
        return rv;
    }

    /* C_SignRecoverInit initializes a signature operation, where the data can be recovered from the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_SignRecoverInit )( CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE ) {

        Log::begin( "C_SignRecoverInit" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_SignRecoverInit", rv );
        Log::end( "C_SignRecoverInit" );
        return rv;
    }


    /* C_SignRecover signs data in a single operation, where the data can be recovered from the signature. */
    CK_DEFINE_FUNCTION( CK_RV, C_SignRecover )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_SignRecover" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_SignRecover", rv );
        Log::end( "C_SignRecover" );
        return rv;
    }


    /* C_CopyObject copies an object, creating a new object for the copy. */
    CK_DEFINE_FUNCTION(CK_RV, C_CopyObject )( CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR ) {

        Log::begin( "C_CopyObject" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_CopyObject", rv );
        Log::end( "C_CopyObject" );
        return rv;
    }


    /* C_GetObjectSize gets the size of an object in bytes */
    CK_DEFINE_FUNCTION( CK_RV, C_GetObjectSize )( CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR ) {

        Log::begin( "C_GetObjectSize" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_GetObjectSize", rv );
        Log::end( "C_GetObjectSize" );
        return rv;
    }


    /**
    * C_EncryptUpdate continues a multiple-part encryption
    * operation.
    *
    * @param hSession                  session's handle
    * @param pPart                     the plaintext data
    * @param ulPartLen                 plaintext data len
    * @param pEncryptedPart            gets ciphertext
    * @param pulEncryptedPartLen       gets c-text size
    *
    */
    CK_DEFINE_FUNCTION(CK_RV,C_EncryptUpdate)( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_EncryptUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_EncryptUpdate", rv );
        Log::end( "C_EncryptUpdate" );
        return rv;
    }


    /**
    * C_EncryptFinal finishes a multiple-part encryption
    * operation.
    *
    * @param hSession                   session handle
    * @param pLastEncryptedPart         last c-text
    * @param pulLastEncryptedPartLen    gets last size
    */
    CK_DEFINE_FUNCTION( CK_RV, C_EncryptFinal )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_EncryptFinal" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_EncryptFinal", rv );
        Log::end( "C_EncryptFinal" );
        return rv;
    }


    /**
    * C_DecryptUpdate continues a multiple-part decryption
    * operation.
    *
    * @param hSession           session's handle
    * @param pEncryptedPart     encrypted data
    * @param ulEncryptedPart    input length
    * @param pPart              gets plaintext
    * @param pulPartLen         p-text size
    */
    CK_DEFINE_FUNCTION(CK_RV,C_DecryptUpdate)( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_DecryptUpdate" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DecryptUpdate", rv );
        Log::end( "C_DecryptUpdate" );
        return rv;
    }


    /**
    * C_DecryptFinal finishes a multiple-part decryption
    * operation.
    *
    * @param hSession           the session's handle
    * @param pLastPart          gets plaintext
    * @param pulLastPartLen     p-text size
    */
    CK_DEFINE_FUNCTION( CK_RV, C_DecryptFinal )( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR ) {

        Log::begin( "C_DecryptFinal" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DecryptFinal", rv );
        Log::end( "C_DecryptFinal" );
        return rv;
    }


    /* C_DigestKey continues a multi-part message-digesting operation, by digesting the value of a secret key as part of
    * the data already digested. */
    CK_DEFINE_FUNCTION( CK_RV, C_DigestKey )( CK_SESSION_HANDLE, CK_OBJECT_HANDLE ) {

        Log::begin( "C_DigestKey" );

        CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        if( g_isInitialized ) {

            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }

        Log::logCK_RV( "C_DigestKey", rv );
        Log::end( "C_DigestKey" );
        return rv;
    }

} // extern "C"
