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

#ifndef WIN32
#include <stdlib.h>
#endif
#include <memory>
#include <string>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include "Application.hpp"
#include "Configuration.hpp"
#include "PKCS11Exception.hpp"
#include "Log.hpp"
#ifdef WIN32 
#include <shlobj.h> // For SHGetFolderPath
#else
#endif


// Determine Processor Endianess
#include <limits.h>
#if (UINT_MAX == 0xffffffffUL)
   typedef unsigned int _u4;
#else
#  if (ULONG_MAX == 0xffffffffUL)
     typedef unsigned long _u4;
#  else
#    if (USHRT_MAX == 0xffffffffUL)
       typedef unsigned short _u4;
#    endif
#  endif
#endif

_u4 endian = 1;

bool IS_LITTLE_ENDIAN = (*((unsigned char *)(&endian))) ? true  : false;
bool IS_BIG_ENDIAN    = (*((unsigned char *)(&endian))) ? false : true;

#ifdef MACOSX_LEOPARD
#define SCardIsValidContext(x) SCARD_S_SUCCESS
#endif

extern boost::condition_variable g_WaitForSlotEventCondition;

/*
*/
Application::Application( ) {

    Log::start( );
	std::string stConfigurationDirectoryPath;

#ifdef WIN32 
    
    // For each user (roaming) data, use the CSIDL_APPDATA value. 
    // This defaults to the following path: "\Documents and Settings\All Users\Application Data" 
    TCHAR szPath[MAX_PATH];

    SHGetFolderPath( NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, szPath );

    stConfigurationDirectoryPath = std::string( szPath ) + std::string( "/Gemalto/DotNet PKCS11/" );

#else
	char *home = getenv("HOME");
	if (home)
		stConfigurationDirectoryPath = std::string( home ) + std::string( "/.config/Gemalto/DotNet PKCS11/" );
	else
		stConfigurationDirectoryPath = std::string( "/tmp/Gemalto/DotNet PKCS11/" );
#endif

    std::string stConfigurationFilePath = stConfigurationDirectoryPath + std::string( "Gemalto.NET.PKCS11.ini" );

    Log::log( "Application::Application - stConfigurationFilePath <%s>", stConfigurationFilePath.c_str( ) );
    boost::filesystem::path configurationDirectoryPath( stConfigurationFilePath );

    if( ! boost::filesystem::exists( configurationDirectoryPath ) ) {
    
        Log::s_bEnableLog = false;
        
        Device::s_bEnableCache = true;
    
    } else {

        // Initialize the configuration 
	    Configuration c;
	    try {

		    c.load( stConfigurationFilePath );

            const std::string stCacheSectionName( "Cache" );
            const std::string stCacheParameterEnable( "Enable" );
            const std::string stLogSectionName( "Log" );
            const std::string stLogParameterEnable( "Enable" );
            const std::string stLogParameterPath( "Path" );

		    // Read the flag in the configuration to enable/disable the log
		    std::string stResult = "";

		    c.getValue( stLogSectionName, stLogParameterEnable, stResult );
		
            if( 0 == stResult.compare( "1" ) ) {
	
			    Log::s_bEnableLog = true;

		        // Read the flag in the configuration for the log filepath
		        stResult = "";
		
                c.getValue( stLogSectionName, stLogParameterPath, stResult );
		
                if( stResult.size( ) > 0 ) {
	
			        Log::setLogPath( stResult );
		        
                } else {
#ifdef WIN32
                    Log::setLogPath( stConfigurationDirectoryPath );
#endif
                }
		    }

		    // Read the flag in the configuration to enable/disable the cache on disk
		    stResult = "";
		
            c.getValue( stCacheSectionName, stCacheParameterEnable, stResult );
		
            if( 0 == stResult.compare( "1" ) ) {

			    Device::s_bEnableCache = true;

		    } else {

			    Device::s_bEnableCache = false;
		    }
	    } catch( ... ) {

		    // Unable to find the configuration file
		    // Use default settings instead
            Log::error( "Application::Application", "No configuration file found. Use default settings" );
	    }
    }

    Log::log( "" );
    Log::log( "" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( " PKCS11 STARTS" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "" );

    m_DeviceMonitor.reset( new DeviceMonitor( ) );

	// Initialise the PCSC devices listener
	m_DeviceMonitor->addListener( this );

    Log::stop( "Application::Application" );
}


/*
*/
Application::~Application( ) {

    if( m_DeviceMonitor.get( ) ) {

	    // Remove the application from the PCSC devices listener list
	    m_DeviceMonitor->removeListener( this ); 
    }

    finalize( );

    Log::log( "" );
    Log::log( "" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( " PKCS11 STOPS" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "######   ######   ######   ######   ######   ######   ######   ######   ######" );
    Log::log( "" );
}


/*
*/
void Application::notifyReaderInserted( const std::string& a_stReaderName ) {

	BOOST_FOREACH( boost::shared_ptr< Device >& d, m_DeviceMonitor->getDeviceList( ) ) {
	    
        // Search the device associated to this new reader
		if( d.get( ) && ( 0 == d->getReaderName( ).compare( a_stReaderName ) ) ) {
            
            // Create the PKCS11 slot associated to this new reader
			addSlot( d );
			
			return;
		}
	}
}


/*
*/
void Application::notifyReaderRemoved( const std::string& a_stReaderName ) {

    unsigned char ucSlotId = 0;

	BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		// If the slot exists and the the names are the same
		if( s.get( ) && !s->getReaderName( ).compare( a_stReaderName ) ) {

            s->tokenDelete( );

            s->setEvent( true, ucSlotId );

			return;
		}

        ++ucSlotId;
	}
}


/*
*/
void Application::notifySmartCardRemoved( const std::string& a_stReaderName ) {

    unsigned char ucSlotId = 0;

	BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		// If the slot exists and the the names are the same
		if( s.get( ) && !s->getReaderName( ).compare( a_stReaderName ) ) {

			s->tokenDelete( );
            
            s->setEvent( true, ucSlotId );
			
            return;
		}

        ++ucSlotId;
	}
}


/*
*/
void Application::notifySmartCardInserted( const std::string& a_stReaderName ) {

    unsigned char ucSlotId = 0;

    BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		// If the slot exists and the names are the same
		if( s.get( ) && !s->getReaderName( ).compare( a_stReaderName ) ) {

// LCA: Not create token on event but register insertion in slot
//			s->tokenCreate( );
            s->tokenInserted();

            s->setEvent( true, ucSlotId );

			return;
		}

        ++ucSlotId;
	}


}


/*
*/
void Application::notifySmartCardChanged( const std::string& a_stReaderName ) {
	
    unsigned char ucSlotId = 0;

    BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		// If the slot exists and the the names are the same
		if( s.get( ) && !s->getReaderName( ).compare( a_stReaderName ) ) {

			s->tokenUpdate( );

            s->setEvent( true, ucSlotId );

			return;
		}

        ++ucSlotId;
	}
}


///*
//*/
//void Application::getSlotList( const CK_BBOOL& a_bTokenPresent, CK_SLOT_ID_PTR a_pSlotList, CK_ULONG_PTR a_pulCount ) {
//
//    *a_pulCount = 1;
//
//    if( a_pSlotList ) {
//     
//        a_pSlotList[ 0 ] = 1;
//    }
//
///*
//	CK_ULONG ulCountSlot = 0;
//	
//	CK_ULONG ulCountSlotWithToken = 0;
//
//	CK_SLOT_ID iIndex = 0;
//
//    CK_RV rv = CKR_OK;
//
//	// Build the slot list
//    size_t l = m_Slots.size( );
//
//	for( size_t i = 0; i < l ; ++i ) {
//
//		if( m_Slots[ i ].get( ) ) {
//
//			if( !a_bTokenPresent ) {
//
//				// Found a valid slot
//				++ulCountSlot;
//
//				if( a_pSlotList ) {
//					
//                    if ( ulCountSlot > *a_pulCount ) {
//                 
//                        rv  = CKR_BUFFER_TOO_SMALL;
//                    
//                    } else {
//
//					    a_pSlotList[ iIndex ] = i;
//					
//                        ++iIndex;
//                    }
//				}
//
//			} else if( m_Slots[ i ]->getToken( ).get( ) ) { //isCardPresent( ) ) {
//			
//				// Found a slot within a token
//				++ulCountSlotWithToken;
// 
//				if( a_pSlotList ) {
//					
//                   if ( ulCountSlotWithToken > *a_pulCount ) {
//                 
//                        rv = CKR_BUFFER_TOO_SMALL;
//                    }
//
//                   a_pSlotList[ iIndex ] = i;
//					
//                   ++iIndex;
//				}
//			}
//		}
//	}
//
//	// Return the slot count
//	if( a_bTokenPresent ) {
//	
//		*a_pulCount = ulCountSlotWithToken;	
//	
//    } else {
//	
//		*a_pulCount = ulCountSlot;
//	}
//
//    if ( CKR_OK != rv ) {
//                 
//        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
//    }
//*/
//}


/*
*/
void Application::getSlotList( const CK_BBOOL& a_bTokenPresent, CK_SLOT_ID_PTR a_pSlotList, CK_ULONG_PTR a_pulCount ) {

	CK_ULONG ulCountSlot = 0;
	
	CK_ULONG ulCountSlotWithToken = 0;

	CK_SLOT_ID iIndex = 0;

    CK_RV rv = CKR_OK;

	// Build the slot list
    size_t l = m_Slots.size( );

	for( size_t i = 0; i < l ; ++i ) {

        Slot* s = m_Slots[ i ].get( );

		if( s ) {

			if( !a_bTokenPresent ) {

				// Found a valid slot
				++ulCountSlot;

				if( a_pSlotList ) {
					
                    if ( ulCountSlot > *a_pulCount ) {
                 
                        rv  = CKR_BUFFER_TOO_SMALL;
                    
                    } else {

					    a_pSlotList[ iIndex ] = i;
					
                        ++iIndex;
                    }
				}
			
//            } else if( m_Slots[ i ]->getToken( ).get( ) ) { //isCardPresent( ) ) {
            } else if( /*s->isTokenInserted( ) ||*/ s->isCardPresent( ) ) {
			
				// Found a slot within a token
				++ulCountSlotWithToken;
 
				if( a_pSlotList ) {
					
                   if ( ulCountSlotWithToken > *a_pulCount ) {
                 
                        rv = CKR_BUFFER_TOO_SMALL;
                    }

                   a_pSlotList[ iIndex ] = i;
					
                   ++iIndex;
				}
			}
		}
	}

	// Return the slot count
	if( a_bTokenPresent ) {
	
		*a_pulCount = ulCountSlotWithToken;	
	
    } else {
	
		*a_pulCount = ulCountSlot;
	}

    if ( CKR_OK != rv ) {
                 
        throw PKCS11Exception( CKR_BUFFER_TOO_SMALL );
    }
}


/*
*/
const boost::shared_ptr< Slot >& Application::getSlot( const CK_SLOT_ID& a_slotId ) {

    if( a_slotId >= m_Slots.size( ) ) {
    
        throw PKCS11Exception( CKR_SLOT_ID_INVALID );
    }
    
    boost::shared_ptr< Slot >& s = m_Slots.at( a_slotId );
    
    if( !s.get( ) ) {
    
        throw PKCS11Exception( CKR_SLOT_ID_INVALID );
    }

    return s;
}


/* Initialize the slot list from the device list
*/
void Application::getDevices( void ) {

	BOOST_FOREACH( boost::shared_ptr< Device >& d, m_DeviceMonitor->getDeviceList( ) ) {
	
		if( d.get( ) ) {

			unsigned char ucDeviceId = d->getDeviceID( );

            m_Slots[ ucDeviceId ].reset( new Slot( d ) );
		}
	}
}


/*
*/
void Application::addSlot( const boost::shared_ptr< Device >& a_pDevice ) {

    if( !a_pDevice ) {
    
        return;
    }

    Log::begin( "Application::addSlot" ); 

    unsigned char ucDeviceId = a_pDevice->getDeviceID( );

    m_Slots[ ucDeviceId ].reset( new Slot( a_pDevice ) );

    m_Slots[ ucDeviceId ]->setEvent( true, ucDeviceId );

    Log::end( "Application::addSlot" ); 
}


/*
*/
const boost::shared_ptr< Slot >& Application::getSlotFromSession( const CK_SESSION_HANDLE& a_hSession ) {

	BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		if( s.get( ) && s->isSessionOwner( a_hSession ) ) {

			return s;
		}	
	}

	throw PKCS11Exception( CKR_SESSION_HANDLE_INVALID );
}


/*
*/
void Application::initialize( ) {

	// Start the PCSC devices listener
	if( m_DeviceMonitor.get( ) ) {
        
        m_DeviceMonitor->start( );
    }

  	// Get the known PCSC devices
	getDevices( );
}

//extern boost::mutex g_WaitForSlotEventMutex;

/*
*/
void Application::finalize( void ) {

    g_WaitForSlotEventCondition.notify_all( );
  
    long rv = SCardIsValidContext( DeviceMonitor::m_hContext );


    if( SCARD_S_SUCCESS == rv ) {

        // Call the finalize method for all managed device
	    BOOST_FOREACH( boost::shared_ptr< Slot >& s, m_Slots ) {
	
		    if( s.get( ) ) {

               

			    s->finalize( );
		    }	
	    }

        

  	    // Stop the PCSC devices listenening thread
	    if( m_DeviceMonitor.get( ) ) {

            //g_WaitForSlotEventMutex.unlock( );

            //DeviceMonitor::m_bAlive = false;

            m_DeviceMonitor->stop( );

            SCardReleaseContext( DeviceMonitor::m_hContext );
        }
    }
}
