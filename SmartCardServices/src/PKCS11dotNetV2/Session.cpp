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


#include "Template.hpp"
#include "Session.hpp"
#include "Slot.hpp"
#include "PKCS11Exception.hpp"
#include <boost/foreach.hpp>


unsigned char Session::s_ucSessionObjectIndex = 0;


/*
*/
Session::Session( Slot* a_pSlot, const CK_SESSION_HANDLE& a_hSession, const CK_BBOOL& a_bIsReadWrite ) {
    
	m_Slot = a_pSlot; 
	
	m_ulId = a_hSession;

	m_bIsReadWrite = a_bIsReadWrite;
	
	m_bIsSearchActive = false;
	
	m_bIsDigestActive = false;
	
	m_bIsDigestActiveRSA = false;
	
	m_bIsDigestVerificationActiveRSA = false;

	// The User or the SO has may be performed a login before to open this session
	// In this case the state of the session must be updated
    getState( );
}


/*
*/
CK_STATE Session::getState( void ) { 
    
    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    CK_USER_TYPE ulRole = m_Slot->getUserType( );

    updateState( ulRole );

    return m_ulState; 
}


/*
*/
void Session::updateState( const CK_ULONG& a_ulRoleLogged ) {

	if( m_bIsReadWrite ) {

		switch( a_ulRoleLogged ) {

		case CK_UNAVAILABLE_INFORMATION:
			m_ulState = CKS_RW_PUBLIC_SESSION;
			break;

		case CKU_USER:
			m_ulState = CKS_RW_USER_FUNCTIONS;
			break;

		case CKU_SO:
			m_ulState = CKS_RW_SO_FUNCTIONS;
			break;
		}

	} else {
		
		switch( a_ulRoleLogged ) {

		case CK_UNAVAILABLE_INFORMATION:
			m_ulState = CKS_RO_PUBLIC_SESSION;
			break;

		case CKU_USER:
			m_ulState = CKS_RO_USER_FUNCTIONS;
			break;

		case CKU_SO:
			throw PKCS11Exception( CKR_SESSION_READ_ONLY );
		}
	}
}


/*
*/
StorageObject* Session::getObject( const CK_OBJECT_HANDLE& a_hObject ) {

	if( !a_hObject ) {

		throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	}

	// Find the targeted object
	SESSION_OBJECTS::iterator i = m_Objects.find( a_hObject );

     if( i == m_Objects.end( ) ) {
	
		 throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
	 }

	return i->second;
}


/*
*/
void Session::findObjects( CK_OBJECT_HANDLE_PTR a_phObject, const CK_ULONG& a_ulMaxObjectCount, CK_ULONG_PTR a_pulObjectCount ) {
    
    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    bool bIsNotAllowedToAccessPrivateObjects = !m_Slot->isAuthenticated( );

    Session::EXPLORED_HANDLES::iterator end = m_SessionObjectsReturnedInSearch.end( );

    // For each P11 object
    BOOST_FOREACH( const SESSION_OBJECTS::value_type& o, m_Objects ) {

        // Check if the search has reached the allowed maximum of objects to search 
        if( *a_pulObjectCount >= a_ulMaxObjectCount ) {

            break;
        }

        // Check if this object has been already compared to the search template
        if( end != m_SessionObjectsReturnedInSearch.find( o->first ) ) {

            // This object has already been analysed by a previous call of findObjects for this template
            continue;
        }

        // If the object is private and the user is not logged in
        if( o->second->isPrivate( ) && bIsNotAllowedToAccessPrivateObjects )
        {
            // Then avoid this element. 
            // Do not add it the list of already explored objects (may be a C_Login can occur)
            continue;
        }

        // Add the object to the list of the objects compared to the search template
        m_SessionObjectsReturnedInSearch.insert( o->first );

        // If the template is NULL then return all objects
        if( !_searchTempl ) {

            a_phObject[ *a_pulObjectCount ] = o->first;

            ++(*a_pulObjectCount);

        } else {
            // The template is not NULL.
   
            bool match = true;

            // In this case the template attributes have to be compared to the objects ones.
            BOOST_FOREACH( CK_ATTRIBUTE& t, _searchTempl->getAttributes( ) ) {

                if( ! o->second->compare( t ) ) {

                    match = false;

                    break;
                }
            }

            // The attributes match
            if( match ) {

                // Add the object handle to the outgoing list
                a_phObject[ *a_pulObjectCount ] = o->first;

                // Increment the number of found objects
                ++(*a_pulObjectCount);
            }
        }
    }
}


/*
*/
void Session::deleteObject( const CK_OBJECT_HANDLE& a_hObject ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

	// Find the targeted object
	StorageObject* o = getObject( a_hObject );

	// if this is a readonly session and user is not logged 
	// then only public session objects can be created
	if( !m_bIsReadWrite && o->isToken( ) ) {

		throw PKCS11Exception( CKR_SESSION_READ_ONLY );
	}

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
		throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}
	
	try {
    
        m_Objects.erase( a_hObject );
    
    } catch( ... ) {
    
        throw PKCS11Exception( CKR_OBJECT_HANDLE_INVALID );
    }
}


/*
*/
void Session::getAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the targeted object
	StorageObject* o = getObject( a_hObject );

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
		for( u4 i = 0 ; i < a_ulCount ; ++i ) {

			a_pTemplate[ i ].ulValueLen = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
		}

		throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}

	for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {
		
		o->getAttribute( &a_pTemplate[ i ] );
	}
}


/*
*/
void Session::setAttributeValue( const CK_OBJECT_HANDLE& a_hObject, CK_ATTRIBUTE_PTR a_pTemplate, const CK_ULONG& a_ulCount ) {

    if( !m_Slot ) {
    
        throw PKCS11Exception( CKR_TOKEN_NOT_PRESENT );
    }

    // Find the targeted object
	StorageObject* o = getObject( a_hObject );

	if( o->isPrivate( ) && !m_Slot->isAuthenticated( ) ) {
        
        throw PKCS11Exception( CKR_USER_NOT_LOGGED_IN );
	}

	for( CK_ULONG i = 0 ; i < a_ulCount ; ++i ) {

		o->setAttribute( a_pTemplate[ i ], false );
	}
}


/*
*/
CK_OBJECT_HANDLE Session::computeObjectHandle( const CK_OBJECT_CLASS& a_ulClass, const bool& a_bIsPrivate ) { 
    
    // Register the session object id (value from 0 to 255)
    unsigned char ucByte1 = ++s_ucSessionObjectIndex;

    // Register the object class and if the object is private:
	// Private Data	        1000 [08] = set class to CKO_DATA (0x00) and Private to TRUE (0x08)
	// Public Data	        0000 [00] = set class to CKO_DATA (0x00) and Private to FALSE (0x00)	
	// Private Certificate	1001 [09] = set class to CKO_CERTIFICATE (0x01) and Private to TRUE (0x08)
	// Public Certificate	0001 [01] = set class to CKO_CERTIFICATE (0x01) and Private to FALSE (0x00)		
	// Private Public Key	1010 [10] = set class to CKO_PUBLIC_KEY (0x02) and Private to TRUE (0x08)
	// Public Public Key	0010 [02] = set class to CKO_PUBLIC_KEY (0x02) and Private to FALSE (0x00)    
    // Private Private Key	1011 [11] = set class to CKO_PRIVATE_KEY (0x03) and Private to TRUE (0x08)			
	// Public Private Key	0011 [03] = set class to CKO_PRIVATE_KEY (0x03) and Private to FALSE (0x00)
	unsigned char ucByte2 = (unsigned char)a_ulClass + ( a_bIsPrivate ? 0x08 : 0x00 );

    // Register if the object is owned by the token (value 0) or the session (value corresponding to the session id from 1 to 255)
    unsigned char ucByte3 = (unsigned char) ( 0x000000FF & m_ulId );

    // Register the slot id
    unsigned char ucByte4 = (unsigned char) ( 0x000000FF & m_Slot->getSlotId( ) );

    // Compute the object handle: byte4 as Slot Id, byte3 as Token/Session, byte2 as attributes and byte1 as object Id					
    CK_OBJECT_HANDLE h = ( ucByte4 << 24 ) + ( ucByte3 << 16 ) + ( ucByte2 << 8 )+ ucByte1;

    return h; 
}


/*
*/
void Session::addObject( StorageObject* a_pObj, CK_OBJECT_HANDLE_PTR a_phObject ) { 
    
    *a_phObject = computeObjectHandle( a_pObj->getClass( ), a_pObj->isPrivate( ) ); 
    
    CK_OBJECT_HANDLE h = *a_phObject; 
    
    m_Objects.insert( h, a_pObj ); 
}
