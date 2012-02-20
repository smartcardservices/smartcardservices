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


#ifndef __GEMALTO_CARD_MODULE_SERVICE__
#define __GEMALTO_CARD_MODULE_SERVICE__


#include <string>
#include <boost/ptr_container/ptr_map.hpp>
#include "MarshallerCfg.h"
#include "Array.hpp"
#include "Marshaller.h"
#include "Except.h"
#include "Timer.hpp"
#include "Log.hpp"


const unsigned char CARD_FREE_SPACE  = 0x00; //Returns a byte array blob of 12 bytes
const unsigned char CARD_KEYSIZES = 0x02; // Returns a byte array blob of 16 bytes 
const unsigned char CARD_READ_ONLY = 0x03; // Returns a byte array blob of 1 byte
const unsigned char CARD_CACHE_MODE = 0x04; // Returns a byte array blob of 1 byte
const unsigned char CARD_GUID = 0x05; // Returns a byte array blob of 16 bytes
const unsigned char CARD_SERIAL_NUMBER = 0x06; // Returns a byte array blob of 12 bytes
const unsigned char CARD_PIN_INFO = 0x07; // Returns a byte array blob of 12 bytes
const unsigned char CARD_ROLES_LIST = 0x08; // Returns a byte array blob of 1 byte
const unsigned char CARD_AUTHENTICATED_ROLES = 0x09; // Returns a byte array blob of 1 byte 
const unsigned char CARD_PIN_STRENGTH = 0x0A; // Returns a byte array blob of 1 byte
const unsigned char CARD_X509_ENROLL = 0x0D; // Returns a byte array blob of 1 byte
const unsigned char CARD_PIN_POLICY = 0x80; // Returns a byte array blob of 14 bytes
const unsigned char CARD_CHANGE_PIN_FIRST = 0xFA; // Returns a byte array blob of 1 byte
const unsigned char CARD_VERSION_INFO = 0xFF; // Returns a byte array blob of 4 bytes

/*
*/
class CardModuleService : public Marshaller::SmartCardMarshaller {

public:

    typedef boost::ptr_map< unsigned char, Marshaller::u1Array > PROPERTIES;

    typedef enum { SMART_CARD_TYPE_V1 = 0x00, SMART_CARD_TYPE_V2 = 0x01, SMART_CARD_TYPE_V2PLUS = 0x02 } SMARTCARD_TYPE;

    inline CardModuleService( const std::string& readerName, u2 portNumber = 5, std::string uri = "MSCM" ) : Marshaller::SmartCardMarshaller( readerName, portNumber, uri, (u4)0xC04B4E, (u2)0x7FBD, 0 ) { Timer t; t.start( ); m_Timer.start( ); getVersion( ); t.stop( ">> CardModuleService::CardModuleService" ); }

    inline bool isV2Plus( void ) { return ( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ); }

    void manageGarbageCollector( void );

    inline void updateCardHandle( SCARDHANDLE a_CardHandle ) { UpdatePCSCCardHandle( a_CardHandle ); }

    inline std::string& getReader( void ) { return GetReaderName( ); }

    inline SCARDHANDLE getCardHandle( void ) { return GetCardHandle( ); }

    inline void doSCardTransact( bool& flag ) { DoTransact( flag ); }

    inline void createContainer( const unsigned char& i, const unsigned char& keyImport, const unsigned char& keySpec, const int& keySize, Marshaller::u1Array* keyValue ) { Log::log( ">> CardModuleService::createContainer - index <%#02x>", i ); Timer t; t.start( ); try { Invoke( 5, 0x0234, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_IN_BOOL, keyImport, MARSHALLER_TYPE_IN_U1, keySpec, MARSHALLER_TYPE_IN_S4, keySize, MARSHALLER_TYPE_IN_U1ARRAY, keyValue, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } forceGarbageCollector( ); t.stop( ">> CardModuleService::createContainer" ); }

    inline void deleteContainer( const unsigned char& i ) { Log::log( ">> CardModuleService::deleteContainer - index <%#02x>", i ); Timer t; t.start( ); try { Invoke( 1, 0xF152, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } forceGarbageCollector( ); t.stop( ">> CardModuleService::deleteContainer" ); }

    inline Marshaller::u1Array* getContainer( const unsigned char& i ) { Log::log( ">> CardModuleService::getContainer - index <%#02x>", i ); Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke( 1, 0x9B2E, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_RET_U1ARRAY, &a ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getContainer"); return a; }

    inline Marshaller::u1Array* getContainerProperty( const unsigned char& i, const unsigned char& p, const unsigned char& f ) { Log::log( ">> CardModuleService::getContainerProperty - index <%#02x>", i ); Timer t; t.start( ); Marshaller::u1Array* a = 0; if( SMART_CARD_TYPE_V2PLUS == m_ucSmartCardType ) { try {  Invoke( 3, 0x279C, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_IN_U1, p, MARSHALLER_TYPE_IN_U1, f, MARSHALLER_TYPE_RET_U1ARRAY, &a );  } catch( Marshaller::Exception& x ) { checkException( x ); } } t.stop( ">> CardModuleService::getContainerProperty"); return a; }

    inline void setContainerProperty( const unsigned char& i, const unsigned char& p, Marshaller::u1Array* d, const unsigned char& f ) { Log::log( ">> CardModuleService::setContaineProperty - index <%#02x>", i ); Timer t; t.start( ); try {  Invoke(4, 0x98D1, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_IN_U1, p, MARSHALLER_TYPE_IN_U1ARRAY, d, MARSHALLER_TYPE_IN_U1, f, MARSHALLER_TYPE_RET_VOID); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::setContainerProperty" ); }

    inline Marshaller::u1Array* privateKeyDecrypt( const unsigned char& i, const unsigned char& k, Marshaller::u1Array* d ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke( 3, 0x6144, MARSHALLER_TYPE_IN_U1, i, MARSHALLER_TYPE_IN_U1, k, MARSHALLER_TYPE_IN_U1ARRAY, d, MARSHALLER_TYPE_RET_U1ARRAY, &a ); } catch( Marshaller::Exception& x ) { checkException( x ); } manageGarbageCollector( ); t.stop( ">> CardModuleService::privateKeyDecrypt"); return a; }

    inline void createFile( std::string* p, Marshaller::u1Array* a, const int& z ) { Log::log( ">> CardModuleService::createFile - path <%s>", p->c_str( ) ); Timer t; t.start( ); try {  Invoke( 3, 0xBEF1, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_IN_U1ARRAY, a, MARSHALLER_TYPE_IN_S4, z, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } manageGarbageCollector( ); t.stop( ">> CardModuleService::createFile" ); }

    inline void createDirectory( std::string* p, Marshaller::u1Array* a ) { Log::log( ">> CardModuleService::createDirectory - path <%s>", p->c_str( ) ); Timer t; t.start( ); try {  Invoke( 2, 0xACE9, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_IN_U1ARRAY, a, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } manageGarbageCollector( ); t.stop( ">> CardModuleService::createDirectory" ); }

    inline void writeFile( std::string* p, Marshaller::u1Array* a ) { Log::log( ">> CardModuleService::writeFile - path <%s>", p->c_str( ) ); Timer t; t.start( ); try { Invoke( 2, 0xF20E, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_IN_U1ARRAY, a, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } manageGarbageCollector( ); t.stop( ">> CardModuleService::writeFile" ); }

    inline Marshaller::u1Array* readFile( std::string* p ) { Log::log( ">> CardModuleService::readFile - path <%s>", p->c_str( ) ); Marshaller::u1Array* a = readFileWithoutMemoryCheck( p ); manageGarbageCollector( ); Log::end( ">> CardModuleService::readFile" ); return a; }

    inline Marshaller::u1Array* readFileWithoutMemoryCheck( std::string* p ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke( 2, 0x744C, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_IN_S4, 0, MARSHALLER_TYPE_RET_U1ARRAY, &a ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::readFileWithoutMemoryCheck" ); return a; }

    inline void deleteFile( std::string* p ) { Log::log( ">> CardModuleService::deleteFile - path <%s>", p->c_str( ) ); Timer t; t.start( ); try { Invoke( 1, 0x6E2B, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } forceGarbageCollector( ); t.stop( ">> CardModuleService::deleteFile" ); }

    inline void deleteDirectory( std::string* p ){ Log::log( ">> CardModuleService::deleteDirectory - path <%s>", p->c_str( ) ); Timer t; t.start( ); try { Invoke( 1, 0x9135, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } forceGarbageCollector( ); t.stop( ">> CardModuleService::deleteDirectory" ); }

    inline Marshaller::StringArray* getFiles( std::string* p ) { Log::log( ">> CardModuleService::getFiles - path <%s>", p->c_str( ) ); Timer t; t.start( ); Marshaller::StringArray* a = 0; try {  Invoke( 1, 0xE72B, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_RET_STRINGARRAY, &a ); } catch( Marshaller::Exception& x ) { t.stop( ">> CardModuleService::getFiles"); checkException( x ); } t.stop( ">> CardModuleService::getFiles"); return a; }

    inline Marshaller::u1Array* getFileProperties( std::string* p ) { Log::log( ">> CardModuleService::getFileProperty - path <%s>", p->c_str( ) ); Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke( 1, 0xA01B, MARSHALLER_TYPE_IN_STRING, p->c_str( ), MARSHALLER_TYPE_RET_U1ARRAY, &a ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getFileProperties"); return a; }

    inline int getTriesRemaining( const unsigned char& r) { Timer t; t.start( ); int i = 0; try {  Invoke( 1, 0x6D08, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_RET_S4, &i ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getTriesRemaining"); return i; }

    inline void changeReferenceData( const unsigned char& m, const unsigned char& r, Marshaller::u1Array* oldPin, Marshaller::u1Array* newPin, const int& maxTries ) { Timer t; t.start( ); try {  Invoke( 5, 0xE08A, MARSHALLER_TYPE_IN_U1, m, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_IN_U1ARRAY, oldPin, MARSHALLER_TYPE_IN_U1ARRAY, newPin, MARSHALLER_TYPE_IN_S4, maxTries, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::changeReferenceData" ); }

    inline void changeAuthenticatorEx( const unsigned char& m, const unsigned char& orole, Marshaller::u1Array* op, const unsigned char& nr, Marshaller::u1Array* np, const int& t ) { Timer time; time.start( ); try {  Invoke( 6, 0x9967, MARSHALLER_TYPE_IN_U1, m, MARSHALLER_TYPE_IN_U1, orole, MARSHALLER_TYPE_IN_U1ARRAY, op, MARSHALLER_TYPE_IN_U1, nr, MARSHALLER_TYPE_IN_U1ARRAY, np, MARSHALLER_TYPE_IN_S4, t, MARSHALLER_TYPE_RET_VOID ); } catch( Marshaller::Exception& x ) { checkException( x ); } time.stop( ">> CardModuleService::changeAuthenticatorEx" ); }

    bool isAuthenticated( const unsigned char& );

    Marshaller::u1Array* getCardProperty( const unsigned char& p, const unsigned char& f );

    void setCardProperty( const unsigned char& p, Marshaller::u1Array* d, const unsigned char& f );

    unsigned int getMemory( void );

    void verifyPin( const unsigned char& r, Marshaller::u1Array* p );

    void logOut( const unsigned char& );

    void forceGarbageCollector( void );

    inline Marshaller::u1Array* getChallenge( void ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke(0, 0xFA3B, MARSHALLER_TYPE_RET_U1ARRAY, &a); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getChallenge"); return a; }

    inline void externalAuthenticate( Marshaller::u1Array* a ) { Timer t; t.start( ); try {  Invoke(1, 0x24FE, MARSHALLER_TYPE_IN_U1ARRAY, a, MARSHALLER_TYPE_RET_VOID); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::externalAuthenticate" ); }

    inline Marshaller::s4Array* getKeySizes( void ) { Timer t; t.start( ); Marshaller::s4Array* a = 0; try {  Invoke(0, 0x5EE4, MARSHALLER_TYPE_RET_S4ARRAY, &a); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getKeySizes"); return a; }

    inline Marshaller::u1Array* getSerialNumber( void ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke(0, 0xD017, MARSHALLER_TYPE_RET_U1ARRAY, &a); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getSerialNumber"); return a; }

    inline Marshaller::u1Array* getBioHeader( const unsigned char& r ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke(1, 0x4838, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_RET_U1ARRAY, &a); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getBioHeader"); return a; }

    inline unsigned char matchBio( const unsigned char& r, Marshaller::u1Array* verificationData ) { Timer t; t.start( ); unsigned char u = 0; try {  Invoke(2, 0x2D3D, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_IN_U1ARRAY, verificationData, MARSHALLER_TYPE_RET_BOOL, &u ); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::matchBio"); return u; }

    inline Marshaller::u1Array* getBioRoles( void ) { Timer t; t.start( ); Marshaller::u1Array* a = 0; try {  Invoke(0, 0xA77A, MARSHALLER_TYPE_RET_U1ARRAY, &a); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getBioRoles"); return a; }

    inline unsigned char getBioDefaultRole( void ) { Timer t; t.start( ); unsigned char u = 0; try {  Invoke(0, 0x17FD, MARSHALLER_TYPE_RET_U1, &u); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getBioDefaultRole"); return u; }

    inline std::string* getBioVerificationUIName( void ) { Timer t; t.start( ); std::string* s = 0; try {  Invoke(0, 0x7BB7, MARSHALLER_TYPE_RET_STRING, &s); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getBioVerificationUIName"); return s; }

    inline std::string* getBioEnrollmentUIName( void ) { Timer t; t.start( ); std::string* s = 0; try {  Invoke(0, 0x0D17, MARSHALLER_TYPE_RET_STRING, &s); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::getBioEnrollmentUIName"); return s; }

    SMARTCARD_TYPE getVersion( void );

private:

    inline void deauthenticateEx( const unsigned char& r ) { Timer t; t.start( ); try { Invoke(1, 0xBD7B, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_RET_VOID); } catch( Marshaller::Exception& x ) { checkException( x ); } t.stop( ">> CardModuleService::deauthenticateEx" ); }

    inline Marshaller::u1Array* authenticateEx( const unsigned char& m, const unsigned char& r, Marshaller::u1Array* p ) { /*Timer t; t.start( );*/ Marshaller::u1Array* a = 0; try {  Invoke(3, 0x5177, MARSHALLER_TYPE_IN_U1, m, MARSHALLER_TYPE_IN_U1, r, MARSHALLER_TYPE_IN_U1ARRAY, p, MARSHALLER_TYPE_RET_U1ARRAY, &a);  } catch( Marshaller::Exception& x ) { checkException( x ); } /*t.stop( ">> CardModuleService::authenticateEx");*/ return a; }

    void checkException( Marshaller::Exception & );

    SMARTCARD_TYPE m_ucSmartCardType;

    Timer m_Timer;

    PROPERTIES m_Properties;

};

#endif // __GEMALTO_CARD_MODULE_SERVICE__
