

#include "stdafx.h"
#include "platconfig.h"
#include "config.h"
#ifdef __APPLE__
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif
#include <stdexcept>
#include "cardmoduleservice.h"
#include <Except.h>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <memory>
#include "session.h"
#include "symmalgo.h"
#include "tdes.h"
#include "util.h"
#include "zlib.h"
#include "x509cert.h"
#include "attrcert.h"
#include "dataobject.h"
#include "secretkeyobject.h"
#include "transaction.h"
#include "cardcache.h"
#include "error.h"
#include "timer.h"
#include "md5.h"
#include "log.h"


#ifdef WIN32
#include "BioMan.h"
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif

// Helper functions to manage contents of cmapfile

static void CMapFileClear(u1Array & file, u1 index);
static void CMapFileSetName(u1Array & file, u1 index, string const & name);
static u1 CMapFileGetFlag(u1Array const & file, u1 index);
static void CMapFileSetFlag(u1Array & file, u1 index, u1 flag);
static u2 CMapFileGetSignSize(u1Array const & file, u1 index);
static void CMapFileSetSignSize(u1Array & file, u1 index, u2 size);
static u2 CMapFileGetExchSize(u1Array const & file, u1 index);
static void CMapFileSetExchSize(u1Array & file, u1 index, u2 size);

// software RSA specific inclusion [they would be refined once I go and re-factor RSA algo as per Cryptoki naming convention]
//#include "crypto_public.h"
//#include "cr_rsa.h"

#include "sctoken.h"

#define BITS_0_7(l)  ((BYTE)(l & 0xff))
#define BITS_8_15(l) ((BYTE)(((WORD)l & 0xff00) >> 8))

#define MAX_RETRY 2

#define CARD_PROPERTY_PIN_INFO_EX 0x87
#define CARD_PROPERTY_PIN_INFO 0x07
#define CARD_PROPERTY_EXTERNAL_PIN 0x01
#define CARD_ROLE_USER 0x01

#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)
//#define FEATURE_VERIFY_PIN_START 0x01
//#define FEATURE_VERIFY_PIN_FINISH 0x02
//#define FEATURE_MODIFY_PIN_START 0x03
//#define FEATURE_MODIFY_PIN_FINISH 0x04
//#define FEATURE_GET_KEY_PRESSED 0x05
#define FEATURE_VERIFY_PIN_DIRECT 0x06
//#define FEATURE_MODIFY_PIN_DIRECT 0x07
//#define FEATURE_MCT_READERDIRECT 0x08
//#define FEATURE_MCT_UNIVERSAL 0x09
//#define FEATURE_IFD_PIN_PROP 0x0A
//#define FEATURE_ABORT 0x0B

#define UVM_PIN_ONLY 1
#define UVM_FP_ONLY 2
#define UVM_PIN_OR_FP 3
#define UVM_PIN_AND_FP 4

#define PIN_TYPE_REGULAR 0
#define PIN_TYPE_EXTERNAL 1

#define AUTHENTICATE_ERROR 0
#define AUTHENTICATE_REGULAR 1
#define AUTHENTICATE_PINPAD 2
#define AUTHENTICATE_BIO 3


#pragma pack(push, mdnet, 1)

typedef struct PIN_VERIFY_STRUCTURE
{
   BYTE bTimerOut;                  /* timeout is seconds (00 means use default timeout) */
   BYTE bTimerOut2;                 /* timeout in seconds after first key stroke */
   BYTE bmFormatString;             /* formatting options */
   BYTE bmPINBlockString;           /* bits 7-4 bit size of PIN length in APDU,
                                    * bits 3-0 PIN block size in bytes after
                                    * justification and formatting */
   BYTE bmPINLengthFormat;          /* bits 7-5 RFU,
                                    * bit 4 set if system units are bytes, clear if
                                    * system units are bits,
                                    * bits 3-0 PIN length position in system units
                                    */
   BYTE bPINMaxExtraDigit1;         /* Max PIN size*/
   BYTE bPINMaxExtraDigit2;         /* Min PIN size*/
   BYTE bEntryValidationCondition;  /* Conditions under which PIN entry should
                                    * be considered complete */
   BYTE bNumberMessage;             /* Number of messages to display for PIN
                                    verification */
   USHORT wLangId;                  /* Language for messages */
   BYTE bMsgIndex;                  /* Message index (should be 00) */
   BYTE bTeoPrologue[3];            /* T=1 block prologue field to use (fill with 00) */
   ULONG ulDataLength;              /* length of Data to be sent to the ICC */
   BYTE abData[13];                 /* Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

#pragma pack(pop, mdnet)

// Try/catch macros for all public methods
#define TOKEN_TRY try
#define TOKEN_CATCH(rv) \
   catch(CkError & err) { rv = err.Error(); } \
   catch(PcscError & ) { rv = CKR_FUNCTION_FAILED; } \
   catch(Marshaller::Exception & exc) { rv = CkError::CheckMarshallerException(exc); } \
   catch(...) { rv = CKR_GENERAL_ERROR; } \
   if(rv==CKR_USER_NOT_LOGGED_IN || rv==CKR_PIN_INCORRECT || rv==CKR_PIN_LOCKED) \
   _roleLogged = CKU_NONE; \

namespace {
   class CardTransaction
   {
   private:
      Token * _token;

   public:
      CardTransaction(Token * token) : _token(token)
      {
         _token->CardBeginTransaction();
      }

      ~CardTransaction() throw()
      {
         try
         {
            _token->CardEndTransaction();
         }
         catch(...) {}
      }
   };
}

Token :: Token(std::string* reader) : _mscm(0),
_supportGarbageCollection(true),
_cardCache(0),
_fPinChanged(false),
_fContainerChanged(false),
_fFileChanged(false),
_version(0)
{
   //Log::begin( "Token::Token" );

   m_dwIoctlVerifyPIN = 0;

   m_sReaderName = "";
   if( NULL != reader )
   {
      m_sReaderName = (*reader).c_str( );
   }

   //Log::log( "Token::Token - new CardModuleService..." );
   std::string svcname("MSCM");
   _mscm = new CardModuleService( reader, 5, &svcname );
   //Log::log( "Token::Token - new CardModuleService ok" );

   _mscm->DoSCardTransact(false);  // Turn off transaction handling since it is performed at application level

   // Transact card
   //Log::log( "Token::Token - CardTransaction..." );
   CardTransaction ct(this);
   //Log::log( "Token::Token - CardTransaction ok" );

   //Log::log( "Token::Token - new CardCache..." );
   _cardCache = new CardCache(_mscm);
   //Log::log( "Token::Token - new CardCache ok" );

   // Get seed for RNG from card. This is the first command to
   // card. If it fails, assume the card is not a .NET card.
   try
   {
      //Log::log( "Token::Token - GetChallenge ..." );
      auto_ptr<u1Array> challange(_mscm->GetChallenge());
      //Log::log( "Token::Token - GetChallenge ok" );

      Util::SeedRandom(*challange);
   }
   catch(...)
   {
      Log::error( "Token::Token", "GetChallenge - CKR_TOKEN_NOT_RECOGNIZED" );
      throw CkError(CKR_TOKEN_NOT_RECOGNIZED);
   }

   this->_roleLogged   = CKU_NONE;

   // flush TokenInfo
   memset(&this->_tokenInfo, 0x00, sizeof(this->_tokenInfo));

   this->_tokenInfo.ulMaxSessionCount      = CK_EFFECTIVELY_INFINITE;
   this->_tokenInfo.ulSessionCount         = CK_UNAVAILABLE_INFORMATION;
   this->_tokenInfo.ulMaxRwSessionCount    = CK_EFFECTIVELY_INFINITE;
   this->_tokenInfo.ulRwSessionCount       = CK_UNAVAILABLE_INFORMATION;
   this->_tokenInfo.ulMaxPinLen            = MAX_PIN_LEN;
   this->_tokenInfo.ulMinPinLen            = MIN_PIN_LEN;

   this->_tokenInfo.ulTotalPublicMemory    = CK_UNAVAILABLE_INFORMATION;
   this->_tokenInfo.ulTotalPrivateMemory   = CK_UNAVAILABLE_INFORMATION;
   this->_tokenInfo.ulFreePrivateMemory    = CK_UNAVAILABLE_INFORMATION;
   this->_tokenInfo.ulFreePublicMemory     = CK_UNAVAILABLE_INFORMATION;

   // Version of the Card Operating system
   this->_tokenInfo.hardwareVersion.major  = 2;
   this->_tokenInfo.hardwareVersion.minor  = 0;

   // (TBD) Version of Card Module application
   // there is mess which have been created by reading it from file etc ?
   this->_tokenInfo.firmwareVersion.major  = 2;
   this->_tokenInfo.firmwareVersion.minor  = 0;

   this->_tokenInfo.flags  = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;

   // Check if the smart card is in SSO mode
   if( ( true == this->isSSO( ) ) && ( true == this->isAuthenticated( ) ) )
   {
      this->_tokenInfo.flags &= ~CKF_LOGIN_REQUIRED;
   }
   /*else
   {
   this->_tokenInfo.flags |= CKF_LOGIN_REQUIRED;
   }*/


   // Check if the CKF_PROTECTED_AUTHENTICATION_PATH flag must be raised
   m_isPinPadSupported = isPinPadSupported( );
   //m_isPinExternal = isPinExternalSupported( );
   BYTE bCardMode = UVM_PIN_ONLY;
   BYTE bTypePIN = PIN_TYPE_REGULAR;
   getCardConfiguration( bCardMode, bTypePIN );
   Log::log( "Token::Token - PIN type <%ld> (0 = regular ; 1 = external)", bTypePIN );
   Log::log( "Token::Token - Card mode <%ld> (1 = pin only ; 2 = fp only ; 3 = fp or pin ; 4 = fp and pin)", bCardMode );
   if( ( bTypePIN == PIN_TYPE_EXTERNAL ) && ( ( ( bCardMode == UVM_PIN_ONLY ) && m_isPinPadSupported ) || ( bCardMode != UVM_PIN_ONLY ) ) )
   {
      Log::log( "Token::Token - Enable CKF_PROTECTED_AUTHENTICATION_PATH" );
      this->_tokenInfo.flags  |= CKF_PROTECTED_AUTHENTICATION_PATH;
   }

   // we need to check if token is initialized or not.
   // Initialization would essentially mean that we create
   // the necessary file structure.

   // Get current value of \cardcf file
   std::string sCardcf("cardcf");

   //Log::log( "Token::Token - ReadFile ..." );
   auto_ptr<u1Array> fileData(_mscm->ReadFile(&sCardcf,0));
   //Log::log( "Token::Token - ReadFile ..." );

   if(fileData->GetLength() < 6)
   {
      Log::error( "Token::Token", " (fileData->GetLength() < 6) - CKR_TOKEN_NOT_RECOGNIZED" );
      throw CkError(CKR_TOKEN_NOT_RECOGNIZED);
   }
   CK_ULONG cardCf = LittleEndianToInt<CK_ULONG>(fileData->GetBuffer()+2);

   this->_initialized  = this->IsInitialized();

   if(_initialized)
   {
      //Log::log( "Token::Token - DeserializeTokenInfo ..." );
      this->DeserializeTokenInfo();
      //Log::log( "Token::Token - DeserializeTokenInfo ok" );
   }
   else
   {
      //Log::log( "Token::Token - PopulateDefaultTokenInfo ..." );
      // fill up the tokenInfo
      this->PopulateDefaultTokenInfo();
      //Log::log( "Token::Token - PopulateDefaultTokenInfo ok" );
   }

   // Set current values unequal to the stored to force the initial syncronization
   _cardCfTimer = 0;
   _cardCf = cardCf;
   _publCardCf = ~cardCf;
   _privCardCf = ~cardCf;
   _cacheCardCf = ~cardCf;

   //Log::end( "Token::Token" );
}

Token :: ~Token()
{
   delete _cardCache;
   delete this->_mscm;

   Clear();
}



void Token::ManageGC()
{
   if(!_supportGarbageCollection)
      return;
   try
   {
      s4 freeMemory = _mscm->GetMemory();
      if (freeMemory < 6000)
      {
         Log::log( "Token::ManageGC - ForceGarbageCollector" );
         _mscm->ForceGarbageCollector( );
      }
   }
   catch(...)
   {
      _supportGarbageCollection = false;
   }
}


void Token::Clear()
{
   for(size_t i=0;i<_objects.size();i++)
      delete _objects[i];
   _objects.clear();
}


void Token::BeginTransaction()
{
   // To improve performance, avoid checking cardcf unless there could possibly
   // have been an update by external application, based on the time it was last
   // known to be up-do-date, which means at end of previous transaction.

   static const unsigned long maximumCardCfCheckInterval = 100;  // 100 milliseconds.

   CardBeginTransaction();
   try
   {
      _fPinChanged = false;
      _fContainerChanged = false;
      _fFileChanged = false;

      unsigned long tick = CTimer::ClockTicks();

      // First check d.t possible timer wrap around every ~50 days.
      if(_cardCfTimer > tick || _cardCfTimer + maximumCardCfCheckInterval < tick)
      {
         // Read cache file.
         std::string sCardcf("cardcf");
         ManageGC( );
         auto_ptr<u1Array> fileData(_mscm->ReadFile(&sCardcf,0));
         if(fileData->GetLength() < 6)
            throw CkError(CKR_TOKEN_NOT_RECOGNIZED);

         _cardCf = LittleEndianToInt<CK_ULONG>(fileData->GetBuffer()+2);
      }

      if((_publCardCf != _cardCf) ||
         ((_privCardCf != _cardCf) && (_roleLogged == CKU_USER)))
      {
         // Card changed, so re-synchronize
         Resynchronize();
      }
   }
   catch(...)
   {
      CardEndTransaction();
      throw;
   }
}

void Token::EndTransaction( )
{
   try
   {
      // Update \cardcf if card has changed.
      if(_fPinChanged || _fContainerChanged || _fFileChanged)
      {
         //  cardcf format:
         //  typedef struct _CARD_CACHE_FILE_FORMAT
         //  {
         //      BYTE bVersion;
         //      BYTE bPinsFreshness;
         //      WORD wContainersFreshness;
         //      WORD wFilesFreshness;
         //  } CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;

         //  Read cache file.
         std::string sCardCf("cardcf");
         auto_ptr<u1Array> fileData(_mscm->ReadFile(&sCardCf,0));

         BYTE bPinsFreshness = fileData->ReadU1At(1);
         WORD wContainersFreshness = LittleEndianToInt<WORD>(fileData->GetBuffer(),2);
         WORD wFilesFreshness = LittleEndianToInt<WORD>(fileData->GetBuffer(),4);

         if(_fPinChanged)
            bPinsFreshness++;
         if(_fContainerChanged)
            wContainersFreshness++;
         if(_fFileChanged)
            wFilesFreshness++;

         fileData->SetU1At(1, bPinsFreshness);
         IntToLittleEndian<WORD>(wContainersFreshness, fileData->GetBuffer(),2);
         IntToLittleEndian<WORD>(wFilesFreshness, fileData->GetBuffer(),4);

         ManageGC( );

         // Write cache file back
         _mscm->WriteFile(&sCardCf, fileData.get());

         // As a result of own update, our own cache is still valid
         // as long as it was valid before.
         CK_ULONG newCardCf = LittleEndianToInt<CK_ULONG>(fileData->GetBuffer()+2);

         if(_publCardCf == _cardCf)
            _publCardCf = newCardCf;
         if(_privCardCf == _cardCf)
            _privCardCf = newCardCf;
         if(_cacheCardCf == _cardCf)
            _cacheCardCf = newCardCf;

         _cardCf = newCardCf;
         _cardCfTimer = CTimer::ClockTicks();
      }
      else
         _cardCfTimer = CTimer::ClockTicks();
   }
   catch( CkError x )
   {
      CK_RV rv = x.Error( );
      Log::log( "## Error ## Token::EndTransaction - WriteFile failed <%ld>\n", rv );
   }
   catch( ... )
   {
   }

   CardEndTransaction( );
}

void Token::Resynchronize()
{
   // To be called at initial creation and also whenever
   // it is detected that card has been changed.
   // When re-sync, one have to maintain the object handles
   // of the objects that have not been deleted. Therefore,
   // build a new object list and compare with the existing.

   if(_cacheCardCf != _cardCf)
   {
      _cardCache->ClearAll();
      _cacheCardCf = _cardCf;
   }

   map<int, ContainerInfo> contMap;
   BuildContainerInfoMap(contMap);

   vector<StorageObject*> newObjects;
   vector<string> toDelete;

   SynchronizePublicObjects(newObjects, toDelete, contMap);
   SynchronizeCertificates(newObjects, contMap);

   _publCardCf = _cardCf;

   if(_roleLogged == CKU_USER)
   {
      CK_RV rv = CKR_OK;
      TOKEN_TRY
      {
         SynchronizePrivateObjects(newObjects, toDelete, contMap);
         SynchronizePrivateKeys(newObjects, contMap);
         _privCardCf = _cardCf;
      }
      TOKEN_CATCH(rv);
   }

   // Build the new list with new objects occupying the
   // position as the old objects. StorageObject::IsEqual
   // is used to compare two objects.
   vector<StorageObject*> objects(_objects.size(), 0);
   for(size_t iobj = 0; iobj<_objects.size(); ++iobj)
   {
      if(!_objects[iobj])
         continue;
      for(size_t inew = 0; inew < newObjects.size(); ++inew)
      {
         if(newObjects[inew] && newObjects[inew]->IsEqual(_objects[iobj]))
         {
            // Transfer ownership
            objects[iobj] = newObjects[inew];
            newObjects[inew] = 0;
            break;
         }
      }
   }

   // Add the potential new objects, which are those left in
   // newObjects. Add them to the end of the list
   for(size_t inew = 0; inew < newObjects.size(); ++inew)
   {
      if(newObjects[inew])
         objects.push_back(newObjects[inew]);
   }

   // Delete the objects in the old object list
   for(size_t iobj = 0; iobj<_objects.size(); ++iobj)
      delete _objects[iobj];

   // Store the new list as current
   _objects = objects;

   // Store the list of files to delete, then delete these if logged in.
   _toDelete = toDelete;

   if(_roleLogged == CKU_USER)
      PerformDeferredDelete();

}

u1Array* Token::ComputeCryptogram(u1Array* challenge,u1Array* pin)
{

   // time to prepare the master key.
   // Only accept correct length, otherwise
   // return a zero valued response that is
   // sure to fail authentication.

   CK_BYTE expectedCryptogram[8];
   memset(expectedCryptogram,0x00,8);  // Default

   if(pin->GetLength() == 24)
   {
      // compute the response
      CK_BYTE iv[8];
      memset(iv,0,8);

      CTripleDES tdes;

      tdes.SetEncryptMode(ENCRYPT);
      tdes.SetIV(iv);
      tdes.SetCipherMode(CIPHER_MODE_ECB);
      tdes.SetPaddingMode(PADDING_MODE_NONE);
      tdes.SetKey(pin->GetBuffer(),24);
      tdes.TransformFinalBlock(challenge->GetBuffer(),0,8,expectedCryptogram,0);
   }
   u1Array* response = new u1Array(8);
   response->SetBuffer(expectedCryptogram);

   return response;
}

CK_RV Token::DoPINValidityChecks(u1Array* pin, bool fCheckCharaceters){

   if((pin->GetLength() < MIN_PIN_LEN) || (pin->GetLength() > MAX_PIN_LEN)){
      return CKR_PIN_LEN_RANGE;
   }

   if(fCheckCharaceters)
   {
      // check if pin is valid
      for (u4 i = 0; i < pin->GetLength(); i++){
         if ((pin->GetBuffer()[i] < 0x20) ||
            (pin->GetBuffer()[i] > 0x7D) ||
            (pin->GetBuffer()[i] == 0x24)||
            (pin->GetBuffer()[i] == 0x40)||
            (pin->GetBuffer()[i] == 0x60))
         {
            return CKR_PIN_INVALID;
         }
      }
   }
   return CKR_OK;
}

CK_RV Token::InitPIN(u1Array* soPIN,u1Array* userPIN)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      rv = Token::DoPINValidityChecks(userPIN);

      if(rv != CKR_OK){
         throw CkError(rv);
      }

      auto_ptr<u1Array> challenge(_mscm->GetChallenge());
      auto_ptr<u1Array> cryptogram(ComputeCryptogram(challenge.get(), soPIN));

      try{

         this->_mscm->ChangeReferenceData(MODE_UNBLOCK_PIN,CARD_ROLE_USER,cryptogram.get(),userPIN,MAX_USER_PIN_TRIES);
         this->RegisterPinUpdate();

         // Log in user to update token info
         this->_mscm->VerifyPin(CARD_ROLE_USER, userPIN);

         if(_initialized)
            DeserializeTokenInfo();
         else
            Initialize();

         // Save User PIN Initialized flag, the other PIN flags are not stored
         this->_tokenInfo.flags |= CKF_USER_PIN_INITIALIZED;
         SerializeTokenInfo();
         this->_mscm->LogOut(CARD_ROLE_USER);

         // Reset some User PIN flags
         this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

      }
      catch(Marshaller::RemotingException&){
         rv = CKR_TOKEN_NOT_PRESENT;
      }
      catch(Marshaller::UnauthorizedAccessException&){

         // incorrect pin
         s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_ADMIN);

         // blocked
         if(triesRemaining == 0){
            // update tokeninfo flahs
            this->_tokenInfo.flags |= CKF_SO_PIN_LOCKED;
            this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
            this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
         }else if(triesRemaining == 1){
            this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
            this->_tokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
            this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
         }else if(triesRemaining < MAX_SO_PIN_TRIES){
            this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
            this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
            this->_tokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;
         }

         rv = CKR_PIN_INCORRECT;

      }
      catch(std::runtime_error&){
         rv = CKR_DEVICE_ERROR;
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::SetPIN(u1Array* oldPIN,u1Array* newPIN)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {

      bool fCheckCharacters = (_roleLogged != CKU_SO);
      rv = Token::DoPINValidityChecks(newPIN, fCheckCharacters);

      if(rv != CKR_OK){
         throw CkError(rv);
      }

      CK_BYTE  role       = 0;
      s4 maxTries         = 0;

      auto_ptr<u1Array> oldPINTemp;
      auto_ptr<u1Array> newPINTemp;

      if(this->_roleLogged == CKU_SO){

         role = CARD_ROLE_ADMIN;
         maxTries = MAX_SO_PIN_TRIES;

         u1Array* challenge = this->_mscm->GetChallenge();

         oldPINTemp = auto_ptr<u1Array>(this->ComputeCryptogram(challenge,oldPIN));

         delete challenge;

         // new PIN has to be 24 bytes
         // if not we just pad rest of bytes as zeros
         newPINTemp = auto_ptr<u1Array>(new u1Array(24));
         memset(newPINTemp->GetBuffer(),0,24);
         memcpy(newPINTemp->GetBuffer(),newPIN->GetBuffer(),newPIN->GetLength());

      }else{

         role = CARD_ROLE_USER;
         maxTries = MAX_USER_PIN_TRIES;

         oldPINTemp = auto_ptr<u1Array>(new u1Array(oldPIN->GetLength()));
         oldPINTemp->SetBuffer(oldPIN->GetBuffer());

         newPINTemp = auto_ptr<u1Array>(new u1Array(newPIN->GetLength()));
         newPINTemp->SetBuffer(newPIN->GetBuffer());
      }

      try{
         this->_mscm->ChangeReferenceData(MODE_CHANGE_PIN,role,oldPINTemp.get(),newPINTemp.get(),maxTries);
         this->RegisterPinUpdate();
      }
      catch(Marshaller::RemotingException&){
         rv = CKR_TOKEN_NOT_PRESENT;
      }
      catch(Marshaller::UnauthorizedAccessException&){

         // incorrect pin
         s4 triesRemaining = this->_mscm->GetTriesRemaining(role);

         if(role == CARD_ROLE_ADMIN){

            // blocked
            if(triesRemaining == 0){
               // update tokeninfo flahs
               this->_tokenInfo.flags |= CKF_SO_PIN_LOCKED;
               this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
               this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
            }else if(triesRemaining == 1){
               this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
               this->_tokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
               this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
            }else if(triesRemaining < MAX_SO_PIN_TRIES){
               this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
               this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
               this->_tokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;
            }

         }else{

            // blocked
            if(triesRemaining == 0){
               // update tokeninfo flahs
               this->_tokenInfo.flags |= CKF_USER_PIN_LOCKED;
               this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
               this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
            }else if(triesRemaining == 1){
               this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
               this->_tokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
               this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
            }else if(triesRemaining < MAX_USER_PIN_TRIES){
               this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
               this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
               this->_tokenInfo.flags |= CKF_USER_PIN_COUNT_LOW;
            }
         }

         rv = triesRemaining ? CKR_PIN_INCORRECT : CKR_PIN_LOCKED;


      }
      catch(std::runtime_error&){
         rv = CKR_DEVICE_ERROR;
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::InitToken(u1Array* pin,u1Array* label)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {

      // Check that label does not contain null-characters
      PKCS11_ASSERT(label->GetLength() == 32);
      for(u4 i = 0; i<label->GetLength(); ++i)
      {
         if(!label->ReadU1At(i))
            throw CkError(CKR_ARGUMENTS_BAD);
      }

      // first check if pin is locked or not
      s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_ADMIN);

      // blocked
      if(triesRemaining == 0){
         throw CkError(CKR_PIN_LOCKED);
      }

      // Change User PIN to random
      R_RANDOM_STRUCT & randomStruc = Util::RandomStruct();
      u1Array randomPin(MAX_PIN_LEN);
      R_GenerateBytes(randomPin.GetBuffer(), MAX_PIN_LEN, &randomStruc);
      // Make a number to comply with rules in DoPINValidityChecks
      for(u4 i = 0; i < MAX_PIN_LEN; ++i)
         randomPin.SetU1At(i, '0' + randomPin.ReadU1At(i)%10);   // Not 100% random any more....

      rv = InitPIN(pin, &randomPin);
      if(rv != CKR_OK)
         throw CkError(rv);

      // actual authentication
      rv = this->AuthenticateAdmin(pin);
      if(rv != CKR_OK){
         throw CkError(rv);
      }

      // this seems strange the reason,
      // I am doing this is to use DeleteObject
      // method which expects the user to be logged
      // in
      this->_roleLogged = CKU_USER;

      // TODO: InitToken should not care to do the regular token initialization
      // in particular if it needs to clean up a token that will not load.....
      // It should delete files directly as well as containers.
      BeginTransaction();
      try
      {
         if(!_initialized)
            Initialize();

         //Log::log("Deleting all token objects....");

         // destroy all the token objects
         for(size_t t=0; t<_objects.size(); t++){
            if(this->_objects[t] != NULL_PTR){
               // what if DeleteObject has failed for any reason ?
               this->DeleteObject(CO_TOKEN_OBJECT | static_cast<CK_OBJECT_HANDLE>(t+1));
            }
         }

         // Update the token's label and flags attribute.
         // Re-fetch first to be sure _tokenInfo is valid
         DeserializeTokenInfo();
         _tokenInfo.flags |= CKF_TOKEN_INITIALIZED;
         _tokenInfo.flags &= ~CKF_USER_PIN_INITIALIZED;
         memcpy(_tokenInfo.label, label->GetBuffer(), 32);
         SerializeTokenInfo();

         _mscm->LogOut(CARD_ROLE_ADMIN);
         _roleLogged = CKU_NONE;
      }
      catch(...)
      {
         _roleLogged = CKU_NONE;
         try { _mscm->LogOut(CARD_ROLE_ADMIN); } catch(...) {}
         EndTransaction();
         throw;
      }
      EndTransaction();

   }
   TOKEN_CATCH(rv)
      return rv;
}

bool Token::IsInitialized()
{
   bool result = false;

   // the way we determine that token is not initialized
   // is to check for the existence of p11 directory in the root
   // since GetFiles() does not return directory I have base my judgement
   // on the IOException or DirectoryNotFoundException for tinfo
   std::string tinfo("p11\\tinfo");

   try{
      //ManageGC( );
      _cardCache->ReadFile(tinfo);
      result = true;
   }
   catch(...){}

   return result;

}

void Token::CreateDirIfNotPresent(std::string* /*parent*/,std::string* dir,u1Array* acls)
{

   try{
      this->_mscm->CreateDirectory(dir,acls);
   }
   catch(std::runtime_error&){
      // ignore the exception as the directory may already be present
      // TBD : May it more robust
   }
}

void Token::Initialize()
{
   PKCS11_ASSERT(!_initialized);

   std::string root("");
   std::string p11("p11");

   u1Array acls(3);
   acls.GetBuffer()[0] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // admin acl
   acls.GetBuffer()[1] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // usr acl
   acls.GetBuffer()[2] = CARD_PERMISSION_READ; // everyone acl

   // create p11 directory
   this->CreateDirIfNotPresent(&root,&p11,&acls);

   // create token info
   std::string tinfo("p11\\tinfo");
   _cardCache->ClearFileList("p11");
   this->_mscm->CreateFile(&tinfo,&acls,0);

   // Serialize default token Info
   this->SerializeTokenInfo();

   this->RegisterFileUpdate();

   this->_initialized = true;

}

void Token::ReadAndPopulateObjects(vector<StorageObject*> & objects, vector<string> & toDelete,
                                   string const & prefix, map<int, ContainerInfo> & contMap)
{

   CK_ULONG cls;

   vector<string> files(_cardCache->FileList("p11"));

   for(u4 i=0;i<files.size();i++)
   {
      std::string aFile(files[i]);

      if(aFile.find(prefix) != 0) // Must start with <prefix>
         continue;

      std::string filePath("p11\\");

      filePath.append(aFile);
      const u1Array & fileData = _cardCache->ReadFile(filePath);

      if (aFile.substr(prefix.size(), 3) == "dat")
      {
         cls = CKO_DATA;
      }
      //else if (aFile.substr(prefix.size(), 3) == "cer")
      //{
      //    cls = CKO_CERTIFICATE;
      //}
      else if (aFile.substr(prefix.size(), 3) == "kxc")
      {
         cls = CKO_CERTIFICATE;
      }
      else if (aFile.substr(prefix.size(), 3) == "ksc")
      {
         cls = CKO_CERTIFICATE;
      }
      else if (aFile.substr(prefix.size(), 3) == "puk")
      {
         cls = CKO_PUBLIC_KEY;
      }
      else if (aFile.substr(prefix.size(), 3) == "prk")
      {
         cls = CKO_PRIVATE_KEY;
      }
      else if (aFile.substr(prefix.size(), 3) == "sec")
      {
         cls = CKO_SECRET_KEY;
      }
      else
      {
         cls = CKO_VENDOR_DEFINED;
      }

      StorageObject* object = NULL_PTR;

      switch(cls){

            case CKO_DATA:
               object = new DataObject();
               break;

            case CKO_PUBLIC_KEY:
               object = new RSAPublicKeyObject();
               break;

            case CKO_PRIVATE_KEY:
               object = new RSAPrivateKeyObject();
               break;

            case CKO_SECRET_KEY:
               object = new SecretKeyObject();
               break;

            case CKO_CERTIFICATE:
               object = new X509PubKeyCertObject();
               ((X509PubKeyCertObject*)object)->_certName = aFile.substr(prefix.size(), aFile.size()-prefix.size());
               break;

            default:
               continue;
      }

      vector<u1> from;
      for(u4 u=0;u<fileData.GetLength();u++){
         from.push_back(fileData.GetBuffer()[u]);
      }

      CK_ULONG idx = 0;

      object->Deserialize(from,&idx);

      // put the fileName for the object
      // as it is not deserialized
      object->_fileName = filePath;

      bool fAddObject = true;

      // For CKO_PRIVATE_KEY and CKO_CERTIFICATE, check that the objects
      // actually exists in the container. If they don't, flag that the
      // file shall be deleted.
      if(cls == CKO_PRIVATE_KEY)
      {
         PrivateKeyObject * privKey = static_cast<PrivateKeyObject*>(object);
         map<int, ContainerInfo>::iterator icont = contMap.find(privKey->_ctrIndex);
         if(icont != contMap.end() && icont->second._cmapEntry)
         {
            KeyPair & keyPair = (privKey->_keySpec == KEYSPEC_KEYEXCHANGE) ?
               icont->second._exchKP : icont->second._signKP;
            if(keyPair._checkValue == privKey->_checkValue)
            {
               // Object exist in the container. Flag that there exists a P11 private
               // key for this key pair so that it will not be instantiated twice.
               keyPair._fP11PrivKeyExists = true;
            }
            else
               fAddObject = false;
         }
         else
            fAddObject = false;
      }
      else if(cls == CKO_CERTIFICATE)
      {
         X509PubKeyCertObject * cert = static_cast<X509PubKeyCertObject*>(object);
         map<int, ContainerInfo>::iterator icont = contMap.find(cert->_ctrIndex);
         if(icont != contMap.end() && icont->second._cmapEntry)
         {
            u1Array certValue;
            KeyPair & keyPair = (cert->_keySpec == KEYSPEC_KEYEXCHANGE) ?
               icont->second._exchKP : icont->second._signKP;

            certValue = keyPair._cert;
            if(certValue.GetLength())
            {
               u8 checkValue = 0;
               try
               {
                  X509Cert x509cert(certValue.GetBuffer(), certValue.GetLength());
                  BEROctet::Blob modulus(x509cert.Modulus());
                  checkValue = Util::MakeCheckValue(modulus.data(), static_cast<unsigned int>(modulus.size()));
                  if(cert->_checkValue == checkValue)
                  {
                     // Correct certificate! Assign the value and register it.
                     // Flag that there exists a P11 certificate object for this
                     // key pair so that it will not be instantiated twice.
                     cert->_value = new u1Array();
                     *cert->_value = certValue;
                     keyPair._fP11CertExists = true;
                  }
                  else
                     fAddObject = false;
               }
               catch(...)
               {
                  // Not valid X509 certificate, ignore it.
                  fAddObject = false;
               }
            }
            else
               fAddObject = false;
         }
         else
            fAddObject = false;
      }

      if(fAddObject)
         objects.push_back(object);
      else
      {
         delete object;
         toDelete.push_back(filePath);
      }
   }
}

void Token::SynchronizePublicObjects(vector<StorageObject*> & objects, vector<string> & toDelete, map<int, ContainerInfo> & contMap)
{
   //Log::log("Synchrnoizing Public Objects...");

   if(!_initialized){
      //Log::log("Token not initialized, hence no objects.");
      return;
   }

   ReadAndPopulateObjects(objects, toDelete, "pub", contMap);
   //ManageGC();
}

void Token::SynchronizePrivateObjects(vector<StorageObject*> & objects, vector<string> & toDelete, map<int, ContainerInfo> & contMap)
{
   //Log::log("Synchronizing Private Objects...");

   if(!_initialized){
      //Log::log("Token not initialized, hence no objects.");
      return;
   }

   ReadAndPopulateObjects(objects, toDelete, "pri", contMap);
   //ManageGC();
}

void Token::BuildContainerInfoMap(map<int, ContainerInfo> & contMap)
{
   contMap.clear();

   // Step 1: Populate map from existence of files named mscp\kxc## and mscp\ksc##
   string mscpDir("mscp");
   vector<string> mscpFiles(_cardCache->FileList(mscpDir));

   for(u4 ifile = 0; ifile < mscpFiles.size(); ++ifile)
   {
      std::string aFile(mscpFiles[ifile]);
      if(aFile.size() != 5 || aFile[0] != 'k' || aFile[2] != 'c')
         continue;

      u1 keySpec;
      if(aFile[1] == 'x')
         keySpec = KEYSPEC_KEYEXCHANGE;
      else if(aFile[1] == 's')
         keySpec = KEYSPEC_SIGNATURE;
      else
         continue;

      int ctrIndex;
      if(sscanf(aFile.substr(3, 2).c_str(), "%d", &ctrIndex) != 1)
         continue;
      if(ctrIndex <0)
         continue;

      // Read certificate file

      std::string aFilePath = mscpDir + "\\" + aFile;

      auto_ptr<u1Array> value(ReadCertificateFile(aFilePath));

      if(keySpec == KEYSPEC_SIGNATURE)
      {
         contMap[ctrIndex]._signKP._cert = *value;
         contMap[ctrIndex]._signKP._certName = aFile;
      }
      else
      {
         contMap[ctrIndex]._exchKP._cert = *value;
         contMap[ctrIndex]._exchKP._certName = aFile;
      }
   }

   // Step 2: Update map from valid cmapfile entries

   std::string nameCMapFile("mscp\\cmapfile");
   const u1Array & fileData = _cardCache->ReadFile(nameCMapFile);
   u4 contentLen = fileData.GetLength();
   s4 entries = contentLen / SIZE_CONTAINERMAPRECORD;

   vector<ContainerInfo> vContInfo;
   for(int ctrIndex = 0; ctrIndex < entries; ++ctrIndex)
   {
      if(!(CMapFileGetFlag(fileData, ctrIndex) & 0x01))
         continue;       // Skip not valid containers.

      // Valid cmapfile entry for this ctrIndex
      contMap[ctrIndex]._cmapEntry = true;

      if(CMapFileGetSignSize(fileData, ctrIndex) || CMapFileGetExchSize(fileData, ctrIndex))
      {
         // Exchange
         const CardCache::Container & cont = _cardCache->ReadContainer(ctrIndex);
         u4 modulusLength = cont.exchModulus.GetLength();
         if(modulusLength && CMapFileGetExchSize(fileData, ctrIndex) == modulusLength*8)
         {
            contMap[ctrIndex]._exchKP._modulus = cont.exchModulus;
            contMap[ctrIndex]._exchKP._publicExponent = cont.exchPublicExponent;
            contMap[ctrIndex]._exchKP._checkValue = Util::MakeCheckValue(cont.exchModulus.GetBuffer(), modulusLength);
         }

         // Signature
         modulusLength = cont.signModulus.GetLength();
         if(modulusLength && CMapFileGetSignSize(fileData, ctrIndex) == modulusLength*8)
         {
            contMap[ctrIndex]._signKP._modulus = cont.signModulus;
            contMap[ctrIndex]._signKP._publicExponent = cont.signPublicExponent;
            contMap[ctrIndex]._signKP._checkValue = Util::MakeCheckValue(cont.signModulus.GetBuffer(), modulusLength);
         }
      }
   }
}

void Token::SynchronizeCertificates(vector<StorageObject*> & objects, map<int, ContainerInfo> & contMap)
{
   //Log::log("Synchronizing  Certificates...");

   // Look for certificates in mscp that are not represented by P11 objects
   for(map<int, ContainerInfo>::const_iterator icont = contMap.begin(); icont != contMap.end(); ++icont)
   {
      if(!icont->second._cmapEntry)
         continue;   // Not corresponding to a valid cmapfile entry, ignore it.

      u1 ctrIndex = static_cast<u1>(icont->first);

      for(int ikeySpec = 0; ikeySpec < 2; ++ikeySpec)
      {
         u1 keySpec = (ikeySpec == 0) ? KEYSPEC_KEYEXCHANGE : KEYSPEC_SIGNATURE;
         const KeyPair & keyPair = (ikeySpec == 0) ? icont->second._exchKP : icont->second._signKP;

         // Certificates that have already been represented by object
         // stored under p11 directory shall not be instantiated again.
         if(keyPair._fP11CertExists)
            continue;

         if(keyPair._cert.GetLength())
         {
            if(!FindCertificate(objects, ctrIndex, keySpec))
            {
               //Log::log("Handling enrollement done from CSP...");

               u8 checkValue = 0;
               string strLabel;
               BEROctet::Blob blId;
               try
               {
                  CAttributedCertificate attrCert(keyPair._cert.GetBuffer(), keyPair._cert.GetLength());

                  strLabel = attrCert.DerivedName();
                  blId = attrCert.DerivedId();

                  BEROctet::Blob modulus(attrCert.Modulus());
                  checkValue = Util::MakeCheckValue(modulus.data(), static_cast<unsigned int>(modulus.size()));
               }
               catch(...)
               {
                  // Not valid X509 certificate, ignore it
                  continue;
               }

               X509PubKeyCertObject* cert = new X509PubKeyCertObject();
               cert->_value = new u1Array();
               *cert->_value = keyPair._cert;
               cert->_checkValue = checkValue;
               cert->_certName = keyPair._certName;
               cert->_keySpec = keySpec;
               cert->_ctrIndex = ctrIndex;

               cert->_tokenObject = CK_TRUE;
               cert->_private = CK_FALSE;

               cert->_label = new u1Array(static_cast<s4>(strLabel.size()));
               cert->_label->SetBuffer(reinterpret_cast<const u1*>(strLabel.c_str()));

               // If there is already a corresponding private key, assign
               // the same id attribute, otherwise use the one derived from cert.
               RSAPrivateKeyObject * priv = static_cast<RSAPrivateKeyObject*>(FindPrivateKey(objects, ctrIndex, keySpec));
               if(priv && priv->_id->GetLength())
               {
                  cert->_id = new u1Array();
                  *cert->_id = *priv->_id;
               }
               else
               {
                  cert->_id = new u1Array(static_cast<s4>(blId.size()));
                  cert->_id->SetBuffer(reinterpret_cast<const u1*>(blId.c_str()));
               }

               // prepare object attributes from the parsed certificate
               this->PrepareCertAttributesFromRawData(cert);

               // Register this object
               objects.push_back(cert);
            }
         }
      }
   }
}

void Token::SynchronizePrivateKeys(vector<StorageObject*> & objects, map<int, ContainerInfo> & contMap)
{
   //Log::log("Synchronizing  Private Keys...");

   // Look for private keys in cmapfile that are not represented by P11 objects
   for(map<int, ContainerInfo>::const_iterator icont = contMap.begin(); icont != contMap.end(); ++icont)
   {
      if(!icont->second._cmapEntry)
         continue;   // Not corresponding to a valid cmapfile entry, ignore it.

      u1 ctrIndex = static_cast<u1>(icont->first);

      for(int ikeySpec = 0; ikeySpec < 2; ++ikeySpec)
      {
         u1 keySpec = (ikeySpec == 0) ? KEYSPEC_KEYEXCHANGE : KEYSPEC_SIGNATURE;
         const KeyPair & keyPair = (ikeySpec == 0) ? icont->second._exchKP :  icont->second._signKP;

         // Private keys that have already been represented by object
         // stored under p11 directory shall not be instantiated again.
         if(keyPair._fP11PrivKeyExists)
            continue;

         if(keyPair._checkValue)
         {
            if(!FindPrivateKey(objects, ctrIndex, keySpec))
            {
               //Log::log("Handling enrollement done from CSP...");

               RSAPrivateKeyObject* priv = new RSAPrivateKeyObject();

               // If there is a corresponding certificate, use its label, id and subject attribute

               // TODO: Should check type before cast, however since there
               // are no other certificate types than X509 here, this is safe
               X509PubKeyCertObject * cert = static_cast<X509PubKeyCertObject*>(FindCertificate(objects, ctrIndex, keySpec));
               if(cert)
               {
                  // If cert exist, inherit label and id from cert
                  priv->_label = new u1Array();
                  *priv->_label = *cert->_label;
                  priv->_id = new u1Array();
                  *priv->_id = *cert->_id;
                  priv->_subject = new u1Array();
                  *priv->_subject = *cert->_subject;
               }
               else
               {
                  BEROctet::Blob blId(CAttributedCertificate::DerivedId(keyPair._modulus.GetBuffer(),
                     keyPair._modulus.GetLength()));
                  priv->_id = new u1Array(static_cast<s4>(blId.size()));
                  priv->_id->SetBuffer(blId.c_str());
               }

               priv->_ctrIndex = ctrIndex;
               priv->_keySpec  = keySpec;
               priv->_tokenObject = CK_TRUE;
               priv->_private = CK_TRUE;
               priv->_decrypt = CK_TRUE;
               priv->_unwrap = CK_TRUE;
               priv->_derive = CK_FALSE;
               priv->_sign = CK_TRUE;
               priv->_signRecover = CK_FALSE;
               priv->_publicExponent = new u1Array();
               *priv->_publicExponent = keyPair._publicExponent;
               priv->_modulus = new u1Array();
               *priv->_modulus = keyPair._modulus;
               priv->_checkValue = keyPair._checkValue;

               // add this in the token object list
               objects.push_back(priv);
            }
         }
      }
   }
}

void Token::PrepareCertAttributesFromRawData(X509PubKeyCertObject* certObject)
{

   u1*           pCertValue = NULL;
   unsigned long dwCertLen = 0;
   u1Array*      sernbP = NULL;
   u1Array*      issuerP = NULL;
   u1Array*      subjectP = NULL;

   pCertValue = certObject->_value->GetBuffer();
   dwCertLen  = certObject->_value->GetLength();

   // Parse Certifcate to extract SerNB, Issuer & Subject
   // Create check value from modulus

   try {
      X509Cert x509cert(pCertValue, dwCertLen);

      BEROctet::Blob blSerNum(x509cert.SerialNumber());
      BEROctet::Blob blIssuer(x509cert.Issuer());
      BEROctet::Blob blSubject(x509cert.Subject());
      BEROctet::Blob modulus(x509cert.Modulus());

      sernbP   = new u1Array(static_cast<s4>(blSerNum.size()));
      sernbP->SetBuffer(const_cast<u1*>(blSerNum.data()));

      issuerP  = new u1Array(static_cast<s4>(blIssuer.size()));
      issuerP->SetBuffer(const_cast<u1*>(blIssuer.data()));

      subjectP = new u1Array(static_cast<s4>(blSubject.size()));
      subjectP->SetBuffer(const_cast<u1*>(blSubject.data()));

      certObject->_serialNumber = sernbP;
      certObject->_issuer       = issuerP;
      certObject->_subject      = subjectP;
   }
   catch(...) {} // On parse error, these attributes can't be set.

}


CK_RV Token::AuthenticateUser(Marshaller::u1Array *pin)
{
   CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

   try
   {
      // first check if pin is locked or not
      s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_USER);

      // blocked
      if(triesRemaining == 0)
      {
         // update tokeninfo flahs
         this->_tokenInfo.flags |= CKF_USER_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;

         return CKR_PIN_LOCKED;
      }

      int iCase = howToAuthenticate( pin->GetLength( ) );
      switch( iCase )
      {
      case AUTHENTICATE_REGULAR:
         Log::log( "Token::AuthenticateUser - Normal login" );
         this->_mscm->VerifyPin( CARD_ROLE_USER, pin );
         rv = CKR_OK;
         break;

      case AUTHENTICATE_PINPAD:
         Log::log( "Token::AuthenticateUser - PinPad" );
         rv = verifyPinWithPinPad( );
         break;

      case AUTHENTICATE_BIO:
#ifdef WIN32
         Log::log( "Token::AuthenticateUser - BIO" );
         rv = verifyPinWithBio( /*pin*/ );
#else
      Log::log( "Token::AuthenticateUser - BIO not supported !!" );
      rv = CKR_FUNCTION_NOT_SUPPORTED;
#endif
         break;

      default:
         Log::log( "Token::AuthenticateUser - Unknown !!" );
         rv = CKR_FUNCTION_NOT_SUPPORTED;
         break;
      }
   }
   catch(Marshaller::RemotingException&)
   {
      rv = CKR_TOKEN_NOT_PRESENT;
   }
   catch(Marshaller::UnauthorizedAccessException&)
   {
      rv = CKR_PIN_INCORRECT;
   }
   catch(std::runtime_error&)
   {
      rv = CKR_DEVICE_ERROR;
   }

   if( CKR_OK == rv )
   {
      this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
      this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
      this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
      this->_roleLogged = CKU_USER;
   }
   else
   {
      // incorrect pin
      s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_USER);

      // blocked
      if(triesRemaining == 0)
      {
         // update tokeninfo flahs
         this->_tokenInfo.flags |= CKF_USER_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
      }
      else if(triesRemaining == 1)
      {
         this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
         this->_tokenInfo.flags |= CKF_USER_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
      }
      else if(triesRemaining < MAX_USER_PIN_TRIES)
      {
         this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
         this->_tokenInfo.flags |= CKF_USER_PIN_COUNT_LOW;
      }
   }

   return rv;
}


/*
*/
BYTE Token::howToAuthenticate( BYTE bPinLen )
{
   BYTE bRet = AUTHENTICATE_REGULAR;

   // Get the card mode (1=PIN, 2=FingerPrint, 3=PIN or FP, 4=PIN and FP)
   // The default mode is PIN
   BYTE bCardMode = UVM_PIN_ONLY;
   BYTE bTypePIN = PIN_TYPE_REGULAR;
   getCardConfiguration( bCardMode, bTypePIN );
   Log::log( "Token::AuthenticateUser - PIN type <%ld> (0 = regular ; 1 = external)", bTypePIN );
   Log::log( "Token::AuthenticateUser - Card mode <%ld> (1 = pin only ; 2 = fp only ; 3 = fp or pin ; 4 = fp and pin)", bCardMode );
   Log::log( "Token::AuthenticateUser - PIN len <%ld>", bPinLen );

   if( PIN_TYPE_EXTERNAL == bTypePIN )
   {
      if( UVM_PIN_ONLY == bCardMode )
      {
         if( true == m_isPinPadSupported )
         {
            if( 0 == bPinLen )
            {
               Log::log( "Token::AuthenticateUser - External PIN && UVM1 && PINpad support && null len -> PIN pad" );
               bRet = AUTHENTICATE_PINPAD;
            }
            else
            {
               Log::log( "Token::AuthenticateUser - External PIN && UVM1 && PINpad support && valid len -> PIN normal" );
               bRet = AUTHENTICATE_REGULAR;
            }
         }
         else
         {
            Log::log( "Token::AuthenticateUser - External PIN && UVM1 && NO PINpad support -> ERROR !!!" );
            bRet = AUTHENTICATE_ERROR;
         }
      }
      else
      {
         Log::log( "Token::AuthenticateUser - External PIN && (UVM2 || UVM3 || UVM4) -> Bio" );
         bRet = AUTHENTICATE_BIO;
      }
   }
   else
   {
      if( ( 0 != bPinLen ) && ( ( UVM_PIN_ONLY == bCardMode ) || ( UVM_PIN_OR_FP == bCardMode ) ) )
      {
         Log::log( "Token::AuthenticateUser - Regular PIN && (UVM1 || UVM3)  && valid len -> PIN normal" );
         bRet = AUTHENTICATE_REGULAR;
      }
      else
      {
         Log::log( "Token::AuthenticateUser - Regular PIN && (UVM2 || UVM4)  && NO valid len -> ERROR !!!" );
         bRet = AUTHENTICATE_ERROR;
      }
   }

   return bRet;
}


CK_RV Token::AuthenticateAdmin(Marshaller::u1Array *pin)
{
   //Log::log("Logging as Admin...");

   CK_RV rv = CKR_OK;

   u1Array* challenge = NULL_PTR;
   u1Array* response = NULL_PTR;

   try{

      // first check if pin is locked or not
      s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_ADMIN);

      // blocked
      if(triesRemaining == 0){
         // update tokeninfo flahs
         this->_tokenInfo.flags |= CKF_SO_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;

         return CKR_PIN_LOCKED;
      }

      challenge = this->_mscm->GetChallenge();

      response = this->ComputeCryptogram(challenge,pin);

      this->_mscm->ExternalAuthenticate(response);

      this->_roleLogged = CKU_SO;
   }
   catch(Marshaller::RemotingException&){
      rv = CKR_TOKEN_NOT_PRESENT;
   }
   catch(Marshaller::UnauthorizedAccessException&){

      // incorrect pin
      s4 triesRemaining = this->_mscm->GetTriesRemaining(CARD_ROLE_ADMIN);

      // blocked
      if(triesRemaining == 0){
         // update tokeninfo flahs
         this->_tokenInfo.flags |= CKF_SO_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
      }else if(triesRemaining == 1){
         this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
         this->_tokenInfo.flags |= CKF_SO_PIN_FINAL_TRY;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_COUNT_LOW;
      }else if(triesRemaining < MAX_SO_PIN_TRIES){
         this->_tokenInfo.flags &= ~CKF_SO_PIN_LOCKED;
         this->_tokenInfo.flags &= ~CKF_SO_PIN_FINAL_TRY;
         this->_tokenInfo.flags |= CKF_SO_PIN_COUNT_LOW;
      }

      return CKR_PIN_INCORRECT;

   }
   catch(std::runtime_error&)
   {
      rv = CKR_DEVICE_ERROR;
   }

   if(challenge != NULL_PTR)
      delete challenge;

   if(response != NULL_PTR)
      delete response;

   return rv;
}

CK_RV Token::Logout()
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {

      if(this->_roleLogged == CKU_NONE)
      {
         throw CkError(CKR_USER_NOT_LOGGED_IN);
      }

      u1 role = (this->_roleLogged == CKU_USER) ? CARD_ROLE_USER : CARD_ROLE_ADMIN;

      try
      {
         // For the user
         if( CARD_ROLE_USER == role )
         {
            // We log out if the SSO mode is not activated
            if( false == isSSO( ) )
            {
               this->_mscm->LogOut( role );
            }
         }
         // For the admin
         else
         {
            // We always log out
            this->_mscm->LogOut( role );
         }

         this->_roleLogged = CKU_NONE;
      }
      catch(Marshaller::RemotingException&)
      {
         rv = CKR_TOKEN_NOT_PRESENT;
      }
      catch(std::runtime_error&)
      {
         rv = CKR_DEVICE_ERROR;
      }

   }
   TOKEN_CATCH(rv)

      return rv;
}

CK_RV Token::Login(CK_ULONG userType,u1Array* pin)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      if(userType == CKU_USER){
         if((this->_tokenInfo.flags & CKF_USER_PIN_INITIALIZED) != CKF_USER_PIN_INITIALIZED){
            throw CkError(CKR_USER_PIN_NOT_INITIALIZED);
         }

         if(this->_roleLogged == CKU_SO){
            throw CkError(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
         }else if(this->_roleLogged == CKU_USER){
            throw CkError(CKR_USER_ALREADY_LOGGED_IN);
         }

         rv =  AuthenticateUser(pin);

      }else if(userType == CKU_SO){

         if(this->_roleLogged == CKU_SO){
            throw CkError(CKR_USER_ALREADY_LOGGED_IN);
         }else if(this->_roleLogged == CKU_USER){
            throw CkError(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
         }

         rv = AuthenticateAdmin(pin);
      }
      else
         rv = CKR_USER_TYPE_INVALID;
   }
   TOKEN_CATCH(rv)
      return rv;
}


/* SerializeTokenInfo
*/
void Token::SerializeTokenInfo()
{

   vector<u1> dataToSerialize;

   // Version
   Util::PushBBoolInVector(&dataToSerialize, _version);

   // label
   u1Array* label = new u1Array(32);
   label->SetBuffer(this->_tokenInfo.label);
   Util::PushByteArrayInVector(&dataToSerialize,label);
   delete label;

   // manufacturerId
   u1Array* manuId = new u1Array(32);
   manuId->SetBuffer(this->_tokenInfo.manufacturerID);
   Util::PushByteArrayInVector(&dataToSerialize,manuId);
   delete manuId;

   // model
   u1Array* model = new u1Array(16);
   model->SetBuffer(this->_tokenInfo.model);
   Util::PushByteArrayInVector(&dataToSerialize,model);
   delete model;

   // serial Number
   u1Array* serialNumber = new u1Array(16);
   serialNumber->SetBuffer(this->_tokenInfo.serialNumber);
   Util::PushByteArrayInVector(&dataToSerialize,serialNumber);
   delete serialNumber;

   // rest of the tokenInfo struct (flags)
   CK_FLAGS flags;

   flags = this->_tokenInfo.flags;
   flags &= ~CKF_PROTECTED_AUTHENTICATION_PATH;

   Util::PushULongInVector(&dataToSerialize, flags);

   std::string tinfo("p11\\tinfo");

   u1Array objData((s4)dataToSerialize.size());

   for(u4 i=0;i<dataToSerialize.size();i++){
      objData.SetU1At(i,dataToSerialize.at(i));
   }

   //ManageGC( );

   try
   {
      _cardCache->WriteFile(tinfo,objData);
      RegisterFileUpdate();
   }
   catch( CkError x )
   {
      CK_RV rv = x.Error( );
      Log::log( "## Error ## Token::SerializeTokenInfo - WriteFile failed <%ld>\n", rv );
      throw;
   }
}

void Token::DeserializeTokenInfo()
{
   std::string tinfo("p11\\tinfo");

   const u1Array & fileData = this->_cardCache->ReadFile(tinfo);

   vector<u1> from;
   for(u4 u=0;u<fileData.GetLength();u++){
      from.push_back(fileData.GetBuffer()[u]);
   }

   CK_ULONG idx = 0;

   // Format version. Shall be 0 for this version
   _version = Util::ReadBBoolFromVector(from,&idx);

   // label
   u1Array* label = Util::ReadByteArrayFromVector(from,&idx);
   memcpy(this->_tokenInfo.label,label->GetBuffer(),label->GetLength());
   delete label;

   // manuid
   u1Array* manuId = Util::ReadByteArrayFromVector(from,&idx);
   memcpy(this->_tokenInfo.manufacturerID,manuId->GetBuffer(),manuId->GetLength());
   delete manuId;

   // model
   u1Array* model = Util::ReadByteArrayFromVector(from,&idx);
   memcpy(this->_tokenInfo.model,model->GetBuffer(),model->GetLength());
   delete model;

   // serial number
   u1Array* serialNum = Util::ReadByteArrayFromVector(from,&idx);
   memcpy(this->_tokenInfo.serialNumber,serialNum->GetBuffer(),serialNum->GetLength());
   delete serialNum;

   // Check MSCM's serial number. If this is larger than 8 bytes, do not
   // use stored value since serial number may already have been truncated
   // if the card was P11 enabled prior to this fix in revision 548361.
   auto_ptr<u1Array> serialNumber(_mscm->get_SerialNumber());
   if(serialNumber->GetLength() > 8)
   {
      CMD5 md5;
      CK_BYTE hash[16];
      md5.HashCore(serialNumber->GetBuffer(), 0, serialNumber->GetLength());
      md5.HashFinal(hash);
      Util::ConvAscii(hash, 8, _tokenInfo.serialNumber);
   }

   // flags
   CK_FLAGS flags;

   flags = this->_tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH;

   this->_tokenInfo.flags = Util::ReadULongFromVector(from,&idx);

   this->_tokenInfo.flags |= flags;
}

void Token::PopulateDefaultTokenInfo()
{
   CK_ULONG idx;

   // initialize the token information

   this->_version = 0;

   for(idx=0;idx<32;idx++){
      this->_tokenInfo.label[idx] = ' ';
   }

   this->_tokenInfo.label[0] = 'C';
   this->_tokenInfo.label[1] = 'F';
   this->_tokenInfo.label[2] = '.';
   this->_tokenInfo.label[3] = 'N';
   this->_tokenInfo.label[4] = 'E';
   this->_tokenInfo.label[5] = 'T';
   this->_tokenInfo.label[6] = ' ';
   this->_tokenInfo.label[7] = 'P';
   this->_tokenInfo.label[8] = '1';
   this->_tokenInfo.label[9] = '1';

   this->_tokenInfo.manufacturerID[0] = 'G';
   this->_tokenInfo.manufacturerID[1] = 'e';
   this->_tokenInfo.manufacturerID[2] = 'm';
   this->_tokenInfo.manufacturerID[3] = 'a';
   this->_tokenInfo.manufacturerID[4] = 'l';
   this->_tokenInfo.manufacturerID[5] = 't';
   this->_tokenInfo.manufacturerID[6] = 'o';

   for(idx=7;idx<32;idx++){
      this->_tokenInfo.manufacturerID[idx] = ' ';
   }

   this->_tokenInfo.model[0] = '.';
   this->_tokenInfo.model[1] = 'N';
   this->_tokenInfo.model[2] = 'E';
   this->_tokenInfo.model[3] = 'T';
   this->_tokenInfo.model[4] = ' ';
   this->_tokenInfo.model[5] = 'C';
   this->_tokenInfo.model[6] = 'a';
   this->_tokenInfo.model[7] = 'r';
   this->_tokenInfo.model[8] = 'd';

   for(idx=9;idx<16;idx++){
      this->_tokenInfo.model[idx] = ' ';
   }

   for(idx=0;idx<16;idx++){
      this->_tokenInfo.serialNumber[idx] = ' ';
   }

   // If serial number length is too big to fit in 16 (hex) digit field,
   // then use the 8 first bytes of MD5 hash of the original serial number.
   auto_ptr<u1Array> serialNumber(_mscm->get_SerialNumber());
   if(serialNumber->GetLength() > 8)
   {
      CMD5 md5;
      CK_BYTE hash[16];
      md5.HashCore(serialNumber->GetBuffer(), 0, serialNumber->GetLength());
      md5.HashFinal(hash);
      Util::ConvAscii(hash, 8, _tokenInfo.serialNumber);
   }
   else
      Util::ConvAscii(serialNumber->GetBuffer(),serialNumber->GetLength(),this->_tokenInfo.serialNumber);

}

CK_RV Token::GenerateRandom(CK_BYTE_PTR randomData,CK_ULONG len)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      // usng the challenge as the random data
      u1Array* random = NULL_PTR;

      random = this->_mscm->GetChallenge();

      // now requested length can be more or less than the
      // 8 bytes which challenge generates.
      CK_ULONG minLen = len < 8 ? len : 8;
      memcpy(randomData,random->GetBuffer(),minLen);

      // lets put soft ramdom as the rest of the bytes
      unsigned int uSeed;

      memcpy((BYTE *)&uSeed, random->GetBuffer(), sizeof(unsigned int));
      srand(uSeed);

      if(len > 8)
      {
         for(u4 i=8;i<len;i++)
         {
            randomData[i] = (BYTE)(rand() % RAND_MAX);
         }
      }

      delete random;
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_ULONG Token::FindObjects(Session* session,CK_OBJECT_HANDLE_PTR phObject,
                            CK_ULONG ulMaxObjectCount,CK_ULONG_PTR  pulObjectCount)
{
   CK_RV rv = CKR_OK;
   CK_ULONG idx = 0;
   TOKEN_TRY
   {

      for(s4 i=0;(i < static_cast<s4>(_objects.size())) && (idx < ulMaxObjectCount);i++){

         if(this->_objects[i] == NULL_PTR){
            continue;
         }

         if(session->_tokenObjectsReturnedInSearch[i+1]){
            continue;
         }

         if((this->_objects[i]->_private == CK_TRUE) &&
            (this->_roleLogged != CKU_USER))
         {
            continue;
         }

         if(session->_searchTempl == NULL_PTR){
            phObject[idx++] = CO_TOKEN_OBJECT | (i+1);
            *pulObjectCount = *pulObjectCount + 1;
            session->_tokenObjectsReturnedInSearch[i+1] = true;
         }
         else{
            CK_BBOOL match = CK_TRUE;

            vector<CK_ATTRIBUTE> attributes = session->_searchTempl->_attributes;
            for(CK_ULONG a=0;a<attributes.size();a++){
               if(this->_objects[i]->Compare(attributes.at(a)) == CK_FALSE){
                  match = CK_FALSE;
                  break;
               }
            }

            if(match == CK_TRUE){
               phObject[idx++] = CO_TOKEN_OBJECT | (i+1);
               *pulObjectCount = *pulObjectCount + 1;
               session->_tokenObjectsReturnedInSearch[i+1] = true;
            }
         }
      }
   }
   TOKEN_CATCH(rv)
      return idx;
}


string Token::FindFreeFileName(StorageObject* object)
{
   std::string fileName(object->_private ? "pri" : "pub");

   switch(object->_class){
        case CKO_DATA:
           fileName.append("dat");
           break;

        case CKO_PUBLIC_KEY:
           fileName.append("puk");
           break;

        case CKO_PRIVATE_KEY:
           fileName.append("prk");
           break;

        case CKO_CERTIFICATE:
           fileName.append(((X509PubKeyCertObject*)object)->_certName);
           break;

        case CKO_SECRET_KEY:
           fileName.append("sec");
           break;

        default:
           throw CkError(CKR_FUNCTION_FAILED);
   }

   if(object->_class != CKO_CERTIFICATE)
   {


      // Find free name
      map<CK_LONG, bool> occupied;

      if(_initialized)
      {
         // get the file names in above dir
         vector<string> files(_cardCache->FileList("p11"));

         for(u4 i=0;i<files.size();i++)
         {
            std::string fn(files[i]);
            if(fn.find(fileName) == 0)
            {
               CK_LONG idx = atoi(fn.substr(fileName.size(), 2).c_str());
               occupied[idx] = true;
            }
         }
      }

      s4 i = 0;
      while(occupied.find(i) != occupied.end())
         i++;
      fileName.append(Util::MakeIntString(i, 2));
   }

   return fileName;

}


/* WriteObject
*/
CK_RV Token::WriteObject( StorageObject* object )
{
   //ManageGC( );

   CK_RV rv = CKR_OK;

   std::string fileName( "p11\\" + FindFreeFileName( object ) );

   // This object is stored under p11 directory, assign a unique ID for future identification.
   object->_uniqueId = Util::MakeUniqueId( );

   vector<u1> to;
   object->Serialize( &to );

   u1Array objData( (s4)to.size( ) );
   for( u4 i = 0 ; i < to.size( ) ; i++ )
   {
      objData.SetU1At( i, to.at( i ) );
   }

   u1Array acls( 3 );
   acls.GetBuffer( )[ 0 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // admin acl
   acls.GetBuffer( )[ 1 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // usr acl

   if( object->_private )
   {
      acls.GetBuffer( )[ 2 ] = 0; // everyone acl
   }
   else
   {
      // public objects can be written or read by everyone provide the session is correct

      // NOTE: Breaking PKCS#11 Compliance
      // In the card you can not create public objects unless you are logged in
      // even for R/W Pulblic session

      acls.GetBuffer( )[ 2 ] = CARD_PERMISSION_READ; // everyone acl
   }

   if( !_initialized )
   {
      Initialize( );
   }

   _cardCache->ClearFileList( "p11" );

   // No try/catch. It is managed by the calling method.
   //ManageGC( );
   this->_mscm->CreateFile( &fileName, &acls, 0 );

   try
   {
      //ManageGC( );
      this->_cardCache->WriteFile( fileName, objData );

      RegisterFileUpdate( );
      object->_fileName = fileName;
   }
   catch( CkError x )
   {
      rv = x.Error( );
      Log::log( "## ERROR ## Token::WriteObject - WriteFile failed <%ld>\n", rv );
   }

   if( CKR_OK != rv )
   {
      try
      {
         _mscm->DeleteFile( &fileName );
      }
      catch( ... )
      {
         Log::log( "## ERROR ## Token::WriteObject - DeleteFile failed\n" );
      }
   }

   return rv;
}


CK_RV Token::AddObject(auto_ptr<StorageObject> & stobj, CK_OBJECT_HANDLE_PTR phObject)
{
   //ManageGC();

   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      // from the class field we will be able to determine proper type
      // and hence the corresponding file
      //CheckAvailableSpace( );

      CK_RV rv = WriteObject(stobj.get());
      if(rv == CKR_OK)
      {
         *phObject = CO_TOKEN_OBJECT | RegisterStorageObject(stobj.get());
         stobj.release();
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}


/* AddPrivateKeyObject
*/
CK_RV Token::AddPrivateKeyObject( auto_ptr< StorageObject > &stobj, CK_OBJECT_HANDLE_PTR phObject )
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      RSAPrivateKeyObject *object = static_cast< RSAPrivateKeyObject* >( stobj.get( ) );
      if( !object->_private )
      {
         throw CkError( CKR_ATTRIBUTE_VALUE_INVALID );
      }

      // Public key modulus is mandatory, so unless provided by the template,
      // see if there is a public key with matching CKA_ID. Otherwise return
      // CKR_TEMPLATE_INCOMPLETE.

      RSAPublicKeyObject* rsaPub = NULL_PTR;
      if( !object->_modulus )
      {
         // Search for corresponding public key to make criteria that is used here is to match the CKA_ID
         CK_BBOOL foundPub = CK_FALSE;
         for( s4 i = 0 ; i < static_cast< s4 >( _objects.size( ) ) ; i++ )
         {
            if( this->_objects[ i ] != NULL_PTR )
            {
               if( this->_objects[ i ]->_class == CKO_PUBLIC_KEY )
               {
                  rsaPub = (RSAPublicKeyObject*)this->_objects[ i ];
                  foundPub = Util::CompareByteArrays( rsaPub->_id->GetBuffer( ), object->_id->GetBuffer( ), rsaPub->_id->GetLength( ) );
                  if( foundPub == CK_TRUE )
                  {
                     break;
                  }
               }
            }
         }

         if( !foundPub )
         {
            throw CkError(CKR_TEMPLATE_INCOMPLETE); // Sorry, now other choice...
         }
      }

      u1Array publExp;
      u4 modLength = 0;
      if( object->_modulus != NULL_PTR )
      {
         publExp = *object->_publicExponent;
         modLength = object->_modulus->GetLength( );
         object->_checkValue = Util::MakeCheckValue( object->_modulus->GetBuffer( ), modLength );
      }
      else
      {
         PKCS11_ASSERT( rsaPub );
         publExp = *rsaPub->_exponent;
         modLength = rsaPub->_modulus->GetLength();
         object->_checkValue = Util::MakeCheckValue(rsaPub->_modulus->GetBuffer(), modLength);
      }
      if(publExp.GetLength() < 1 || publExp.GetLength() > 4)
         throw CkError(CKR_ATTRIBUTE_VALUE_INVALID);

      if( (modLength*8 < RSA_KEY_MIN_LENGTH) ||
         (modLength*8 > RSA_KEY_MAX_LENGTH) )
         throw CkError(CKR_ATTRIBUTE_VALUE_INVALID);

      if(publExp.GetLength() < 4)
      {
         // Pad with zeros in the front since big endian
         u1Array exp(4);
         memset(exp.GetBuffer(), 0, exp.GetLength());
         size_t i = 4 - publExp.GetLength();
         memcpy(exp.GetBuffer()+i, publExp.GetBuffer(), publExp.GetLength());
         publExp = exp;
      }

      // Look for existing matching certificate
      // First, read the container map record file
      std::string  nameCMapFile("mscp\\cmapfile");
      const u1Array & fileData(_cardCache->ReadFile(nameCMapFile));

      object->_keySpec = KEYSPEC_KEYEXCHANGE;   // Default

      // NOTE: If it finds a matching certificate, the keySpec
      // will be modified to match that of the certificate.
      CK_BYTE ctrIdx = GetContainerForPrivateKey(fileData, object->_checkValue, &object->_keySpec);
      if(ctrIdx > 99)
      {
         Log::error( "Token::AddPrivateKeyObject", "ctrIdx > 99 - Return CKR_DEVICE_MEMORY" );
         throw CkError(CKR_DEVICE_MEMORY);
      }
      object->_ctrIndex = ctrIdx;

      auto_ptr<u1Array> keyValue;

      //
      /*
      if( object->_modulus->GetLength( ) != object->_d->GetLength( ) )
      {
      }
      if( ( object->_modulus->GetLength( ) / 2 ) != object->_p->GetLength( ) )
      {
      }
      if( ( object->_modulus->GetLength( ) / 2 ) != object->_q->GetLength( ) )
      {
      }
      if( ( object->_modulus->GetLength( ) / 2 ) != object->_dp->GetLength( ) )
      {
      }
      if( ( object->_modulus->GetLength( ) / 2 ) != object->_dq->GetLength( ) )
      {
      }
      */
      if( ( object->_modulus->GetLength( ) / 2 ) != object->_inverseQ->GetLength( ) )
      {
         // Pad with zeros in the front since big endian
         u1Array val( (s4)( object->_modulus->GetLength( ) / 2 ) );
         memset( val.GetBuffer( ), 0, val.GetLength( ) );
         size_t i = val.GetLength( )- object->_inverseQ->GetLength( );
         memcpy( val.GetBuffer( ) + i, object->_inverseQ->GetBuffer(), object->_inverseQ->GetLength( ) );
         *(object->_inverseQ) = val;
         /*
         // Create a new buffer with the a correct size
         u1Array val( (s4)( object->_modulus->GetLength( ) / 2 ) );
         //auto_ptr<u1Array> val = auto_ptr<u1Array>(new u1Array(keyLength));

         // Fill the buffer with zero
         for( size_t i = 0; i < val.GetLength( ) ; i++ )
         {
         val.SetU1At( i, 0 );
         }

         // Fill the buffer with the old value
         u4 j = 0;
         for( size_t i = ( val.GetLength( )- object->_inverseQ->GetLength( ) ) ; i < object->_inverseQ->GetLength( ) ; i++ )
         {
         val.SetU1At( i, object->_inverseQ->ReadU1At( j ) );
         j++;
         }

         object->_inverseQ = &val;
         */
      }

      // compute the total length;
      s4 keyLength = object->_p->GetLength() +
         object->_q->GetLength() +
         object->_inverseQ->GetLength() +
         object->_dp->GetLength() +
         object->_dq->GetLength() +
         object->_d->GetLength();

      if(object->_modulus != NULL_PTR){
         keyLength += object->_modulus->GetLength();
         //keyLength += object->_publicExponent->GetLength();
         keyLength += 4; // public exponent expected by card is on 4 bytes
      }else{
         keyLength += rsaPub->_modulus->GetLength();
         //keyLength += rsaPub->_exponent->GetLength();
         keyLength += 4; // public exponent expected by card is on 4 bytes
      }

      s4 offset = 0;

      // Prepare the keyValue
      keyValue = auto_ptr<u1Array>(new u1Array(keyLength));
      memset(keyValue->GetBuffer(),0,keyValue->GetLength()); // let's zeroed it

      memcpy(keyValue->GetBuffer(),object->_p->GetBuffer(),object->_p->GetLength());

      offset += object->_p->GetLength();

      memcpy((u1*)&keyValue->GetBuffer()[offset],object->_q->GetBuffer(),object->_q->GetLength());

      offset += object->_q->GetLength();

      memcpy((u1*)&keyValue->GetBuffer()[offset],object->_inverseQ->GetBuffer(),object->_inverseQ->GetLength());

      offset += object->_inverseQ->GetLength();

      memcpy((u1*)&keyValue->GetBuffer()[offset],object->_dp->GetBuffer(),object->_dp->GetLength());

      offset += object->_dp->GetLength();

      memcpy((u1*)&keyValue->GetBuffer()[offset],object->_dq->GetBuffer(),object->_dq->GetLength());

      offset += object->_dq->GetLength();

      memcpy((u1*)&keyValue->GetBuffer()[offset],object->_d->GetBuffer(),object->_d->GetLength());

      offset += object->_d->GetLength();

      u4 modulusLen = 0;

      string contName;
      if(object->_modulus != NULL_PTR){

         memcpy((u1*)&keyValue->GetBuffer()[offset],object->_modulus->GetBuffer(),object->_modulus->GetLength());

         offset += object->_modulus->GetLength();

         memcpy((u1*)&keyValue->GetBuffer()[offset],publExp.GetBuffer(),publExp.GetLength());

         modulusLen = object->_modulus->GetLength();

         contName = CAttributedCertificate::DerivedUniqueName(object->_modulus->GetBuffer(),
            object->_modulus->GetLength());

      }else{

         memcpy((u1*)&keyValue->GetBuffer()[offset],rsaPub->_modulus->GetBuffer(),rsaPub->_modulus->GetLength());

         offset += rsaPub->_modulus->GetLength();

         memcpy((u1*)&keyValue->GetBuffer()[offset],publExp.GetBuffer(),publExp.GetLength());

         modulusLen = rsaPub->_modulus->GetLength();

         contName = CAttributedCertificate::DerivedUniqueName(rsaPub->_modulus->GetBuffer(),
            rsaPub->_modulus->GetLength());

      }

      //try
      //{
      this->_cardCache->ClearContainer(ctrIdx);  // Invalidate cache
      //this->_mscm->CreateCAPIContainer(ctrIdx,CK_TRUE,object->_keySpec,(modulusLen*8),keyValue.get());
      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ManageGC( );
            ntry++;
            this->_mscm->CreateCAPIContainer(ctrIdx,CK_TRUE,object->_keySpec,(modulusLen*8),keyValue.get());
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "Token::AddPrivateKeyObject", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  Log::error( "Token::AddPrivateKeyObject", "Throw Exception CKR_DEVICE_MEMORY" );
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
      }

      this->RegisterContainerUpdate();
      /*}
      catch(...)
      {
      Log::error( "Token::AddPrivateKeyObject", "ctrIdx > 99 - Return CKR_DEVICE_MEMORY" );

      throw CkError(CKR_DEVICE_MEMORY);
      }*/

      object->_ctrIndex = ctrIdx;

      rv = this->AddObject(stobj,phObject);
      if(rv == CKR_OK)
      {
         try
         {
            auto_ptr<u1Array> newCMap( UpdateCMap( ctrIdx, fileData, (modulusLen*8), object->_keySpec, CK_TRUE, contName ) );
            this->_cardCache->WriteFile( nameCMapFile, *newCMap );
            this->RegisterFileUpdate( );
         }
         catch( CkError x )
         {
            rv = x.Error( );
            Log::log( "## Error ## Token::AddPrivateKeyObject - WriteFile <%ld>\n", rv );

            try
            {
               DeleteObject( *phObject );
            }
            catch( ... )
            {
            }

            throw CkError( rv );
         }
      }
   }
   TOKEN_CATCH( rv )

      return rv;
}


/* DeleteCMapRecord
*/
void Token::DeleteCMapRecord( CK_BYTE ctrIndex )
{
   // Read the container map record file
   std::string nameCMapFile( "mscp\\cmapfile" );

   try
   {
      u1Array fileData( _cardCache->ReadFile( nameCMapFile ) );

      s4 entries = ( fileData.GetLength( ) / SIZE_CONTAINERMAPRECORD );
      if( ctrIndex >= entries )
      {
         return; // Silently ignore if doesn't exist
      }

      // Nullify the entries at ctrIndex
      CMapFileClear( fileData, ctrIndex );

      // Set default container
      SetDefaultContainer( fileData, 0xFF );

      //ManageGC( );

      // Write the updated content back to cmap
      this->_cardCache->WriteFile( nameCMapFile, fileData );
      this->RegisterFileUpdate( );
   }
   catch( CkError x )
   {
      /*CK_RV rv =*/ x.Error( );
      Log::error( "Token::DeleteCMapRecord", "WriteFile failed" );
      throw;
   }
   /*
   catch(Marshaller::RemotingException&){
   // TBD
   }
   catch(Marshaller::UnauthorizedAccessException&){
   // TBD
   }
   catch(std::runtime_error&){
   // TBD
   }
   */
}

void Token::RemoveKeyFromCMapRecord(CK_BYTE ctrIndex, u1 keySpec)
{

   try{
      // read the container map record file
      std::string nameCMapFile("mscp\\cmapfile");
      u1Array fileData(_cardCache->ReadFile(nameCMapFile));

      s4 entries = (fileData.GetLength() / SIZE_CONTAINERMAPRECORD);
      if(ctrIndex >= entries)
      {
         PKCS11_ASSERT(0);
         return; // Silently ignore if doesn't exist
      }

      // Clear the key size corresponding to keyspec
      if(keySpec == KEYSPEC_KEYEXCHANGE)
         CMapFileSetExchSize(fileData, ctrIndex, 0);
      else if(keySpec == KEYSPEC_SIGNATURE)
         CMapFileSetSignSize(fileData, ctrIndex, 0);
      else
         return;  // unknown key spec

      //ManageGC();

      // now write the updated content back to cmap
      this->_cardCache->WriteFile(nameCMapFile,fileData);
      this->RegisterFileUpdate();

   }
   catch( CkError x )
   {
      /*CK_RV rv =*/ x.Error( );
      Log::error( "Token::RemoveKeyFromCMapRecord", "WriteFile failed" );
   }
   /*
   catch(Marshaller::RemotingException&){
   // TBD
   }
   catch(Marshaller::UnauthorizedAccessException&){
   // TBD
   }
   catch(std::runtime_error&){
   // TBD
   }
   */
}

void Token::SetDefaultContainer(u1Array & contents, CK_BYTE ctrIndex)
{

   s4 entries = (contents.GetLength() / SIZE_CONTAINERMAPRECORD);

   if(ctrIndex == 0xFF)
   {
      for (s4 i=0;i<entries;i++)
      {
         if((CMapFileGetFlag(contents, i) & 0x03) == 0x03)
            return;  // A valid container already default, finished
      }

      // Find first best suitable. Look for one with keys
      for (s4 i=0;i<entries;i++)
      {
         u1 flags = CMapFileGetFlag(contents, i);
         if((flags & 0x01) && (CMapFileGetExchSize(contents, i) || CMapFileGetSignSize(contents, i)))
         {
            CMapFileSetFlag(contents, i, (flags | 0x02));
            return;
         }
      }

      // If no container with keys, then assign any valid container as default
      for (s4 i=0;i<entries;i++)
      {
         u1 flags = CMapFileGetFlag(contents, i);
         if(flags & 0x01)
         {
            CMapFileSetFlag(contents, i, (flags | 0x02));
            return;
         }
      }
   }
   else
   {
      // Assign specific container as default
      PKCS11_ASSERT(ctrIndex < entries);
      if(ctrIndex >= entries)
         return;
      // Remove existing default container
      for (s4 i=0;i<entries;i++)
      {
         u1 flags = CMapFileGetFlag(contents, i);
         CMapFileSetFlag(contents, i, (flags & ~0x02));
      }
      CMapFileSetFlag(contents, ctrIndex, CMapFileGetFlag(contents, ctrIndex) | 0x02);
   }
}

CK_RV Token::AddCertificateObject(auto_ptr<StorageObject> & stobj, CK_OBJECT_HANDLE_PTR phObject)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      X509PubKeyCertObject * object = static_cast<X509PubKeyCertObject*>(stobj.get());

      if(object->_private)
         throw CkError(CKR_ATTRIBUTE_VALUE_INVALID);

      //CheckAvailableSpace();

      // Make check value and look for possibly existing private key(s)

      BEROctet::Blob modulus;
      try
      {
         X509Cert x509cert(object->_value->GetBuffer(), object->_value->GetLength());
         modulus =x509cert.Modulus();
      }
      catch(...)
      {
         throw CkError(CKR_ATTRIBUTE_VALUE_INVALID);
      }

      object->_checkValue   = Util::MakeCheckValue(modulus.data(), static_cast<unsigned int>(modulus.size()));
      string contName(CAttributedCertificate::DerivedUniqueName(modulus));

      std::string nameCMapFile("mscp\\cmapfile");
      const u1Array & fileData(_cardCache->ReadFile(nameCMapFile));

      object->_keySpec = KEYSPEC_KEYEXCHANGE;   // Default

      // NOTE: If it finds a matching private key, the keySpec
      // will be modified to match that of the private key.
      CK_BYTE ctrIdx = GetContainerForCert(fileData, object->_checkValue, &object->_keySpec);
      if(ctrIdx > 99)
      {
         Log::error( "Token::AddCertificateObject", "ctrIdx > 99 - Return CKR_DEVICE_MEMORY" );

         throw CkError(CKR_DEVICE_MEMORY);
      }
      object->_ctrIndex = ctrIdx;

      if(object->_keySpec == KEYSPEC_KEYEXCHANGE)
         object->_certName = "kxc";
      else
         object->_certName = "ksc";
      object->_certName.append(Util::MakeIntString(ctrIdx, 2));

      string fileName("mscp\\");
      fileName.append(object->_certName);

      unsigned long ccLen = object->_value->GetLength();
      autoarray<u1> cc(new u1[ccLen+4]);

      cc[0] = 0x01;
      cc[1] = 0x00;
      cc[2] = BITS_0_7(ccLen);
      cc[3] = BITS_8_15(ccLen);

      // compress the certificate
      //         compress((u1*)&cc[4],&ccLen,object->_value->GetBuffer(),ccLen);
      compress2((u1*)&cc[4],&ccLen,object->_value->GetBuffer(),ccLen, 6); // Set level=6, same as Minidriver

      auto_ptr<u1Array> compressedCert(new u1Array((ccLen + 4)));
      compressedCert->SetBuffer(cc.get());

      auto_ptr<u1Array> acls(new u1Array(3));
      acls->GetBuffer()[0] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // admin acl
      acls->GetBuffer()[1] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // usr acl
      acls->GetBuffer()[2] = CARD_PERMISSION_READ; // everyone acl

      //ManageGC();

      _cardCache->ClearFileList("mscp");
      this->_mscm->CreateFile(&fileName,acls.get(),0);
      try
      {
         this->_cardCache->WriteFile(fileName,*compressedCert);
         this->RegisterFileUpdate();
      }
      catch( CkError x )
      {
         rv = x.Error( );
         Log::error( "Token::AddCertificateObject", "WriteFile failed" );
      }

      if( CKR_OK != rv )
      {
         try
         {
            _mscm->DeleteFile( &fileName );
         }
         catch( ... )
         {
         }

         throw CkError( rv );
      }

      rv = AddObject(stobj ,phObject);
      if(rv == CKR_OK)
      {
         //ManageGC();

         try
         {
            auto_ptr<u1Array> newCMap(UpdateCMap(ctrIdx,fileData, contName));
            _cardCache->WriteFile(nameCMapFile,*newCMap);
            RegisterFileUpdate();
         }
         catch( CkError x )
         {
            rv = x.Error( );
            Log::error( "Token::AddCertificateObject", "WriteFile 2 failed" );
         }

         if( CKR_OK != rv )
         {
            try
            {
               _mscm->DeleteFile( &fileName );
            }
            catch( ... )
            {
            }

            try
            {
               DeleteObject( *phObject );
            }
            catch( ... )
            {
            }

            throw CkError( rv );
         }
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::DeleteObject( CK_OBJECT_HANDLE hObject )
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      StorageObject * obj = GetObject(hObject);

      // some more checks
      if((this->_roleLogged != CKU_USER) && (obj->_private == CK_TRUE)){
         throw CkError(CKR_USER_NOT_LOGGED_IN);
      }

      if(obj->_class == CKO_CERTIFICATE){

         //Log::log("Deleting the certificate.");

         CertificateObject * cert = static_cast<CertificateObject*>(obj);
         CK_BYTE ctrIdx = cert->_ctrIndex;

         if(ctrIdx != 0xFF){

            // Delete the file under mscp

            string fileName("mscp\\");
            fileName.append(cert->_certName);
            _cardCache->ClearFile(fileName);
            try
            {
               _cardCache->ClearFileList("mscp");
               _mscm->DeleteFile(&fileName);
               RegisterFileUpdate();
            }
            catch(FileNotFoundException &) {}

            // Check if there exist private key(s) or other
            // certificate (with different key spec) in the container
            u1 otherKeySpec = (cert->_keySpec == KEYSPEC_KEYEXCHANGE) ? KEYSPEC_SIGNATURE : KEYSPEC_KEYEXCHANGE;

            bool fOtherCertExist = (FindCertificate(_objects, ctrIdx, otherKeySpec) != 0);

            bool fPrivKeysExist = false;
            if(FindPrivateKey(_objects, ctrIdx, KEYSPEC_KEYEXCHANGE) || FindPrivateKey(_objects, ctrIdx, KEYSPEC_SIGNATURE))
               fPrivKeysExist = true;

            // If there are no longer any objects associated with this
            // container, then free this CMap record
            if(!fOtherCertExist && !fPrivKeysExist)
            {
               //Log::log("Deleting container ",ctrIdx);
               DeleteCMapRecord(ctrIdx);
            }
         }
      }
      if(obj->_class == CKO_PRIVATE_KEY){

         //Log::log("Deleting the private key.");

         RSAPrivateKeyObject * privKey = static_cast<RSAPrivateKeyObject*>(obj);
         CK_BYTE ctrIdx = privKey->_ctrIndex;

         if(ctrIdx != 0xFF){


            // Check if there exist certificate(s) or other
            // private key (with different key spec) in the container
            u1 otherKeySpec = (privKey->_keySpec == KEYSPEC_KEYEXCHANGE) ? KEYSPEC_SIGNATURE : KEYSPEC_KEYEXCHANGE;

            bool fOtherKeyExist = (FindPrivateKey(_objects, ctrIdx, otherKeySpec) != 0);

            bool fCertsExist = false;
            if(FindCertificate(_objects, ctrIdx, KEYSPEC_KEYEXCHANGE) || FindCertificate(_objects, ctrIdx, KEYSPEC_SIGNATURE))
               fCertsExist = true;

            if(fOtherKeyExist)
            {
               // To not delete the other key, overwrite this one with dummy data
               // TODO
               // this->_mscm->CreateCAPIContainer(ctrIdx,.....);
               RegisterContainerUpdate();
            }
            else
            {
               _cardCache->ClearContainer(ctrIdx);   // Invalidate cache
               _mscm->DeleteCAPIContainer(ctrIdx);
               RegisterContainerUpdate();
            }

            // Check if the record in cmapfile shall be cleared,
            // depending on if there are other keys in it.
            // empty the corresponding record in cmapfile

            if(fOtherKeyExist || fCertsExist)
            {
               //Log::log("Removing key from container ",ctrIdx);
               RemoveKeyFromCMapRecord(ctrIdx, privKey->_keySpec);
            }
            else
            {
               //Log::log("Deleting container ",ctrIdx);
               DeleteCMapRecord(ctrIdx);
            }
         }
      }

      // delete the file from card
      if(!obj->_fileName.empty())
      {
         _cardCache->ClearFile(obj->_fileName);
         try
         {
            _cardCache->ClearFileList("p11");
            this->_mscm->DeleteFile(&obj->_fileName);
            this->RegisterFileUpdate();
         }
         catch(FileNotFoundException &) {}
      }

      UnregisterStorageObject(obj);
      delete obj;
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::GetAttributeValue(CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulCount)
{
   CK_RV rv  = CKR_OK;
   CK_RV arv = CKR_OK;
   TOKEN_TRY
   {

      //Log::log("Get Attributes of token object..");

      StorageObject * obj = GetObject(hObject);

      if((this->_roleLogged != CKU_USER) && (obj->_private == CK_TRUE)){
         for(u4 i=0;i<ulCount;i++){
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION; //(CK_LONG)-1;
         }
         throw CkError(CKR_USER_NOT_LOGGED_IN);
      }

      for(u4 i=0;i<ulCount;i++){
         rv = obj->GetAttribute(&pTemplate[i]);
         if(rv != CKR_OK){
            arv = rv;
         }
      }
   }
   TOKEN_CATCH(arv)
      return arv;
}


CK_RV Token::SetAttributeValue( CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount )
{
   CK_RV rv = CKR_OK;
   CK_RV arv = CKR_OK;
   TOKEN_TRY
   {
      StorageObject* pObj = GetObject( hObject );
      // ??? pObj == NULL_PTR

      // Check if we have a proper session
      if( ( this->_roleLogged != CKU_USER ) && ( pObj->_private == CK_TRUE ) )
      {
         throw CkError( CKR_USER_NOT_LOGGED_IN );
      }

      if( pObj->_modifiable == CK_FALSE )
      {
         throw CkError(CKR_ATTRIBUTE_READ_ONLY);
      }

      for( u4 i = 0 ; i < ulCount ; i++ )
      {
         rv = pObj->SetAttribute( pTemplate[ i ], CK_FALSE );
         if( rv != CKR_OK )
         {
            arv = rv;
         }
      }

      if( arv == CKR_OK )
      {
         // If the object is not yet represented by a file under
         // "p11" directory, this file must be created first.

         bool fCreate = false;

         // The object is represented by a P11 file if and only if
         // the _uniqueId has been assigned a value.
         if( pObj->_uniqueId == 0 )
         {
            fCreate = true;
            if(!_initialized)
               Initialize();

            u1Array acls(3);
            acls.GetBuffer( )[ 0 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // admin acl
            acls.GetBuffer( )[ 1 ] = CARD_PERMISSION_READ | CARD_PERMISSION_WRITE;  // usr acl

            if(pObj->_private)
               acls.GetBuffer()[2] = 0; // everyone acl
            else
               acls.GetBuffer()[2] = CARD_PERMISSION_READ; // everyone acl

            string fileName("p11\\" + FindFreeFileName(pObj));
            _cardCache->ClearFileList("p11");
            _mscm->CreateFile(&fileName,&acls,0);
            RegisterFileUpdate();
            pObj->_fileName = fileName;
            pObj->_uniqueId = Util::MakeUniqueId();
         }

         // marshall this object back to the card
         vector<u1> to;
         pObj->Serialize(&to);

         u1Array objData((s4)to.size());

         for(u4 i=0;i<to.size();i++){
            objData.SetU1At(i,to.at(i));
         }

         //ManageGC();

         try
         {
            this->_cardCache->WriteFile(pObj->_fileName,objData);
            this->RegisterFileUpdate();
         }
         catch( CkError x )
         {
            arv = x.Error( );
            Log::error( "Token::SetAttributeValue", "WriteFile failed" );
         }

         if( CKR_OK != arv )
         {
            /*try
            {
            _mscm->DeleteFile(&obj->_fileName);
            }
            catch( ... )
            {
            }*/

            if(fCreate)   // Restore state of object prior to update attempt.
            {
               pObj->_fileName.clear();
               pObj->_uniqueId = 0;
            }
         }
      }
   }
   TOKEN_CATCH(arv)
      return arv;
}


CK_BYTE Token::GetAvailableContainerIndex(u1Array const & cmapContents)
{
   u4  contentLen = cmapContents.GetLength();

   // cmap file does not contain anything
   // so index is 0
   if(contentLen == 0){
      return 0;
   }

   s4 entries = contentLen / SIZE_CONTAINERMAPRECORD;

   for(s4 i=0;i<entries;i++){
      // lets find out which entry has all zeros
      // which denotes available index

      // as per minidriver specification
      // if bit 0 of flags should be set for it to be
      // a valid entry
      if((CMapFileGetFlag(cmapContents, i) & 0x01) != 0x01){
         return i;
      }
   }

   // reaching here means that cmap file has entries
   // which are all occupied, in that the available
   // index would be entries
   return entries;
}

CK_BYTE Token::GetContainerForCert(u1Array const & cmapContents, u8 checkValue, u1 * keySpec)
{
   // Look for existing matching private key
   vector <PrivateKeyObject*> vPriv(FindPrivateKeys(_objects, checkValue));
   for(size_t ipriv = 0; ipriv < vPriv.size(); ++ipriv)
   {
      // See it the corresponding container/keyspec is already occupied by a certificate.
      // If it isn't, this is free for use.
      if(!FindCertificate(_objects, vPriv[ipriv]->_ctrIndex, vPriv[ipriv]->_keySpec))
      {
         *keySpec = vPriv[ipriv]->_keySpec;
         return vPriv[ipriv]->_ctrIndex;
      }
   }
   // No matching private key, find new container

   return GetAvailableContainerIndex(cmapContents);
}

CK_BYTE Token::GetContainerForPrivateKey(u1Array const & cmapContents, u8 checkValue, u1 * keySpec)
{
   // Look for existing matching certificate
   vector <CertificateObject*> vCert(FindCertificates(_objects, checkValue));
   for(size_t icert = 0; icert < vCert.size(); ++icert)
   {
      // See it the corresponding container/keyspec is already occupied by a key.
      // If it isn't, this is free for use.
      if(!FindPrivateKey(_objects, vCert[icert]->_ctrIndex, vCert[icert]->_keySpec))
      {
         *keySpec = vCert[icert]->_keySpec;
         return vCert[icert]->_ctrIndex;
      }
   }
   // No matching certificate, find new container

   return GetAvailableContainerIndex(cmapContents);
}

auto_ptr<u1Array> Token::UpdateCMap(CK_BYTE ctrIdx, u1Array const & contents, string const & contName )
{
   u4  contentLen = contents.GetLength();
   s4 entries = contentLen / SIZE_CONTAINERMAPRECORD;

   u4 newCMapSize = SIZE_CONTAINERMAPRECORD * entries;

   if(ctrIdx >= entries){
      entries = ctrIdx + 1;
      newCMapSize = entries * SIZE_CONTAINERMAPRECORD;
   }

   //autoarray<u1> updatedContents(new u1[newCMapSize]);

   auto_ptr<u1Array> updatedContents(new u1Array(newCMapSize));

   memset(updatedContents->GetBuffer(), 0, newCMapSize);
   memcpy(updatedContents->GetBuffer(), contents.GetBuffer(), contentLen);

   u1 flags = CMapFileGetFlag(*updatedContents, ctrIdx);
   if(!(flags & 0x01))
   {
      // Container record is new, set container Name (UNICODE string)
      CMapFileSetName(*updatedContents, ctrIdx, contName);
      CMapFileSetFlag(*updatedContents, ctrIdx, flags | 0x01);
   }

   SetDefaultContainer(*updatedContents, 0xFF);

   return updatedContents;
}

auto_ptr<u1Array> Token::UpdateCMap(CK_BYTE ctrIdx,u1Array const & contents,u4 keySize,u1 keySpec,CK_BBOOL isDefault, string const & contName)
{
   u4  contentLen = contents.GetLength();
   s4 entries = contentLen / SIZE_CONTAINERMAPRECORD;

   u4 newCMapSize = SIZE_CONTAINERMAPRECORD * entries;

   if(ctrIdx >= entries){
      entries = ctrIdx + 1;
      newCMapSize = entries * SIZE_CONTAINERMAPRECORD;
   }

   auto_ptr<u1Array> updatedContents(new u1Array(newCMapSize));

   memset(updatedContents->GetBuffer(), 0, newCMapSize);
   memcpy(updatedContents->GetBuffer(), contents.GetBuffer(), contentLen);

   u1 flags = CMapFileGetFlag(*updatedContents, ctrIdx);
   if(!(flags & 0x01))
   {
      // Container record is new, set container Name (UNICODE string)
      CMapFileSetName(*updatedContents, ctrIdx, contName);
      CMapFileSetFlag(*updatedContents, ctrIdx, flags | 0x01);
   }

   // Default container
   SetDefaultContainer(*updatedContents, isDefault ? ctrIdx : 0xFF);

   // Container Key Size
   if (keySpec == KEYSPEC_SIGNATURE){
      CMapFileSetSignSize(*updatedContents, ctrIdx, keySize);
   }else{
      CMapFileSetExchSize(*updatedContents, ctrIdx, keySize);
   }

   return updatedContents;
}

vector <PrivateKeyObject*> Token::FindPrivateKeys(vector<StorageObject*> const & objects, u8 checkValue)
{
   // checkValue is derived from the modulus and is sufficiently
   // long (8 bytes) to be a unique handle to the key pair / certificate
   vector <PrivateKeyObject*> vPriv;

   for(s4 i = 0; i < static_cast<s4>(objects.size()); i++){
      if(objects[i] && objects[i]->_class == CKO_PRIVATE_KEY){
         PrivateKeyObject * privObject = (PrivateKeyObject*)objects[i];
         if(privObject->_checkValue == checkValue)
            vPriv.push_back(privObject);
      }
   }
   return vPriv;
}

PrivateKeyObject * Token::FindPrivateKey(vector<StorageObject*> const & objects, CK_BYTE ctrdIdx, u1 keySpec)
{
   vector <PrivateKeyObject*> vPriv;

   for(s4 i = 0; i < static_cast<s4>(objects.size()); i++)
   {
      if(objects[i] && objects[i]->_class == CKO_PRIVATE_KEY)
      {
         PrivateKeyObject * privObject = (PrivateKeyObject*)objects[i];
         if(privObject->_ctrIndex == ctrdIdx && privObject->_keySpec == keySpec)
            return privObject;  // Is supposed to be only one.
      }
   }
   return 0;
}

vector <CertificateObject*> Token::FindCertificates(vector<StorageObject*> const & objects, u8 checkValue)
{
   // checkValue is derived from the modulus and is sufficiently
   // long (8 bytes) to be a unique handle to the key pair / certificate
   vector <CertificateObject*> vCert;

   for(s4 i = 0; i < static_cast<s4>(objects.size()); i++)
   {
      if(objects[i] && objects[i]->_class == CKO_CERTIFICATE)
      {
         CertificateObject * certObject = (CertificateObject*)objects[i];
         if(certObject->_checkValue == checkValue)
            vCert.push_back(certObject);
      }
   }
   return vCert;
}

CertificateObject * Token::FindCertificate(vector<StorageObject*> const & objects, CK_BYTE ctrdIdx, u1 keySpec)
{
   for(s4 i = 0; i < static_cast<s4>(objects.size()); i++)
   {
      if(objects[i] && objects[i]->_class == CKO_CERTIFICATE)
      {
         CertificateObject * certObject = (CertificateObject*)objects[i];
         if(certObject->_ctrIndex == ctrdIdx && certObject->_keySpec == keySpec)
            return certObject;
      }
   }
   return 0;
}

CK_RV Token::GenerateKeyPair(auto_ptr<StorageObject> & stobjRsaPub, auto_ptr<StorageObject> & stobjRsaPriv,
                             CK_OBJECT_HANDLE_PTR phPubKey,CK_OBJECT_HANDLE_PTR phPrivKey)
{

   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      RSAPublicKeyObject * rsaPubObject = static_cast<RSAPublicKeyObject*>(stobjRsaPub.get());
      RSAPrivateKeyObject * rsaPrivObject = static_cast<RSAPrivateKeyObject*>(stobjRsaPriv.get());

      if( (rsaPubObject->_modulusLen < RSA_KEY_MIN_LENGTH) ||
         (rsaPubObject->_modulusLen > RSA_KEY_MAX_LENGTH) )
         throw CkError(CKR_ATTRIBUTE_VALUE_INVALID);

      //CheckAvailableSpace(); // HACK !!

      //Log::log("Generating KeyPair on the smartcard...");

      std::string nameCMapFile;

      // TBD (Start a pc/sc transaction here)

      // let's first read the container record file to
      // see which container is available.
      // No need to search for matching certificate,
      // since this can not exist one yet!! ;)
      nameCMapFile = "mscp\\cmapfile";
      const u1Array & fileData = this->_cardCache->ReadFile(nameCMapFile);

      CK_BYTE ctrIdx = this->GetAvailableContainerIndex(fileData);
      if(ctrIdx == 0xFF)
         throw CkError(CKR_DEVICE_MEMORY);

      // create a capi container.
      // KEYSPEC_KEYEXCHANGE by default.
      this->_cardCache->ClearContainer(ctrIdx);   // Invalidate cache
      //this->_mscm->CreateCAPIContainer(ctrIdx,CK_FALSE,KEYSPEC_KEYEXCHANGE,rsaPubObject->_modulusLen,NULL_PTR);
      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ManageGC( );
            ntry++;
            this->_mscm->CreateCAPIContainer(ctrIdx,CK_FALSE,KEYSPEC_KEYEXCHANGE,rsaPubObject->_modulusLen,NULL_PTR);
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "Token::GenerateKeyPair", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  Log::error( "Token::GenerateKeyPair", "Throw Exception CKR_DEVICE_MEMORY" );
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
      }

      this->RegisterContainerUpdate();

      rsaPubObject->_ctrIndex = ctrIdx;
      rsaPubObject->_keySpec = KEYSPEC_KEYEXCHANGE;

      rsaPrivObject->_ctrIndex = ctrIdx;
      rsaPrivObject->_keySpec = KEYSPEC_KEYEXCHANGE;

      // populate these objects with the key material
      const CardCache::Container & cont = _cardCache->ReadContainer(ctrIdx);

      rsaPubObject->_exponent = new u1Array();
      *rsaPubObject->_exponent = cont.exchPublicExponent;
      rsaPubObject->_modulus = new u1Array();
      *rsaPubObject->_modulus = cont.exchModulus;
      rsaPubObject->_local = CK_TRUE;


      // Copy these modulus and exponent in the private key component also
      rsaPrivObject->_publicExponent = new u1Array();
      *rsaPrivObject->_publicExponent = cont.exchPublicExponent;

      rsaPrivObject->_modulus = new u1Array();
      *rsaPrivObject->_modulus = cont.exchModulus;
      rsaPrivObject->_checkValue = Util::MakeCheckValue(cont.exchModulus.GetBuffer(),
         cont.exchModulus.GetLength());
      rsaPrivObject->_local = CK_TRUE;

      string contName(CAttributedCertificate::DerivedUniqueName(cont.exchModulus.GetBuffer(),
         cont.exchModulus.GetLength()));

      // now its time to add the corresponding objects to
      // the card (as files)

      // The public key may be a session object, in that case, don't save it.

      if( rsaPubObject->_tokenObject )
      {
         rv = this->AddObject( stobjRsaPub, phPubKey );
      }

      if( CKR_OK == rv )
      {
         rv = this->AddObject( stobjRsaPriv, phPrivKey );

         if( CKR_OK == rv )
         {
            try
            {
               auto_ptr<u1Array> newCMap( UpdateCMap( ctrIdx, fileData, rsaPubObject->_modulusLen, KEYSPEC_KEYEXCHANGE, CK_TRUE, contName ) );
               _cardCache->WriteFile( nameCMapFile, *newCMap );
               RegisterFileUpdate( );
            }
            catch( CkError x )
            {
               rv = x.Error( );
               Log::error( "Token::SetAttributeValue", "WriteFile failed" );
            }

            if( CKR_OK != rv )
            {
               if( rsaPubObject->_tokenObject )
               {
                  DeleteObject( *phPubKey );
                  // ???
               }
               DeleteObject( *phPrivKey );

               throw CkError( rv );
            }
         }
         else if( rsaPubObject->_tokenObject )
         {
            DeleteObject( *phPubKey );
         }
      }
   }
   TOKEN_CATCH(rv)

      return rv;
}


CK_RV Token::GetObject(CK_OBJECT_HANDLE hObject,StorageObject** object)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      *object = GetObject(hObject);
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::Encrypt(StorageObject* pubObj,u1Array* dataToEncrypt,CK_ULONG mechanism,CK_BYTE_PTR pEncryptedData)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      RSAPublicKeyObject* object = (RSAPublicKeyObject*)pubObj;

      if(mechanism == CKM_RSA_PKCS){
         // first do the length checks
         if(dataToEncrypt->GetLength() > (object->_modulus->GetLength() - 11)){
            throw CkError(CKR_DATA_LEN_RANGE);
         }

         rsaPublicKey_t key;

         key.modulus = object->_modulus->GetBuffer() ;
         key.modulusLength = object->_modulus->GetLength() * 8 ;
         key.publicExponent = object->_exponent->GetBuffer();
         key.publicExponentLength =  object->_exponent->GetLength() * 8;

         u4 outLength = object->_modulus->GetLength();

         DWORD rv ;
         DWORD size ;
         DWORD pubSize ;
         R_RSA_PUBLIC_KEY	rsaKeyPublic ;

         rsaKeyPublic.bits = key.modulusLength ;

         size = (key.modulusLength + 7) / 8 ;
         memcpy(rsaKeyPublic.modulus, key.modulus, size) ;

         pubSize = (key.publicExponentLength + 7) / 8 ;
         memset(rsaKeyPublic.exponent, 0, size) ;
         memcpy(&rsaKeyPublic.exponent[size - pubSize], key.publicExponent, pubSize) ;

         R_RANDOM_STRUCT & randomStruct = Util::RandomStruct();

         rv = RSAPublicEncrypt(
            pEncryptedData,
            &outLength,
            dataToEncrypt->GetBuffer(),
            dataToEncrypt->GetLength(),
            &rsaKeyPublic,
            &randomStruct);

      }else{

         u4 modulusLen = object->_modulus->GetLength();

         if(dataToEncrypt->GetLength() > (modulusLen)){
            throw CkError(CKR_DATA_LEN_RANGE);
         }

         // pre-pad with zeros
         u1Array* messageToEncrypt = new u1Array(modulusLen);
         memset(messageToEncrypt->GetBuffer(),0,modulusLen);

         s4 offsetMsgToEncrypt = modulusLen - dataToEncrypt->GetLength();

         for(u4 i=0,j=offsetMsgToEncrypt;i<dataToEncrypt->GetLength();i++,j++){
            messageToEncrypt->GetBuffer()[j] = dataToEncrypt->GetBuffer()[i];
         }

         // just block transform now
         s4 size ;
         s4 pubSize ;
         R_RSA_PUBLIC_KEY	rsaKeyPublic ;

         //Build the RSA public key context
         rsaKeyPublic.bits = object->_modulus->GetLength() * 8;

         size = (rsaKeyPublic.bits  + 7) / 8 ;
         memcpy(rsaKeyPublic.modulus,object->_modulus->GetBuffer(),size) ;

         pubSize = ((object->_exponent->GetLength() * 8) + 7) / 8 ;
         memset(rsaKeyPublic.exponent, 0, size) ;
         memcpy(&rsaKeyPublic.exponent[size - pubSize], object->_exponent->GetBuffer(), pubSize) ;

         u4 outputLen = size;

         rv = RSAPublicBlock(pEncryptedData,&outputLen,messageToEncrypt->GetBuffer(),size,&rsaKeyPublic);
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::Decrypt(StorageObject* privObj,u1Array* dataToDecrypt,CK_ULONG mechanism,CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      u1Array* data = NULL_PTR;

      RSAPrivateKeyObject * rsaKey = static_cast<RSAPrivateKeyObject*>(privObj);

      //data = this->_mscm->PrivateKeyDecrypt(rsaKey->_ctrIndex, rsaKey->_keySpec, dataToDecrypt);
      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ManageGC( );
            ntry++;
            data = this->_mscm->PrivateKeyDecrypt( rsaKey->_ctrIndex, rsaKey->_keySpec, dataToDecrypt );
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "Token::Decrypt", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
      }





      if(mechanism == CKM_RSA_PKCS){

         u1* decryptedMessage = (u1*)data->GetBuffer();

#define PKCS_EMEV15_PADDING_TAG   0x2

         if ((decryptedMessage[0] != 0x00) || (decryptedMessage[1] != PKCS_EMEV15_PADDING_TAG))
         {
            // TBD: Lookup correct error message
            // invalid message padding
            rv = CKR_ENCRYPTED_DATA_INVALID;
         }else{

            // seach message padding separator
            u4 mPos = 2 + 8;
            while ((decryptedMessage[mPos] != 0x00) && (mPos < data->GetLength()))
            {
               mPos++;
            }

            // point on message itself.
            mPos++;
            u1Array* finalDecryptedMessage = new u1Array(data->GetLength() - mPos);
            memcpy(finalDecryptedMessage->GetBuffer(),(u1*)&decryptedMessage[mPos],finalDecryptedMessage->GetLength());

            delete data;

            data = finalDecryptedMessage;
         }
      }
      // else... CKM_RSA_X_509: Ignore padding

      if(data){
         if(*pulDataLen >= data->GetLength())
            memcpy(pData,data->GetBuffer(),data->GetLength());
         else
            rv = CKR_BUFFER_TOO_SMALL;
         *pulDataLen = data->GetLength();
         delete data;
      }
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::Verify(StorageObject* pubObj,u1Array* dataToVerify,CK_ULONG mechanism,u1Array* signature)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      RSAPublicKeyObject* object = (RSAPublicKeyObject*)pubObj;

      if(((mechanism == CKM_RSA_PKCS) && (dataToVerify->GetLength() > (object->_modulus->GetLength() - 11))) ||
         ((mechanism == CKM_RSA_X_509) && (dataToVerify->GetLength() > object->_modulus->GetLength())))
      {
         throw CkError(CKR_DATA_LEN_RANGE);
      }

      if(signature->GetLength() != object->_modulus->GetLength()){
         throw CkError(CKR_SIGNATURE_LEN_RANGE);
      }

      s4 size ;
      s4 pubSize ;
      R_RSA_PUBLIC_KEY	rsaKeyPublic ;

      //Build the RSA public key context
      rsaKeyPublic.bits = object->_modulus->GetLength() * 8;

      size = (rsaKeyPublic.bits  + 7) / 8 ;
      memcpy(rsaKeyPublic.modulus,object->_modulus->GetBuffer(),size) ;

      pubSize = ((object->_exponent->GetLength() * 8) + 7) / 8 ;
      memset(rsaKeyPublic.exponent, 0, size) ;
      memcpy(&rsaKeyPublic.exponent[size - pubSize], object->_exponent->GetBuffer(), pubSize) ;

      u4 messageToVerifyLen = size;
      u1Array* messageToVerify = new u1Array(messageToVerifyLen);

      RSAPublicBlock(messageToVerify->GetBuffer(),&messageToVerifyLen,signature->GetBuffer(),size,&rsaKeyPublic);

      switch(mechanism){

            case CKM_RSA_PKCS:
               rv = VerifyRSAPKCS1v15(messageToVerify,dataToVerify,size);
               break;

            case CKM_RSA_X_509:
               rv = VerifyRSAX509(messageToVerify,dataToVerify,size);
               break;


            case CKM_SHA1_RSA_PKCS:
               rv = VerifyHash(messageToVerify,dataToVerify,size,CKM_SHA_1);
               break;

            case CKM_SHA256_RSA_PKCS:
               rv = VerifyHash(messageToVerify,dataToVerify,size,CKM_SHA256);
               break;

            case CKM_MD5_RSA_PKCS:
               rv = VerifyHash(messageToVerify,dataToVerify,size,CKM_MD5);
               break;

            default:
               PKCS11_ASSERT(CK_FALSE);
               rv = CKR_GENERAL_ERROR;
               break;
      }

      delete messageToVerify;
   }
   TOKEN_CATCH(rv)
      return rv;
}

CK_RV Token::VerifyHash(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen,CK_ULONG hashAlgo)
{
   u1 DER_SHA1_Encoding[]   = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
   u1 DER_SHA256_Encoding[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
   u1 DER_MD5_Encoding[]    = {0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10};

   s4  DER_Encoding_Len = 0;

   switch(hashAlgo){
        case CKM_SHA_1:
           DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
           break;

        case CKM_SHA256:
           DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
           break;

        case CKM_MD5:
           DER_Encoding_Len = sizeof(DER_MD5_Encoding);
           break;

   }

   u1* msg  = messageToVerify->GetBuffer();
   u1* hash = dataToVerify->GetBuffer();

   // Check the decoded value against the expected data.
   if ((msg[0] != 0x00) || (msg[1] != 0x01)){
      return CKR_SIGNATURE_INVALID;
   }

   s4 posn = modulusLen - DER_Encoding_Len - dataToVerify->GetLength();

   for(s4 i = 2; i < (posn - 1); i++)
   {
      if(msg[i] != 0xFF){
         return CKR_SIGNATURE_INVALID;
      }
   }

   if(msg[posn - 1] != 0x00){
      return CKR_SIGNATURE_INVALID;
   }

   for (u4 i = 0; i < dataToVerify->GetLength(); i++){
      if (msg[posn + i + DER_Encoding_Len] != hash[i]){
         return CKR_SIGNATURE_INVALID;
      }
   }

   return CKR_OK;
}

CK_RV Token::VerifyRSAX509(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen)
{
   // reach the first non-zero bytes in decrypted signature
   // and data
   u4 pos1=0;
   u4 pos2=0;

   for(;pos1<dataToVerify->GetLength();pos1++){
      if(dataToVerify->GetBuffer()[pos1] != 0)
         break;
   }

   for(;pos2<messageToVerify->GetLength();pos2++){
      if(messageToVerify->GetBuffer()[pos2] != 0)
         break;
   }

   if((dataToVerify->GetLength() - pos1) != (modulusLen - pos2)){
      return CKR_SIGNATURE_INVALID;
   }

   for(u4 i=pos1,j=pos2;i<(modulusLen - pos2);i++,j++){
      if(dataToVerify->GetBuffer()[i] != messageToVerify->GetBuffer()[j]){
         return CKR_SIGNATURE_INVALID;
      }
   }

   return CKR_OK;
}

CK_RV Token::VerifyRSAPKCS1v15(u1Array* messageToVerify,u1Array* dataToVerify,u4 modulusLen)
{
   // skip past the pkcs block formatting data
   u4 pos = 2;
   for(;pos<modulusLen;pos++)
   {
      if(messageToVerify->GetBuffer()[pos] == 0x00)
      {
         pos++;
         break;
      }
   }

   if(dataToVerify->GetLength() != (modulusLen - pos)){
      return CKR_SIGNATURE_INVALID;
   }

   for(u4 i=0, j=pos;i< (modulusLen - pos); i++,j++){
      if(dataToVerify->GetBuffer()[i] != messageToVerify->GetBuffer()[j]){
         return CKR_SIGNATURE_INVALID;
      }
   }

   return CKR_OK;
}


CK_RV Token::Sign(StorageObject* privObj,u1Array* dataToSign,CK_ULONG mechanism,CK_BYTE_PTR pSignature)
{
   CK_RV rv = CKR_OK;
   TOKEN_TRY
   {
      u1Array* messageToSign = NULL_PTR;

      // TODO: Should check if cast is safe
      RSAPrivateKeyObject * rsaKey = static_cast<RSAPrivateKeyObject*>(privObj);
      CK_ULONG modulusLen = rsaKey->_modulus->GetLength();

      if(((mechanism == CKM_RSA_PKCS) && (dataToSign->GetLength() > modulusLen - 11)) ||
         ((mechanism == CKM_RSA_X_509) && (dataToSign->GetLength() > modulusLen)))
      {
         throw CkError(CKR_DATA_LEN_RANGE);
      }

      switch(mechanism){

            case CKM_RSA_PKCS:
               messageToSign = PadRSAPKCS1v15(dataToSign,modulusLen);
               break;

            case CKM_RSA_X_509:
               messageToSign = PadRSAX509(dataToSign,modulusLen);
               break;

            case CKM_SHA1_RSA_PKCS:
               messageToSign = EncodeHashForSigning(dataToSign,modulusLen,CKM_SHA_1);
               break;

            case CKM_SHA256_RSA_PKCS:
               messageToSign = EncodeHashForSigning(dataToSign,modulusLen,CKM_SHA256);
               break;

            case CKM_MD5_RSA_PKCS:
               messageToSign = EncodeHashForSigning(dataToSign,modulusLen,CKM_MD5);
               break;
      }

      u1Array* signatureData = NULL_PTR;

      //signatureData = this->_mscm->PrivateKeyDecrypt(rsaKey->_ctrIndex, rsaKey->_keySpec, messageToSign);

      int ntry = 0;
      while( ntry < MAX_RETRY )
      {
         try
         {
            ManageGC( );
            ntry++;
            signatureData = this->_mscm->PrivateKeyDecrypt(rsaKey->_ctrIndex, rsaKey->_keySpec, messageToSign);
            break;
         }
         catch( Marshaller::Exception & x )
         {
            CK_RV rv = CkError::CheckMarshallerException( x );
            if( CKR_DEVICE_MEMORY == rv )
            {
               Log::error( "Token::Sign", "ForceGarbageCollector" );
               _mscm->ForceGarbageCollector( );
               if( ntry >= MAX_RETRY )
               {
                  throw CkError( rv );
               }
            }
            else
            {
               throw CkError( rv );
            }
         }
      }

      memcpy(pSignature,signatureData->GetBuffer(),signatureData->GetLength());

      delete signatureData;
      delete messageToSign;
   }
   TOKEN_CATCH(rv)
      return rv;
}

// these methods should be moved to rsa library
// once we have it
u1Array* Token::PadRSAPKCS1v15(u1Array* dataToSign,CK_ULONG modulusLen)
{
   u1Array* messageToSign = new u1Array(modulusLen);
   memset(messageToSign->GetBuffer(),0,modulusLen);

   messageToSign->SetU1At(1,1);

   s4 offsetMessageToSign = modulusLen - dataToSign->GetLength() - 3;

   for(s4 i=0;i<offsetMessageToSign;i++){
      messageToSign->SetU1At(2+i,0xFF);
   }

   offsetMessageToSign += 3;

   memcpy((u1*)&messageToSign->GetBuffer()[offsetMessageToSign],dataToSign->GetBuffer(),dataToSign->GetLength());

   return messageToSign;
}

u1Array* Token::PadRSAX509(u1Array* dataToSign,CK_ULONG modulusLen)
{

   u1Array* messageToSign = new u1Array(modulusLen);
   memset(messageToSign->GetBuffer(),0,modulusLen);

   s4 offsetMessageToSign = modulusLen - dataToSign->GetLength();

   memcpy((u1*)&messageToSign->GetBuffer()[offsetMessageToSign],dataToSign->GetBuffer(),dataToSign->GetLength());

   return messageToSign;
}

u1Array* Token::EncodeHashForSigning(u1Array* hashedData,CK_ULONG modulusLen,CK_ULONG hashAlgo)
{
   u1 DER_SHA1_Encoding[]   = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
   u1 DER_SHA256_Encoding[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
   u1 DER_MD5_Encoding[]    = {0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10};

   u1* DER_Encoding = NULL_PTR;
   s4  DER_Encoding_Len = 0;

   switch(hashAlgo){
        case CKM_SHA_1:
           DER_Encoding_Len = sizeof(DER_SHA1_Encoding);
           DER_Encoding = new u1[DER_Encoding_Len]; //(u1*)malloc(DER_Encoding_Len);
           memcpy(DER_Encoding,DER_SHA1_Encoding,DER_Encoding_Len);
           break;

        case CKM_SHA256:
           DER_Encoding_Len = sizeof(DER_SHA256_Encoding);
           DER_Encoding = new u1[DER_Encoding_Len]; //(u1*)malloc(DER_Encoding_Len);
           memcpy(DER_Encoding,DER_SHA256_Encoding,DER_Encoding_Len);
           break;

        case CKM_MD5:
           DER_Encoding_Len = sizeof(DER_MD5_Encoding);
           DER_Encoding = new u1[DER_Encoding_Len]; //(u1*)malloc(DER_Encoding_Len);
           memcpy(DER_Encoding,DER_MD5_Encoding,DER_Encoding_Len);
           break;

   }

   u1Array* messageToSign = new u1Array(modulusLen);
   memset(messageToSign->GetBuffer(),0,modulusLen);

   messageToSign->SetU1At(1,1);

   // caluclate pos
   s4 pos = modulusLen - DER_Encoding_Len - hashedData->GetLength();

   for(s4 i=2;i<(pos - 1);i++){
      messageToSign->SetU1At(i,0xFF);
   }

   memcpy((u1*)&messageToSign->GetBuffer()[pos],DER_Encoding,DER_Encoding_Len);
   memcpy((u1*)&messageToSign->GetBuffer()[pos+DER_Encoding_Len],hashedData->GetBuffer(),hashedData->GetLength());

   delete DER_Encoding;

   return messageToSign;
}

bool Token::PerformDeferredDelete()
{
   bool fSync = true;
   PKCS11_ASSERT(this->_roleLogged != CKU_NONE);

   if(_toDelete.empty())
      return fSync;

   _cardCache->ClearFileList("mscp");
   _cardCache->ClearFileList("p11");

   // Delete files that are pending to be deleted
   vector<string>::iterator ifile = _toDelete.begin();
   while(ifile != _toDelete.end())
   {
      try
      {
         _cardCache->ClearFile(*ifile);
         _mscm->DeleteFile(&(*ifile));
         RegisterFileUpdate();
         ifile = _toDelete.erase(ifile);
      }
      catch(FileNotFoundException &)
      {
         ifile = _toDelete.erase(ifile);
      }
      catch(...)
      {
         // Failed to delete, keep it in the list.
         fSync = false;
         ++ifile;
      }
   }
   return fSync;
}

s4 Token::RegisterStorageObject(StorageObject * object)
{
   // add this in the token object list

   for(size_t k = 0; k<_objects.size(); k++)
   {
      PKCS11_ASSERT(_objects[k] != object);
   }


   size_t t = 0;
   while(t < _objects.size())
   {
      if(!_objects[t])
      {
         _objects[t] = object;
         return static_cast<s4>(t+1);
      }
      ++t;
   }
   // Expand list
   _objects.push_back(object);
   return static_cast<s4>(_objects.size());
}

void Token::UnregisterStorageObject(StorageObject * object)
{
   size_t t = 0;
   while(t<_objects.size())
   {
      if(_objects[t] == object)
      {
         _objects[t] = 0;
         break;
      }
      ++t;
   }
}

auto_ptr<u1Array> Token::ReadCertificateFile(string const & path)
{
   // Read certificate file

   const u1Array & compressedCert = _cardCache->ReadFile(path);

   // Decompress
   unsigned long origLen = compressedCert.ReadU1At(3) * 256 + compressedCert.ReadU1At(2);
   autoarray<u1> origData(new u1[origLen]);
   auto_ptr<u1Array> value(new u1Array(origLen));
   uncompress(value->GetBuffer(), &origLen, compressedCert.GetBuffer()+4, compressedCert.GetLength() - 4);
   return value;

}

void Token::RegisterPinUpdate()
{
   _fPinChanged = true;
}

void Token::RegisterContainerUpdate()
{
   _fContainerChanged = true;
}

void Token::RegisterFileUpdate()
{
   _fFileChanged = true;
}

//void Token::CheckAvailableSpace()
//{
//   return;
//
//   //u4 highWaterMark = 20000;
//   //auto_ptr<u4Array> freeSpace(_mscm->QueryFreeSpace());
//
//   //u4 availSpace = freeSpace->ReadU4At(2);
//   //if(availSpace < highWaterMark)
//   //    throw CkError(CKR_DEVICE_MEMORY);
//
//}


/*
*/
bool Token::isAuthenticated( void )
{
   bool bRet = false;
   try
   {
      bRet = (bool)(_mscm->IsAuthenticated( CARD_ROLE_USER ));
   }
   catch( ... )
   {
      Log::error( "Token::isAuthenticated",  "isAuthenticated" );
      bRet = false;
   }
   return bRet;
}


/*
*/
bool Token::isSSO( void )
{
   bool bRet = false;
   u1Array* ba = 0;
   try
   {
      ba = _mscm->GetCardProperty( 0x80, 0 );
   }
   catch( ... )
   {
      //Log::error( "Token::isSSO",  "GetCardProperty" );
      Log::log( "Token::isSSO - GetCardProperty failed !" );
      bRet = false;
   }
   if( 0 != ba )
   {
      bRet = (bool)(ba->GetBuffer( )[9]);

      /*
      log2( "Max Attempts <%d>", ba->GetBuffer( )[0] );
      log2( "Min Length <%d>", ba->GetBuffer( )[1] );
      log2( "Max Length <%d>", ba->GetBuffer( )[2] );
      log2( "Char Set <0x%02X>", ba->GetBuffer( )[3] );
      log2( "Complexity rule 1 <%d>", ba->GetBuffer( )[4] );
      log2( "Complexity rule 2 <%d>", ba->GetBuffer( )[5] );
      log2( "Adjacent allowed <%s>", ba->GetBuffer( )[6] ? "Yes" : "No" );
      log2( "History <%d>", ba->GetBuffer( )[7] );
      log2( "Unblock allowed <%s>", ba->GetBuffer( )[8] ? "Yes" : "No" );
      log2( "SSO allowed <%s>", ba->GetBuffer( )[9] ? "Yes" : "No" );

      std::string s6 = ba->GetBuffer( )[6] ? "YES" : "NO";
      std::string s8 = ba->GetBuffer( )[8] ? "YES" : "NO";
      std::string s9 = ba->GetBuffer( )[9] ? "YES" : "NO";
      std::string s3 = "";
      translateToHex( ba->GetBuffer( )[3], s3 );

      if( ( ba->GetBuffer( )[0] != m_iMaxAttemps )
      || ( ba->GetBuffer( )[1] != m_iMinLength )
      || ( ba->GetBuffer( )[2] != m_iMaxLength )
      || ( s3 != m_stCharSet )
      || ( ba->GetBuffer( )[4] != m_iComplexityRule1 )
      || ( ba->GetBuffer( )[5] != m_iComplexityRule2 )
      || ( s6 != m_stAdjacentAllowed )
      || ( ba->GetBuffer( )[7] != m_iHistory )
      || ( s8 != m_stAllowUnblock )
      || ( s9 != m_stAllowSSO ) )
      {
      bRet = false;
      error( "check pin policy" );
      }
      */

      delete ba;
   }
   return bRet;
}


/*
*/
void Token::CardBeginTransaction( )
{
   //Log::begin( "Token::CardBeginTransaction" );

   //Log::log( "Token::CardBeginTransaction - _mscm->GetPcscCardHandle..." );
   SCARDHANDLE hCard = _mscm->GetPcscCardHandle( );
   //Log::log( "Token::CardBeginTransaction - hCard <%#02x>", hCard );

   if( !hCard )
   {
      Log::error( "Token::CardBeginTransaction",  "CKR_FUNCTION_FAILED" );
      throw CkError( CKR_FUNCTION_FAILED );
   }

   LONG hResult = SCardBeginTransaction( hCard );
   while( SCARD_W_RESET_CARD == hResult )
   {
      _roleLogged = CKU_NONE;
      DWORD dwActiveProtocol;

      //Log::log( "Token::CardBeginTransaction - SCardReconnect..." );
      LONG hr = SCardReconnect( hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &dwActiveProtocol );
      //Log::log( "Token::CardBeginTransaction - hr <%#02x>", hr );
      if( SCARD_S_SUCCESS == hr )
      {
         //Log::log( "Token::CardBeginTransaction - SCardBeginTransaction..." );
         hResult = SCardBeginTransaction( hCard );
         //Log::log( "Token::CardBeginTransaction - hResult <%#02x>", hResult );
      }
      else
      {
         Log::log( "Token::CardBeginTransaction - ## ERROR ## PcscError <%#02x>", hr );
         Log::error( "Token::CardBeginTransaction",  "PcscError" );
         throw PcscError( hr );
      }
   };


   if( hResult != SCARD_S_SUCCESS )
   {
      Log::log( "Token::CardBeginTransaction - ## ERROR ## hResult <%#02x>", hResult );
      Log::error( "Token::CardBeginTransaction",  "PcscError" );
      throw PcscError( hResult );
   }

   //Log::end( "Token::CardBeginTransaction" );
}


void Token::CardEndTransaction()
{
   //Log::begin( "Token::CardEndTransaction" );

   SCARDHANDLE hCard = _mscm->GetPcscCardHandle( );//_mscm->GetSCardHandle();
   if(!hCard)
      throw CkError(CKR_FUNCTION_FAILED);

   LONG hResult = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
#ifdef __APPLE__
   while((hResult == SCARD_W_RESET_CARD) || (hResult == SCARD_W_REMOVED_CARD))
#else
   while(hResult == SCARD_W_RESET_CARD)
#endif
   {
      _roleLogged = CKU_NONE;
      DWORD dwActiveProtocol;
      LONG hr = SCardReconnect(hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,SCARD_LEAVE_CARD,&dwActiveProtocol);
      if(hr == SCARD_S_SUCCESS)
         hResult = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
      else
         throw PcscError(hr);
   }
   if(hResult != SCARD_S_SUCCESS && hResult != SCARD_E_NOT_TRANSACTED) // SCARD_E_NOT_TRANSACTED shouldn't occur, still ignore it.
      throw PcscError(hResult);

   //Log::end( "Token::CardEndTransaction" );
}

StorageObject * Token::GetObject(CK_OBJECT_HANDLE hObject)
{
   CK_LONG idx = (CK_LONG)(hObject & CO_OBJECT_HANDLE_MASK);

   if((idx < 1) || (idx > static_cast<CK_LONG>(_objects.size())) || !_objects[idx-1])
      throw CkError(CKR_OBJECT_HANDLE_INVALID);

   return _objects[idx-1];
}


void CMapFileClear(u1Array & file, u1 index)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD;
   memset(file.GetBuffer()+idx, 0, SIZE_CONTAINERMAPRECORD);
}

void CMapFileSetName(u1Array & file, u1 index, string const & name)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_GUID_INFO;
   memset(file.GetBuffer()+idx, 0, 80);
   const size_t length = name.size() > 39 ? 39 : name.size();
   for(size_t i = 0; i<length; i++)
      file.SetU1At(idx + 2*i, name[i]); // Convert to wchar, little endian.
}

u1 CMapFileGetFlag(u1Array const & file, u1 index)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_FLAGS;
   return file.ReadU1At(idx);
}

void CMapFileSetFlag(u1Array & file, u1 index, u1 flag)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_FLAGS;
   file.SetU1At(idx, flag);
}

u2 CMapFileGetSignSize(u1Array const & file, u1 index)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_SIG_KEY_SIZE;
   return LittleEndianToInt<u2>(file.GetBuffer(), idx);
}

void CMapFileSetSignSize(u1Array & file, u1 index, u2 size)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_SIG_KEY_SIZE;
   IntToLittleEndian<u2>(size, file.GetBuffer(), idx);
}

u2 CMapFileGetExchSize(u1Array const & file, u1 index)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_EXC_KEY_SIZE;
   return LittleEndianToInt<u2>(file.GetBuffer(), idx);
}

void CMapFileSetExchSize(u1Array & file, u1 index, u2 size)
{
   u4 idx = index * SIZE_CONTAINERMAPRECORD + IDX_EXC_KEY_SIZE;
   IntToLittleEndian<u2>(size, file.GetBuffer(), idx);
}


/*
*/
bool Token::isPinPadSupported( void )
{
   // Get Reader Features
   BYTE  outBuffer[256];
   memset( outBuffer, 0, sizeof( outBuffer ) );
   DWORD dwLen = 0;
   LONG lRet = SCardControl( _mscm->GetPcscCardHandle( ), CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, outBuffer, sizeof(outBuffer), &dwLen );

   // Search IOCTL of Verify PIN feature
   int i = 0;
   bool isVerifyPin = false;
   m_dwIoctlVerifyPIN = 0;
   if ( ( SCARD_S_SUCCESS == lRet ) && ( dwLen > 0 ) )
   {
      while( ( i + 6 ) <= (int)dwLen )
      {
         // Search Verify PIN feature Tag
         if (  (outBuffer[i] == FEATURE_VERIFY_PIN_DIRECT)
            &&(outBuffer[i+1] == 4)
            )
         {
            m_dwIoctlVerifyPIN += (outBuffer[i+2] << 24);
            m_dwIoctlVerifyPIN += (outBuffer[i+3] << 16);
            m_dwIoctlVerifyPIN += (outBuffer[i+4] << 8);
            m_dwIoctlVerifyPIN += outBuffer[i+5];

            isVerifyPin = true;

            break;
         }
         else
         {
            i += (outBuffer[i+1] + 2);
         }
      }
   }

   return (isVerifyPin);
}


/*
*/
bool Token::isPinExternalSupported( void )
{
   bool bIsPinExternalSupported = false;

   u1Array* pinProperties = new u1Array( 0 );
   try
   {
      pinProperties = _mscm->GetCardProperty( CARD_PROPERTY_PIN_INFO, CARD_ROLE_USER );

      if( CARD_PROPERTY_EXTERNAL_PIN == pinProperties->GetBuffer( )[ 0 ] )
      {
         bIsPinExternalSupported = true;
      }
   }
   catch( ... )
   {
   }

   delete pinProperties;

   return bIsPinExternalSupported;
}

/*
*/
CK_RV Token::verifyPinWithPinPad( void )
{
   DWORD PinId = CARD_ROLE_USER;
   LONG                 lRet;
   BYTE                 offset;
   DWORD                dwSendLen;
   PIN_VERIFY_STRUCTURE pin_verify;
   BYTE                 inBuffer[256];
   DWORD                dwInLen = 0;
   BYTE                 outBuffer[256];
   DWORD                dwOutLen = 0;

   pin_verify.bTimerOut = 30;                               /* Time out between key stroke = max(bTimerOut, bTimerOut2). Must be between 15 and 40 sec.*/
   pin_verify.bTimerOut2 = 00;

   pin_verify.bmFormatString = 0x82;                        /* Padding V2=0x82 */

   pin_verify.bmPINBlockString = 0x06;
   pin_verify.bmPINLengthFormat = 0x00;
   pin_verify.bPINMaxExtraDigit1 = 0x08;                    /* Max */
   pin_verify.bPINMaxExtraDigit2 = 0x04;                    /* Min */
   pin_verify.bEntryValidationCondition = 0x02;             /* validation key pressed */
   pin_verify.bNumberMessage = 0x01;
   pin_verify.wLangId = 0x0904;
   pin_verify.bMsgIndex = 0x00;
   pin_verify.bTeoPrologue[0] = 0x00;
   pin_verify.bTeoPrologue[1] = 0x00;
   pin_verify.bTeoPrologue[2] = 0x00;                       /* pin_verify.ulDataLength = 0x00; we don't know the size yet */

   offset = 0;
   pin_verify.abData[offset++] = 0x00;                      /* CLA */ /*********************************/
   pin_verify.abData[offset++] = 0x20;                      /* INS: VERIFY */
   pin_verify.abData[offset++] = 0x00;                      /* P1: always 0 */
   pin_verify.abData[offset++] = (BYTE)PinId;               /* P2: PIN reference */
   pin_verify.abData[offset++] = 0x08;                      /* Lc: 8 data bytes */

   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */
   pin_verify.abData[offset++] = 0xFF;                      /* 'FF' */

   pin_verify.ulDataLength = offset;                        /* APDU size */
   dwSendLen = sizeof(PIN_VERIFY_STRUCTURE);

   // Select MSCM Application
   inBuffer[0] = 0x00;   //CLA
   inBuffer[1] = 0xA4;   //INS
   inBuffer[2] = 0x04;   //P1
   inBuffer[3] = 0x00;   //P2
   inBuffer[4] = 0x04;   //Li

   memcpy(&inBuffer[5], "MSCM", 4);

   dwInLen = 5 + inBuffer[4];

   dwOutLen = sizeof(outBuffer);
   memset(outBuffer, 0x00, sizeof(outBuffer));

   lRet = SCardTransmit(_mscm->GetPcscCardHandle(),
      SCARD_PCI_T0,
      inBuffer,
      dwInLen,
      NULL,
      outBuffer,
      &dwOutLen
      );

   // Send Verify command to the reader
   dwOutLen = 0;
   memset(outBuffer, 0x00, sizeof(outBuffer));

   lRet = SCardControl(_mscm->GetPcscCardHandle(),
      m_dwIoctlVerifyPIN,
      (BYTE *)&pin_verify,
      dwSendLen,
      outBuffer,
      sizeof(outBuffer),
      &dwOutLen
      );

   Log::log( "Token::verifyPinWithPinPad - sw <%#02x %#02x>", outBuffer[ 0 ], outBuffer[ 1 ] );

   CK_RV rv = CKR_FUNCTION_FAILED;
   if( ( 0x90 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) )
   {
      //this->_tokenInfo.flags &= ~CKF_USER_PIN_LOCKED;
      //this->_tokenInfo.flags &= ~CKF_USER_PIN_FINAL_TRY;
      //this->_tokenInfo.flags &= ~CKF_USER_PIN_COUNT_LOW;
      //this->_roleLogged = CKU_USER;
      rv = CKR_OK;
   }
   else if( ( 0x63 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) )
   {
      rv = CKR_PIN_INCORRECT;
   }
   // operation was cancelled by the ‘Cancel’ button
   else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x01 == outBuffer[ 1 ] ) )
   {
      //return SCARD_W_CANCELLED_BY_USER;
      rv = CKR_FUNCTION_CANCELED;
   }
   // operation timed out
   else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x00 == outBuffer[ 1 ] ) )
   {
      //return SCARD_E_TIMEOUT;
      rv = CKR_FUNCTION_CANCELED;
   }
   // operation timed out
   else if( ( 0x64 == outBuffer[ 0 ] ) && ( 0x03 == outBuffer[ 1 ] ) )
   {
      //return SCARD_E_TIMEOUT;
      rv = CKR_PIN_INCORRECT;
   }

   Log::log( "Token::verifyPinWithPinPad - rv <%#02x>", rv );

   return rv;
}


/*
*/
CK_RV Token::verifyPinWithBio( void /*Marshaller::u1Array *pin*/ )
{
   Log::log( "Token::verifyPinWithBio - <BEGIN>" );

   CK_RV rv = CKR_GENERAL_ERROR;

#ifdef WIN32
   // Get the current OS version
   OSVERSIONINFO osvi;
   memset( &osvi, 0, sizeof( OSVERSIONINFO ) );
   osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
   GetVersionEx(&osvi);
   // Check if the Os is W7 or W2K8R2
   if( ( 6 == osvi.dwMajorVersion ) && ( osvi.dwMinorVersion >= 1 ) )
   {
      Log::log( "Token::verifyPinWithBio - Os is W7 or W2K8R2" );

      CardEndTransaction( );

      // The OS is W7 or W2K8R2
      HMODULE hDll = NULL;
      LRESULT lRes = GSC_OK;
      LRESULT (WINAPI *ptr_SetUITitles) (WCHAR*, WCHAR*);
      LRESULT (WINAPI *ptr_AuthenticateUserCard) ();

      // Load DLL
      hDll = LoadLibraryA("GemSelCert.dll");
      Log::log( "Token::verifyPinWithBio - load lib" );

      if( 0 != hDll )
      {
         // Set UI Titles
         ptr_SetUITitles = (LRESULT (WINAPI *) (WCHAR*, WCHAR*))GetProcAddress(hDll,"SetUITitles");
         if( NULL != ptr_SetUITitles )
         {
            ptr_SetUITitles(L"Smartcard Security", L"User authentication");
            Log::log( "Token::verifyPinWithBio - ptr_SetUITitles" );

            // Authenticate Card User
            ptr_AuthenticateUserCard = (LRESULT (WINAPI *)())GetProcAddress(hDll,"AuthenticateUserCard");
            if( NULL != ptr_AuthenticateUserCard )
            {
               lRes = ptr_AuthenticateUserCard();
               Log::log( "Token::verifyPinWithBio - ptr_AuthenticateUserCard" );

               switch(lRes)
               {
               case GSC_OK:
                  rv = CKR_OK;
                  Log::log( "Token::verifyPinWithBio - CKR_OK" );
                  break;

               case GSC_CANCEL:
                  rv = CKR_FUNCTION_CANCELED;
                  Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_CANCELED" );
                  break;

               case GSC_NO_CERT:
                  rv = CKR_KEY_NEEDED;
                  Log::log( "Token::verifyPinWithBio - CKR_KEY_NEEDED" );
                  break;

               case GSC_NO_CARD:
                  rv = CKR_TOKEN_NOT_RECOGNIZED;
                  Log::log( "Token::verifyPinWithBio - CKR_TOKEN_NOT_RECOGNIZED" );
                  break;

               case GSC_WRONG_PIN:
                  rv = CKR_PIN_INCORRECT;
                  Log::log( "Token::verifyPinWithBio - CKR_PIN_INCORRECT" );
                  break;

               case GSC_READ_CARD:
                  rv = CKR_FUNCTION_FAILED;
                  Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_FAILED" );
                  break;

               case GSC_WRITE_CARD:
                  rv = CKR_FUNCTION_FAILED;
                  Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_FAILED" );
                  break;

               default:
                  Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_FAILED" );
                  rv = CKR_FUNCTION_FAILED;
                  break;
               }
            }
         }

         // Release DLL
         FreeLibrary(hDll);
         Log::log( "Token::verifyPinWithBio - FreeLibrary" );
      }

      CardBeginTransaction( );
   }
   // The OS is Vista or XP
   else
   {
      Log::log( "Token::verifyPinWithBio - Os is Vista or XP" );

      CBioMan* pBioMan = NULL;
      DWORD dwRes = BIO_ERR_NOT_SUPPORTED;

      // Init BioMan helper
      pBioMan = new CBioMan( );
      Log::log( "Token::verifyPinWithBio - new" );
      pBioMan->Connect( this->_mscm );
      Log::log( "Token::verifyPinWithBio - connect" );

      // Biometrics Verification
      dwRes = pBioMan->VerifyBio( );
      Log::log( "Token::verifyPinWithBio - verify bio" );

      delete pBioMan;
      Log::log( "Token::verifyPinWithBio - delete" );

      // Error ?
      switch( dwRes )
      {
      case BIO_ERR_SUCCESS:
         Log::log( "Token::verifyPinWithBio - CKR_OK" );
         rv = CKR_OK;
         break;

      case BIO_ERR_NO_CARD:
         Log::log( "Token::verifyPinWithBio - CKR_TOKEN_NOT_PRESENT" );
         rv = CKR_TOKEN_NOT_PRESENT;
         break;

      case BIO_ERR_NOT_SUPPORTED:
      case BIO_ERR_NO_FINGER:
         Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_NOT_SUPPORTED" );
         //this->_mscm->VerifyPin( CARD_ROLE_USER, pin );
         rv = CKR_FUNCTION_NOT_SUPPORTED; //CKR_OK;
         break;

      case BIO_ERR_BIO_NOT_CHECKED:
      case BIO_ERR_PIN_NOT_CHECKED:
         Log::log( "Token::verifyPinWithBio - CKR_PIN_INCORRECT" );
         rv = CKR_PIN_INCORRECT;
         break;

      case BIO_ERR_BIO_LAST:
      case BIO_ERR_PIN_LAST:
         Log::log( "Token::verifyPinWithBio - CKR_PIN_INCORRECT" );
         rv = CKR_PIN_INCORRECT;
         break;

      case BIO_ERR_BLOCKED:
         Log::log( "Token::verifyPinWithBio - CKR_PIN_INCORRECT" );
         rv = CKR_PIN_INCORRECT;
         break;

      case BIO_ERR_ABORT:
         Log::log( "Token::verifyPinWithBio - CKR_FUNCTION_FAILED" );
         rv = CKR_FUNCTION_FAILED;
         break;

      default:
         Log::log( "Token::verifyPinWithBio - CKR_GENERAL_ERROR" );
         rv = CKR_GENERAL_ERROR;
         break;
      }
   }
#endif

   Log::log( "Token::verifyPinWithBio - <END>" );

   return rv;
}


/*
*/
void Token::getCardConfiguration( BYTE& a_bMode, BYTE &a_bTypePIN )
{
   a_bMode = UVM_PIN_ONLY;
   a_bTypePIN = PIN_TYPE_REGULAR;

   u1Array* ba = new u1Array( 0 );

   try
   {
      ba = _mscm->GetCardProperty( CARD_PROPERTY_PIN_INFO_EX, CARD_ROLE_USER );

      DWORD dwFlagsEx = (DWORD)(
         ba->GetBuffer( )[ 12 ] +
         ( ( ba->GetBuffer( )[ 13 ] ) << 8 ) +
         ( ( ba->GetBuffer( )[ 14 ] ) << 16 ) +
         ( ( ba->GetBuffer( )[ 15 ] ) << 24 )
         );
      Log::log( "Token::getCardMode - dwFlagsEx <%#08x>", dwFlagsEx );

      WORD wActiveMode = (WORD)( ba->GetBuffer( )[ 12 ] + ( ( ba->GetBuffer( )[ 13 ] ) << 8 ) );
      Log::log( "Token::getCardMode - Active mode <%ld>", wActiveMode );

      a_bMode = (BYTE)wActiveMode;

      a_bTypePIN = (BYTE)ba->GetBuffer( )[ 0 ];
   }
   catch( ... )
   {
      Log::log( "Token::getCardMode - PIN_INFO_EX not supported - Default values used" );
      a_bMode = UVM_PIN_ONLY;
      a_bTypePIN = PIN_TYPE_REGULAR;
   }

   delete ba;
}
