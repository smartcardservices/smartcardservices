lib_LTLIBRARIES = libgtop11dotnet.la

libgtop11dotnet_la_LDFLAGS = -shared

libgtop11dotnet_la_SOURCES = \
	algo_des.cpp \
	algo_des.h \
	algo_md5.cpp \
	algo_md5.h \
	algo_sha1.cpp \
	algo_sha1.h \
	algo_sha256.cpp \
	algo_sha256.h \
	algo_utils.cpp \
	algo_utils.h \
	Application.cpp \
	Application.hpp \
	Array.cpp \
	Array.hpp \
	attrcert.cpp \
	attrcert.h \
	autogen.sh \
	beroctet.cpp \
	beroctet.h \
	cardmod.h \
	CardModuleService.cpp \
	CardModuleService.hpp \
	cert_utils.cpp \
	cert_utils.h \
	Configuration.cpp \
	Configuration.hpp \
	cr_digit.cpp \
	cr_digit.h \
	cr_global.h \
	cr_nn.cpp \
	cr_nn.h \
	cr_random.cpp \
	cr_random.h \
	cr_rsa.cpp \
	cr_rsa.h \
	cryptoki.h \
	des.cpp \
	des.h \
	Device.cpp \
	Device.hpp \
	DeviceMonitor.cpp \
	DeviceMonitor.hpp \
	Digest.cpp \
	digest.h \
	DigestMD5.cpp \
	DigestSHA1.cpp \
	DigestSHA256.cpp \
	Except.h \
	ha_config.h \
	IDeviceMonitorListener.hpp \
	Log.cpp \
	Log.hpp \
	MarshallerCfg.h \
	Marshaller.cpp \
	Marshaller.h \
	MarshallerUtil.cpp \
	MarshallerUtil.h \
	md5.h \
	MiniDriverAuthentication.cpp \
	MiniDriverAuthentication.hpp \
	MiniDriverCardCacheFile.cpp \
	MiniDriverCardCacheFile.hpp \
	MiniDriverContainer.cpp \
	MiniDriverContainer.hpp \
	MiniDriverContainerMapFile.cpp \
	MiniDriverContainerMapFile.hpp \
	MiniDriver.cpp \
	MiniDriverException.hpp \
	MiniDriverFiles.cpp \
	MiniDriverFiles.hpp \
	MiniDriver.hpp \
	MiniDriverPinPolicy.cpp \
	MiniDriverPinPolicy.hpp \
	Module.cpp \
	pbbase.h \
	PCSC.cpp \
	PCSC.h \
	PKCS11.cpp \
	PKCS11Exception.hpp \
	PCSCMissing.h \
	pkcs11f.h \
	pkcs11.h \
	Pkcs11ObjectCertificate.cpp \
	Pkcs11ObjectCertificate.hpp \
	Pkcs11ObjectCertificateX509PublicKey.cpp \
	Pkcs11ObjectCertificateX509PublicKey.hpp \
	Pkcs11ObjectData.cpp \
	Pkcs11ObjectData.hpp \
	Pkcs11ObjectKey.cpp \
	Pkcs11ObjectKey.hpp \
	Pkcs11ObjectKeyPrivate.cpp \
	Pkcs11ObjectKeyPrivate.hpp \
	Pkcs11ObjectKeyPrivateRSA.cpp \
	Pkcs11ObjectKeyPrivateRSA.hpp \
	Pkcs11ObjectKeyPublic.cpp \
	Pkcs11ObjectKeyPublic.hpp \
	Pkcs11ObjectKeyPublicRSA.cpp \
	Pkcs11ObjectKeyPublicRSA.hpp \
	Pkcs11ObjectStorage.cpp \
	Pkcs11ObjectStorage.hpp \
	pkcs11t.h \
	pkcs-11v2-20a3.h \
	Session.cpp \
	Session.hpp \
	sha1.h \
	sha256.h \
	Slot.cpp \
	Slot.hpp \
	SmartCardReader.cpp \
	SmartCardReaderException.hpp \
	SmartCardReader.hpp \
	symmalgo.cpp \
	symmalgo.h \
	tdes.cpp \
	tdes.h \
	Template.cpp \
	Template.hpp \
	Timer.cpp \
	Timer.hpp \
	Token.cpp \
	Token.hpp \
	util.cpp \
	util.h \
	version.hpp \
	x509cert.cpp \
	x509cert.h

AM_CPPFLAGS = -DCRYPTOKI_EXPORTS=1 \
	-DUNIX $(PTHREAD_CFLAGS) \
	-Wall \
	-Wextra \
	-pedantic

if ENABLE_SYSTEM_BOOST
else
BOOST_INCLUDES = -I../boost_1_46_1
BOOST_LIB = -L../boost_1_46_1/stage/lib
endif

INCLUDES = \
	$(BOOST_INCLUDES) \
	$(PCSC_CFLAGS)

LIBS = \
    $(PCSC_LIBS) \
	-lz \
	$(BOOST_LIB) \
    -lboost_date_time \
    -lboost_filesystem \
    -lboost_serialization \
    -lboost_system \
    -lboost_thread \
    -lpthread
     
EXTRA_DIST = autogen.sh c-mac.sh ./docs/LGPL-2.1 ./docs/Release_Notes_Linux.pdf ./docs/PKCS\#11_Libs_.NET_Linux_User_Guide.pdf ./config/Gemalto.NET.PKCS11.ini

# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
install-exec-hook:
	$(MKDIR_P) $(DESTDIR)/$(prefix)/lib/pkcs11
	cd $(DESTDIR)/$(prefix)/lib/pkcs11 ; rm -f libgtop11dotnet.@DYN_LIB_EXT@ ; $(LN_S) ../libgtop11dotnet.@DYN_LIB_EXT@

