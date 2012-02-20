lib_LTLIBRARIES = libgtop11dotnet.la

libgtop11dotnet_la_LDFLAGS = -shared

libgtop11dotnet_la_SOURCES = \
	$(top_srcdir)/cppMarshaller/Array.cpp \
	$(top_srcdir)/cppMarshaller/Array.h \
	$(top_srcdir)/cppMarshaller/Except.h \
	$(top_srcdir)/cppMarshaller/MarshallerCfg.h \
	$(top_srcdir)/cppMarshaller/Marshaller.cpp \
	$(top_srcdir)/cppMarshaller/Marshaller.h \
	$(top_srcdir)/cppMarshaller/PCSC.cpp \
	$(top_srcdir)/cppMarshaller/PCSC.h \
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
	application.cpp \
	application.h \
	attrcert.cpp \
	attrcert.h \
	beroctet.cpp \
	beroctet.h \
	cardcache.cpp \
	cardcache.h \
	cardmoduleservice.cpp \
	cardmoduleservice.h \
	certificateobject.cpp \
	certificateobject.h \
	cert_utils.cpp \
	cert_utils.h \
	config.h \
	critsect.cpp \
	critsect.h \
	dataobject.cpp \
	dataobject.h \
	des.cpp \
	des.h \
	digest.cpp \
	digest.h \
	error.cpp \
	error.h \
	event.cpp \
	event.h \
	keyobject.cpp \
	keyobject.h \
	md5.cpp \
	md5.h \
	mutex.cpp \
	mutex.h \
	pkcs11.cpp \
	pkcs11f.h \
	pkcs11.h \
	pkcs11t.h \
	platconfig.h \
	privatekeyobject.cpp \
	privatekeyobject.h \
	publickeyobject.cpp \
	publickeyobject.h \
	resource.h \
	rsa/cr_digit.cpp \
	rsa/cr_digit.h \
	rsa/cr_global.h \
	rsa/cr_nn.cpp \
	rsa/cr_nn.h \
	rsa/cr_random.cpp \
	rsa/cr_random.h \
	rsa/cr_rsa.cpp \
	rsa/cr_rsa.h \
	rsa/ha_config.h \
	rsaprivatekeyobject.cpp \
	rsaprivatekeyobject.h \
	rsapublickeyobject.cpp \
	rsapublickeyobject.h \
	sctoken.cpp \
	sctoken.h \
	secretkeyobject.cpp \
	secretkeyobject.h \
	session.cpp \
	session.h \
	sha1.cpp \
	sha1.h \
	sha256.cpp \
	sha256.h \
	slot.cpp \
	slot.h \
	stdafx.cpp \
	stdafx.h \
	storageobject.cpp \
	storageobject.h \
	symmalgo.cpp \
	symmalgo.h \
	tdes.cpp \
	tdes.h \
	template.cpp \
	template.h \
	thread.cpp \
	thread.h \
	timer.cpp \
	timer.h \
	transaction.cpp \
	transaction.h \
	util.cpp \
	util.h \
	x509cert.cpp \
	x509cert.h \
	x509pubkeycertobject.cpp \
	x509pubkeycertobject.h \
	log.h \
	log.cpp

AM_CPPFLAGS = -DINCLUDE_EVENTING=1 -DCRYPTOKI_EXPORTS=1 \
	-DUNIX $(PTHREAD_CFLAGS) \
	-Wall \
	-Wextra \
	-pedantic

INCLUDES = \
	-I$(top_srcdir)/cppMarshaller \
	-I$(top_srcdir)/PKCS11Module2 \
	-I$(top_srcdir)/PKCS11Module2/rsa \
	$(PCSC_CFLAGS)

LIBS = $(PCSC_LIBS) $(PTHREAD_LIBS) -lz

# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
install-exec-hook:
	$(MKDIR_P) $(DESTDIR)/$(prefix)/lib/pkcs11
	cd $(DESTDIR)/$(prefix)/lib/pkcs11 ; rm -f libgtop11dotnet.@DYN_LIB_EXT@ ; $(LN_S) ../libgtop11dotnet.@DYN_LIB_EXT@

