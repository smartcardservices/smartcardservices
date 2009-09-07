# Makefile for doing a test build and then installing source for SecurityExamples
# Created on 07/19/05 By John Hurley <jhurley@apple.com>
# Based on Makefile for CoreDataExamples

Project = ccid

#
# Top-level Makefile for SmartcardCCID Allows build or clean
# of all directories in one swoop.  
#

.PHONY: installsrc clean installhdrs install

SUBPROJECTS = libusb ccid

installsrc::
	@cp -R Makefile $(SUBPROJECTS) $(SRCROOT)
	
install::
	@echo "the proj is: " $(Project)
	@for proj in $(SUBPROJECTS); do \
		mkdir -p $(SYMROOT)/$${proj}; \
	done
	(cd $(SRCROOT)/$(Project)/ccid && ./MacOSX/configure --no-configure --disable-opensc )

installsrc clean installhdrs install::
	@for proj in $(SUBPROJECTS); do \
		(cd $${proj} && make $@ \
			SRCROOT=$(SRCROOT)/$${proj} \
			OBJROOT=$(OBJROOT)/$${proj} \
			SYMROOT=$(SYMROOT)/$${proj} \
			DSTROOT=$(DSTROOT) \
		) || exit 1; \
	done
