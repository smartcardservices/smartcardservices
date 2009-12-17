/*
 *  Copyright (c) 2008-2009 Gemalto <support@gemalto.com>
 * 
 *  @APPLE_LICENSE_HEADER_START@
 *  
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *  
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *  
 *  @APPLE_LICENSE_HEADER_END@
 */

/*
 * Gemalto.cpp - Gemalto.tokend main program
 */

#include "GemaltoToken.h"


static void terminate(int /*sig*/)
{
	delete token;
	_exit(0);
}

int main(int argc, const char *argv[])
{
	secdebug("Gemalto.tokend", "main starting with %d arguments", argc);
	secdelay("/tmp/delay/Gemalto");

	signal(SIGTERM, terminate);
	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);

	token = new GemaltoToken();
	return SecTokendMain(argc, argv, token->callbacks(), token->support());
}

/* arch-tag: 8B9B7BB4-124C-11D9-ACF9-000A9595DEEE */
