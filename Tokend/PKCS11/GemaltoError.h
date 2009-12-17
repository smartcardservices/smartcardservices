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
 *  GemaltoError.h
 *  Gemalto.tokend
 */

#ifndef _GEMALTOERROR_H_
#define _GEMALTOERROR_H_

#include <security_utilities/debugging.h>
#include <security_utilities/errors.h>
#include "cryptoki.h"


class CKError : public Security::CommonError
{
protected:
	CKError(CK_RV rv);
public:
    const CK_RV resultValue;
    virtual OSStatus osStatus() const;
	virtual int unixError() const;
    virtual const char *what () const throw ();

    static void check(CK_RV rv)	{ if (rv != CKR_OK) throwMe(rv); }
    static void throwMe(CK_RV rv) __attribute__((noreturn));
protected:
    //IFDEBUG(void debugDiagnose(const void *id) const;)
	void debugDiagnose(const void *id) const;
};

#endif /* !_GEMALTOERROR_H_ */


/* arch-tag: 8B34BC1C-124C-11D9-B7AA-000A9595DEEE */
