/******************************************************************************
** 
**  $Id$
**
**  Package: PKCS-11
**  Author : Chris Osgood <oznet@mac.com>
**  License: Copyright (C) 2002 Schlumberger Network Solutions
**           <http://www.slb.com/sns>
**  Purpose: Support for Linux (maybe others) shared library unloading.
**           This will automatically get called by the runtime system when the
**           library is finalized (just in case the application hasn't closed
**           everything down). 
** 
******************************************************************************/
#ifdef __USE_FINI__

#include "cryptoki.h"

void _fini()
{
   C_Finalize(0);
}

#endif
