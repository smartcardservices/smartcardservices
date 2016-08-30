//
// main.cpp - Entry point for testing the PKCS11 library
//

#include <stdio.h>
#include <unistd.h>

//#define LPSCARD_READERSTATE LPSCARD_READERSTATE_A
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

//==============================
int main(int argC, char** argV)
//==============================
{
	printf("\nSCardConnect Test\n\n");

	for (int i=0; i<100; i++)
	{
		// Direct call to Establish Context:
		LONG retVal;
		SCARDCONTEXT hSC;
		retVal =  SCardEstablishContext( SCARD_SCOPE_SYSTEM,NULL,NULL, &hSC );
		if (retVal) {
			printf("Failed to establish context %d, Error: %X %s\n", i, retVal, pcsc_stringify_error(retVal));
		}
		else
		{
			printf("Direct establish context %d succeeded!\n", i);
		}
		sleep(1);
	}

	return 0;
}
