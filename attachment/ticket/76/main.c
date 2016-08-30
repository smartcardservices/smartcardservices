#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdio.h>
#include <stdlib.h>

static void check(LONG rv, const char *file, int line) 
{
	if (rv != SCARD_S_SUCCESS)
	{
		printf("%s:%d ERROR: %s\n", file, line, pcsc_stringify_error(rv));
		exit(1);
	}
}

#define CHECK(rv)  check(rv, __FILE__, __LINE__)

int main(void) 
{
	SCARDCONTEXT hContext = 0;
	SCARDHANDLE hCard = 0;
	int i;
	LPSTR mszReaders = 0;
	DWORD dwReaders = 0;
	LONG rv;
    
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	CHECK(rv);
	printf("hContext: %d\n", hContext);
    
	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	CHECK(rv);
	mszReaders = (char *) malloc(sizeof(char) * dwReaders);
    
	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	CHECK(rv);
    
	LPCSTR reader = mszReaders;	// use first reader if any
	DWORD dwActiveProtocol = 0;
	rv = SCardConnect(hContext, reader, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
	CHECK(rv);
    
	for (i = 1;; i++)
	{
		printf("%d\n", i);
		rv = SCardConnect(hContext, reader, SCARD_SHARE_SHARED,
                          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard,
                          &dwActiveProtocol);
		CHECK(rv);
	}
	return 0;
}
