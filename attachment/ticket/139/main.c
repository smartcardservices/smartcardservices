//
//  main.c
//  TestSCard
//
//  Created by IT on 26/11/14.
//  Copyright (c) 2014 IT. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include "reader.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    SCARDCONTEXT hContext;
    LPSTR mszReaders;
    DWORD err = SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&hContext);
    if (err != 0) {
        printf("ScardEstqblishedContext : %08x\n",err);
    } else {
        DWORD cchReaders = 0;
        err = SCardListReaders(hContext, "SCard$AllReaders", NULL, &cchReaders);
        if (err != 0) {
            printf("ScardListReaders : %08x\n",err);
            return 0;
        }
        mszReaders = calloc(cchReaders, sizeof(char));
        if (!mszReaders) {
            printf("calloc\n");
            return 0;
        }
        err = SCardListReaders(hContext,"SCard$AllReaders", mszReaders, &cchReaders);
        if (err != 0) {
            printf("ScardListReaders : %08x\n",err);
            return 0;
        }
        
        printf("Reader : %s\n", mszReaders);
        
        SCARDHANDLE hCard;
        DWORD dwActiveProtocol;
        err = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_RAW, &hCard, &dwActiveProtocol);
        if (err != 0) {
            printf("ScardConnect : %08x\n",err);
        } else {
            DWORD dwAtrLen = 32;
            err = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, NULL, &dwAtrLen);
            printf("ATR LENGTH : %1d\n", dwAtrLen);
            if (err != 0) {
                printf("SCardGetAttrib : %08x\n",err);
            } else {
                printf("ATR LENGTH %1d\n", dwAtrLen);
                SCardDisconnect(hCard, SCARD_LEAVE_CARD);
                SCardReleaseContext(hContext);
            }
        }
    }
    return 0;
}
