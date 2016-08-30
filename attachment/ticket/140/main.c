#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>

int main(int argc, const char * argv[]) {
    SCARDCONTEXT hContext;
    char *szChosenReader;
    char *mszReaders;
    DWORD err = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (err != 0) {
        printf("SCardEstablishContext : %08x\n", err);
    } else {
        DWORD cchReaders = 0;
        err = SCardListReaders(hContext, "SCard$AllReaders", NULL, &cchReaders);
        if (err != 0) {
            printf("SCardListReaders : %08x\n", err);
        } else {
            mszReaders = calloc(cchReaders, sizeof(char));
            if (mszReaders == NULL) {
                perror("calloc for SCardListReaders");
            } else {
                err = SCardListReaders(hContext, "SCard$AllReaders", mszReaders, &cchReaders);
                if (err != 0) {
                    printf("SCardListReaders : %08x\n", err);
                } else if ('\0' == *mszReaders) {
                    printf("There are no smart card readers. Please plug one in.\n");
                } else {
                    DWORD cReaders = 0;
                    for (char *readerName = mszReaders; *readerName != '\0'; readerName += strlen(readerName) + 1) {
                        printf("Found reader %s\n", readerName);
                        cReaders++;
                    }
                    szChosenReader = mszReaders;
                    SCARD_READERSTATE readerState;
                    memset(&readerState, 0, sizeof(SCARD_READERSTATE));
                    readerState.szReader = szChosenReader;
                    readerState.dwCurrentState = SCARD_STATE_UNAWARE;
                    err = SCardGetStatusChange(hContext, 0, &readerState, 1);
                    if (err != 0) {
                        printf("SCardGetStatusChange : %08x\n", err);
                    } else if (! (SCARD_STATE_PRESENT & readerState.dwEventState)) {
                        printf("Card is not present in %s. Please insert smart card.\n", szChosenReader);
                    } else {
                        SCARDHANDLE hCard;
                        DWORD dwActiveProtocol;
                        err = SCardConnect(hContext, szChosenReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, &hCard, &dwActiveProtocol);
                        if (err != 0) {
                            printf("SCardConnect: %08x\n", err);
                        } else {
                            DWORD chReaderLen;
                            err = SCardStatus(hCard, NULL, &chReaderLen, NULL, NULL, NULL, NULL);
                            if (err != 0) {
                                printf("SCardStatus without buf: %08x\n", err);
                            } else {
                                LPTSTR mszReaderNames = calloc(chReaderLen, sizeof(char));
                                if (NULL == mszReaderNames) {
                                    perror("calloc for SCardStatus");
                                } else {
                                    DWORD dwState;
                                    DWORD dwProtocol;
                                    BYTE atr[32];
                                    DWORD cbAtrLen = 32;
                                    err = SCardStatus(hCard, mszReaderNames, &chReaderLen, &dwState, &dwProtocol, atr, &cbAtrLen);
                                    if (err != 0) {
                                        printf("SCardStatus with buf: %08x\n", err);
                                    } else {
                                        printf("State: %d, protocol: %d, ATR length: %d\n", dwState, dwProtocol, cbAtrLen);
                                        BOOL gotMultiStringEnd = 0;
                                        for (DWORD i = 0; i < chReaderLen; i += strlen(mszReaderNames + i) + 1) {
                                            char *readerName = mszReaderNames + i;
                                            if ('\0' == *readerName) {
                                                gotMultiStringEnd = 1;
                                                break;
                                            }
                                            printf("Name of reader: %s\n", readerName);
                                        }
                                        if (! gotMultiStringEnd) {
                                            fprintf(stderr, "SCardStatus reader names multistring did not end with empty string!\n");
                                        }
                                    }
                                    free(mszReaderNames);
                                }
                            }
                            err = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
                            if (err != 0) {
                                printf("SCardDisconnect: %08x\n", err);
                            }
                        }
                    }
                }
                free(mszReaders);
            }
        }
    }
    err = SCardReleaseContext(hContext);
    if (err != 0) printf("SCardReleaseContext: %08x\n", err);
    return 0;
}