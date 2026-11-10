#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <time.h>

#define KEYSIZE 32
#define IVSIZE 16
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _AES {

    PBYTE	pPlainText;         // base address of the plain text data 
    DWORD	dwPlainSize;        // size of the plain text data

    PBYTE	pCipherText;        // base address of the encrypted data	
    DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)

    PBYTE	pKey;               // the 32 byte key
    PBYTE	pIv;                // the 16 byte iv

} AES, * PAES;

BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);

#endif