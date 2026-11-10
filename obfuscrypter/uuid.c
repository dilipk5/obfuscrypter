#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- */
/*  GenerateUUid: builds "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" from 16 bytes */
/*  Byte order: Data1 (b0..b3), Data2 (b4,b5), Data3 (b6,b7) are printed      */
/*  reversed because UuidFromStringA stores them little-endian in memory.     */
/*  Bytes 8..15 are printed in order.                                         */
/*  Returns a malloc'd 37-byte string (caller must free), or NULL on error.   */
/* ------------------------------------------------------------------------- */
char* GenerateUUid(BYTE a, BYTE b, BYTE c, BYTE d,
    BYTE e, BYTE f, BYTE g, BYTE h,
    BYTE i, BYTE j, BYTE k, BYTE l,
    BYTE m, BYTE n, BYTE o, BYTE p)
{
    char* out = (char*)malloc(37);          /* 36 chars + NUL */
    if (out == NULL)
        return NULL;

    int written = sprintf_s(out, 37,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        d, c, b, a,          /* Data1: bytes 0..3, reversed */
        f, e,                /* Data2: bytes 4,5, reversed  */
        h, g,                /* Data3: bytes 6,7, reversed  */
        i, j,                /* bytes 8,9                   */
        k, l, m, n, o, p);   /* bytes 10..15                */

    if (written != 36) {     /* malformed -> bail */
        free(out);
        return NULL;
    }
    return out;
}


/* ------------------------------------------------------------------------- */
/*  GenerateUuidOutput: prints a C array literal of UUID strings.            */
/* ------------------------------------------------------------------------- */
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize)
{
    if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 16 != 0) {
        printf("[!] Shellcode size must be non-zero and a multiple of 16 (got %zu)\n",
            ShellcodeSize);
        return FALSE;
    }

    printf("char* UuidArray[%zu] = {\n\t", ShellcodeSize / 16);

    SIZE_T counter = 0;
    for (SIZE_T i = 0; i + 15 < ShellcodeSize; i += 16) {

        char* uuid = GenerateUUid(
            pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
            pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
            pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
            pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]);

        if (uuid == NULL) {
            printf("\n};\n\n");
            return FALSE;
        }

        counter++;

        if (i + 16 >= ShellcodeSize)
            printf("\"%s\"", uuid);           /* last element: no trailing comma */
        else
            printf("\"%s\", ", uuid);

        free(uuid);                           /* free the heap string */

        if (counter % 3 == 0 && i + 16 < ShellcodeSize)
            printf("\n\t");
    }

    printf("\n};\n\n");
    return TRUE;
}

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR	StringUuid,
    UUID* Uuid
    );

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE          pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T         sBuffSize = 0;

    RPC_STATUS     STATUS = 0;

    // Getting UuidFromStringA address from Rpcrt4.dll
    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (pUuidFromStringA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Getting the real size of the shellcode which is the number of UUID strings * 16
    sBuffSize = NmbrOfElements * 16;

    // Allocating memory which will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;

    // Loop through all the UUID strings saved in UuidArray
    for (int i = 0; i < NmbrOfElements; i++) {

        // Deobfuscating one UUID string at a time
        // UuidArray[i] is a single UUID string from the array UuidArray
        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
            // if it failed
            printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
            return FALSE;
        }

        // 16 bytes are written to TmpBuffer at a time
        // Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
        TmpBuffer = (PBYTE)(TmpBuffer + 16);

    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    return TRUE;
}