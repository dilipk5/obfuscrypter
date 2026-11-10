#ifndef UUID_H
#define UUID_H

#include <stdio.h>
#include <Windows.h>

BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

#endif