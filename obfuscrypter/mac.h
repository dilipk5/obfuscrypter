#ifndef MAC_H
#define MAC_H

#include <stdio.h>
#include <Windows.h>

BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

#endif