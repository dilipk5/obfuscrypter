#ifndef IPV4_H
#define IPV4_H

#include <stdio.h>
#include <Windows.h>

BOOL GenerateIpv4Output(unsigned char* pShellcode, size_t sShellcode);
BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

#endif