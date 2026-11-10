#ifndef IPV6_H
#define IPV6_H

#include <stdio.h>
#include <Windows.h>

BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T sShellcode);
BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);
#endif