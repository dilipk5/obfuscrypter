#include "xor.h"
#include <windows.h>

VOID XorByiKey(IN PBYTE pShellcode, IN SIZE_T sShellcodesize, IN BYTE bKey)
{

	for (size_t i = 0; i < sShellcodesize; i++)
	{
		pShellcode[i] = pShellcode[i] ^ (bKey + 1);
	}
}