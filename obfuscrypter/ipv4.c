#include <stdio.h>
#include <Windows.h>

// Method - 1 -> IPV4fuscation

// takes 4 raw bytes and returns them in a inpv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {
	static char Output[32];

	sprintf_s(Output, sizeof(Output), "%d.%d.%d.%d", a, b, c, d);
	return Output;
}

// Generate the ipv4 output representation of the shellcode 
// function takes a pointer or base address to the shellcode buffer and the size of the shellcode buffer

BOOL GenerateIpv4Output(unsigned char* pShellcode, size_t sShellcode) {
	if (pShellcode == NULL || sShellcode == 0 || sShellcode % 4 != 0) {
		return FALSE;
	}
	printf("char* IPv4Array[%d] = { \n", sShellcode / 4);

	// we will read one shellcode byte at a time, when the total is 4, begin generating the ipv4 address
	// the var c is used to store the number of bytes read, by default starts at 4.

	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < sShellcode; i++) {
		// tracking the number of bytes read and when they reach 4 we enter this statement to begin generating the ipv4 address

		if (c == 4) {
			counter++;
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
			if (i == sShellcode - 4) {
				printf("\t\"%s\"\n", IP);
				break;
			}
			else {
				printf("\t\"%s\",\n", IP);
			}
			c = 1;
		}
		else { c++; }
	}
	printf("}\n");
	return TRUE;
}

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR* Terminator,
	PVOID		Addr
	);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T          sBuffSize = 0;

	PCSTR           Terminator = NULL;

	NTSTATUS        STATUS = 0;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}