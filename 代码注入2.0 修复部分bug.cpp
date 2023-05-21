#include <iostream>
#include <Windows.h>
#define FILE_PATH "C:\\Program Files (x86)\\Thunder Network\\Thunder\\Program\\ThunderStart.exe"
#define NEW_FILE_PATH "C:\\Program Files (x86)\\Thunder Network\\Thunder\\Program\\new_ThunderStart.exe"

VOID PrintSectionName(PIMAGE_SECTION_HEADER peSectionHeader, DWORD NumberOfSections) {
	for (int i = 0; i < NumberOfSections; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%c", peSectionHeader->Name[j]);
		}
		printf("\nMisc.VirtualSize : %x", peSectionHeader->Misc.VirtualSize);
		printf("\nPointerToRawData : %x", peSectionHeader->PointerToRawData);
		printf("\nSizeOfRawData : %x", peSectionHeader->SizeOfRawData);
		printf("\nVirtualAddress : %x\n\n", peSectionHeader->VirtualAddress);
		peSectionHeader++;
	}
};

VOID SectionFileCopyToImage(PIMAGE_SECTION_HEADER peSectionHeader, DWORD NumberOfSections, LPVOID lpFileBuffer, LPVOID lpImageBuffer) {
	for (int i = 0; i < NumberOfSections; i++) {
		DWORD dwVirOffset = peSectionHeader->VirtualAddress;	//内存偏移
		DWORD dwRawOffset = peSectionHeader->PointerToRawData;	//文件偏移
		DWORD dwSizeOfRawData = peSectionHeader->SizeOfRawData;	//大小
		LPVOID lpFileBufferOffset = (LPVOID)((DWORD)lpFileBuffer + dwRawOffset);
		LPVOID lpImageBufferOffset = (LPVOID)((DWORD)lpImageBuffer + dwVirOffset);

		memcpy(lpImageBufferOffset, lpFileBufferOffset, dwSizeOfRawData);
		peSectionHeader++;
	}
};

VOID SectionImageCopyToNew(PIMAGE_SECTION_HEADER peSectionHeader, DWORD NumberOfSections, LPVOID lpImageBuffer, LPVOID pNewBuffer) {
	for (int i = 0; i < NumberOfSections; i++) {
		DWORD dwVirOffset = peSectionHeader->VirtualAddress;	//内存偏移
		DWORD dwRawOffset = peSectionHeader->PointerToRawData;	//文件偏移
		DWORD dwSizeOfRawData = peSectionHeader->SizeOfRawData;	//大小
		LPVOID lpNewBufferOffset = (LPVOID)((DWORD)pNewBuffer + dwRawOffset);
		LPVOID lpImageBufferOffset = (LPVOID)((DWORD)lpImageBuffer + dwVirOffset);

		memcpy(lpNewBufferOffset, lpImageBufferOffset, dwSizeOfRawData);
		peSectionHeader++;
	}
};

DWORD GetFileSize(PIMAGE_SECTION_HEADER peSectionHeader, DWORD NumberOfSections) {
	for (int i = 0; i < NumberOfSections; ) {
		peSectionHeader++;
		i++;
		if (i == NumberOfSections -1 )
		{
			return (peSectionHeader->PointerToRawData + peSectionHeader->SizeOfRawData);
		}
	}
};

DWORD My_ReadFile(OUT LPVOID* lpFileBuffer) {
	//变量区
	DWORD dwFile_Size = 0;		//文件大小
	LPVOID pFileBuffer = NULL;	//堆区指针
	size_t elements_read = 0;	//写入大小

	//1.创建文件指针
	FILE* pFile;

	//2.打开文件
	fopen_s(&pFile, FILE_PATH, "rb");
	if (!pFile) {
		printf("打开文件失败! \n");
		return 0;
	}

	//3.储存文件的大小
	fseek(pFile, 0, SEEK_END);
	dwFile_Size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	//4.开辟内存空间
	pFileBuffer = calloc(dwFile_Size, 1);
	if (!pFileBuffer) {
		printf("内存开辟失败! \n");
		fclose(pFile);
		return 0;
	}

	//5.将文件内容写入到缓冲区
	elements_read = fread(pFileBuffer, 1, dwFile_Size, pFile);
	if (!elements_read) {
		printf("文件写入失败! \n");
		fclose(pFile);
		free(pFileBuffer);
		return 0;
	}
	*lpFileBuffer = pFileBuffer;
	pFileBuffer = NULL;
	fclose(pFile);
	return elements_read;
}

DWORD FileBufferToImageBuffer(IN LPVOID lpFileBuffer, OUT LPVOID* lpImageBuffer) {
	//变量区
	PIMAGE_DOS_HEADER peDosHeader = NULL;			//DOS头
	PIMAGE_NT_HEADERS peNTHeader = NULL;			//NT头
	PIMAGE_FILE_HEADER pePEHeader = NULL;			//PE头
	PIMAGE_OPTIONAL_HEADER peOptionHeader = NULL;	//可选PE头
	PIMAGE_SECTION_HEADER peSectionHeader = NULL;	//节表
	LPVOID pImageBuffer = NULL;						//堆区指针
	size_t elements_read;							//保存大小
	
	peDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
	if (peDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("不是有效的PE文件! \n");
		return 0;
	}
	printf("e_lfanew : %x\n", peDosHeader->e_lfanew);
	
	peNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffer + peDosHeader->e_lfanew);
	if (peNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("不是有效的PE文件! \n");
		return 0;
	}

	pePEHeader = (PIMAGE_FILE_HEADER)((DWORD)lpFileBuffer + peDosHeader->e_lfanew + 0x4);
	printf("NumberOfSections : %d \n", pePEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader : 0x%x \n", pePEHeader->SizeOfOptionalHeader);

	peOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)lpFileBuffer + peDosHeader->e_lfanew + 0x4 + 0x14);
	printf("AddressOfEntryPoint : %x \n", peOptionHeader->AddressOfEntryPoint);
	printf("ImageBase : %x \n", peOptionHeader->ImageBase);
	printf("SizeOfHeaders : %x \n", peOptionHeader->SizeOfHeaders);
	printf("SizeOfImage : %x \n\n", peOptionHeader->SizeOfImage);

	peSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileBuffer + peDosHeader->e_lfanew + 0x18 + pePEHeader->SizeOfOptionalHeader);
	PrintSectionName(peSectionHeader, pePEHeader->NumberOfSections);

	//开辟堆区空间
	pImageBuffer = calloc(peOptionHeader->SizeOfImage, 1);
	if (!pImageBuffer) {
		printf("内存开辟失败! \n");
		return 0;
	}
	//拷贝SizeOfHeaders
	memcpy(pImageBuffer, lpFileBuffer, peOptionHeader->SizeOfHeaders);

	//循环拷贝Section
	SectionFileCopyToImage(peSectionHeader, pePEHeader->NumberOfSections, lpFileBuffer, pImageBuffer);

	//返回指针
	*lpImageBuffer = pImageBuffer;
	return 1;

}

DWORD ImageBufferToNewBuffer(IN LPVOID lpImageBuffer, OUT LPVOID* lpNewBuffer) {
	//变量区
	PIMAGE_DOS_HEADER peDosHeader = NULL;			//DOS头
	PIMAGE_NT_HEADERS peNTHeader = NULL;			//NT头
	PIMAGE_FILE_HEADER pePEHeader = NULL;			//PE头
	PIMAGE_OPTIONAL_HEADER peOptionHeader = NULL;	//可选PE头
	PIMAGE_SECTION_HEADER peSectionHeader = NULL;	//节表
	LPVOID pNewBuffer = NULL;						//堆区指针
	size_t elements_read;							//保存大小
	size_t NewBuffer_size;							//文件大小

	peDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	peNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpImageBuffer + peDosHeader->e_lfanew);
	pePEHeader = (PIMAGE_FILE_HEADER)((DWORD)lpImageBuffer + peDosHeader->e_lfanew + 0x4);
	peOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)lpImageBuffer + peDosHeader->e_lfanew + 0x4 + 0x14);
	peSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpImageBuffer + peDosHeader->e_lfanew + 0x18 + pePEHeader->SizeOfOptionalHeader);

	//判断空间大小
	NewBuffer_size = GetFileSize(peSectionHeader, pePEHeader->NumberOfSections);
	if (NewBuffer_size == 0)
	{
		printf("获取文件大小失败! \n");
		return 0;
	}

	//开辟堆区空间
	pNewBuffer = calloc(NewBuffer_size, 1);
	if (!pNewBuffer) {
		printf("内存开辟失败! \n");
		return 0;
	}
	//拷贝SizeOfHeaders
	memcpy(pNewBuffer, lpImageBuffer, peOptionHeader->SizeOfHeaders);

	//循环拷贝Section
	SectionImageCopyToNew(peSectionHeader, pePEHeader->NumberOfSections, lpImageBuffer, pNewBuffer);

	//返回指针
	*lpNewBuffer = pNewBuffer;
	return NewBuffer_size;
};

DWORD CreateNewFile(IN LPVOID lpNewBuffer, IN DWORD NewBuffer_size, OUT LPSTR lpszFile) {
	HANDLE hFile = NULL;
	LPDWORD lpNumberOfBytesWritten = NULL;
	errno_t err;
	hFile = CreateFileA(lpszFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed CODE:%d\n", GetLastError());
		return 0;
	}
	err = WriteFile(hFile, lpNewBuffer, NewBuffer_size, lpNumberOfBytesWritten, NULL);
	if (!err)
	{
		printf("WriteFile failed CODE:%d\n", GetLastError());
		CloseHandle(hFile);
		return 0;
	}
	printf("写入成功 写入文件大小为:%d \n", (DWORD)lpNumberOfBytesWritten);
	return (DWORD)lpNumberOfBytesWritten;

	return 0;
};

int main()
{   
	LPVOID lpFileBuffer = NULL;
	LPVOID lpImageBuffer = NULL;
	LPVOID lpNewBuffer = NULL;
	DWORD NewBuffer_size = 0;

	size_t elements_read = 0;
	elements_read = My_ReadFile(&lpFileBuffer);
	if (lpFileBuffer == NULL || elements_read == 0) {
		printf("文件写入失败! 写入数据:%d字节\n", elements_read);
	}

	FileBufferToImageBuffer(lpFileBuffer, &lpImageBuffer);

	NewBuffer_size = ImageBufferToNewBuffer(lpImageBuffer, &lpNewBuffer);

	CreateNewFile(lpNewBuffer, NewBuffer_size,(LPSTR)NEW_FILE_PATH);

	return 0;
}
