#include <iostream>
#include <iomanip>
#include <windows.h>
using namespace std;

#define OFFSET(structure, member) ((int64_t)&((structure*)0)->member)
#define MY_File_Path "C:\\Windows\\System32\\notepad.exe"
#define	格式控制符 setw(25) << left
#define	格式控制符HEX setw(12) << left << showbase <<  hex
#define 默认 "\033[0m" <<
#define 红色 "\033[31m"<<
#define 绿色 "\033[32m"<<
#define 黄色 "\033[33m"<<
#define 蓝色 "\033[34m"<<
#define 斜体 "\033[3m" <<

LPVOID My_OpenFile(LPSTR File_Path) {
	DWORD File_Size = NULL;	//保存文件大小
	LPVOID File_Buffer = NULL;	//内存开辟空间
	FILE* File_Pointer;	//定义文件指针
	fopen_s(&File_Pointer, File_Path, "rb");	//读取文件(文件指针,文件路径,打开方式)

	if (!File_Pointer) {
		cout << "文件打开失败! 错误代码:Luxun001" << endl;
		return NULL;
	}
	else {
		fseek(File_Pointer, 0, SEEK_END);	//将文件指针指向末尾(文件指针,偏移量,origin)
		/*************************************
		SEEK_CUR -> 文件当前位置	Current position of file pointer
		SEEK_END -> 文件末尾		End of file
		SEKK_SET -> 文件起始位置	Beginning of file
		其中SEEK_SET,SEEK_CUR和SEEK_END依次为0，1和2
		*************************************/

		File_Size = ftell(File_Pointer);	//获取当前文件大小 -> ftell - 返回文件指针相对起始位置的偏移量

		File_Buffer = malloc(File_Size);	//开辟内存空间,大小为File_Size
		if (!File_Buffer)
		{
			cout << "文件打开失败! 错误代码:Luxun002" << endl;
			fclose(File_Pointer);
			return NULL;
		}
		else {
			rewind(File_Pointer); //或者使用 fseek(File_Pointer, 0, SEEK_SET)
			size_t conut = fread(File_Buffer, File_Size, 1, File_Pointer);
			if (!conut) {
				cout << "文件读取失败! 错误代码:Luxun003" << endl;
				fclose(File_Pointer);
				free(File_Buffer);
				return NULL;
			}
			else {
				//执行正文
				cout << "执行成功!!!" << endl;
				fclose(File_Pointer);
				return File_Buffer;
			}
		}
	}
}


int main()
{
	PIMAGE_DOS_HEADER PE_DosHeader = NULL;	//DOS头
	PIMAGE_NT_HEADERS32 PE_NTHeader = NULL;		//NT头
	PIMAGE_FILE_HEADER PE_PEHeader = NULL;	//PE头
	PIMAGE_OPTIONAL_HEADER32 PE_OptionHeader = NULL;	//可选PE头
	PIMAGE_SECTION_HEADER PE_SectionHeader = NULL;	//节表

	LPVOID File_Buffer = My_OpenFile((LPSTR)MY_File_Path);
	if (!File_Buffer)
	{
		cout << "文件读取失败! 错误代码:Luxun004" << endl;	
		return NULL;
	}else if(*((PWORD)File_Buffer) != IMAGE_DOS_SIGNATURE)
	{
		cout << "不是有效的PE标志文件! 错误代码:Luxun005" << endl;
		free(File_Buffer);
		return NULL;
	}
	else {
		PE_DosHeader = (PIMAGE_DOS_HEADER)File_Buffer;
		cout << 蓝色 "-----------------------------------DOS头部信息(BEGIN)-----------------------------------" << endl << endl;
		cout << 默认 格式控制符HEX << "地址偏移" << 格式控制符 << "变量名" << 格式控制符HEX << "大小" << 格式控制符HEX << "数值" << 格式控制符 << "说明" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_magic) << 格式控制符 << "e_magic" << 格式控制符HEX << sizeof(PE_DosHeader->e_magic) << 格式控制符HEX << PE_DosHeader->e_magic << 格式控制符 << "DOS 头的标识，通常为 \"MZ\"" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_cblp) << 格式控制符 << "e_cblp" << 格式控制符HEX << sizeof(PE_DosHeader->e_cblp) << 格式控制符HEX << PE_DosHeader->e_cblp << 格式控制符 << "文件的最后一页包含的字节数" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_cp) << 格式控制符 << "e_cp" << 格式控制符HEX << sizeof(PE_DosHeader->e_cp) << 格式控制符HEX << PE_DosHeader->e_cp << 格式控制符 << "文件中的页数" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_crlc) << 格式控制符 << "e_crlc" << 格式控制符HEX << sizeof(PE_DosHeader->e_crlc) << 格式控制符HEX << PE_DosHeader->e_crlc << 格式控制符 << "重定位表的数量" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_cparhdr) << 格式控制符 << "e_cparhdr" << 格式控制符HEX << sizeof(PE_DosHeader->e_cparhdr) << 格式控制符HEX << PE_DosHeader->e_cparhdr << 格式控制符 << "头部大小，以段为单位" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_minalloc) << 格式控制符 << "e_minalloc" << 格式控制符HEX << sizeof(PE_DosHeader->e_minalloc) << 格式控制符HEX << PE_DosHeader->e_minalloc << 格式控制符 << "程序运行所需的最小附加段数" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_maxalloc) << 格式控制符 << "e_maxalloc" << 格式控制符HEX << sizeof(PE_DosHeader->e_maxalloc) << 格式控制符HEX << PE_DosHeader->e_maxalloc << 格式控制符 << "程序运行所需的最大附加段数" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_ss) << 格式控制符 << "e_ss" << 格式控制符HEX << sizeof(PE_DosHeader->e_ss) << 格式控制符HEX << PE_DosHeader->e_ss << 格式控制符 << "SS 寄存器的初始值" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_sp) << 格式控制符 << "e_sp" << 格式控制符HEX << sizeof(PE_DosHeader->e_sp) << 格式控制符HEX << PE_DosHeader->e_sp << 格式控制符 << "SP 寄存器的初始值" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_csum) << 格式控制符 << "e_csum" << 格式控制符HEX << sizeof(PE_DosHeader->e_csum) << 格式控制符HEX << PE_DosHeader->e_csum << 格式控制符 << "校验和，用于验证文件的完整性" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_ip) << 格式控制符 << "e_ip" << 格式控制符HEX << sizeof(PE_DosHeader->e_ip) << 格式控制符HEX << PE_DosHeader->e_ip << 格式控制符 << "IP 寄存器的初始值" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_cs) << 格式控制符 << "e_cs" << 格式控制符HEX << sizeof(PE_DosHeader->e_cs) << 格式控制符HEX << PE_DosHeader->e_cs << 格式控制符 << "CS 寄存器的初始值" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_lfarlc) << 格式控制符 << "e_lfarlc" << 格式控制符HEX << sizeof(PE_DosHeader->e_lfarlc) << 格式控制符HEX << PE_DosHeader->e_lfarlc << 格式控制符 << "重定位表的文件地址" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_ovno) << 格式控制符 << "e_ovno" << 格式控制符HEX << sizeof(PE_DosHeader->e_ovno) << 格式控制符HEX << PE_DosHeader->e_ovno << 格式控制符 << "覆盖号，通常为 0" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_oemid) << 格式控制符 << "e_oemid" << 格式控制符HEX << sizeof(PE_DosHeader->e_oemid) << 格式控制符HEX << PE_DosHeader->e_oemid << 格式控制符 << "OEM 标识符" << endl;
		cout << 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_oeminfo) << 格式控制符 << "e_oeminfo" << 格式控制符HEX << sizeof(PE_DosHeader->e_oeminfo) << 格式控制符HEX << PE_DosHeader->e_oeminfo << 格式控制符 << "OEM 信息" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_DOS_HEADER, e_lfanew) << 格式控制符 << "e_lfanew" << 格式控制符HEX << sizeof(PE_DosHeader->e_lfanew) << 格式控制符 << PE_DosHeader->e_lfanew << 格式控制符 << "PE 头的文件地址" << endl;
	}
	if (*((PDWORD)((DWORD)File_Buffer + PE_DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		cout << 默认 "不是有效的PE标志文件! 错误代码:Luxun006" << endl;
		free(File_Buffer);
		return NULL;
	}
	else {
		PE_NTHeader = (PIMAGE_NT_HEADERS32)((DWORD)File_Buffer+ PE_DosHeader->e_lfanew);
		PE_PEHeader = (PIMAGE_FILE_HEADER)(((DWORD)File_Buffer + PE_DosHeader->e_lfanew+4));
		PE_OptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)File_Buffer + PE_DosHeader->e_lfanew + 0x18);
		PE_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)File_Buffer + PE_DosHeader->e_lfanew + 0xf8);
		DWORD SectionCount = PE_PEHeader->NumberOfSections;
		DWORD NToffset = PE_DosHeader->e_lfanew;
		DWORD FileOffset = PE_DosHeader->e_lfanew + 4;
		DWORD SectionOffset = PE_DosHeader->e_lfanew + 0xf8;
		DWORD OpOffset = OFFSET(IMAGE_FILE_HEADER, Characteristics) + FileOffset + 2;
		cout << 黄色 "----------------------------------NT头部信息(BEGIN)----------------------------------" << endl;
		cout << 默认 格式控制符HEX << "地址偏移" << 格式控制符 << "变量名" << 格式控制符HEX << "大小" << 格式控制符HEX << "数值" << 格式控制符 << "说明" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_NT_HEADERS32, Signature) + NToffset << 格式控制符 << "Signature" << 格式控制符HEX << sizeof(PE_NTHeader->Signature) << 格式控制符HEX << PE_NTHeader->Signature << 格式控制符 << "PE 文件的标识 \"PE\"" << endl;


		cout << 黄色 "----------------------------------  PE头信息[0]  ----------------------------------" << endl;
		cout << 默认 格式控制符HEX << "地址偏移" << 格式控制符 << "变量名" << 格式控制符HEX << "大小" << 格式控制符HEX << "数值" << 格式控制符 << "说明" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, Machine) + FileOffset << 格式控制符 << "Machine" << 格式控制符HEX << sizeof(PE_PEHeader->Machine) << 格式控制符HEX << PE_PEHeader->Machine << 格式控制符 << "可执行文件的CPU类型" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, NumberOfSections) + FileOffset << 格式控制符 << "NumberOfSections" << 格式控制符HEX << sizeof(PE_PEHeader->NumberOfSections) << 格式控制符HEX << PE_PEHeader->NumberOfSections << 格式控制符 << "文件中的节表数量" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, TimeDateStamp) + FileOffset << 格式控制符 << "TimeDateStamp" << 格式控制符HEX << sizeof(PE_PEHeader->TimeDateStamp) << 格式控制符HEX << PE_PEHeader->TimeDateStamp << 格式控制符 << "文件创建的时间和日期" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, PointerToSymbolTable) + FileOffset << 格式控制符 << "PointerToSymbolTable" << 格式控制符HEX << sizeof(PE_PEHeader->PointerToSymbolTable) << 格式控制符HEX << PE_PEHeader->PointerToSymbolTable << 格式控制符 << "符号表的偏移地址" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, NumberOfSymbols) + FileOffset << 格式控制符 << "NumberOfSymbols" << 格式控制符HEX << sizeof(PE_PEHeader->NumberOfSymbols) << 格式控制符HEX << PE_PEHeader->NumberOfSymbols << 格式控制符 << "符号表的记录数" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, SizeOfOptionalHeader) + FileOffset << 格式控制符 << "SizeOfOptionalHeader" << 格式控制符HEX << sizeof(PE_PEHeader->SizeOfOptionalHeader) << 格式控制符HEX << PE_PEHeader->SizeOfOptionalHeader << 格式控制符 << "可选头的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_FILE_HEADER, Characteristics) + FileOffset << 格式控制符 << "Characteristics" << 格式控制符HEX << sizeof(PE_PEHeader->Characteristics) << 格式控制符HEX << PE_PEHeader->Characteristics << 格式控制符 << "描述文件的特性" << endl;


		cout << 黄色 "----------------------------------可选PE头信息[1]----------------------------------" << endl;
		cout << 默认 格式控制符HEX << "地址偏移" << 格式控制符 << "变量名" << 格式控制符HEX << "大小" << 格式控制符HEX << "数值" << 格式控制符 << "说明" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, Magic) + OpOffset << 格式控制符 << "Magic" << 格式控制符HEX << sizeof(PE_OptionHeader->Magic) << 格式控制符HEX << PE_OptionHeader->Magic << 格式控制符 << "标识该文件的位数32|64" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfCode) + OpOffset << 格式控制符 << "SizeOfCode" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfCode) << 格式控制符HEX << PE_OptionHeader->SizeOfCode << 格式控制符 << "代码节的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfInitializedData) + OpOffset << 格式控制符 << "SizeOfInitializedData" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfInitializedData) << 格式控制符HEX << PE_OptionHeader->SizeOfInitializedData << 格式控制符 << "初始化数据节的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfUninitializedData) + OpOffset << 格式控制符 << "SizeOfUninitializedData" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfUninitializedData) << 格式控制符HEX << PE_OptionHeader->SizeOfUninitializedData << 格式控制符 << "未初始化数据节的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint) + OpOffset << 格式控制符 << "AddressOfEntryPoint" << 格式控制符HEX << sizeof(PE_OptionHeader->AddressOfEntryPoint) << 格式控制符HEX << PE_OptionHeader->AddressOfEntryPoint << 格式控制符 << "程序入口点" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, BaseOfCode) + OpOffset << 格式控制符 << "BaseOfCode" << 格式控制符HEX << sizeof(PE_OptionHeader->BaseOfCode) << 格式控制符HEX << PE_OptionHeader->BaseOfCode << 格式控制符 << "代码节在内存中的基址" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, BaseOfData) + OpOffset << 格式控制符 << "BaseOfData" << 格式控制符HEX << sizeof(PE_OptionHeader->BaseOfData) << 格式控制符HEX << PE_OptionHeader->BaseOfData << 格式控制符 << "数据节在内存中的基址" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, ImageBase) + OpOffset << 格式控制符 << "ImageBase" << 格式控制符HEX << sizeof(PE_OptionHeader->ImageBase) << 格式控制符HEX << PE_OptionHeader->ImageBase << 格式控制符 << "程序在内存中的基址" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SectionAlignment) + OpOffset << 格式控制符 << "SectionAlignment" << 格式控制符HEX << sizeof(PE_OptionHeader->SectionAlignment) << 格式控制符HEX << PE_OptionHeader->SectionAlignment << 格式控制符 << "内存中节对齐的字节数" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, FileAlignment) + OpOffset << 格式控制符 << "FileAlignment" << 格式控制符HEX << sizeof(PE_OptionHeader->FileAlignment) << 格式控制符HEX << PE_OptionHeader->FileAlignment << 格式控制符 << "文件中节对齐的字节数" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfImage) + OpOffset << 格式控制符 << "SizeOfImage" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfImage) << 格式控制符HEX << PE_OptionHeader->SizeOfImage << 格式控制符 << "程序在内存中的映像大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders) + OpOffset << 格式控制符 << "SizeOfHeaders" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfHeaders) << 格式控制符HEX << PE_OptionHeader->SizeOfHeaders << 格式控制符 << "PE头和节表的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, CheckSum) + OpOffset << 格式控制符 << "CheckSum" << 格式控制符HEX << sizeof(PE_OptionHeader->CheckSum) << 格式控制符HEX << PE_OptionHeader->CheckSum << 格式控制符 << "校验和，用于校验PE文件是否被修改" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, Subsystem) + OpOffset << 格式控制符 << "Subsystem" << 格式控制符HEX << sizeof(PE_OptionHeader->Subsystem) << 格式控制符HEX << PE_OptionHeader->Subsystem << 格式控制符 << "程序所运行的子系统类型" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, DllCharacteristics) + OpOffset << 格式控制符 << "DllCharacteristics" << 格式控制符HEX << sizeof(PE_OptionHeader->DllCharacteristics) << 格式控制符HEX << PE_OptionHeader->DllCharacteristics << 格式控制符 << "动态链接库（DLL）的特征" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfStackReserve) + OpOffset << 格式控制符 << "SizeOfStackReserve" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfStackReserve) << 格式控制符HEX << PE_OptionHeader->SizeOfStackReserve << 格式控制符 << "栈的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfStackCommit) + OpOffset << 格式控制符 << "SizeOfStackCommit" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfStackCommit) << 格式控制符HEX << PE_OptionHeader->SizeOfStackCommit << 格式控制符 << "栈提交的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfHeapReserve) + OpOffset << 格式控制符 << "SizeOfHeapReserve" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfHeapReserve) << 格式控制符HEX << PE_OptionHeader->SizeOfHeapReserve << 格式控制符 << "堆的大小" << endl;
		cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, SizeOfHeapCommit) + OpOffset << 格式控制符 << "SizeOfHeapCommit" << 格式控制符HEX << sizeof(PE_OptionHeader->SizeOfHeapCommit) << 格式控制符HEX << PE_OptionHeader->SizeOfHeapCommit << 格式控制符 << "堆提交的大小" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, LoaderFlags) + OpOffset << 格式控制符 << "LoaderFlags" << 格式控制符HEX << sizeof(PE_OptionHeader->LoaderFlags) << 格式控制符HEX << PE_OptionHeader->LoaderFlags << 格式控制符 << "加载标致" << endl;
		cout << 默认 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes) + OpOffset << 格式控制符 << "NumberOfRvaAndSizes" << 格式控制符HEX << sizeof(PE_OptionHeader->NumberOfRvaAndSizes) << 格式控制符HEX << PE_OptionHeader->NumberOfRvaAndSizes << 格式控制符 << "数据目录表的数量" << endl;
		for (int i = 0; i < 16; i++) {
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory[i]) + OpOffset << 格式控制符 << "DataDirectory" <<  格式控制符HEX << sizeof(PE_OptionHeader->DataDirectory[i]) << 格式控制符HEX << PE_OptionHeader->DataDirectory[i].Size << 格式控制符 << "数据目录在内存中的虚拟地址" << endl;
		}
		cout << 黄色 "----------------------------------NT头部信息(END)----------------------------------" << endl;
		for (int j = 1; j < SectionCount + 1;j++) {
			cout << 绿色 "----------------------------------Sections信息" << j << "----------------------------------" << endl;
			cout << 默认 格式控制符HEX << "地址偏移" << 格式控制符 << "变量名" << 格式控制符HEX << "大小" << 格式控制符HEX << "数值" << 格式控制符 << "说明" << endl;
			cout << 红色 斜体 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, Name[7]) + SectionOffset + (j * 0x28) << 格式控制符 << "节表名" << 格式控制符HEX << sizeof(PE_SectionHeader->Name);
			for (int i = 0; i < 8; i++) {
				cout << PE_SectionHeader->Name[i];
			}
			cout << "\t\t" << 格式控制符 << "节表名" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, Misc) + SectionOffset + (j * 0x28) << 格式控制符 << "Misc" << 格式控制符HEX << sizeof(PE_SectionHeader->Misc.PhysicalAddress) << 格式控制符HEX << PE_SectionHeader->Misc.PhysicalAddress << 格式控制符 << "内存中大小" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, VirtualAddress) + SectionOffset + (j * 0x28) << 格式控制符 << "VirtualAddress" << 格式控制符HEX << sizeof(PE_SectionHeader->VirtualAddress) << 格式控制符HEX << PE_SectionHeader->VirtualAddress << 格式控制符 << "内存中偏移" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, SizeOfRawData) + SectionOffset + (j * 0x28) << 格式控制符 << "SizeOfRawData" << 格式控制符HEX << sizeof(PE_SectionHeader->SizeOfRawData) << 格式控制符HEX << PE_SectionHeader->SizeOfRawData << 格式控制符 << "文件中大小" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, PointerToRawData) + SectionOffset + (j * 0x28) << 格式控制符 << "PointerToRawData" << 格式控制符HEX << sizeof(PE_SectionHeader->PointerToRawData) << 格式控制符HEX << PE_SectionHeader->PointerToRawData << 格式控制符 << "文件中偏移" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, PointerToRelocations) + SectionOffset + (j * 0x28) << 格式控制符 << "PointerToRelocation" << 格式控制符HEX << sizeof(PE_SectionHeader->PointerToRelocations) << 格式控制符HEX << PE_SectionHeader->PointerToRelocations << 格式控制符 << "重定位的偏移" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, PointerToLinenumbers) + SectionOffset + (j * 0x28) << 格式控制符 << "PointerToLinenumbers" << 格式控制符HEX << sizeof(PE_SectionHeader->PointerToLinenumbers) << 格式控制符HEX << PE_SectionHeader->PointerToLinenumbers << 格式控制符 << "行号表的偏移" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, NumberOfRelocations) + SectionOffset + (j * 0x28) << 格式控制符 << "NumberOfRelocations" << 格式控制符HEX << sizeof(PE_SectionHeader->NumberOfRelocations) << 格式控制符HEX << PE_SectionHeader->NumberOfRelocations << 格式控制符 << "重定位项数目" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, NumberOfLinenumbers) + SectionOffset + (j * 0x28) << 格式控制符 << "NumberOfLinenumbers" << 格式控制符HEX << sizeof(PE_SectionHeader->NumberOfLinenumbers) << 格式控制符HEX << PE_SectionHeader->NumberOfLinenumbers << 格式控制符 << "行号表中行号的数目" << endl;
			cout << 默认 格式控制符HEX << OFFSET(IMAGE_SECTION_HEADER, Characteristics) + SectionOffset + (j * 0x28) << 格式控制符 << "Characteristics" << 格式控制符HEX << sizeof(PE_SectionHeader->Characteristics) << 格式控制符HEX << PE_SectionHeader->Characteristics << 格式控制符 << "标志(块属性)" << endl;
			PE_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)File_Buffer + PE_DosHeader->e_lfanew + 0xf8 + (j * 0x28));
		}
	}
	


		
	
	system("Pause");
	return 1;
}
