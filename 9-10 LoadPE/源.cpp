#include "标头.h"

//全局变量区
#define MAXPROCESS 0x512	//最大进程数

NMHDR* pNMHDR = NULL;
LPNMITEMACTIVATE lpnmitem = NULL;
HINSTANCE hAPPInstance = NULL;
TCHAR szFileName[MAX_PATH];
LPVOID lpFileBuffe = NULL;
HWND hMainDlg = NULL;
WORD DirFlag = 0xFFFF;
///////////////////////////

int WINAPI CALLBACK WinMain(_In_ HINSTANCE hInstance,_In_opt_ HINSTANCE hPrevInstance,_In_ LPSTR lpCmdLine,_In_ int nShowCmd) {
	hAPPInstance = hInstance;
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);
	return 0;
}
DWORD GetFOA(LPVOID FileBuffer, DWORD RVA) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + +0x18 + pFileHeader->SizeOfOptionalHeader);

	if (RVA < pOptionalHeader->SizeOfHeaders)
	{
		return RVA;
	}
	else {
		for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
		{
			if (RVA >= pSectionHeader->VirtualAddress && RVA <= (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize))
			{
				DWORD FOA = RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
				return FOA;
			}
			pSectionHeader++;
		}
	}
	return -1;
}
DWORD GetRVA(LPVOID FileBuffer, DWORD FOA) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)FileBuffer + pDosHeader->e_lfanew + +0x18 + pFileHeader->SizeOfOptionalHeader);

	if (FOA < pOptionalHeader->SizeOfHeaders)
	{
		return FOA;
	}
	else {
		for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
		{
			if (FOA >= pSectionHeader->PointerToRawData && FOA <= (pSectionHeader->SizeOfRawData + pSectionHeader->PointerToRawData))
			{
				DWORD RVA = FOA - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress;
				return RVA;
			}
			pSectionHeader++;
		}
	}
	return -1;
}

BOOL SetIcon(HWND hwndDlg) {
	HICON hIcon = LoadIcon(hAPPInstance, MAKEINTRESOURCE(IDI_ICON));
	if (hIcon)
	{
		SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
		return TRUE;
	}
	return FALSE;
}
BOOL SetListViewColumn(HWND hwndDlg) {
	WCHAR szText[256] = { NULL };
	HWND hListView = GetDlgItem(hwndDlg, IDC_LIST_MAIN_PROCESS);
	SendMessage(hListView, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	if (hListView)
	{
		int ColCount = 4; 
		LVCOLUMN lvColumn;
		lvColumn = { 0 };
		lvColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

		LoadString(hAPPInstance, STR_LISTVIEW_PROCESS, szText, sizeof(szText) / sizeof(szText[0]));
		lvColumn.pszText = szText;
		lvColumn.iSubItem = 0;
		lvColumn.cx = 200;
		ListView_InsertColumn(hListView, 0, &lvColumn);

		for (int i = 1; i < ColCount; i++)
		{
			LoadString(hAPPInstance, STR_LISTVIEW_PROCESS + i, szText, sizeof(szText) / sizeof(szText[0]));
			lvColumn.pszText = szText;
			lvColumn.iSubItem = i;
			lvColumn.cx = 100;
			ListView_InsertColumn(hListView, i, &lvColumn);
		}
	}
	hListView = GetDlgItem(hwndDlg, IDC_LIST_MAIN_MOUDLE);
	if (hListView)
	{
		int ColCount = 3;
		LVCOLUMN lvColumn;
		lvColumn = { 0 };
		lvColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		LoadString(hAPPInstance, STR_LISTVIEW_MOUDLE, szText, sizeof(szText) / sizeof(szText[0]));
		lvColumn.pszText = szText;
		lvColumn.iSubItem = 0;
		lvColumn.cx = 300;
		ListView_InsertColumn(hListView, 0, &lvColumn);
		for (int i = 1; i < ColCount; i++)
		{
			LoadString(hAPPInstance, STR_LISTVIEW_MOUDLE + i, szText, sizeof(szText) / sizeof(szText[0]));
			lvColumn.pszText = szText;
			lvColumn.iSubItem = i;
			lvColumn.cx = 100;
			ListView_InsertColumn(hListView, i, &lvColumn);
		}
		return TRUE;
	}
	return FALSE;
}
BOOL SetListViewItemProcess(HWND hwndDlg) {
	struct ProcessData
	{
		WCHAR	wProcessName[MAX_PATH];	//进程名称
		DWORD	dwPID;					//进程ID
		DWORD	lpBase;					//镜像基址
		DWORD	dwSize;					//镜像大小
	};
	std::vector<ProcessData> ProDataVector;	//创建向量

	DWORD dwProcessList [MAXPROCESS];
	DWORD cbNeeded;
	if (!EnumProcesses(dwProcessList, sizeof(dwProcessList), &cbNeeded)) {//EnumProcesses遍历进程PID，存储在dwProcessList数组中，cbNeeded存储有多少字节的数据
		return FALSE;
	}
	DWORD dwNumOfProcesses = cbNeeded / sizeof(DWORD);	//进程数
	for (int i = 0; i < dwNumOfProcesses; i++)
	{
		DWORD PID = dwProcessList[i];
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);//OpenProcess打开进程对象 获取进程的句柄
		if (hProcess)
		{
			HMODULE hModule;
			DWORD cbNeededModule;
			MODULEINFO moduleInfo;
			TCHAR ModulePath[MAX_PATH];
 		if (EnumProcessModulesEx(hProcess, &hModule, sizeof(hModule), &cbNeededModule, LIST_MODULES_ALL)) {//EnumProcessModulesEx ->获取当前进程模块的句柄列表
				GetModuleFileNameEx(hProcess, hModule, ModulePath, MAX_PATH);//GetModuleFileNameEx ->获取指定模块的路径
				GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));//GetModuleInformation ->检索有关模块信息结构中指定模块的信息
				const TCHAR* fileName = _tcsrchr(ModulePath, '\\');
				fileName++;

				//创建结构体 - 存放到列表视图中
				ProcessData ProcessDatalist;
				wcscpy_s(ProcessDatalist.wProcessName, MAX_PATH, fileName);
				ProcessDatalist.dwPID = PID;
				ProcessDatalist.lpBase = (DWORD)moduleInfo.lpBaseOfDll;
				ProcessDatalist.dwSize = moduleInfo.SizeOfImage;
				ProDataVector.push_back(ProcessDatalist);
			}
		}
	}
	HWND hListView = GetDlgItem(hwndDlg, IDC_LIST_MAIN_PROCESS);

	for (int i = 0; i < ProDataVector.size(); i++)
	{
		LV_ITEM lvItem;
		lvItem = { 0 };
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = i;
		lvItem.iSubItem = 0;
		lvItem.pszText = ProDataVector[i].wProcessName;
		ListView_InsertItem(hListView, &lvItem);
		
		lvItem.iSubItem = 1;
		wchar_t PIDbuffer[10];
		wsprintf(PIDbuffer, L"%d", ProDataVector[i].dwPID);
		lvItem.pszText = PIDbuffer;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText); 

		lvItem.iSubItem = 2;
		wchar_t Basebuffer[10];
		wsprintf(Basebuffer, L"%-#0x", ProDataVector[i].lpBase);
		lvItem.pszText = Basebuffer;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);

		lvItem.iSubItem = 3;
		wchar_t dwSizebuffer[10];
		wsprintf(dwSizebuffer, L"%-#0x", ProDataVector[i].dwSize);
		lvItem.pszText = dwSizebuffer;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);
	}
	ProDataVector.clear();
	return TRUE;
}
int GetListViewItemPID(LPNMITEMACTIVATE lParam) {
	wchar_t buffer[256];
	LVITEM lvitem = { 0 };
	lvitem.mask = LVIF_TEXT;
	lvitem.iItem = lParam->iItem;
	lvitem.iSubItem = 1;
	lvitem.pszText = buffer;
	lvitem.cchTextMax = 256;
	SendMessage(lParam->hdr.hwndFrom, LVM_GETITEMTEXT, lParam->iItem, (LPARAM)&lvitem);
	int PID = wcstol(buffer, nullptr, 10);
	return PID;
}
BOOL SetListViewItemMoudle(HWND hwndDlg,int PID) {
	struct MoudleData
	{
		WCHAR	wMoudleName[MAX_PATH];		//模块路径
		DWORD	lpBase;						//模块基址
		DWORD	dwSize;						//模块大小
	};
	std::vector<MoudleData> MouDataVector;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);//OpenProcess打开进程对象 获取进程的句柄
	if (hProcess)
	{
		HMODULE hModules[128];
		DWORD cbNeededModule;
		MODULEINFO moduleInfo;
		TCHAR ModulePath[MAX_PATH];
		if (EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeededModule, LIST_MODULES_32BIT)) {//EnumProcessModulesEx ->获取当前进程模块的句柄列表
			int numModules = cbNeededModule / sizeof(HMODULE);
			for (int i = 0; i < numModules; i++) {
				GetModuleFileNameEx(hProcess, hModules[i], ModulePath, MAX_PATH);//GetModuleFileNameEx ->获取指定模块的路径
				GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(MODULEINFO));//GetModuleInformation ->检索有关模块信息结构中指定模块的信息

				//创建结构体
				MoudleData MoudlDatalist;
				wcscpy_s(MoudlDatalist.wMoudleName, MAX_PATH, ModulePath);
				MoudlDatalist.lpBase = (DWORD)moduleInfo.lpBaseOfDll;
				MoudlDatalist.dwSize = moduleInfo.SizeOfImage;
				MouDataVector.push_back(MoudlDatalist);
			}
			HWND hListView = GetDlgItem(hwndDlg, IDC_LIST_MAIN_MOUDLE);
			ListView_DeleteAllItems(hListView);
			//这是很重要的一步 导致内存居高不下
			for (int i = 0; i < MouDataVector.size(); i++)
			{
				LV_ITEM lvItem;
				lvItem = { 0 };
				lvItem.mask = LVIF_TEXT;
				lvItem.iItem = i;
				lvItem.iSubItem = 0;
				lvItem.pszText = MouDataVector[i].wMoudleName;
				ListView_InsertItem(hListView, &lvItem);

				lvItem.iSubItem = 1;
				wchar_t Basebuffer[512];
				wsprintf(Basebuffer, L"%-#0x", MouDataVector[i].lpBase);
				lvItem.pszText = Basebuffer;
				ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);

				lvItem.iSubItem = 2;
				wchar_t dwSizebuffer[512];
				wsprintf(dwSizebuffer, L"%-#0x", MouDataVector[i].dwSize);
				lvItem.pszText = dwSizebuffer;
				ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);
			}
			MouDataVector.clear();
			return TRUE;
		}
	}
	return FALSE;
}
BOOL SetEditText(HWND hwndDlg, int DlgItem, LPCWSTR EditText) {
	HWND hEditPath = GetDlgItem(hwndDlg, DlgItem);
	if (hEditPath) {
		SetWindowText(hEditPath, EditText);
		return TRUE;
	}
	return FALSE;
}
BOOL SetEditTextEnd(HWND hwndDlg, int DlgItem, LPCWSTR EditText) {
	HWND hEditPath = GetDlgItem(hwndDlg, DlgItem);
	if (hEditPath) {
		SendMessage(hEditPath, EM_SETSEL, -1, -1);
		SendMessage(hEditPath, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(EditText));
		return TRUE;
	}
	return FALSE;
}
BOOL SetDialogFileInfo(HWND hwndDlg) {
	typedef struct _IDC_EDIT_FILEINFO
	{
		DWORD	OEP;				//入口点
		DWORD	IMAGEBASE;			//镜像基址
		DWORD	IMAGESIZE;			//镜像大小
		DWORD	CODEBASE;			//代码基址

		DWORD	DATABASE;			//数据基址
		DWORD	MEM_ALIGNMENT;		//内存对齐
		DWORD	FILE_ALIGNMENT;		//文件对齐
		DWORD	Magic;				//标志字

		DWORD	SUBSYSTEM;			//子系统
		DWORD	NUMOFSECTION;		//区段数目
		DWORD	TIME;				//时间戳
		DWORD	SIZEOFHEADER;		//PE头大小

		DWORD	CHARACTERISTICS;	//特征值
		DWORD	CHECKSUM;			//校验和
		DWORD	SIZEOPHEADER;		//可选PE头大小
		DWORD	NUMOFDIREC;			//目录项数目
	}IDC_EDIT_FILEINFO, *PIDC_EDIT_FILEINFO;
	SetEditText(hwndDlg, IDC_EDIT_FILEINFO_PATH, szFileName);
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD fileSize = GetFileSize(hFile, NULL);
		if (fileSize != INVALID_FILE_SIZE)
		{
			lpFileBuffe = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
			DWORD bytesRead = 0;
			if (ReadFile(hFile, lpFileBuffe, fileSize, &bytesRead, NULL)) {
				if (bytesRead == fileSize) {

					PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
					PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x4);
					if (pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 || pFileHeader->Machine == IMAGE_FILE_MACHINE_IA64)
					{
						MessageBox(hwndDlg, TEXT("暂不支持64位程序解析"), TEXT("亲爱的用户："), MB_OK);
						EndDialog(hwndDlg, 0);
						LPVOID lpFileBuffe = NULL;
						CloseHandle(hFile);
						return FALSE;
					}

					PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x18);
					IDC_EDIT_FILEINFO editFileInfo;
					editFileInfo.OEP = pOptionalHeader->AddressOfEntryPoint;
					editFileInfo.IMAGEBASE = pOptionalHeader->ImageBase;
					editFileInfo.IMAGESIZE = pOptionalHeader->SizeOfImage;
					editFileInfo.CODEBASE = pOptionalHeader->BaseOfCode;
					editFileInfo.DATABASE = pOptionalHeader->BaseOfData;
					editFileInfo.MEM_ALIGNMENT = pOptionalHeader->SectionAlignment;
					editFileInfo.FILE_ALIGNMENT = pOptionalHeader->FileAlignment;
					editFileInfo.Magic = pOptionalHeader->Magic;
					editFileInfo.SUBSYSTEM = pOptionalHeader->Subsystem;
					editFileInfo.NUMOFSECTION = pFileHeader->NumberOfSections;
					editFileInfo.TIME = pFileHeader->TimeDateStamp;
					editFileInfo.SIZEOFHEADER = pOptionalHeader->SizeOfHeaders;
					editFileInfo.CHARACTERISTICS = pFileHeader->Characteristics;
					editFileInfo.CHECKSUM = pOptionalHeader->CheckSum; 
					editFileInfo.SIZEOPHEADER = pFileHeader->SizeOfOptionalHeader;
					editFileInfo.NUMOFDIREC = pOptionalHeader->NumberOfRvaAndSizes;
					
					for (int i = 0; i < 16; i++)
					{
						LPVOID pEditFileInfo = &editFileInfo ;
						wchar_t dwSizebuffer[512];
						wsprintf(dwSizebuffer, L"%08X", *((DWORD*)pEditFileInfo + i));
						SetEditText(hwndDlg, IDC_EDIT_FILEINFO_OEP + i, dwSizebuffer);
					}
					CloseHandle(hFile);
					return TRUE;
				}
			}
		}
	}
	wchar_t dwSizebuffer[512];
	wsprintf(dwSizebuffer, L"ERROR: %08X", GetLastError());
	MessageBox(hwndDlg, TEXT("文件打开失败"), dwSizebuffer, MB_OK);
	return FALSE;
}
BOOL SetDialogSectionInfo(HWND hwndDlg) {
	WCHAR szText[256] = { NULL };
	HWND hListView = GetDlgItem(hwndDlg, IDC_LIST_SECTIONTABLE);
	SendMessage(hListView, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	if (hListView)
	{
		int ColCount = 5;
		LVCOLUMN lvColumn;
		lvColumn = { 0 };
		lvColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		for (int i = 0; i < ColCount; i++)
		{
			LoadString(hAPPInstance, STR_SECTION_NAME + i, szText, sizeof(szText) / sizeof(szText[0]));
			lvColumn.pszText = szText;
			lvColumn.iSubItem = i;
			lvColumn.cx = 100;
			ListView_InsertColumn(hListView, i, &lvColumn);
		}
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x4);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + +0x18 + pFileHeader->SizeOfOptionalHeader);
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++) {
		LV_ITEM lvItem;
		lvItem = { 0 };
		lvItem.mask = LVIF_TEXT;
		lvItem.iItem = i;
		lvItem.iSubItem = 0;

		wchar_t wBuffe[10];
		swprintf(wBuffe, sizeof(wBuffe),L"%hs", &pSectionHeader->Name);;
		lvItem.pszText = wBuffe;
		ListView_InsertItem(hListView, &lvItem);

		lvItem.iSubItem = 1;
		wsprintf(wBuffe, L"%08X", pSectionHeader->VirtualAddress);;
		lvItem.pszText = wBuffe;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);

		lvItem.iSubItem = 2;
		wsprintf(wBuffe, L"%08X", pSectionHeader->Misc.VirtualSize);;
		lvItem.pszText = wBuffe;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);

		lvItem.iSubItem = 3;
		wsprintf(wBuffe, L"%08X", pSectionHeader->PointerToRawData);;
		lvItem.pszText = wBuffe;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);

		lvItem.iSubItem = 4;
		wsprintf(wBuffe, L"%08X", pSectionHeader->SizeOfRawData);;
		lvItem.pszText = wBuffe;
		ListView_SetItemText(hListView, i, lvItem.iSubItem, lvItem.pszText);
		pSectionHeader++;
	};
	return TRUE;
}
BOOL SetDialogDIRInfo(HWND hwndDlg) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew +  0x18 );
	
	for (int i = 0; i < 16; i++)
	{
		wchar_t dwSizebuffer[512];
		wsprintf(dwSizebuffer, L"%08X", pOptionalHeader->DataDirectory[i].VirtualAddress);
		SetEditText(hwndDlg, IDC_EDIT_DIR_RVA_Export + i, dwSizebuffer);

		wsprintf(dwSizebuffer, L"%08X", pOptionalHeader->DataDirectory[i].Size);
		SetEditText(hwndDlg, IDC_EDIT_DIR_SIZE_Export + i, dwSizebuffer);
	}
	return TRUE;
}
BOOL OutPutExportInfo(HWND hwndDlg) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x4);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x18 + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY  pDir = (PIMAGE_DATA_DIRECTORY)((DWORD)lpFileBuffe + pDosHeader->e_lfanew + 0x18 + pFileHeader->SizeOfOptionalHeader - 0x80);	//创建数据目录结构体
	if (pDir->VirtualAddress == 0)
	{
		const wchar_t* EditText = TEXT("没有导出表哦！！！\n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		return FALSE;
	}

	DWORD ExportAdderss = GetFOA(lpFileBuffe, pDir->VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pExport = (IMAGE_EXPORT_DIRECTORY*)((DWORD)lpFileBuffe + ExportAdderss);

	wchar_t EditText[512];
	swprintf(EditText, sizeof(EditText), L"-----------------------------------------\n");
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"原始文件名: %hs \n", (CHAR*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pExport->Name)));
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"-----------------------------------------\n");
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"Base: %08X \n", pExport->Base);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"NumberOfFunctions: %08X \n", pExport->NumberOfFunctions);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"NumberOfNames: %08X \n", pExport->NumberOfNames);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"AddressOfFunctions: %08X \n", pExport->AddressOfFunctions);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"AddressOfNames: %08X \n", pExport->AddressOfNames);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"AddressOfNameOrdinals: %08X \n", pExport->AddressOfNameOrdinals);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"-----------------------------------------\n");
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	swprintf(EditText, sizeof(EditText), L"导出序号----------虚拟地址---------导出函数名\n");
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);

	DWORD* pFunctionNameAddress = (DWORD*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pExport->AddressOfNames));
	WORD* pOrdinals = (WORD*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pExport->AddressOfNameOrdinals));

	DWORD dwFunctionAddress = GetFOA(lpFileBuffe, pExport->AddressOfFunctions);
	DWORD* pFunctionAddressTabs = (DWORD*)((DWORD)lpFileBuffe + dwFunctionAddress);

	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		char* lpName = (char*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, *pFunctionNameAddress));
		DWORD dwFunctionAddress = *(pFunctionAddressTabs + (*pOrdinals));
		DWORD Ord = pExport->Base + (*pOrdinals);
		swprintf(EditText, sizeof(EditText), L"%08X----------%08X----------%hs \n", Ord, dwFunctionAddress, lpName);
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);

		pFunctionNameAddress++;
		pOrdinals++;
	}
	
	return TRUE;
}
BOOL OutPutImportInfo(HWND hwndDlg) {
	//1.定位到导入表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffe + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pNtHeader + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pOptionalHeader->DataDirectory[1].VirtualAddress));
	if (pOptionalHeader->DataDirectory[1].VirtualAddress == 0)
	{
		const wchar_t* EditText = TEXT("没有导入表哦！！！ \n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		return FALSE;

	}
	while (pImport->OriginalFirstThunk != 0)
	{
		DWORD i = 0;
		wchar_t EditText[4096] = L"";
		swprintf(EditText, sizeof(EditText), L"-----------------------------------------\n\n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		swprintf(EditText, sizeof(EditText), L"文件名: %hs \n", (CHAR*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pImport->Name)));
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		swprintf(EditText, sizeof(EditText), L"-----------------------------------------\n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		swprintf(EditText, sizeof(EditText), L"OriginalFirstThunk(INT): %08X \n", pImport->OriginalFirstThunk);
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		swprintf(EditText, sizeof(EditText), L"FirstThunk(IAT): %08X \n", pImport->FirstThunk);
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		swprintf(EditText, sizeof(EditText), L"\n-----------------------------------------\n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);

		PIMAGE_THUNK_DATA32 INT = (IMAGE_THUNK_DATA32*)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pImport->OriginalFirstThunk));
		swprintf(EditText, sizeof(EditText), L"\n-----------(INT)OriginalFirstThunk------------\n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);

		while (!(INT->u1.Ordinal == 0))
		{
			DWORD HigOrder = (DWORD)INT->u1.Ordinal & IMAGE_ORDINAL_FLAG32;	//判断最高位是否位1
			if (HigOrder != 0)	//最高位不是0 输出函数编号
			{
				DWORD TheOrder = (DWORD)INT->u1.Ordinal & 0x7FFFFFFF;
				swprintf(EditText, sizeof(EditText), L"OriginalFirstThunk RVA: %08X \n", (pImport->OriginalFirstThunk + (i * 4)));
				SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
				swprintf(EditText, sizeof(EditText), L"函数编号：%08X \n", TheOrder);
				SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
				i++;
			}
			else {	//最高位是0 输出函数名
				PIMAGE_IMPORT_BY_NAME IMPORT_Function_name = (IMAGE_IMPORT_BY_NAME*)GetFOA(lpFileBuffe, INT->u1.ForwarderString);
				char* dll_function_name = (char*)((DWORD)lpFileBuffe + (DWORD)IMPORT_Function_name->Name);
				swprintf(EditText, sizeof(EditText), L"FirstThunk RVA: %08X \t 函数名称 : %hs\n",(pImport->OriginalFirstThunk + (i * 4)), dll_function_name);
				SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
				i++;
			}
			INT++;
		}

		pImport++;
	}
	return FALSE;
}
BOOL OutPutResourcesInfo(HWND hwndDlg) {
	//1.定位到资源表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffe + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pNtHeader + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pResource = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pOptionalHeader->DataDirectory[1].VirtualAddress));
	if (pOptionalHeader->DataDirectory[5].VirtualAddress == 0)
	{
		const wchar_t* EditText = TEXT("没有资源表哦！！！ \n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		return FALSE;
	}



	return FALSE;
}
BOOL OutPutBaseRelocationInfo(HWND hwndDlg) {
	//1.定位到重定位
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffe + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pNtHeader + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pOptionalHeader->DataDirectory[5].VirtualAddress));

	// 取消编辑框的字数上限
	HWND hEdit = GetDlgItem(hwndDlg, IDC_EDIT_DIR);
	SendMessage(hEdit, EM_SETLIMITTEXT, 0, 0);


	if (pOptionalHeader->DataDirectory[5].VirtualAddress == 0)
	{
		const wchar_t* EditText = TEXT("没有重定位表哦！！！ \n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		return FALSE;
	}

	while (!(pBaseRelocation->VirtualAddress == 0 && pBaseRelocation->SizeOfBlock == 0))
	{
		

		DWORD Count = (pBaseRelocation->SizeOfBlock / 0x2) - 0x4;
		wchar_t EditText[4096] = L"";
		swprintf(EditText, sizeof(EditText), L"VirtualAddress: %08X , SizeOfBlock: %08X ,ltems : %08X\n", pBaseRelocation->VirtualAddress, pBaseRelocation->SizeOfBlock, Count);
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);

		WORD* BaseNumber = (WORD*)((DWORD)pBaseRelocation + 0x8);
		for (int i = 0; i < Count; i++)
		{
			//低12位 + VirtualAddress = 真正修改的地方

			WORD HigBaseNumber = *BaseNumber & 0xF000;	//高4位 == 3 需要修改的数据 
			WORD LowBaseNumber = *BaseNumber & 0x0FFF;	//高4位 == 0 不需要修改(内存对齐数据)

			DWORD RealAddress = pBaseRelocation->VirtualAddress + LowBaseNumber;

			swprintf(EditText, sizeof(EditText), L"Index: %08X ,  Team: %08X\n", i+1, RealAddress);
			SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
			BaseNumber++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	return FALSE;
}
BOOL OutPutBoundImportInfo(HWND hwndDlg) {
	//1.定位绑定导入表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffe;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)lpFileBuffe + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtHeader + 0x4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pNtHeader + 0x18);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)lpFileBuffe + GetFOA(lpFileBuffe, pOptionalHeader->DataDirectory[11].VirtualAddress));
	if (pOptionalHeader->DataDirectory[11].VirtualAddress == 0)
	{
		const wchar_t* EditText = TEXT("没有绑定导入表哦！！！ \n");
		SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
		return FALSE;

	}

	wchar_t EditText[4096] = L"";
	swprintf(EditText, sizeof(EditText), L"TimeDateStamp: %08X , OffsetModuleName: %04X ,NumberOfModuleForwarderRefs : %04X\n", pBoundImport->TimeDateStamp, pBoundImport->OffsetModuleName, pBoundImport->NumberOfModuleForwarderRefs);
	SetEditTextEnd(hwndDlg, IDC_EDIT_DIR, EditText);
	

	return FALSE;
}
BOOL OutPutIATInfo(HWND hwndDlg) {

	return FALSE;
}

BOOL CALLBACK DialogMainProc(HWND hwndDlg,UINT uMsg,WPARAM wParam , LPARAM lParam) {
	switch (uMsg)
	{
	case WM_INITDIALOG:
		hMainDlg = GetDlgItem(hwndDlg, IDD_DIALOG_MAIN); // 获取主对话框的句柄
		SetIcon(hwndDlg);
		SetListViewColumn(hwndDlg);
		SetListViewItemProcess(hwndDlg);
		return TRUE;
	case WM_NOTIFY:
		pNMHDR = (NMHDR*)lParam;
		switch (wParam)
		{
		case IDC_LIST_MAIN_PROCESS:
			switch (pNMHDR->code)
			{
			case NM_CLICK:
				lpnmitem = (LPNMITEMACTIVATE)lParam;
				SetListViewItemMoudle(hwndDlg, GetListViewItemPID(lpnmitem));
			}
			return TRUE;
			break;
		}
		return FALSE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_MAIN_OPENFILE:
			OPENFILENAME ofn;
			ofn = { 0 };
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFile = szFileName;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = TEXT("可执行文件 (*.exe;*.dll;*.com)\0*.exe;*.dll;*.com\0所有文件 (*.*)\0*.*\0");;
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			// 显示文件对话框
			if (GetOpenFileName(&ofn))
			{
				DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_FILEINFO), hwndDlg, DialogFileProc);
			}
			
			return TRUE;
			break;
			
		case IDC_BUTTON_MAIN_SHELL:
			MessageBox(hwndDlg,TEXT("此功能暂时未解锁"), TEXT("亲爱的用户："), MB_OK);
			return TRUE;
		case IDC_BUTTON_MAIN_DLLINIT:
			MessageBox(hwndDlg, TEXT("此功能暂时未解锁"), TEXT("亲爱的用户："), MB_OK);
			return TRUE;
		case IDC_BUTTON_MAIN_ABOUT:
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_ABOUT), hwndDlg, DialogAboutProc);
			return TRUE;
		case IDC_BUTTON_MAIN_QUIT:
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		return FALSE;
	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	return FALSE;
}
BOOL CALLBACK DialogFileProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg)
	{
	case WM_INITDIALOG:
		SetDialogFileInfo(hwndDlg);
		return TRUE;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDC_BUTTON_FILEINFO_QUIT:
			HeapFree(GetProcessHeap(), 0, lpFileBuffe);
			EndDialog(hwndDlg, 0);
			return TRUE;
		case IDC_BUTTON_FILEINFO_SECTION:
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_SECTIONTABLE), hwndDlg, DialogSectionProc);
			return TRUE;
		case IDC_BUTTON_FILEINFO_DIREC:
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR), hwndDlg, DialogDirProc);
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK DialogAboutProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (wParam)
		{
		case IDC_BUTTON_ABOUT_OK:
			EndDialog(hwndDlg, 0);
			return TRUE;
		case IDC_BUTTON_ABOUT_QUIT:
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		return FALSE;
	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	return FALSE;
}
BOOL CALLBACK DialogSectionProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg)
	{
	case WM_INITDIALOG:
		SetDialogSectionInfo(hwndDlg);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	return FALSE;
}
BOOL CALLBACK DialogDirProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg)
	{
	case WM_INITDIALOG:
		SetDialogDIRInfo(hwndDlg);
		return TRUE;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDC_BUTTON_DIR_OK:
			EndDialog(hwndDlg, 0);
			return TRUE;
		case IDC_BUTTON_DIR_Export:
			DirFlag = 0;
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR_INFO), hwndDlg, DialogDirProcInfo);
			return TRUE;
		case IDC_BUTTON_DIR_Import:
			DirFlag = 1;
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR_INFO), hwndDlg, DialogDirProcInfo);
			return TRUE;
		case IDC_BUTTON_DIR_Resources:
			DirFlag = 2;
			MessageBox(hwndDlg, TEXT("此功能暂时未解锁"), TEXT("亲爱的用户："), MB_OK);
			return TRUE;
		case IDC_BUTTON_DIR_BaseRelocation:
			DirFlag = 3;
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR_INFO), hwndDlg, DialogDirProcInfo);
			return TRUE;
		case IDC_BUTTON_DIR_BoundImport:
			DirFlag = 4;
			DialogBox(hAPPInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR_INFO), hwndDlg, DialogDirProcInfo);
			return TRUE;
		case IDC_BUTTON_DIR_IAT:
			DirFlag = 5;
			MessageBox(hwndDlg, TEXT("此功能暂时未解锁"), TEXT("亲爱的用户："), MB_OK);
			return TRUE;
		}

		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK DialogDirProcInfo(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch(uMsg)
	{
	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	case WM_INITDIALOG:
		SetDialogDIRInfo(hwndDlg);
		switch (DirFlag)
		{
		case 0:
			OutPutExportInfo(hwndDlg);
			return TRUE;
		case 1:
			OutPutImportInfo(hwndDlg);
			return TRUE;
		case 2:
			OutPutResourcesInfo(hwndDlg);

			return TRUE;
		case 3:
			OutPutBaseRelocationInfo(hwndDlg);

			return TRUE;
		case 4:
			OutPutBoundImportInfo(hwndDlg);

			return TRUE;
		case 5:
			OutPutIATInfo(hwndDlg);

			return TRUE;
		default:
			MessageBox(hwndDlg, TEXT("错误的标志位"), TEXT("检查DirFlag"), MB_OK);
			break;
		}
		return FALSE;
	}
	return FALSE;
}