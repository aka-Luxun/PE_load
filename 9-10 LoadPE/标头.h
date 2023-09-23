#pragma once
#include <Windows.h>
#include <psapi.h>
#include <vector>
#include <tchar.h>
#include <iostream>
#include "resource.h"
#include <commctrl.h> // 用于通用控件（Common Controls）
#pragma comment(lib,"comctl32.lib")

//主窗口过程函数
BOOL CALLBACK DialogMainProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//文件窗口过程函数
BOOL CALLBACK DialogFileProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//关于窗口过程函数
BOOL CALLBACK DialogAboutProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//节表过程函数
BOOL CALLBACK DialogSectionProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//数据目录过程函数
BOOL CALLBACK DialogDirProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//数据目录信息过程函数
BOOL CALLBACK DialogDirProcInfo(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);


//设置图标
BOOL SetIcon(HWND hwndDlg);

//设置列表视图的项
BOOL SetListViewColumn(HWND hwndDlg);

//设置列表视图进程的子项
BOOL SetListViewItemProcess(HWND hwndDlg);

//获取列表视图的子项值（PID）
int GetListViewItemPID(LPNMITEMACTIVATE lParam);

//设置列表视图模块的子项
BOOL SetListViewItemMoudle(HWND hwndDlg, int PID);

//设置Edit编辑框的文本
BOOL SetEditText(HWND hwndDlg, int DlgItem, LPCWSTR EditText);

//设置文件窗口的信息
BOOL SetDialogFileInfo(HWND hwndDlg);

//设置节表窗口信息
BOOL SetDialogSectionInfo(HWND hwndDlg);