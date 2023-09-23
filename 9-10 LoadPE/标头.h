#pragma once
#include <Windows.h>
#include <psapi.h>
#include <vector>
#include <tchar.h>
#include <iostream>
#include "resource.h"
#include <commctrl.h> // ����ͨ�ÿؼ���Common Controls��
#pragma comment(lib,"comctl32.lib")

//�����ڹ��̺���
BOOL CALLBACK DialogMainProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//�ļ����ڹ��̺���
BOOL CALLBACK DialogFileProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//���ڴ��ڹ��̺���
BOOL CALLBACK DialogAboutProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//�ڱ���̺���
BOOL CALLBACK DialogSectionProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//����Ŀ¼���̺���
BOOL CALLBACK DialogDirProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

//����Ŀ¼��Ϣ���̺���
BOOL CALLBACK DialogDirProcInfo(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);


//����ͼ��
BOOL SetIcon(HWND hwndDlg);

//�����б���ͼ����
BOOL SetListViewColumn(HWND hwndDlg);

//�����б���ͼ���̵�����
BOOL SetListViewItemProcess(HWND hwndDlg);

//��ȡ�б���ͼ������ֵ��PID��
int GetListViewItemPID(LPNMITEMACTIVATE lParam);

//�����б���ͼģ�������
BOOL SetListViewItemMoudle(HWND hwndDlg, int PID);

//����Edit�༭����ı�
BOOL SetEditText(HWND hwndDlg, int DlgItem, LPCWSTR EditText);

//�����ļ����ڵ���Ϣ
BOOL SetDialogFileInfo(HWND hwndDlg);

//���ýڱ�����Ϣ
BOOL SetDialogSectionInfo(HWND hwndDlg);