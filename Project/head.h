#include <Winsock2.h>	// 解决重定义的问题

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>

#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#pragma comment(lib,"ws2_32.lib")
#include <stdio.h>

#include "resource.h"
#include "wmsort.h"
#include "mysql.h" 
#include <time.h>

/* 4字节的IP地址*/
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部*/
typedef struct ip_header{
	u_char ver_ihl; // 版本(4 bits) + 首部长度(4 bits)
	u_char tos; // 服务类型(Type of service)
	u_short tlen; // 总长(Total length)
	u_short identification; // 标识(Identification)
	u_short flags_fo; // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char ttl; // 存活时间(Time to live)
	u_char proto; // 协议(Protocol)
	u_short crc; // 首部校验和(Header checksum)
	ip_address saddr; // 源地址(Source address)
	ip_address daddr; // 目的地址(Destination address)
	u_int op_pad; // 选项与填充(Option + Padding)
}ip_header;

/*TCP 首部*/
typedef struct tcp_header{
	u_short th_sport; //16位源端口
	u_short th_dport; //16位目的端口
	u_int th_seq; //32位序列号
	u_int th_ack; //32位确认号
	u_char th_lenres; //4位首部长度/6位保留字
	u_char th_flag; //6位标志位
	u_short th_win; //16位窗口大小
	u_short th_sum; //16位校验和
	u_short th_urp; //16位紧急数据偏移量
}tcp_header;

/* UDP 首部*/
typedef struct udp_header{
	u_short sport; // 源端口(Source port)
	u_short dport; // 目的端口(Destination port)
	u_short len; // UDP数据包长度(Datagram length)
	u_short crc; // 校验和(Checksum)
}udp_header;

pcap_t *adhandle;

// 相关信息
typedef struct commonport
{
	u_short sport;
	u_short dport;
	int num;
	char command[5];	// 命令字16进制4位
	struct commonport *next;
}*ComPort;

// 相关全局变量
int OICQ_HTTP_WM_NUM = 0;
int TOTAL_num = 0, OICQ_num = 0, TCP_num = 0, UDP_num = 0, ICMP_num = 0;
FILE *fp, *fp_HTTP, *fp_WM;
char filename[20];
HWND HDLG;
ComPort OICQ_PORT = NULL;
int OICQ_PICTURE = 0;	// 接收图片标识
int OICQ_HTTP_GET = 0;	// 接收离线文件标识
int OICQ_HTTP_POST = 0;	// 发送离线文件标识
u_short OICQ_HTTP_GET_SrcPort = 0;	// 本机接收离线文件端口号
char OICQ_HTTP_GET_DstIP[20] = { 0 };	// 离线文件所在服务器IP
const int FILE_PATTERNS_NUM = 4;	//  文件特征码个数
char FILE_PATTERNS[FILE_PATTERNS_NUM][MAXM] = { "d0cf11e0a1b11ae1", "25504446", "504b0304", "526172211a0700" };	// 文件特征码组成的模式串
char FILE_PATTERNS_MEANS[FILE_PATTERNS_NUM][MAXM] = { "doc||ppt||xls", "pdf", "zip||docx||pptx||xlsx", "rar" };	// 文件特征码对应后缀
WM_STRUCT *FILE_PATTERN_WMSTRUCT = wmNew();	// WM算法用于存储模式串的结构, 预先创建

// 已识别3703版本QQ协议命令字
char OICQ_COMMANDS[][5] = {"001d", "00ce", "0001", "0027", "0002", "0081", "0058", "000d", "0062", "003c", "0065", "003e", "005c", "00b5",	"0067"};
// 已识别3703版本QQ协议命令字含义
char OICQ_COMMANDMEANS[][100] = {"Request Key", "Receive message", "Log out", "Get friend online", "Heart Message", "Get status of friend", "Download group friend", "Set status", "Request login", "Group name operation", "Request extra information", "MEMO Operation", "Get level", "Get friend's status of group", "Signature operation"};

int CommandNum()
{
	int i = 0, j = 0, cmdnum = 0;
	for (i = 0; j < sizeof(OICQ_COMMANDS); i++)
	{
		j += sizeof(OICQ_COMMANDS[i]);
		cmdnum++;
	}
	return cmdnum;
}

// 已识别3703版本QQ协议命令字数量
int OICQ_COMMANDNUM = CommandNum();

int CommandMeanIndex(char* cmd)
{
	int i = 0;
	for ( i = 0; i < OICQ_COMMANDNUM; i++)
	{
		if (strcmp(cmd, (char *)OICQ_COMMANDS[i]) == 0)
		{
			return i;
		}
	}
	return -1;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	unsigned long t = 0;
	int flag = 0;
	int i, j;
	struct tm *ltime;
	time_t local_tv_sec;
	u_int ip_alen;
	ip_header *ih;
	tcp_header *th;
	udp_header *uh;
	u_int ip_len;
	u_int tcp_len, udp_len;
	u_short sport, dport;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	ih = (ip_header *)(pkt_data + 14);
	ip_alen = ntohs(ih->tlen);
	ip_len = (ih->ver_ihl & 0xf) * 4; /* 获得TCP首部的位置*/

	char buf[256] = { 0 };
	if (ih->proto == 17)	// UDP
	{
		UDP_num = UDP_num + 1;
		uh = (udp_header *)((u_char*)ih + ip_len);
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);
		udp_len = ntohs(uh->len);
		
		memset(buf, 0, 256);
		sprintf(buf, "UDP	src:%d.%d.%d.%d:%d -> des:%d.%d.%d.%d:%d\r\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport);

		if ((*((u_char*)uh + 0x08) == 0x02) && *((u_char*)uh + udp_len - 1) == 0x03)	// 文本聊天标识
		{
			OICQ_num = OICQ_num + 1;
		
			t = 0;
			for (i = 15; i<19; i++)
			{
				t <<= 8;
				t |= *((u_char*)uh + i) & 0xff;
			}
			

			memset(buf, 0, 256);
			sprintf(buf, "--OICQ--	src:%d.%d.%d.%d:%d -> des:%d.%d.%d.%d:%d\r\nversion:%02x%02x\tcommand:%02x%02x\tsequence:%02x%02x\tQQ_id:%lu\r\n",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4,
				sport,
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4,
				dport,
				*((u_char*)uh + 9), 
				*((u_char*)uh + 10),
				*((u_char*)uh + 11), 
				*((u_char*)uh + 12),
				*((u_char*)uh + 13),
				*((u_char*)uh + 14),
				t);

			fprintf(fp, buf);
			
			for(i = 0; i < (int)udp_len; i++)
			{
				fputc(*((u_char*)uh+i),fp);
			}
			
			
			fprintf(fp, "\r\n\r\n");

			// 记录相关信息
			ComPort temp = new commonport;
			temp->sport = sport;
			temp->dport = dport;
			temp->num = 0;
			memset(temp->command, 0, sizeof(temp->command));
			sprintf(temp->command, "%02x%02x", *((u_char*)uh + 11), *((u_char*)uh + 12));
			temp->next = NULL;
			temp->next = OICQ_PORT;
			OICQ_PORT = temp;

			if (strcmp(temp->command, "0352") == 0)
			{
				OICQ_PICTURE = OICQ_PICTURE + 1;
			}
		}
		::SendMessage(::GetDlgItem(HDLG, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT(buf));
	}

	if (ih->proto == 6)		// TCP
	{
		TCP_num = TCP_num + 1;
		th = (tcp_header *)((u_char*)ih + ip_len);
		tcp_len = (th->th_lenres & 0xf0) >> 2;/* 获得TCP首部的长度*/
		/* 将网络字节序列转换成主机字节序列*/
		sport = ntohs(th->th_sport);
		dport = ntohs(th->th_dport);

		memset(buf, 0, 256);
		sprintf(buf, "TCP	src:%d.%d.%d.%d:%d -> des:%d.%d.%d.%d:%d\r\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport);
		::SendMessage(::GetDlgItem(HDLG, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT(buf));

		// OICQ传输离线文件识别
		if (dport == 80)	// HTTP
		{
			if ((*((u_char*)th + tcp_len) == 0x47) && (*((u_char*)th + tcp_len + 1) == 0x45) && (*((u_char*)th + tcp_len + 2) == 0x54))	// HTTP->GET
			{
				j = 0;
				for (i = 3; i < (int)(ip_alen - ip_len - tcp_len); i++)
				{
					if ((*((u_char*)th + tcp_len + i) == 0x0d) && (*((u_char*)th + tcp_len + i + 1) == 0x0a))
					{
						j++;
					}
					if (j == 2)
					{
						break;
					}
				}
				if (j == 2)
				{
					i = i + 2;
					for (j = i; j < (int)(ip_alen - ip_len - tcp_len); j++)
					{
						if ((*((u_char*)th + tcp_len + j) == 0x0d) && (*((u_char*)th + tcp_len + j + 1) == 0x0a))
						{
							break;
						}
					}
					memset(buf, 0, sizeof(buf));
					memcpy(buf, (u_char*)th + tcp_len + i, j - i);
					if (strcmp(buf, "User-Agent: QQClient") == 0)	// 客户端请求 接收 离线文件
					{
						OICQ_HTTP_WM_NUM = 0;
						OICQ_HTTP_GET++;
						sprintf(OICQ_HTTP_GET_DstIP, "%d.%d.%d.%d", 
							ih->daddr.byte1,
							ih->daddr.byte2,
							ih->daddr.byte3,
							ih->daddr.byte4);
						OICQ_HTTP_GET_SrcPort = sport;
						return;
					}
				}
			}

			/*
			if ((*((u_char*)ht) == 0x50) && (*((u_char*)ht + 1) == 0x4f) && (*((u_char*)ht + 2) == 0x53) && (*((u_char*)ht + 3) == 0x54))	// HTTP->POST
			{

			}
			*/
		}

		if (OICQ_HTTP_GET)	// 已经发送接收离线文件请求
		{
			if (sport == 80)
			{
				if ((ip_alen - ip_len - tcp_len) > 0)
				{
					memset(buf, 0, sizeof(buf));
					sprintf(buf, "%d.%d.%d.%d",
						ih->saddr.byte1,
						ih->saddr.byte2,
						ih->saddr.byte3,
						ih->saddr.byte4);
					if ((strcmp(buf, OICQ_HTTP_GET_DstIP) == 0) && (OICQ_HTTP_GET_SrcPort == dport))
					//if (OICQ_HTTP_GET_SrcPort == dport)		// fuwuqi...
					{
						//OICQ_HTTP_GET = 0;
						//memset(OICQ_HTTP_GET_DstIP, 0, sizeof(OICQ_HTTP_GET_DstIP));
						//OICQ_HTTP_GET_SrcPort = 0;

						char substr[3] = { 0 };
						for (i = 0; i < (int)(ip_alen - ip_len - tcp_len); i++)
						{
							// 写入2进制数据
							fputc(*((u_char*)th + tcp_len + i), fp_HTTP);
							if (OICQ_HTTP_WM_NUM < 1024)
							{
								// 写入16进制数据
								sprintf(substr, "%02x", *((u_char*)th + tcp_len + i));
								fprintf(fp_WM, substr);
								OICQ_HTTP_WM_NUM = OICQ_HTTP_WM_NUM + 1;
							}
						}
					}
				}
			}

		}
	}

	if (ih->proto == 1)		// ICMP
	{
		ICMP_num = ICMP_num + 1;
		memset(buf, 0, 256);
		sprintf(buf, "ICMP	src:%d.%d.%d.%d -> des:%d.%d.%d.%d\r\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);
		::SendMessage(::GetDlgItem(HDLG, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT(buf));
	}
}