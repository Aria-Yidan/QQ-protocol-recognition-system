#include <Winsock2.h>	// ����ض��������

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

/* 4�ֽڵ�IP��ַ*/
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 �ײ�*/
typedef struct ip_header{
	u_char ver_ihl; // �汾(4 bits) + �ײ�����(4 bits)
	u_char tos; // ��������(Type of service)
	u_short tlen; // �ܳ�(Total length)
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo; // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char ttl; // ���ʱ��(Time to live)
	u_char proto; // Э��(Protocol)
	u_short crc; // �ײ�У���(Header checksum)
	ip_address saddr; // Դ��ַ(Source address)
	ip_address daddr; // Ŀ�ĵ�ַ(Destination address)
	u_int op_pad; // ѡ�������(Option + Padding)
}ip_header;

/*TCP �ײ�*/
typedef struct tcp_header{
	u_short th_sport; //16λԴ�˿�
	u_short th_dport; //16λĿ�Ķ˿�
	u_int th_seq; //32λ���к�
	u_int th_ack; //32λȷ�Ϻ�
	u_char th_lenres; //4λ�ײ�����/6λ������
	u_char th_flag; //6λ��־λ
	u_short th_win; //16λ���ڴ�С
	u_short th_sum; //16λУ���
	u_short th_urp; //16λ��������ƫ����
}tcp_header;

/* UDP �ײ�*/
typedef struct udp_header{
	u_short sport; // Դ�˿�(Source port)
	u_short dport; // Ŀ�Ķ˿�(Destination port)
	u_short len; // UDP���ݰ�����(Datagram length)
	u_short crc; // У���(Checksum)
}udp_header;

pcap_t *adhandle;

// �����Ϣ
typedef struct commonport
{
	u_short sport;
	u_short dport;
	int num;
	char command[5];	// ������16����4λ
	struct commonport *next;
}*ComPort;

// ���ȫ�ֱ���
int OICQ_HTTP_WM_NUM = 0;
int TOTAL_num = 0, OICQ_num = 0, TCP_num = 0, UDP_num = 0, ICMP_num = 0;
FILE *fp, *fp_HTTP, *fp_WM;
char filename[20];
HWND HDLG;
ComPort OICQ_PORT = NULL;
int OICQ_PICTURE = 0;	// ����ͼƬ��ʶ
int OICQ_HTTP_GET = 0;	// ���������ļ���ʶ
int OICQ_HTTP_POST = 0;	// ���������ļ���ʶ
u_short OICQ_HTTP_GET_SrcPort = 0;	// �������������ļ��˿ں�
char OICQ_HTTP_GET_DstIP[20] = { 0 };	// �����ļ����ڷ�����IP
const int FILE_PATTERNS_NUM = 4;	//  �ļ����������
char FILE_PATTERNS[FILE_PATTERNS_NUM][MAXM] = { "d0cf11e0a1b11ae1", "25504446", "504b0304", "526172211a0700" };	// �ļ���������ɵ�ģʽ��
char FILE_PATTERNS_MEANS[FILE_PATTERNS_NUM][MAXM] = { "doc||ppt||xls", "pdf", "zip||docx||pptx||xlsx", "rar" };	// �ļ��������Ӧ��׺
WM_STRUCT *FILE_PATTERN_WMSTRUCT = wmNew();	// WM�㷨���ڴ洢ģʽ���Ľṹ, Ԥ�ȴ���

// ��ʶ��3703�汾QQЭ��������
char OICQ_COMMANDS[][5] = {"001d", "00ce", "0001", "0027", "0002", "0081", "0058", "000d", "0062", "003c", "0065", "003e", "005c", "00b5",	"0067"};
// ��ʶ��3703�汾QQЭ�������ֺ���
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

// ��ʶ��3703�汾QQЭ������������
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
	ip_len = (ih->ver_ihl & 0xf) * 4; /* ���TCP�ײ���λ��*/

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

		if ((*((u_char*)uh + 0x08) == 0x02) && *((u_char*)uh + udp_len - 1) == 0x03)	// �ı������ʶ
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

			// ��¼�����Ϣ
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
		tcp_len = (th->th_lenres & 0xf0) >> 2;/* ���TCP�ײ��ĳ���*/
		/* �������ֽ�����ת���������ֽ�����*/
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

		// OICQ���������ļ�ʶ��
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
					if (strcmp(buf, "User-Agent: QQClient") == 0)	// �ͻ������� ���� �����ļ�
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

		if (OICQ_HTTP_GET)	// �Ѿ����ͽ��������ļ�����
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
							// д��2��������
							fputc(*((u_char*)th + tcp_len + i), fp_HTTP);
							if (OICQ_HTTP_WM_NUM < 1024)
							{
								// д��16��������
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