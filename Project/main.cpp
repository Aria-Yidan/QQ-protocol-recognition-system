/////////////////////////////////////////////////
// ComctlDemo.cpp�ļ�


#include "head.h"

// ���ӵ�comctl32.lib��
#pragma comment(lib,"comctl32.lib")

// ״̬��ID��
#define IDC_STATUS 101

// �����󶨱�ʶ
int NETWORKCARD_BIND = 0;

BOOL __stdcall DlgProc(HWND, UINT, WPARAM, LPARAM);
void ClearGlobalVariable();
void UpdateProcess(HWND hWndList);
int BindNetworkCards(HWND hWndComboBox);
pcap_if_t* GetNetworkCards();
int FindFilePatternIndex(char *str);
int BeginGetPacket(int count);
int GetSearchHistoryFromMySQL(HWND hDlg);
int AddSearchHistoryIntoMySQL(char *oicq_fileinfo);

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
	// ��ʼ��Comctl32.dll��
	::InitCommonControls();

	::DialogBoxParam(hInstance, (LPCTSTR)IDD_MAIN, NULL, DlgProc, NULL);

	return 0;
}

BOOL __stdcall DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:	// ��ʼ�����򴰿�
	{
						  
						  // ��ʼ����Ͽ�ؼ�
						  HWND hWndComboBox = ::GetDlgItem(hDlg, IDC_COMBO_NC);

						  // ��������б�
						  pcap_if_t *alldevs = GetNetworkCards();
						  
						  // ����Ͽ��������
						  int i = 0;
						  pcap_if_t *d;
						  ::SendMessage(hWndComboBox, CB_RESETCONTENT, 0, 0);
						  for (d = alldevs; d; d = d->next)
						  {
							  i++;
							  if (d->description)
							  {
								  ::SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)TEXT(d->description));
							  }
							  
						  }
						  // Ĭ��ѡ����Ͽ��еĵ�һ��
						  ::SendMessage(hWndComboBox, CB_SETCURSEL, 0, 0);

						  // ------------------------------------------------------------------------------
						  // ��ʼ���б���ͼ�ؼ�
						  HWND hWndList = ::GetDlgItem(hDlg, IDC_LIST);

						  // ����������չ���
						  ::SendMessage(hWndList, LVM_SETEXTENDEDLISTVIEWSTYLE,
							  0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

						  LVCOLUMN column;
						  // ָ��LVCOLUMN�ṹ�е�pszText��fmt��cx����Ч
						  column.mask = LVCF_TEXT | LVCF_FMT | LVCF_WIDTH;
						  // ������Ч���������
						  column.fmt = LVCFMT_CENTER;	// ָ���ı�������ʾ
						  column.cx = 150;		// ָ�������Ŀ��
						  column.pszText = "Э������";	// ָ��������ʾ���ı�

						  // ���һ���µ�ר��
						  ::SendMessage(hWndList, LVM_INSERTCOLUMN, 0, (LPARAM)&column);
						  // �����һ��ר��
						  column.pszText = "����";
						  column.cx = 70;
						  ::SendMessage(hWndList, LVM_INSERTCOLUMN, 1, (LPARAM)&column);
						  // �����һ��ר��
						  column.pszText = "�����Ϣ";
						  column.cx = 160;
						  ::SendMessage(hWndList, LVM_INSERTCOLUMN, 2, (LPARAM)&column);

						  // ------------------------------------------------------------------------------
						  // ��ʼ��״̬��

						  // ����״̬��
						  HWND hWndStatus = ::CreateStatusWindow(WS_CHILD | WS_VISIBLE | SBS_SIZEGRIP,
							  NULL, hDlg, IDC_STATUS);
						  // ���ñ���ɫ
						  ::SendMessage(hWndStatus, SB_SETBKCOLOR, 0, RGB(0xa6, 0xca, 0xf0));
						  // ��״̬������
						  int pInt[] = { 152, -1 };
						  ::SendMessage(hWndStatus, SB_SETPARTS, 2, (long)pInt);
						  // ���ø������ı�
						  ::SendMessage(hWndStatus, SB_SETTEXT, 0, (long)" ׼������");
						  ::SendMessage(hWndStatus, SB_SETTEXT, 1, (long)" \t������������յ�����");

						  // ------------------------------------------------------------------------------
						  // ��ʼ��ȫ�ֱ���
						  ClearGlobalVariable();
						  InitFilePattern(FILE_PATTERN_WMSTRUCT, FILE_PATTERNS);
						  HDLG = hDlg;
	}
		break;

	case WM_COMMAND:	// ��Ӧ��ť
		switch (LOWORD(wParam))
		{
		case IDCANCEL:
			::EndDialog(hDlg, IDCANCEL);
			break;

		case IDC_HISTORY:
		{
			if (GetSearchHistoryFromMySQL(hDlg) < 0)	// ��ѯʧ��
			{
				::SendMessage(::GetDlgItem(hDlg, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT("��ѯʧ�ܣ�"));
			}
			break;
		}
		
		case IDC_BEGIN:
		{
						  if (NETWORKCARD_BIND)
						  {
							  ClearGlobalVariable();
							  //break;
							  // ��ñ༭�������Packet��
							  char szBuffer[256] = { 0 };
							  HWND hWndEdit = ::GetDlgItem(hDlg, IDC_PACKETNUMIN);
							  *((LPWORD)szBuffer) = 256;	// ��õ���󳤶�
							  int nLen = ::SendMessage(hWndEdit, EM_GETLINE, 0, (LPARAM)szBuffer);
							  if (nLen == 0)
							  {
								  ::MessageBox(hDlg, "�����벶��������", "��ʾ", MB_OK | MB_DEFBUTTON1);
							  }
							  else
							  {
								  szBuffer[nLen] = '\0';
								  HWND hWndStatus = ::GetDlgItem(hDlg, IDC_STATUS);
								  ::SendMessage(hWndStatus, SB_SETTEXT, 0, (long)" ���ڲ���...");
								  if (BeginGetPacket(atoi(szBuffer)) == 0)
								  {
									  UpdateProcess(::GetDlgItem(hDlg, IDC_LIST));
									  ::SendMessage(hWndStatus, SB_SETTEXT, 0, (long)" ������ϣ�");
								  }
							  }
						  }
						  else
						  {
							  ::MessageBox(hDlg, "���Ȱ�������", "��ʾ", MB_OK | MB_DEFBUTTON1);
						  }

						  break;
		}
		case IDC_BIND:
		{
						 HWND hWndStatus = ::GetDlgItem(hDlg, IDC_STATUS);
						 if (BindNetworkCards(::GetDlgItem(hDlg, IDC_COMBO_NC)) < 0)
						 {
							 NETWORKCARD_BIND = 0;
							 ::SendMessage(hWndStatus, SB_SETTEXT, 0, (long)" ������ʧ�ܣ�");
						 }
						 else
						 {
							 NETWORKCARD_BIND = 1;
							 ::SendMessage(hWndStatus, SB_SETTEXT, 0, (long)" �������ɹ���");
						 }
						 break;
		}
		case IDC_CLEAR:
			ClearGlobalVariable();
			break;
		}
		break;

	case WM_NOTIFY:		// ��Ӧͨ�ÿؼ�״̬�����仯
	{
					  if (wParam == IDC_LIST)
					  {
						  NMHDR* pHeader = (NMHDR*)lParam;
						  HWND hWndList = pHeader->hwndFrom;

						  if (pHeader->code == NM_DBLCLK)	// ˫���¼�
						  {
							  
						  }
					  }
	}
		break;
	}
	return 0;
}

void ClearGlobalVariable()
{
	TOTAL_num = 0;
	TCP_num = 0;
	UDP_num = 0;
	ICMP_num = 0;
	OICQ_num = 0;
	OICQ_PORT = NULL;
	OICQ_PICTURE = 0;
	OICQ_HTTP_GET = 0;
	WM_SEARCH_RESULT->next = NULL;
	WM_SEARCH_RESULT_TEMP = WM_SEARCH_RESULT;

	::SendMessage(::GetDlgItem(HDLG, IDC_LIST), LVM_DELETEALLITEMS, 0, 0);
	::SendMessage(::GetDlgItem(HDLG, IDC_OUTPUT), WM_SETTEXT, 0, (LPARAM)TEXT(""));
	if (NETWORKCARD_BIND)
	{
		::SendMessage(::GetDlgItem(HDLG, IDC_STATUS), SB_SETTEXT, 0, (long)" �������ɹ���");
	}
	else
	{
		::SendMessage(::GetDlgItem(HDLG, IDC_STATUS), SB_SETTEXT, 0, (long)" ׼������");
	}
}

void FindComPort(char* result)
{
	int num = -1;
	u_short sport = 0, dport = 0;
	ComPort temp1, temp2;
	temp1 = OICQ_PORT;
	while (temp1)
	{
		if (temp1->sport == 8000 || temp1->dport == 8000)		// ��Ҫ�Ľ�������������������������
		{
			if (temp1->next && (temp1->num != -1))
			{
				temp1->num = 1;
				temp2 = temp1->next;
				do
				{
					if (temp2->num != -1)
					{
						if (temp1->sport == temp2->sport && temp1->dport == temp2->dport)
						{
							temp1->num++;
							temp2->num = -1;
						}
					}
					temp2 = temp2->next;
				} while (temp2);
			}
		}
		temp1 = temp1->next;
	}

	temp1 = OICQ_PORT;
	while (temp1)
	{
		if (temp1->sport == 8000 || temp1->dport == 8000)
		{
			if (temp1->num > num)
			{
				num = temp1->num;
				sport = temp1->sport;
				dport = temp1->dport;
			}
		}
		temp1->num = 0;
		temp1 = temp1->next;
	}
	if (num !=  -1)
	{
		sprintf(result, "sport: %d, dport: %d", sport, dport);
	}
	else
	{
		sprintf(result, "");
	}

	// ------------------------------------------------------------
	temp1 = OICQ_PORT;
	while (temp1)
	{
		if (temp1->next && (temp1->num != -1))
		{
			temp1->num = 1;
			temp2 = temp1->next;
			do
			{
				if (temp2->num != -1)
				{
					if (strcmp(temp1->command, temp2->command) == 0)
					{
						temp1->num++;
						temp2->num = -1;
					}
				}
				temp2 = temp2->next;
			} while (temp2);
		}
		temp1 = temp1->next;
	}
	//temp1 = OICQ_PORT;
}

void UpdateProcess(HWND hWndList)
{
	// ɾ�����е���
	::SendMessage(hWndList, LVM_DELETEALLITEMS, 0, 0);

	int nItem = 0;	// �����
	char relatedINF[256] = { 0 };	// �����Ϣ
	char oicq_fileinfo[256] = { 0 };	// OICQ�ļ�ʶ�������Ϣ
	int i = 0;	// OICQ_COMMAND�����±�

	
	// ����һ����
	LVITEM  item = { 0 };
	item.iItem = nItem;

	item.mask = LVIF_TEXT;			// ָ��pszText����Ч
	item.pszText = (LPTSTR)TEXT("OICQ");	// �����ı�

	::SendMessage(hWndList, LVM_INSERTITEM, 0, (long)&item);

	// ����������ı�
	LVITEM lvi;
	lvi.iSubItem = 1;		// ָ��Ҫ���õ�1��ר�����ı�

	wsprintf(relatedINF, "%d", OICQ_num);
	lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
	::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

	lvi.iSubItem = 2;		// ָ��Ҫ���õ�2��ר�����ı�
	FindComPort(relatedINF);
	//wsprintf(relatedINF, "\ttest...");
	lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
	::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

	nItem++;
	// ------------------------------------------------------------
	if (OICQ_HTTP_GET)
	{
		item = { 0 };
		item.iItem = nItem;

		item.mask = LVIF_TEXT;			// ָ��pszText����Ч
		item.pszText = (LPTSTR)TEXT("OICQ->File");	// �����ı�

		::SendMessage(hWndList, LVM_INSERTITEM, 0, (long)&item);

		// ����������ı�
		lvi;
		lvi.iSubItem = 1;		// ָ��Ҫ���õ�1��ר�����ı�

		wsprintf(relatedINF, "%d", OICQ_HTTP_GET);
		lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
		::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

		lvi.iSubItem = 2;		// ָ��Ҫ���õ�2��ר�����ı�

		int j = 0;
		//memset(relatedINF, 0, sizeof(relatedINF));
		WM_SEARCH_RESULT_TEMP = WM_SEARCH_RESULT->next;
		while (WM_SEARCH_RESULT_TEMP)
		{
			i = FindFilePatternIndex(WM_SEARCH_RESULT_TEMP->str);
			if (i >= 0)
			{
				if (j > 0)
				{
					strcat(oicq_fileinfo, "��");
				}
				strcat(oicq_fileinfo, FILE_PATTERNS_MEANS[i]);
				j++;
			}
			WM_SEARCH_RESULT_TEMP = WM_SEARCH_RESULT_TEMP->next;
		}
		lvi.pszText = (LPTSTR)oicq_fileinfo;	// Ҫ���õ��ı�
		::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

		nItem++;
	}
	// ------------------------------------------------------------
	if (OICQ_PICTURE)
	{
		item = { 0 };
		item.iItem = nItem;

		item.mask = LVIF_TEXT;			// ָ��pszText����Ч
		item.pszText = (LPTSTR)TEXT("OICQ->Picture");	// �����ı�

		::SendMessage(hWndList, LVM_INSERTITEM, 0, (long)&item);

		// ����������ı�
		lvi;
		lvi.iSubItem = 1;		// ָ��Ҫ���õ�1��ר�����ı�

		wsprintf(relatedINF, "%d", OICQ_PICTURE);
		lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
		::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

		lvi.iSubItem = 2;		// ָ��Ҫ���õ�2��ר�����ı�
		wsprintf(relatedINF, "");
		lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
		::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

		nItem++;
	}
	// ------------------------------------------------------------
	ComPort temp = OICQ_PORT;
	while (temp)
	{
		if (temp->num > 0)
		{
			i = CommandMeanIndex(temp->command);
			if (i >= 0)
			{
				sprintf(relatedINF, "OICQ command: %s", OICQ_COMMANDS[i]);
				// ����һ����
				item = { 0 };
				item.iItem = nItem;

				item.mask = LVIF_TEXT;			// ָ��pszText����Ч
				item.pszText = (LPTSTR)relatedINF;	// �����ı�

				::SendMessage(hWndList, LVM_INSERTITEM, 0, (long)&item);

				// ����������ı�
				wsprintf(relatedINF, "%d", temp->num);
				lvi.iSubItem = 1;		// ָ��Ҫ���õ�1��ר�����ı�
				lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
				::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

				wsprintf(relatedINF, "%s", OICQ_COMMANDMEANS[i]);
				lvi.iSubItem = 2;		// ָ��Ҫ���õ�2��ר�����ı�
				lvi.pszText = (LPTSTR)relatedINF;	// Ҫ���õ��ı�
				::SendMessage(hWndList, LVM_SETITEMTEXT, nItem, (LPARAM)&lvi);

				nItem++;
			}
		}
		temp = temp->next;
	}
	
	// ���������ݼ�¼�����ݿ���
	AddSearchHistoryIntoMySQL(oicq_fileinfo);

}

int BindNetworkCards(HWND hWndComboBox)
{
	int i = 0;
	int cbIndex = 0;
	pcap_if_t *alldevs = GetNetworkCards();
	pcap_if_t *d = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip";
	struct bpf_program fcode;

	cbIndex = ::SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0);
	for (d = alldevs, i = 0; i<cbIndex; d = d->next, ++i);

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		//printf("can't open the adapter.%s is not supported by winpcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	//compile the filter

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0){
		//fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -2;
	}

	//set the filter

	if (pcap_setfilter(adhandle, &fcode)<0){
		//fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -3;
	}

	pcap_freealldevs(alldevs);

	return 0;
}

pcap_if_t* GetNetworkCards()
{
	pcap_if_t *alldevs;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		//printf("find all devs err:%s", errbuf);
		//exit(1);
		return NULL;
	}

	return alldevs;
}

int FindFilePatternIndex(char *str)
{
	int i = 0;
	for (i = 0; i < FILE_PATTERNS_NUM; i++)
	{
		if (strcmp(FILE_PATTERNS[i], str) == 0)
		{
			return i;
		}
	}
	return -1;
}

int BeginGetPacket(int count)
{
	
	time_t timeBegin = time(NULL);
	sprintf(filename, "%d.txt", timeBegin);
	fp = fopen(filename, "ab+");
	sprintf(filename, "HTTP_%d.txt", timeBegin);
	fp_HTTP = fopen(filename, "ab+");
	sprintf(filename, "WM_%d.txt", timeBegin);
	fp_WM = fopen(filename, "ab+");
	
	pcap_loop(adhandle, count, packet_handler, NULL);
	fprintf(fp, "Get %d packet", count);
	fprintf(fp, "\tTCP: %d packet", TCP_num);
	fprintf(fp, "\tUDP: %d packet", UDP_num);
	fprintf(fp, "\tOICQ: %d packet\r\n", OICQ_num);

	char buf[1024] = { 0 };
	sprintf(buf, "Get %d packet\tTCP: %d packet\tUDP: %d packet\tICMP: %d packet\r\n", count, TCP_num, UDP_num, ICMP_num);
	::SendMessage(::GetDlgItem(HDLG, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT(buf));

	fclose(fp);
	fclose(fp_HTTP);
	fclose(fp_WM);

	// ʶ��OICQЭ�鴫����ļ�
	if (OICQ_HTTP_GET)
	{
		int i = 0, length = 0;

		sprintf(filename, "WM_%d.txt", timeBegin);
		fp_WM = fopen(filename, "r");
		while (!feof(fp_WM))
		{
			fgets(buf, sizeof(buf), fp_WM);

			length = strlen(buf);
			wmSearch(FILE_PATTERN_WMSTRUCT, (unsigned char*)buf, length);	// wmGroupMatch�������ı�

			//fseek(fp_WM, -(MAXM - 1), SEEK_CUR);	// ��ǰ�ƶ�ģʽ����󳤶�-1, ������ʼ�򲻸ı�
		}
		fclose(fp_WM);
	}

	TOTAL_num = count;
	return 0;
}

int GetSearchHistoryFromMySQL(HWND hDlg)
{
	/*
	mysql> describe packetcapture_inf;
	+------------------+-----------+------+-----+---------+-------+
	| Field            | Type      | Null | Key | Default | Extra |
	+------------------+-----------+------+-----+---------+-------+
	| TIME             | char(30)  | NO   | PRI | NULL    |       |
	| TOTALPACKETNUM   | int(11)   | NO   |     | NULL    |       |
	| OICQPACKETNUM    | int(11)   | YES  |     | NULL    |       |
	| OICQ_FILENUM     | int(11)   | YES  |     | NULL    |       |
	| OICQ_FILEINFO    | char(100) | YES  |     | NULL    |       |
	| OICQ_PICTURENUM  | int(11)   | YES  |     | NULL    |       |
	| OICQ_PICTUREINFO | char(100) | YES  |     | NULL    |       |
	+------------------+-----------+------+-----+---------+-------+
	*/

	// �������OUTPUT�༭��
	::SendMessage(::GetDlgItem(hDlg, IDC_OUTPUT), WM_SETTEXT, 0, (LPARAM)TEXT(""));


	MYSQL * con = mysql_init((MYSQL*) 0); 
	MYSQL_RES *res;
	MYSQL_ROW row;

	int rt;	//int t, i;
	char buf[256] = { 0 };
	
	char dbuser[30] = "root";
	char dbpasswd[30] = "root";
	char dbip[30] = "localhost";
	char dbname[50] = "OICQexe_MySQL";
	char tablename[50] = "PacketCapture_INF";
	char *query = NULL;

	if (con != NULL && mysql_real_connect(con, dbip, dbuser, dbpasswd, dbname, 3306, NULL, 0))
	{
		if (!mysql_select_db(con, dbname))
		{
			con->reconnect = 1;		/* set to 1 if automatic reconnect */

			query = "select * from PacketCapture_INF";

			rt = mysql_real_query(con, query, strlen(query));		// �ɹ�����0
			if (rt == 0)
			{
				res = mysql_store_result(con);	// �����������res�ṹ����

				//t = mysql_num_fields(res);
				while (row = mysql_fetch_row(res))
				{
					sprintf(buf, "%s\r\n\tTotal: %s packet, OICQ: %s packet\r\n\tOICQ_File: %s [%s]\tOICQ_Picture: %s packet\r\n\r\n",
						row[0],
						row[1],
						row[2],
						row[3],
						row[4],
						row[5]);
					::SendMessage(::GetDlgItem(hDlg, IDC_OUTPUT), EM_REPLACESEL, TRUE, (LPARAM)TEXT(buf));
				}

				mysql_free_result(res);
				mysql_close(con);
				return 0;
			}
			else
			{
				mysql_close(con);
				return -3;	// ��ѯqueryʧ��
			}
			
		}
		else
		{
			mysql_close(con);
			return -2;	// ʹ��OICQexe_MySQLʧ��
		}
	}
	else
	{
		return -1;	// ����MySQL���ݿ�ʧ��
	}
}

int AddSearchHistoryIntoMySQL(char *oicq_fileinfo)
{
	/*
	mysql> describe packetcapture_inf;
	+------------------+-----------+------+-----+---------+-------+
	| Field            | Type      | Null | Key | Default | Extra |
	+------------------+-----------+------+-----+---------+-------+
	| TIME             | char(30)  | NO   | PRI | NULL    |       |
	| TOTALPACKETNUM   | int(11)   | NO   |     | NULL    |       |
	| OICQPACKETNUM    | int(11)   | YES  |     | NULL    |       |
	| OICQ_FILENUM     | int(11)   | YES  |     | NULL    |       |
	| OICQ_FILEINFO    | char(100) | YES  |     | NULL    |       |
	| OICQ_PICTURENUM  | int(11)   | YES  |     | NULL    |       |
	| OICQ_PICTUREINFO | char(100) | YES  |     | NULL    |       |
	+------------------+-----------+------+-----+---------+-------+
	*/

	//return 0;
	MYSQL * con = mysql_init((MYSQL*)0);

	char query[512] = { 0 };
	char time_mysql[30] = { 0 };
	int rt;

	char dbuser[30] = "root";
	char dbpasswd[30] = "root";
	char dbip[30] = "localhost";
	char dbname[50] = "OICQexe_MySQL";
	char tablename[50] = "PacketCapture_INF";

	if (con != NULL && mysql_real_connect(con, dbip, dbuser, dbpasswd, dbname, 3306, NULL, 0))
	{
		if (!mysql_select_db(con, dbname))
		{
			con->reconnect = 1;		/* set to 1 if automatic reconnect */

			time_t rawtime;
			struct tm *timeinfo;
			time(&rawtime);				// ��ȡϵͳʱ�� 
			timeinfo = localtime(&rawtime);	// ת������ʱ�� 
			sprintf(time_mysql, "%d.%02d.%02d - %02d:%02d:%02d",
				timeinfo->tm_year + 1900, 
				timeinfo->tm_mon + 1, 
				timeinfo->tm_mday, 
				timeinfo->tm_hour, 
				timeinfo->tm_min, 
				timeinfo->tm_sec);
			sprintf(query, "INSERT INTO PacketCapture_INF VALUES('%s', %d, %d, %d, '%s', %d, '%s')",
				time_mysql,
				TOTAL_num,
				OICQ_num,
				OICQ_HTTP_GET,
				oicq_fileinfo,
				OICQ_PICTURE,
				"NULL");

			int temp = strlen(query);
			rt = mysql_real_query(con, query, strlen(query));		// �ɹ�����0
			mysql_close(con);
			if (rt == 0)
			{	
				return 0;
			}
			else
			{
				return -3;	// ִ��queryʧ��
			}

		}
		else
		{
			mysql_close(con);
			return -2;	// ʹ��OICQexe_MySQLʧ��
		}
	}
	else
	{
		return -1;	// ����MySQL���ݿ�ʧ��
	}
}