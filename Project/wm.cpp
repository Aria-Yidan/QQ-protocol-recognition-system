#include "wm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

extern int nline = 1;
extern int nfound = 0;
#define MAXN 10001 //ģʽ������󳤶�MAXN - 1
#define MAXM 51//������󳤶�ΪMAXM - 1

/* ****************************************************************
������void wmNew()
Ŀ�ģ�����һ��ģʽ������
������
��
���أ�
WM_STRUCT - ������ģʽ����
****************************************************************/
WM_STRUCT * wmNew()
{
	WM_STRUCT *p = (WM_STRUCT *)malloc(sizeof(WM_STRUCT));
	if (!p) return 0;
	p->msNumPatterns = 0;//ģʽ���ĸ���,��ʼΪ0
	p->msSmallest = 1000;//���ģʽ���ĳ���
	return p;
}

/* ****************************************************************
������void wmFree(WM_STRUCT *)
Ŀ�ģ��ͷ�ģʽ����ռ�ÿռ�
������
ps => ģʽ����
���أ�

****************************************************************/
void wmFree(WM_STRUCT *ps) //�ͷſռ亯��
{
	if (ps->msPatArray) //���ģʽ�����д����Ӵ��������ͷ��Ӵ�����ռ�ÿռ�
	{
		if (ps->msPatArray->psPat) free(ps->msPatArray->psPat);	//�Ӵ���Ϊ�գ����ͷ�
		free(ps->msPatArray);
	}
	if (ps->msNumArray) free(ps->msNumArray);
	if (ps->msHash) free(ps->msHash);
	if (ps->msPrefix) free(ps->msPrefix);
	if (ps->msShift) free(ps->msShift);
	free(ps);
}

/* ****************************************************************
������int wmAddPattern(WM_STRUCT *,unsigned char *,int )
Ŀ�ģ���ģʽ����ps������һ������Ϊm���Ӵ�q
������
ps => ģʽ����
q => Ҫ�������Ӵ�
m => �Ӵ�����
���أ�
int* - �����ɹ�0��ʧ��-1
****************************************************************/
int wmAddPattern(WM_STRUCT *ps, unsigned char *q, int m)
{
	WM_PATTERN_STRUCT *p;  //����һ���Ӵ��ṹ
	p = (WM_PATTERN_STRUCT *)malloc(sizeof(WM_PATTERN_STRUCT));
	if (!p) return -1;

	p->psPat = (unsigned char*)malloc(m + 1); //���Ӵ�����ĳ��ȷ���ռ�
	memset(p->psPat + m, 0, 1);	//���һ��λ������Ϊ�����ַ���/0�� 
	memcpy(p->psPat, q, m); //����q���Ӵ��ṹ������
	p->psLen = m; //�Ӵ����ȸ�ֵ
	ps->msNumPatterns++; //ģʽ�������Ӵ�������1
	if (p->psLen < (unsigned)ps->msSmallest) ps->msSmallest = p->psLen; //����ȷ������ַ�������

	p->next = ps->plist; //�������Ӵ������ַ������б��С�������ʽ�������ڶ���ͷ��
	ps->plist = p;

	return 0;
}

/* ****************************************************************
������static unsigned HASH16(unsigned char *)
Ŀ�ģ���һ���ַ����й�ϣ���㡣���㷽ʽΪ��(((*T)<<8) | *(T+1))��
������
T => Ҫ��ϣ������ַ���
���أ�
unsigned - ��̬���������ض��ַ���T����Ĺ�ϣֵ
****************************************************************/
static unsigned HASH16(unsigned char *T)
{
	/*/
	printf("T:%c\n",*(T));
	getchar();
	printf("T+1:%c\n",*(T+1));
	getchar();
	printf("T<<8:%c\n",(int)((*T)<<8));
	getchar();
	printf("HASH16:%d\n",((*T)<<8) | *(T+1));
	getchar();
	//*/
	return (unsigned short)(((*T) << 8) | *(T + 1)); //�Ե�һ���ַ�����8λ��Ȼ����ڶ����ַ��������
}

/* ****************************************************************
������sort(WM_STRUCT *)
Ŀ�ģ����ַ�����ps�е��Ӵ����У������Ӵ���ֵ�Ĺ�ϣֵ��С��������
������
ps => ģʽ����
���أ���
****************************************************************/
void sort(WM_STRUCT *ps)
{
	int m = ps->msSmallest; //��ȡ����Ӵ�����
	int i, j;
	unsigned char *temp;
	int flag;	//ð������ı�־λ����һ�˱Ƚ��޽���ʱ��˵���Ѿ�������򣬼���������ѭ������
	for (i = ps->msNumPatterns - 1, flag = 1; i > 0 && flag; i--)  //ѭ�����ַ������е�ÿ���Ӵ����������ϣֵ��С����ð������
	{
		flag = 0;
		for (j = 0; j<i; j++)
		{
			if (HASH16(&(ps->msPatArray[j + 1].psPat[m - 2]))<HASH16(&(ps->msPatArray[j].psPat[m - 2])))//�Ƚϵ�Ϊÿ���Ӵ���ȡ���ֵ���������ַ��Ĺ�ϣֵ
			{
				flag = 1;
				temp = ps->msPatArray[j + 1].psPat;
				ps->msPatArray[j + 1].psPat = ps->msPatArray[j].psPat;
				ps->msPatArray[j].psPat = temp;
			}
		}
	}
}

/* ****************************************************************
������static void wmPrepHashedPatternGroups(WM_STRUCT *)
Ŀ�ģ����㹲�ж��ٸ���ͬ�Ĺ�ϣֵ���Ҵ�С����
������
ps => ģʽ����
���أ�
****************************************************************/
static void wmPrepHashedPatternGroups(WM_STRUCT *ps)
{
	unsigned sindex, hindex, ningroup;
	int i;
	int m = ps->msSmallest;
	ps->msNumHashEntries = HASHTABLESIZE;	//HASH��Ĵ�С
	ps->msHash = (HASH_TYPE*)malloc(sizeof(HASH_TYPE)* ps->msNumHashEntries);	//HASH��
	if (!ps->msHash)
	{
		printf("No memory in wmPrepHashedPatternGroups()\n");
		return;
	}

	for (i = 0; i<(int)ps->msNumHashEntries; i++)	//HASH��Ԥ�����ʼ����ȫ����ʼ��Ϊ(HASH_TYPE)-1
	{
		ps->msHash[i] = (HASH_TYPE)-1;
	}

	for (i = 0; i<ps->msNumPatterns; i++)	//��������Ӵ�����HASHԤ����
	{
		hindex = HASH16(&ps->msPatArray[i].psPat[m - 2]);	//��ģʽ�Ӵ�����������ַ������ϣֵ��ƥ�䣩
		sindex = ps->msHash[hindex] = i;
		ningroup = 1;
		//��ʱ��ϣ���Ѿ�������
		while ((++i<ps->msNumPatterns) && (hindex == HASH16(&ps->msPatArray[i].psPat[m - 2])))	//�Һ�׺��ͬ���Ӵ���
			ningroup++;
		ps->msNumArray[sindex] = ningroup;	//��i���Ӵ���������ģʽ�������׺2�ַ���ͬ�Ӵ��ĸ���
		i--;
	}
}

/* ****************************************************************
������static void wmPrepShiftTable(WM_STRUCT *)
Ŀ�ģ�����shift�����ÿ���ַ���Ҫ�ƶ��ľ���
������
ps => ģʽ����
���أ�

****************************************************************/
static void wmPrepShiftTable(WM_STRUCT *ps)
{
	int i;
	unsigned short m, k, cindex;
	unsigned shift;
	m = (unsigned short)ps->msSmallest;
	ps->msShift = (unsigned char*)malloc(SHIFTTABLESIZE*sizeof(char));
	if (!ps->msShift)
		return;

	for (i = 0; i<SHIFTTABLESIZE; i++)	//��ʼ��Shift����ʼֵΪ����ַ����ĳ���
	{
		ps->msShift[i] = (unsigned)(m - 2 + 1);
	}

	for (i = 0; i<ps->msNumPatterns; i++)	//���ÿ���Ӵ�Ԥ����
	{
		for (k = 0; k<m - 1; k++)
		{
			shift = (unsigned short)(m - 2 - k);
			cindex = ((ps->msPatArray[i].psPat[k] << 8) | (ps->msPatArray[i].psPat[k + 1]));//BΪ2
			if (shift < ps->msShift[cindex])
				ps->msShift[cindex] = shift;//k=m-2ʱ��shift=0��
		}
	}
}

/* ****************************************************************
������static void wmPrepPrefixTable(WM_STRUCT *)
Ŀ�ģ�����Prefix��
������
ps => ģʽ����
���أ�
��
****************************************************************/
static void wmPrepPrefixTable(WM_STRUCT *ps)//����Prefix��
{
	int i;
	ps->msPrefix = (HASH_TYPE*)malloc(sizeof(HASH_TYPE)* ps->msNumPatterns);	//����ռ䳤��Ϊ�����Ӵ��ĸ���*
	if (!ps->msPrefix)
	{
		printf("No memory in wmPrepPrefixTable()\n");
		return;
	}

	for (i = 0; i<ps->msNumPatterns; i++)	//��ϣ����Prefix��
	{
		ps->msPrefix[i] = HASH16(ps->msPatArray[i].psPat);//��ÿ��ģʽ����ǰ׺���й�ϣ
	}
}

/* ****************************************************************
������void wmGroupMatch(WM_STRUCT *,int ,unsigned char *,unsigned char *)
Ŀ�ģ���׺��ϣֵ��ͬ���Ƚ�ǰ׺�Լ������ַ���ƥ��
������
ps => ģʽ����
lindex =>
Tx => Ҫ����ƥ����ַ�������
T => ģʽ�Ӵ�
���أ�
��
****************************************************************/
void wmGroupMatch(WM_STRUCT *ps,
	int lindex,//lindexΪ��׺��ϣֵ��ͬ����Щģʽ�Ӵ��е�һ��ģʽ�Ӵ���index
	unsigned char *Tx,
	unsigned char *T)
{
	WM_PATTERN_STRUCT *patrn;
	WM_PATTERN_STRUCT *patrnEnd;
	int text_prefix;
	unsigned char *px, *qx;

	patrn = &ps->msPatArray[lindex];
	patrnEnd = patrn + ps->msNumArray[lindex];

	text_prefix = HASH16(T);


	for (; patrn<patrnEnd; patrn++)
	{
		if (ps->msPrefix[lindex++] != text_prefix)
			continue;
		else	//�����׺��ϣֵ��ͬ����
		{
			px = patrn->psPat;	//ȡpatrn���ִ�
			qx = T;
			while (*(px++) == *(qx++) && *(qx - 1) != '\0');	//����ģʽ�����бȽ�
			if (*(px - 1) == '\0')	//ƥ�䵽�˽���λ�ã�˵��ƥ��ɹ�
			{
				printf("Match pattern \"%s\" at line %d column %d\n", patrn->psPat, nline, T - Tx + 1);
				nfound++;
			}
		}
	}
}

/* ****************************************************************
������int wmPrepPatterns(WM_STRUCT *ps)
Ŀ�ģ���ģʽ����Ԥ������plist�õ�msPatArray
������
ps => ģʽ����
���أ�
int - Ԥ����ɹ�0��ʧ��-1
****************************************************************/
int wmPrepPatterns(WM_STRUCT *ps)
{
	int kk;
	WM_PATTERN_STRUCT *plist;

	ps->msPatArray = (WM_PATTERN_STRUCT*)malloc(sizeof(WM_PATTERN_STRUCT)*ps->msNumPatterns);
	if (!ps->msPatArray)
		return -1;

	ps->msNumArray = (unsigned short*)malloc(sizeof(short)*ps->msNumPatterns);
	if (!ps->msNumArray)
		return -1;

	for (kk = 0, plist = ps->plist; plist != NULL && kk<ps->msNumPatterns; plist = plist->next)
	{
		memcpy(&ps->msPatArray[kk++], plist, sizeof(WM_PATTERN_STRUCT));
	}
	sort(ps);	//��ϣ����
	wmPrepHashedPatternGroups(ps);	//��ϣ��
	wmPrepShiftTable(ps);	//shift��
	wmPrepPrefixTable(ps);	//Prefix��
	return 0;
}

/* ****************************************************************
������void wmSearch(WM_STRUCT *ps,unsigned char *Tx,int n)
Ŀ�ģ��ַ���ƥ�����
������
ps => ģʽ����
Tx => �����ҵ��ַ�������
n => �����ҵ��ַ�������
���أ�
��
****************************************************************/
void wmSearch(WM_STRUCT *ps, unsigned char *Tx, int n)
{
	int Tleft, lindex, tshift;
	unsigned char *T, *Tend, *window;
	Tleft = n;
	Tend = Tx + n;
	if (n < ps->msSmallest)	/*�����ҵ��ַ������б���Сģʽ�Ӵ����̣�
							��Ȼ�ǲ����ܲ��ҵ��ģ�ֱ���˳�*/
							return;

	for (T = Tx, window = Tx + ps->msSmallest - 1; window<Tend; T++, window++, Tleft--)
	{
		tshift = ps->msShift[(*(window - 1) << 8) | *window];
		while (tshift)//��tshift!=0,��ƥ��
		{
			window += tshift;
			T += tshift;
			Tleft -= tshift;
			if (window>Tend) return;
			tshift = ps->msShift[(*(window - 1) << 8) | *window];
		}
		//tshift=0��������׺��ϣֵ�Ѿ���ͬ
		if ((lindex = ps->msHash[(*(window - 1) << 8) | *window]) == (HASH_TYPE)-1) continue;
		lindex = ps->msHash[(*(window - 1) << 8) | *window];
		wmGroupMatch(ps, lindex, Tx, T);//��׺��ϣֵ��ͬ���Ƚ�ǰ׺������ģʽ��
	}
}

int TEST()
{
	int length, n;
	WM_STRUCT *p;
	char keyword[MAXM]; //����
	char str[MAXN]; //ģʽ��
	p = wmNew();	//����ģʽ����
	//printf("Scanf the number of pattern words ->\n");	//����ģʽ������ģʽ�Ӵ��ĸ���,n
	//scanf("%d", &n);
	//printf("Scanf the pattern words ->\n");
	char pattern[4][20] = { "d0cf11e0a1b11ae1", "25504446", "504b0304", "526172211a0700" };

	for (n = 0; n < 4; n++)
	{
		length = strlen(pattern[n]);
		wmAddPattern(p, (unsigned char*)pattern[n], length);	//����ģʽ�Ӵ�
	}
	wmPrepPatterns(p);	//��ģʽ����Ԥ����
	strcpy(str, "485454502f312e3120323030204f4b0d0a557365722d52657475726e436f64653a20300d0a436f6e74656e742d4c616e67756167653a7a682d434e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6f637465742d73747265616d0d0a436f6e74656e742d446973706f736974696f6e3a206174746163686d656e740d0a4163636570742d52616e6765733a2062797465730d0a436f6e74656e742d4c656e6774683a2033313734340d0a0d0ad0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000003900000000000000001000003b00000001000000feffffff0000000038000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff526172211a0700ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeca5c1005b8009040000f052bf0000000000001000000000000800003c1400000e00626a626aacfaacfa000000000000000000000000000000000000040816003b1a0000ce900100ce90010006010000000000000d0000000000000000000000000000000000000000000000ffff0f000000000000000000ffff0f000000000000000000ffff0f0000000000000000000000000000000000b70000000000a606000000000000a6060000ef13000000000000ef13000000000000ef13000000000000ef13000000000000ef130000140000000000000000000000ffffffff000000000314000000000000031400000000000003140000380000003b140000240000005f1400001c0000000314000000000000fe1b00006c0100007b140000000000007b140000000000007b140000000000007b140000000000007b14000000000000af15000000000000af15000000000000af15000000000000711b000002000000731b000000000000731b000000000000731b000000000000731b000000000000731b000000000000731b0000240000006a1d0000a20200000c20000032000000971b00002100000000000000000000000000000000000000ef13000000000000af1500000000000000000000000000000000000000000000af15000000000000af15000000000000af15000000000000af15000000000000971b0000000000000000000000000000ef13000000000000ef130000000000007b1400000000000000000000000000007b14000034010000b81b000016000000851800000000000085180000000000008518000000000000af150000ae010000ef130000000000007b14000000000000ef130000000000007b14000000000000711b00000000000000000000000000008518000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000af15000000000000711b000000000000000000000000000085180000000000000000000000000000851800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085180000000000007b14000000000000ffff");	//����Ҫ��ƥ����ַ�������
	length = strlen(str);
	wmSearch(p, (unsigned char*)str, length);
	wmFree(p);

	getchar();
	getchar();
	return(0);
}