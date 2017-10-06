#ifndef WM_H
#define WM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASHTABLESIZE (256*256)
#define MAXLEN 256

typedef struct wm_pattern_struct//ÿ��ģʽ���Ľṹ
{
	struct wm_pattern_struct *next;//ָ����һ��ģʽ��
	unsigned char *psPat; //pattern array//ģʽ������
	unsigned psLen; //length of pattern in bytes//ģʽ���ĳ���
}WM_PATTERN_STRUCT;

#define HASH_TYPE short
#define SHIFTTABLESIZE (256*256)

typedef struct wm_struct//ģʽ�����Ľṹ
{
	WM_PATTERN_STRUCT *plist; //pattern listģʽ�Ӵ��б�
	WM_PATTERN_STRUCT *msPatArray; //array of patternsģʽ�Ӵ����飨���У�
	unsigned short *msNumArray; //array of group counts, # of patterns in each hash group
	int msNumPatterns; //number of patterns loaded//ģʽ�Ӵ��ĸ���
	unsigned msNumHashEntries;//HASH��Ĵ�С
	HASH_TYPE *msHash; //last 2 characters pattern hash table//HASH��
	unsigned char* msShift; //bad word shift table//SHIFT��
	HASH_TYPE *msPrefix; //first 2 characters prefix table//PREFIX��
	int msSmallest; //shortest length of all patterns//���ģʽ�Ӵ��ĳ���
}WM_STRUCT;

//��������
WM_STRUCT * wmNew();  //����ģʽ��������
void wmFree(WM_STRUCT *ps); //�ͷſռ亯��
int wmAddPattern(WM_STRUCT *ps, unsigned char *P, int m); //�����ģʽ������
int wmPrepPatterns(WM_STRUCT *ps); //Ԥ������
void wmSearch(WM_STRUCT *ps, unsigned char *Tx, int n); //ģʽƥ�亯��

#endif