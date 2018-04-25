/** @file
 * @brief �ַ�ת��������
 *
 * $Author: tufei $
 * $Date: 2012/03/29 01:20:19 $
 * $Revision: 1.5 $
 *
 * @copy
 * <h2><center>��Ȩ���� (C)2012, �人������Ϣ��ҵ�ɷ����޹�˾</center></h2>
 */

#ifndef __CHAR_CONVERT_H__
#define __CHAR_CONVERT_H__

/**
 * @brief �ַ�ת����(�ҿ�)BCD�롣
 *
 * @param[in]  pcAsc���ַ�����
 * @param[out] pucBcd��BCB�뻺�档
 * @param[in]  usLen����Ҫת�����ַ������ȡ�
 * @return
 * - 0����ʾ�ɹ���
 * - <0����ʾʧ�ܡ�
 */
extern short Asc2Bcd(char* pcAsc, unsigned char* pucBcd, unsigned short usLen);

/**
 * @brief BCD�뻻���ַ�ת
 *
 * @param[in]  pucBcd��BCB�뻺�档
 * @param[out] pcAsc���ַ�����
 * @param[in]  usLen����Ҫת����BCB�볤�ȡ�
 * @return
 * - 0����ʾ�ɹ���
 * - <0����ʾʧ�ܡ�
 */
extern short Bcd2Asc(unsigned char* pucBcd, char* pcAsc, unsigned short usLen);

/**
 * @brief Bcd��ת������ֵ��
 *
 * @param[in]  	pucBcd��		Bcd���ַ�����
 * @param[in]  	ucBcdLen��	Bcd���ַ������ȣ�ȡֵ��Χ��(0-6)��
 * @return
 * - >0����ʾ�ɹ���Ϊת�����������ֵ��
 * - <0����ʾʧ�ܡ�
 */
int Bcd2Int(unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief INT����תBCD�롣
 *
 * @param[in]  uiNum����������
 * @param[out] pucBcd��BCD�뻺�档���ֽ���ǰ��
 * @param[in]  ucBcdLen��BCD�볤�ȡ�
 * @return
 * - 0����ʾ�ɹ���
 * - <0����ʾʧ�ܡ�
 */
short Int2Bcd(unsigned int uiNum, unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief LONG LONG ����תBCD�롣
 *
 * @param[in]  ullNum��64λ��������
 * @param[out] pucBcd��BCD�뻺�档���ֽ���ǰ��
 * @param[in]  ucBcdLen��BCD�볤�ȡ�
 * @return
 * - 0����ʾ�ɹ���
 * - <0����ʾʧ�ܡ�
 */
short LongLong2Bcd(ULONGLONG ullNum, unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief Bcd��תLONG LONG����ֵ��
 *
 * @param[in]  	pucBcd��		Bcd���ַ�����
 * @param[in]  	ucBcdLen��	Bcd���ַ������ȣ�ȡֵ��Χ��(0-6)��
 * @return
 * - >0����ʾ�ɹ���Ϊת�����LONG LONG����ֵ��
 * - <0����ʾʧ�ܡ�
 */
LONGLONG Bcd2LongLong(unsigned char* pucBcd, unsigned char ucBcdLen);

int iSplitStr(const char* pcStr, int iStr1Len, char* pcStr1, char* pcStr2);

void BcdSumToAsc(unsigned char* pucBcdSum, char* pcAscSum);

int iTestDate(const unsigned char* pucDate);
void AddDot(char* pcData);
char AscToInt(char c);
int iStrIsNum(const char* pcBuff);
unsigned char  *chstohex ( const char *chs, unsigned char *hex);
void OutputData2Log(const unsigned char *pucOutInfo, DWORD iDataLen);
void OutHintInfo2Log(const char *pucOutInfo);
void Hex2Str(unsigned char *src, unsigned char *dst, unsigned char Src_Len);
void TRACEBUF(unsigned char* buff, int buffLen);

void ConvertOutputData(unsigned char* pucOutput, int iOutLen, char* pcOut);
void IntToAscStr(char* pNumStr);
#endif //__CHAR_CONVERT_H__
