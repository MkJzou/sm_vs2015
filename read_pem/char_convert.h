/** @file
 * @brief 字符转换函数。
 *
 * $Author: tufei $
 * $Date: 2012/03/29 01:20:19 $
 * $Revision: 1.5 $
 *
 * @copy
 * <h2><center>版权所有 (C)2012, 武汉天喻信息产业股份有限公司</center></h2>
 */

#ifndef __CHAR_CONVERT_H__
#define __CHAR_CONVERT_H__

/**
 * @brief 字符转换成(右靠)BCD码。
 *
 * @param[in]  pcAsc，字符串。
 * @param[out] pucBcd，BCB码缓存。
 * @param[in]  usLen，需要转换的字符串长度。
 * @return
 * - 0，表示成功；
 * - <0，表示失败。
 */
extern short Asc2Bcd(char* pcAsc, unsigned char* pucBcd, unsigned short usLen);

/**
 * @brief BCD码换成字符转
 *
 * @param[in]  pucBcd，BCB码缓存。
 * @param[out] pcAsc，字符串。
 * @param[in]  usLen，需要转换的BCB码长度。
 * @return
 * - 0，表示成功；
 * - <0，表示失败。
 */
extern short Bcd2Asc(unsigned char* pucBcd, char* pcAsc, unsigned short usLen);

/**
 * @brief Bcd码转整型数值。
 *
 * @param[in]  	pucBcd，		Bcd码字符串。
 * @param[in]  	ucBcdLen，	Bcd码字符串长度，取值范围：(0-6)。
 * @return
 * - >0，表示成功，为转化后的整型数值；
 * - <0，表示失败。
 */
int Bcd2Int(unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief INT型数转BCD码。
 *
 * @param[in]  uiNum，整型数。
 * @param[out] pucBcd，BCD码缓存。高字节在前。
 * @param[in]  ucBcdLen，BCD码长度。
 * @return
 * - 0，表示成功；
 * - <0，表示失败。
 */
short Int2Bcd(unsigned int uiNum, unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief LONG LONG 型数转BCD码。
 *
 * @param[in]  ullNum，64位整型数。
 * @param[out] pucBcd，BCD码缓存。高字节在前。
 * @param[in]  ucBcdLen，BCD码长度。
 * @return
 * - 0，表示成功；
 * - <0，表示失败。
 */
short LongLong2Bcd(ULONGLONG ullNum, unsigned char* pucBcd, unsigned char ucBcdLen);

/**
 * @brief Bcd码转LONG LONG型数值。
 *
 * @param[in]  	pucBcd，		Bcd码字符串。
 * @param[in]  	ucBcdLen，	Bcd码字符串长度，取值范围：(0-6)。
 * @return
 * - >0，表示成功，为转化后的LONG LONG型数值；
 * - <0，表示失败。
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
