/** @file
 * @brief 字符转换函数。
 *
 * $Author: tufei $
 * $Date: 2012/03/29 01:23:01 $
 * $Revision: 1.6 $
 *
 * @copy
 * <h2><center>版权所有 (C)2012, 武汉天喻信息产业股份有限公司</center></h2>
 */

/**************************** INCLUDE FILES BEGIN **************************/
//#ifdef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <Windows.h>
#include "char_convert.h"

//#include "global_config.h"
//#include "win32_debug_cfg.h"
//#include "ty_err.h"
//#include "ty_type.h"

//#else //WIN32

//#include "includes.h"

//#endif //WIN32

#include <string.h>
#include <stdlib.h>

//#include "common.h"



#ifdef SERVER
#define LOGFILE _T(".\\Log_Server.txt")
#else
#ifdef CLIENT
#define LOGFILE _T(".\\Log_Client.txt")
//#endif
#else
#ifndef PREINIT
#define LOGFILE _T(".\\UpgradeToolLog.txt")

#endif
#endif
#endif

//#ifndef PREINIT
//#define LOGFILE _T(".\\Log_PreInit.txt")
//#endif


//#include "char_convert.h"
/**************************** INCLUDE FILES END ****************************/

/**************************** DEFINE MACRO BEGIN ***************************/

/**************************** DEFINE MACRO END *****************************/

/**************************** EXTERN FUNCTIONS BEGIN ***********************/

/**************************** EXTERN FUNCTIONS END *************************/

/**************************** EXTERN VARIABLES BEGIN ***********************/

/**************************** EXTERN VARIABLES END *************************/

/**************************** GLOBAL VARIABLES BEGIN ***********************/

/**************************** GLOBAL VARIABLES END *************************/

/**************************** STATIC FUNCTIONS BEGIN ***********************/

/**************************** STATIC FUNCTIONS END *************************/

/**************************** STATIC VARIABLES BEGIN ***********************/

/**************************** STATIC VARIABLES END *************************/


//short Asc2Bcd(char *pcAsc, unsigned char *pucBcd, unsigned short usLen)
//{
//	unsigned char ucAsc;
//	unsigned char ucByte = 0;
//	unsigned short usCnt;
//
//	for(usCnt = 0; usCnt < usLen; usCnt++)
//	{
//		ucAsc = pcAsc[usCnt];
//		if(    ((ucAsc >= '0') && (ucAsc <= '9'))
//			|| ((ucAsc >= 'A') && (ucAsc <= 'F'))
//			|| ((ucAsc >= 'a') && (ucAsc <= 'f'))
//			)
//		{
//			if((usLen - usCnt) % 2)
//			{
//				ucByte += ucAsc & 0x0F;
//				if(    ((ucAsc & 0xF0) == 0x40)//对字母小写处理
//					|| ((ucAsc & 0xF0) == 0x60)//对字母大写处理
//					)
//				{
//					ucByte += 0x09;
//				}
//				*pucBcd++ = ucByte;
//			}
//			else
//			{
//				ucByte = (ucAsc<<4);
//				if(   ((ucAsc & 0xF0) == 0x40)//对字母小写处理
//					||((ucAsc & 0xF0) == 0x60)//对字母大写处理
//					)
//				{
//					ucByte += 0x90;
//				}
//			}
//		}
//		else
//		{
//			return TY_ERR;
//		}
//	}
//
//	return TY_OK;
//}

//short Bcd2Asc(unsigned char *pucBcd, char *pcAsc, unsigned short usLen)
//{
//	unsigned short i;
//	unsigned char ucTmp;
//
//	for(i=0;i<usLen;i++)
//	{
//		ucTmp = pucBcd[i]>>4;
//		pcAsc[i*2] = (ucTmp>9)? (ucTmp-10+'A'):(ucTmp+'0');
//		ucTmp = pucBcd[i]&0xF;
//		pcAsc[i*2+1] = (ucTmp>9)? (ucTmp-10+'A'):(ucTmp+'0');
//	}
//	return TY_OK;
//}
short Bcd2Asc(unsigned char* pucBcd, char* pcAsc, unsigned short usLen)
{
	for (int i = 0; i < usLen; i++)
	{
		sprintf_s(pcAsc, sizeof(pcAsc), "%02X", pucBcd[i]);
		pcAsc += 2;
	}
	return 0;
}

short Asc2Bcd(char* pcAsc, unsigned char* pucBcd, unsigned short usLen)
{
	//unsigned char ucAsc;
	unsigned char ucByte = 0;
	unsigned short usCnt;
	for (usCnt = 0; usCnt < usLen; usCnt++)
	{
		if (((pcAsc[usCnt] < '0') && (pcAsc[usCnt] > '9')) && ((pcAsc[usCnt] < 'A') && (pcAsc[usCnt] > 'F')) && ((pcAsc[usCnt] < 'a') && (pcAsc[usCnt] > 'f')))
		{
			return -1;  //有出现0-9 A-F a-f之外的字符
		}
	}
	char szTmp[3] = {0};
	for (int i = 0; i < usLen / 2; i++)
	{
		memcpy(szTmp, pcAsc + 2 * i, 2);
		*pucBcd++ = (unsigned char)strtol(szTmp, NULL, 16);
	}
	return 0;
}


int Bcd2Int(unsigned char* pucBcd, unsigned char ucBcdLen)
{
	char acTemp[13];

	if ((ucBcdLen > 6) || (pucBcd == NULL))
	{
		return -2;
	}
	Bcd2Asc(pucBcd, acTemp, ucBcdLen);
	acTemp[2 * ucBcdLen] = 0;
	return (atoi(acTemp));
}

short Int2Bcd(unsigned int uiNum, unsigned char* pucBcd, unsigned char ucBcdLen)
{
	unsigned int i;
	unsigned char ucByte;

	for (i = 0; i < ucBcdLen; i++)
	{
		ucByte = uiNum % 100;
		uiNum /= 100;

		pucBcd[ucBcdLen - 1 - i] = (ucByte % 10) & 0x0F;
		pucBcd[ucBcdLen - 1 - i] |= ((ucByte / 10) << 4);
	}
	return 0;
}

short LongLong2Bcd(ULONGLONG ullNum, unsigned char* pucBcd, unsigned char ucBcdLen)
{
	unsigned int i;
	unsigned char ucByte;

	for (i = 0; i < ucBcdLen; i++)
	{
		ucByte = (unsigned char)(ullNum % 100);
		ullNum /= 100;

		pucBcd[ucBcdLen - 1 - i] = (ucByte % 10) & 0x0F;
		pucBcd[ucBcdLen - 1 - i] |= ((ucByte / 10) << 4);
	}
	return 0;
}

LONGLONG Bcd2LongLong(unsigned char* pucBcd, unsigned char ucBcdLen)
{
	unsigned char i;
	LONGLONG llValue;

	llValue = 0;
	for (i = 0; i < ucBcdLen; i++)
	{
		llValue *= 10;
		llValue += (pucBcd[i] >> 4) & 0x0F;
		llValue *= 10;
		llValue += (pucBcd[i]) & 0x0F;
	}

	return llValue;
}

int iSplitStr(const char* pcStr, int iStr1Len, char* pcStr1, char* pcStr2)
{
	int iPos, iAdd;
	int iLen = strlen(pcStr);
	for (iPos = 0,iAdd = 0; iPos < iLen;)
	{
		if (iAdd >= iStr1Len)
		{
			break;
		}
		if (pcStr[iPos] >= 0x81)
		{
			if (pcStr[iPos + 1] < 0x40)
			{
				iPos += 4;
				iAdd += 2;
				if (iAdd > iStr1Len)
				{
					iPos -= 4;
					break;
				}
			}
			else
			{
				iPos += 2;
				iAdd += 2;
				if (iAdd > iStr1Len)
				{
					iPos -= 2;
					break;
				}
			}
		}
		else
		{
			iPos++;
			iAdd += 1;
		}
	}
	if (iPos <= 0)
	{
		return -1;
	}
	memcpy(pcStr1, pcStr, iPos);
	pcStr1[iPos] = 0;
	if (iPos < iLen)
	{
		memcpy(pcStr2, &pcStr[iPos], iLen - iPos);
		pcStr2[iLen - iPos] = 0;
	}
	return 0;
}


void AddDot(char* pcData)
{
	unsigned char ucLen = strlen(pcData);

	if (ucLen < 3)
	{
		return;
	}
	pcData[ucLen + 1] = 0;
	pcData[ucLen] = pcData[ucLen - 1];
	pcData[ucLen - 1] = pcData[ucLen - 2];
	pcData[ucLen - 2] = '.';
}

void NoDispIntegerStartZero(char* pcData)
{
	unsigned char ucLen = strlen(pcData);
	unsigned char uc;
	char acBuffer[16];

	for (uc = 0; uc < 9; uc++)
	{
		if (pcData[uc] == '0')
		{
			//pcData[uc] = ' ';
		}
		else
		{
			break;
		}
	}
	strcpy_s(acBuffer, 16, pcData + uc);
	strcpy_s(pcData, 16, acBuffer);
	return;
}

void BcdSumToAsc(unsigned char* pucBcdSum, char* pcAscSum)
{
	memset(pcAscSum, 0, 14);
	Bcd2Asc(pucBcdSum, pcAscSum, 6);
	AddDot(pcAscSum);
	NoDispIntegerStartZero(pcAscSum);
}

int iIsNum(unsigned char ucByte)
{
	if ((ucByte & 0xf) > 9)
	{
		return 0;
	}
	if ((ucByte >> 4) > 9)
	{
		return 0;
	}
	return 1;
}


int iStrIsNum(const char* pcBuff)
{
	int i;
	int iLen = strlen(pcBuff);
	if (iLen <= 0)
	{
		return 0;
	}
	for (i = 0; i < iLen; i++)
	{
		if (pcBuff[i] < '0' || pcBuff[i] > '9')
		{
			return 0;
		}
	}
	return 1;
}

int iTestDate(const unsigned char* pucDate)
{
	int iYear;
	if (!iIsNum(pucDate[0]))				//如果不是数字返回错误
	{
		return -1;
	}
	if (!iIsNum(pucDate[1]))				//如果不是数字返回错误
	{
		return -1;
	}
	if (!iIsNum(pucDate[3]))
	{
		return -1;
	}
	if (pucDate[3] == 0)					//如果天是0返回错误
	{
		return -1;
	}
	switch (pucDate[2])					//判断月份
	{
	case 0x01:
	case 0x03:
	case 0x05:
	case 0x7:
	case 0x08:
	case 0x10:
	case 0x12:
		if (pucDate[3] > 0x31)
		{
			return -2;
		}
		break;
	case 0x02:
		//if((pucDate[1]%4) == 0 )
		iYear = ((pucDate[0] >> 4) * 10 + (pucDate[0] & 0x0F)) * 100 + ((pucDate[1] >> 4) * 10 + (pucDate[1] & 0x0F));//modify liujun 20080618
		if ((iYear % 4 == 0) && (iYear % 100 != 0) || (iYear % 400 == 0))
		{
			if (pucDate[3] > 0x29)
			{
				return -2;
			}
		}
		else
		{
			if (pucDate[3] > 0x28)
			{
				return -2;
			}
		}
		break;
	case 0x04:
	case 0x06:
	case 0x09:
	case 0x11:
		if (pucDate[3] > 0x30)
		{
			return -2;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

char AscToInt(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	else if (c >= 'A' && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else if (c >= 'a' && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else
	{
		return c;
	}
}

void IntToAscStr(char* pNumStr)
{
	unsigned short nNumDigit = strlen(pNumStr);

	char aucAscStr[10] = {0};
	Hex2Str((unsigned char*)pNumStr, (unsigned char*)aucAscStr, nNumDigit * 2);
	memcpy(pNumStr, aucAscStr, nNumDigit*2);
}
unsigned char* chstohex(const char* chs, unsigned char* hex)
{
	char aucTmp[3] =
	{
		0
	};
	int iLen = strlen(chs) / 2;
	for (int i = 0; i < iLen; i++)
	{
		memcpy(aucTmp, chs + i * 2, 2);
		hex[i] = (unsigned char)strtol(aucTmp, NULL, 16);
	}
	return hex;
}


//remove space of string 
char* EraseSpaceOfStr(char* szStrIn)
{
	int istrLen = strlen(szStrIn);
	char* szStrOut = (char*)malloc(istrLen + 1);
	memcpy(szStrIn, szStrOut, istrLen);
	int i = 0, j = 0;
	for (i = 0; i <= istrLen; i++)
	{
		if ((szStrIn[i] != 32) || (szStrIn[i] != 9) || (szStrIn[i] != 10)) //去掉空格、tab,回车
		{
			szStrOut[j] = szStrIn[i];
			j++;
		}
	}
	memcpy(szStrIn, szStrOut, strlen(szStrOut));
	free(szStrOut);
	return szStrIn;
}


void ConvertOutputData(unsigned char* pucOutput, int iOutLen, char* pcOut)
{
	int nBufLen = sizeof(char) * (iOutLen * 2 + 1);
	char* pszBuf = new char[nBufLen];
	memset(pszBuf, 0, nBufLen);

	int iOffset = 0;
	for (int i = 0; i < iOutLen; i++)
	{
		sprintf_s(pszBuf + 2 * i, nBufLen - 2 * i, "%02X", pucOutput[i]);
	}

	pszBuf[nBufLen - 1] = '\0';
	memcpy(pcOut, pszBuf, nBufLen);
	delete[] pszBuf;
}

//----------------------------------------------------------------------------- 
// 名称：Hex2Str
// 功能：16进制转换成字符串函数
// 参数：src   :    输入指针
//       dst   :    输出指针
//       Src_Len	输入数据长度
// 返回： 
// 说明：
//-----------------------------------------------------------------------------
void Hex2Str(unsigned char *src, unsigned char *dst, unsigned char Src_Len)
{
	unsigned char i = 0;
	unsigned char tmp = 0;

	while (i < Src_Len)        
	{                           
		tmp = *src ; 
		tmp = (tmp >> 4) & 0x0f;
		if (tmp <= 9)
		{
			*dst++ = tmp + '0';
		}
		else if ((tmp >= 0x0A) && (tmp <= 0x0F))
		{
			*dst++ = tmp - 10 + 'A';
		}

		tmp = *src++;        
		tmp = tmp & 0x0f;
		if (tmp <= 9)
		{
			*dst++ = tmp + '0';
		}
		else if ((tmp >= 0x0A) && (tmp <= 0x0F))
		{
			*dst++ = tmp - 10 + 'A';
		}
		i++;
	}
	dst[i] = '\0';
}

#if 0
//输出log,数据
void OutputData2Log(const unsigned char *pucOutInfo, DWORD iDataLen)
{
	FILE* pLog = NULL;
	_tfopen_s(&pLog, LOGFILE, _T("a+"));
	if (NULL != pLog)
	{
		int nBufLen = iDataLen * 2 + 1;
		TCHAR* pszBuf = new TCHAR[nBufLen];
		memset(pszBuf, 0, sizeof(TCHAR) * nBufLen);
		for (unsigned int i = 0; i < iDataLen; i++)
		{
			_stprintf_s(pszBuf + 2 * i, nBufLen - 2 * i, _T("%02X"), pucOutInfo[i]);					
		}
		pszBuf[nBufLen - 1] = _T('\0');
		fwrite(pszBuf, 1, nBufLen * sizeof(TCHAR), pLog);
		//fwrite(_T("\r\n"), 1, 2 * sizeof(TCHAR), pLog);
		fclose(pLog);
		delete []pszBuf;
		pszBuf = NULL;
	}
}


void OutHintInfo2Log(const TCHAR *pucOutInfo)
{
	FILE* pLog = NULL;
	_tfopen_s(&pLog, LOGFILE, _T("a+"));
	if (NULL != pLog)
    {
        //获取当前时间
        ::SYSTEMTIME st;
        ::GetLocalTime(&st);
        char szTime[32]={0};
        sprintf_s(szTime,30,"\r\n【%04d-%02d-%02d %02d:%02d:%02d】",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
        fwrite(szTime, 1, strlen(szTime), pLog);

		fwrite(pucOutInfo, sizeof(TCHAR), _tcslen(pucOutInfo), pLog);
		fflush(pLog);
		fclose(pLog);
	}
}
#else
void OutputData2Log(const unsigned char *pucOutInfo, DWORD iDataLen)
{
}
//输出log,数据提示信息
void OutHintInfo2Log(const TCHAR *pucOutInfo)
{
}
#endif