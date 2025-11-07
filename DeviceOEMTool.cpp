/*********************************************************************************
					Dearborn Electronics India Pvt Ltd.,
**********************************************************************************
 Project Name           : Innova Shop Software - OEM Tool - J2534 API
 File Name              : DeviceOEMTool.cpp
 Description            : implementation of the CDeviceOEMTool class.
 Date                   : Jan 29, 2008
 Version                : 1.0
 Author                 : Chakravarthy
 Revision               :
 Copyright (c) 2008 Dearborn Electronics India Pvt L, Inc

  File       Date           Author                      Description
  Version
_____________________________________________________________________________

  1.0        Jan 29, 2008   Chakravarthy                Initial Version
_____________________________________________________________________________
*********************************************************************************/
#include "stdafx.h"
#include "DeviceOEMTool.h"
#include "NewProtocol.h"
#include "math.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//for rndis device checking 
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>


#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")

#define MAX_DATA_SIZE 4095
//#define PASSTHRU_MSG_DATA_SIZE 8  // Update this with your actual fragment size

// Buffer to hold the complete message
static unsigned char fullData[MAX_DATA_SIZE];

// Variable to track the current length of the reassembled message
static unsigned long totalDataLength = 0;

// Variable to track the sequence number (for reassembling)
static unsigned short expectedSeqNum = 1;

#define MAX_LINE_LENGTH 100

//Macro for Enable USB MultiMode Implementation Count
#define MULTI_MODE_DEBUGGING 1

/*Inline macro function*/
//inline unsigned long  ntohl (unsigned long n){return (n << 24) | ( (n << 8) & 0x00ff0000) | ( (n >> 8) & 0x0000ff00) | (n >> 24);}
//inline unsigned short ntohs (unsigned short n) { return (n << 8)  | (n >> 8); }
#define uword(n)  (*(WORD*)&n)
#define ulong(n)  (*(DWORD*)&n)

/*
 * Wait times and retries tweaker section.
 * Wait times are in msecs.
 */
#define ENABLE_COMM_WAIT    6000
#define DISABLE_COMM_WAIT   6000
#define FAST_INIT_WAIT      1500
 /*Jayasheela-changed fivebaud init wait to 10sec */
#define FIVEBAUD_INIT_WAIT  10000
#define SENDIOCTLDATA_WAIT  1000
#define GETCONFIG_WAIT      1000
#define READFILE_WAIT       100
#define WRITEFILE_TRIES     3

#ifdef GARUDA_TOOL
//#define IDE5K432PATH		"C:\\Windows\\System32\\Garuda40432.dll";
#define IDE5K432PATH		"C:\\Windows\\System32\\Garuda3_0404_32.dll";
#else
#define IDE5K432PATH		"C:\\Windows\\System32\\IDE5k432.dll";
#endif

DEVICEBASE_CALLBACK_RX_FUNC RxfunCallBack[MAX_PROTOCOL_NUM];//33000//MAX_PROTOCOL_NUM
LPVOID gpVoid[MAX_PROTOCOL_NUM];//33000//MAX_PROTOCOL_NUM//100000


/*Jayasheela-to store First frame callback function
  and to update rx status of the received messages */
DEVICEBASE_CALLBACK_FC_FUNC OnFirstFramefunCallBack;
LPVOID gpFFVoid;
DEVICEBASE_CALLBACK_ISO15765_SETRXSTATUS_FUNC OnISO15765RxMsgSetstatusfnCallBack;

DEVICEBASE_CALLBACK_J1939_SETRXSTATUS_FUNC OnJ1939RxMsgSetstatusfnCallBack;
LPVOID gpUpdateRxstatusVoid;
CDeviceOEMTool* pOEMTool;
unsigned long ulTimestamp = 0;
void GetDllVersion(char*);


PASSTHRU_MSG* g_pstPassThruMsg = NULL;
unsigned long ulIS015765_USB_Packets = 0;
unsigned long ulISO15765_ConsecutiveFrames = 0;
LARGE_INTEGER t1, t2;           // ticks
LARGE_INTEGER frequency;

unsigned long ulJ1939_USB_Packets = 0;
char server_ip_addr[16];// = "172.30.1.9";//192.168.1.30
char client_ip_addr[16];// [16] ; ;// [16] ;
char subnetaddr[16] ;//[16];// = "255.255.255.0";
char Gwaddr[16] ;//[16]; //= "192.168.1.100";

/*char* server_ip_addr = "172.30.1.6";//"192.168.0.131";// = "172.30.1.9";//192.168.1.30
char* client_ip_addr = "172.30.1.20";//"192.168.0.125"; ;// [16] ;*/
//char* subnetaddr = "255.255.255.0";//[16];// = "255.255.255.0";
//char* Gwaddr = "172.30.1.1";//"192.168.0.1";//[16]; //= "192.168.1.100";*/

unsigned short	Tester_logical_addr;// = 0x0E80;//tester id
unsigned short	ECU_logical_addr;
unsigned short	ECU_logical_addr1;
unsigned long diag_msg_len = 0;
unsigned char* diag_msg_data;
/* Message acknowledgement buffer. */
UCHAR bufCmdAck[INPUTREPORTMAX];
#define CAN_CHAN_NO		0x01
static unsigned int isHidDevice;
class CCanMsg
{
public:
	CCanMsg() : _msg_id(0), _data_len(0), _bExtended(false), _timestamp(0) {}
	~CCanMsg() {}

	unsigned long  _msg_id;
	int           _data_len;
	unsigned char _data[64]; //8 chiru
	bool          _bExtended;
	unsigned long _ulTxflags;
	unsigned long _timestamp;
};
CCanMsg objFlowControlFrm;

CDeviceOEMTool::CDeviceOEMTool(CDebugLog* pclsDebugLog) : CDeviceBase(pclsDebugLog)
{
/*	HidDevHandle = NULL;
	ReadHandle = NULL;
	WriteHandle = NULL;
	HidAttached = FALSE;
	hEventObject = NULL;
	hCallBckThread = NULL;
	m_bThreadQuit = FALSE;
	m_nChannelID = 0;
	m_bLoopBack = FALSE;
	m_ulLastErrorCode = J2534_ERR_NOT_SUPPORTED;
	memset(&m_ptFastInitResponse, 0, sizeof(PASSTHRU_MSG));
	m_CmdAck = NULL;
	/* XXX Cleanups: The following handles may not be necessary. */
/*	m_FastInit = NULL;
	m_5BaudInit = NULL;
	/* Ravi : INtegrated for ISO 15765 */
	/* Init ISO 15765 variables */
//	m_FlowControlEvent = NULL;
	/*Jayasheela-chaged BS and STMIN values to default values */
/**	m_nBlockSizeTx = 0xFFFF;
	m_nSTminTx = 0xFFFF;
	/*Jayasheela - added for BS and STMIN*/
/*	m_ByteISO15765_BS = 0x00;
	m_ByteISO15765_STMIN = 0x00;
	m_ByteISO15765_WFT_MAX = 0x00;

//	m_FD_ISO15765_DATA_LENGTH = 8;//chiru
	//J1939 Supported
	//By default MIN DELAy is 0 which is exception to default value of 50ms
	m_ulJ1939_BRDCST_MIN_DELAY = 0x00;

	m_bFlowControlIssued = FALSE;

	dev = NULL;

	ulIS015765_USB_Packets = 0;
	ulJ1939_USB_Packets = 0;

	m_bSepTimeEvent = NULL;
	OnJ1939RxMsgSetstatusfnCallBack = NULL;*/

	HidDevHandle = NULL;
	m_serverSockId = INVALID_SOCKET;
	ReadHandle = NULL;
	WriteHandle = NULL;
	HidAttached = FALSE;
	hEventObject = NULL;
	hCallBckThread = NULL;
	m_bThreadQuit = FALSE;
	m_nChannelID = 0;
	m_bLoopBack = FALSE;
	m_ulLastErrorCode = J2534_ERR_NOT_SUPPORTED;
	memset(&m_ptFastInitResponse, 0, sizeof(PASSTHRU_MSG));
	m_CmdAck = NULL;
	/* XXX Cleanups: The following handles may not be necessary. */
	m_FastInit = NULL;
	m_5BaudInit = NULL;
	/* Ravi : INtegrated for ISO 15765 */
	/* Init ISO 15765 variables */
	m_FlowControlEvent = NULL;
	/*Jayasheela-chaged BS and STMIN values to default values */
	m_nBlockSizeTx = 0xFFFF;
	m_nSTminTx = 0xFFFF;
	/*Jayasheela - added for BS and STMIN*/
	m_ByteISO15765_BS = 0x00;
	m_ByteISO15765_STMIN = 0x00;
	m_ByteISO15765_WFT_MAX = 0x00;

	m_bFlowControlIssued = FALSE;

	dev = NULL;

	ulIS015765_USB_Packets = 0;

	m_bSepTimeEvent = NULL;

}

CDeviceOEMTool::~CDeviceOEMTool()
{
	CloseHandles();

	if (hCallBckThread)
	{
		TerminateThread(hCallBckThread, 0);
		hCallBckThread = NULL;
	}
	if (m_CmdAck != NULL)
	{
		CloseHandle(m_CmdAck);
		m_CmdAck = NULL;
	}
	/* XXX Cleanups: The following methods may not be necessary. */
	if (m_5BaudInit != NULL)
	{
		CloseHandle(m_5BaudInit);
		m_5BaudInit = NULL;
	}
	if (m_FastInit != NULL)
	{
		CloseHandle(m_FastInit);
		m_FastInit = NULL;
	}
	/* Ravi : Intgrated for ISO 15765 */
	if (m_FlowControlEvent != NULL)
	{
		CloseHandle(m_FlowControlEvent);
		m_FlowControlEvent = NULL;
	}
}

#ifdef MULTI_MODE_DEBUGGING
//Debugging purpose for counts
unsigned long ulMsgCounter = 0;
unsigned long ulMaxPacking[10];
#endif


/*****************************************************************************
*            CALL BACK Function for receive
******************************************************************************/
/*std::string GetLogPath()
{
	DWORD bufferSize = GetCurrentDirectoryA(0, NULL); // required buffer size
	if (bufferSize == 0) {
		return "";
	}

	std::vector<char> buffer(bufferSize);
	if (GetCurrentDirectoryA(bufferSize, buffer.data()) == 0) {
		return "";
	}

	return std::string(buffer.data());
}*/

/*void SaveBufferToHexTxt(const unsigned char* data, size_t length, const std::string& filename)
{
	std::string path = GetLogPath();
	if (path.empty()) {
		return;
	}
	path += "\\" + filename;

	std::ofstream outFile(path);
	if (!outFile) {
		return;
	}

	outFile << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i) {
		outFile << std::setw(2) << static_cast<int>(data[i]) << " ";
		if ((i + 1) % 16 == 0) {
			outFile << "\n"; // 16 bytes per line
		}
	}
}*/

void SaveBufferToHexTxt(const unsigned char* data, size_t length, const char* filename)
{
	char fullPath[MAX_PATH];
	snprintf(fullPath, MAX_PATH, "C:\\Garuda\\%s", filename);

	FILE* fp = NULL;
	fopen_s(&fp, fullPath, "a"); // append mode
	if (!fp) return;

	SYSTEMTIME st;
	GetLocalTime(&st);
	fprintf(fp, "\n[%04d-%02d-%02d %02d:%02d:%02d.%03d]\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	for (size_t i = 0; i < length; i++) {
		fprintf(fp, "%02X ", data[i]);
		if ((i + 1) % 16 == 0) {
			fprintf(fp, "\n");
		}
	}
	fprintf(fp, "\n");

	fflush(fp);
	fclose(fp);
}



DWORD WINAPI CallBackFun(void* vP)
{
	CDeviceOEMTool* pOemTool = reinterpret_cast<CDeviceOEMTool*>(vP);
	PASSTHRU_MSG stPassRxThruMsg;
	PASSTHRU_MSG stSetRxstatusPassRxThruMsg;
	PASSTHRU_MSG stTempPassRxThruMsg;
	InputBuffer_t* Inputbuffer;
	int nBytesRead = 0;
	short nDataCount = 0, data_index = 0;
	uint32_t protocolid;
	unsigned long ulRxFlags = 0, msg_index;
	BOOL bFirstFrameIndication = FALSE;
	int nDataOffset;
	int i = 0;
	unsigned char ucPCIindex = 0;
	unsigned char ucPCItype = 0;
	unsigned char ucMsgDL = 0;
	unsigned char ucMinFF_DL = 0;
	unsigned short usFF_DL = 0;
	unsigned long ulExtendedAddrType = 0;
	unsigned char ucCANIDSize = 0;
	SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData;
	unsigned long nJ1939MsgIdx = 0xFF;

	/*BOOL replace = !FALSE;*/

	memset(&stPassRxThruMsg, 0, sizeof(stPassRxThruMsg));

	TRACE("Call back function reached \n");
	stSaveRxMultipleSegmData = new SAVE_MULTIPLE_SEGMENT_RXDATA[10];

	for (msg_index = 0; msg_index < 10; msg_index++)
	{
		stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
		stSaveRxMultipleSegmData[msg_index].usDataIndex = 0;
		stSaveRxMultipleSegmData[msg_index].usLeftDL = 0;
	}
	
	while (pOemTool->m_bThreadQuit == false)
	{
	//	Inputbuffer = (InputBuffer_t*)bufCmdAck;
		Inputbuffer = (InputBuffer_t*)&pOemTool->InputReport;
		pOemTool->ReadInputReport();


		//  if(pOemTool->InputReport[2] == ECU_READMESSAGE_ACK)
		if (Inputbuffer->command == ECU_READMESSAGE_ACK)
		{

			TRACE("Call back function read response\n");

			TRACE("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
				pOemTool->InputReport[1], pOemTool->InputReport[2],
				pOemTool->InputReport[3], pOemTool->InputReport[4],
				pOemTool->InputReport[5], pOemTool->InputReport[6],
				pOemTool->InputReport[15], pOemTool->InputReport[16],
				pOemTool->InputReport[17], pOemTool->InputReport[18],
				pOemTool->InputReport[19], pOemTool->InputReport[20],
				pOemTool->InputReport[21], pOemTool->InputReport[22]);


			/* XXX Check for USB segmented message and start reconstruction. */
			//switch(pOemTool->InputReport[1])
			switch (Inputbuffer->proto_id)
			{

				/* Common Receive Processing for the following protocols */
				/* The following receive implementation does not support multiple
				   receive messages in a single USB frame */

				   /*case CAN:
					   {

						   unsigned char uchMode;
						   unsigned char uchMessageCnt;

						   uchMode = (unsigned char)((pOemTool->InputReport[4] >> 6) && 0x03);
						   uchMessageCnt = pOemTool->InputReport[4] & 0x3F;
						   ulMsgCounter+= uchMessageCnt;
						   ulMaxPacking[uchMessageCnt]++;
						   //ulMsgCounter++;
						   TRACE("%lu MsgCount - %d : %lu, %lu , %lu , %lu \n",GetTickCount(),uchMessageCnt, ulMsgCounter,
							   ulMaxPacking[1],ulMaxPacking[2],ulMaxPacking[3]);
					   }
					   break;*/

			case CAN:
			case CAN_CH1:
			case SW_CAN_PS:
			{
				/* //Message Simulation for testing
				//Start

				///Get the timestamp from the device
				stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;


				pOemTool->InputReport[1] = 0x05;
				pOemTool->InputReport[2] = ECU_READMESSAGE_ACK;
				pOemTool->InputReport[3] = 0;
				pOemTool->InputReport[4] = 0x43; //Mode

				pOemTool->InputReport[5] = 18; //Msg 1

				pOemTool->InputReport[6] = 0x00; //Rx Flags
				pOemTool->InputReport[7] = 0x00;
				pOemTool->InputReport[8] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[0]; //Time Stamp
				pOemTool->InputReport[9] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[1];
				pOemTool->InputReport[10] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[2];
				pOemTool->InputReport[11] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[3];

				pOemTool->InputReport[12] = 0x00; //Header
				pOemTool->InputReport[13] = 0x00; //Header
				pOemTool->InputReport[14] = 0x01; //Header
				pOemTool->InputReport[15] = 0x01; //Header

				pOemTool->InputReport[16] = 0x00; //Data
				pOemTool->InputReport[17] = 0x01; //Data
				pOemTool->InputReport[18] = 0x02; //Data
				pOemTool->InputReport[19] = 0x03; //Data
				pOemTool->InputReport[20] = 0x04; //Data
				pOemTool->InputReport[21] = 0x05; //Data
				pOemTool->InputReport[22] = 0x06; //Data
				pOemTool->InputReport[23] = 0x07; //Data

				pOemTool->InputReport[24] = 18; //Msg 1

				pOemTool->InputReport[25] = 0x00; //Rx Flags
				pOemTool->InputReport[26] = 0x00;
				pOemTool->InputReport[27] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[0]; //Time Stamp
				pOemTool->InputReport[28] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[1];
				pOemTool->InputReport[29] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[2];
				pOemTool->InputReport[30] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[3];

				pOemTool->InputReport[31] = 0x00; //Header
				pOemTool->InputReport[32] = 0x00; //Header
				pOemTool->InputReport[33] = 0x01; //Header
				pOemTool->InputReport[34] = 0x02; //Header

				pOemTool->InputReport[35] = 0x00; //Data
				pOemTool->InputReport[36] = 0x01; //Data
				pOemTool->InputReport[37] = 0x02; //Data
				pOemTool->InputReport[38] = 0x03; //Data
				pOemTool->InputReport[39] = 0x04; //Data
				pOemTool->InputReport[40] = 0x05; //Data
				pOemTool->InputReport[41] = 0x06; //Data
				pOemTool->InputReport[42] = 0x07; //Data


				pOemTool->InputReport[43] = 18; //Msg 1

				pOemTool->InputReport[44] = 0x00; //Rx Flags
				pOemTool->InputReport[45] = 0x00;
				pOemTool->InputReport[46] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[0]; //Time Stamp
				pOemTool->InputReport[47] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[1];
				pOemTool->InputReport[48] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[2];
				pOemTool->InputReport[49] = ((unsigned char*)&stPassRxThruMsg.ulTimeStamp)[3];

				pOemTool->InputReport[50] = 0x00; //Header
				pOemTool->InputReport[51] = 0x00; //Header
				pOemTool->InputReport[52] = 0x01; //Header
				pOemTool->InputReport[53] = 0x03; //Header

				pOemTool->InputReport[54] = 0x00; //Data
				pOemTool->InputReport[55] = 0x01; //Data
				pOemTool->InputReport[56] = 0x02; //Data
				pOemTool->InputReport[57] = 0x03; //Data
				pOemTool->InputReport[58] = 0x04; //Data
				pOemTool->InputReport[59] = 0x05; //Data
				pOemTool->InputReport[60] = 0x06; //Data
				pOemTool->InputReport[61] = 0x07; //Data


				//End  */


				unsigned char uchMode, uchMode1;
				unsigned char uchMessageCnt, uchMessagecnt1;

				//uchMode = (unsigned char)((pOemTool->InputReport[4] >> 6) && 0x03);
				uchMode = (unsigned char)((Inputbuffer->u.ReadMsgs.mode >> 6) && 0x03);
				uchMode1 = (unsigned char)((Inputbuffer->u.ReadMsgsMode1.mode >> 6) && 0x03);
				//	uchMessageCnt = pOemTool->InputReport[4] & 0x3F;
				uchMessageCnt = Inputbuffer->u.ReadMsgs.mode & 0x3F;
				uchMessagecnt1 = Inputbuffer->u.ReadMsgsMode1.mode & 0x3F;
				//    stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];
				stPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;


#ifdef MULTI_MODE_DEBUGGING
				//Debugging Purpose
				ulMsgCounter += uchMessageCnt;
				ulMaxPacking[uchMessageCnt]++;
				TRACE("%lu MsgCount - %d : %lu, %lu , %lu , %lu \n", GetTickCount(), uchMessageCnt, ulMsgCounter,
					ulMaxPacking[1], ulMaxPacking[2], ulMaxPacking[3]);
#endif

				if (uchMode == 0x00 && uchMode1 == 0x00) // Legacy Mode
				{
					TRACE("Legacy Mode - CAN Frame received\n");

					/* nDataCount = (short)(pOemTool->InputReport[5]);
					 nDataCount = nDataCount | (short)(pOemTool->InputReport[6] << 8);*/
					nDataCount = (short)(Inputbuffer->u.ReadMsgs.messagelength);
					nDataCount = nDataCount | (short)(Inputbuffer->u.ReadMsgs.messagelength1 << 8);
					stPassRxThruMsg.ulDataSize = nDataCount;

					/*Collect receive flags*/
				   /* ulRxFlags = (unsigned long)pOemTool->InputReport[7];
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[8] << 8;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[9] << 16;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[10] << 24;*/
					ulRxFlags = (unsigned long)Inputbuffer->u.ReadMsgs.RxFlags;

					/*Get the timestamp from the device*/
				  /*  stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;*/
					stPassRxThruMsg.ulTimeStamp = (unsigned long)Inputbuffer->u.ReadMsgs.TimeStamp;

					stPassRxThruMsg.ulRxStatus = ulRxFlags;
					stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;

					// Copy the non segmtd message and store in the Cbuffer
				  //  memcpy((char*)&stPassRxThruMsg.ucData,&pOemTool->InputReport[15],nDataCount);
					memcpy((char*)&stPassRxThruMsg.ucData, &Inputbuffer->u.ReadMsgs.Data_Bytes, nDataCount);

					// Callback to push the msg into queue
					RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg,
						gpVoid[stPassRxThruMsg.ulProtocolID]);

					//memset(&pOemTool->InputReport,0,INPUTREPORTMAX);
					memset(&Inputbuffer, 0, sizeof(Inputbuffer));
				}
				else if (uchMode == 0x01 && uchMode1 == 0x01) // Multi Frame Mode
				{
					if (uchMessageCnt > 1)
						TRACE("Multi Frame Mode - CAN Frame received - %d\n", uchMessageCnt);

					//int nIdx = 5;
					int len = 0;
					len = sizeof(Inputbuffer->Reserved) + sizeof(Inputbuffer->proto_id) + sizeof(Inputbuffer->command);
					len += sizeof(Inputbuffer->u.ReadMsgsMode1.segnum) + sizeof(Inputbuffer->u.ReadMsgsMode1.mode);
					for (int nMsgIdx = 0; nMsgIdx < uchMessageCnt; nMsgIdx++)
					{
						//Databytes Count;
						//nDataCount = pOemTool->InputReport[nIdx] - 6; //2 Byte Flag + 4 Bytes TimeStamp
						nDataCount = Inputbuffer->u.ReadMsgsMode1.messagelength - 6;
						stPassRxThruMsg.ulDataSize = nDataCount;

						// Check whether frame formatted properly or not
					//	if((nIdx + pOemTool->InputReport[nIdx]) > 61)
						if ((len + Inputbuffer->u.ReadMsgsMode1.messagelength) > 61)
						{
							TRACE("Error: Invalid CAN Message Format for Mode - 01\n");
							break;
						}

						//Rx Flags - 2 Bytes
					/*	ulRxFlags = (unsigned long)pOemTool->InputReport[nIdx + 1];
						ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[nIdx + 2] << 8;*/
						ulRxFlags = (unsigned long)Inputbuffer->u.ReadMsgsMode1.RxFlags;
						stPassRxThruMsg.ulRxStatus = ulRxFlags;

						//Timestamp
					/*	stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[nIdx + 3];
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 4] << 8;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 5] << 16;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 6] << 24;	*/
						stPassRxThruMsg.ulTimeStamp = (unsigned long)Inputbuffer->u.ReadMsgsMode1.TimeStamp;
						stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;

						// Copy the databytes into buffer
						//memcpy((char*)&stPassRxThruMsg.ucData,&pOemTool->InputReport[nIdx + 7],nDataCount);
						memcpy((char*)&stPassRxThruMsg.ucData, Inputbuffer->u.ReadMsgsMode1.Data_Bytes, nDataCount);

						// Callback to push the msg into queue
						RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg,
							gpVoid[stPassRxThruMsg.ulProtocolID]);

						//Update index for pointing next frame
					//	indx = indx + nDataCount + 6 + 1;  //DataCount + 6 Bytes ( 2Bytes Rx Flax + 4 Bytes TimeStamp) + lenth field
						len = len + nDataCount + sizeof(Inputbuffer->u.ReadMsgsMode1.RxFlags) + sizeof(Inputbuffer->u.ReadMsgsMode1.TimeStamp) +
							sizeof(Inputbuffer->u.ReadMsgsMode1.messagelength);
					}

					//memset(&pOemTool->InputReport,0,INPUTREPORTMAX);
					memset(Inputbuffer, 0, sizeof(Inputbuffer));
				}
			}
			break;

			/* Common Receive Processing for the following protocols */
			/* The following receive implementation does not support multiple
			   receive messages in a single USB frame */

			   //case CAN: 
			   //case CAN_CH1: 
			   //case SW_CAN_PS:
			case SCI_A_ENGINE:
			case SCI_A_TRANS:
			case SCI_B_ENGINE:
			case SCI_B_TRANS:
			case ISO14230:
			case ISO9141:
			{
				stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];

				/* Check for non-segmented or first frame message */
				if ((pOemTool->InputReport[3] == 0) || (pOemTool->InputReport[3] == 1))
				{
					nDataCount = (short)(pOemTool->InputReport[5]);
					nDataCount = nDataCount | (short)(pOemTool->InputReport[6] << 8);

					stPassRxThruMsg.ulDataSize = nDataCount;

					/*Collect receive flags*/
					ulRxFlags = (unsigned long)pOemTool->InputReport[7];
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[8] << 8;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[9] << 16;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[10] << 24;

					/*Get the timestamp from the device*/
					stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;

					stPassRxThruMsg.ulRxStatus = ulRxFlags;

					if (((pOemTool->InputReport[1] == ISO14230) || (pOemTool->InputReport[1] == ISO9141)) &&
						((stPassRxThruMsg.ulRxStatus & 0x00000001) == 0x00000001))
					{
						stPassRxThruMsg.ulDataSize--;
					}
					stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;

					/* For First frame message copy and continue to read the
					   other frames */
					if (pOemTool->InputReport[3] == 1)
					{
						/* Save the data index */
						data_index = 50;

						/* Read upto the end of the first frame.
						   50 data bytes*/
						   /* Ravi : This may not be a good idea for he CAN message
						   TBD Need to come back and tune it for CAN Message if needed
						   Even the 50 is a hard coded value and should have been the
						   data size derived out of the Message length in the HFCP */
						memcpy((char*)&stPassRxThruMsg.ucData, &pOemTool->InputReport[15],
							50);

						continue;

					}

					/* Copy the non segmtd message and store in the Cbuffer */
					memcpy((char*)&stPassRxThruMsg.ucData, &pOemTool->InputReport[15],
						nDataCount);

				}
				/* Segmented messages */
				else
				{
					/* Copy the data bytes from the segmented messages */
					/* Read upto the end of the first frame.
					   50 data bytes*/
					memcpy((char*)&stPassRxThruMsg.ucData[data_index], &pOemTool->InputReport[4],
						61);
					/* update the data index */
					data_index += 61;

					/* Data index has not reached message length then
					   continue to read next frames else store onto the
					   CBuffer */
					if (data_index < nDataCount)
					{
						continue;
					}

				}

				RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg,
					gpVoid[stPassRxThruMsg.ulProtocolID]);
				memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
			}
			break;

			case J1850PWM:/*J1850 PWM Protocol Receive indication*/
			{
				/*Collect Rx Flags from the receive queue*/
				ulRxFlags = ntohl(ulong(pOemTool->InputReport[6]));

				/*Get the timestamp from the device*/
				stPassRxThruMsg.ulTimeStamp = ntohl(ulong(pOemTool->InputReport[10]));

				/*Get the datacount form the receive message*/
				nDataCount = pOemTool->InputReport[5] + 3;

				/*Copy the data into the PassThruMessage*/
				memcpy((char*)&stPassRxThruMsg.ucData, &pOemTool->InputReport[14], nDataCount);
				stPassRxThruMsg.ulProtocolID = J1850PWM;
				stPassRxThruMsg.ulDataSize = nDataCount;
				stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;
				stPassRxThruMsg.ulRxStatus |= 0x00;
				RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg,
					gpVoid[stPassRxThruMsg.ulProtocolID]);
				memset(&pOemTool->InputReport, 0, OUTPUTREPORTMAX);
			}
			break;

			case ISO15765:/*ISO15765 Protocol Receive indication*/
			case ISO15765_CH1:
			case FD_ISO15765_PS:
			case SW_ISO15765_PS:
			{
				unsigned char uchMode;
				unsigned char uchMessageCnt;
#if 0
				uchMode = (unsigned char)((pOemTool->InputReport[4] >> 6) && 0x03);
				uchMessageCnt = pOemTool->InputReport[4] & 0x3F;
#else
				uchMode = (unsigned char)((Inputbuffer->u.ReadMsgsTP.mode >> 6) && 0x03);
				uchMessageCnt = Inputbuffer->u.ReadMsgsTP.mode & 0x3F;
#endif
				if (uchMode == 0x00) //Legacy Frame
				{
					/* Ravi : INtegrated for ISO 15765 */
#if 0
					stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];
#else
					stPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
#endif

					/* Ravi : RxStatus bit defination has the Extended Address flag. */
#if 0
					nDataCount = (short)(pOemTool->InputReport[5]);
					nDataCount = nDataCount | (short)(pOemTool->InputReport[6] << 8);
#else
					nDataCount = Inputbuffer->u.ReadMsgsTP.messagelength;
					//nDataCount = nDataCount | (short)(Inputbuffer->u.ReadMsgsTP.messagelength1 << 8);
#endif
		/*Collect receive flags*/
#if 0		
					ulRxFlags = (unsigned long)pOemTool->InputReport[7];
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[8] << 8;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[9] << 16;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[10] << 24;
#else
					ulRxFlags = (unsigned long)Inputbuffer->u.ReadMsgsTP.RxFlags;
#endif
					/*jayasheela-Added to chek padding error */
					if (nDataCount < 0x000C)
						ulRxFlags = ulRxFlags | 0x00000010;

					/*Get the timestamp from the device*/
#if 0
					stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;
#else
					stPassRxThruMsg.ulTimeStamp = (unsigned long)Inputbuffer->u.ReadMsgsTP.TimeStamp;
#endif
					/*jayasheela-call callback function to updated Rxstatus flag*/
#if 0
					stSetRxstatusPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];
#else
					stSetRxstatusPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
#endif
					stSetRxstatusPassRxThruMsg.ulRxStatus = ulRxFlags;
					stSetRxstatusPassRxThruMsg.ulDataSize = nDataCount;
					stSetRxstatusPassRxThruMsg.ulExtraDataIndex = stSetRxstatusPassRxThruMsg.ulDataSize;
					stSetRxstatusPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
#if 0
					memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0],
						&pOemTool->InputReport[15],
						stSetRxstatusPassRxThruMsg.ulDataSize);
#else
					memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0],
						Inputbuffer->u.ReadMsgsTP.u.Data_Bytes,
						stSetRxstatusPassRxThruMsg.ulDataSize);
#endif
					OnISO15765RxMsgSetstatusfnCallBack(&stSetRxstatusPassRxThruMsg, gpUpdateRxstatusVoid);

					/* Check if the received message is of type extended CAN ID */
					ulExtendedAddrType = stSetRxstatusPassRxThruMsg.ulRxStatus & ISO15765_ADDR_TYPE;
					// Ravi : Since the RxStatus is set in the call back, we need to update the 
					// stPassRxThruMsg structure here.
					stPassRxThruMsg.ulRxStatus = stSetRxstatusPassRxThruMsg.ulRxStatus;
					if (ulExtendedAddrType)
					{
						ucPCItype = Inputbuffer->u.ReadMsgsTP.u.extaddr.PCItype & 0xF0;
						ucMsgDL = Inputbuffer->u.ReadMsgsTP.u.extaddr.PCItype & 0x0F;
						//ucPCIindex = 20;
					}
					else
					{
						ucPCItype = Inputbuffer->u.ReadMsgsTP.u.stdaddr.PCItype & 0xF0;
						ucMsgDL = Inputbuffer->u.ReadMsgsTP.u.stdaddr.PCItype & 0xF0;
						//ucPCIindex = 19;
					}
#if 0
					ucPCItype = pOemTool->InputReport[ucPCIindex] & 0xF0;
#else
					/* Not required */
					//ucPCItype = Inputbuffer->u.ReadMsgsTP.PCIbyte & 0xF0;
#endif
		/* Put the received input report for debug purpose */
					for (int i = 0; i < nDataCount; i++)
					{
						TRACE("%2X ", stPassRxThruMsg.ucData[i]);
					}
					TRACE("\n");
					switch (ucPCItype)
					{
					case 0x00:
					{
						TRACE("Single Frame Received\n");
						//TRACE("Valid Message %X\n",pOemTool->InputReport[ucPCIindex]);
						/* Construct the Start of message indication */
						ucCANIDSize = sizeof(Inputbuffer->u.ReadMsgsTP.u.stdaddr.canid);
						if (ulExtendedAddrType)
						{
							ucCANIDSize += sizeof(uint8_t);
						}
#if 0
						else
						{
							ucCANIDSize = 4;
						}
#endif
						/* Update the Data Size and Extra Data Index */
						/* Subtract RxFlags and Time Stamp to get the pass thru data length */
						/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
						No need to subtract with 8 bytes */
#if 0
						memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], ucCANIDSize);
#else  
					//	unsigned long MSG_ID = SWAP32(Inputbuffer->u.ReadMsgsTP.u.Data_Bytes);
						memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgsTP.u.Data_Bytes, ucCANIDSize);
#endif
						/*Jayasheela-should consider the leght specified in PCI bytes*/
						/*ucMsgDL = nDataCount - ucCANIDSize - 1;
						stPassRxThruMsg.ulDataSize = nDataCount - 1;*/
#if 0
						ucMsgDL = pOemTool->InputReport[ucPCIindex] & 0x0F;
#else
						/* Not required */
						//ucMsgDL = Inputbuffer->u.ReadMsgsTP.PCIbyte & 0x0F;
#endif
						stPassRxThruMsg.ulDataSize = ucMsgDL + ucCANIDSize;
						stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;
#if 0
						memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);
#else
						if (ulExtendedAddrType) { 

							memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgsTP.u.extaddr.usFF_DL, ucMsgDL);
						}
						else
						{
							memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgsTP.u.stdaddr.usFF_DL, ucMsgDL);
						}
					//	memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], Inputbuffer->u.ReadMsgsTP.u.Data_Bytes, ucMsgDL);
#endif
						/* Send the Start of message indication */
						RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
						//memset(&pOemTool->InputReport,0,INPUTREPORTMAX);
						memset(Inputbuffer, 0, sizeof(Inputbuffer));
					}
					break;
					case 0x10:
					{
						TRACE("First Frame Received\n");

						ulISO15765_ConsecutiveFrames = 0;

						/* Get the First Frame Data Length */
#if 0
						usFF_DL = pOemTool->InputReport[ucPCIindex] & 0x0F;
						usFF_DL = (usFF_DL << 8) | pOemTool->InputReport[++ucPCIindex];
#else
						if (ulExtendedAddrType) {
							usFF_DL = Inputbuffer->u.ReadMsgsTP.u.extaddr.PCItype & 0x0F;
							usFF_DL = (usFF_DL << 8) | Inputbuffer->u.ReadMsgsTP.u.extaddr.usFF_DL;
							ucMinFF_DL = 6;
						}
						else {
							usFF_DL = Inputbuffer->u.ReadMsgsTP.u.stdaddr.PCItype & 0x0F;
							usFF_DL = (usFF_DL << 8) | Inputbuffer->u.ReadMsgsTP.u.stdaddr.usFF_DL;
							ucMinFF_DL = 7;
						}
#endif

						TRACE("%X\n", usFF_DL);
#if 0
						/* Check for valid First Frame */
						if (ulExtendedAddrType)
						{
							ucMinFF_DL = 6;
						}
						else
						{
							ucMinFF_DL = 7;
						}
#endif	
						if (usFF_DL > ucMinFF_DL)
						{
							/* Construct the Start of message indication */
#if 0
							if (ulExtendedAddrType)
							{
								ucCANIDSize = 5;
							}
							else
							{
								ucCANIDSize = 4;
							}
#else
							ucCANIDSize = sizeof(Inputbuffer->u.ReadMsgsTP.u.stdaddr.canid);
							if (ulExtendedAddrType)
							{
								ucCANIDSize += sizeof(uint8_t);

							}
#endif
							msg_index = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);

							if (0xff == msg_index)
							{
								continue;
							}
							stPassRxThruMsg.ulDataSize = ucCANIDSize;

							/*Jayasheela -removed as EDI is zero for all indiactions */
							//stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize; 

							/* Update the Rx status as Start of the message and received */
							stPassRxThruMsg.ulRxStatus |= 0x02;
#if 0
							memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], ucCANIDSize);
							/* Take back-up of the FF data to construct the segmented message data */
							/* Copy the CAN ID */
							memcpy((char*)&stTempPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], ucCANIDSize);
							/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
							No need to subtract with 8 bytes */
							ucMsgDL = nDataCount - ucCANIDSize - 2;
							memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);
#else
							memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgsTP.u.Data_Bytes, ucCANIDSize);
							/* Take back-up of the FF data to construct the segmented message data */
							/* Copy the CAN ID */
							memcpy((char*)&stTempPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgsTP.u.Data_Bytes, ucCANIDSize);
							/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
							No need to subtract with 8 bytes */
							ucMsgDL = nDataCount - ucCANIDSize - 2;
							if (ulExtendedAddrType) {
								memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &(Inputbuffer->u.ReadMsgsTP.u.extaddr.usFF_DL), ucMsgDL);
							}
							else {
								memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &(Inputbuffer->u.ReadMsgsTP.u.stdaddr.usFF_DL), ucMsgDL);
							}
#endif
							stTempPassRxThruMsg.ulDataSize = nDataCount - 2;
							stPassRxThruMsg.ulExtraDataIndex = 0;
							/* Send the Start of message indication */
							RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
							memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
							memset(Inputbuffer, 0, sizeof(Inputbuffer));

							// Build flow control frame

							/*Jayasheela-construct flow control frame */

							CCanMsg		    flow_control_frame;
							bool	        bFoundFCMsgId;

							OnFirstFramefunCallBack(stPassRxThruMsg, gpFFVoid,
								&flow_control_frame._msg_id,
								flow_control_frame._data, &flow_control_frame._data_len,
								&flow_control_frame._ulTxflags,
								&bFoundFCMsgId);

							if (!bFoundFCMsgId)
							{
								TRACE("Not found flow control message id ");
								continue;
							}
							J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
							//Send the Flow control frame

							enJ2534Error = pOemTool->SendToDevice(flow_control_frame._msg_id, flow_control_frame._data, flow_control_frame._data_len, flow_control_frame._ulTxflags, (unsigned long)stPassRxThruMsg.ulProtocolID);

							if (enJ2534Error != J2534_STATUS_NOERROR)
							{
								TRACE("Flow control not Transmitted\n");
								continue;
							}

							pOemTool->ReadInputReport();
#if 0
							if (pOemTool->InputReport[3] == J2534_STATUS_NOERROR)
#else
							if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
#endif
							{
								TRACE("PASS:Flow control Wrtie TXDONE\n");;//pstPassThruMsg->ulTimeStamp = ulTimestamp;
								//LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
							}
							else
							{
								TRACE("FAIL:Flow control Wrtie TXDONE\n");;//			m_ulLastErrorCode = (J2534ERROR)pOemTool->ReadInputReport[3];
								//			return m_ulLastErrorCode;
							}


							/* Copy the First Frame Details to construct the Segmented data */
							stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID = stPassRxThruMsg.ulProtocolID;
							stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
							stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulRxStatus = stPassRxThruMsg.ulRxStatus;
							stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize = usFF_DL + ucCANIDSize;
							stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize;
							stSaveRxMultipleSegmData[msg_index].usDataIndex = 0;
							memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
								&stTempPassRxThruMsg.ucData[0], stTempPassRxThruMsg.ulDataSize);
							stSaveRxMultipleSegmData[msg_index].usDataIndex = nDataCount - 2; /*Ravi : TXflag and Time stamp are not considered */
							stSaveRxMultipleSegmData[msg_index].usLeftDL = (unsigned short)(stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize - stTempPassRxThruMsg.ulDataSize);
						}
						else
						{
							TRACE("First Frame Received is invalid - FF DL = %x\n", usFF_DL);
						}
					}
					break;
					case 0x20:
					{
						TRACE("Consecutive Frame Received1\n");

#if 0
						memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], ucCANIDSize);
#else
						memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgsTP.u.Data_Bytes, ucCANIDSize);
#endif
						msg_index = pOemTool->GetMsgIndex(stSaveRxMultipleSegmData, stPassRxThruMsg, ucCANIDSize);

						if (0xff == msg_index)
						{
							continue;
						}


						BOOL bAllFramesReceived = FALSE;

						/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
						No need to subtract with 8 bytes */
						ucMsgDL = nDataCount - ucCANIDSize - 1;
						if (stSaveRxMultipleSegmData[msg_index].usLeftDL > 0)
						{
#if 0
							memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
								&pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);
#else
							if (ulExtendedAddrType) {
								memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
									&Inputbuffer->u.ReadMsgsTP.u.extaddr.usFF_DL, ucMsgDL);
							}
							else {
								memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
									&Inputbuffer->u.ReadMsgsTP.u.stdaddr.usFF_DL, ucMsgDL);
							}
#endif
							memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
							memset(Inputbuffer, 0, sizeof(Inputbuffer));
							if (ucMsgDL >= stSaveRxMultipleSegmData[msg_index].usLeftDL)
							{
								/*copy data to structure to put into buffer */
								stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize;
								stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID;
								//stPassRxThruMsg.ulTimeStamp  = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
								//stPassRxThruMsg.ulRxStatus   = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulRxStatus;
								stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulExtraDataIndex;

								TRACE("Consecutive Frame Received2\n");
								memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize);
								RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
								bAllFramesReceived = TRUE;
							}
							stSaveRxMultipleSegmData[msg_index].usLeftDL = stSaveRxMultipleSegmData[msg_index].usLeftDL - ucMsgDL;
							stSaveRxMultipleSegmData[msg_index].usDataIndex = stSaveRxMultipleSegmData[msg_index].usDataIndex + ucMsgDL;
						}

						if (bAllFramesReceived == FALSE)
						{
							//Send Flowcontrol if required..
							ulISO15765_ConsecutiveFrames++;

							CCanMsg		    flow_control_frame;
							bool	        bFoundFCMsgId;

							OnFirstFramefunCallBack(stPassRxThruMsg, gpFFVoid,
								&flow_control_frame._msg_id,
								flow_control_frame._data, &flow_control_frame._data_len,
								&flow_control_frame._ulTxflags,
								&bFoundFCMsgId);

							if (!bFoundFCMsgId)
							{
								TRACE("Not found flow control message id ");
								continue;
							}

							J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;

							if (ulISO15765_ConsecutiveFrames == flow_control_frame._data[1])
							{

								ulISO15765_ConsecutiveFrames = 0;

								enJ2534Error = pOemTool->SendToDevice(flow_control_frame._msg_id, flow_control_frame._data, flow_control_frame._data_len, flow_control_frame._ulTxflags, (unsigned long)stPassRxThruMsg.ulProtocolID);

								if (enJ2534Error != J2534_STATUS_NOERROR)
								{
									TRACE("Flow control not Transmitted\n");
									continue;
								}

								pOemTool->ReadInputReport();
#if 0
								if (pOemTool->InputReport[3] == J2534_STATUS_NOERROR)
#else
								if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
#endif
								{
									TRACE("PASS:Flow control Wrtie TXDONE\n");;//pstPassThruMsg->ulTimeStamp = ulTimestamp;
									//LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
								}
								else
								{
									TRACE("FAIL:Flow control Wrtie TXDONE\n");;//			m_ulLastErrorCode = (J2534ERROR)pOemTool->ReadInputReport[3];
									//			return m_ulLastErrorCode;
								}

							}
						}

					}
					break;
					case 0x30:
					{
						/* Check for Flow Control Frame if multiframe request is sent from the device */
						TRACE("Checking Flow Control:  %X \n", pOemTool->m_bFlowControlIssued);
						if (pOemTool->m_bFlowControlIssued == TRUE)
						{
							TRACE("Flow Control Received\n");
							/* Update the Data Size and Extra Data Index */
							stPassRxThruMsg.ulDataSize = nDataCount;
							stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;
							// Copy the Flow control Frame
#if 0
							memcpy(&objFlowControlFrm._data[0], &pOemTool->InputReport[ucPCIindex], 8);
#else
							if (ulExtendedAddrType) {
								memcpy(&objFlowControlFrm._data[0], &Inputbuffer->u.ReadMsgsTP.u.extaddr.PCItype, 8);
							}
							else {
								memcpy(&objFlowControlFrm._data[0], &Inputbuffer->u.ReadMsgsTP.u.stdaddr.PCItype, 8);
							}
#endif
							//if (objFlowControlFrm._data[2])
							{
								QueryPerformanceCounter(&t1);
								QueryPerformanceFrequency(&frequency);
							}
							// Clear the Input report
							memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
							memset(Inputbuffer, 0, sizeof(Inputbuffer));
							// Set Flow control Event
							SetEvent(pOemTool->m_FlowControlEvent);
							TRACE("Event is Set\n");
							/* Ravi : As per Implementation from Chaku there is no need
							to call the RxfunCallBack for the flow control since the
							Event is set. Need to analyse and conclude */
							continue;
						}
					}
					break;
					default:
					{
					}
					break;
					}
				}
				else if (uchMode == 0x01) // Multi Frame Mode
				{
#if 0
					int nIdx = 5;
#else
					int nIdx = sizeof(InputBuffer_t) - sizeof(Inputbuffer->u) + sizeof(Inputbuffer->u.ReadMsgTP1.segnum)
						+ sizeof(Inputbuffer->u.ReadMsgTP1.mode);
#endif
					uint8_t* pSrc;
					pSrc = (uint8_t*)&Inputbuffer->u.ReadMsgTP1.u.stdaddr;
					for (int nMsgIdx = 0; nMsgIdx < uchMessageCnt; nMsgIdx++)
					{
						/* Ravi : INtegrated for ISO 15765 */
#if 0
						stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];

						//Databytes Count;
						nDataCount = pOemTool->InputReport[nIdx] - 6; //2 Byte Flag + 4 Bytes TimeStamp							
#else
						stPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;

						//Databytes Count;
						nDataCount = Inputbuffer->u.ReadMsgTP1.messagelength -
							(sizeof(Inputbuffer->u.ReadMsgTP1.RxFlags) + sizeof(Inputbuffer->u.ReadMsgTP1.TimeStamp));

#endif
						// Check whether frame formatted properly or not
#if 0
						if ((nIdx + pOemTool->InputReport[nIdx]) > 509) // chiru 61
#else
						if ((nIdx + Inputbuffer->u.ReadMsgTP1.messagelength) > 509)
#endif
						{
							/* Max buffer size - 3 bytes */
							TRACE("Error: Invalid CAN Message Format for Mode - 01\n");
							break;
						}

						//Rx Flags - 2 Bytes
#if 0
						ulRxFlags = (unsigned long)pOemTool->InputReport[nIdx + 1];
						ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[nIdx + 2] << 8;
#else
						ulRxFlags = Inputbuffer->u.ReadMsgTP1.RxFlags;
#endif
						/*jayasheela-Added to chek padding error */
						if (nDataCount < 0x000C)
							ulRxFlags = ulRxFlags | 0x00000010;
#if 0
						//Timestamp
						stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[nIdx + 3];
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 4] << 8;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 5] << 16;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 6] << 24;
#else
						stPassRxThruMsg.ulTimeStamp = Inputbuffer->u.ReadMsgTP1.TimeStamp;
#endif

						/*jayasheela-call callback function to updated Rxstatus flag*/
#if 0
						stSetRxstatusPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];
#else
						stSetRxstatusPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
						protocolid = Inputbuffer->proto_id;
#endif
						stSetRxstatusPassRxThruMsg.ulRxStatus = ulRxFlags;
						stSetRxstatusPassRxThruMsg.ulDataSize = nDataCount;
						stSetRxstatusPassRxThruMsg.ulExtraDataIndex = stSetRxstatusPassRxThruMsg.ulDataSize;
						stSetRxstatusPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
#if 0
						memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], stSetRxstatusPassRxThruMsg.ulDataSize);
#else
						memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0],
							&Inputbuffer->u.ReadMsgTP1.u.Data_Bytes, stSetRxstatusPassRxThruMsg.ulDataSize);
#endif

						OnISO15765RxMsgSetstatusfnCallBack(&stSetRxstatusPassRxThruMsg, gpUpdateRxstatusVoid);

						/* Check if the received message is of type extended CAN ID */
						ulExtendedAddrType = stSetRxstatusPassRxThruMsg.ulRxStatus & ISO15765_ADDR_TYPE;
						// Ravi : Since the RxStatus is set in the call back, we need to update the 
						// stPassRxThruMsg structure here.
						stPassRxThruMsg.ulRxStatus = stSetRxstatusPassRxThruMsg.ulRxStatus;
#if 0
						if (ulExtendedAddrType)
						{
							ucPCIindex = nIdx + 12;
						}
						else
						{
							ucPCIindex = nIdx + 11;
						}
						ucPCItype = pOemTool->InputReport[ucPCIindex] & 0xF0;
#else
						

						// Get base pointer to your CAN frame data
					
						if (ulExtendedAddrType) {
							ucPCItype = Inputbuffer->u.ReadMsgTP1.u.extaddr.PCItype & 0xF0;
						}
						else {
							ucPCItype = Inputbuffer->u.ReadMsgTP1.u.stdaddr.PCItype & 0xF0;
						}
#endif

						/* Put the received input report for debug purpose */
					/*	for (int i = 0; i < nDataCount; i++)
						{
							TRACE("%2X ", stPassRxThruMsg.ucData[i]);
						}*/
						TRACE("\n");
						switch (ucPCItype)
						{
						case 0x00:
						{
							TRACE("Single Frame Received\n");
							//TRACE("Valid Message %X\n",pOemTool->InputReport[ucPCIindex]);
							/* Construct the Start of message indication */
#if 0
							if (ulExtendedAddrType)
							{
								ucCANIDSize = 5;
							}
							else
							{
								ucCANIDSize = 4;
							}
#else
							ucCANIDSize = sizeof(Inputbuffer->u.ReadMsgTP1.u.stdaddr.canid);
							if (ulExtendedAddrType) {
								ucCANIDSize += sizeof(uint8_t);
							}
#endif
							/* Update the Data Size and Extra Data Index */
							/* Subtract RxFlags and Time Stamp to get the pass thru data length */
							/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
							No need to subtract with 8 bytes */
#if 0
							memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], ucCANIDSize);
#else
							memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgTP1.u.Data_Bytes, ucCANIDSize);
#endif
							/*Jayasheela-should consider the leght specified in PCI bytes*/
							/*ucMsgDL = nDataCount - ucCANIDSize - 1;
							stPassRxThruMsg.ulDataSize = nDataCount - 1;*/
#if 0
							ucMsgDL = pOemTool->InputReport[ucPCIindex] & 0x0F;
#else
							if (Inputbuffer->proto_id == FD_ISO15765_PS)
							{
								if (ulExtendedAddrType) {
									ucMsgDL = Inputbuffer->u.ReadMsgTP1.u.extaddr.PCItype & 0x0F;
									memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.extaddr.usFF_DL, ucMsgDL);
								}
								else {
									ucMsgDL = Inputbuffer->u.ReadMsgTP1.u.stdaddr.PCItype & 0x0F;
									memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL, ucMsgDL);
									if (ucMsgDL == 0)
									{
										ucMsgDL = Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL & 0xFF;
										memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.Data_Bytes, ucMsgDL);
									}
								}
							}
							else
							{
								if (ulExtendedAddrType) {
									ucMsgDL = Inputbuffer->u.ReadMsgTP1.u.extaddr.PCItype & 0x0F;
									memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.extaddr.usFF_DL, ucMsgDL);
								}
								else {
									ucMsgDL = Inputbuffer->u.ReadMsgTP1.u.stdaddr.PCItype & 0x0F;
									memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL, ucMsgDL);
								}

							}


#endif
							stPassRxThruMsg.ulDataSize = ucMsgDL + ucCANIDSize;
							stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;
#if 0	
							memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize], &pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);

#endif
							/* Send the Start of message indication */
							RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

							//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
							memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
							memset(Inputbuffer, 0, sizeof(Inputbuffer));
						}
						break;
						case 0x10:
						{
							TRACE("First Frame Received\n");

							ulISO15765_ConsecutiveFrames = 0;

							/* Get the First Frame Data Length */
#if 0
							usFF_DL = pOemTool->InputReport[ucPCIindex] & 0x0F;
							usFF_DL = (usFF_DL << 8) | pOemTool->InputReport[++ucPCIindex];
						//	ucPCIindex += 2; for can fd
							usFF_DL = (pOemTool->InputReport[ucPCIindex] << 24 & 0x000000FF) |
								(pOemTool->InputReport[++ucPCIindex] << 16 & 0x000000FF) |
								(pOemTool->InputReport[++ucPCIindex] << 8 & 0x000000FF) |
								(pOemTool->InputReport[++ucPCIindex] & 0x000000FF);//
#else
							if (ulExtendedAddrType) {
								usFF_DL = Inputbuffer->u.ReadMsgTP1.u.extaddr.PCItype & 0x0F;
								usFF_DL = (usFF_DL  << 8) | (Inputbuffer->u.ReadMsgTP1.u.extaddr.usFF_DL);
							//	usFF_DL = Inputbuffer->u.ReadMsgTP1.u.extaddr.rsvd;
								ucMinFF_DL = 6;
							}
							else {
								usFF_DL = Inputbuffer->u.ReadMsgTP1.u.stdaddr.PCItype & 0x0F;
								usFF_DL = (usFF_DL  << 8) | (Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL);
								//usFF_DL = Inputbuffer->u.ReadMsgTP1.u.stdaddr.rsvd;
								ucMinFF_DL = 7;
							}
#endif

							TRACE("%X\n", usFF_DL);
							/* Check for valid First Frame */

							if (usFF_DL > ucMinFF_DL)
							{
								/* Construct the Start of message indication */
#if 0
								if (ulExtendedAddrType)
								{
									ucCANIDSize = 5;
								}
								else
								{
									ucCANIDSize = 4;
								}
#else
								ucCANIDSize = sizeof(Inputbuffer->u.ReadMsgTP1.u.stdaddr.canid);
								if (ulExtendedAddrType) {
									ucCANIDSize += sizeof(uint8_t);
								}
#endif
								msg_index = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);

								if (0xff == msg_index)
								{
									continue;
								}
								stPassRxThruMsg.ulDataSize = ucCANIDSize;

								/*Jayasheela -removed as EDI is zero for all indiactions */
								//stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize; 

								/* Update the Rx status as Start of the message and received */
								stPassRxThruMsg.ulRxStatus |= 0x02;
#if 0
								memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], ucCANIDSize);
								/* Take back-up of the FF data to construct the segmented message data */
								/* Copy the CAN ID */
								memcpy((char*)&stTempPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], ucCANIDSize);
#else
								memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgTP1.u.Data_Bytes, ucCANIDSize);
								memcpy((char*)&stTempPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgTP1.u.Data_Bytes, ucCANIDSize);
#endif
								/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
								No need to subtract with 8 bytes */
								ucMsgDL = nDataCount - ucCANIDSize - 2;
#if 0
								memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);
#else
								if (ulExtendedAddrType) {
								//	memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.extaddr.usFF_DL, ucMsgDL);
									memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.extaddr.Data_Bytes, ucMsgDL);
								}
								else {
								//	memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL, ucMsgDL);
									memcpy((char*)&stTempPassRxThruMsg.ucData[ucCANIDSize], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.Data_Bytes, ucMsgDL);
								}
#endif
								stTempPassRxThruMsg.ulDataSize = nDataCount - 2;
								stPassRxThruMsg.ulExtraDataIndex = 0;
								/* Send the Start of message indication */
								RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
								memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
								memset(Inputbuffer, 0, sizeof(Inputbuffer));

								// Build flow control frame

								/*Jayasheela-construct flow control frame */

								CCanMsg		    flow_control_frame;
								bool	        bFoundFCMsgId;

								OnFirstFramefunCallBack(stPassRxThruMsg, gpFFVoid,
									&flow_control_frame._msg_id,
									flow_control_frame._data, &flow_control_frame._data_len,
									&flow_control_frame._ulTxflags,
									&bFoundFCMsgId);

								if (!bFoundFCMsgId)
								{
									TRACE("Not found flow control message id ");
									continue;
								}
								J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
								//Send the Flow control frame

								enJ2534Error = pOemTool->SendToDevice(flow_control_frame._msg_id, flow_control_frame._data, flow_control_frame._data_len, flow_control_frame._ulTxflags, (unsigned long)stPassRxThruMsg.ulProtocolID);

								if (enJ2534Error != J2534_STATUS_NOERROR)
								{
									TRACE("Flow control not Transmitted\n");
									continue;
								}

								pOemTool->ReadInputReport();
#if 0
								if (pOemTool->InputReport[3] == J2534_STATUS_NOERROR)
#else
								if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
#endif
								{
									TRACE("PASS:Flow control Wrtie TXDONE\n");;//pstPassThruMsg->ulTimeStamp = ulTimestamp;
									//LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
								}
								else
								{
									TRACE("FAIL:Flow control Wrtie TXDONE\n");;//			m_ulLastErrorCode = (J2534ERROR)pOemTool->ReadInputReport[3];
									//			return m_ulLastErrorCode;
								}


								/* Copy the First Frame Details to construct the Segmented data */
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID = stPassRxThruMsg.ulProtocolID;
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulRxStatus = stPassRxThruMsg.ulRxStatus;
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize = usFF_DL + ucCANIDSize;
								stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize;
								stSaveRxMultipleSegmData[msg_index].usDataIndex = 0;
								memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
									&stTempPassRxThruMsg.ucData[0], stTempPassRxThruMsg.ulDataSize);
								stSaveRxMultipleSegmData[msg_index].usDataIndex = nDataCount - 2; /*Ravi : TXflag and Time stamp are not considered */
								stSaveRxMultipleSegmData[msg_index].usLeftDL = (unsigned short)(stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize - stTempPassRxThruMsg.ulDataSize);
							}
							else
							{
								TRACE("First Frame Received is invalid - FF DL = %x\n", usFF_DL);
							}
						}
						break;
						case 0x20:
						{
							TRACE("Consecutive Frame Received1\n");
#if 0	
							memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], ucCANIDSize);
#else
							memcpy((char*)&stPassRxThruMsg.ucData[0], Inputbuffer->u.ReadMsgTP1.u.Data_Bytes, ucCANIDSize);
#endif
							msg_index = pOemTool->GetMsgIndex(stSaveRxMultipleSegmData, stPassRxThruMsg, ucCANIDSize);

							if (0xff == msg_index)
							{
								continue;
							}


							BOOL bAllFramesReceived = FALSE;

							/*Ravi : Note that the Message length is excluding the RXFlags and Time Stamp
							No need to subtract with 8 bytes */
							ucMsgDL = nDataCount - ucCANIDSize - 1;
							if (stSaveRxMultipleSegmData[msg_index].usLeftDL > 0)
							{
#if 0	
								memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
									&pOemTool->InputReport[ucPCIindex + 1], ucMsgDL);
#else
								if (ulExtendedAddrType) {
									memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
										&Inputbuffer->u.ReadMsgTP1.u.extaddr.usFF_DL, ucMsgDL);
								}
								else {
								/*	memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
										&Inputbuffer->u.ReadMsgTP1.u.stdaddr.usFF_DL, ucMsgDL);*/
									if (pSrc == (uint8_t*)&Inputbuffer->u.ReadMsgTP1.u.stdaddr)
									{
										pSrc += 5;
									}
									else
									{
										pSrc += 19;
									}
									memcpy((char*)&stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[stSaveRxMultipleSegmData[msg_index].usDataIndex],
										pSrc, ucMsgDL);

								}

#endif

								//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
						//		memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
						//		memset(Inputbuffer, 0, sizeof(Inputbuffer));

								if (ucMsgDL >= stSaveRxMultipleSegmData[msg_index].usLeftDL)
								{
									/*copy data to structure to put into buffer */
									stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize;
									stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID;
									//stPassRxThruMsg.ulTimeStamp  = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
									//stPassRxThruMsg.ulRxStatus   = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulRxStatus;
									stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulExtraDataIndex;

									TRACE("Consecutive Frame Received2\n");
									memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulDataSize);
									RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
									stSaveRxMultipleSegmData[msg_index].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
									bAllFramesReceived = TRUE;
								}
								stSaveRxMultipleSegmData[msg_index].usLeftDL = stSaveRxMultipleSegmData[msg_index].usLeftDL - ucMsgDL;
								stSaveRxMultipleSegmData[msg_index].usDataIndex = stSaveRxMultipleSegmData[msg_index].usDataIndex + ucMsgDL;
							}

							if (bAllFramesReceived == FALSE)
							{
								//Send Flowcontrol if required..
								ulISO15765_ConsecutiveFrames++;

								CCanMsg		    flow_control_frame;
								bool	        bFoundFCMsgId;

								OnFirstFramefunCallBack(stPassRxThruMsg, gpFFVoid,
									&flow_control_frame._msg_id,
									flow_control_frame._data, &flow_control_frame._data_len,
									&flow_control_frame._ulTxflags,
									&bFoundFCMsgId);

								if (!bFoundFCMsgId)
								{
									TRACE("Not found flow control message id ");
									continue;
								}

								J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;

								if (ulISO15765_ConsecutiveFrames == flow_control_frame._data[1])
								{

									ulISO15765_ConsecutiveFrames = 0;

									enJ2534Error = pOemTool->SendToDevice(flow_control_frame._msg_id, flow_control_frame._data, flow_control_frame._data_len, flow_control_frame._ulTxflags, (unsigned long)stPassRxThruMsg.ulProtocolID);

									if (enJ2534Error != J2534_STATUS_NOERROR)
									{
										TRACE("Flow control not Transmitted\n");
										continue;
									}

									pOemTool->ReadInputReport();
#if 0
									if (pOemTool->InputReport[3] == J2534_STATUS_NOERROR)
#else
									if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
#endif
									{
										TRACE("PASS:Flow control Wrtie TXDONE\n");;//pstPassThruMsg->ulTimeStamp = ulTimestamp;
										//LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
									}
									else
									{
										TRACE("FAIL:Flow control Wrtie TXDONE\n");;//			m_ulLastErrorCode = (J2534ERROR)pOemTool->ReadInputReport[3];
										//			return m_ulLastErrorCode;
									}

								}
							}

						}
						break;
						case 0x30:
						{
							/* Check for Flow Control Frame if multiframe request is sent from the device */
							TRACE("Checking Flow Control:  %X \n", pOemTool->m_bFlowControlIssued);
							if (pOemTool->m_bFlowControlIssued == TRUE)
							{
								TRACE("Flow Control Received\n");
								/* Update the Data Size and Extra Data Index */

								stPassRxThruMsg.ulDataSize = nDataCount;
								stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;
								// Copy the Flow control Frame
#if 0
								memcpy(&objFlowControlFrm._data[0], &pOemTool->InputReport[ucPCIindex], 8);
#else
								if (ulExtendedAddrType) {
									memcpy(&objFlowControlFrm._data[0], &Inputbuffer->u.ReadMsgTP1.u.extaddr.PCItype, 8);
								}
								else {
									memcpy(&objFlowControlFrm._data[0], &Inputbuffer->u.ReadMsgTP1.u.stdaddr.PCItype, 8);
								}
#endif
								//if (objFlowControlFrm._data[2])
								{
									QueryPerformanceCounter(&t1);
									QueryPerformanceFrequency(&frequency);
								}
								// Clear the Input report
								//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet										
						//		memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
						//		memset(Inputbuffer, 0, sizeof(Inputbuffer));
								// Set Flow control Event
								SetEvent(pOemTool->m_FlowControlEvent);
								TRACE("Event is Set\n");
								/* Ravi : As per Implementation from Chaku there is no need
								to call the RxfunCallBack for the flow control since the
								Event is set. Need to analyse and conclude */
								continue;
							}
						}
						break;
						default:
						{
						}
						break;
						}

						//Checking whether PCI is Multi Frame or not
						if (ucPCItype == 0x10)
						{
							//In Multi Frame, we are reading one more frame and updating the parsing info frame
							//so no necessitity of parising other frames, it already corrupted

							break;
						}

						//Update index for pointing next frame
#if 0
						nIdx = nIdx + nDataCount + 6 + 1; //DataCount + 6 Bytes ( 2Bytes Rx Flax + 4 Bytes TimeStamp) + lenth field
#else
						nIdx = nIdx + nDataCount + sizeof(Inputbuffer->u.ReadMsgTP1.messagelength) + sizeof(Inputbuffer->u.ReadMsgTP1.RxFlags)
							+ sizeof(Inputbuffer->u.ReadMsgTP1.TimeStamp);
#endif
					}

					//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
					memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
					memset(Inputbuffer, 0, sizeof(Inputbuffer));
				}
			}
			break;
			case J1939_CH1:/*J1939 Protocol Receive indication*/
			case J1939_CH2:
			case J1939_PS:
			{
				unsigned char uchMode;
				unsigned char uchMessageCnt;
				unsigned long ulJ1939MsgId = 0x00;
				unsigned char uchPriority;
				unsigned long ulPGN;
				unsigned char uchSrc;
				unsigned char uchDest;
				unsigned char uchTPId;
				unsigned char nCANDataIdx;

				uchMode = (unsigned char)((pOemTool->InputReport[4] >> 6) && 0x03);
				uchMessageCnt = pOemTool->InputReport[4] & 0x3F;

				//TRACE("\nMessage Count - %d",uchMessageCnt);
				if (uchMode == 0x00) //Legacy Frame
				{
					/* Ravi : INtegrated for ISO 15765 */
					stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];

					/* Ravi : RxStatus bit defination has the Extended Address flag. */
					nDataCount = (short)(pOemTool->InputReport[5]);
					nDataCount = nDataCount | (short)(pOemTool->InputReport[6] << 8);

					/*Collect receive flags*/

					ulRxFlags = (unsigned long)pOemTool->InputReport[7];
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[8] << 8;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[9] << 16;
					ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[10] << 24;

					/*Get the timestamp from the device*/
					stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
					stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;

					//To get the J1939 Message Id from USB Frame
					ulJ1939MsgId = (pOemTool->InputReport[15] << 24);
					ulJ1939MsgId |= (pOemTool->InputReport[16] << 16);
					ulJ1939MsgId |= (pOemTool->InputReport[17] << 8);
					ulJ1939MsgId |= (pOemTool->InputReport[18] << 0);

					//To get the J1939 Header Details
					pOemTool->GetPGNParametersFromHeader(ulJ1939MsgId, uchPriority, ulPGN, uchSrc, uchDest);

					nCANDataIdx = 19;
					ucCANIDSize = 4;

					switch (ulPGN)
					{
					case 0xEC00:
					{
						switch (pOemTool->InputReport[nCANDataIdx])
						{
						case 0x10: //CM: RTS
						{
							PASSTHRU_MSG* passThruMsg;
							unsigned long ulMsgId;
							unsigned long ulCTSPGN;
							unsigned long ulDataBytes;
							unsigned long ulPackets;

							//Checking whether any message slot availble for saving the data
							nJ1939MsgIdx = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);
							if (nJ1939MsgIdx == 0xFF)
							{
								continue;
							}

							passThruMsg = &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg;
							passThruMsg->ulProtocolID = stPassRxThruMsg.ulProtocolID;

							//To get the PGN from the data bytes
							ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN = pOemTool->InputReport[nCANDataIdx + 5];
							ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN |= (pOemTool->InputReport[nCANDataIdx + 6] << 8);
							ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN |= (pOemTool->InputReport[nCANDataIdx + 7] << 16);


							passThruMsg->ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
							passThruMsg->ulRxStatus = ulRxFlags;

							//Compute J1939 Header
							ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, ulCTSPGN, uchSrc, uchDest);
							passThruMsg->ucData[0] = (unsigned char)((unsigned char*)&ulMsgId)[3];
							passThruMsg->ucData[1] = (unsigned char)((unsigned char*)&ulMsgId)[2];
							passThruMsg->ucData[2] = (unsigned char)((unsigned char*)&ulMsgId)[1];
							passThruMsg->ucData[3] = (unsigned char)((unsigned char*)&ulMsgId)[0];

							passThruMsg->ucData[4] = uchDest; //Destination Address 

							stSaveRxMultipleSegmData[nJ1939MsgIdx].bBAM = false;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex = 5;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSSource = uchSrc;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts = pOemTool->InputReport[nCANDataIdx + 3];
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt = 0x01;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSBytesReceived = 0x00;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes = pOemTool->InputReport[nCANDataIdx + 1];
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes |= (pOemTool->InputReport[nCANDataIdx + 2] << 0x8);
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS = pOemTool->InputReport[nCANDataIdx + 4];
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS = 0;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].ulLastRxTimeStamp = GetTickCount();

							//Send CTS for the received frame
							PASSTHRU_MSG passThruMsgCTS;
							unsigned char ctsDataBytes[8];


							ctsDataBytes[0] = 0x11;
							//Set to Min of Max Packets & Max CTS Packets can receive
							if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
							{
								ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
							}
							else
							{
								ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS;
							}

							ctsDataBytes[2] = 0x01;
							ctsDataBytes[3] = 0xFF;
							ctsDataBytes[4] = 0xFF;
							ctsDataBytes[5] = (unsigned char)((ulCTSPGN >> 0) & 0xFF);
							ctsDataBytes[6] = (unsigned char)((ulCTSPGN >> 8) & 0xFF);
							ctsDataBytes[7] = (unsigned char)((ulCTSPGN >> 16) & 0xFF);

							//Compute J1939 Header
							ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

							J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
							enJ2534Error = pOemTool->SendJ1939SingleMessage(ulMsgId, ctsDataBytes, 8, 0x100, (unsigned char)passThruMsg->ulProtocolID);
							if (enJ2534Error != J2534_STATUS_NOERROR)
							{
								TRACE("CTS not Transmitted\n");
								continue;
							}
						}
						break;
						case 0x11: //CM: CTS
						case 0xFF: //CM: Connection Abort
						{
							//Checking whether RTS from device or not
							TRACE("RTS Issued:  %X \n", pOemTool->m_bFlowControlIssued);
							if (pOemTool->m_bFlowControlIssued == TRUE)
							{
								TRACE("CTS Received\n");
								/* Update the Data Size and Extra Data Index */
								stPassRxThruMsg.ulDataSize = nDataCount;
								stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;

								objFlowControlFrm._msg_id = ulJ1939MsgId;

								// Copy the CTS Frame
								memcpy(&objFlowControlFrm._data[0], &pOemTool->InputReport[nCANDataIdx], 8);
								//if (objFlowControlFrm._data[2])
								{
									QueryPerformanceCounter(&t1);
									QueryPerformanceFrequency(&frequency);
								}

								// Clear the Input report
								memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);

								// Set Flow control Event
								SetEvent(pOemTool->m_FlowControlEvent);
								TRACE("Event is Set\n");

								continue;
							}
						}
						break;
						case 0x13: //End of Msg Ack
						{
						}
						break;
						case 0x20: //CM: BAM
						{
							PASSTHRU_MSG* passThruMsg;
							unsigned long ulMsgId;
							unsigned long ulBAMPGN;
							unsigned long ulDataBytes;
							unsigned long ulPackets;

							//Checking whether any message slot availble for saving the data
							nJ1939MsgIdx = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);
							if (nJ1939MsgIdx == 0xFF)
							{
								continue;
							}

							passThruMsg = &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg;
							passThruMsg->ulProtocolID = stPassRxThruMsg.ulProtocolID;

							//To get the PGN from the data bytes
							ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN = pOemTool->InputReport[nCANDataIdx + 5];
							ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN |= (pOemTool->InputReport[nCANDataIdx + 6] << 8);
							ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN |= (pOemTool->InputReport[nCANDataIdx + 7] << 16);


							passThruMsg->ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
							passThruMsg->ulRxStatus = ulRxFlags;

							//Compute J1939 Header
							ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, ulBAMPGN, uchSrc, uchDest);
							passThruMsg->ucData[0] = (unsigned char)((unsigned char*)&ulMsgId)[3];
							passThruMsg->ucData[1] = (unsigned char)((unsigned char*)&ulMsgId)[2];
							passThruMsg->ucData[2] = (unsigned char)((unsigned char*)&ulMsgId)[1];
							passThruMsg->ucData[3] = (unsigned char)((unsigned char*)&ulMsgId)[0];

							passThruMsg->ucData[4] = 0xFF; //BAM 

							stSaveRxMultipleSegmData[nJ1939MsgIdx].bBAM = true;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex = 5;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSSource = uchSrc;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPkts = pOemTool->InputReport[nCANDataIdx + 3];
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt = 0x01;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSBytesReceived = 0x00;
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes = pOemTool->InputReport[nCANDataIdx + 1];
							stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes |= (pOemTool->InputReport[nCANDataIdx + 2] << 0x8);
							stSaveRxMultipleSegmData[nJ1939MsgIdx].ulLastRxTimeStamp = GetTickCount();
						}
						break;
						}
					}
					break;

					case 0xEB00:
					{
						unsigned char uchPacketNo = pOemTool->InputReport[nCANDataIdx];
						PASSTHRU_MSG* passThruMsg;
						unsigned int nDataIdx;
						unsigned char uchDataLength = 7;

						if (uchDest == 0xFF)
						{
							//BAM Message
							//Get the J1939 Message Idx suits for uchSrc Multi Message
							nJ1939MsgIdx = pOemTool->GetJ1939MsgIndex(stSaveRxMultipleSegmData, pOemTool->InputReport[1], uchSrc, true);
							if (nJ1939MsgIdx == 0xFF)
								continue;

							if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt)
							{
								nDataIdx = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

								if ((nDataIdx - 5 + 7) > stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes)
								{
									uchDataLength = 7 - ((nDataIdx - 5 + 7) - stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes);
								}

								//Copy the data bytes to array
								memcpy(&stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[nDataIdx],
									&pOemTool->InputReport[nCANDataIdx + 1],
									uchDataLength);

								//Update Data Index
								stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex += uchDataLength;

								//Update Data Size
								stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

								//Check whether received all the packet or not
								if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPkts)
								{
									/*copy data to structure to put into buffer */
									stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;
									stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID;
									stPassRxThruMsg.ulTimeStamp = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
									stPassRxThruMsg.ulRxStatus = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulRxStatus;
									stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;

									memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize);
									if (RxfunCallBack[stPassRxThruMsg.ulProtocolID] != NULL)
										RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

									//Reset Protocol Id
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
								}

								//Upate Next Packet
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt++;
							}
							else
							{
								//Error in receiving the frames
								stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
							}

						}
						else
						{
							//Get the J1939 Message Idx suits for uchSrc Multi Message
							nJ1939MsgIdx = pOemTool->GetJ1939MsgIndex(stSaveRxMultipleSegmData, pOemTool->InputReport[1], uchSrc, false);
							if (nJ1939MsgIdx == 0xFF)
								continue;

							if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt)
							{
								nDataIdx = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

								if ((nDataIdx - 5 + 7) > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes)
								{
									uchDataLength = 7 - ((nDataIdx - 5 + 7) - stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes);
								}

								//Copy the data bytes to array
								memcpy(&stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[nDataIdx],
									&pOemTool->InputReport[nCANDataIdx + 1],
									uchDataLength);

								//Update Data Index
								stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex += uchDataLength;

								//Update Data Size
								stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

								//Check whether received all the packet or not
								if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
								{
									/*copy data to structure to put into buffer */
									stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;
									stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID;
									stPassRxThruMsg.ulTimeStamp = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
									stPassRxThruMsg.ulRxStatus = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulRxStatus;
									stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;

									memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize);
									RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

									//Reset Protocol Id
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;

									//Sending End of Message Ack to the sender
									PASSTHRU_MSG passThruMsgCTS;
									unsigned char ctsDataBytes[8];

									ctsDataBytes[0] = 0x13;
									ctsDataBytes[1] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes >> 0) & 0xFF);												ctsDataBytes[2] = 0x01;
									ctsDataBytes[3] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes >> 8) & 0xFF);
									ctsDataBytes[4] = 0xFF;
									ctsDataBytes[5] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 0) & 0xFF);
									ctsDataBytes[6] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 8) & 0xFF);
									ctsDataBytes[7] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 16) & 0xFF);

									//Compute J1939 Header
									unsigned long ulEndofAckMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

									J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
									enJ2534Error = pOemTool->SendJ1939SingleMessage(ulEndofAckMsgId, ctsDataBytes, 8, 0x100, (unsigned char)stPassRxThruMsg.ulProtocolID);
									if (enJ2534Error != J2534_STATUS_NOERROR)
									{
										TRACE("CTS not Transmitted\n");
										continue;
									}
								}
								else
								{
									stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS++;

									//Checking for Maximum no. of packets received for one CTS or not
									if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS ==
										stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS)
									{
										//Reset Packet Cnt received
										stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS = 0;

										//Send CTS for the received frame
										PASSTHRU_MSG passThruMsgCTS;
										unsigned char ctsDataBytes[8];


										ctsDataBytes[0] = 0x11;
										//Set to Min of Max Packets & Max CTS Packets can receive
										if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
										{
											ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
										}
										else
										{
											ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS;
										}
										//ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
										ctsDataBytes[2] = uchPacketNo + 1;
										ctsDataBytes[3] = 0xFF;
										ctsDataBytes[4] = 0xFF;
										ctsDataBytes[5] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 0) & 0xFF);
										ctsDataBytes[6] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 8) & 0xFF);
										ctsDataBytes[7] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 16) & 0xFF);

										//Compute J1939 Header
										unsigned long ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

										J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
										enJ2534Error = pOemTool->SendJ1939SingleMessage(ulMsgId, ctsDataBytes, 8, 0x100, (unsigned char)stPassRxThruMsg.ulProtocolID);
										if (enJ2534Error != J2534_STATUS_NOERROR)
										{
											TRACE("CTS not Transmitted\n");
											continue;
										}

									}
								}

								//Upate Next Packet
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt++;

							}
							else
							{
								//Error in receiving the frames
								stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
							}

						}
					}
					break;
					case 0xEE00:
					{
						//Copying  Data Bytes
						stPassRxThruMsg.ucData[0] = pOemTool->InputReport[nCANDataIdx];

						stPassRxThruMsg.ulDataSize = 1;
						stPassRxThruMsg.ulExtraDataIndex = 0;
						stPassRxThruMsg.ulRxStatus = ulRxFlags;

						//Send Address Claim or Lost Indication to J2534 Layer
						if (OnJ1939RxMsgSetstatusfnCallBack != NULL)
						{
							OnJ1939RxMsgSetstatusfnCallBack(&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
						}

					}
					break;
					default:
					{
						//Normal Message
						//Check for loopback or normal message or Ack
						TRACE("Single Frame Received\n");

						//Copying Header
						memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], ucCANIDSize);

						//Copying Src Address
						stPassRxThruMsg.ucData[ucCANIDSize] = uchDest;

						//Copying  Data Bytes
						memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize + 1], &pOemTool->InputReport[nCANDataIdx], nDataCount - ucCANIDSize);

						stPassRxThruMsg.ulDataSize = nDataCount + 1;
						stPassRxThruMsg.ulExtraDataIndex = 0;
						stPassRxThruMsg.ulRxStatus = ulRxFlags;

						/* Send the Start of message indication */
						if (RxfunCallBack[stPassRxThruMsg.ulProtocolID] != NULL)
							RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

						//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
						//memset(&pOemTool->InputReport,0,INPUTREPORTMAX);	
					}
					}
				}
				else if (uchMode == 0x01) // Multi Frame Mode
				{

#ifdef MULTI_MODE_DEBUGGING
					//Debugging Purpose
					ulMsgCounter += uchMessageCnt;
					ulMaxPacking[uchMessageCnt]++;
					TRACE("%lu MsgCount - %d : %lu, %lu , %lu , %lu \n", GetTickCount(), uchMessageCnt, ulMsgCounter,
						ulMaxPacking[1], ulMaxPacking[2], ulMaxPacking[3]);
#endif

					int nIdx = 5;
					for (int nMsgIdx = 0; nMsgIdx < uchMessageCnt; nMsgIdx++)
					{
						stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];

						//Databytes Count;
						nDataCount = pOemTool->InputReport[nIdx] - 6; //2 Byte Flag + 4 Bytes TimeStamp							

						// Check whether frame formatted properly or not
						if ((nIdx + pOemTool->InputReport[nIdx]) > 61)
						{
							TRACE("Error: Invalid CAN Message Format for Mode - 01\n");
							break;
						}

						//Rx Flags - 2 Bytes
						ulRxFlags = (unsigned long)pOemTool->InputReport[nIdx + 1];
						ulRxFlags = ulRxFlags | (unsigned long)pOemTool->InputReport[nIdx + 2] << 8;
						/*jayasheela-Added to chek padding error */
						if (nDataCount < 0x000C)
							ulRxFlags = ulRxFlags | 0x00000010;

						//Timestamp
						stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[nIdx + 3];
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 4] << 8;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 5] << 16;
						stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[nIdx + 6] << 24;

						//To get the J1939 Message Id from USB Frame
						ulJ1939MsgId = (pOemTool->InputReport[nIdx + 7] << 24);
						ulJ1939MsgId |= (pOemTool->InputReport[nIdx + 8] << 16);
						ulJ1939MsgId |= (pOemTool->InputReport[nIdx + 9] << 8);
						ulJ1939MsgId |= (pOemTool->InputReport[nIdx + 10] << 0);

						if (ulJ1939MsgId == 0x18EEEFF9)
						{
							int test = 0;
						}

						ucCANIDSize = 4;

						//To get the J1939 Header Details
						pOemTool->GetPGNParametersFromHeader(ulJ1939MsgId, uchPriority, ulPGN, uchSrc, uchDest);

						nCANDataIdx = 11;
						uchTPId = (unsigned char)((ulPGN >> 8) & 0xFF);
						switch (uchTPId)
						{
						case 0xEC:
						{
							switch (pOemTool->InputReport[nIdx + nCANDataIdx])
							{
							case 0x10: //CM: RTS
							{
								PASSTHRU_MSG* passThruMsg;
								unsigned long ulMsgId;
								unsigned long ulCTSPGN;
								unsigned long ulDataBytes;
								unsigned long ulPackets;

								//Checking whether any message slot availble for saving the data
								nJ1939MsgIdx = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);
								if (nJ1939MsgIdx == 0xFF)
								{
									continue;
								}

								passThruMsg = &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg;
								passThruMsg->ulProtocolID = stPassRxThruMsg.ulProtocolID;

								//To get the PGN from the data bytes
								ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN = pOemTool->InputReport[nIdx + nCANDataIdx + 5];
								ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN |= (pOemTool->InputReport[nIdx + nCANDataIdx + 6] << 8);
								ulCTSPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN |= (pOemTool->InputReport[nIdx + nCANDataIdx + 7] << 16);

								passThruMsg->ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
								passThruMsg->ulRxStatus = ulRxFlags;

								//Compute J1939 Header
								ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, ulCTSPGN, uchSrc, uchDest);
								passThruMsg->ucData[0] = (unsigned char)((unsigned char*)&ulMsgId)[3];
								passThruMsg->ucData[1] = (unsigned char)((unsigned char*)&ulMsgId)[2];
								passThruMsg->ucData[2] = (unsigned char)((unsigned char*)&ulMsgId)[1];
								passThruMsg->ucData[3] = (unsigned char)((unsigned char*)&ulMsgId)[0];

								passThruMsg->ucData[4] = uchDest; //Destination Address 

								stSaveRxMultipleSegmData[nJ1939MsgIdx].bBAM = false;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex = 5;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSSource = uchSrc;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts = pOemTool->InputReport[nIdx + nCANDataIdx + 3];
								//Commented by Amit
								//stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS = pOemTool->InputReport[nIdx + nCANDataIdx + 4];
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS = pOemTool->InputReport[nIdx + nCANDataIdx + 4];
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt = 0x01;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSBytesReceived = 0x00;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes = pOemTool->InputReport[nIdx + nCANDataIdx + 1];
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes |= (pOemTool->InputReport[nIdx + nCANDataIdx + 2] << 0x8);
								stSaveRxMultipleSegmData[nJ1939MsgIdx].ulLastRxTimeStamp = GetTickCount();

								//Reset Packet Cnt received
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS = 0;


								//Send CTS for the received frame
								PASSTHRU_MSG passThruMsgCTS;
								unsigned char ctsDataBytes[8];


								ctsDataBytes[0] = 0x11;
								//Set to Min of Max Packets & Max CTS Packets can receive
								if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
								{
									ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
								}
								else
								{
									ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS;
								}
								//ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
								ctsDataBytes[2] = 0x01;
								ctsDataBytes[3] = 0xFF;
								ctsDataBytes[4] = 0xFF;
								ctsDataBytes[5] = (unsigned char)((ulCTSPGN >> 0) & 0xFF);
								ctsDataBytes[6] = (unsigned char)((ulCTSPGN >> 8) & 0xFF);
								ctsDataBytes[7] = (unsigned char)((ulCTSPGN >> 16) & 0xFF);

								//Compute J1939 Header
								ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

								J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
								enJ2534Error = pOemTool->SendJ1939SingleMessage(ulMsgId, ctsDataBytes, 8, 0x100, (unsigned char)passThruMsg->ulProtocolID);
								if (enJ2534Error != J2534_STATUS_NOERROR)
								{
									TRACE("CTS not Transmitted\n");
									continue;
								}
							}
							break;
							case 0x11: //CM: CTS
							{
								//Checking whether RTS from device or not
								TRACE("RTS Issued:  %X \n", pOemTool->m_bFlowControlIssued);
								if (pOemTool->m_bFlowControlIssued == TRUE)
								{
									TRACE("CTS Received\n");
									/* Update the Data Size and Extra Data Index */
									stPassRxThruMsg.ulDataSize = nDataCount;
									stPassRxThruMsg.ulExtraDataIndex = stPassRxThruMsg.ulDataSize;

									// Copy the CTS Frame
									objFlowControlFrm._msg_id = ulJ1939MsgId;
									memcpy(&objFlowControlFrm._data[0], &pOemTool->InputReport[nIdx + nCANDataIdx], 8);
									//if (objFlowControlFrm._data[2])
									{
										QueryPerformanceCounter(&t1);
										QueryPerformanceFrequency(&frequency);
									}

									// Clear the Input report
									memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
									// Set Flow control Event
									SetEvent(pOemTool->m_FlowControlEvent);
									TRACE("Event is Set\n");
									/* Ravi : As per Implementation from Chaku there is no need
									to call the RxfunCallBack for the flow control since the
									Event is set. Need to analyse and conclude */
									continue;
								}
							}
							break;
							case 0x13: //End of Msg Ack
							{
							}
							break;
							case 0x20: //CM: BAM
							{
								PASSTHRU_MSG* passThruMsg;
								unsigned long ulMsgId;
								unsigned long ulBAMPGN;
								unsigned long ulDataBytes;
								unsigned long ulPackets;

								//Checking whether any message slot availble for saving the data
								nJ1939MsgIdx = pOemTool->GetIndexToStoreMessage(stSaveRxMultipleSegmData);
								if (nJ1939MsgIdx == 0xFF)
								{
									continue;
								}

								passThruMsg = &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg;
								passThruMsg->ulProtocolID = stPassRxThruMsg.ulProtocolID;

								//To get the PGN from the data bytes
								ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN = pOemTool->InputReport[nIdx + nCANDataIdx + 5];
								ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN |= (pOemTool->InputReport[nIdx + nCANDataIdx + 6] << 8);
								ulBAMPGN = stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPGN |= (pOemTool->InputReport[nIdx + nCANDataIdx + 7] << 16);


								passThruMsg->ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
								passThruMsg->ulRxStatus = ulRxFlags;

								//Compute J1939 Header
								ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, ulBAMPGN, uchSrc, uchDest);
								passThruMsg->ucData[0] = (unsigned char)((unsigned char*)&ulMsgId)[3];
								passThruMsg->ucData[1] = (unsigned char)((unsigned char*)&ulMsgId)[2];
								passThruMsg->ucData[2] = (unsigned char)((unsigned char*)&ulMsgId)[1];
								passThruMsg->ucData[3] = (unsigned char)((unsigned char*)&ulMsgId)[0];

								passThruMsg->ucData[4] = 0xFF; //BAM 

								stSaveRxMultipleSegmData[nJ1939MsgIdx].bBAM = true;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex = 5;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSSource = uchSrc;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPkts = pOemTool->InputReport[nIdx + nCANDataIdx + 3];
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt = 0x01;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSBytesReceived = 0x00;
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes = pOemTool->InputReport[nIdx + nCANDataIdx + 1];
								stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes |= (pOemTool->InputReport[nIdx + nCANDataIdx + 2] << 0x8);
								stSaveRxMultipleSegmData[nJ1939MsgIdx].ulLastRxTimeStamp = GetTickCount();
							}
							break;
							}
						}
						break;
						case 0xEB:
						{
							unsigned char uchPacketNo = pOemTool->InputReport[nIdx + nCANDataIdx];
							PASSTHRU_MSG* passThruMsg;
							unsigned int nDataIdx;
							unsigned char uchDataLength = 7;


							if (uchDest == 0xFF)
							{
								//BAM Message
								//Get the J1939 Message Idx suits for uchSrc Multi Message
								nJ1939MsgIdx = pOemTool->GetJ1939MsgIndex(stSaveRxMultipleSegmData, pOemTool->InputReport[1], uchSrc, true);
								if (nJ1939MsgIdx == 0xFF)
									continue;

								if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt)
								{
									nDataIdx = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

									//To correctthe length for the Padding Bytes
									if ((nDataIdx - 5 + 7) > stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes)
									{
										uchDataLength = 7 - ((nDataIdx - 5 + 7) - stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSTotBytes);
									}

									//Copy the data bytes to array
									memcpy(&stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[nDataIdx],
										&pOemTool->InputReport[nIdx + nCANDataIdx + 1],
										uchDataLength);

									//Update Data Index
									stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex += uchDataLength;

									//Update Data Size
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

									//Check whether received all the packet or not
									if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSPkts)
									{
										/*copy data to structure to put into buffer */
										stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;
										stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID;
										stPassRxThruMsg.ulTimeStamp = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
										stPassRxThruMsg.ulRxStatus = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulRxStatus;
										stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;

										memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize);
										RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

										//Reset Protocol Id
										stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
									}

									//Upate Next Packet
									stSaveRxMultipleSegmData[nJ1939MsgIdx].nBAMRTSNextPkt++;
								}
								else
								{
									//Error in receiving the frames
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
								}

							}
							else
							{
								//Get the J1939 Message Idx suits for uchSrc Multi Message
								nJ1939MsgIdx = pOemTool->GetJ1939MsgIndex(stSaveRxMultipleSegmData, pOemTool->InputReport[1], uchSrc, false);
								if (nJ1939MsgIdx == 0xFF)
									continue;

								if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt)
								{
									nDataIdx = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

									if ((nDataIdx - 5 + 7) > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes)
									{
										uchDataLength = 7 - ((nDataIdx - 5 + 7) - stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes);
									}

									//Copy the data bytes to array
									memcpy(&stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[nDataIdx],
										&pOemTool->InputReport[nIdx + nCANDataIdx + 1],
										uchDataLength);

									//Update Data Index
									stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex += uchDataLength;

									//Update Data Size
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].usDataIndex;

									//Check whether received all the packet or not
									if (uchPacketNo == stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
									{
										/*copy data to structure to put into buffer */
										stPassRxThruMsg.ulDataSize = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize;
										stPassRxThruMsg.ulProtocolID = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID;
										stPassRxThruMsg.ulTimeStamp = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulTimeStamp;
										stPassRxThruMsg.ulRxStatus = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulRxStatus;
										stPassRxThruMsg.ulExtraDataIndex = stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulExtraDataIndex;

										memcpy((char*)&stPassRxThruMsg.ucData[0], &stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ucData[0], stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulDataSize);
										RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

										//Reset Protocol Id
										stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;

										//Sending End of Message Ack to the sender
										PASSTHRU_MSG passThruMsgCTS;
										unsigned char ctsDataBytes[8];

										ctsDataBytes[0] = 0x13;
										ctsDataBytes[1] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes >> 0) & 0xFF);												ctsDataBytes[2] = 0x01;
										ctsDataBytes[3] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSTotBytes >> 8) & 0xFF);
										ctsDataBytes[4] = 0xFF;
										ctsDataBytes[5] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 0) & 0xFF);
										ctsDataBytes[6] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 8) & 0xFF);
										ctsDataBytes[7] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 16) & 0xFF);

										//Compute J1939 Header
										unsigned long ulEndofAckMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

										J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
										enJ2534Error = pOemTool->SendJ1939SingleMessage(ulEndofAckMsgId, ctsDataBytes, 8, 0x100, (unsigned char)stPassRxThruMsg.ulProtocolID);
										if (enJ2534Error != J2534_STATUS_NOERROR)
										{
											TRACE("CTS not Transmitted\n");
											continue;
										}
									}
									else
									{
										stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS++;

										//Checking for Maximum no. of packets received for one CTS or not
										if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS ==
											stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS)
										{
											//Reset Packet Cnt received
											stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPacketCntForCTS = 0;

											//Send CTS for the received frame
											PASSTHRU_MSG passThruMsgCTS;
											unsigned char ctsDataBytes[8];


											ctsDataBytes[0] = 0x11;
											//Set to Min of Max Packets & Max CTS Packets can receive
											if (stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS > stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts)
											{
												ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
											}
											else
											{
												ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSMaxPacketsForCTS;
											}
											//ctsDataBytes[1] = stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPkts;
											ctsDataBytes[2] = uchPacketNo + 1;
											ctsDataBytes[3] = 0xFF;
											ctsDataBytes[4] = 0xFF;
											ctsDataBytes[5] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 0) & 0xFF);
											ctsDataBytes[6] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 8) & 0xFF);
											ctsDataBytes[7] = (unsigned char)((stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSPGN >> 16) & 0xFF);

											//Compute J1939 Header
											unsigned long ulMsgId = pOemTool->ComputeJ1939Header(uchPriority, 0xEC00, uchDest, uchSrc);

											J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
											enJ2534Error = pOemTool->SendJ1939SingleMessage(ulMsgId, ctsDataBytes, 8, 0x100, (unsigned char)stPassRxThruMsg.ulProtocolID);
											if (enJ2534Error != J2534_STATUS_NOERROR)
											{
												TRACE("CTS not Transmitted\n");
												continue;
											}

										}
									}

									//Upate Next Packet
									stSaveRxMultipleSegmData[nJ1939MsgIdx].nCTSRTSNextPkt++;

								}
								else
								{
									//Error in receiving the frames
									stSaveRxMultipleSegmData[nJ1939MsgIdx].stSaveMultSegmPassRxThruMsg.ulProtocolID = 0;
								}

							}
						}
						break;

						case 0xEE:
						{
							//Copying  Data Bytes
							stPassRxThruMsg.ucData[0] = pOemTool->InputReport[nCANDataIdx];

							stPassRxThruMsg.ulDataSize = 1;
							stPassRxThruMsg.ulExtraDataIndex = 0;
							stPassRxThruMsg.ulRxStatus = ulRxFlags;

							//Send Address Claim or Lost Indication to J2534 Layer
							if (OnJ1939RxMsgSetstatusfnCallBack != NULL)
							{
								OnJ1939RxMsgSetstatusfnCallBack(&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);
							}

						}
						break;

						default:
						{
							//Normal Message
							//Check for loopback or normal message or Ack
							TRACE("Single Frame Received\n");

							//Copying Header
							memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[nIdx + 7], ucCANIDSize);

							//Copying Src Address
							stPassRxThruMsg.ucData[ucCANIDSize] = uchDest;

							//Copying  Data Bytes
							memcpy((char*)&stPassRxThruMsg.ucData[ucCANIDSize + 1], &pOemTool->InputReport[nIdx + 7 + ucCANIDSize], nDataCount - ucCANIDSize);

							stPassRxThruMsg.ulDataSize = nDataCount + 1;
							stPassRxThruMsg.ulExtraDataIndex = 0;
							stPassRxThruMsg.ulRxStatus = ulRxFlags;
							/* Send the Start of message indication */
							if (RxfunCallBack[stPassRxThruMsg.ulProtocolID] != NULL)
								RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

							//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
							//memset(&pOemTool->InputReport,0,INPUTREPORTMAX);

						}
						}


						//Checking whether PCI is Multi Frame or not
						if (ucPCItype == 0x10)
						{
							//In Multi Frame, we are reading one more frame and updating the parsing info frame
							//so no necessitity of parising other frames, it already corrupted

							break;
						}

						//Update index for pointing next frame
						nIdx = nIdx + nDataCount + 6 + 1; //DataCount + 6 Bytes ( 2Bytes Rx Flax + 4 Bytes TimeStamp) + lenth field					
					}
				}

				//Reset shall be done at the end of parsing of all the messages in the Multi Mode Packet
				memset(&pOemTool->InputReport, 0, INPUTREPORTMAX);
			}
			break;
			case J1850VPW:
			case CCD:
			{
				if (pOemTool->InputReport[1] == ISO9141)
					stPassRxThruMsg.ulProtocolID = ISO9141;
				if (pOemTool->InputReport[1] == SCI_A_ENGINE)
					stPassRxThruMsg.ulProtocolID = SCI_A_ENGINE;
				if (pOemTool->InputReport[1] == SCI_A_TRANS)
					stPassRxThruMsg.ulProtocolID = SCI_A_TRANS;
				if (pOemTool->InputReport[1] == SCI_B_ENGINE)
					stPassRxThruMsg.ulProtocolID = SCI_B_ENGINE;
				if (pOemTool->InputReport[1] == SCI_B_TRANS)
					stPassRxThruMsg.ulProtocolID = SCI_B_TRANS;
				if (pOemTool->InputReport[1] == CCD)
					stPassRxThruMsg.ulProtocolID = CCD;
				nDataCount = (short)pOemTool->InputReport[4] << 8;
				nDataCount = nDataCount | (short)pOemTool->InputReport[5];

				/*Collect Rx Flags from the receive queue*/
				ulRxFlags = ntohl(ulong(pOemTool->InputReport[6]));

				/*Get the timestamp from the device*/
				stPassRxThruMsg.ulTimeStamp = ntohl(ulong(pOemTool->InputReport[10]));

				if (ulRxFlags & START_OF_MESSAGE)
				{
					stPassRxThruMsg.ulRxStatus |= 0x02;//Start of Message Indication
				}
				else if (ulRxFlags & RX_BREAK) // For VPWM Protocol Only
				{
					stPassRxThruMsg.ulRxStatus |= 0x04;//Brake Received
				}
				else
				{
					stPassRxThruMsg.ulRxStatus |= 0x00;//Normal Message received
				}
				/*Process the incomming report data*/
				/* if data length is <51, data sahll be READ AS single USB frame*/
				if ((nDataCount != 0) && (nDataCount <= 50))
				{
					memcpy((char*)&stPassRxThruMsg.ucData, &pOemTool->InputReport[14],
						nDataCount);
				}
				/*Read specific bytes from USB device.If the data length exceeds 64,
				the data array will be Reading into several arrays with each
				containing 64 bytes.The 0-63 byte of the array is read first,then
				the 64-127 byte and so on.*/
				else
				{
					int nIndex = 0;
					do
					{
						if (FALSE == bFirstFrameIndication)
						{
							bFirstFrameIndication = TRUE;
							nDataOffset = 14;
							if (nDataCount > (INPUTREPORTMAX - nDataOffset))
								nBytesRead = 50;
							else
								nBytesRead = nDataCount;
						}
						else
						{
							nDataOffset = 3;
							if (nDataCount > (INPUTREPORTMAX - nDataOffset))
								nBytesRead = 61;
							else
								nBytesRead = nDataCount;
						}
						memcpy((char*)&stPassRxThruMsg.ucData[nIndex],
							&pOemTool->InputReport[nDataOffset], nBytesRead);
						nDataCount = nDataCount - nBytesRead;
						nIndex = nIndex + nBytesRead;
						pOemTool->ReadInputReport();
					} while (nDataCount != 0);
				}
				RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg,
					gpVoid[stPassRxThruMsg.ulProtocolID]);
			}
			break;
/*			case DOIP_PROTOCOL_ID:
			//	unsigned short len ;
				stSetRxstatusPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
				stSetRxstatusPassRxThruMsg.ulRxStatus = ulRxFlags;
				stSetRxstatusPassRxThruMsg.ulDataSize = Inputbuffer->u.DOIP_rcv_msg.Curlen;//nDataCount;
				stSetRxstatusPassRxThruMsg.ulExtraDataIndex = stSetRxstatusPassRxThruMsg.ulDataSize;
				stSetRxstatusPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;
				
				if (Inputbuffer->u.DOIP_rcv_msg.status == J2534_STATUS_NOERROR)
				{
						if (Inputbuffer->u.DOIP_rcv_msg.LastPkt)
						{
							memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0],
								&Inputbuffer->u.DOIP_rcv_msg.data[0], stSetRxstatusPassRxThruMsg.ulDataSize);

							RxfunCallBack[stSetRxstatusPassRxThruMsg.ulProtocolID](&stSetRxstatusPassRxThruMsg,
								gpVoid[stSetRxstatusPassRxThruMsg.ulProtocolID]);
						}
						else
						{
							unsigned long len;
							unsigned short seqnum;

							if (Inputbuffer->u.DOIP_rcv_msg.SeqNum == 1)
							{
								
								memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[0],
									&Inputbuffer->u.DOIP_rcv_msg.data[0], stSetRxstatusPassRxThruMsg.ulDataSize);
								len = sizeof(Inputbuffer->Reserved) + sizeof(Inputbuffer->proto_id) + sizeof(Inputbuffer->command);
								len += sizeof(Inputbuffer->u.DOIP_rcv_msg.Curlen);
								seqnum = 0;
							}
							else
							{
								if ((seqnum + 1) != Inputbuffer->u.DOIP_rcv_msg.SeqNum)
								{
									len = 0;
									seqnum = 0;
									return -1;
								}
								if ((len + Inputbuffer->u.DOIP_rcv_msg.Curlen) > PASSTHRU_MSG_DATA_SIZE)
								{
									Inputbuffer->u.DOIP_rcv_msg.Curlen = PASSTHRU_MSG_DATA_SIZE - len;
								}
								memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[len], &Inputbuffer->u.DOIP_rcv_msg.data[0], stSetRxstatusPassRxThruMsg.ulDataSize);
							}
							len  = 0;
						}
				}
				break;*/
			case DOIP_PROTOCOL_ID:
				static unsigned long length;
				stSetRxstatusPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
				stSetRxstatusPassRxThruMsg.ulRxStatus = ulRxFlags;
				stSetRxstatusPassRxThruMsg.ulDataSize = Inputbuffer->u.DOIP_rcv_msg.Curlen;  // nDataCount;
				stSetRxstatusPassRxThruMsg.ulExtraDataIndex = stSetRxstatusPassRxThruMsg.ulDataSize;
				stSetRxstatusPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp;

				if (Inputbuffer->u.DOIP_rcv_msg.status == J2534_STATUS_NOERROR)
				{
					// Handle the first fragment (if this is the first packet or a new message)
					if (Inputbuffer->u.DOIP_rcv_msg.SeqNum == 1)
					{
						length = stSetRxstatusPassRxThruMsg.ulDataSize;
						totalDataLength = 0;  // Reset the total length for a new message
						expectedSeqNum = 1;   // Reset the expected sequence number
					}

					// Check if this is the last packet
					if (Inputbuffer->u.DOIP_rcv_msg.LastPkt)
					{
						if (Inputbuffer->u.DOIP_rcv_msg.SeqNum != 1) {
							length += stSetRxstatusPassRxThruMsg.ulDataSize;
							stSetRxstatusPassRxThruMsg.ulDataSize = length;
						}
						// If it's the last packet, append the data and process it
						memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[totalDataLength],
							&Inputbuffer->u.DOIP_rcv_msg.data[0],
							stSetRxstatusPassRxThruMsg.ulDataSize);
						totalDataLength += stSetRxstatusPassRxThruMsg.ulDataSize;  // Update total data length

						// Process the full data (the complete message)
						RxfunCallBack[stSetRxstatusPassRxThruMsg.ulProtocolID](&stSetRxstatusPassRxThruMsg,
							gpVoid[stSetRxstatusPassRxThruMsg.ulProtocolID]);
						memset(Inputbuffer, 0, sizeof(Inputbuffer));
				/*		if ((totalDataLength + stSetRxstatusPassRxThruMsg.ulDataSize) <= MAX_DATA_SIZE)
						{
							memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[totalDataLength],
								&Inputbuffer->u.DOIP_rcv_msg.data[0],
								stSetRxstatusPassRxThruMsg.ulDataSize);
							totalDataLength += stSetRxstatusPassRxThruMsg.ulDataSize;  // Update total data length
							// Process the full data (the complete message)
							RxfunCallBack[stSetRxstatusPassRxThruMsg.ulProtocolID](&stSetRxstatusPassRxThruMsg,
								gpVoid[stSetRxstatusPassRxThruMsg.ulProtocolID]);
						}working one */
					}
					else
					{
						// If it's not the last packet, just append the data and wait for more fragments
						if ((totalDataLength + stSetRxstatusPassRxThruMsg.ulDataSize) <= MAX_DATA_SIZE)
						{
							memcpy((char*)&stSetRxstatusPassRxThruMsg.ucData[totalDataLength],
								&Inputbuffer->u.DOIP_rcv_msg.data[0],
								stSetRxstatusPassRxThruMsg.ulDataSize);
							totalDataLength += stSetRxstatusPassRxThruMsg.ulDataSize;  // Update total data length
							// Process the full data (the complete message)
						/*	RxfunCallBack[stSetRxstatusPassRxThruMsg.ulProtocolID](&stSetRxstatusPassRxThruMsg,
								gpVoid[stSetRxstatusPassRxThruMsg.ulProtocolID]);*/
						}
						else
						{
							// Error: Data exceeds max buffer size
							return -1;
						}
					}
				}
				break;

			default:
				break;
			}
		}
		//else if (pOemTool->InputReport[2] == ECU_ISO15765PERIODIC_MSG_IND)
		else if (Inputbuffer->command == ECU_ISO15765PERIODIC_MSG_IND)
		{
		//	if (pOemTool->InputReport[1] == ISO15765 || pOemTool->InputReport[1] == ISO15765_CH1)
		    if (Inputbuffer->proto_id == ISO15765 || Inputbuffer->proto_id == ISO15765_CH1)
			{

				//stPassRxThruMsg.ulProtocolID = pOemTool->InputReport[1];
				stPassRxThruMsg.ulProtocolID = Inputbuffer->proto_id;
				/* Ravi : RxStatus bit defination has the Extended Address flag. */
				nDataCount = (short)(pOemTool->InputReport[5]);
				nDataCount = nDataCount | (short)(pOemTool->InputReport[6] << 8);
				stPassRxThruMsg.ulDataSize = nDataCount;

				/*Get the timestamp from the device*/
				stPassRxThruMsg.ulTimeStamp = (unsigned long)pOemTool->InputReport[11];
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[12] << 8;
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[13] << 16;
				stPassRxThruMsg.ulTimeStamp = stPassRxThruMsg.ulTimeStamp | (unsigned long)pOemTool->InputReport[14] << 24;

				memcpy((char*)&stPassRxThruMsg.ucData[0], &pOemTool->InputReport[15], stPassRxThruMsg.ulDataSize);
				/*Tx Done indication bit is 3rd bit so Rxstatus should be 0x08*/
				stPassRxThruMsg.ulRxStatus = 0x00000009;

				//pstPassThruMsg->ulExtraDataIndex=0x00;
				RxfunCallBack[stPassRxThruMsg.ulProtocolID](&stPassRxThruMsg, gpVoid[stPassRxThruMsg.ulProtocolID]);

				TRACE("Tx Done TimeStamp = %ul\n", stPassRxThruMsg.ulTimeStamp);
			}

		}
		else
		{
			/* If Received data is not zero then check for Command ack */
			//if (pOemTool->InputReport[1] != 0)
			if (Inputbuffer->proto_id != 0)
			{

				TRACE("Got a command ack \n");

				TRACE("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
					pOemTool->InputReport[1], pOemTool->InputReport[2],
					pOemTool->InputReport[3], pOemTool->InputReport[4],
					pOemTool->InputReport[5], pOemTool->InputReport[6],
					pOemTool->InputReport[15], pOemTool->InputReport[16],
					pOemTool->InputReport[17], pOemTool->InputReport[18],
					pOemTool->InputReport[19], pOemTool->InputReport[20],
					pOemTool->InputReport[21], pOemTool->InputReport[22]);



				/* Copy the command ack data to the buffer */
				for (i = INPUTREPORTMAX; i >= 0; i--)
				{
					bufCmdAck[i] = pOemTool->InputReport[i];
				}
				TRACE("Event successful for command ack \n");
			//	if (pOemTool->InputReport[2] == ECU_SENDMESSAGE_ACK)
				if (Inputbuffer->command == ECU_SENDMESSAGE_ACK)
				{
					for (int nIndex = 8; nIndex > 4; nIndex--)
					{
						ulTimestamp = ulTimestamp << 0x08;
						ulTimestamp += pOemTool->InputReport[nIndex];
					}
					TRACE("Calculating Timestamp for the message = %ul \n", ulTimestamp);

					if (g_pstPassThruMsg != NULL)
					{

						TRACE("g_pstPassThruMsg is not NULL\n");

						//if (bufCmdAck[3] == J2534_STATUS_NOERROR)
						if(Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
						{

							TRACE("Wrtie Success\n");
							g_pstPassThruMsg->ulTimeStamp = ulTimestamp;

							//TX Done for Only ISO15765
					//		if ((pOemTool->InputReport[1] == ISO15765) || (pOemTool->InputReport[1] == ISO15765_CH1) || (pOemTool->InputReport[1] == FD_ISO15765_PS))
							if ((Inputbuffer->proto_id == ISO15765) || (Inputbuffer->proto_id == ISO15765_CH1) || (Inputbuffer->proto_id == FD_ISO15765_PS))
							{   

								if (ulIS015765_USB_Packets != 0)
								{
									ulIS015765_USB_Packets--;

									//Send TX Done after getting Ack for all USB frames..
									if (ulIS015765_USB_Packets == 0)
									{

										/*Tx Done indication bit is 3rd bit so Rxstatus should be 0x08*/
										g_pstPassThruMsg->ulRxStatus = 0x00000009;

										//jayasheela-checking CAN_ID type
										if (g_pstPassThruMsg->ulTxFlags & CAN_29BIT_ID)
										{
											g_pstPassThruMsg->ulRxStatus = g_pstPassThruMsg->ulRxStatus | 0x00000100;
											g_pstPassThruMsg->ucData[0] = g_pstPassThruMsg->ucData[0] & 0x3F;
										}
										else
										{
											g_pstPassThruMsg->ucData[0] = g_pstPassThruMsg->ucData[0] & 0x00;
											g_pstPassThruMsg->ucData[1] = g_pstPassThruMsg->ucData[1] & 0x00;
											g_pstPassThruMsg->ucData[2] = g_pstPassThruMsg->ucData[2] & 0x0F;
										}			/*Checking for ISO15765_TX_DONE and LOOPBACK Message*/


										//pstPassThruMsg->ulExtraDataIndex=0x00;
										RxfunCallBack[g_pstPassThruMsg->ulProtocolID](g_pstPassThruMsg, gpVoid[g_pstPassThruMsg->ulProtocolID]);

										TRACE("Tx Done TimeStamp = %ul\n", g_pstPassThruMsg->ulTimeStamp);



										if (TRUE == pOemTool->m_bLoopBack)
										{

											g_pstPassThruMsg->ulRxStatus = (g_pstPassThruMsg->ulRxStatus & 0x00000100) | 0x00000001;

											//Jayasheela -removed pad and EXT addr checking 
											/*if(!(pstPassThruMsg->ulTxFlags & ISO15765_FRAME_PAD))
											pstPassThruMsg->ulRxStatus = pstPassThruMsg->ulRxStatus|0x10;

											  if(pstPassThruMsg->ulTxFlags & ISO15765_ADDR_TYPE )
											pstPassThruMsg->ulRxStatus = pstPassThruMsg->ulRxStatus|0x80;*/

											g_pstPassThruMsg->ulExtraDataIndex = g_pstPassThruMsg->ulDataSize;

											RxfunCallBack[g_pstPassThruMsg->ulProtocolID](g_pstPassThruMsg, gpVoid[g_pstPassThruMsg->ulProtocolID]);
										}

										SetEvent(pOemTool->m_CmdAck);
										g_pstPassThruMsg = NULL;
									}
								}
							}
						/*	else if ((pOemTool->InputReport[1] == J1939_PS) || (pOemTool->InputReport[1] == J1939_CH1)
								|| (pOemTool->InputReport[1] == J1939_CH2))*/
							else if ((Inputbuffer->proto_id == J1939_PS) || (Inputbuffer->proto_id == J1939_CH1)
								|| (Inputbuffer->proto_id == J1939_CH2))
							{

								if (ulJ1939_USB_Packets != 0)
								{
									ulJ1939_USB_Packets--;

									//Send TX Done after getting Ack for all USB frames..
									if (ulJ1939_USB_Packets == 0)
									{
										//Below code is commented, since J1939 doesn't support TxDone / First Frame Indication
										/////////////////////////////////////////////////////////////////////////////////////////////

										//Tx Done indication bit is 3rd bit so Rxstatus should be 0x08
										//g_pstPassThruMsg->ulRxStatus = 0x00000009;
										//g_pstPassThruMsg->ulRxStatus = g_pstPassThruMsg->ulRxStatus | 0x00000100;										


										//pstPassThruMsg->ulExtraDataIndex=0x00;
										 RxfunCallBack[g_pstPassThruMsg->ulProtocolID](g_pstPassThruMsg, gpVoid[g_pstPassThruMsg->ulProtocolID]);

										//TRACE("Tx Done TimeStamp = %ul\n",g_pstPassThruMsg->ulTimeStamp);	


										//To support the loopback
										if (TRUE == pOemTool->m_bLoopBack)
										{
											g_pstPassThruMsg->ulRxStatus = (g_pstPassThruMsg->ulRxStatus & 0x00000100) | 0x00000001;
											g_pstPassThruMsg->ulExtraDataIndex = g_pstPassThruMsg->ulDataSize;

											RxfunCallBack[g_pstPassThruMsg->ulProtocolID](g_pstPassThruMsg, gpVoid[g_pstPassThruMsg->ulProtocolID]);
										}

										//SetEvent(pOemTool->m_CmdAck);
										//g_pstPassThruMsg=NULL;
									}
								}
							}
							else
							{
								SetEvent(pOemTool->m_CmdAck);
								g_pstPassThruMsg = NULL;
							}
						}
						else
						{
							SetEvent(pOemTool->m_CmdAck);
							g_pstPassThruMsg = NULL;
						}
					}
				}
				else
				{
					SetEvent(pOemTool->m_CmdAck);
				}
			}
			else
			{
				//TRACE("FAIL:ReadInput Report \n");
			}
		}

		if (pOemTool->m_bThreadQuit)
		{
			break;
		}
	}
	//	for (msg_index = 0; msg_index < 10; msg_index++)
	{
		delete[] stSaveRxMultipleSegmData;

	}
	return 0;
}



#ifdef GARUDA_BULK

usb_dev_handle* open_dev(void);

usb_dev_handle* open_dev(void)
{
	struct usb_bus* bus;
	struct usb_device* dev;

	for (bus = usb_get_busses(); bus; bus = bus->next)
	{
		for (dev = bus->devices; dev; dev = dev->next)
		{
			if (dev->descriptor.idVendor == VID
				&& dev->descriptor.idProduct == PID)
			{
				return usb_open(dev);
			}
		}
	}
	return NULL;
}

#endif
/******************************************************************************
   Function Name    : vOpenDevice()
   Input Params :
   Output Params    :
   Return           :
   Description      :
******************************************************************************/
J2534ERROR CDeviceOEMTool::vOpenDevice()
{
/*	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	int nProtIndex;
	// Write to Log File.
	if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
	{
		sprintf(szBuffer, "Start");
		m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
			DEBUGLOG_TYPE_COMMENT, szBuffer);
	}



	/*If device already opened, return J2534_ERR_DEVICE_IN_USE.*/
/*#ifdef GARUDA_HID
	if (HidDevHandle)
		return J2534_ERR_DEVICE_IN_USE;
#endif

#ifdef GARUDA_BULK
	if (dev)
		return J2534_ERR_DEVICE_IN_USE;
#endif

#ifdef GARUDA_HID
	/*Initialize the Innova USB Hardware using the below Function
	HidDevHandle is going to fill with USB device handle and
	Vendor ID and Product ID which has to get from PassThruOpen()*/
/*	m_ulLastErrorCode = InitUSBDevice();
	if (m_ulLastErrorCode == J2534_STATUS_NOERROR)
	{
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "returned 0x%02X", J2534_STATUS_NOERROR);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		/*Initialize Channel list*/
/*		for (nProtIndex = 0; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
		{
			m_enChannelList[nProtIndex] = (J2534_PROTOCOL)0;
		}
	}
	else
	{
		// Write to Log File.
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "OpenDeviceFail returned 0x%02X", m_ulLastErrorCode);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}
#endif

#ifdef GARUDA_BULK

//	usb_init(); /* initialize the library */
//	usb_find_busses(); /* find all busses */
//	usb_find_devices(); /* find all connected devices */


/*	if (!(dev = open_dev()))
	{
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	if (usb_set_configuration(dev, 1) < 0)
	{
		usb_close(dev);
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	if (usb_claim_interface(dev, 0) < 0)
	{
		usb_close(dev);
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	HidAttached = TRUE;

	/*Initialize Channel list*/
/*	for (nProtIndex = 0; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
	{
		m_enChannelList[nProtIndex] = (J2534_PROTOCOL)0;
	}

#endif

	return J2534_STATUS_NOERROR;*/

	
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	int nProtIndex;
	// Write to Log File.
	if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
	{
		sprintf(szBuffer, "Start");
		m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
			DEBUGLOG_TYPE_COMMENT, szBuffer);
	}
/*	unsigned char uchDataBuffer[] = "1";
	SaveBufferToHexTxt(uchDataBuffer, sizeof(uchDataBuffer), "uchDataBuffer_dump.txt");*/
    isHidDevice = bOpenHidDevice(); //bOpenHidDevice() ? 1 : 0;

// Define macros based on the result of the check
	if (isHidDevice)
	{
#ifdef GARUDA_HID
		HidDevHandle = NULL;
		if (HidDevHandle)
			return J2534_ERR_DEVICE_IN_USE;

#endif
	}
	else
	{
#ifdef GARUDA_TCP
		HidDevHandle = NULL;
		if (HidDevHandle)
			return J2534_ERR_DEVICE_IN_USE;
#endif
	}


	/*If device already opened, return J2534_ERR_DEVICE_IN_USE.*/
#ifdef GARUDA_HID
	if (HidDevHandle)
		return J2534_ERR_DEVICE_IN_USE;
#endif

#ifdef GARUDA_TCP
	if (HidDevHandle)
		return J2534_ERR_DEVICE_IN_USE;
#endif

#ifdef GARUDA_BULK
	if (dev)
		return J2534_ERR_DEVICE_IN_USE;
#endif

	/*Initialize the Innova USB Hardware using the below Function
	HidDevHandle is going to fill with USB device handle and
	Vendor ID and Product ID which has to get from PassThruOpen()*/
	m_ulLastErrorCode = InitUSBDevice();
	if (m_ulLastErrorCode == J2534_STATUS_NOERROR)
	{
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "returned 0x%02X", J2534_STATUS_NOERROR);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		/*Initialize Channel list*/
		for (nProtIndex = 0; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
		{
			m_enChannelList[nProtIndex] = (J2534_PROTOCOL)0;
		}
	}
	else
	{
		// Write to Log File.
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "OpenDeviceFail returned 0x%02X", m_ulLastErrorCode);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vOpenDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

#ifdef GARUDA_BULK

	usb_init(); /* initialize the library */
	usb_find_busses(); /* find all busses */
	usb_find_devices(); /* find all connected devices */


	if (!(dev = open_dev()))
	{
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	if (usb_set_configuration(dev, 1) < 0)
	{
		usb_close(dev);
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	if (usb_claim_interface(dev, 0) < 0)
	{
		usb_close(dev);
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

	HidAttached = TRUE;

	/*Initialize Channel list*/
	for (nProtIndex = 0; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
	{
		m_enChannelList[nProtIndex] = (J2534_PROTOCOL)0;
	}

#endif

	return J2534_STATUS_NOERROR;
}
/******************************************************************************
   Function Name    : vCloseDevice()
   Input Params :
   Output Params    :
   Return           :
   Description      :
******************************************************************************/
J2534ERROR CDeviceOEMTool::vCloseDevice()
{
/*	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	// Write to Log File.
	if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
	{
		sprintf(szBuffer, "Start");
		m_pclsLog->Write("DeviceOEMTool.cpp", "vCloseDevice()",
			DEBUGLOG_TYPE_COMMENT, szBuffer);
	}

#ifdef GARUDA_HID
	//Check if the device is open
	if (HidDevHandle)
	{
		m_ulLastErrorCode = CloseUSBDevice();
		// Write to Log File.
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "vCloseDevice returned 0x%02X", m_ulLastErrorCode);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vCloseDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		HidDevHandle = NULL;
		HidAttached = FALSE;
		//Kill The Thread
		if (hCallBckThread)
		{
			TerminateThread(hCallBckThread, 0);
			hCallBckThread = NULL;
			m_bThreadQuit = TRUE;
		}
	}
#endif

#ifdef GARUDA_BULK

	if (dev)
	{
		usb_release_interface(dev, 0);
		usb_close(dev);
		dev = NULL;
		//HidAttached  = FALSE;
		//Kill The Thread
		if (hCallBckThread)
		{
			TerminateThread(hCallBckThread, 0);
			hCallBckThread = NULL;
			m_bThreadQuit = TRUE;
		}
	}

#endif

#ifdef MULTI_MODE_DEBUGGING
	//Debugging Purpose
	ulMsgCounter = 0;

	for (int nIdx = 0; nIdx < 10; nIdx++)
	{
		ulMaxPacking[nIdx++] = 0;
	}
#endif

	return J2534_STATUS_NOERROR;*/

	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	// Write to Log File.
	if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
	{
		sprintf(szBuffer, "Start");
		m_pclsLog->Write("DeviceOEMTool.cpp", "vCloseDevice()",
			DEBUGLOG_TYPE_COMMENT, szBuffer);
	}

	/*Check if the device is open.*/
	if (HidDevHandle)
	{
		m_ulLastErrorCode = CloseUSBDevice();
		// Write to Log File.
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "vCloseDevice returned 0x%02X", m_ulLastErrorCode);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vCloseDevice()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		HidDevHandle = NULL;
		HidAttached = FALSE;
		//Kill The Thread
		if (hCallBckThread)
		{
			TerminateThread(hCallBckThread, 0);
			hCallBckThread = NULL;
			m_bThreadQuit = TRUE;
		}
	}

#ifdef GARUDA_BULK

	if (dev)
	{
		usb_release_interface(dev, 0);
		usb_close(dev);
		dev = NULL;
		//HidAttached  = FALSE;
		//Kill The Thread
		if (hCallBckThread)
		{
			TerminateThread(hCallBckThread, 0);
			hCallBckThread = NULL;
			m_bThreadQuit = TRUE;
		}
	}

#endif
	return J2534_STATUS_NOERROR;
}
/******************************************************************************
   Function Name    : vConnectProtocol()
   Input Params     :
   Output Params    :
   Return           :
   Description      :
******************************************************************************/

J2534ERROR CDeviceOEMTool::vConnectProtocol(
	J2534_PROTOCOL  enProtocolID,
	unsigned long   ulFlags,
	unsigned long   ulBaudRate,
	DEVICEBASE_CALLBACK_RX_FUNC pfnCallback,
	DEVICEBASE_CALLBACK_FC_FUNC pfirstframefnCallback,
	DEVICEBASE_CALLBACK_ISO15765_SETRXSTATUS_FUNC psetRxstatusfnCallback,
	LPVOID          pVoid,
	unsigned long* pulChannelID)
{
	DWORD dwID = 0;
	int nProtIndex;
	/*Jayasheela-added to handle protocol id*/
	//unsigned char pulProtocolID;
	/*jayasheela-added m_bThreadQuit = FALSE;*/
	m_bThreadQuit = FALSE;
	/*Check if thread is already running*/
	//Kill The Thread
	if (hCallBckThread == NULL)
	{
		hCallBckThread = ::CreateThread(NULL, 0, &CallBackFun, this, 0, &dwID);
		//TerminateThread(hCallBckThread,0);
		//hCallBckThread = NULL;
	}

	TRACE("Connect Protocol \n");

	//hCallBckThread = ::CreateThread (NULL, 0, &CallBackFun, this, 0, &dwID);

	m_CmdAck = CreateEvent(NULL, TRUE, FALSE, NULL);

	/* The following event handles may need to be GC'd */
	m_5BaudInit = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_FastInit = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_FlowControlEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	/*Jayasheela-added to get protocol ID*/
	//GetProtocolID(enProtocolID,&pulProtocolID);
	m_ulLastErrorCode = EnableCommuncation(ulFlags, ulBaudRate, (J2534_PROTOCOL)enProtocolID);

	if (m_ulLastErrorCode == J2534_STATUS_NOERROR)
	{
		for (nProtIndex = 1; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
		{
			if (m_enChannelList[nProtIndex] == 0)
			{
				m_enChannelList[nProtIndex] = (J2534_PROTOCOL)enProtocolID;
				*pulChannelID = nProtIndex;
				m_nChannelID = *pulChannelID;
				break;
			}
		}
		//Store callback function pointer
		RxfunCallBack[enProtocolID] = pfnCallback;
		gpVoid[enProtocolID] = pVoid;
		if ((enProtocolID == ISO15765_CH1) || (enProtocolID == ISO15765) || (enProtocolID == FD_ISO15765_PS))
		{
			/*Jayasheela-store First frame callback function */
			OnFirstFramefunCallBack = pfirstframefnCallback;
			gpFFVoid = pVoid;

			//RxStatus Functional Callback from protocol
			OnISO15765RxMsgSetstatusfnCallBack = psetRxstatusfnCallback;

			//Protocol Object
			gpUpdateRxstatusVoid = pVoid;
		}
		else if ((enProtocolID == J1939_PS) || (enProtocolID == J1939_CH1) || (enProtocolID == J1939_CH2))
		{
			OnJ1939RxMsgSetstatusfnCallBack = psetRxstatusfnCallback;
		}
	}

	TRACE("Protocol Connect flags %ld\n", ulFlags);

	return m_ulLastErrorCode;
}

/******************************************************************************
   Function Name    : vDisconnectProtocol()
   Input Params     :
   Output Params    :
   Return           :
   Description      :
******************************************************************************/
J2534ERROR CDeviceOEMTool::vDisconnectProtocol(unsigned long ulChannelID)
{
	int nProtIndex;
	m_ulLastErrorCode = DisableCommuncation(ulChannelID);//nikhileshtest_removed
	//	m_ulLastErrorCode = J2534_STATUS_NOERROR;//nikhileshtest_added
	if (m_ulLastErrorCode == J2534_STATUS_NOERROR)
	{

		/* Jayasheela-Initialize Channel list*/
		m_enChannelList[ulChannelID] = (J2534_PROTOCOL)0;
		for (nProtIndex = 1; nProtIndex < MAX_PROTOCOL_NUM; nProtIndex++)
		{
			if (m_enChannelList[nProtIndex] != 0)
				break;
		}
		if (nProtIndex >= MAX_PROTOCOL_NUM)
		{
			m_bThreadQuit = TRUE;
			Sleep(10);
			TerminateThread(hCallBckThread, 0);
			hCallBckThread = NULL;
			m_nChannelID = 0;
			/*jayasheela-added to handle the exception*/
			CloseHandle(m_CmdAck);
			m_CmdAck = NULL;
		}
	}
	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vWriteMsgs(unsigned long    ulChannelID,
	PASSTHRU_MSG* pstPassThruMsg,
	unsigned long* pulNumMsgs)
{
	int nBytesToWrite = 0;
	DWORD           dwWaitStatus;
	unsigned short usDataCount = 0;
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	BufferCommand_t WriteMsgs;
	InputBuffer_t* Inputbuffer;
	switch (m_enChannelList[ulChannelID])
	{
	case J1850PWM:

		if (m_enChannelList[ulChannelID] == J1850PWM)
			usDataCount = (unsigned short)pstPassThruMsg->ulDataSize - 3;

		if (m_enChannelList[ulChannelID] == CAN || m_enChannelList[ulChannelID] == SW_CAN_PS || m_enChannelList[ulChannelID] == CAN_CH1 || m_enChannelList[ulChannelID] == FD_CAN_PS)
			usDataCount = (unsigned short)pstPassThruMsg->ulDataSize - 4;

		uchDataBuffer[0] = m_enChannelList[ulChannelID];
		uchDataBuffer[1] = ECU_SENDMESSAGE;
		uchDataBuffer[2] = (unsigned char)((usDataCount >> 8) & 0xFF);
		uchDataBuffer[3] = (unsigned char)((usDataCount) & 0xFF);
		uchDataBuffer[4] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);
		uchDataBuffer[5] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 16 & 0x000000FF);
		uchDataBuffer[6] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 8 & 0x000000FF);
		uchDataBuffer[7] = (unsigned char)(pstPassThruMsg->ulTxFlags & 0x000000FF);
		/*Copy the data to the main buffer*/
		memcpy(&uchDataBuffer[8], pstPassThruMsg->ucData, pstPassThruMsg->ulDataSize);
		/*Send message to the device*/
		m_ulLastErrorCode = SendSingleFrameECUMessage(uchDataBuffer, pstPassThruMsg, 8, ulChannelID);
		break;
	case J1850VPW:
	case CCD:
		m_ulLastErrorCode = SendMultipleFrameECUMessages(pstPassThruMsg, ulChannelID);
		break;
	case ISO15765:
	case SW_ISO15765_PS:
	case FD_ISO15765_PS:
	case ISO15765_CH1:
	{
		/*Emptying the txlist*/
		EmptyTxList(m_TxList);

		// decompose ISO-15765 into multiple CAN frames
		if ((pstPassThruMsg->ulProtocolID == ISO15765) || (pstPassThruMsg->ulProtocolID == SW_ISO15765_PS) || (pstPassThruMsg->ulProtocolID == ISO15765_CH1))
		{
			m_ulLastErrorCode = DecomposeISO15765Message(pstPassThruMsg->ucData,
				(short)pstPassThruMsg->ulDataSize,
				pstPassThruMsg->ulTxFlags);
		}
		else
		{
			m_ulLastErrorCode = DecomposeFDISO15765Message(pstPassThruMsg->ucData,
				(short)pstPassThruMsg->ulDataSize,
				pstPassThruMsg->ulTxFlags);
		}
		ResetEvent(m_CmdAck);
		g_pstPassThruMsg = pstPassThruMsg;

		/*if(pstPassThruMsg->ulDataSize>7)
		{
			ulIS015765_USB_Packets=(pstPassThruMsg->ulDataSize-6)/49; //49 data bytes per USB packet excluding PCI bytes..
			ulIS015765_USB_Packets++;
		}
		else
		{
			ulIS015765_USB_Packets=(pstPassThruMsg->ulDataSize)/49; //49 data bytes per USB packet excluding PCI bytes..

		}

		if((pstPassThruMsg->ulDataSize%56)!=0)
		{
			ulIS015765_USB_Packets++;
		}		*/

		if (m_ulLastErrorCode == J2534_STATUS_NOERROR)
			m_ulLastErrorCode = SendISO15765Messages((unsigned long)m_enChannelList[ulChannelID]);

		if (m_ulLastErrorCode != J2534_STATUS_NOERROR)
			return m_ulLastErrorCode;


		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
		//	if (bufCmdAck[3] == J2534_STATUS_NOERROR)
			if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
			{
				/*for(int nIndex = 8; nIndex > 4; nIndex--)
				{
					pstPassThruMsg->ulTimeStamp = pstPassThruMsg->ulTimeStamp << 0x08;
					pstPassThruMsg->ulTimeStamp += bufCmdAck[nIndex];

				}
				TRACE("Calcuated Time Stamp = %02X %02X %02X %02X %02X\n",
					   InputReport[8],
					   InputReport[7],
					   InputReport[6],
					   InputReport[5],
					   InputReport[4]);*/

					   //pstPassThruMsg->ulTimeStamp = ulTimestamp;
				LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
			}
			else
			{
				m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
				return m_ulLastErrorCode;
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			break;
		}
		default:
		{
			break;
		}
		}
		g_pstPassThruMsg = NULL;
	}
	break;

	case J1939_PS:
	case J1939_CH1:
	case J1939_CH2:
	{
		/*Emptying the txlist*/
		EmptyTxList(m_TxList);

		// decompose J1939 into multiple CAN frames
		m_ulLastErrorCode = DecomposeJ1939Message(pstPassThruMsg->ucData,
			(short)pstPassThruMsg->ulDataSize,
			pstPassThruMsg->ulTxFlags);
		if (m_ulLastErrorCode != J2534_STATUS_NOERROR)
			return m_ulLastErrorCode;

		//Reset Acknowledgement
		ResetEvent(m_CmdAck);
		g_pstPassThruMsg = pstPassThruMsg;


		//Send J1939 Message to Garuda
		m_ulLastErrorCode = SendJ1939Messages((unsigned char)m_enChannelList[ulChannelID]);
		if (m_ulLastErrorCode != J2534_STATUS_NOERROR)
			return m_ulLastErrorCode;

		//Below Code is to support Loopback
		/////////////////////////////////////////////////////////////////////////////////////////			
		/*dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
			{
				if(bufCmdAck[3] == J2534_STATUS_NOERROR)
				{
					//pstPassThruMsg->ulTimeStamp = ulTimestamp;
					LogToDebugFile("vWriteMsgs", DEBUGLOG_TYPE_COMMENT, "vWriteMsgs successful");
				}
				else
				{
					m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					return m_ulLastErrorCode;
				}
				break;
			}
		case WAIT_TIMEOUT:
			{

				break;
			}
		default:
			{
				break;
			}
		}*/

		g_pstPassThruMsg = NULL;
	}
	break;

	/* Common Write message for the following Protocols */
	case CAN:
	case FD_CAN_PS:
	case CAN_CH1:
		m_ulLastErrorCode = (J2534ERROR)SendMultipleCANECUMessage(pstPassThruMsg,
			(unsigned long)m_enChannelList[ulChannelID],
			*pulNumMsgs);
		break;
	case SW_CAN_PS:
	case SCI_A_ENGINE:
	case SCI_A_TRANS:
	case SCI_B_ENGINE:
	case SCI_B_TRANS:
	case ISO14230:
	case ISO9141:
		m_ulLastErrorCode = (J2534ERROR)SendECUMessage(pstPassThruMsg, (unsigned char)m_enChannelList[ulChannelID]);
		break; 
	case DOIP_PROTOCOL_ID:
		m_ulLastErrorCode = (J2534ERROR)SendDOIPMessage(pstPassThruMsg, (unsigned char)m_enChannelList[ulChannelID]);
	default:
		return J2534_ERR_MSG_PROTOCOL_ID;
		break;
	}
	TRACE(" Write msg ended with code %d\n", m_ulLastErrorCode);

	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vStartPeriodic(unsigned long    ulChannelID,
	PASSTHRU_MSG* pstMsg,
	unsigned long    ulTimeInterval,
	unsigned long* pulPeriodicRefID)
{
	unsigned char ucReport[30];
	DWORD           dwWaitStatus;
	ZeroMemory(ucReport, 30);
	unsigned int msg_id;
	CCanMsg* pCan;
	unsigned long ulDataIndex = 0, ulDataSize = 0;
	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	int	nOffset = 0;
	// Write to Log File.

		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			LogToDebugFile("vStartPeriodic", DEBUGLOG_TYPE_COMMENT, "vStartPeriodic called");
		}
		msg_id = ntohl(ulong(pstMsg->ucData[0]));

		pCan = new CCanMsg;

		pCan->_msg_id = msg_id;

		/* Ravi : Store the Txflags here */
		pCan->_ulTxflags = pstMsg->ulTxFlags;

		if (ISO15765 == pstMsg->ulProtocolID || FD_ISO15765_PS == pstMsg->ulProtocolID)
		{

			if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
			{
				ulDataSize = pstMsg->ulDataSize - 5; // remove message id from data
			}
			else
			{
				ulDataSize = pstMsg->ulDataSize - 4; // remove message id from data
			}
			if (0 == ulDataSize)
			{

				/* Check for Extended address flag set */
				if (ISO15765_ADDR_TYPE & pstMsg->ulTxFlags)
				{
					pCan->_data[nOffset++] = pstMsg->ucData[4];
					pCan->_data_len = 1; // for PCI byte
				}
				/*Checking for padding*/
				if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
				{
					memset(&pCan->_data[nOffset], 0x00, (8 - nOffset));

					pCan->_data_len = 8;
				}
			}
			else
			{
				/* Check for Extended address flag set */
				if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
				{
					pCan->_data[nOffset++] = pstMsg->ucData[4];
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
					/* Calculate how many data bytes need to be sent in this frame */
					pCan->_data_len = ulDataSize + 2; // for PCI byte
					ulDataIndex = 5;

				}
				else
				{
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
					/* Calculate how many data bytes need to be sent in this frame */
					pCan->_data_len = ulDataSize + 1; // for PCI byte
					// 	pCan->_data_len = ulDataSize ; // for PCI byte
					ulDataIndex = 4;
				}
				memcpy(&pCan->_data[nOffset], &pstMsg->ucData[ulDataIndex], ulDataSize);
				nOffset += ulDataSize;

				/*Checking for padding*/
				if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
				{
					memset(&pCan->_data[nOffset], 0x00, (8 - ulDataSize));
					pCan->_data_len = 8;
				}
			}
		}
		else
		{
			ulDataSize = pstMsg->ulDataSize - 4;
			memcpy(&pCan->_data[nOffset], &pstMsg->ucData[4], ulDataSize);
			pCan->_data_len = ulDataSize;
		}
		//pstMsg->ulDataSize = pCan->_data_len + 4;
		pstMsg->ulDataSize = pCan->_data_len + 4;
		/*Proocess Start Periodic command*/
	  /* ucReport[0] = m_enChannelList[ulChannelID];
		ucReport[1] = ECU_SEND_PERIODICMESSAGE;
		ucReport[2] = START_NEW_PERIODIC_MSG_TXN;
		ucReport[3] = (unsigned char)(ulTimeInterval & 0x000000FF);
		ucReport[4] = (unsigned char)(ulTimeInterval>>8 & 0x000000FF);
		ucReport[5] = (unsigned char)(ulTimeInterval>>16 & 0x000000FF);
		ucReport[6] = (unsigned char)(ulTimeInterval>>24 & 0x000000FF);
		ucReport[7] = (char) *pulPeriodicRefID;*/
		pWriteMsgs->proto_id = m_enChannelList[ulChannelID];
		pWriteMsgs->command = ECU_SEND_PERIODICMESSAGE;
		pWriteMsgs->u.StartPeriodicMsg.Start_Periodic = START_NEW_PERIODIC_MSG_TXN;
		pWriteMsgs->u.StartPeriodicMsg.Time_Interval = (unsigned long)(ulTimeInterval);
		pWriteMsgs->u.StartPeriodicMsg.PeriodicRefID = (char)*pulPeriodicRefID;
		/*Copy the message of 12 bytes to report buffer. If the PASSTHRU message length
		is more than 12 bytes, the message is considered as INVALID message and will be
		discarded from the above layer itself.So i am taking directly length of the message*/

		/* Copies the transmit flags */
	   /* ucReport[8] = (unsigned char)(pstMsg->ulTxFlags & 0x000000FF);
		ucReport[9] = (unsigned char)(pstMsg->ulTxFlags >>8 & 0x000000FF);
		ucReport[10] = (unsigned char)(pstMsg->ulTxFlags >>16 & 0x000000FF);
		ucReport[11] = (unsigned char)(pstMsg->ulTxFlags >>24 & 0x000000FF);*/

		pWriteMsgs->u.StartPeriodicMsg.TxFlags = (unsigned long)(pstMsg->ulTxFlags);
		/* Copies only data size */
	  //  ucReport[12] = (unsigned char) ((pstMsg->ulDataSize) & 0xFF) ;
		pWriteMsgs->u.StartPeriodicMsg.DataSize = (unsigned char)((pstMsg->ulDataSize) & 0xFF);

		/* Copies only the data  */

	/*	ucReport[13] = (unsigned char)(pCan->_msg_id >> 24 & 0x000000FF);
		ucReport[14] =(unsigned char)(pCan->_msg_id >> 16 & 0x000000FF);
		ucReport[15] =(unsigned char)(pCan->_msg_id >> 8 & 0x000000FF);
		ucReport[16] =(unsigned char)(pCan->_msg_id & 0x000000FF); */

		pWriteMsgs->u.StartPeriodicMsg.Msg_Id = (unsigned long)SWAP32(&pCan->_msg_id);

		memcpy(pWriteMsgs->u.StartPeriodicMsg.Data_Bytes, &pCan->_data[0], pCan->_data_len);

		ResetEvent(m_CmdAck);


		if (!WriteOutputReport(ucReport, pCan->_data_len + 21))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				/*	if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
						bufCmdAck[2] == ECU_SEND_PERIODICMESSAGE_ACK &&
						bufCmdAck[3] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
					Inputbuffer->command == ECU_SEND_PERIODICMESSAGE_ACK &&
					Inputbuffer->u.startperiodic.status == J2534_STATUS_NOERROR)
				{
					//	*pulPeriodicRefID = (unsigned long)bufCmdAck[4];
					*pulPeriodicRefID = (unsigned long)Inputbuffer->u.startperiodic.RefID;
					// Write to Log File.
					LogToDebugFile("vStartPeriodic", DEBUGLOG_TYPE_COMMENT, "vStartPeriodic successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.startperiodic.status;
				}

				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
/*	else
	{
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			LogToDebugFile("vStartPeriodic", DEBUGLOG_TYPE_COMMENT, "vStartPeriodic called");
		}
		msg_id = ntohl(ulong(pstMsg->ucData[0]));

		pCan = new CCanMsg;

		pCan->_msg_id = msg_id;

		/* Ravi : Store the Txflags here */
/*		pCan->_ulTxflags = pstMsg->ulTxFlags;

		if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
		{
			ulDataSize = pstMsg->ulDataSize - 5; // remove message id from data
		}
		else
		{
			ulDataSize = pstMsg->ulDataSize - 4; // remove message id from data
		}

		if (0 == ulDataSize)
		{

			/* Check for Extended address flag set */
/*			if (ISO15765_ADDR_TYPE & pstMsg->ulTxFlags)
			{
				pCan->_data[nOffset++] = pstMsg->ucData[4];
				pCan->_data_len = 1; // for PCI byte
			}
			/*Checking for padding*/
/*			if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (8 - nOffset));

				pCan->_data_len = 8;
			}
		}
		else
		{
			/* Check for Extended address flag set */
/*			if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
			{
				pCan->_data[nOffset++] = pstMsg->ucData[4];
				/* construct the PCI byte */
/*				pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
				/* Calculate how many data bytes need to be sent in this frame */
/*				pCan->_data_len = ulDataSize + 2; // for PCI byte
				ulDataIndex = 5;

			}
			else
			{
				/* construct the PCI byte */
/*				pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
				/* Calculate how many data bytes need to be sent in this frame */
/*				pCan->_data_len = ulDataSize + 1; // for PCI byte
				// 	pCan->_data_len = ulDataSize ; // for PCI byte
				ulDataIndex = 4;
			}
			memcpy(&pCan->_data[nOffset], &pstMsg->ucData[ulDataIndex], ulDataSize);
			nOffset += ulDataSize;

			/*Checking for padding*/
/*			if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (8 - ulDataSize));
				pCan->_data_len = 8;
			}
		}
		pstMsg->ulDataSize = pCan->_data_len + 4;
		pWriteMsgs->proto_id = m_enChannelList[ulChannelID];
		pWriteMsgs->command = ECU_SEND_PERIODICMESSAGE;
		pWriteMsgs->u.StartPeriodicMsg.Start_Periodic = START_NEW_PERIODIC_MSG_TXN;
		pWriteMsgs->u.StartPeriodicMsg.Time_Interval = (unsigned long)(ulTimeInterval);
		pWriteMsgs->u.StartPeriodicMsg.PeriodicRefID = (char)*pulPeriodicRefID;
		pWriteMsgs->u.StartPeriodicMsg.TxFlags = (unsigned long)(pstMsg->ulTxFlags);
		pWriteMsgs->u.StartPeriodicMsg.DataSize = (unsigned char)((pstMsg->ulDataSize) & 0xFF);
		pWriteMsgs->u.StartPeriodicMsg.Msg_Id = (unsigned long)SWAP32(&pCan->_msg_id);

		memcpy(pWriteMsgs->u.StartPeriodicMsg.Data_Bytes, &pCan->_data[0], pCan->_data_len);

		ResetEvent(m_CmdAck);


		if (!WriteOutputReport(ucReport, pCan->_data_len + 21))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				/*	if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
						bufCmdAck[2] == ECU_SEND_PERIODICMESSAGE_ACK &&
						bufCmdAck[3] == J2534_STATUS_NOERROR)*/
/*				if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
					Inputbuffer->command == ECU_SEND_PERIODICMESSAGE_ACK &&
					Inputbuffer->u.startperiodic.status == J2534_STATUS_NOERROR)
				{
					//	*pulPeriodicRefID = (unsigned long)bufCmdAck[4];
					*pulPeriodicRefID = (unsigned long)Inputbuffer->u.startperiodic.RefID;
					// Write to Log File.
					LogToDebugFile("vStartPeriodic", DEBUGLOG_TYPE_COMMENT, "vStartPeriodic successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.startperiodic.status;
				}

				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
	}*/
	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vUpdatePeriodic(unsigned long    ulChannelID,
	PASSTHRU_MSG* pstMsg,
	unsigned long    ulTimeInterval,
	unsigned long    ulPeriodicRefID)
{
	unsigned char ucReport[26];
	DWORD           dwWaitStatus;
	ZeroMemory(ucReport, 22);
	unsigned int msg_id;
	CCanMsg* pCan;
	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	unsigned long ulDataIndex = 0, ulDataSize = 0;
	int	nOffset = 0;
	// Write to Log File.
	if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
	{
		LogToDebugFile("vUpdatePeriodic", DEBUGLOG_TYPE_COMMENT, "vUpdatePeriodic called");
	}
	msg_id = ntohl(ulong(pstMsg->ucData[0]));

	pCan = new CCanMsg;

	pCan->_msg_id = msg_id;

	/* Ravi : Store the Txflags here */
	pCan->_ulTxflags = pstMsg->ulTxFlags;

	if (ISO15765 == pstMsg->ulProtocolID || FD_ISO15765_PS == pstMsg->ulProtocolID)
	{

		if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
		{
			ulDataSize = pstMsg->ulDataSize - 5; // remove message id from data
		}
		else
		{
			ulDataSize = pstMsg->ulDataSize - 4; // remove message id from data
		}

		if (0 == ulDataSize)
		{

			/* Check for Extended address flag set */
			if (ISO15765_ADDR_TYPE & pstMsg->ulTxFlags)
			{
				pCan->_data[nOffset++] = pstMsg->ucData[4];
				pCan->_data_len = 1; // for PCI byte
			}
			/*Checking for padding*/
			if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (8 - nOffset));

				pCan->_data_len = 8;
			}
		}
		else
		{
			/* Check for Extended address flag set */
			if (pstMsg->ulTxFlags & ISO15765_ADDR_TYPE)
			{
				pCan->_data[nOffset++] = pstMsg->ucData[4];
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
				/* Calculate how many data bytes need to be sent in this frame */
				pCan->_data_len = ulDataSize + 2; // for PCI byte
				ulDataIndex = 5;

			}
			else
			{
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00 | (short)(ulDataSize);
				/* Calculate how many data bytes need to be sent in this frame */
				pCan->_data_len = ulDataSize + 1; // for PCI byte
				//pCan->_data_len = ulDataSize ; // for PCI byte
				ulDataIndex = 4;
			}
			memcpy(&pCan->_data[nOffset], &pstMsg->ucData[ulDataIndex], ulDataSize);
			nOffset += ulDataSize;

			/*Checking for padding*/
			if (pstMsg->ulTxFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (8 - ulDataSize));
				pCan->_data_len = 8;
			}
		}
	}
	else
	{
		ulDataSize = pstMsg->ulDataSize - 4;
		memcpy(&pCan->_data[nOffset], &pstMsg->ucData[4], ulDataSize);
		pCan->_data_len = ulDataSize;
	}
	//pstMsg->ulDataSize = pCan->_data_len + 4;
	pstMsg->ulDataSize = pCan->_data_len + 4;
	/*Proocess Start Periodic command*/
  /*  ucReport[0] = m_enChannelList[ulChannelID];
	ucReport[1] = ECU_SEND_PERIODICMESSAGE;
	ucReport[2] = UPDATE_DATA_TO_MSG_ID;
	ucReport[3] = (unsigned char)(ulTimeInterval & 0x000000FF);
	ucReport[4] = (unsigned char)(ulTimeInterval>>8 & 0x000000FF);
	ucReport[5] = (unsigned char)(ulTimeInterval>>16 & 0x000000FF);
	ucReport[6] = (unsigned char)(ulTimeInterval>>24 & 0x000000FF);
	ucReport[7] = (char) ulPeriodicRefID;*/
	pWriteMsgs->proto_id = m_enChannelList[ulChannelID];
	pWriteMsgs->command = ECU_SEND_PERIODICMESSAGE;
	pWriteMsgs->u.StartPeriodicMsg.Time_Interval = (unsigned long)(ulTimeInterval);
	pWriteMsgs->u.StartPeriodicMsg.PeriodicRefID = (char)ulPeriodicRefID;

	/*Copy the message of 12 bytes to report buffer. If the PASSTHRU message length
	is more than 12 bytes, the message is considered as INVALID message and will be
	discarded from the above layer itself.So i am taking directly length of the message*/

	/* Copies the transmit flags */
   /* ucReport[8] = (unsigned char)(pstMsg->ulTxFlags & 0x000000FF);
	ucReport[9] = (unsigned char)(pstMsg->ulTxFlags >>8 & 0x000000FF);
	ucReport[10] = (unsigned char)(pstMsg->ulTxFlags >>16 & 0x000000FF);
	ucReport[11] = (unsigned char)(pstMsg->ulTxFlags >>24 & 0x000000FF);*/
	pWriteMsgs->u.StartPeriodicMsg.TxFlags = (unsigned long)(pstMsg->ulTxFlags);

	/* Copies only data size */
 //   ucReport[12] = (unsigned char) ((pstMsg->ulDataSize) & 0xFF) ;
	pWriteMsgs->u.StartPeriodicMsg.DataSize = (unsigned char)((pstMsg->ulDataSize) & 0xFF);

	/* Copies only the data  */

/*	ucReport[13] = (unsigned char)(pCan->_msg_id >> 24 & 0x000000FF);
	ucReport[14] =(unsigned char)(pCan->_msg_id >> 16 & 0x000000FF);
	ucReport[15] =(unsigned char)(pCan->_msg_id >> 8 & 0x000000FF);
	ucReport[16] =(unsigned char)(pCan->_msg_id & 0x000000FF); */
	pWriteMsgs->u.StartPeriodicMsg.Msg_Id = (unsigned long)SWAP32(&pCan->_msg_id);

	//memcpy(&ucReport[17], &pCan->_data[0],pCan->_data_len);
	memcpy(pWriteMsgs->u.StartPeriodicMsg.Data_Bytes, &pCan->_data[0], pCan->_data_len);

	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport, pCan->_data_len + 21))
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{ 
			 Inputbuffer = (InputBuffer_t*)bufCmdAck;

	/*		if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
				bufCmdAck[2] == ECU_SEND_PERIODICMESSAGE_ACK &&
				bufCmdAck[3] == J2534_STATUS_NOERROR)*/
			 if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
				 Inputbuffer->command == ECU_SEND_PERIODICMESSAGE_ACK &&
				 Inputbuffer->u.updateperiodic.status == J2534_STATUS_NOERROR)
			{
				//ulPeriodicRefID = (unsigned long)bufCmdAck[4];
				 ulPeriodicRefID = (unsigned long)Inputbuffer->u.updateperiodic.RefID;
				// Write to Log File.
				LogToDebugFile("vUpdatePeriodic", DEBUGLOG_TYPE_COMMENT, "vUpdatePeriodic successful");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
				//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
				 m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.updateperiodic.status;
			}

			break;
		}
		case WAIT_TIMEOUT:
		{
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vStopPeriodic(unsigned long ulChannelID,
	unsigned long ulPeriodicRefID)
{
	unsigned char ucReport[11];
	DWORD dwWaitStatus;
	ZeroMemory(ucReport, 11);
	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	LogToDebugFile("vStopPeriodic", DEBUGLOG_TYPE_COMMENT, "vStopPeriodic called");

	/* Proocess Stop Periodic command */
	/*ucReport[0] = m_enChannelList[ulChannelID];
	ucReport[1] = ECU_SEND_PERIODICMESSAGE;
	ucReport[2] = STOP_PERIODIC_MSG_TXN;
	ucReport[3] = 0x00;
	ucReport[4] = 0x00;
	ucReport[5] = 0x00;
	ucReport[6] = 0x00;
	ucReport[7] = (unsigned char)(ulPeriodicRefID );*/

	pWriteMsgs->proto_id = m_enChannelList[ulChannelID];
	pWriteMsgs->command = ECU_SEND_PERIODICMESSAGE;
	pWriteMsgs->u.StopPeriodicMsg.Stop_Periodic = STOP_PERIODIC_MSG_TXN;
	pWriteMsgs->u.StopPeriodicMsg.Reserved = 0x00;
	pWriteMsgs->u.StopPeriodicMsg.PeriodicRefID = (unsigned char)(ulPeriodicRefID);

	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport,11 ))//8
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
		   	Inputbuffer = (InputBuffer_t*)bufCmdAck;
		/*	if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
				bufCmdAck[2] == ECU_SEND_PERIODICMESSAGE_ACK &&
				bufCmdAck[3] == J2534_STATUS_NOERROR)*/
			if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
				Inputbuffer->command == ECU_SEND_PERIODICMESSAGE_ACK &&
				Inputbuffer->u.stopperiodic.status == J2534_STATUS_NOERROR)
			{
				/// Write to Log File.
				LogToDebugFile("vStopPeriodic", DEBUGLOG_TYPE_COMMENT, "vStopPeriodic Success");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
			//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
				m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.stopperiodic.status;
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vStartFilter(unsigned long  ulChannelID,
	J2534_FILTER   enFilterType,
	PASSTHRU_MSG* pstMask,
	PASSTHRU_MSG* pstPattern,
	PASSTHRU_MSG* pstFlowControl,
	unsigned long* pulFilterRefID)
{
	unsigned char ucReport[32];
	DWORD         dwWaitStatus;
	ZeroMemory(ucReport, 32);
	BufferCommand_t* StartFilter;
	StartFilter = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	// Write to Log File.
	LogToDebugFile("vStartFilter", DEBUGLOG_TYPE_COMMENT, "vStartFilter called");

	/*Proocess Filter command*/
   // ucReport[0] = m_enChannelList[ulChannelID];
   // ucReport[1] = ECU_START_MSGFILTER;
	StartFilter->proto_id = m_enChannelList[ulChannelID];
	StartFilter->command = ECU_START_MSGFILTER;
	if (J2534_FILTER_FLOW_CONTROL != enFilterType)
	{
		/*Proocess Filter command*/
		//ucReport[0] = m_enChannelList[ulChannelID];
		//ucReport[1] = ECU_START_MSGFILTER;
		//ucReport[2] = enFilterType;
		StartFilter->proto_id = m_enChannelList[ulChannelID];
		StartFilter->command = ECU_START_MSGFILTER;
		StartFilter->u.StartFilter.filter_type = enFilterType;

		//Copy the message of 12 bytes to report buffer. If the PASSTHRU message length is more
		//than 12 bytes, the message is considered as INVALID message and will be discarded from
		//the above layer itself.So i am taking directly length of the message.

		/* Store the mask length */
		//ucReport[3] =( unsigned char ) pstMask->ulDataSize;
		StartFilter->u.StartFilter.Store_Mask = (unsigned char)pstMask->ulDataSize;

		//Copy the mask message to report buffer
		//memcpy(&ucReport[4], &pstMask->ucData,pstMask->ulDataSize);
		memcpy(&StartFilter->u.StartFilter.Mask_Buffer, &pstMask->ucData, pstMask->ulDataSize);
		/* Store the pattern length */
		//ucReport[4 + pstMask->ulDataSize] =( unsigned char ) pstPattern->ulDataSize;
		StartFilter->u.StartFilter.Pattern_Length = (unsigned char)pstPattern->ulDataSize;
		//Copy the pattern message to report buffer
	//	memcpy(&ucReport[4 + pstMask->ulDataSize + 1], &pstPattern->ucData, pstPattern->ulDataSize);
		memcpy(&StartFilter->u.StartFilter.Pattern_Buffer, &pstPattern->ucData, pstPattern->ulDataSize);
		ResetEvent(m_CmdAck);


		if (!WriteOutputReport(ucReport, (pstMask->ulDataSize + pstPattern->ulDataSize + 9)))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;
				/*if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
				   bufCmdAck[2] == ECU_START_MSGFILTER_ACK &&
				   bufCmdAck[3] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
					Inputbuffer->command == ECU_START_MSGFILTER_ACK &&
					Inputbuffer->u.STARTfilter.status == J2534_STATUS_NOERROR)
				{
					//*pulFilterRefID = (unsigned long)bufCmdAck[4];
					*pulFilterRefID = (unsigned long)(Inputbuffer->u.STARTfilter.Ref_Id);
					// Write to Log File.
					LogToDebugFile("vStartFilter", DEBUGLOG_TYPE_COMMENT, "vStartFilter successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.STARTfilter.status);
				}
				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
		return m_ulLastErrorCode;
	}
	else
	{
		/* Ravi : Since the Flow control support is not there in the Firmware
		the work around is implemented here to do the All pass setting to get the
		messages from the OEM tool Hardware Interface */

		/* Set as all pass filter */
	//	ucReport[0] = m_enChannelList[ulChannelID];
	//	ucReport[1] = ECU_START_MSGFILTER;
	//	ucReport[2] = J2534_FILTER_PASS;
		StartFilter->proto_id = m_enChannelList[ulChannelID];
		StartFilter->command = ECU_START_MSGFILTER;
		StartFilter->u.StartFilter.filter_type = J2534_FILTER_PASS;

		/* Store the mask length */
	//	ucReport[3] =( unsigned char ) pstMask->ulDataSize;
		StartFilter->u.StartFilter.Store_Mask = (unsigned char)pstMask->ulDataSize;

		//Copy the mask message to report buffer
	//	memcpy(&ucReport[4], &pstMask->ucData,pstMask->ulDataSize);

		memcpy(&StartFilter->u.StartFilter.Mask_Buffer, &pstMask->ucData, pstMask->ulDataSize);

		/* Store the pattern length */
		//ucReport[4 + pstMask->ulDataSize] = ( unsigned char ) pstPattern->ulDataSize;
		StartFilter->u.StartFilter.Pattern_Length = (unsigned char)pstPattern->ulDataSize;

		//Copy the pattern message to report buffer
	//	memcpy(&ucReport[4 + pstMask->ulDataSize + 1], &pstPattern->ucData,pstPattern->ulDataSize);

		memcpy(&StartFilter->u.StartFilter.Pattern_Buffer, &pstPattern->ucData, pstPattern->ulDataSize);
		ResetEvent(m_CmdAck);


		if (!WriteOutputReport(ucReport, (pstMask->ulDataSize + pstPattern->ulDataSize + 9)))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;
				/* if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
				   bufCmdAck[2] == ECU_START_MSGFILTER_ACK &&
				   bufCmdAck[3] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
					Inputbuffer->command == ECU_START_MSGFILTER_ACK &&
					Inputbuffer->u.STARTfilter.status == J2534_STATUS_NOERROR)
				{
					//*pulFilterRefID = (unsigned long)bufCmdAck[4];
					*pulFilterRefID = (unsigned long)(Inputbuffer->u.STARTfilter.Ref_Id);
					// Write to Log File.
					LogToDebugFile("vStartFilter", DEBUGLOG_TYPE_COMMENT, "vStartFilter successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.STARTfilter.status);
					return m_ulLastErrorCode;
				}
				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
		return m_ulLastErrorCode;
	}
}

/* Ravi : No update needed here since the Flow control filter is referenced as Pass
filter in the Start filter for the Hardware interface and can be continued. Based on
the final Flow control filter stratergy, Stop Filter needs to be revisited*/

J2534ERROR CDeviceOEMTool::vStopFilter(unsigned long ulChannelID,
	unsigned long ulFilterRefID)
{
	unsigned char ucReport[3];
	DWORD         dwWaitStatus;
	ZeroMemory(ucReport, 3);
	BufferCommand_t* StopFilter;
	StopFilter = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	// Write to Log File.
	LogToDebugFile("vStopFilter", DEBUGLOG_TYPE_COMMENT, "vStopFilter called");

	/*Proocess Stop Filtercommand*/
   // ucReport[0] = m_enChannelList[ulChannelID];
   // ucReport[1] = ECU_STOP_MSGFILTER;
   // ucReport[2] = (unsigned char)(ulFilterRefID &0x000000FF);
	StopFilter->proto_id = m_enChannelList[ulChannelID];
	StopFilter->command = ECU_STOP_MSGFILTER;
	StopFilter->u.StopFilter.filter_type = (unsigned char)(ulFilterRefID & 0x000000FF);

	ResetEvent(m_CmdAck);

	int len = sizeof(StopFilter->proto_id) + sizeof(StopFilter->command);

	len += sizeof(StopFilter->u.StopFilter);

	if (!WriteOutputReport(ucReport, len))
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
			/*     if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
					 bufCmdAck[2] == ECU_STOP_MSGFILTER_ACK &&
					 bufCmdAck[3] == J2534_STATUS_NOERROR)*/
			if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
				Inputbuffer->command == ECU_STOP_MSGFILTER_ACK &&
				Inputbuffer->u.STOPfilter.status == J2534_STATUS_NOERROR)
			{
				// Write to Log File.
				LogToDebugFile("vStopFilter", DEBUGLOG_TYPE_COMMENT, "vStopFilter Success");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
				// m_ulLastErrorCode = (J2534ERROR) bufCmdAck[3];
				m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.STOPfilter.status);
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return m_ulLastErrorCode;
}

J2534ERROR CDeviceOEMTool::vIoctl(unsigned long ulChannelID,
	J2534IOCTLID enumIoctlID,
	void* pInput,
	void* pOutput)
{
	unsigned char ucReport[32];
	int nIndex = 0;
	int nNumJ1850PWMFuncMsg = 0;
	DWORD           dwWaitStatus;
	BufferCommand_t* pWriteMsgs;
	InputBuffer_t* Inputbuffer;
	pWriteMsgs = (BufferCommand_t*)ucReport;

	ZeroMemory(ucReport, 32);

	// Log
	LogToDebugFile("vIoctl", DEBUGLOG_TYPE_COMMENT, "Ioctl called");

	// Take action based on IOCTL
	switch (enumIoctlID)
	{
	case GET_CONFIG:
	{
		// Get it
		m_ulLastErrorCode = GetConfig((SCONFIG*)pInput, ulChannelID);
	}
	break;
	case SET_CONFIG:
	{
		//Set it
		m_ulLastErrorCode = SetConfig((SCONFIG*)pInput, ulChannelID);
	}
	break;
	case GET_IP_ADDRESS:
	{
		pWriteMsgs->proto_id = DOIP_PROTOCOL_ID;
		pWriteMsgs->command = ECU_IOCTL_COMMAND;
		pWriteMsgs->u.IOCTL.IOCTL_ID = enumIoctlID;
		pWriteMsgs->u.IOCTL.rsvd = 0x01;

		TRACE("Wait for the IOCtl command event \n");

		ResetEvent(m_CmdAck);



		if (!WriteOutputReport(ucReport, 10))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			 {
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				if (((Inputbuffer->proto_id == ECU_PROTOCOL_ID) ||
					(Inputbuffer->command == J2534_SETUPCMDPROT_ID)) &&
					Inputbuffer->u.IOctl.Response == ECU_IOCTL_RESPONSE &&
					Inputbuffer->u.IOctl.status == J2534_STATUS_NOERROR)
				{
				//	local_ip_addr[16] = Inputbuffer->u.IOctl.u.databytes;

					LogToDebugFile("GET_IP_ADDRESS", DEBUGLOG_TYPE_COMMENT, "GET_IP_ADDRESS Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}		
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.IOctl.status;
				}
				break;

			 }
		    }
		}
	}
	case READ_VBATT:
		/*{

			 unsigned long *pulBattVoltage1;
			 pulBattVoltage1 = (unsigned long *)pOutput;
			 *pulBattVoltage1 = 12000;
			 m_ulLastErrorCode = J2534_STATUS_NOERROR;
			 break;

		}*/

	case READ_PROG_VOLTAGE:
	case CLEAR_TX_BUFFER:
	case CLEAR_RX_BUFFER:
	case CLEAR_PERIODIC_MSGS:
	case CLEAR_MSG_FILTERS:
	{
		/*Jayasheela-Need to send protocol id C3 for setup commands */
		if ((enumIoctlID == READ_VBATT) || (enumIoctlID == READ_PROG_VOLTAGE))
			//ucReport[0] = J2534_SETUPCMDPROT_ID;
			pWriteMsgs->proto_id = J2534_SETUPCMDPROT_ID;
		else
		/*	ucReport[0] = m_enChannelList[ulChannelID];
		ucReport[1] = ECU_IOCTL_COMMAND;
		ucReport[2] = enumIoctlID;
		ucReport[3] = 0x01;*/
			pWriteMsgs->proto_id = m_enChannelList[ulChannelID];
		    pWriteMsgs->command = ECU_IOCTL_COMMAND;
			pWriteMsgs->u.IOCTL.IOCTL_ID = enumIoctlID;
			pWriteMsgs->u.IOCTL.rsvd = 0x01;

		TRACE("Wait for the IOCtl command event \n");

		ResetEvent(m_CmdAck);



		if (!WriteOutputReport(ucReport, 10))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{ 
				Inputbuffer = (InputBuffer_t*)bufCmdAck;
			/*	if (((bufCmdAck[1] == ECU_PROTOCOL_ID) ||
					(bufCmdAck[1] == J2534_SETUPCMDPROT_ID)) &&
					bufCmdAck[2] == ECU_IOCTL_RESPONSE &&
					bufCmdAck[4] == J2534_STATUS_NOERROR)*/
				if (((Inputbuffer->proto_id == ECU_PROTOCOL_ID) ||
					(Inputbuffer->command == J2534_SETUPCMDPROT_ID)) &&
					Inputbuffer->u.IOctl.Response == ECU_IOCTL_RESPONSE &&
					Inputbuffer->u.IOctl.status == J2534_STATUS_NOERROR)
				{
					if (enumIoctlID == READ_VBATT)
					{
						/*Read the voltage and vbatt value*/
						unsigned long* pulBattVoltage;
						pulBattVoltage = (unsigned long*)pOutput;
						*pulBattVoltage = 0;
						/*jayasheela-data starts from 6th byte */
					/*	*pulBattVoltage = (bufCmdAck[6] & 0xFF);
						*pulBattVoltage = *pulBattVoltage | (bufCmdAck[7] << 8);
						*pulBattVoltage = *pulBattVoltage | (bufCmdAck[8] << 16);
						*pulBattVoltage = *pulBattVoltage | (bufCmdAck[9] << 24);*/
						*pulBattVoltage = Inputbuffer->u.IOctl.u.voltage;
						if (*pulBattVoltage <= 12000)
							*pulBattVoltage = *pulBattVoltage + 400;
						else
							*pulBattVoltage = *pulBattVoltage + 300;
						// Write to Log File.
						LogToDebugFile("READ_VBATT", DEBUGLOG_TYPE_COMMENT, "READ_VBATT Successful");
					}
					else if (enumIoctlID == READ_PROG_VOLTAGE)
					{
						unsigned long* pulProgVoltage;
						pulProgVoltage = (unsigned long*)pOutput;
						*pulProgVoltage = 0;
						/*jayasheela-data starts from 6th byte */
					/*	*pulProgVoltage = (bufCmdAck[6] & 0xFF);
						*pulProgVoltage = *pulProgVoltage | (bufCmdAck[7] << 8);
						*pulProgVoltage = *pulProgVoltage | (bufCmdAck[8] << 16);
						*pulProgVoltage = *pulProgVoltage | (bufCmdAck[9] << 24);*/
						*pulProgVoltage = Inputbuffer->u.IOctl.u.voltage;
						// Write to Log File.
						LogToDebugFile("READ_PROG_VOLTAGE", DEBUGLOG_TYPE_COMMENT, "READ_PROG_VOLTAGE Successful");
					}
					else if (enumIoctlID == CLEAR_TX_BUFFER)
					{
						// Write to Log File.
						LogToDebugFile("CLEAR_TX_BUFFER", DEBUGLOG_TYPE_COMMENT, "CLEAR_TX_BUFFER Successful");
					}
					else if (enumIoctlID == CLEAR_RX_BUFFER)
					{
						// Write to Log File.
						LogToDebugFile("CLEAR_RX_BUFFER", DEBUGLOG_TYPE_COMMENT, "CLEAR_RX_BUFFER Successful");
					}
					else if (enumIoctlID == CLEAR_PERIODIC_MSGS)
					{
						// Write to Log File.
						LogToDebugFile("CLEAR_PERIODIC_MSGS", DEBUGLOG_TYPE_COMMENT, "CLEAR_PERIODIC_MSGS Successful");
					}
					else if (enumIoctlID == CLEAR_MSG_FILTERS)
					{
						// Write to Log File.
						LogToDebugFile("CLEAR_MSG_FILTERS", DEBUGLOG_TYPE_COMMENT, "CLEAR_MSG_FILTERS Successful");
					}
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.IOctl.status;
				}

				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
	}
	break;
	case FAST_INIT:
	{
		//Sending FAST_INIT Command to the device
		m_ulLastErrorCode = FastInit((PASSTHRU_MSG*)pInput, (PASSTHRU_MSG*)pOutput, ulChannelID);
	}
	break;
	case FIVE_BAUD_INIT:
	{
		//Sending FIVE_BAUD_INIT Command to the device
		m_ulLastErrorCode = FiveBaudInit((SBYTE_ARRAY*)pInput, (SBYTE_ARRAY*)pOutput, ulChannelID);
	}
	break;
	case PROTECT_J1939_ADDR:
	{
		//Sending Protect J1939 Address Command to the device
		m_ulLastErrorCode = ProtectJ1939Address((SBYTE_ARRAY*)pInput, (SBYTE_ARRAY*)pOutput, ulChannelID);
	}
	break;
	case ADD_TO_FUNCT_MSG_LOOKUP_TABLE:
	case DELETE_FROM_FUNCT_MSG_LOOKUP_TABLE:
	{
		memcpy(m_FunctionTable, pInput,
			sizeof(COEMTOOL_J1850PWM_LOOKUP_TABLE) * J1850PWM_LIMIT);

		for (nIndex = 0; nIndex < J1850PWM_LIMIT; nIndex++)
		{
			ucReport[nIndex] = m_FunctionTable[nIndex].ucFuncID;
			if (m_FunctionTable[nIndex].bValid == true)
				nNumJ1850PWMFuncMsg++;
		}
		m_ulLastErrorCode = SendIOCTLData(enumIoctlID, ucReport, nNumJ1850PWMFuncMsg, ulChannelID);
	}
	break;
	case CLEAR_FUNCT_MSG_LOOKUP_TABLE:
		m_ulLastErrorCode = SendIOCTLData(CLEAR_FUNCT_MSG_LOOKUP_TABLE, ucReport, 0, ulChannelID);
		break;
	case SW_CAN_HS:
	case SW_CAN_NS:
	{
		ucReport[0] = (unsigned char)m_enChannelList[ulChannelID];
		ucReport[1] = ECU_IOCTL_COMMAND;
		/*Jayasheela-send cmd as per HFCP*/
		/*if(enumIoctlID==SW_CAN_HS)
		ucReport[2] = 0x80;
		else
		ucReport[2] = 0x87;*/
		ucReport[2] = enumIoctlID;
		ResetEvent(m_CmdAck);

		if (!WriteOutputReport(ucReport, 3))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
					bufCmdAck[4] == J2534_STATUS_NOERROR)
				{
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
				}
				break;
			}
			case WAIT_TIMEOUT:
			{
				break;
			}
			default:
			{
				break;
			}
			}
		}
		else
		{
			m_ulLastErrorCode = J2534_ERR_FAILED;
		}
	}
	break;
	default:
		m_ulLastErrorCode = J2534_ERR_NOT_SUPPORTED;
		break;
	}

	TRACE(" IOCtl end with code %d \n", m_ulLastErrorCode);

	return m_ulLastErrorCode;
}
/*******************************************************************************
						PROTOCOL COMMUNICATION FUNCTIONS
						--------------------------------
	1. EnableCommuncation():- This function will enable the communication
							  with the selected protocol.
	2. DisableCommuncation():-This function will disable the communication
							  with the selected protocol.
*******************************************************************************/
J2534ERROR CDeviceOEMTool::EnableCommuncation(unsigned long ulFlags,
	unsigned long ulBaudRate,
	J2534_PROTOCOL enProtocolID)
{
	unsigned char ucReport[20];
	J2534ERROR ret_status = J2534_ERR_FAILED;
	DWORD dwWaitStatus;
	int ret = 0;
	BufferCommand_t* EnableCommunication;
	InputBuffer_t* Inputbuffer;
	EnableCommunication = (BufferCommand_t*)ucReport;
	 ZeroMemory(ucReport,20);

	TRACE("Enable Communication \n");

	// Write to Log File.
	LogToDebugFile("EnableCommuncation", DEBUGLOG_TYPE_COMMENT, "EnableCommuncation called");

	/*Proocess  PROTOCOL_ENABLECANCOM command*/
/*	ucReport[0] = enProtocolID;
	ucReport[1] = PROTOCOL_ENABLECANCOM;
	ucReport[2] = (unsigned char)(ulBaudRate & 0x000000FF);
	ucReport[3] = (unsigned char)(ulBaudRate>>8 & 0x000000FF);
	ucReport[4] = (unsigned char)(ulBaudRate>>16 & 0x000000FF);
	ucReport[5] = (unsigned char)(ulBaudRate>>24 & 0x000000FF);
	ucReport[6] = (unsigned char)(ulFlags & 0x000000FF);
	ucReport[7] = (unsigned char)(ulFlags>>8 & 0x000000FF);
	ucReport[8] = (unsigned char)(ulFlags>>16 & 0x000000FF);
	ucReport[9] = (unsigned char)(ulFlags>>24 & 0x000000FF);*/

	EnableCommunication->proto_id = enProtocolID;
	EnableCommunication->command = PROTOCOL_ENABLECANCOM;
	EnableCommunication->u.EnableComm.baudrate = ulBaudRate;
	EnableCommunication->u.EnableComm.conn_flags = ulFlags;
	if (enProtocolID == DOIP_PROTOCOL_ID)
	{
		EnableCommunication->u.EnableComm.baudrate = NULL;
		EnableCommunication->u.EnableComm.conn_flags = NULL;
		m_ulLastErrorCode = vDOIPClient(ECU_logical_addr);//Tester_logical_addr
		if (m_ulLastErrorCode != J2534_STATUS_NOERROR)
		{
			return m_ulLastErrorCode;
		}
//		J2534IOCTLID enumIoctlID = GET_IP_ADDRESS;
//		m_ulLastErrorCode = CDeviceOEMTool::vIoctl(GET_IP_ADDRESS, enumIoctlID, NULL,NULL);
		m_ulLastErrorCode = DOIPClientDetailsSEND(client_ip_addr, subnetaddr, Gwaddr, ECU_logical_addr);
		if (m_ulLastErrorCode != J2534_STATUS_NOERROR)
		{
			return m_ulLastErrorCode;
		}
		m_ulLastErrorCode = DOIP_configure_server(server_ip_addr, Tester_logical_addr, NULL, NULL, NULL);

		return m_ulLastErrorCode;
	}
	ResetEvent(m_CmdAck);
	int len = sizeof(EnableCommunication->proto_id) + sizeof(EnableCommunication->command);

	len += sizeof(EnableCommunication->u.EnableComm);
	if (!WriteOutputReport(ucReport, len))
	{

		TRACE("Wait for the command event \n");

		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);//nikhiltest commented for test

		TRACE("Received the event \n");
//		Sleep(400); //for first time need to connect protocol //chiru
		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			Inputbuffer = (InputBuffer_t*)bufCmdAck;

			/*	if (bufCmdAck[1] == enProtocolID &&
					bufCmdAck[2] == PROTOCOL_ENABLECANCOM_ACK &&
					bufCmdAck[3] == J2534_STATUS_NOERROR)*/
			if (Inputbuffer->proto_id == enProtocolID &&
				Inputbuffer->command == PROTOCOL_ENABLECANCOM_ACK &&
				Inputbuffer->u.EnableCom.status == J2534_STATUS_NOERROR)
			{
				// Write to Log File.
				LogToDebugFile("EnableCommuncation", DEBUGLOG_TYPE_COMMENT, "Setbaud Rate successful");
				ret_status = J2534_STATUS_NOERROR;
				TRACE(" Reached Init success \n");
			}
			else
			{
				TRACE(" Reached Init error \n");
				ret_status = J2534_ERR_NOT_SUPPORTED; //(J2534ERROR)bufCmdAck[3];
			}
			break;

		}
		case WAIT_TIMEOUT:
		{
			TRACE(" Reached Init timeout \n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}

	TRACE(" Reached Init End \n");

	return ret_status;
}
J2534ERROR CDeviceOEMTool::DisableCommuncation(unsigned long ucChannelId)
{
	unsigned char ucReport[10];
	unsigned char report[15];
	J2534ERROR ret_stat = J2534_ERR_NOT_SUPPORTED;
	DWORD dwWaitStatus;
	ZeroMemory(ucReport, 10);
	BufferCommand_t* DisableCommunication;
	BufferCommand_t* Disablecom;

	InputBuffer_t* Inputbuffer;
	DisableCommunication = (BufferCommand_t*)ucReport;
	Disablecom = (BufferCommand_t*)report;
	// Write to Log File.
	LogToDebugFile("DisableCommunnication", DEBUGLOG_TYPE_COMMENT, "DisableCommunnication called");
	/*Proocess PROTOCOL_DISABLECOM Command*/
	DisableCommunication->proto_id = (unsigned long)m_enChannelList[ucChannelId];//m_enChannelList[m_nChannelID];nikhileshtest_deleted
	DisableCommunication->command = PROTOCOL_DISABLECOM;
	if (DisableCommunication->proto_id == DOIP_PROTOCOL_ID)
	{ 
		int lenn = sizeof(Disablecom->u.disablecom.ipaddr);
		Disablecom->proto_id = DOIP_PROTOCOL_ID;
		Disablecom->command = 0x02;
		memcpy((void*)Disablecom->u.disablecom.ipaddr, server_ip_addr, lenn);
		Disablecom->u.disablecom.ipaddr[lenn - 1] = '\0';

		int leng = sizeof(DisableCommunication->proto_id) + sizeof(DisableCommunication->command)+ sizeof(Disablecom->u.disablecom.ipaddr);
		ResetEvent(m_CmdAck);


		if (!WriteOutputReport(report, leng))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, DISABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				/*  if (bufCmdAck[1] == m_enChannelList[ucChannelId] &&
					 bufCmdAck[2] == PROTOCOL_DISABLECOM_ACK &&
					 bufCmdAck[3] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == m_enChannelList[ucChannelId] &&
					Inputbuffer->command == PROTOCOL_DISABLECOM_ACK &&
					Inputbuffer->u.DisableCom.status == J2534_STATUS_NOERROR)
				{
					// Write to Log File.
					LogToDebugFile("DisableCommunnication", DEBUGLOG_TYPE_COMMENT, "DisableCommunnication Success");
					ret_stat = J2534_STATUS_NOERROR;
					free(server_ip_addr);
				}

				else
				{
					// ret_stat = (J2534ERROR) bufCmdAck[3];
					ret_stat = (J2534ERROR)(Inputbuffer->u.DisableCom.status);
				}

				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}

		return ret_stat;
	}
	int len = sizeof(DisableCommunication->proto_id) + sizeof(DisableCommunication->command);
	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport, len))
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, DISABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			Inputbuffer = (InputBuffer_t*)bufCmdAck;

			/*  if (bufCmdAck[1] == m_enChannelList[ucChannelId] &&
				 bufCmdAck[2] == PROTOCOL_DISABLECOM_ACK &&
				 bufCmdAck[3] == J2534_STATUS_NOERROR)*/
			if (Inputbuffer->proto_id == m_enChannelList[ucChannelId] &&
				Inputbuffer->command == PROTOCOL_DISABLECOM_ACK &&
				Inputbuffer->u.DisableCom.status == J2534_STATUS_NOERROR)
			{
				// Write to Log File.
				LogToDebugFile("DisableCommunnication", DEBUGLOG_TYPE_COMMENT, "DisableCommunnication Success");
				ret_stat = J2534_STATUS_NOERROR;
			}

			else
			{
				// ret_stat = (J2534ERROR) bufCmdAck[3];
				ret_stat = (J2534ERROR)(Inputbuffer->u.DisableCom.status);
			}

			break;
		}
		case WAIT_TIMEOUT:
		{
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}

	return ret_stat;
}
J2534ERROR CDeviceOEMTool::SendJ1939SingleMessage(unsigned long ulMsgId,
	unsigned char* pData,
	unsigned char uchDataLength,
	unsigned long ulTxFlags,
	unsigned long ulProtocolId)
{
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	int nIdx = 0;
	DWORD dwWaitStatus;

	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);

	nIdx = 0;
	uchDataBuffer[nIdx++] = (unsigned char)ulProtocolId;
	uchDataBuffer[nIdx++] = ECU_SENDMESSAGE;
	uchDataBuffer[nIdx++] = 0x00;
	uchDataBuffer[nIdx++] = 0x01;
	uchDataBuffer[nIdx++] = 0xC0; //Mode 3

	//Setting Tx Flags
	uchDataBuffer[nIdx++] = (unsigned char)((ulTxFlags >> 0) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulTxFlags >> 8) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulTxFlags >> 16) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulTxFlags >> 24) & 0xFF);

	//Setting Msg Id
	uchDataBuffer[nIdx++] = (unsigned char)((ulMsgId >> 24) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulMsgId >> 16) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulMsgId >> 8) & 0xFF);
	uchDataBuffer[nIdx++] = (unsigned char)((ulMsgId >> 0) & 0xFF);

	//Setting DataLength
	uchDataBuffer[nIdx++] = uchDataLength;

	//Copying DataBytes
	memcpy(uchDataBuffer + nIdx, pData, uchDataLength);


	WriteOutputReport(uchDataBuffer, OUTPUTREPORTMAX);

	return J2534_STATUS_NOERROR;

	//Below Code Not Execute
	//////////////////////////////////////////////////////////////////////////////////////////
	dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
	switch (dwWaitStatus)
	{
	case WAIT_OBJECT_0:
	{
		if (bufCmdAck[2] == ECU_SENDMESSAGE_ACK)
		{
			if (bufCmdAck[3] == J2534_STATUS_NOERROR)
			{
				// Write to Log File.*/
				sprintf(szBuffer, "SendJ1939Message returned 0x%02X", J2534_STATUS_NOERROR);
				LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendJ1939ECUMessage()");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
				m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
			}
		}
		break;
	}
	case WAIT_TIMEOUT:
	{
		m_ulLastErrorCode = J2534_ERR_TIMEOUT;
		break;
	}
	default:
	{
		break;
	}
	}



	return m_ulLastErrorCode;
}



J2534ERROR CDeviceOEMTool::SendMultipleCANECUMessage(PASSTHRU_MSG* pstPassThruMsg,
	unsigned char ucChannelId,
	unsigned long ulNumberMsgs)
{
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	unsigned char* outputBuffer = NULL;
	outputBuffer = (unsigned char*)malloc(sizeof(unsigned char) * OUTPUTREPORTMAX);

	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	DWORD dwWaitStatus;
	int totalNumberOfMessage = 0;
	unsigned int iCount = 0;
	int nIdex = 0;
	bool bHeaderAdded = false;
	bool bSendMessage = false;

	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)outputBuffer;
	InputBuffer_t* Inputbuffer;

	for (unsigned long ulmsg = 0; ulmsg < ulNumberMsgs; ulmsg++)
	{
		if (iCount == 0)
		{

			bSendMessage = false;
			bHeaderAdded = false;

			ZeroMemory(outputBuffer, OUTPUTREPORTMAX);
			nIdex = 0;
			/*	*(outputBuffer + nIdex++) = ucChannelId;
				*(outputBuffer + nIdex++) = ECU_SENDMESSAGE;
				*(outputBuffer + nIdex++) = 0x00;*/
			pWriteMsgs->proto_id = ucChannelId;
			pWriteMsgs->command = ECU_SENDMESSAGE;
			pWriteMsgs->u.WriteMsgs.segnum = 0x00;
			//	nIdex += 2;
		}
		int len = sizeof(pWriteMsgs->proto_id) + sizeof(pWriteMsgs->command);
		//CMD_SIZEOF_PROTO_CMD(pWriteMsgs);
		len += sizeof(pWriteMsgs->u.WriteMsgs);

		if (OUTPUTREPORTMAX - 1 >= (len + 8 + (pstPassThruMsg + ulmsg)->ulDataSize))
		{
			iCount++;

			//Copy TX Flags 4 Bytes
		/*	*(outputBuffer + nIdex++) = (unsigned char)((pstPassThruMsg + ulmsg)->ulTxFlags & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)((pstPassThruMsg + ulmsg)->ulTxFlags>>8 & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)((pstPassThruMsg + ulmsg)->ulTxFlags>>16 & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)((pstPassThruMsg + ulmsg)->ulTxFlags>>24 & 0x000000FF);*/

			pWriteMsgs->u.WriteMsgs.TxFlags = (unsigned long)((pstPassThruMsg + ulmsg)->ulTxFlags);

			//Calculate Message ID : 4 Bytes
			unsigned long ulMessageID = ntohl(ulong((pstPassThruMsg + ulmsg)->ucData[0]));

			//Copy message Id 4 bytes
		/*	*(outputBuffer + nIdex++) = (unsigned char)(ulMessageID >> 24 & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)(ulMessageID >> 16 & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)(ulMessageID >> 8 & 0x000000FF);
			*(outputBuffer + nIdex++) = (unsigned char)(ulMessageID & 0x000000FF);*/

			pWriteMsgs->u.WriteMsgs.Msg_Id = (unsigned long)SWAP32(&ulMessageID);

			//	*(outputBuffer + nIdex++) = (unsigned char)(pstPassThruMsg + ulmsg)->ulDataSize - 4;
			pWriteMsgs->u.WriteMsgs.Data_Length = (unsigned char)(pstPassThruMsg + ulmsg)->ulDataSize - 4;
			//Copy the databytes
			//memcpy(outputBuffer + nIdex,(pstPassThruMsg + ulmsg)->ucData + 4,(pstPassThruMsg + ulmsg)->ulDataSize - 4);
			memcpy(&pWriteMsgs->u.WriteMsgs.Data_Bytes, (pstPassThruMsg + ulmsg)->ucData + 4, (pstPassThruMsg + ulmsg)->ulDataSize - 4);
			len += (pstPassThruMsg + ulmsg)->ulDataSize - 4;
			//	nIdex += (pstPassThruMsg + ulmsg)->ulDataSize - 4;

		}
		else
		{
			//	outputBuffer[3] =(unsigned char) ((iCount) & 0xFF);		
			//	outputBuffer[4] =(unsigned char) (0xC0 | (iCount >> 8 & 0xFF) );
			pWriteMsgs->u.WriteMsgs.Messagelength = (unsigned char)((iCount) & 0xFF);
			pWriteMsgs->u.WriteMsgs.Messagelength1 = (unsigned char)(0xC0 | (iCount >> 8 & 0xFF));
			bHeaderAdded = true;
			iCount = 0;
			bSendMessage = true;
			ulmsg--;
		}

		if ((ulmsg == ulNumberMsgs - 1) && (bHeaderAdded == false))
		{
			//	outputBuffer[3] =(unsigned char) ((iCount) & 0xFF);		
			//	outputBuffer[4] =(unsigned char) (0xC0 | (iCount >> 8 & 0xFF) );
			pWriteMsgs->u.WriteMsgs.Messagelength = (unsigned char)((iCount) & 0xFF);
			pWriteMsgs->u.WriteMsgs.Messagelength1 = (unsigned char)(0xC0 | (iCount >> 8 & 0xFF));
			bSendMessage = true;
		}

		if (bSendMessage)
		{
			// Write the buffer to the device.
			/*Send data to device*/
				//TRACE("Multi Frame  %d - [%0.2X][%0.2X]  \n",ulNumberMsgs,
			//outputBuffer[11],outputBuffer[12]);

			//Sleep(1000);

			WriteOutputReport(outputBuffer, OUTPUTREPORTMAX);
			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				Inputbuffer = (InputBuffer_t*)bufCmdAck;
				//	if(bufCmdAck[2] == ECU_SENDMESSAGE_ACK)
				if (Inputbuffer->command == ECU_SENDMESSAGE_ACK)
				{
					//	if(bufCmdAck[3] == J2534_STATUS_NOERROR)
					if (Inputbuffer->u.Writemessages.status == J2534_STATUS_NOERROR)
					{
						// Write to Log File.*/
						sprintf(szBuffer, "SendCANMessage returned 0x%02X", J2534_STATUS_NOERROR);
						LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendCANECUMessage()");
						m_ulLastErrorCode = J2534_STATUS_NOERROR;
					}
					else
					{
						//m_ulLastErrorCode =  (J2534ERROR)bufCmdAck[4];
						m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.Writemessages.ERR_status);
					}
				}
				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}

	}

	return m_ulLastErrorCode;
}

/******************************************************************************
   Function Name    : SendECUMessage()
   Description      : Send the KWP protocol message to the device.

Message Format : From PC to Device              From Device to PC
----------------------------------              ------------------
		Byte0 : ProtoclID                       Byte0 : ProtocolID
		Byte1 : SID                             Byte1 : SID_ACK
		Byte2 : Segment No.                     Byte2 : Segment No.
		Byte3:  Data Count                      Byte3 : ErrorCode
		Byte4:  Data Count                      Byte4:  TX Timestamp
		Byte5:  TX Flags                        Byte5:  TX Timestamp
		Byte6:  TX Flags                        Byte6:  TX Timestamp
		Byte7:  TX Flags                        Byte7:  TX Timestamp
		Byte8:  TX Flags
		Byte9:  Onwards Databytes including header
******************************************************************************/
J2534ERROR CDeviceOEMTool::SendECUMessage(PASSTHRU_MSG* pstPassThruMsg, unsigned char ucChannelId)
{


//#ifdef GARUDA_HID
#ifdef GARUDA_TCP
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	BOOL bTxInProgress = FALSE;
	BOOL bFirstFrmIndication = FALSE;
	int nDataOffSet = 0;
	unsigned long  nIndex = 0;
	unsigned long  nDataWriteIndex = 0;
	DWORD dwWaitStatus;

	LogToDebugFile("SendECUMessage", DEBUGLOG_TYPE_COMMENT, "SendECUMessage called");

	uchDataBuffer[0] = ucChannelId; //m_enChannelList[m_nChannelID]//ucChannelId;//nikhiltest_deleted
	uchDataBuffer[1] = ECU_SENDMESSAGE;
	uchDataBuffer[2] = 0x00; /* Segment Id. */
	uchDataBuffer[3] = (unsigned char)(pstPassThruMsg->ulDataSize & 0xFF);
	uchDataBuffer[4] = (unsigned char)(pstPassThruMsg->ulDataSize >> 8 & 0xFF);
	uchDataBuffer[5] = (unsigned char)(pstPassThruMsg->ulTxFlags & 0x000000FF);
	uchDataBuffer[6] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 8 & 0x000000FF);
	uchDataBuffer[7] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 16 & 0x000000FF);
	uchDataBuffer[8] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);

	/* Write specific bytes to the USB device.If the data length exceeds 54,
	the data array will be divided into several arrays with each containing
	64 bytes. The 0-54 byte of the array is sent first,then the 55-116 byte
	and then 117-177 and so on. */

	/* If data length is zero then return error */
	if (pstPassThruMsg->ulDataSize == 0)
	{
		m_ulLastErrorCode = J2534_ERR_FAILED;
		return m_ulLastErrorCode;
	}

	ResetEvent(m_CmdAck);
	g_pstPassThruMsg = pstPassThruMsg;

	/* if data length is <55, data shall be sent on single USB frame*/
	if (pstPassThruMsg->ulDataSize <= 55)
	{
		memcpy(&uchDataBuffer[9], pstPassThruMsg->ucData, 55);
		WriteOutputReport(uchDataBuffer, OUTPUTREPORTMAX);
	}
	else /* Data length >54 data shall be sent on multiple USB frames*/
	{
		/* Indicate segmented data transfer */
		uchDataBuffer[2] = 1;
		do
		{
			bTxInProgress = TRUE;
			if (FALSE == bFirstFrmIndication)
			{
				nDataOffSet = 9; /* 9 bytes of First Segmented msg header */
				bFirstFrmIndication = !FALSE; /* Set flag */
			}
			else
			{
				nDataOffSet = 3; /* 3 bytes of Intermediate Segmented msg header */
			}

			for (nIndex = 0; ((nDataOffSet + nIndex) < OUTPUTREPORTMAX) &&
				((nDataWriteIndex + nIndex) < pstPassThruMsg->ulDataSize); nIndex++)
			{
				uchDataBuffer[nDataOffSet + nIndex] = pstPassThruMsg->ucData[nDataWriteIndex + nIndex];
			}

			/*Send data to device*/
			WriteOutputReport(uchDataBuffer, OUTPUTREPORTMAX);

			/* Save the no. data bytes transmitted so far */
			nDataWriteIndex = nDataWriteIndex + nIndex;

			if (nDataWriteIndex == pstPassThruMsg->ulDataSize)
			{
				bTxInProgress = FALSE;
				bFirstFrmIndication = FALSE; /* Reset flag */
			}



			/* Indicate segmented data transfer */
			uchDataBuffer[2]++;

		} while (FALSE != bTxInProgress);
	}

	/* Read Input Report needs to check for write message ACK */
	m_ulLastErrorCode = J2534_ERR_FAILED;

	dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
	switch (dwWaitStatus)
	{
	case WAIT_OBJECT_0:
	{
		if (bufCmdAck[2] == ECU_SENDMESSAGE_ACK)
		{
			if (bufCmdAck[3] == J2534_STATUS_NOERROR)
			{
				// Write to Log File.*/
				sprintf(szBuffer, "SendCANMessage returned 0x%02X", J2534_STATUS_NOERROR);
				LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendCANECUMessage()");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
				m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
			}
		}
		break;
	}
	case WAIT_TIMEOUT:
	{
		m_ulLastErrorCode = J2534_ERR_TIMEOUT;
		break;
	}
	default:
	{
		break;
	}
	}
	return m_ulLastErrorCode;

#endif 

#ifdef GARUDA_BULK

	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	unsigned char uchDataBuffer[512];
	ZeroMemory(uchDataBuffer, 512);
	BOOL bTxInProgress = FALSE;
	BOOL bFirstFrmIndication = FALSE;
	int nDataOffSet = 0;
	unsigned long  nIndex = 0;
	unsigned long  nDataWriteIndex = 0;
	DWORD dwWaitStatus;

	// Write to Log File.
	/*if(m_enChannelList[m_nChannelID] == 4)
	{
	LogToDebugFile("SendECUMessage", DEBUGLOG_TYPE_COMMENT, "SendECUMessage called");
	}
	else
	{
	LogToDebugFile("SendISO9141Message", DEBUGLOG_TYPE_COMMENT, "SendISO9141Message called");
}*/

	LogToDebugFile("SendECUMessage", DEBUGLOG_TYPE_COMMENT, "SendECUMessage called");

	uchDataBuffer[0] = ucChannelId; //m_enChannelList[m_nChannelID]//ucChannelId;//nikhiltest_deleted
	uchDataBuffer[1] = ECU_SENDMESSAGE;
	uchDataBuffer[2] = 0x00; /* Segment Id. */
	uchDataBuffer[3] = (unsigned char)(pstPassThruMsg->ulDataSize & 0xFF);
	uchDataBuffer[4] = (unsigned char)(pstPassThruMsg->ulDataSize >> 8 & 0xFF);
	uchDataBuffer[5] = (unsigned char)(pstPassThruMsg->ulTxFlags & 0x000000FF);
	uchDataBuffer[6] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 8 & 0x000000FF);
	uchDataBuffer[7] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 16 & 0x000000FF);
	uchDataBuffer[8] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);

	/* Write specific bytes to the USB device.If the data length exceeds 54,
	the data array will be divided into several arrays with each containing
	64 bytes. The 0-54 byte of the array is sent first,then the 55-116 byte
	and then 117-177 and so on. */

	/* If data length is zero then return error */
	if (pstPassThruMsg->ulDataSize == 0)
	{
		m_ulLastErrorCode = J2534_ERR_FAILED;
		return m_ulLastErrorCode;
	}

	ResetEvent(m_CmdAck);
	g_pstPassThruMsg = pstPassThruMsg;

	/* if data length is <55, data shall be sent on single USB frame*/
	if (pstPassThruMsg->ulDataSize <= 55)
	{
		memcpy(&uchDataBuffer[9], pstPassThruMsg->ucData, 55);
		WriteOutputReport(uchDataBuffer, OUTPUTREPORTMAX);
	}
	else /* Data length >54 data shall be sent on multiple USB frames*/
	{
		unsigned long  nDataIndex = 0;
		unsigned char chSegmentIDx = 0;

		/* Indicate segmented data transfer */
		uchDataBuffer[2] = 1;
		do
		{
			bTxInProgress = TRUE;
			if (FALSE == bFirstFrmIndication)
			{
				nDataOffSet = 9; /* 9 bytes of First Segmented msg header */
				bFirstFrmIndication = !FALSE; /* Set flag */
			}
			else
			{
				nDataOffSet = 3; /* 3 bytes of Intermediate Segmented msg header */
			}

			for (nIndex = 0; ((nDataOffSet + nIndex) < OUTPUTREPORTMAX) &&
				((nDataWriteIndex + nIndex) < pstPassThruMsg->ulDataSize); nIndex++)
			{
				uchDataBuffer[nDataOffSet + nIndex] = pstPassThruMsg->ucData[nDataWriteIndex + nIndex];
			}

			/*Send data to device*/
			//WriteOutputReport(uchDataBuffer,OUTPUTREPORTMAX);

			/* Save the no. data bytes transmitted so far */
			nDataWriteIndex = nDataWriteIndex + nIndex;

			nDataIndex = nDataIndex + nIndex;

			chSegmentIDx = chSegmentIDx + 1;

			uchDataBuffer[nDataIndex + 0] = ucChannelId; //m_enChannelList[m_nChannelID]//ucChannelId;//nikhiltest_deleted
			uchDataBuffer[nDataIndex + 1] = ECU_SENDMESSAGE;
			uchDataBuffer[nDataIndex + 2] = chSegmentIDx; /* Segment Id. */
			uchDataBuffer[nDataIndex + 3] = (unsigned char)(pstPassThruMsg->ulDataSize & 0xFF);
			uchDataBuffer[nDataIndex + 4] = (unsigned char)(pstPassThruMsg->ulDataSize >> 8 & 0xFF);
			uchDataBuffer[nDataIndex + 5] = (unsigned char)(pstPassThruMsg->ulTxFlags & 0x000000FF);
			uchDataBuffer[nDataIndex + 6] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 8 & 0x000000FF);
			uchDataBuffer[nDataIndex + 7] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 16 & 0x000000FF);
			uchDataBuffer[nDataIndex + 8] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);

			if (nDataWriteIndex == pstPassThruMsg->ulDataSize)
			{
				bTxInProgress = FALSE;
				bFirstFrmIndication = FALSE; /* Reset flag */
			}

			/* Indicate segmented data transfer */
			//uchDataBuffer[2]++;

		} while (FALSE != bTxInProgress);

		if (dev)
		{
			if (usb_bulk_write(dev, EP_OUT, (char*)&uchDataBuffer[0], nDataIndex, 1000)
				!= index)
			{
				TRACE("error: bulk write failed\n");
			}
			else
			{
				TRACE("error: bulk write Success\n");
				//ret_stat= FALSE;
			}
		}
	}

	/* Read Input Report needs to check for write message ACK */
	m_ulLastErrorCode = J2534_ERR_FAILED;

	dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
	switch (dwWaitStatus)
	{
	case WAIT_OBJECT_0:
	{
		if (bufCmdAck[2] == ECU_SENDMESSAGE_ACK)
		{
			if (bufCmdAck[3] == J2534_STATUS_NOERROR)
			{
				/*if((m_bLoopBack == TRUE) && (!((ucChannelId==0x05) || (ucChannelId ==0x90))))
				{
					pstPassThruMsg->ulRxStatus = 0x01;
					pstPassThruMsg->ulExtraDataIndex = pstPassThruMsg->ulDataSize;
					/*Jayasheela -ntohl is not required bcz:lsb should come first

					pstPassThruMsg->ulTimeStamp=0x00000000;
					for(int nIndex = 8; nIndex > 4; nIndex--)
					{
						pstPassThruMsg->ulTimeStamp = pstPassThruMsg->ulTimeStamp << 0x08;
						pstPassThruMsg->ulTimeStamp += bufCmdAck[nIndex];
					}
					if(pstPassThruMsg->ulTxFlags & CAN_29BIT_ID)
					{
						pstPassThruMsg->ucData[0] = pstPassThruMsg->ucData[0] & 0x3F;
					}
					else
					{
						pstPassThruMsg->ucData[0] = pstPassThruMsg->ucData[0] & 0x00;
						pstPassThruMsg->ucData[1] = pstPassThruMsg->ucData[1] & 0x00;
						pstPassThruMsg->ucData[2] = pstPassThruMsg->ucData[2] & 0x0F;
					}
					/* LOOPBACK Message
					RxfunCallBack[pstPassThruMsg->ulProtocolID](pstPassThruMsg, gpVoid[pstPassThruMsg->ulProtocolID]);
				}*/

				// Write to Log File.
				sprintf(szBuffer, "SendCANMessage returned 0x%02X", J2534_STATUS_NOERROR);
				LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendCANECUMessage()");
				m_ulLastErrorCode = J2534_STATUS_NOERROR;
			}
			else
			{
				m_ulLastErrorCode = (J2534ERROR)bufCmdAck[4];
			}
		}
		break;
	}
	case WAIT_TIMEOUT:
	{
		m_ulLastErrorCode = J2534_ERR_TIMEOUT;
		break;
	}
	default:
	{
		break;
	}
	}
	return m_ulLastErrorCode;

#endif 
	
}

/******************************************************************************/
/*					ISO15765 I M P L E M E N T A T I O N		              */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::DecomposeISO15765Message(unsigned char* ucdata,
	short nDataLength,
	unsigned long ulFlags)
{
	unsigned int msg_id;
	int	nOffset = 0;
	BYTE bLength = 0;
	unsigned char ucExtAddrByte = 0;
	CCanMsg* pCan;
	short sCmpDatalength;
	msg_id = ntohl(ulong(ucdata[0]));

	if (ulFlags & ISO15765_ADDR_TYPE)
	{
		nDataLength -= 5; // remove message id from data
		sCmpDatalength = 6;
	}
	else
	{
		nDataLength -= 4; // remove message id from data
		sCmpDatalength = 7;
	}
	ucdata += 4;

	//Build Single Frame
	if (nDataLength <= sCmpDatalength)
	{
		pCan = new CCanMsg;

		pCan->_msg_id = msg_id;

		/* Ravi : Store the Txflags here */
		pCan->_ulTxflags = ulFlags;

		/* Check for Extended address flag set */
		if (ulFlags & ISO15765_ADDR_TYPE)
		{
			pCan->_data[nOffset++] = *ucdata;
			ucdata += 1;
			/* construct the PCI byte */
			pCan->_data[nOffset++] = 0x00 | (nDataLength);
			/* Calculate how many data bytes need to be sent in this frame */
			pCan->_data_len = nDataLength + 2; // for PCI byte
		}
		else
		{
			/* construct the PCI byte */
			pCan->_data[nOffset++] = 0x00 | (nDataLength);
			/* Calculate how many data bytes need to be sent in this frame */
			pCan->_data_len = nDataLength + 1; // for PCI byte
		}


		memcpy(&pCan->_data[nOffset], ucdata, nDataLength);
		nOffset += nDataLength;

		/*Checking for padding*/
		if (ulFlags & ISO15765_FRAME_PAD)
		{
			memset(&pCan->_data[nOffset], 0x00, (8 - nOffset));

			pCan->_data_len = 8;
		}

		m_TxList.Add(pCan);


	}
	else /*Build First Frame*/
	{
		pCan = new CCanMsg;
		pCan->_msg_id = msg_id;

		/* Ravi : Store the Txflags here */
		pCan->_ulTxflags = ulFlags;

		memset(pCan->_data, 0, sizeof(pCan->_data));

		/*Check if Extended address is needed*/
		if (ulFlags & ISO15765_ADDR_TYPE)
		{
			pCan->_data[nOffset++] = *ucdata;
			ucExtAddrByte = *ucdata;
			/* construct the PCI byte */
			pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
			pCan->_data[nOffset++] = LOBYTE(nDataLength);
		}
		else
		{
			/* construct the PCI byte */
			pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
			pCan->_data[nOffset++] = LOBYTE(nDataLength);
		}

		pCan->_data_len = 8;
		bLength = 8 - nOffset;

		/*Copy the data if Extended address is needed*/
		if (ulFlags & ISO15765_ADDR_TYPE)
		{
			ucdata = ucdata + 1;
			for (int i = 0; i < bLength; ++i)
			{
				pCan->_data[nOffset++] = *ucdata++;
				nDataLength--;
			}
		}
		else
		{
			for (int i = 0; i < bLength; ++i)
			{
				pCan->_data[nOffset++] = *ucdata++;
				nDataLength--;
			}
		}

		m_TxList.Add(pCan);
		//Build Consecutive Frame(s)
		unsigned char frame_num = 0x21;
		while (nDataLength)
		{
			nOffset = 0;
			pCan = new CCanMsg;
			memset(pCan->_data, 0, sizeof(pCan->_data));
			pCan->_msg_id = msg_id;

			/*Jayasheela-store tx flag */
			pCan->_ulTxflags = ulFlags;

			if (nDataLength < 7)
			{
				if (ulFlags & ISO15765_FRAME_PAD)
				{
					pCan->_data_len = 8;
				}
				else
				{
					if (ulFlags & ISO15765_ADDR_TYPE)
					{
						pCan->_data_len = nDataLength + 2; // for PCI byte
					}
					else
					{
						pCan->_data_len = nDataLength + 1; // for PCI byte
					}
				}
			}
			else
			{
				pCan->_data_len = 8;
			}
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
				pCan->_data[nOffset++] = ucExtAddrByte;
			}

			pCan->_data[nOffset++] = frame_num;

			if (frame_num == 0x2F)
				frame_num = 0x20;
			else
				frame_num++;


			bLength = 8 - nOffset;
			/* calculate how many data bytes need to be sent in this frame */
			for (int i = 0; i < bLength && nDataLength > 0; ++i)
			{
				pCan->_data[nOffset++] = *ucdata++;
				nDataLength--;
			}

			/*Checking for padding*/
			// Ravi : Jayasheela to check if the padding is needed for non Flowcontrol messages
			// IF needed then we need to pad the CF less than DL of 8 bytes here

			m_TxList.Add(pCan);

		}
	}

	return J2534_STATUS_NOERROR;
}

/******************************************************************************/
/*					ISO15765 I M P L E M E N T A T I O N		              */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::DecomposeFDISO15765Message(unsigned char* ucdata,
	short nDataLength,
	unsigned long ulFlags)
{
	short pdu = nDataLength - 4;
	unsigned int msg_id;
	int	nOffset = 0;
	BYTE bLength = 0;
	unsigned char ucExtAddrByte = 0;
	CCanMsg* pCan;
	short sCmpDatalength;
	msg_id = ntohl(ulong(ucdata[0]));
	if (ulFlags & ISO15765_ADDR_TYPE)
	{
		nDataLength -= 5; // remove message id from data
		sCmpDatalength = 6;
	}
	else
	{
		nDataLength -= 4; // remove message id from datadat
		sCmpDatalength = 7;
	}


	int overhead = (ulFlags & ISO15765_ADDR_TYPE) ? 2 : 1;
	int totalLength = pdu + overhead;//overhead;

	if (totalLength <= 8)
		m_FD_ISO15765_DATA_LENGTH = 8;
	else if (totalLength < 12)
		m_FD_ISO15765_DATA_LENGTH = 12;
	else if (totalLength < 16)
		m_FD_ISO15765_DATA_LENGTH = 16;
	else if (totalLength < 20)
		m_FD_ISO15765_DATA_LENGTH = 20;
	else if (totalLength < 24)
		m_FD_ISO15765_DATA_LENGTH = 24;
	else if (totalLength < 32)
		m_FD_ISO15765_DATA_LENGTH = 32;
	else if (totalLength < 48)
		m_FD_ISO15765_DATA_LENGTH = 48;
	else
		m_FD_ISO15765_DATA_LENGTH = 64;

/*	if (nDataLength <= 8)
	{
		m_FD_ISO15765_DATA_LENGTH = 8;
	}
	else if (nDataLength <=12)
	{
		m_FD_ISO15765_DATA_LENGTH = 12;
	}	
	else if (nDataLength <= 16)
	{
		m_FD_ISO15765_DATA_LENGTH = 16;
	}
	else if (nDataLength <= 20)
	{
		m_FD_ISO15765_DATA_LENGTH = 20;
	}
	else if (nDataLength <= 24)
	{
		m_FD_ISO15765_DATA_LENGTH = 24;
	}
	else if (nDataLength <= 32)
	{
		m_FD_ISO15765_DATA_LENGTH = 32;
	}
	else if (nDataLength <= 48)
	{
		m_FD_ISO15765_DATA_LENGTH = 48;
	}
	else
	{
		m_FD_ISO15765_DATA_LENGTH = 64;
	}*/
	ucdata += 4;
	//construct single frame
	if (m_FD_ISO15765_DATA_LENGTH <= 8) 
	{
		if ((nDataLength <= sCmpDatalength))
		{
			pCan = new CCanMsg;

			pCan->_msg_id = msg_id;

			/* Ravi : Store the Txflags here */
			pCan->_ulTxflags = ulFlags;

			/* Check for Extended address flag set */
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
				pCan->_data[nOffset++] = *ucdata;
				ucdata += 1;
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00 | (nDataLength);
				/* Calculate how many data bytes need to be sent in this frame */
				pCan->_data_len = nDataLength + 2; // for PCI byte
			}
			else
			{
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00 | (nDataLength);
				/* Calculate how many data bytes need to be sent in this frame */
				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;//nDataLength + 1; // for PCI byte
			}


			memcpy(&pCan->_data[nOffset], ucdata, nDataLength);
			nOffset += nDataLength;

			/*Checking for padding*/
			if (ulFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (m_FD_ISO15765_DATA_LENGTH - nOffset));

				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
			}

			m_TxList.Add(pCan);
		}
		else
		{
			pCan = new CCanMsg;
			pCan->_msg_id = msg_id;

			/* Ravi : Store the Txflags here */
			pCan->_ulTxflags = ulFlags;

			memset(pCan->_data, 0, sizeof(pCan->_data));

			/*Check if Extended address is needed*/
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
				pCan->_data[nOffset++] = *ucdata;
				ucExtAddrByte = *ucdata;
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
				pCan->_data[nOffset++] = LOBYTE(nDataLength);
			}
			else
			{
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
				pCan->_data[nOffset++] = LOBYTE(nDataLength);
			}

			pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
			bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;

			/*Copy the data if Extended address is needed*/
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
				ucdata = ucdata + 1;
				for (int i = 0; i < bLength; ++i)
				{
					pCan->_data[nOffset++] = *ucdata++;
					nDataLength--;
				}
			}
			else
			{
				for (int i = 0; i < bLength; ++i)
				{
					pCan->_data[nOffset++] = *ucdata++;
					nDataLength--;
				}
			}

			m_TxList.Add(pCan);
			//Build Consecutive Frame(s)
			unsigned char frame_num = 0x21;
			while (nDataLength)
			{
				nOffset = 0;
				pCan = new CCanMsg;
				memset(pCan->_data, 0, sizeof(pCan->_data));
				pCan->_msg_id = msg_id;

				/*Jayasheela-store tx flag */
				pCan->_ulTxflags = ulFlags;

				if (nDataLength < m_FD_ISO15765_DATA_LENGTH - 1)
				{
					if (ulFlags & ISO15765_FRAME_PAD)
					{
						pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
					}
					else
					{
						if (ulFlags & ISO15765_ADDR_TYPE)
						{
							pCan->_data_len = nDataLength + 2; // for PCI byte
						}
						else
						{
							pCan->_data_len = nDataLength + 1; // for PCI byte
						}
					}
				}
				else
				{
					pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
				}
				if (ulFlags & ISO15765_ADDR_TYPE)
				{
					pCan->_data[nOffset++] = ucExtAddrByte;
				}

				pCan->_data[nOffset++] = frame_num;

				if (frame_num == 0x2F)
					frame_num = 0x20;
				else
					frame_num++;


				bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;
				/* calculate how many data bytes need to be sent in this frame */
				for (int i = 0; i < bLength && nDataLength > 0; ++i)
				{
					pCan->_data[nOffset++] = *ucdata++;
					nDataLength--;
				}

				/*Checking for padding*/
				// Ravi : Jayasheela to check if the padding is needed for non Flowcontrol messages
				// IF needed then we need to pad the CF less than DL of 8 bytes here

				m_TxList.Add(pCan);
			}
		}
	}

	else
	{
		//construct can fd single frame
	//	if ((pdu < (m_FD_ISO15765_DATA_LENGTH - 1)))
		if ((pdu + overhead <=m_FD_ISO15765_DATA_LENGTH) && (pdu < 63))//overhead
		{
			pCan = new CCanMsg;

			pCan->_msg_id = msg_id;

			/* Ravi : Store the Txflags here */
			pCan->_ulTxflags = ulFlags;

			/* Check for Extended address flag set */
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
		/*		pCan->_data[nOffset++] = 0x00;
				/* Calculate how many data bytes need to be sent in this frame 
				pCan->_data[nOffset++] = nDataLength;
				pCan->_data_len = nDataLength + 2; // for PCI byte*/
				pCan->_data[nOffset++] = *ucdata++;
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00 ;
				pCan->_data[nOffset++] = nDataLength;
				/* Calculate how many data bytes need to be sent in this frame */
			//	pCan->_data_len = nDataLength + 3; // for PCI byte
				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
			}
			else
			{
				/* construct the PCI byte */
				pCan->_data[nOffset++] = 0x00;
				/* Calculate how many data bytes need to be sent in this frame */
				pCan->_data[nOffset++] = nDataLength;
			//	pCan->_data_len = nDataLength + 2; // for PCI byte
				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
			}


/*			memcpy(&pCan->_data[nOffset], ucdata, nDataLength);
			nOffset += nDataLength;*/
			bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;
			/*Copy the data if Extended address is needed*/
			if (ulFlags & ISO15765_ADDR_TYPE)
			{
				ucdata = ucdata + 1;
				for (int i = 0; i < bLength; ++i)
				{
					pCan->_data[nOffset++] = *ucdata++;
					nDataLength--;
				}
			}
			else
			{
				for (int i = 0; i < bLength; ++i)
				{
					pCan->_data[nOffset++] = *ucdata++;
					nDataLength--;
				}
			}

			/*Checking for padding*/
			if (ulFlags & ISO15765_FRAME_PAD)
			{
				memset(&pCan->_data[nOffset], 0x00, (m_FD_ISO15765_DATA_LENGTH - nOffset));

				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
			}

			m_TxList.Add(pCan);
		}

		else
		{   //construct canfd single frame with normal CAN_TP

			if (pdu <= 4095)
			{
				pCan = new CCanMsg;
				pCan->_msg_id = msg_id;

				/* Ravi : Store the Txflags here */
				pCan->_ulTxflags = ulFlags;

				memset(pCan->_data, 0, sizeof(pCan->_data));

				/*Check if Extended address is needed*/
				if (ulFlags & ISO15765_ADDR_TYPE)
				{
					pCan->_data[nOffset++] = *ucdata;
					ucExtAddrByte = *ucdata;
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
					pCan->_data[nOffset++] = LOBYTE(nDataLength);
				}
				else
				{
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x10 | (HIBYTE(nDataLength));
					pCan->_data[nOffset++] = LOBYTE(nDataLength);
				}

				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
				bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;

				/*Copy the data if Extended address is needed*/
				if (ulFlags & ISO15765_ADDR_TYPE)
				{
					ucdata = ucdata + 1;
					for (int i = 0; i < bLength; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}
				}
				else
				{
					for (int i = 0; i < bLength; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}
				}

				m_TxList.Add(pCan);
				//Build Consecutive Frame(s)
				unsigned char frame_num = 0x21;
				while (nDataLength)
				{
					nOffset = 0;
					pCan = new CCanMsg;
					memset(pCan->_data, 0, sizeof(pCan->_data));
					pCan->_msg_id = msg_id;

					/*Jayasheela-store tx flag */
					pCan->_ulTxflags = ulFlags;

					if (nDataLength < m_FD_ISO15765_DATA_LENGTH - 1)
					{
						if (ulFlags & ISO15765_FRAME_PAD)
						{
							pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
						}
						else
						{
							if (ulFlags & ISO15765_ADDR_TYPE)
							{
								pCan->_data_len = nDataLength + 2; // for PCI byte
							}
							else
							{
								pCan->_data_len = nDataLength + 1; // for PCI byte
							}
						}
					}
					else
					{
						pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
					}
					if (ulFlags & ISO15765_ADDR_TYPE)
					{
						pCan->_data[nOffset++] = ucExtAddrByte;
					}

					pCan->_data[nOffset++] = frame_num;

					if (frame_num == 0x2F)
						frame_num = 0x20;
					else
						frame_num++;


					bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;
					/* calculate how many data bytes need to be sent in this frame */
					for (int i = 0; i < bLength && nDataLength > 0; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}

					/*Checking for padding*/
					// Ravi : Jayasheela to check if the padding is needed for non Flowcontrol messages
					// IF needed then we need to pad the CF less than DL of 8 bytes here

					m_TxList.Add(pCan);
				}
			}
			//construct CANFD first frame with morethan 4095 bytes
			else
			{
				pCan = new CCanMsg;
				pCan->_msg_id = msg_id;

				/* Ravi : Store the Txflags here */
				pCan->_ulTxflags = ulFlags;

				memset(pCan->_data, 0, sizeof(pCan->_data));

				/*Check if Extended address is needed*/
				if (ulFlags & ISO15765_ADDR_TYPE)
				{
					pCan->_data[nOffset++] = *ucdata;
					ucExtAddrByte = *ucdata;
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x10;
					pCan->_data[nOffset++] = 0x00;
					pCan->_data[nOffset++] = nDataLength >> 24 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength >> 16 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength >> 8 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength & 0x000000FF;
				}
				else
				{
					/* construct the PCI byte */
					pCan->_data[nOffset++] = 0x10;
					pCan->_data[nOffset++] = 0x00;
					pCan->_data[nOffset++] = nDataLength >> 24 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength >> 16 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength >> 8 & 0x000000FF;
					pCan->_data[nOffset++] = nDataLength & 0x000000FF;
				}

				pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
				bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;

				/*Copy the data if Extended address is needed*/
				if (ulFlags & ISO15765_ADDR_TYPE)
				{
					ucdata = ucdata + 1;
					for (int i = 0; i < bLength; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}
				}
				else
				{
					for (int i = 0; i < bLength; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}
				}

				m_TxList.Add(pCan);
				//Build Consecutive Frame(s)
				unsigned char frame_num = 0x21;
				while (nDataLength)
				{
					nOffset = 0;
					pCan = new CCanMsg;
					memset(pCan->_data, 0, sizeof(pCan->_data));
					pCan->_msg_id = msg_id;

					/*Jayasheela-store tx flag */
					pCan->_ulTxflags = ulFlags;

					if (nDataLength < m_FD_ISO15765_DATA_LENGTH - 1)
					{
						if (ulFlags & ISO15765_FRAME_PAD)
						{
							pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
						}
						else
						{
							if (ulFlags & ISO15765_ADDR_TYPE)
							{
								pCan->_data_len = nDataLength + 2; // for PCI byte
							}
							else
							{
								pCan->_data_len = nDataLength + 1; // for PCI byte
							}
						}
					}
					else
					{
						pCan->_data_len = m_FD_ISO15765_DATA_LENGTH;
					}
					if (ulFlags & ISO15765_ADDR_TYPE)
					{
						pCan->_data[nOffset++] = ucExtAddrByte;
					}

					pCan->_data[nOffset++] = frame_num;

					if (frame_num == 0x2F)
						frame_num = 0x20;
					else
						frame_num++;


					bLength = m_FD_ISO15765_DATA_LENGTH - nOffset;
					/* calculate how many data bytes need to be sent in this frame */
					for (int i = 0; i < bLength && nDataLength > 0; ++i)
					{
						pCan->_data[nOffset++] = *ucdata++;
						nDataLength--;
					}

					/*Checking for padding*/
					// Ravi : Jayasheela to check if the padding is needed for non Flowcontrol messages
					// IF needed then we need to pad the CF less than DL of 8 bytes here

					m_TxList.Add(pCan);
				}
			}
		}
	}
	return J2534_STATUS_NOERROR;
}

J2534ERROR CDeviceOEMTool::SendISO15765Messages(unsigned long ucProtocolid)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	int block_size = 0;
	int seperation_time = 0;
	const int num_frames = m_TxList.GetSize();
	double  elapsedTime;
	PASSTHRU_MSG pstPassThruMsg;
	memset(&pstPassThruMsg, 0, sizeof(PASSTHRU_MSG));
	if (num_frames == 0)
		return J2534_ERR_FAILED;

	// send First frame
	int frame_index = 0;
	CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);

	if (frame_index < num_frames)
	{
		ResetEvent(m_FlowControlEvent);
		m_bFlowControlIssued = TRUE;
	}

	ulIS015765_USB_Packets = 0;


	if (num_frames == 1)
	{
		ulIS015765_USB_Packets = 1;
	}

	/*Send Message to the network*/
	/*Send Message to the network*/
	enJ2534Error = SendToDevice(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
	//TRACE("Before Multi Con Frames : %X %X %X\n",pCan->_data[0],pCan->_data[1],pCan->_data[2]);
	if (enJ2534Error != J2534_STATUS_NOERROR)
	{
		TRACE("First Frame not Transmitted\n");
		return enJ2534Error;
	}
	// Process Multi Frame
	while (frame_index < num_frames)
	{
		//Amit Commented for waiting for flow control message 

		// process flow control frame
		DWORD dwWaitStatus;
		//ResetEvent(m_FlowControlEvent);
		//m_bFlowControlIssued = TRUE;

		///////////////////////////////////////////////////////////////////////
		// Commented below code to handle TP in Firmware

#define TATAMOTORS_SUPPORT		
#ifdef  TATAMOTORS_SUPPORT
		dwWaitStatus = WaitForSingleObject(m_FlowControlEvent, 4000);

		if (dwWaitStatus == WAIT_TIMEOUT)
		{
			m_bFlowControlIssued = FALSE;
			TRACE("m_FlowControlEvent Timed Out \n");
			return J2534_ERR_NO_FLOW_CONTROL;
		}
		else
		{
			TRACE("m_FlowControlEvent not  Timed Out \n");
			if ((objFlowControlFrm._data[0] & 0xf0) == 0x30)
			{
				m_bFlowControlIssued = FALSE;
			}
			else
			{
				m_bFlowControlIssued = FALSE;
				return J2534_ERR_NO_FLOW_CONTROL;
			}
		}
#endif


		/*If the block size and seperation time is between 0x00 and 0xFF, the flow control
		value reported by the vehicle should be ignored.if the value is 0xFFFF use the
		value reported by the vehicle*/

		if ((m_nBlockSizeTx >= 0x00) && (m_nBlockSizeTx <= 0x000000FF))
			block_size = m_nBlockSizeTx;
		else if (m_nBlockSizeTx == 0xFFFF)
			block_size = objFlowControlFrm._data[1];

		if (m_nSTminTx >= 0x00 && m_nSTminTx <= 0xFF)
			seperation_time = m_nSTminTx;
		else
			seperation_time = objFlowControlFrm._data[2];


		if (frame_index < num_frames)
		{
			ResetEvent(m_FlowControlEvent);
			m_bFlowControlIssued = TRUE;
			//QueryPerformanceCounter(&t1);
			//QueryPerformanceFrequency(&frequency);
		}

		// block_size of zero -> send remaining frames in message
		if (block_size == 0)
			block_size = num_frames;


		if (ulIS015765_USB_Packets == 0)
		{

			if ((num_frames - 1) <= block_size)
			{
				ulIS015765_USB_Packets += (num_frames - 1) / 7;//62

				if (((num_frames - 1) % 7) != 0)//62
				{
					ulIS015765_USB_Packets++;
				}
			}
			else
			{
				unsigned long ulFrames = (num_frames - 1);
				while (ulFrames > block_size)
				{
					ulIS015765_USB_Packets += block_size / 7;//62

					if ((block_size % 7) != 0)//62
					{
						ulIS015765_USB_Packets++;
					}
					ulFrames = ulFrames - block_size;
				}

				if (ulFrames > 0)
				{
					ulIS015765_USB_Packets++;
				}
			}
		}

		/*ulIS015765_USB_Packets+=(num_frames-1)/block_size;

		if(((num_frames-1)%block_size)!=0)
		{
			ulIS015765_USB_Packets++;
		}


		ulIS015765_USB_Packets+=block_size/7;

		if((block_size%7)!=0)
		{
			ulIS015765_USB_Packets++;
		}*/

#ifdef GARUDA_TOOL
		/*Jayasheela-modified to send multiple consecutive frames in a single USB frame */
		//if(seperation_time  == 0)
		if (1)
		{
			if ((ucProtocolid == ISO15765) || (ucProtocolid == SW_ISO15765_PS) || (ucProtocolid == ISO15765_CH1))
			{
				enJ2534Error = SendISO15765MsgToDevice(num_frames, block_size, &frame_index, seperation_time);
			}
			else
				enJ2534Error = SendFDISO15765MsgToDevice(num_frames, block_size, &frame_index, seperation_time);

			if (enJ2534Error != J2534_STATUS_NOERROR)
			{
				return enJ2534Error;
			}
		}
		else
		{

			// send block (multiple frames)
			for (int i = 0; i < block_size && (frame_index < num_frames); ++i)
			{
				//DWORD dwStartTick = GetTickCount();
				// start timer


				t2.QuadPart = 0;

				// get ticks per second

				if (i != 0)
				{
					t1.QuadPart = 0;
					QueryPerformanceCounter(&t1);
				}

				//if (seperation_time > 0)
				//	::Sleep (seperation_time);
				//while((GetTickCount() - dwStartTick) <= seperation_time);
				while (true)
				{
					QueryPerformanceCounter(&t2);
					elapsedTime = (t2.QuadPart - t1.QuadPart) / (frequency.QuadPart / 1000);
					if ((int)elapsedTime >= (seperation_time - 1))
					{
						break;
					}
				}

				pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);
				enJ2534Error = SendToDevice(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
				if (enJ2534Error != J2534_STATUS_NOERROR)
				{
					return enJ2534Error;
				}

			}
		}

#else
		// send block (multiple frames)
		for (int i = 0; i < block_size && (frame_index < num_frames); ++i)
		{
			if (seperation_time > 0)
				::Sleep(seperation_time);
			pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);
			/*Send Message to the network*/
			//Sleep(1);
			//TRACE("Con Frames : %d %d %d\n",pCan->_data[0],pCan->_data[1],pCan->_data[2]);
			enJ2534Error = SendToDevice(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
			if (enJ2534Error != J2534_STATUS_NOERROR)
			{
				return enJ2534Error;
			}
		}
#endif

	}
	return enJ2534Error;
}

/******************************************************************************/
/*					J1939 I M P L E M E N T A T I O N		              */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::DecomposeJ1939Message(unsigned char* ucdata,
	short nDataLength,
	unsigned long ulFlags)
{
	unsigned int msg_id;
	int	nOffset = 0;
	BYTE bLength = 0;
	unsigned char ucExtAddrByte = 0;
	CCanMsg* pCan;
	short sCmpDatalength;

	ULONG ulReqHdr;
	UCHAR uchPriority;
	ULONG ulPGN;
	UCHAR uchPDUSpecific;
	UCHAR uchPDUFormat;
	UCHAR uchSrcAddr;
	UCHAR uchDestAddr;

	//To get the message id
	msg_id = ntohl(ulong(ucdata[0]));

	//To get the destination address
	uchDestAddr = ucdata[4];

	//Header is 5 Byte
	//Single Frame Max Hold 8 Bytes Data
	nDataLength -= 5;
	sCmpDatalength = 8;

	//Build Single Frame
	if (nDataLength <= sCmpDatalength)
	{
		pCan = new CCanMsg;

		pCan->_msg_id = msg_id;
		pCan->_ulTxflags = ulFlags;
		pCan->_data_len = nDataLength;

		memcpy(&pCan->_data, ucdata + 5, nDataLength);
		//Padding to 8 Bytes, if datalength less than 8
		if (nDataLength < 8)
		{
			for (int nIdx = nDataLength; nIdx < sCmpDatalength; nIdx++)
			{
				pCan->_data[nIdx] = 0xFF;
			}

			pCan->_data_len = sCmpDatalength;
		}
		m_TxList.Add(pCan);

		//Check for Padding Required or not
	}
	else // Multi Frame
	{
		//To get the J1939 Header Details
		GetPGNParametersFromHeader(msg_id, uchPriority, ulPGN, uchPDUSpecific,
			uchPDUFormat, uchSrcAddr, uchDestAddr);

		//Construct First Frame
		////////////////////////////////////////////////////////////////////////////////
		pCan = new CCanMsg;

		//Compute Header With PGN EC00
		msg_id = ComputeJ1939Header(uchPriority, 0xEC00, uchSrcAddr, ucdata[4]);

		pCan->_msg_id = msg_id;
		pCan->_ulTxflags = ulFlags;
		pCan->_data_len = 8;

		//Fill the control byte
		if (ucdata[4] == 0xFF) // Global Addressing
		{
			pCan->_data[0] = 32; //Control Byte - BAM
		}
		else // Peer to Peer
		{
			pCan->_data[0] = 16; //Control Byte - RTS
		}

		//Fill the dataBytes
		pCan->_data[1] = ((nDataLength >> 0) & 0xFF); //Data Length - Low Byte
		pCan->_data[2] = ((nDataLength >> 8) & 0xFF); //Data Length - High Byte
		pCan->_data[3] = (((nDataLength % 7) == 0) ? (nDataLength / 7) : (nDataLength / 7) + 1) & 0xFF; // Packet Count
		pCan->_data[4] = 0xFF; //Reserved			
		pCan->_data[5] = (ulPGN >> 0) & 0xFF; // PGN - Low Byte
		pCan->_data[6] = (ulPGN >> 8) & 0xFF;
		pCan->_data[7] = (ulPGN >> 16) & 0xFF; // PGN - High Byte

		//Add it to list
		m_TxList.Add(pCan);

		//Construct dataByte Frame
		////////////////////////////////////////////////////////////////////////////////

		UCHAR uchSequenceNo = 0x01;
		while (nDataLength > 0)
		{
			pCan = new CCanMsg;

			//Compute Header With PGN EB00
			msg_id = ComputeJ1939Header(uchPriority, 0xEB00, uchSrcAddr, ucdata[4]);

			pCan->_msg_id = msg_id;
			pCan->_ulTxflags = ulFlags;
			pCan->_data_len = 8;

			pCan->_data[0] = uchSequenceNo;
			memcpy(pCan->_data + 1, ucdata + 5 + ((uchSequenceNo - 1) * 7), (nDataLength >= 7) ? 7 : nDataLength);

			//Padding to 8 Bytes, if datalength less than 7
			if (nDataLength < 7)
			{
				for (int nIdx = nDataLength + 1; nIdx < sCmpDatalength; nIdx++)
				{
					pCan->_data[nIdx] = 0xFF;
				}

				pCan->_data_len = sCmpDatalength;
			}

			//Add it to list
			m_TxList.Add(pCan);

			uchSequenceNo++;
			nDataLength = nDataLength - 7;
		}
	}

	return J2534_STATUS_NOERROR;
}

J2534ERROR CDeviceOEMTool::SendJ1939Messages(unsigned char ucProtocolid)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	int block_size = 0;
	int seperation_time = 0;
	const int num_frames = m_TxList.GetSize();
	double  elapsedTime;
	PASSTHRU_MSG pstPassThruMsg;
	int frame_index = 0;
	CCanMsg* pCan = NULL;
	bool bCTSRequired = FALSE;
	unsigned char uchMaxFramesInUSBPacket = 3;

	memset(&pstPassThruMsg, 0, sizeof(PASSTHRU_MSG));
	ulJ1939_USB_Packets = 0;

	if (num_frames == 0)
		return J2534_ERR_FAILED;

	// Sending First Frame of either BAM / RTS

	//To get the first frame from List
	pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);

	//Reset CTS if no. of Frame > 1
	if (num_frames > 1)
	{
		//Checking whether CTS Required or not
		if (((pCan->_msg_id >> 8) & 0xFF) != 0xFF)
			bCTSRequired = TRUE;

		if (bCTSRequired)
		{
			ResetEvent(m_FlowControlEvent);
			m_bFlowControlIssued = TRUE;
		}
	}
	else
	{
		ulJ1939_USB_Packets = 1;
	}

	//Sending First Frame
	enJ2534Error = SendJ1939SingleMessage(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
	//enJ2534Error = SendToDevice(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags,ucProtocolid);
	if (enJ2534Error != J2534_STATUS_NOERROR)
	{
		TRACE("First Frame not Transmitted\n");
		return enJ2534Error;
	}

	// Process Multi Frame
	while (frame_index < num_frames)
	{
		DWORD dwWaitStatus;
		UCHAR uchNextPacketNo;
		UCHAR uchMaxPacketsSent;

		//Check whether CTS Required or not
		if (bCTSRequired)
		{
			//T3 - Max Wait time for CTS. Default Value is : 1250 + additional buffer we are giving 750 ms
			//T4 - Max Wait time for CTS with Zero Packets and next CTS
			dwWaitStatus = WaitForSingleObject(m_FlowControlEvent, 2000);
			if (dwWaitStatus == WAIT_TIMEOUT)
			{
				m_bFlowControlIssued = FALSE;
				TRACE("m_FlowControlEvent Timed Out \n");
				return J2534_ERR_TIMEOUT;
			}
			else
			{
				TRACE("m_FlowControlEvent not  Timed Out \n");
				if (objFlowControlFrm._data[0] == 0x11)
				{
					//Check whether Sender Src and Receiver Dest Matching or not
					//To get the J1939 Header Details
					unsigned char uchPriority;
					unsigned long ulPGN;
					unsigned char uchPDUSpecific;
					unsigned char uchPDUFormat;
					unsigned char uchSrcAddr;
					unsigned char uchDestAddr;
					unsigned char uchSenderDest;

					//To get the Receiver Source
					GetPGNParametersFromHeader(objFlowControlFrm._msg_id, uchPriority, ulPGN, uchPDUSpecific,
						uchPDUFormat, uchSrcAddr, uchDestAddr);

					//To get the Sender Destination
					uchSenderDest = (unsigned char)((pCan->_msg_id >> 8) & 0xFF);
					if (uchSenderDest != uchSrcAddr)
						return J2534_ERR_FAILED;

					m_bFlowControlIssued = FALSE;
				}
				else
				{
					m_bFlowControlIssued = FALSE;
					return J2534_ERR_FAILED;
				}

				uchNextPacketNo = objFlowControlFrm._data[2];
				frame_index = uchNextPacketNo;
				block_size = uchMaxPacketsSent = objFlowControlFrm._data[1];
			}

			//Reset FlowControl Event
			ResetEvent(m_FlowControlEvent);
			m_bFlowControlIssued = TRUE;
		}
		else
		{
			uchMaxPacketsSent = 0xFF;

			QueryPerformanceCounter(&t1);
			QueryPerformanceFrequency(&frequency);
		}

		//Set the Block Size
		if ((uchMaxPacketsSent == 0) || (uchMaxPacketsSent == 0xFF))
		{
			block_size = num_frames - 1;
		}

		/*If the block size and seperation time is between 0x00 and 0xFF, the flow control
		value reported by the vehicle should be ignored.if the value is 0xFFFF use the
		value reported by the vehicle*/


		// block_size of zero -> send remaining frames in message
		if (block_size == 0)
			block_size = num_frames - 1;


		if (ulJ1939_USB_Packets == 0)
		{
			if ((num_frames - 1) <= block_size)
			{
				ulJ1939_USB_Packets += (num_frames - 1) / uchMaxFramesInUSBPacket;

				if (((num_frames - 1) % uchMaxFramesInUSBPacket) != 0)
				{
					ulJ1939_USB_Packets++;
				}
			}
			else
			{
				unsigned long ulFrames = (num_frames - 1);
				while (ulFrames > block_size)
				{
					ulJ1939_USB_Packets += block_size / uchMaxFramesInUSBPacket;

					if ((block_size % uchMaxFramesInUSBPacket) != 0)
					{
						ulJ1939_USB_Packets++;
					}

					ulFrames = ulFrames - block_size;
				}

				if (ulFrames > 0)
				{
					ulJ1939_USB_Packets++;
				}
			}
		}

#ifdef GARUDA_TOOL
		/*Jayasheela-modified to send multiple consecutive frames in a single USB frame */
		if (m_ulJ1939_BRDCST_MIN_DELAY == 0)
		{
			enJ2534Error = SendJ1939MsgToDevice(num_frames, block_size, &frame_index, seperation_time, !bCTSRequired, uchNextPacketNo);
			if (enJ2534Error != J2534_STATUS_NOERROR)
			{
				return enJ2534Error;
			}
		}
		else
		{

			// send block (multiple frames)
			for (int i = 0; i < block_size && (frame_index < num_frames); ++i)
			{
				//DWORD dwStartTick = GetTickCount();
				// start timer


				t2.QuadPart = 0;

				// get ticks per second

				if (i != 0)
				{
					t1.QuadPart = 0;
					QueryPerformanceCounter(&t1);
				}

				//if (seperation_time > 0)
				//	::Sleep (seperation_time);
				//while((GetTickCount() - dwStartTick) <= seperation_time);
				while (true)
				{
					QueryPerformanceCounter(&t2);
					elapsedTime = (t2.QuadPart - t1.QuadPart) / (frequency.QuadPart / 1000);
					if ((int)elapsedTime >= (m_ulJ1939_BRDCST_MIN_DELAY - 1))
					{
						break;
					}
				}

				pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);
				enJ2534Error = SendJ1939SingleMessage(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
				if (enJ2534Error != J2534_STATUS_NOERROR)
				{
					return enJ2534Error;
				}

			}
		}

#else
		// send block (multiple frames)
		for (int i = 0; i < block_size && (frame_index < num_frames); ++i)
		{
			if (seperation_time > 0)
				::Sleep(seperation_time);
			pCan = (CCanMsg*)m_TxList.GetAt(frame_index++);
			/*Send Message to the network*/
			//Sleep(1);
			//TRACE("Con Frames : %d %d %d\n",pCan->_data[0],pCan->_data[1],pCan->_data[2]);
			enJ2534Error = SendToDevice(pCan->_msg_id, pCan->_data, pCan->_data_len, pCan->_ulTxflags, ucProtocolid);
			if (enJ2534Error != J2534_STATUS_NOERROR)
			{
				return enJ2534Error;
			}
		}
#endif

	}
	return enJ2534Error;
}
/******************************************************************************/
/*  Function Name   :SendJ1939MsgToDevice()                                */
/*  Input Params    :No of frames,blk size,frame index                        */
/*  Output Params   :NULL                                                     */
/*	Description		:Function will send 7 CAN frames in a single USB frame	  */
/*  Return          :J2534ERROR								  .               */
/******************************************************************************/
/*Jayasheela-added to send the multiple consecutive frames in a single USB frame*/
J2534ERROR CDeviceOEMTool::SendJ1939MsgToDevice(const int num_frames, int block_size, int* frame_index, int seperation_time, bool bBAM, unsigned char nStartPacketNo)
{
#ifdef  GARUDA_BULK

	unsigned char uchDataBuffer[512];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendJ1939messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames;
	}

	unsigned int index = 0;
	unsigned int nDataLengthIdx = 0;
	while ((*frame_index) < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		int nFramesInUSB = 0;
		//unsigned int index = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));

		//Set Protocol Id
		uchDataBuffer[index++] = m_enChannelList[m_nChannelID];

		//Set Service Id
		uchDataBuffer[index++] = ECU_SENDMESSAGE;

		//Set Segment Id
		uchDataBuffer[index++] = 0x00;

		//Skipping 2 Bytes for Mode & Data Length
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the mode and data lenght */

		for (int i = 0; i < uchMaxFramesInUSBPacket; i++)
		{
			// Seperation time has to be handled in tx

			nFramesInUSB++;

			//Setting Tx Flags
			uchDataBuffer[index++] = (unsigned char)((ulTxFlags >> 0) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulTxFlags >> 8) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulTxFlags >> 16) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulTxFlags >> 24) & 0xFF);

			//Setting Msg Id
			uchDataBuffer[index++] = (unsigned char)((ulMsgId >> 24) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulMsgId >> 16) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulMsgId >> 8) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((ulMsgId >> 0) & 0xFF);

			//Setting DataLength
			uchDataBuffer[index++] = uchDataLength;

			//Copying DataBytes			
			memcpy(&uchDataBuffer[index], &pCan->_data[0], pCan->_data_len);
			index += pCan->_data_len;

			//To get the next frame from the list
			(*frame_index) += 1;
			if ((*frame_index) < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		uchDataBuffer[nDataLengthIdx + 4] = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		uchDataBuffer[nDataLengthIdx + 3] = (unsigned char)((nTotalDataLength) & 0xFF);

		nDataLengthIdx = nDataLengthIdx + 64;
	}

	if (index > 0)
	{
		if (dev)
		{
			if (usb_bulk_write(dev, EP_OUT, (char*)&uchDataBuffer[0], index, 1000)
				!= index)
			{
				TRACE("error: bulk write failed\n");
			}
			else
			{
				TRACE("error: bulk write Success\n");
				//ret_stat= FALSE;
			}
		}

	}
	return J2534_STATUS_NOERROR;

#endif

//#ifdef  GARUDA_HID
#ifdef GARUDA_TCP
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	unsigned char uchMaxFramesInUSBPacket = 3;

	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames - (*frame_index);
	}

	unsigned long ulNumFramesTransmitted = 0;

	while (ulNumFramesTransmitted < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		unsigned int index = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		int nFramesInUSB = 0;

		//Set Protocol Id
		uchDataBuffer[index++] = m_enChannelList[m_nChannelID];

		//Set Service Id
		uchDataBuffer[index++] = ECU_SENDMESSAGE;

		//Set Segment Id
		uchDataBuffer[index++] = 0x00;

		//Skipping 2 Bytes for Mode & Data Length
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the mode and data lenght */

		for (int i = 0; i < uchMaxFramesInUSBPacket; i++) // Iterate only for Max Msg's place in USB Frame
		{
			// Seperation time has to be handled in J2534 / Firmware

			nFramesInUSB++;

			//Setting Tx Flags
			uchDataBuffer[index++] = (unsigned char)((pCan->_ulTxflags >> 0) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_ulTxflags >> 8) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_ulTxflags >> 16) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_ulTxflags >> 24) & 0xFF);

			//Setting Msg Id
			uchDataBuffer[index++] = (unsigned char)((pCan->_msg_id >> 24) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_msg_id >> 16) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_msg_id >> 8) & 0xFF);
			uchDataBuffer[index++] = (unsigned char)((pCan->_msg_id >> 0) & 0xFF);

			//Setting DataLength
			uchDataBuffer[index++] = pCan->_data_len;

			//Copying DataBytes			
			memcpy(&uchDataBuffer[index], &pCan->_data[0], pCan->_data_len);
			index += pCan->_data_len;

			//Update Frames Transmitted
			ulNumFramesTransmitted++;

			//To get the next frame from the list
			(*frame_index) += 1;
			if (ulNumFramesTransmitted < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}

		//To set the length & Mode
		uchDataBuffer[4] = (unsigned char)(0xC0 | (nFramesInUSB >> 8 & 0xFF));
		uchDataBuffer[3] = (unsigned char)((nFramesInUSB) & 0xFF);

		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		if (WriteOutputReport(uchDataBuffer, 512))//chiru
		{
			return J2534_ERR_FAILED;
		}
		else
		{
			//do nothing
		}
	}
	return J2534_STATUS_NOERROR;

#endif	
	
}

J2534ERROR CDeviceOEMTool::SendToDevice(unsigned int nMsgID, unsigned char* ucData,
	int nDataLength, unsigned long ulFlags, unsigned long ucChannelid)

{

	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	int nTotalDataLength = 0;
	PASSTHRU_MSG pstPassThruMsg;
	unsigned long ulDataIndex = 0;
	int len = 0;
	//BufferCommand_t* pWriteMsgs;
	//pWriteMsgs = (BufferCommand_t*)uchDataBuffer;

	memset(&pstPassThruMsg, 0, sizeof(PASSTHRU_MSG));

	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, "SendToECU start");

	/*Add Message ID length to the data length*/
	nTotalDataLength = nDataLength + 4;
#ifdef GARUDA_TOOL
	/*Jayasheea-check is a EXT ADDR frame */
	if (ulFlags & ISO15765_ADDR_TYPE)
	{
		ulDataIndex = 1;
	}
	else
	{
		ulDataIndex = 0;
	}
	unsigned int index = 0;
	//uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
	//uchDataBuffer[index++] = ucChannelid;
	//uchDataBuffer[index++] = ECU_SENDMESSAGE;
	//uchDataBuffer[index++] = 0x00; /* Segment Id. */
	//index++;	/* Needed to skip the mode and data lenght */
	//index++;	/* Needed to skip the mode and data lenght */


	/* bit15:bit14 indicates mode */
   /* Mode 0,bit15:bit14=0:0 Flow control frame or single frame */
	if ((ucData[ulDataIndex] >> 4) == 0x03 || (ucData[ulDataIndex] >> 4) == 0x00)
	{
		BufferCommand_t* pbuf = NULL;
		Mode0* pWriteMsgs;

		pbuf = (BufferCommand_t*)uchDataBuffer;
		pbuf->proto_id = ucChannelid;
		pbuf->command = ECU_SENDMESSAGE;
		len = sizeof(pbuf->proto_id) + sizeof(pbuf->command);

		pWriteMsgs = (Mode0*)(uchDataBuffer + len);
		pWriteMsgs->segnum = 0x00;
		//uchDataBuffer[4] = (unsigned char)0x00 | ((nTotalDataLength >> 8) & 0xFF);
		pWriteMsgs->Messagelength1 = (unsigned char)0x00 | ((nTotalDataLength >> 8) & 0xFF);
		pWriteMsgs->Messagelength = (unsigned char)((nTotalDataLength) & 0xFF);
		pWriteMsgs->TxFlags = (unsigned long)ulFlags;
		pWriteMsgs->Msg_Id = (unsigned long)SWAP32(&nMsgID);
		memcpy(pWriteMsgs->Data_Bytes, ucData, nDataLength);
		len += sizeof(struct Mode0) + nDataLength;
	}
	/* Mode 1,bit15:bit14=0:1 first frame */
	else if (((ucData[ulDataIndex]) >> 4) == 0x01)
	{
		BufferCommand_t* pbuf = NULL;
		Mode1* pWriteMsgs;
		pbuf = (BufferCommand_t*)uchDataBuffer;
		pbuf->proto_id = ucChannelid;
		pbuf->command = ECU_SENDMESSAGE;
		len = sizeof(pbuf->proto_id) + sizeof(pbuf->command);
		pWriteMsgs = (Mode1*)(uchDataBuffer + len);

		pWriteMsgs->segnum = 0x00;
		//uchDataBuffer[4] = (unsigned char)0x40 | ((nTotalDataLength >> 8) & 0xFF);
		pWriteMsgs->Messagelength1 = (unsigned char)0x40 | ((nTotalDataLength >> 8) & 0xFF);
		pWriteMsgs->Messagelength = (unsigned char)((nTotalDataLength) & 0xFF);
		pWriteMsgs->Conversation_ID = 0x00;
		pWriteMsgs->TxFlags = (unsigned long)ulFlags;
		pWriteMsgs->Msg_Id = (unsigned long)SWAP32(&nMsgID);
		memcpy(pWriteMsgs->Data_Bytes, ucData, nDataLength);
		len += sizeof(struct Mode1) + nDataLength;
		//index++;	/* Needed to skip conversation id */
	}
	else
	{
		//do nothing
	}
	//uchDataBuffer[3] = (unsigned char) ((nTotalDataLength) & 0xFF);

/*	uchDataBuffer[index++] = (unsigned char)(ulFlags & 0x000000FF);
	uchDataBuffer[index++] = (unsigned char)(ulFlags>>8 & 0x000000FF);
	uchDataBuffer[index++] = (unsigned char)(ulFlags>>16 & 0x000000FF);
	uchDataBuffer[index++] = (unsigned char)(ulFlags>>24 & 0x000000FF);*/


	/*	uchDataBuffer[index++] = (unsigned char)(nMsgID >> 24 & 0x000000FF);
		uchDataBuffer[index++] =(unsigned char)(nMsgID >> 16 & 0x000000FF);
		uchDataBuffer[index++] =(unsigned char)(nMsgID >> 8 & 0x000000FF);
		uchDataBuffer[index++] =(unsigned char)(nMsgID & 0x000000FF);*/



		//  memcpy(&pWriteMsgs->u.Writemsgs_TP.Data_Bytes,&ucData[0],nDataLength);

	  //	int len = sizeof(pWriteMsgs->proto_id) + sizeof(pWriteMsgs->command);
	  //	len += sizeof(pWriteMsgs->u.Writemsgs_TP);

		  /*Write the data to the device*/

	  //	if(!WriteOutputReport(uchDataBuffer,(nDataLength + index)))
	if (!WriteOutputReport(uchDataBuffer, len))
		return J2534_STATUS_NOERROR;
	else
		return J2534_ERR_FAILED;
#else
	//(unsigned char)m_enChannelList[ulChannelID]
	uchDataBuffer[0] = (unsigned char)ucChannelid; //m_enChannelList[m_nChannelID];//nikhiltest_deleted
	uchDataBuffer[1] = ECU_SENDMESSAGE;
	uchDataBuffer[2] = 0x00; /* Segment Id. */
	uchDataBuffer[3] = (unsigned char)((nDataLength + 4) & 0xFF); // HFCP needs 4 bytes to be added
	uchDataBuffer[4] = (unsigned char)(((nDataLength + 4) >> 8) & 0xFF);
	uchDataBuffer[5] = (unsigned char)(ulFlags & 0x000000FF);
	uchDataBuffer[6] = (unsigned char)(ulFlags >> 8 & 0x000000FF);
	uchDataBuffer[7] = (unsigned char)(ulFlags >> 16 & 0x000000FF);
	uchDataBuffer[8] = (unsigned char)(ulFlags >> 24 & 0x000000FF);
	uchDataBuffer[9] = (unsigned char)(nMsgID >> 24 & 0x000000FF);
	uchDataBuffer[10] = (unsigned char)(nMsgID >> 16 & 0x000000FF);
	uchDataBuffer[11] = (unsigned char)(nMsgID >> 8 & 0x000000FF);
	uchDataBuffer[12] = (unsigned char)(nMsgID & 0x000000FF);



	memcpy(&uchDataBuffer[13], &ucData[0], nDataLength);
	/*Write the data to the device*/
	if (!WriteOutputReport(uchDataBuffer, (nDataLength + 13)))
	{
		return J2534_STATUS_NOERROR;
	}
	else
	{
		return J2534_ERR_FAILED;
	}
#endif
}

void CDeviceOEMTool::EmptyTxList(CPtrArray& ptrList)
{
	for (int i = 0; i < ptrList.GetSize(); ++i)
	{
		delete (CCanMsg*)ptrList.GetAt(i);
	}
	ptrList.RemoveAll();
}

/******************************************************************************
   Function Name    : SendSingleFrameECUMessage()
   Description      : Send the selected protocol message to the device.
******************************************************************************/
J2534ERROR CDeviceOEMTool::SendSingleFrameECUMessage(unsigned char* ucData,
	PASSTHRU_MSG* pstPassThruMsg,
	int nBytesToWrite, unsigned long ulChannelID)
{
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	// Write to Log File.
	LogToDebugFile("SendUnSegmentedECUMessage", DEBUGLOG_TYPE_COMMENT,
		"SendUnSegmentedECUMessage Start");


	//Send the data to the device.
	if (!WriteOutputReport(ucData, pstPassThruMsg->ulDataSize + nBytesToWrite))
	{
		ReadInputReport();
		if (InputReport[1] == m_enChannelList[ulChannelID] &&    //nikhileshtest_deleted //  m_enChannelList[m_nChannelID] &&
			InputReport[2] == ECU_SENDMESSAGE_ACK &&
			InputReport[3] == J2534_STATUS_NOERROR)
		{
			/*If loopback is enabled send the callback to the uppler layer*/
			if (m_bLoopBack == TRUE)
			{
				pstPassThruMsg->ulRxStatus = 0x01;
				pstPassThruMsg->ulExtraDataIndex = pstPassThruMsg->ulDataSize;
				pstPassThruMsg->ulTimeStamp = ntohl(ulong(InputReport[4]));
				RxfunCallBack[pstPassThruMsg->ulProtocolID](pstPassThruMsg,
					gpVoid[pstPassThruMsg->ulProtocolID]);
			}
			// Write to Log File.
			sprintf(szBuffer, "SendUnSegmentedECUMessage returned 0x%02X", J2534_STATUS_NOERROR);
			LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendUnSegmentedECUMessage()");
			return J2534_STATUS_NOERROR;
		}
		else return (J2534ERROR)InputReport[3];
	}
	return J2534_ERR_FAILED;
}
/******************************************************************************
   Function Name    : SendMultipleFrameECUMessages()
   Description      : Send the selected protocol message to the device.

Message Format : From PC to Device              From Device to PC
----------------------------------              ------------------
		Byte0 : ProtoclID                       Byte0 : ProtocolID
		Byte1 : SID                             Byte1 : SID_ACK
		Byte2:  Data Count                      Byte2 : ErrorCode
		Byte3:  Data Count
		Byte4:  TX Flags
		Byte5:  TX Flags
		Byte6:  TX Flags
		Byte7:  TX Flags
		Byte8:  Onwards Databytes including header
******************************************************************************/
J2534ERROR CDeviceOEMTool::SendMultipleFrameECUMessages(PASSTHRU_MSG* pstPassThruMsg, unsigned long ulChannelID)
{
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	unsigned short nTotalDataLength = 0;
	BOOL bTxInProgress = FALSE;
	BOOL bFirstFrmIndication = FALSE;
	int nDataOffSet = 0;
	int nIndex = 0;
	int nDataWriteIndex = 0;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);

	// Write to Log File.
	LogToDebugFile("SendMultipleFrameECUMessages", DEBUGLOG_TYPE_COMMENT,
		"SendMultipleFrameECUMessages start");

	//Getting data count
	nTotalDataLength = (unsigned short)pstPassThruMsg->ulDataSize;

	uchDataBuffer[0] = (unsigned char)m_enChannelList[ulChannelID];//nikhileshtest_deleted//  m_enChannelList[m_nChannelID];
	uchDataBuffer[1] = ECU_SENDMESSAGE;
	uchDataBuffer[2] = (unsigned char)((nTotalDataLength >> 8) & 0xFF);
	uchDataBuffer[3] = (unsigned char)((nTotalDataLength) & 0xFF);
	uchDataBuffer[4] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);
	uchDataBuffer[4] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 24 & 0x000000FF);
	uchDataBuffer[5] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 16 & 0x000000FF);
	uchDataBuffer[6] = (unsigned char)(pstPassThruMsg->ulTxFlags >> 8 & 0x000000FF);
	uchDataBuffer[7] = (unsigned char)(pstPassThruMsg->ulTxFlags & 0x000000FF);

	/* if data length is <56, data sahll be sent on single USB frame*/
	if ((nTotalDataLength != 0) && (nTotalDataLength <= 56))
	{
		memcpy(&uchDataBuffer[8], pstPassThruMsg->ucData, OUTPUTREPORTMAX - 8);
		m_ulLastErrorCode = SendSingleFrameECUMessage(uchDataBuffer, pstPassThruMsg, 8, ulChannelID);
	}
	/*If the data length exceeds 64,the data array will be divided into several
	USB Frames with each containing 64 bytes.The 0-63 byte of USB Frame is sent first,
	then the 64-127 byte and so on.*/
	else
	{
		do
		{
			bTxInProgress = TRUE;
			if (FALSE == bFirstFrmIndication)
			{
				bFirstFrmIndication = TRUE;
				nDataOffSet = 8;
			}
			else
			{
				nDataOffSet = 2;
			}

			for (nIndex = 0; ((nDataOffSet + nIndex) < OUTPUTREPORTMAX) && \
				((nDataWriteIndex + nIndex) < nTotalDataLength); nIndex++)
			{
				uchDataBuffer[nDataOffSet + nIndex] = pstPassThruMsg->ucData[nDataWriteIndex + nIndex];
			}

			/*Send data to device*/

			WriteOutputReport(uchDataBuffer, OUTPUTREPORTMAX);
			nDataWriteIndex = nDataWriteIndex + nIndex;
			if (nDataWriteIndex == nTotalDataLength)
			{
				bTxInProgress = FALSE;
				bFirstFrmIndication = FALSE;
			}
		} while (FALSE != bTxInProgress);

		ReadInputReport();
		if (InputReport[1] == m_enChannelList[m_nChannelID] &&
			InputReport[2] == ECU_SENDMESSAGE_ACK &&
			InputReport[3] == J2534_STATUS_NOERROR)
		{
			if (m_bLoopBack == TRUE)
			{
				pstPassThruMsg->ulRxStatus = 0x01;
				pstPassThruMsg->ulExtraDataIndex = pstPassThruMsg->ulDataSize;
				pstPassThruMsg->ulTimeStamp = ntohl(ulong(InputReport[4]));
				RxfunCallBack[pstPassThruMsg->ulProtocolID](pstPassThruMsg,
					gpVoid[pstPassThruMsg->ulProtocolID]);
			}
			// Write to Log File.
			sprintf(szBuffer, "SendMultipleFrameECUMessages returned 0x%02X", J2534_STATUS_NOERROR);
			LogToDebugFile(szBuffer, DEBUGLOG_TYPE_COMMENT, "SendMultipleFrameECUMessages()");
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
		}
		else m_ulLastErrorCode = (J2534ERROR)InputReport[3];
	}
	return m_ulLastErrorCode;
}
#ifdef GARUDA_TOOL

J2534ERROR CDeviceOEMTool::vGetRevision(char* pchFirmwareVersion,
	char* pchDllVersion,
	char* pchApiVersion)
{
	unsigned char uchVer[80];
	memset(&uchVer, 0, 80);
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);
	BufferCommand_t* GetRevision;
	InputBuffer_t* Inputbuffer;
	GetRevision = (BufferCommand_t*)uchDataBuffer;
	unsigned long ulFirmwareVersion = 0;
	DWORD dwWaitStatus;
	char buffer[10];
	// Log
	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "Start");

	// Check for parameters
	if (!pchFirmwareVersion || !pchDllVersion || !pchApiVersion)
	{
		// Null parameters
		LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "NULL parameters");
		return J2534_ERR_NULLPARAMETER;
	}

	/*copy default versions first*/
	//strcpy(pchFirmwareVersion, "01.00.00"); // Firmware Version
	//strcpy(pchDllVersion,"00.00.00.10");            // Dll Version
	strcpy(pchApiVersion, "04.04");              // API version


	GetDllVersion(pchDllVersion);

	//To append the Version Type
	//Amit Chnged from R to T
	strcat(pchDllVersion, " T");

	/*Jayasheela -send setup command protocol id */
#if 0
	uchDataBuffer[0] = J2534_SETUPCMDPROT_ID;
	uchDataBuffer[1] = GET_FIRMWARE_VERSION;
#endif
	GetRevision->proto_id = J2534_SETUPCMDPROT_ID;
	GetRevision->command = GET_FIRMWARE_VERSION;
	ResetEvent(m_CmdAck);
	if (!WriteOutputReport(uchDataBuffer, 5))
	{

		if (hCallBckThread != NULL)
		{

			//ReadInputReport();

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{ 
#if 0
				if (bufCmdAck[1] == J2534_SETUPCMDPROT_ID &&
					bufCmdAck[2] == GET_FIRMWARE_VERSION_ACK &&
					bufCmdAck[3] == J2534_STATUS_NOERROR)
#endif          				/* Copy the command ack data to the buffer */
				Inputbuffer = (InputBuffer_t*)bufCmdAck;
				if (Inputbuffer->proto_id == J2534_SETUPCMDPROT_ID &&
					Inputbuffer->command == GET_FIRMWARE_VERSION_ACK &&
					Inputbuffer->u.GetRevision.status == J2534_STATUS_NOERROR)
				{
					/***********************/
#if 0
					DWORD dwLeftMost = bufCmdAck[4];
					DWORD dwSecondLeft = bufCmdAck[5];
					DWORD dwSecondRight = bufCmdAck[6];
#endif
					DWORD dwLeftMost = Inputbuffer->u.GetRevision.LM;
					DWORD dwSecondLeft = Inputbuffer->u.GetRevision.SL;
					DWORD dwSecondRight = Inputbuffer->u.GetRevision.SR;
					//DWORD dwRightMost = InputReport[7];

					sprintf(pchFirmwareVersion, "%d.%d.%d %s", bufCmdAck[7], bufCmdAck[8], bufCmdAck[9],
						(char*)bufCmdAck + 10);
			//		snprintf(pSerialNo, sizeof(pSerialNo), "%s", bufCmdAck);

					/*_itoa( dwLeftMost, buffer, 10 );
					strcpy(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondLeft, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondRight, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);

					//To add the additional Info
					strcat(pchFirmwareVersion,(char*)InputReport[7]);*/

					//strcat(pchFirmwareVersion,".");
					//_itoa( dwRightMost, buffer, 10 );
					//strcat(pchFirmwareVersion,buffer);

					/************************/
					/*Collect the firmware version from the device*/
					LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "GetRevision Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;

				}
				else
				{
				//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.GetRevision.status;
				}
				break;

			}

			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
		else
		{
			ReadInputReport();
			Inputbuffer = (InputBuffer_t*)InputReport;
			if (InputReport[1] != 0)
			{ 
#if 0
				if (InputReport[1] == J2534_SETUPCMDPROT_ID &&
					InputReport[2] == GET_FIRMWARE_VERSION_ACK &&
					InputReport[3] == J2534_STATUS_NOERROR)
#endif
				if (Inputbuffer->proto_id == J2534_SETUPCMDPROT_ID &&
					Inputbuffer->command == GET_FIRMWARE_VERSION_ACK &&
					Inputbuffer->u.GetRevision.status == J2534_STATUS_NOERROR)
				{
					/***********************/
#if 0
					DWORD dwLeftMost = InputReport[4];
					DWORD dwSecondLeft = InputReport[5];
					DWORD dwSecondRight = InputReport[6];
					//DWORD dwRightMost = InputReport[7];
#endif
	/*				DWORD dwLeftMost = Inputbuffer->u.GetRevision.LM;
					DWORD dwSecondLeft = Inputbuffer->u.GetRevision.SL;
					DWORD dwSecondRight = Inputbuffer->u.GetRevision.SR;*/
					sprintf(pchFirmwareVersion, "%d.%d.%d %s", InputReport[7], InputReport[8], InputReport[9],
						(char*)InputReport + 10);
		
				//	sprintf(pSerailNo, "%d.%d.%d %s", InputReport[7], InputReport[8], InputReport[9],
				//		(char*)InputReport + 10); //(char*)InputReport + 7, (char*)InputReport + 8,
					//	(char*)InputReport + 9, InputReport[10]);// , InputReport[11], InputReport[12],
					//	InputReport[13], InputReport[14], InputReport[15], InputReport[16], InputReport[17]);//"%s%s%s%d%d%d%d%d%d%d%d"

					/*_itoa( dwLeftMost, buffer, 10 );
					strcpy(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondLeft, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondRight, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);

					//To add the additional Info
					strExtaInfo.Format("%s",( (char*)InputReport[7])
					strcat(pchFirmwareVersion,strExtaInfo);
					//strcat(pchFirmwareVersion,".");
					//_itoa( dwRightMost, buffer, 10 );
					//strcat(pchFirmwareVersion,buffer);*/

					/************************/
					/*Collect the firmware version from the device*/
					LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "GetRevision Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
				//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.GetRevision.status;
				}
			}
		}
	}
	else
	{
		m_ulLastErrorCode = J2534_ERR_FAILED;
	}
	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "End");
	return m_ulLastErrorCode;
}
#else
J2534ERROR CDeviceOEMTool::vGetRevision(char* pchFirmwareVersion,
	char* pchDllVersion,
	char* pchApiVersion)
{
	unsigned char uchVer[80];
	memset(&uchVer, 0, 80);
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);

	// Log
	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "Start");

	// Check for parameters
	if (!pchFirmwareVersion || !pchDllVersion || !pchApiVersion)
	{
		// Null parameters
		LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "NULL parameters");
		return J2534_ERR_NULLPARAMETER;
	}
	/*Jayasheela -send setup command protocol id */
	uchDataBuffer[0] = J2534_SETUPCMDPROT_ID;
	uchDataBuffer[1] = GET_FIRMWARE_VERSION;
	if (!WriteOutputReport(uchDataBuffer, 2))
	{
		ReadInputReport();
		if (InputReport[1] == J2534_SETUPCMDPROT_ID &&
			InputReport[2] == GET_FIRMWARE_VERSION_ACK &&
			InputReport[3] == J2534_STATUS_NOERROR)
		{
			/*Collect the firmware version from the device*/
			LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "GetRevision Successful");
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
		}
		else m_ulLastErrorCode = (J2534ERROR)InputReport[3];
	}
	/*Jayasheela-hardcoded value for firmware version*/
	//sprintf((char *)uchVer,"%d", usFirmwareVersion);
	strcpy(pchFirmwareVersion, "01.00.00"); // Firmware Version
	/***************************Nikhilesh**************************/
	GetDllVersion(pchDllVersion);
	/**************************************************************/
	strcpy(pchApiVersion, "04.04");              // API version

	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "End");
	return J2534_STATUS_NOERROR;
}

#endif

#ifdef GARUDA_TOOL
J2534ERROR CDeviceOEMTool::vGetSerialNo(char* pSerialNo)
{
	unsigned char uchVer[80];
	memset(&uchVer, 0, 80);
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);
	BufferCommand_t* GetSerialNo;
	InputBuffer_t* Inputbuffer;
	GetSerialNo = (BufferCommand_t*)uchDataBuffer;
	DWORD dwWaitStatus;
	// Log
	LogToDebugFile("vGetSerialNo", DEBUGLOG_TYPE_COMMENT, "Start");

	// Check for parameters
	if (!pSerialNo)
	{
		// Null parameters
		LogToDebugFile("vGetSerialNo", DEBUGLOG_TYPE_COMMENT, "NULL parameters");
		return J2534_ERR_NULLPARAMETER;
	}
	GetSerialNo->proto_id = J2534_SETUPCMDPROT_ID;
	GetSerialNo->command = GETSerail_VERSION;
	ResetEvent(m_CmdAck);
	if (!WriteOutputReport(uchDataBuffer, 5))
	{

		if (hCallBckThread != NULL)
		{

			//ReadInputReport();

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
#if 0
				if (bufCmdAck[1] == J2534_SETUPCMDPROT_ID &&
					bufCmdAck[2] == GET_FIRMWARE_VERSION_ACK &&
					bufCmdAck[3] == J2534_STATUS_NOERROR)
#endif          				/* Copy the command ack data to the buffer */
					Inputbuffer = (InputBuffer_t*)bufCmdAck;
			/*	    Inputbuffer->command = GETSerail_VERSION_ACK;
					Inputbuffer->u.GetSerialNo.status = J2534_STATUS_NOERROR;*/
				if (Inputbuffer->proto_id == J2534_SETUPCMDPROT_ID &&
					Inputbuffer->command == GETSerail_VERSION_ACK &&
					Inputbuffer->u.GetSerialNo.status == J2534_STATUS_NOERROR)
				{
					/***********************/
#if 0
					DWORD dwLeftMost = bufCmdAck[4];
					DWORD dwSecondLeft = bufCmdAck[5];
					DWORD dwSecondRight = bufCmdAck[6];
#endif
		/*			DWORD dwLeftMost = Inputbuffer->u.GetRevision.LM;
					DWORD dwSecondLeft = Inputbuffer->u.GetRevision.SL;
					DWORD dwSecondRight = Inputbuffer->u.GetRevision.SR;
					//DWORD dwRightMost = InputReport[7];*/

				/*	sprintf(pSerailNo, "%d.%d.%d %s", bufCmdAck[7], bufCmdAck[8], bufCmdAck[9],
						(char*)bufCmdAck + 10);*/
					memset(pSerialNo, 0, 80);
				/*	bufCmdAck[7] = 'M';
					bufCmdAck[8] = 'I';
					bufCmdAck[9] = 'L';
					bufCmdAck[17] = 1;*/
			/*		sprintf(pSerialNo, "%s%d%d%d%d%d%d%d%d", (char*)bufCmdAck + 7, bufCmdAck[10], bufCmdAck[11], bufCmdAck[12],
						bufCmdAck[13], bufCmdAck[14], bufCmdAck[15], bufCmdAck[16], bufCmdAck[17]);*/
					strncpy(pSerialNo, (char*)bufCmdAck + 7, 80);
				//	snprintf(pSerialNo, sizeof(pSerialNo), "%s", bufCmdAck);

					/*_itoa( dwLeftMost, buffer, 10 );
					strcpy(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondLeft, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);
					strcat(pchFirmwareVersion,".");
					_itoa( dwSecondRight, buffer, 10 );
					strcat(pchFirmwareVersion,buffer);

					//To add the additional Info
					strcat(pchFirmwareVersion,(char*)InputReport[7]);*/

					//strcat(pchFirmwareVersion,".");
					//_itoa( dwRightMost, buffer, 10 );
					//strcat(pchFirmwareVersion,buffer);

					/************************/
					/*Collect the firmware version from the device*/
					LogToDebugFile("vGetSerialNo", DEBUGLOG_TYPE_COMMENT, "vGetSerialNo Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;

				}
				else
				{
					//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.GetSerialNo.status;
				}
				break;

			}

			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
		else
		{
			ReadInputReport();
			Inputbuffer = (InputBuffer_t*)InputReport;
		/*	Inputbuffer->command = GETSerail_VERSION_ACK;
			Inputbuffer->u.GetSerialNo.status = J2534_STATUS_NOERROR;*/
			if (InputReport[1] != 0)
			{
#if 0
				if (InputReport[1] == J2534_SETUPCMDPROT_ID &&
					InputReport[2] == GET_FIRMWARE_VERSION_ACK &&
					InputReport[3] == J2534_STATUS_NOERROR)
#endif
					if (Inputbuffer->proto_id == J2534_SETUPCMDPROT_ID &&
						Inputbuffer->command == GETSerail_VERSION_ACK &&
						Inputbuffer->u.GetSerialNo.status == J2534_STATUS_NOERROR)
					{
						/***********************/
#if 0
						DWORD dwLeftMost = InputReport[4];
						DWORD dwSecondLeft = InputReport[5];
						DWORD dwSecondRight = InputReport[6];
						//DWORD dwRightMost = InputReport[7];
#endif
				/*		sprintf(pSerialNo, "%s%d%d%d%d%d%d%d%d", (char*)InputReport + 7, InputReport[10], InputReport[11], InputReport[12],
								InputReport[13], InputReport[14], InputReport[15], InputReport[16], InputReport[17]); */
						strncpy(pSerialNo, (char*)InputReport + 7, 80);

						/************************/
						/*Collect the firmware version from the device*/
						LogToDebugFile("vGetSerialNo", DEBUGLOG_TYPE_COMMENT, "vGetSerialNo Successful");
						m_ulLastErrorCode = J2534_STATUS_NOERROR;
					}
					else
					{
						//	m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
						m_ulLastErrorCode = (J2534ERROR)Inputbuffer->u.GetSerialNo.status;
					}
			}
		}
	}
	else
	{
		m_ulLastErrorCode = J2534_ERR_FAILED;
	}
	LogToDebugFile("vGetSerialNo", DEBUGLOG_TYPE_COMMENT, "End");
	return m_ulLastErrorCode;
}
#else
J2534ERROR CDeviceOEMTool::vGetRevision(char* pchFirmwareVersion,
	char* pchDllVersion,
	char* pchApiVersion)
{
	unsigned char uchVer[80];
	memset(&uchVer, 0, 80);
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);

	// Log
	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "Start");

	// Check for parameters
	if (!pchFirmwareVersion || !pchDllVersion || !pchApiVersion)
	{
		// Null parameters
		LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "NULL parameters");
		return J2534_ERR_NULLPARAMETER;
	}
	/*Jayasheela -send setup command protocol id */
	uchDataBuffer[0] = J2534_SETUPCMDPROT_ID;
	uchDataBuffer[1] = GET_FIRMWARE_VERSION;
	if (!WriteOutputReport(uchDataBuffer, 2))
	{
		ReadInputReport();
		if (InputReport[1] == J2534_SETUPCMDPROT_ID &&
			InputReport[2] == GET_FIRMWARE_VERSION_ACK &&
			InputReport[3] == J2534_STATUS_NOERROR)
		{
			/*Collect the firmware version from the device*/
			LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "GetRevision Successful");
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
		}
		else m_ulLastErrorCode = (J2534ERROR)InputReport[3];
	}
	/*Jayasheela-hardcoded value for firmware version*/
	//sprintf((char *)uchVer,"%d", usFirmwareVersion);
	strcpy(pchFirmwareVersion, "01.00.00"); // Firmware Version
	/***************************Nikhilesh**************************/
	GetDllVersion(pchDllVersion);
	/**************************************************************/
	strcpy(pchApiVersion, "04.04");              // API version

	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "End");
	return J2534_STATUS_NOERROR;
}

#endif

#ifdef GARUDA_TOOL
//-----------------------------------------------------------------------------
//	Function Name	: vLoggingStatus()
//	Input Params	: 
//	Output Params	: 
//	Return			: 
//	Description		: 
//-----------------------------------------------------------------------------
J2534ERROR CDeviceOEMTool::vLoggingStatus(unsigned long bLogFlag, SYSTEMTIME* LogTime)
{
	DWORD dwWaitStatus;
	m_ulLastErrorCode = J2534_ERR_FAILED;
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);
	SYSTEMTIME Time;
	GetLocalTime(&Time);

	uchDataBuffer[0] = J2534_SETUPCMDPROT_ID;
	uchDataBuffer[2] = (unsigned char)Time.wYear;
	uchDataBuffer[3] = (unsigned char)(Time.wYear >> 8);
	uchDataBuffer[4] = (unsigned char)Time.wMonth;
	uchDataBuffer[5] = (unsigned char)Time.wDay;
	uchDataBuffer[6] = (unsigned char)Time.wHour;
	uchDataBuffer[7] = (unsigned char)Time.wMinute;
	uchDataBuffer[8] = (unsigned char)Time.wSecond;
	uchDataBuffer[9] = (unsigned char)Time.wMilliseconds;
	uchDataBuffer[10] = (unsigned char)(Time.wMilliseconds >> 8);

	if (bLogFlag == 1)
	{
		uchDataBuffer[1] = DEVICE_STARTLOGGING;

		ResetEvent(m_CmdAck);
		if (!WriteOutputReport(uchDataBuffer, 11))
		{

			dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
			switch (dwWaitStatus)
			{
			case WAIT_OBJECT_0:
			{
				if (bufCmdAck[1] == J2534_SETUPCMDPROT_ID &&
					bufCmdAck[2] == DEVICE_STARTLOGGING &&
					bufCmdAck[3] == J2534_STATUS_NOERROR)
				{
					LogToDebugFile("vLoggingStatus", DEBUGLOG_TYPE_COMMENT, "vLoggingStatus Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
				}

				break;
			}
			case WAIT_TIMEOUT:
			{
				m_ulLastErrorCode = J2534_ERR_TIMEOUT;
				break;
			}
			default:
			{
				break;
			}
			}
		}
	}
	else
	{
		uchDataBuffer[1] = DEVICE_STOPLOGGING;

		if (!WriteOutputReport(uchDataBuffer, 2))
		{
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
		}
		else
		{
			m_ulLastErrorCode = J2534_ERR_FAILED;
		}
	}
	LogToDebugFile("vGetRevision", DEBUGLOG_TYPE_COMMENT, "End");
	*LogTime = Time;
	return m_ulLastErrorCode;
}
#endif

#ifdef GARUDA_TOOL
//-----------------------------------------------------------------------------
//	Function Name	: vSessionCommand()
//	Input Params	: 
//	Output Params	: 
//	Return			: 
//	Description		: 
//-----------------------------------------------------------------------------
J2534ERROR CDeviceOEMTool::vSessionCommand(unsigned long bsessionFlag)
{
	m_ulLastErrorCode = J2534_ERR_FAILED;
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);
	BufferCommand_t* SessionCommand;
	InputBuffer_t* Inputbuffer;

	//	uchDataBuffer[0] = J2534_SESSIONCMDPROT_ID;
	//	uchDataBuffer[1] = 0x01;
	SessionCommand = (BufferCommand_t*)uchDataBuffer;
	SessionCommand->proto_id = J2534_SESSIONCMDPROT_ID;
	SessionCommand->command = 0x01;

	if (bsessionFlag == 1)
	{
		int len = sizeof(SessionCommand->proto_id) + sizeof(SessionCommand->command);

		len += sizeof(SessionCommand->u.Device_STARTSESSION);

		//uchDataBuffer[2] = DEVICE_STARTSESSION;
		SessionCommand->u.Device_STARTSESSION = DEVICE_STARTSESSION;

		if (!WriteOutputReport(uchDataBuffer, len))
		{

			ReadInputReport();

			if (InputReport[1] != 0)
			{

				TRACE("Got a command ack \n");

				/* Copy the command ack data to the buffer */
				for (int i = INPUTREPORTMAX; i >= 0; i--)
				{
					bufCmdAck[i] = InputReport[i];
				}
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				/*	if (bufCmdAck[1] == J2534_SESSIONCMDPROT_ID &&
					   bufCmdAck[2] == 0x01 &&
					   bufCmdAck[3] == DEVICE_STARTSESSION  &&
					   bufCmdAck[4] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == J2534_SESSIONCMDPROT_ID &&
					Inputbuffer->command == 0x01 &&
					Inputbuffer->u.StartSession.Device_STARTSESSION == DEVICE_STARTSESSION &&
					Inputbuffer->u.StartSession.Status == J2534_STATUS_NOERROR)
				{
					LogToDebugFile("vSessionCommand", DEBUGLOG_TYPE_COMMENT, "vLoggingStatus Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.StartSession.Device_STARTSESSION);
				}
			}

		}
	}
	else
	{
		//uchDataBuffer[2] = DEVICE_STOPSESSION;
		int len = sizeof(SessionCommand->proto_id) + sizeof(SessionCommand->command);

		len += sizeof(SessionCommand->u.Device_STARTSESSION);
		SessionCommand->u.Device_STOPSESSION = DEVICE_STOPSESSION;

		if (!WriteOutputReport(uchDataBuffer, len))
		{

		//	ReadInputReport();
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
			if (InputReport[1] != 0)
			{

				TRACE("Got a command ack \n");

				/* Copy the command ack data to the buffer */
				for (int i = INPUTREPORTMAX; i >= 0; i--)
				{
					bufCmdAck[i] = InputReport[i];
				}
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				/*	if (bufCmdAck[1] == J2534_SESSIONCMDPROT_ID &&
					   bufCmdAck[2] == 0x01 &&
					   bufCmdAck[3] == DEVICE_STOPSESSION  &&
					   bufCmdAck[4] == J2534_STATUS_NOERROR)*/
				if (Inputbuffer->proto_id == J2534_SESSIONCMDPROT_ID &&
					Inputbuffer->command == 0x01 &&
					Inputbuffer->u.StopSession.Device_STOPSESSION == DEVICE_STOPSESSION &&
					Inputbuffer->u.StopSession.Status == J2534_STATUS_NOERROR)
				{
					LogToDebugFile("vSessionCommand", DEBUGLOG_TYPE_COMMENT, "vLoggingStatus Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
				}
				else
				{
					m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
				}
			}

		}
	}
	LogToDebugFile("vSessionCommand", DEBUGLOG_TYPE_COMMENT, "End");

	return m_ulLastErrorCode;
}
#endif

void GetDllVersion(char* pchDllVersion)
{
	LPTSTR lpszFilePath = IDE5K432PATH;
	DWORD dwDummy;
	char buffer[10];
	UINT uLen;
	VS_FIXEDFILEINFO* lpFfi;
	DWORD dwFVISize = GetFileVersionInfoSize(lpszFilePath, &dwDummy);

	if (!dwFVISize)
	{
		strcpy(pchDllVersion, "DLL does not exist");
		return;
	}
	LPBYTE lpVersionInfo = new BYTE[dwFVISize];
	GetFileVersionInfo(lpszFilePath, 0, dwFVISize, lpVersionInfo);

	VerQueryValue(lpVersionInfo, _T("\\"), (LPVOID*)&lpFfi, &uLen);
	DWORD dwFileVersionMS = lpFfi->dwFileVersionMS;
	DWORD dwFileVersionLS = lpFfi->dwFileVersionLS;
	delete[] lpVersionInfo;
	DWORD dwLeftMost = HIWORD(dwFileVersionMS);
	DWORD dwSecondLeft = LOWORD(dwFileVersionMS);
	DWORD dwSecondRight = HIWORD(dwFileVersionLS);
	DWORD dwRightMost = LOWORD(dwFileVersionLS);
	TRACE("IDE5k432 Version: %d.%d.%d.%d\n", dwLeftMost, dwSecondLeft,
		dwSecondRight, dwRightMost);
	/****/
	_itoa(dwLeftMost, buffer, 10);
	strcpy(pchDllVersion, buffer);
	strcat(pchDllVersion, ".");
	_itoa(dwSecondLeft, buffer, 10);
	strcat(pchDllVersion, buffer);
	strcat(pchDllVersion, ".");
	_itoa(dwSecondRight, buffer, 10);
	strcat(pchDllVersion, buffer);
	strcat(pchDllVersion, ".");
	_itoa(dwRightMost, buffer, 10);
	strcat(pchDllVersion, buffer);

	return;
}

J2534ERROR CDeviceOEMTool::vProgrammingVoltage(unsigned long ulDeviceID,
	unsigned long ulPin,
	unsigned long ulVoltage)
{
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);
	LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_ERROR, "vProgrammingVoltage start");
	/*Check for the device handle. if the device is not connected then
	throw the error*/
	if (!HidDevHandle)
		m_ulLastErrorCode = J2534_ERR_DEVICE_NOT_CONNECTED;

	if ((ulPin != 0) && (ulPin != 6) && (ulPin != 9) && (ulPin != 11) &&
		(ulPin != 12) && (ulPin != 13) && (ulPin != 14) && (ulPin != 15))
	{
		// Write to Log File.
		LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_ERROR, "Invalid pin number");
		return(J2534_ERR_PIN_INVALID);
	}
	if (ulPin < 15)
	{
		if (ulVoltage < MIN_BAT_VOLTAGE)
		{
			// Write to Log File.
			LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_ERROR, "Battery voltage is low");
			return(J2534_ERR_NOT_SUPPORTED);
		}
		if ((ulVoltage > MAX_BAT_VOLTAGE) && (ulVoltage != VOLTAGE_OFF))
		{
			// Write to Log File.
			LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_ERROR, "Battery voltage is High");
			return(J2534_ERR_NOT_SUPPORTED);
		}
	}
	else
	{
		if ((ulVoltage != SHORT_TO_GROUND) && (ulVoltage != VOLTAGE_OFF))
		{
			// Write to Log File.
			LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_ERROR, "Battery voltage for Pin 15 is invalid");
			return(J2534_ERR_NOT_SUPPORTED);
		}
	}
	/*Jayasheela-added setup ommands */
	uchDataBuffer[0] = J2534_SETUPCMDPROT_ID;
	uchDataBuffer[1] = ECU_SETPROGRAMMINGVOLTAGE;
	uchDataBuffer[2] = (unsigned char)(ulPin & 0x000000FF);
	uchDataBuffer[3] = (unsigned char)(ulVoltage & 0x000000FF);
	uchDataBuffer[4] = (unsigned char)(ulVoltage >> 8 & 0x000000FF);
	uchDataBuffer[5] = (unsigned char)(ulVoltage >> 16 & 0x000000FF);
	uchDataBuffer[6] = (unsigned char)(ulVoltage >> 24 & 0x000000FF);

	if (!WriteOutputReport(uchDataBuffer, 7))
	{
		ReadInputReport();
		if (InputReport[1] == J2534_SETUPCMDPROT_ID &&
			InputReport[2] == ECU_SETPROGRAMMINGVOLTAGE_ACK &&
			InputReport[3] == J2534_STATUS_NOERROR)
		{
			LogToDebugFile("vProgrammingVoltage", DEBUGLOG_TYPE_COMMENT, "vProgrammingVoltage Successful");
			m_ulLastErrorCode = J2534_STATUS_NOERROR;
		}
		else m_ulLastErrorCode = (J2534ERROR)InputReport[3];
	}
	return m_ulLastErrorCode;
}

BOOL CDeviceOEMTool::vIsDeviceConnected(BOOL bFlag)
{
	return GetDeviceDetected();
}


J2534ERROR CDeviceOEMTool::vGetLastError(char* pErrorDescription)
{
	if (pErrorDescription == NULL)
	{
		return J2534_ERR_NULLPARAMETER;
	}
	switch (m_ulLastErrorCode)
	{
	case J2534_STATUS_NOERROR:
		strcpy(pErrorDescription, "Function call successful");
		break;
	case J2534_ERR_NOT_SUPPORTED:
		strcpy(pErrorDescription, "Function not supported");
		break;
	case J2534_ERR_INVALID_CHANNEL_ID:
		strcpy(pErrorDescription, "Invalid ChannelID value");
		break;
	case J2534_ERR_INVALID_PROTOCOL_ID:
		strcpy(pErrorDescription, "Invalid ProtocolID value");
		break;
	case J2534_ERR_NULLPARAMETER:
		strcpy(pErrorDescription, "NULL pointer supplied where a valid pointer is required");
		break;

	case J2534_ERR_INVALID_IOCTL_VALUE:
		strcpy(pErrorDescription, "Invalid value for Ioctl parameter");
		break;
	case J2534_ERR_INVALID_FLAGS:
		strcpy(pErrorDescription, "Invalid flag values");
		break;
	case J2534_ERR_FAILED:
		//strcpy(pErrorDescription , "Undefined error., use PassThruGetLastError for description of error");
		strcpy(pErrorDescription, "Undefined error.");
		break;

	case J2534_ERR_INVALID_DEVICE_ID:
		strcpy(pErrorDescription, "Device not connected to PC");
		break;

	case J2534_ERR_TIMEOUT:
		strcpy(pErrorDescription, "Timeout. No message available to read or could not read the specified number of messages. The actual number of messages read is placed in <NumMsgs>");

		break;
	case J2534_ERR_INVALID_MSG:
		strcpy(pErrorDescription, "Invalid message structure pointed to by pMsg ");
		break;
	case J2534_ERR_INVALID_TIME_INTERVAL:
		strcpy(pErrorDescription, "Invalid TimeInterval value");
		break;

	case J2534_ERR_EXCEEDED_LIMIT:
		strcpy(pErrorDescription, "Exceeded maximum number of message IDs or allocated space");
		break;

	case J2534_ERR_INVALID_MSG_ID:
		strcpy(pErrorDescription, "Invalid MsgID value");
		break;
	case J2534_ERR_DEVICE_IN_USE:
		strcpy(pErrorDescription, "Device already open and/or in use");
		break;
	case J2534_ERR_INVALID_IOCTL_ID:
		strcpy(pErrorDescription, "Invalid IoctlID value");
		break;

	case J2534_ERR_BUFFER_EMPTY:
		strcpy(pErrorDescription, "Protocol message buffer empty");
		break;

	case J2534_ERR_BUFFER_FULL:
		strcpy(pErrorDescription, "Protocol message buffer full");
		break;
	case J2534_ERR_BUFFER_OVERFLOW:
		strcpy(pErrorDescription, "Protocol message buffer overflow");
		break;
	case J2534_ERR_PIN_INVALID:
		strcpy(pErrorDescription, "Invalid pin number");
		break;

	case J2534_ERR_CHANNEL_IN_USE:
		strcpy(pErrorDescription, "Channel already in use");
		break;
	case J2534_ERR_MSG_PROTOCOL_ID:
		strcpy(pErrorDescription, "Protocol type does not match the protocol associated with Channel ID");
		break;

	case J2534_ERR_INVALID_FILTER_ID:
		strcpy(pErrorDescription, " Invalid MsgID value");
		break;
	case J2534_ERR_NO_FLOW_CONTROL:
		strcpy(pErrorDescription, "An attempt was made to send a message on an ISO15765 ChannelID before a flow control filter was established.");
		break;
	case J2534_ERR_NOT_UNIQUE:
		strcpy(pErrorDescription, "  A CAN ID in PatternMsg or FlowControlMsg matches either ID in an existing Flow Control Filter");
		break;
	case J2534_ERR_INVALID_BAUDRATE:
		strcpy(pErrorDescription, "Desired baud rate cannot be achieved within tolerances");
		break;
	case J2534_ERR_DEVICE_NOT_CONNECTED:
		strcpy(pErrorDescription, "Device not connected");
		break;
	default:
		strcpy(pErrorDescription, "Unknown Last error !!");
		break;
	}
	return J2534_STATUS_NOERROR;
}

J2534ERROR CDeviceOEMTool::InitUSBDevice()
{
#if 0
	if (bOpenHidDevice())
		return J2534_STATUS_NOERROR;
	else
		return J2534_ERR_DEVICE_NOT_CONNECTED;

	return J2534_STATUS_NOERROR;
#endif
	if (isHidDevice) {
#ifdef GARUDA_HID
		if (bOpenHidDevice())
			return J2534_STATUS_NOERROR;
#endif
	}
//#else
	else {
#ifdef GARUDA_TCP
		if (bOpenTCPInterfaceDevice())
			return J2534_STATUS_NOERROR;
#endif
		else
			return J2534_ERR_DEVICE_NOT_CONNECTED;
	}
}

J2534ERROR CDeviceOEMTool::CloseUSBDevice()
{
	CloseHandles();
	return J2534_STATUS_NOERROR;
}

/*************************************************************************************
			Innova OEM TOOL USB Device Interface Implementations
______________________________________________________________________________________

	BOOL bOpenHidDevice();  // Open the HID Device based on VID and PID
	//Reads the newest report from the device
	void  ReadInputReport();
	//Get Output Report size
	int GetOutputReportSize(void);
	int GetInputReportSize(void);
	int GetFeatureReportByteLength(void);
	//Writes the newest report from the device based on report number
	BOOL WriteOutputReport(unsigned char*ucReport,DWORD dwLength);
	void CloseHandles();
	BOOL GetDeviceDetected() {return (HidAttached);}
	void DisplayInputReport();
	void PrepareForOverlappedTransfer();
	// gets the device capabilites and puts it in Capabilities
	void GetDeviceCapabilities(void);
************************************************************************************/

/************************************************************************************
*
*   Function: bOpenHidDevice
*   Purpose: tries to open a HID device based on VID and PID
*   Parameters: vid - HID device's vendor ID
*               pid - HID device's product ID

*   Returns: TRUE, if device is found
*            FALSE, if device is not found
*
*************************************************************************************/
BOOL CDeviceOEMTool::bOpenHidDevice()
{
	static GUID HidGuid;                        /* HID Globally Unique ID: windows supplies us with this value */
	HDEVINFO HidDevInfo;                        /* handle to structure containing all attached HID Device information */
	SP_DEVICE_INTERFACE_DATA devInfoData;       /* Information structure for HID devices */
	BOOLEAN Result;                             /* result of getting next device information structure */
	HIDD_ATTRIBUTES  HIDAttrib;                 /* HID device HIDAttrib */
	BOOL                                LastDevice = FALSE;
	int                                 MemberIndex = 0;
	Length = 0;
	detailData = NULL;
	/*
	API function: HidD_GetHidGuid
	Get the GUID for all system HIDs.
	Returns: the GUID in HidGuid.
	*/

	HidD_GetHidGuid(&HidGuid);

	/*
	API function: SetupDiGetClassDevs
	Returns: a handle to a device information set for all installed devices.
	Requires: the GUID returned by GetHidGuid.
	*/

	HidDevInfo = SetupDiGetClassDevs
	(&HidGuid,
		NULL,
		NULL,
		DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);

	devInfoData.cbSize = sizeof(devInfoData);

	//Step through the available devices looking for the one we want.
	//Quit on detecting the desired device or checking all available devices without success.

	MemberIndex = 0;
	LastDevice = FALSE;
	do
	{
		/*
		API function: SetupDiEnumDeviceInterfaces
		On return, MyDeviceInterfaceData contains the handle to a
		SP_DEVICE_INTERFACE_DATA structure for a detected device.
		Requires:
		The DeviceInfoSet returned in SetupDiGetClassDevs.
		The HidGuid returned in GetHidGuid.
		An index to specify a device.
			*/

		Result = SetupDiEnumDeviceInterfaces(HidDevInfo,
			0,
			&HidGuid,
			MemberIndex,
			&devInfoData);

		if (Result != 0)
		{
			//A device has been detected, so get more information about it.

			/*
			API function: SetupDiGetDeviceInterfaceDetail
			Returns: an SP_DEVICE_INTERFACE_DETAIL_DATA structure
			containing information about a device.
			To retrieve the information, call this function twice.
			The first time returns the size of the structure in Length.
			The second time returns a pointer to the data in DeviceInfoSet.
			Requires:
			A DeviceInfoSet returned by SetupDiGetClassDevs
			The SP_DEVICE_INTERFACE_DATA structure returned by SetupDiEnumDeviceInterfaces.

			  The final parameter is an optional pointer to an SP_DEV_INFO_DATA structure.
			  This application doesn't retrieve or use the structure.
			  If retrieving the structure, set
			  MyDeviceInfoData.cbSize = length of MyDeviceInfoData.
			  and pass the structure's address.
			*/

			//Get the Length value.
			//The call will return with a "buffer too small" error which can be ignored.

			Result = SetupDiGetDeviceInterfaceDetail(HidDevInfo,
				&devInfoData,
				NULL,
				0,
				&Length,
				NULL);

			//Allocate memory for the HidDevHandle structure, using the returned Length.

			detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(Length);

			//Set cbSize in the detailData structure.

			detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			//Call the function again, this time passing it the returned buffer size.

			Result = SetupDiGetDeviceInterfaceDetail(HidDevInfo,
				&devInfoData,
				detailData,
				Length,
				&Required,
				NULL);

			/*
			API function: CreateFile
			Returns: a handle that enables reading and writing to the device.
			Requires:
			The DevicePath in the detailData structure
			returned by SetupDiGetDeviceInterfaceDetail.
		*/

			HidDevHandle = CreateFile(detailData->DevicePath,
				0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				(LPSECURITY_ATTRIBUTES)NULL,
				OPEN_EXISTING,
				0,
				NULL);


			/*
			API function: HidD_GetHIDAttrib
			Requests information from the device.
			Requires: the handle returned by CreateFile.
			Returns: a HIDD_HIDAttrib structure containing
			the Vendor ID, Product ID, and Product Version Number.
			Use this information to decide if the detected device is
			the one we're looking for.
		*/

		//Set the Size to the number of bytes in the structure.

			HIDAttrib.Size = sizeof(HIDAttrib);

			Result = HidD_GetAttributes(HidDevHandle,
				&HIDAttrib);
			//Is it the desired device?
			HidAttached = FALSE;
			if (HIDAttrib.VendorID == VID)
			{
				if (HIDAttrib.ProductID == PID)
				{
					usFirmwareVersion = HIDAttrib.VersionNumber;
					//Both the Vendor ID and Product ID match.
					HidAttached = TRUE;
					//Get the device's capablities.
					GetDeviceCapabilities();
					// Get a handle for writing Output reports.
					WriteHandle = CreateFile
					(detailData->DevicePath,
						GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						(LPSECURITY_ATTRIBUTES)NULL,
						OPEN_EXISTING,
						0,
						NULL);
					// Prepare to read reports using Overlapped I/O.
					PrepareForOverlappedTransfer();

				} //if (HIDAttrib.ProductID == ProductID)

				else
					//The Product ID doesn't match.
					CloseHandle(HidDevHandle);
			}
			else if (HIDAttrib.VendorID == VID_2_0)
			{
				if (HIDAttrib.ProductID == PID_2_0)
				{
					usFirmwareVersion = HIDAttrib.VersionNumber;
					//Both the Vendor ID and Product ID match.
					HidAttached = TRUE;
					//Get the device's capablities.
					GetDeviceCapabilities();
					// Get a handle for writing Output reports.
					WriteHandle = CreateFile
					(detailData->DevicePath,
						GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						(LPSECURITY_ATTRIBUTES)NULL,
						OPEN_EXISTING,
						0,
						NULL);
					// Prepare to read reports using Overlapped I/O.
					PrepareForOverlappedTransfer();

				} //if (HIDAttrib.ProductID == ProductID)

				else
					//The Product ID doesn't match.
					CloseHandle(HidDevHandle);

			} //if (HIDAttrib.VendorID == VendorID)


			else
				CloseHandle(HidDevHandle);

			//Free the memory used by the detailData structure (no longer needed).
			free(detailData);
		}
		else
			//SetupDiEnumDeviceInterfaces returned 0, so there are no more devices to check.
			LastDevice = TRUE;
		//If we haven't found the device yet, and haven't tried every available device,
		//try the next one.
		MemberIndex = MemberIndex + 1;
	} //do
	while ((LastDevice == FALSE) && (HidAttached == FALSE));
	// SetupDiDestroyDeviceInfoList(HidDevHandle);
	return HidAttached;
}

/************************************************************************************
*   Function: GetDeviceCapabilities
*   Purpose: Gets the devices specific capabilites
*   Parameters: Void
*   Returns: Void
*************************************************************************************/
void CDeviceOEMTool::GetDeviceCapabilities(void)
{
	//Get the Capabilities structure for the device.
	PHIDP_PREPARSED_DATA    PreparsedData;

	/*
	API function: HidD_GetPreparsedData
	Returns: a pointer to a buffer containing the information about the device's
	capabilities.
	Requires: A handle returned by CreateFile.
	There's no need to access the buffer directly,
	but HidP_GetCaps and other API functions require a pointer to the buffer.
	*/

	HidD_GetPreparsedData(HidDevHandle, &PreparsedData);

	/*
	API function: HidP_GetCaps
	Learn the device's capabilities.
	For standard devices such as joysticks, you can find out the specific
	capabilities of the device.
	For a custom device, the software will probably know what the device is
	capable of,and the call only verifies the information.
	Requires: the pointer to the buffer returned by HidD_GetPreparsedData.
	Returns: a Capabilities structure containing the information.
	*/

	HidP_GetCaps(PreparsedData, &Capabilities);

	//No need for PreparsedData any more, so free the memory it's using.
	HidD_FreePreparsedData(PreparsedData);
}

/************************************************************************************
*   Function: GetInputReportSize
*   Purpose:  Returns the info from capablities
*   Parameters: Void
*   Returns: Input Report size for device
*************************************************************************************/

int CDeviceOEMTool::GetInputReportSize(void)
{
	return(Capabilities.InputReportByteLength);
}
/************************************************************************************
*   Function: GetOutputReportSize
*   Purpose:  Returns the info from capablities
*   Parameters: Void
*   Returns: Input Report size for device
*************************************************************************************/

int CDeviceOEMTool::GetOutputReportSize(void)
{
	return(Capabilities.OutputReportByteLength);
}
/************************************************************************************
*   Function: GetFeatureReportByteLength
*   Purpose:  Returns the info from capablities
*   Parameters: Void
*   Returns: Feature Report size for device
*************************************************************************************/

int CDeviceOEMTool::GetFeatureReportByteLength(void)
{
	return(Capabilities.FeatureReportByteLength);
}

/************************************************************************************
*   Function: ReadReport
*   Purpose:  returns a report
*   Parameters:
*   Returns
*************************************************************************************/
void CDeviceOEMTool::ReadInputReport()
{
#if 0
	// Retrieve an Input report from the device.
	DWORD   Result;
	memset(&InputReport, 0, INPUTREPORTMAX);

	//The first byte is the report number.
	InputReport[0] = 0;

#ifdef GARUDA_HID
	/*API call:ReadFile
	'Returns: the report in InputReport.
	'Requires: a device handle returned by CreateFile
	'(for overlapped I/O, CreateFile must be called with FILE_FLAG_OVERLAPPED),
	'the Input report length in bytes returned by HidP_GetCaps,
	'and an overlapped structure whose hEvent member is set to an event object.
	*/

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		Result = ReadFile(ReadHandle,
			InputReport,
			Capabilities.InputReportByteLength,
			&NumberOfBytesRead,
			(LPOVERLAPPED)&HIDOverlapped);
	}

	/*API call:WaitForSingleObject 'Used with overlapped ReadFile.
	'Returns when ReadFile has received the requested amount of data or on timeout.
	'Requires an event object created with CreateEvent and a timeout value in milliseconds.*/

	/*Here dont chanfe this timeout value from 6000. if you change this you will be in
	 trouble already we ( chak & sudhir) have wasted one complete day on this to investigate
	this problem*/

	Result = WaitForSingleObject(hEventObject, READFILE_WAIT);

	switch (Result)
	{
	case WAIT_OBJECT_0:
	{
		break;
	}
	case WAIT_TIMEOUT:
	{
		/*API call: CancelIo Cancels the ReadFile Requires the device handle.
		Returns non-zero on success.*/
		Result = CancelIo(ReadHandle);
		break;
	}
	default:
	{
		break;
	}
	}

	/*
	API call: ResetEvent Sets the event object to non-signaled.Requires a handle to the
	event object.Returns non-zero on success.*/

	ResetEvent(hEventObject);
#endif 
#ifdef GARUDA_BULK

	UCHAR chTemp[INPUTREPORTMAX];
	if (dev)
	{
		if (usb_bulk_read(dev, EP_IN, (char*)&InputReport[0], 64, 2000)
			== 64)
		{
			TRACE("Read Sucess\n");
			memcpy(chTemp, InputReport, 64);
			memcpy(InputReport + 1, chTemp, 63);
			InputReport[0] = 0;
		}
		else
		{
			TRACE("Read failed\n");
		}
	}

#endif
#endif
	// Retrieve an Input report from the device.
	DWORD   Result;
	memset(&InputReport, 0, INPUTREPORTMAX);

	//The first byte is the report number.
	InputReport[0] = 0;
	if (isHidDevice) {
#ifdef GARUDA_HID
		/*API call:ReadFile
		'Returns: the report in InputReport.
		'Requires: a device handle returned by CreateFile
		'(for overlapped I/O, CreateFile must be called with FILE_FLAG_OVERLAPPED),
		'the Input report length in bytes returned by HidP_GetCaps,
		'and an overlapped structure whose hEvent member is set to an event object.
		*/

		if (ReadHandle != INVALID_HANDLE_VALUE)
		{
			Result = ReadFile(ReadHandle,
				InputReport,
				Capabilities.InputReportByteLength,
				&NumberOfBytesRead,
				(LPOVERLAPPED)&HIDOverlapped);
		}

		/*API call:WaitForSingleObject 'Used with overlapped ReadFile.
		'Returns when ReadFile has received the requested amount of data or on timeout.
		'Requires an event object created with CreateEvent and a timeout value in milliseconds.*/

		/*Here dont chanfe this timeout value from 6000. if you change this you will be in
		 trouble already we ( chak & sudhir) have wasted one complete day on this to investigate
		this problem*/
		
		Result = WaitForSingleObject(hEventObject, READFILE_WAIT);

		switch (Result)
		{
		case WAIT_OBJECT_0:
		{
			break;
		}
		case WAIT_TIMEOUT:
		{
			/*API call: CancelIo Cancels the ReadFile Requires the device handle.
			Returns non-zero on success.*/
			Result = CancelIo(ReadHandle);
			break;
		}
		default:
		{
			break;
		}
		}

		/*
		API call: ResetEvent Sets the event object to non-signaled.Requires a handle to the
		event object.Returns non-zero on success.*/
		SaveBufferToHexTxt(InputReport, Capabilities.InputReportByteLength, "uchDataBuffer_dump.txt");
		ResetEvent(hEventObject);
#endif 
	}
	else {
#ifdef GARUDA_TCP

		//Reading the message from the socket
		UCHAR chTemp[INPUTREPORTMAX];
		memset(&chTemp, 0, INPUTREPORTMAX);
/*		UCHAR chTemp[4096];
		memset(&chTemp, 0, 4096);*/
		int nBytesRead;



		if (ReadDataFromPort(m_serverSockId, chTemp, 512, nBytesRead) == 0)//64
		{

			memcpy(InputReport + 1, chTemp, 512);//64
			InputReport[0] = 0;
		/*	UCHAR	InputReport[4096];
			memcpy(InputReport + 1, chTemp, 4096);
			InputReport[0] = 0;*/
		}
		else
		{
			TRACE("Read failed\n");
		}
#endif
	}
#ifdef GARUDA_BULK

	UCHAR chTemp[INPUTREPORTMAX];
	if (dev)
	{
		if (usb_bulk_read(dev, EP_IN, (char*)&InputReport[0], 64, 2000)
			== 64)
		{
			TRACE("Read Sucess\n");
			memcpy(chTemp, InputReport, 64);
			memcpy(InputReport + 1, chTemp, 63);
			InputReport[0] = 0;
		}
		else
		{
			TRACE("Read failed\n");
		}
	}

#endif
}

/************************************************************************************
*   Function: WriteOutputReport
*   Purpose:  -- calls the API which writes a report to endpoint1
*   Parameters
*       *OutputReport -- the report to be written
*       ReportNumber --
*                    0 : Exchange Input and Output reports
*                    1 : Exchange Feature reports.
*   Returns :
*           zero if the write failed
*************************************************************************************/

BOOL CDeviceOEMTool::WriteOutputReport(unsigned char* ucReport, DWORD dwLength)
{
#if 0
	DWORD   BytesWritten = 0;
	INT     Index = 0;
	ULONG   Result;
	int     tries = 0;
	BOOL    ret_stat = TRUE;

	//The first byte is the report number.
	memset(&OutputReport, 0, OUTPUTREPORTMAX);
#ifdef GARUDA_HID
	OutputReport[0] = 0;
	memcpy(&OutputReport[1], ucReport, dwLength);
#endif

#ifdef GARUDA_BULK    
	memcpy(&OutputReport[0], ucReport, dwLength);
#endif


#ifdef GARUDA_HID
	/*
	API Function: WriteFile
	Sends a report to the device.
	Returns: success or failure.
	Requires:
	A device handle returned by CreateFile.
	A buffer that holds the report.
	The Output Report length returned by HidP_GetCaps,
	A variable to hold the number of bytes written.
	*/
	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		do {
			Result = WriteFile(WriteHandle,
				OutputReport,
				Capabilities.OutputReportByteLength,
				&BytesWritten,
				NULL);
			if (!Result)
			{
				//The WriteFile failed
				tries++;
			}
			else
			{
				/*Data has been written to the device*/
				ret_stat = FALSE;
				break;
			}
		} while (tries < WRITEFILE_TRIES);
	}

#endif

#ifdef GARUDA_BULK

	if (dev)
	{
		if (usb_bulk_write(dev, EP_OUT, (char*)&OutputReport[0], 64, 1000)
			!= 64)
		{
			TRACE("error: bulk write failed\n");
		}
		else
		{
			ret_stat = FALSE;
		}
	}

#endif

	return ret_stat;
#endif
	DWORD   BytesWritten = 0;
	INT     Index = 0;
	ULONG   Result;
	int     tries = 0;
	BOOL    ret_stat = TRUE;

	//The first byte is the report number.
	memset(OutputReport, 0, OUTPUTREPORTMAX+1);
	if (isHidDevice){
#ifdef GARUDA_HID
	/*	if (dwLength > OUTPUTREPORTMAX) {
			// Handle error: either truncate or reject
			dwLength = OUTPUTREPORTMAX; // truncate safely
		}*/
		OutputReport[0] = 0;
		memcpy(&OutputReport[1], ucReport, dwLength);
		SaveBufferToHexTxt(OutputReport, dwLength, "uchDataBuffer_dump.txt");
#endif
	}
	else {
#ifdef GARUDA_TCP
		memcpy(&OutputReport[0], ucReport, dwLength);
#endif
	}
#ifdef GARUDA_BULK    
	memcpy(&OutputReport[0], ucReport, dwLength);
#endif

	if (isHidDevice) {
#ifdef GARUDA_HID
		/*
		API Function: WriteFile
		Sends a report to the device.
		Returns: success or failure.
		Requires:
		A device handle returned by CreateFile.
		A buffer that holds the report.
		The Output Report length returned by HidP_GetCaps,
		A variable to hold the number of bytes written.
		*/
		if (WriteHandle != INVALID_HANDLE_VALUE)
		{
			do {
				Result = WriteFile(WriteHandle,
					OutputReport,
					Capabilities.OutputReportByteLength,
					&BytesWritten,
					NULL);
				if (!Result)
				{
					//The WriteFile failed
					tries++;
				}
				else
				{
					/*Data has been written to the device*/
					ret_stat = FALSE;
					break;
				}
			} while (tries < WRITEFILE_TRIES);
		}

#endif
	}
	else {
#ifdef GARUDA_TCP
/*		UCHAR OutputReport[4096];
		memset(&OutputReport, 0, 4096);
		memcpy(&OutputReport[0], ucReport, dwLength);
		int message_len = strlen((char*)OutputReport);
		Result = send(m_serverSockId, (char*)message_len, sizeof(message_len), 0);*/
		Result = send(m_serverSockId, (char*)OutputReport, dwLength, 0);//dwLength

	//	TRACE("Length Sent - %d, %d\n", Result, dwLength);
		DWORD DWError = WSAGetLastError();
		if (Result == SOCKET_ERROR)
		{
			//Client lost the connection
			TRACE("error: write failed\n");
		}
		else
		{
			ret_stat = FALSE;
		}
#endif
	}

#ifdef GARUDA_BULK

	if (dev)
	{
		if (usb_bulk_write(dev, EP_OUT, (char*)&OutputReport[0], 64, 1000)
			!= 64)
		{
			TRACE("error: bulk write failed\n");
		}
		else
		{
			ret_stat = FALSE;
		}
	}

#endif

	return ret_stat;
}



/*******************************************************************************/
/*  Function: PrepareForOverlappedTransfer                                     */
/*  Purpose:                                                                   */
/*  Parameters: None                                                           */
/*  Returns : None                                                             */
/*******************************************************************************/
void CDeviceOEMTool::PrepareForOverlappedTransfer()
{
	//Get a handle to the device for the overlapped ReadFiles.

	ReadHandle = CreateFile
	(detailData->DevicePath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		(LPSECURITY_ATTRIBUTES)NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL);

	/*API function: CreateEvent
	Requires:
	  Security HIDAttrib or Null
	  Manual reset (true). Use ResetEvent to set the event object's state to non-signaled.
	  Initial state (true = signaled)
	  Event object name (optional)
	Returns: a handle to the event object
	*/

	if (hEventObject == 0)
	{
		hEventObject = CreateEvent(NULL, TRUE, TRUE, "");
		HIDOverlapped.hEvent = hEventObject;
		HIDOverlapped.Offset = 0;
		HIDOverlapped.OffsetHigh = 0;
	}
}
/******************************************************************************/
/*  Function: CloseHandles                                                    */
/*  Purpose:  Close Read, Write and device handles                            */
/*  Parameters: None                                                          */
/*  Returns :                                                                 */
/******************************************************************************/
void CDeviceOEMTool::CloseHandles()
{
#if 0
	if (HidDevHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(HidDevHandle);
	}

	if (ReadHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ReadHandle);
	}

	if (WriteHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(WriteHandle);
	}

#ifdef GARUDA_BULK
	if (dev)
	{
		usb_close(dev);
		dev = NULL;
	}
#endif
#endif
	if (isHidDevice) {
#ifdef GARUDA_HID
		if (HidDevHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(HidDevHandle);
		}

		if (ReadHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ReadHandle);
		}

		if (WriteHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(WriteHandle);
		}
		isHidDevice = 0;
#endif
	}
	else {
#ifdef GARUDA_TCP
		if (m_serverSockId != INVALID_SOCKET)
		{
			closesocket(m_serverSockId);
			m_serverSockId = INVALID_SOCKET;
		}
		isHidDevice = 0;
#endif
	}

#ifdef GARUDA_BULK
	if (dev)
	{
		usb_close(dev);
		dev = NULL;
	}
#endif
}
/******************************************************************************/
/*                  U T I L I T Y F U N C T I O N S                           */
/******************************************************************************/
/******************************************************************************/
/*  Function Name   :GetConfig()                                              */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ERROR                                               */
/*  Description     :                                                         */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::GetConfig(SCONFIG* psIptPtrConfig, unsigned long ulChannelID)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	unsigned char ucReport[OUTPUTREPORTMAX];
	int nBytesToWrite = 0;
	J2534ERROR      ret_stat = J2534_ERR_TIMEOUT;
	DWORD           dwWaitStatus;
	BufferCommand_t* GetConfig;
	GetConfig = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	Inputbuffer = (InputBuffer_t*)bufCmdAck;

	/*jayasheela-added to handle single wire IOCTl commands */
	//unsigned char pulIoctlParameter;

	//GetIoctlParameter(psIptPtrConfig,&pulIoctlParameter);
	memset(&ucReport, 0, OUTPUTREPORTMAX);
#if 0
	ucReport[0] = (unsigned char)m_enChannelList[ulChannelID];// m_enChannelList[m_nChannelID]; //nikhileshtest_deleted
	ucReport[1] = ECU_IOCTL_COMMAND;
	ucReport[2] = GET_CONFIG;
	ucReport[3] = 0x01; /* No. of commands */
	ucReport[4] = psIptPtrConfig->Parameter;
#endif
	GetConfig->proto_id = (unsigned long)m_enChannelList[ulChannelID];
	GetConfig->command = ECU_IOCTL_COMMAND;
	GetConfig->u.GetConfig.IOCTL_ID = GET_CONFIG;
	GetConfig->u.GetConfig.rsvd = 0x01;
	GetConfig->u.GetConfig.Parameter = psIptPtrConfig->Parameter;

	ResetEvent(m_CmdAck);


	/*Write the IOCTL value to the device*/
	if (!WriteOutputReport(ucReport, 13))//5
	{
		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
		/*	if (bufCmdAck[1] == m_enChannelList[ulChannelID] &&
				bufCmdAck[2] == ECU_IOCTL_RESPONSE) */
			if (Inputbuffer->proto_id == m_enChannelList[ulChannelID] &&
				Inputbuffer->command == ECU_IOCTL_RESPONSE)
			{
				/*jayasheela-added to map parameter values */
			//	if (bufCmdAck[4] == J2534_STATUS_NOERROR && bufCmdAck[6] == psIptPtrConfig->Parameter)
				if ( Inputbuffer->u.Getconfig.status== J2534_STATUS_NOERROR && Inputbuffer->u.Getconfig.parameter == psIptPtrConfig->Parameter)
				{
					/*Send back the data to the above layer*/
					switch (psIptPtrConfig->Parameter)
					{
					case DATA_RATE:
					{
						//psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
#if 0
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[8] << 8);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[9] << 16);
#endif
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | Inputbuffer->u.Getconfig.value << 8;
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | Inputbuffer->u.Getconfig.value1 << 16;
					}
					break;
					case BIT_SAMPLE_POINT:
					{
						//psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
					}
					break;
					/*KWP and ISO9141 related IOCTL Parameters*/
					case P1_MAX:
					case P3_MIN:
					case P4_MIN:
					case W0:
					case W1:
					case W2:
					case W3:
					case W4:
					case W5:
					case TIDLE:
					case TINIL:
					case TWUP:
					{
#if 0
						psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[8] << 8);
#endif
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (Inputbuffer->u.Getconfig.value << 8);
					}
					break;
					case PARITY:
					case DATA_BITS:
					case FIVE_BAUD_MOD:
					{
						//psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
					}
					break;
					/*SCI related IOCTL Parameters*/
					case T1_MAX:
					case T2_MAX:
					case T3_MAX:
					case T4_MAX:
					case T5_MAX:
					{
#if 0					   
						psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[8] << 8);
#endif
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (Inputbuffer->u.Getconfig.value << 8);
					}
					break;
					/*J1850 Related IOCTL Parameters*/
					case NODE_ADDRESS:
					case NETWORK_LINE:
					{
					//	psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
					}
					break;
					/*ISO15765 Related IOCTL Parameters*/
					/*Ravi : The bellow get config is not sent to Hadware
					interface and hence does not need any proceeing here */
					/*
					case ISO15765_BS:
					case ISO15765_STMIN:
					case BS_TX:
					case STMIN_TX:
					case ISO15765_WFT_MAX:
					*/
					/*Single Wire CAN Related IOCTL Parameters : J2534-2*/
					case SWCAN_HS_DATA_RATE:
					{
						//psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
#if 0
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[8] << 8);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[9] << 16);
#endif
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | Inputbuffer->u.Getconfig.value << 8;
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | Inputbuffer->u.Getconfig.value1 << 16;
					}
					break;
					case SWCAN_SPEEDCHANGE_ENABLE:
					case SWCAN_RES_SWITCH:
					{
					//	psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
					}
					break;
					case J1962_PINS:
					{
#if 0					   
						psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (bufCmdAck[8] << 8);
#endif
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
						psIptPtrConfig->ulValue = psIptPtrConfig->ulValue | (Inputbuffer->u.Getconfig.value << 8);
					}
					break;
					case LOOPBACK:
					{
					//	psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
					 	psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
						//psIptPtrConfig->ulValue = m_bLoopBack;
						//m_ulLastErrorCode = J2534_STATUS_NOERROR;
					}
					break;
					case FD_ISO15765_TX_DATA_LENGTH:
					{
					//	psIptPtrConfig->ulValue = (bufCmdAck[7] & 0xFF);
						psIptPtrConfig->ulValue = (Inputbuffer->u.Getconfig.datarate & 0xFF);
					}
					break;
					default:
						ret_stat = J2534_ERR_NOT_SUPPORTED;
					}

					// Write to Log File.
					LogToDebugFile("GetConfig", DEBUGLOG_TYPE_COMMENT, "GetConfig Successful");
					ret_stat = J2534_STATUS_NOERROR;
				}
				else
				{
				//	ret_stat = (J2534ERROR)bufCmdAck[4];
			    	ret_stat = (J2534ERROR)Inputbuffer->u.Getconfig.status;
				}
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			ret_stat = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return ret_stat;
}
/******************************************************************************/
/*  Function Name   :SetConfig()                                              */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ERROR                                               */
/*  Description     :                                                         */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::SetConfig(SCONFIG* psIptPtrConfig, unsigned long ulChannelID)
{
	unsigned char ucReport[OUTPUTREPORTMAX];
	memset(&ucReport, 0, OUTPUTREPORTMAX);
	SetConfig_t* SetConfig;
	SetConfig = (SetConfig_t*)ucReport;
	int nBytesToWrite = 0;
	/*jayasheela-added to handle single wire IOCTl commands */
	//unsigned char pulIoctlParameter;

	//GetIoctlParameter(psIptPtrConfig,&pulIoctlParameter);
	switch (psIptPtrConfig->Parameter)
	{
		/*DataRate IOCTL common for all protocols*/
	case DATA_RATE:
		/*KWP and ISO9141 related IOCTL Parameters*/
	case P1_MAX:
	case P3_MIN:
	case P4_MIN:
	case W0:
	case W1:
	case W2:
	case W3:
	case W4:
	case W5:
	case TIDLE:
	case TINIL:
	case TWUP:
	case PARITY:
	case DATA_BITS:
	case FIVE_BAUD_MOD:
		/*SCI related IOCTL Parameters*/
	case T1_MAX:
	case T2_MAX:
	case T3_MAX:
	case T4_MAX:
	case T5_MAX:
		/*J1850 Related IOCTL Parameters*/
	case NODE_ADDRESS:
	case NETWORK_LINE:
	{
#if 0
		ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
		ucReport[2] = (unsigned char)(psIptPtrConfig->ulValue >> 8 & 0x000000FF);
		ucReport[3] = (unsigned char)(psIptPtrConfig->ulValue >> 16 & 0x000000FF);
		ucReport[4] = (unsigned char)(psIptPtrConfig->ulValue >> 24 & 0x000000FF);
#endif

		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter & 0x000000FF);
		SetConfig->value = (unsigned long)psIptPtrConfig->ulValue;
		nBytesToWrite = 8;
		m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
	}
	break;
	case FD_CAN_DATA_PHASE_RATE:
	{
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter);
		//SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue);
		nBytesToWrite = 8;
	//	m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	/*ISO15765 Related IOCTL Parameters*/
	case ISO15765_BS:
	{
		m_ByteISO15765_BS = (unsigned long)(psIptPtrConfig->ulValue & 0x000000FF);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	/*Jayasheela-removed comment to handle BS and STMIIN*/

	case FD_ISO15765_TX_DATA_LENGTH:
	{
		m_FD_ISO15765_DATA_LENGTH = (unsigned long)(psIptPtrConfig->ulValue & 0x000000FF);
	/*	ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);*/
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter);
		SetConfig->value = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
	//	SetConfig->value = 64;
		nBytesToWrite = 8;
		m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
	//	m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	case ISO15765_STMIN:
	{
		m_ByteISO15765_STMIN = (unsigned long)(psIptPtrConfig->ulValue & 0x000000FF);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	case BS_TX:
	{
		//if(0xFFFF==psIptPtrConfig->ulValue)

		m_nBlockSizeTx = (unsigned int)(psIptPtrConfig->ulValue & 0x0000FFFF);

		//	else
			//	m_nBlockSizeTx = (unsigned char) (psIptPtrConfig->ulValue  & 0x000000FF);

		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	case STMIN_TX:
	{
		if (0xFFFF == psIptPtrConfig->ulValue)

			m_nSTminTx = (unsigned char)(psIptPtrConfig->ulValue & 0x0000FFFF);

		else
			m_nSTminTx = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);

		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;

	case ISO15765_WFT_MAX:
	{
		m_ByteISO15765_WFT_MAX = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;

	/*Single Wire CAN Related IOCTL Parameters : J2534-2*/
	case SWCAN_HS_DATA_RATE:
	case SWCAN_SPEEDCHANGE_ENABLE:
	case SWCAN_RES_SWITCH:
	case J1962_PINS:
	{  
#if 0
		ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
		ucReport[2] = (unsigned char)(psIptPtrConfig->ulValue >> 8 & 0x000000FF);
		ucReport[3] = (unsigned char)(psIptPtrConfig->ulValue >> 16 & 0x000000FF);
		ucReport[4] = (unsigned char)(psIptPtrConfig->ulValue >> 24 & 0x000000FF);
#endif
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter & 0x000000FF);
		SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue);
		nBytesToWrite = 8;
		m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
	}
	break;
	case J1962__PINS:
	{  
#if 0
		ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
		ucReport[2] = (unsigned char)(psIptPtrConfig->ulValue >> 8 & 0x000000FF);
		ucReport[3] = (unsigned char)(psIptPtrConfig->ulValue >> 16 & 0x000000FF);
		ucReport[4] = (unsigned char)(psIptPtrConfig->ulValue >> 24 & 0x000000FF);
#endif
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter);
		//SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue);
		SetConfig->value = 1550;
		nBytesToWrite = 8;
	//	m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	case FD_ISO15765_PS_J1962_PINS:
	{
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter);
		SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue);
		nBytesToWrite = 8;
	//	m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
		m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	case LOOPBACK:
	{ 
#if 0
		ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
#endif
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter & 0x000000FF);
		SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue & 0x000000FF);
		nBytesToWrite = 8;
		m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
		m_bLoopBack = psIptPtrConfig->ulValue;
		//m_ulLastErrorCode = J2534_STATUS_NOERROR;
	}
	break;
	/*Jayasheela-Added to handle the SYNC_JUMP_WIDTH*/
	case SYNC_JUMP_WIDTH:
		/*Jayasheela-Added to handle the BIT_SAMPLE_POINT*/
	case BIT_SAMPLE_POINT:
	{
#if 0
		ucReport[0] = (unsigned char)(psIptPtrConfig->Parameter & 0x000000FF);
		ucReport[1] = (unsigned char)(psIptPtrConfig->ulValue & 0x000000FF);
		ucReport[2] = (unsigned char)(psIptPtrConfig->ulValue >> 8 & 0x000000FF);
		ucReport[3] = (unsigned char)(psIptPtrConfig->ulValue >> 16 & 0x000000FF);
		ucReport[4] = (unsigned char)(psIptPtrConfig->ulValue >> 24 & 0x000000FF);
#endif
		SetConfig->parameter = (unsigned long)(psIptPtrConfig->Parameter & 0x000000FF);
		SetConfig->value = (unsigned long)(psIptPtrConfig->ulValue);
		nBytesToWrite = 8;
		m_ulLastErrorCode = SendIOCTLData(SET_CONFIG, ucReport, nBytesToWrite, ulChannelID);
	}
	break;
	case J1939_BRDCST_MIN_DELAY:
	{
		m_ulJ1939_BRDCST_MIN_DELAY = psIptPtrConfig->ulValue;
	}
	break;
	default:
		m_ulLastErrorCode = J2534_ERR_NOT_SUPPORTED;
		break;
	}
	return m_ulLastErrorCode;
}

/******************************************************************************/
/*  Function Name   :FastInit()                                               */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ERROR                                               */
/*  Description     :                                                         */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::FastInit(PASSTHRU_MSG* pInput, PASSTHRU_MSG* pOutPut, unsigned long ulChannelID)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	unsigned char ucReport[OUTPUTREPORTMAX];
	memset(&ucReport, 0, OUTPUTREPORTMAX);
	DWORD dwWaitStatus;

	ucReport[0] = (unsigned char)m_enChannelList[ulChannelID];//m_enChannelList[m_nChannelID]; //nikhileshtest_deleted
	ucReport[1] = ECU_IOCTL_COMMAND;
	ucReport[2] = FAST_INIT;
	ucReport[3] = (unsigned char)pInput->ulDataSize;
	memcpy(&ucReport[4], &pInput->ucData[0], pInput->ulDataSize);

	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport, pInput->ulDataSize + 4))
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, FAST_INIT_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			if (bufCmdAck[2] == ECU_IOCTL_RESPONSE &&
				bufCmdAck[4] == J2534_STATUS_NOERROR)
			{
				m_ptFastInitResponse.ulDataSize = bufCmdAck[5];
				m_ptFastInitResponse.ulTxFlags = 0x00;
				m_ptFastInitResponse.ulRxStatus = 0x00;
				m_ptFastInitResponse.ulTimeStamp = 0;
				m_ptFastInitResponse.ulExtraDataIndex = m_ptFastInitResponse.ulDataSize;
				memcpy(&m_ptFastInitResponse.ucData[0], &bufCmdAck[6],
					m_ptFastInitResponse.ulDataSize);

				/*Copy the response to output pointer*/
				memcpy(pOutPut, &m_ptFastInitResponse, sizeof(PASSTHRU_MSG));
				//*pOutPut = m_ptFastInitResponse;
				m_bFastInitIssued = FALSE;

				// Write to Log File.
				LogToDebugFile("FastInit", DEBUGLOG_TYPE_COMMENT, "FastInit Successful");
				return J2534_STATUS_NOERROR;
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			// Write to Log File.
			LogToDebugFile("FastInit", DEBUGLOG_TYPE_ERROR, "FastInit Failed");
			return J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return J2534_ERR_FAILED;
}

/******************************************************************************/
/*  Function Name   :CarbInit()                                               */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ERROR                                               */
/*  Description     :                                                         */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::FiveBaudInit(SBYTE_ARRAY* pInput, SBYTE_ARRAY* pOutput, unsigned long ulChannelID)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	unsigned char ucReport[OUTPUTREPORTMAX];
	DWORD dwWaitStatus;
	J2534ERROR      ret_stat = J2534_ERR_FAILED;

	memset(&ucReport, 0, OUTPUTREPORTMAX);

	ucReport[0] = (unsigned char)m_enChannelList[ulChannelID]; //m_enChannelList[m_nChannelID];//nikhileshtest_deleted
	ucReport[1] = ECU_IOCTL_COMMAND;
	ucReport[2] = FIVE_BAUD_INIT;
	ucReport[3] = 0x01;
	ucReport[4] = pInput->pucBytePtr[0];

	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport, 5))
	{


		dwWaitStatus = WaitForSingleObject(m_CmdAck, FIVEBAUD_INIT_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			if (bufCmdAck[1] == m_enChannelList[ulChannelID]
				&& bufCmdAck[2] == ECU_IOCTL_RESPONSE)
			{
				if (bufCmdAck[4] == J2534_STATUS_NOERROR)
				{
					pOutput->pucBytePtr[0] = bufCmdAck[6];
					pOutput->pucBytePtr[1] = bufCmdAck[7];
					pOutput->ulNumOfBytes = 2;
					// Write to Log File.
					LogToDebugFile("FiveBaudInit", DEBUGLOG_TYPE_COMMENT, "FiveBaudInit Successful");
					ret_stat = J2534_STATUS_NOERROR;
				}
				else
				{
					ret_stat = (J2534ERROR)bufCmdAck[4];
				}
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			ret_stat = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return ret_stat;
}
/******************************************************************************/
/*  Function Name   :ProtectJ1939Addr                                         */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ERROR                                               */
/*  Description     :                                                         */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::ProtectJ1939Address(SBYTE_ARRAY* pInput, SBYTE_ARRAY* pOutput, unsigned long ulChannelID)
{
	J2534ERROR enJ2534Error = J2534_STATUS_NOERROR;
	unsigned char ucReport[OUTPUTREPORTMAX];
	DWORD dwWaitStatus;

	memset(&ucReport, 0, OUTPUTREPORTMAX);

	ucReport[0] = (unsigned char)m_enChannelList[ulChannelID]; //m_enChannelList[m_nChannelID];//nikhileshtest_deleted
	ucReport[1] = ECU_IOCTL_COMMAND;
	ucReport[2] = PROTECT_J1939_ADDR_HFCP_ID;
	ucReport[3] = pInput->ulNumOfBytes;
	memcpy(ucReport + 4, pInput->pucBytePtr, pInput->ulNumOfBytes);

	ResetEvent(m_CmdAck);

	if (!WriteOutputReport(ucReport, 4 + pInput->ulNumOfBytes))
	{
		dwWaitStatus = WaitForSingleObject(m_CmdAck, ENABLE_COMM_WAIT);
		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{
			if ((bufCmdAck[1] == m_enChannelList[ulChannelID]) &&
				(bufCmdAck[2] == ECU_IOCTL_RESPONSE) &&
				(bufCmdAck[3] == PROTECT_J1939_ADDR_HFCP_ID))
			{

				enJ2534Error = (J2534ERROR)bufCmdAck[4];
			}
		}
		break;
		case WAIT_TIMEOUT:
		{
			enJ2534Error = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}

	return enJ2534Error;
}
/******************************************************************************/
/*  Function Name   :LogToDebugFile                                           */
/*  Input Params    :                                                         */
/*  Output Params   :                                                         */
/*  Return          :                                                         */
/*  Description     :                                                         */
/******************************************************************************/
void CDeviceOEMTool::LogToDebugFile(CString szFunct, int nDebugType,
	CString szLogInfo)
{
	if ((m_pclsLog != NULL) &&
		(m_pclsLog->m_pfdLogFile != NULL))
	{
		m_pclsLog->Write("DeviceOEMTool.cpp", szFunct, nDebugType, szLogInfo);
	}
}
/******************************************************************************/
/*  Function Name   :SendIOCTLData()                                          */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ETL data to the device.                       */
/******************************************************************************/
J2534ERROR CDeviceOEMTool::SendIOCTLData(J2534IOCTLID enmIOCTLID,
	unsigned char* ucData, int nBytesToWrite, unsigned long ulChannelID)
{
	unsigned char ucReport[OUTPUTREPORTMAX];
	DWORD           dwWaitStatus;
	J2534ERROR      ret_stat = J2534_ERR_FAILED;
	BufferCommand_t* SendIOCTLData;
	SendIOCTLData = (BufferCommand_t*)ucReport;
	InputBuffer_t* Inputbuffer;
	memset(&ucReport, 0, OUTPUTREPORTMAX);
#if 0
	ucReport[0] = (unsigned char)m_enChannelList[ulChannelID];//m_enChannelList[m_nChannelID];//nikhileshtest_deleted
	ucReport[1] = ECU_IOCTL_COMMAND;
	ucReport[2] = enmIOCTLID;
	ucReport[3] = 0x01;
#endif
	SendIOCTLData->proto_id = (unsigned long)m_enChannelList[ulChannelID];//m_enChannelList[m_nChannelID];//nikhileshtest_deleted
	SendIOCTLData->command = ECU_IOCTL_COMMAND;
	SendIOCTLData->u.SendIOCTLData.IOCTL_ID = enmIOCTLID;
	SendIOCTLData->u.SendIOCTLData.rsvd = 0x01;

	if (enmIOCTLID != CLEAR_FUNCT_MSG_LOOKUP_TABLE)
		memcpy(&SendIOCTLData->u.SendIOCTLData.data, &ucData[0], nBytesToWrite);
	//	memcpy(&ucReport[4], &ucData[0], nBytesToWrite);

	ResetEvent(m_CmdAck);


	if (!WriteOutputReport(ucReport, nBytesToWrite + 10)) //4
	{

		dwWaitStatus = WaitForSingleObject(m_CmdAck, SENDIOCTLDATA_WAIT);

		switch (dwWaitStatus)
		{
		case WAIT_OBJECT_0:
		{  
		    	Inputbuffer = (InputBuffer_t*)bufCmdAck;

	//		if (bufCmdAck[1] == m_enChannelList[ulChannelID]
	//			&& bufCmdAck[2] == ECU_IOCTL_RESPONSE)
			if (Inputbuffer->proto_id == m_enChannelList[ulChannelID]
				&& Inputbuffer->command == ECU_IOCTL_RESPONSE)
			{
			//	if (bufCmdAck[4] == J2534_STATUS_NOERROR)
				if (Inputbuffer->u.sendIOCTL.status == J2534_STATUS_NOERROR)
				{
					// Write to Log File.
					LogToDebugFile("SendIOCTLData", DEBUGLOG_TYPE_COMMENT, "SendIOCTLData Successful");
					ret_stat = J2534_STATUS_NOERROR;
				}
				else
				{
					//ret_stat = (J2534ERROR)bufCmdAck[4];
					  ret_stat = (J2534ERROR)Inputbuffer->u.sendIOCTL.status;
				}
			}
			break;
		}
		case WAIT_TIMEOUT:
		{
			ret_stat = J2534_ERR_TIMEOUT;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return ret_stat;
}
/******************************************************************************/
/*  Function Name   :GetIndexToStoreMessage()                                          */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ETL data to the device.                       */
/******************************************************************************/
unsigned long CDeviceOEMTool::GetIndexToStoreMessage(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData)
{
	unsigned long	i;
	for (i = 0; i < 10; i++)
	{
		if (stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ulProtocolID == 0)
			return(i);
		stSaveRxMultipleSegmData++;
	}
	return(0xff);
}
unsigned long CDeviceOEMTool::GetJ1939MsgIndex(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData, unsigned long ulProtocolId,
	unsigned long uchSrc, bool bBAMMsg)
{
	unsigned long ulMsgIdx = 0xFF;

	for (int nIdx = 0; nIdx < 10; nIdx++)
	{
		if (stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ulProtocolID == ulProtocolId)
		{
			if (stSaveRxMultipleSegmData->bBAM == bBAMMsg)
			{
				if ((stSaveRxMultipleSegmData->bBAM) && (stSaveRxMultipleSegmData->nBAMRTSSource == uchSrc))
				{
					return nIdx;
				}
				else if ((!stSaveRxMultipleSegmData->bBAM) && (stSaveRxMultipleSegmData->nCTSRTSSource == uchSrc))
				{
					return nIdx;
				}

				return nIdx;
			}
		}

		stSaveRxMultipleSegmData++;
	}

	return ulMsgIdx;
}
/******************************************************************************/
/*  Function Name   :GetMsgIndex()                                          */
/*  Input Params    :NULL                                                     */
/*  Output Params   :NULL                                                     */
/*  Return          :J2534ETL data to the device.                       */
/******************************************************************************/
unsigned long CDeviceOEMTool::GetMsgIndex(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData,
	PASSTHRU_MSG stPassRxThruMsg,
	unsigned char ucCANIDSize)
{
//	unsigned char i, j;
	static int i, j;
	bool bPattrenMatchFound;
	unsigned long ulStoredStRxstatus;
	unsigned long ulRxRxstatus;
	bPattrenMatchFound = FALSE;
	/*check extended address bit in Tx flags */
	ulStoredStRxstatus = stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ulRxStatus & ISO15765_ADDR_TYPE;
	ulRxRxstatus = stPassRxThruMsg.ulRxStatus & ISO15765_ADDR_TYPE;
	for (i = 0; i < 10; i++)
	{
		if (0 != stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ulProtocolID)
		{
			if (ulStoredStRxstatus & ulRxRxstatus)
			{
				for (j = 0; j < ucCANIDSize; j++)
				{
					if (stPassRxThruMsg.ucData[j] == stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ucData[j])
					{
						if (4 == j)
						{
							bPattrenMatchFound = TRUE;
						}
					}
					else
					{
						break;
					}
				}
				if (bPattrenMatchFound)
				{
					break;
				}
			}
			else if ((!ulStoredStRxstatus) & (!ulRxRxstatus))
			{
				for (j = 0; j < ucCANIDSize; j++)
				{
					if (stPassRxThruMsg.ucData[j] == stSaveRxMultipleSegmData->stSaveMultSegmPassRxThruMsg.ucData[j])
					{
						if (3 == j)
						{
							bPattrenMatchFound = TRUE;
						}
					}
					else
					{
						break;
					}

				}
				if (bPattrenMatchFound)
				{
					break;
				}
			}
			else
			{
				//do nothing
			}
		}
		stSaveRxMultipleSegmData++;
	}
	if (bPattrenMatchFound)
	{
		return i;
	}
	else
	{
		return (0xff);
	}
}
/******************************************************************************/
/*  Function Name   :SendISO15765MsgToDevice()                                */
/*  Input Params    :No of frames,blk size,frame index                        */
/*  Output Params   :NULL                                                     */
/*	Description		:Function will send 7 CAN frames in a single USB frame	  */
/*  Return          :J2534ERROR								  .               */
/******************************************************************************/
/*Jayasheela-added to send the multiple consecutive frames in a single USB frame*/
J2534ERROR CDeviceOEMTool::SendISO15765MsgToDevice(const int num_frames, int block_size, int* frame_index, int seperation_time)

{


#ifdef  GARUDA_BULK

	unsigned char uchDataBuffer[512];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames;
	}

	unsigned int index = 0;
	unsigned int nDataLengthIdx = 0;
	while ((*frame_index) < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		//unsigned int index = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
		uchDataBuffer[index++] = ECU_SENDMESSAGE;
		uchDataBuffer[index++] = 0x00; /* Segment Id. */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the conversation Id */
		uchDataBuffer[index++] = (seperation_time & 0xFF);/* STMIN byte0 */
		index++; /* Needed to skip the STMIN byte1 */
		for (int i = 0; i < 7; i++) /*7 since only 7 mesage to append in single USB frame*/
		{
			/* Ravi : Saparation time not to be handled in the 2534 dll.
			It needs to be handled in the firmware implementaion. This needs
				to be sent to firmware as a parameter on the USB after # of messages */
				/* if (seperation_time > 0) 			::Sleep (seperation_time); */

			nTotalDataLength += pCan->_data_len;
			memcpy(&uchDataBuffer[index], &pCan->_data[0], pCan->_data_len);
			index += pCan->_data_len;
			(*frame_index) += 1;
			if ((*frame_index) < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		uchDataBuffer[nDataLengthIdx + 4] = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		uchDataBuffer[nDataLengthIdx + 3] = (unsigned char)((nTotalDataLength) & 0xFF);

		nDataLengthIdx = nDataLengthIdx + 64;
		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		/*if(WriteOutputReport(uchDataBuffer,64))
		{
		return J2534_ERR_FAILED;
		}
		else
		{
		//do nothing
	}*/
	}

	if (index > 0)
	{
		if (dev)
		{
			if (usb_bulk_write(dev, EP_OUT, (char*)&uchDataBuffer[0], index, 1000)
				!= index)
			{
				TRACE("error: bulk write failed\n");
			}
			else
			{
				TRACE("error: bulk write Success\n");
				//ret_stat= FALSE;
			}
		}

	}
	return J2534_STATUS_NOERROR;

#endif

//#ifdef  GARUDA_HID
#ifdef  GARUDA_TCP
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames - (*frame_index);
	}

	unsigned long ulNumFramesTransmitted = 0;

	while (ulNumFramesTransmitted < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		unsigned int index = 0;
		int len = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		BufferCommand_t* pWriteMsgs;
		pWriteMsgs = (BufferCommand_t*)uchDataBuffer;
		/*	uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
			uchDataBuffer[index++] = ECU_SENDMESSAGE;
			uchDataBuffer[index++] = 0x00; /* Segment Id. */
			//	index++; /* Needed to skip the mode and data lenght */
			//	index++; /* Needed to skip the mode and data lenght */
			//	index++; /* Needed to skip the conversation Id */
		pWriteMsgs->proto_id = m_enChannelList[m_nChannelID];
		pWriteMsgs->command = ECU_SENDMESSAGE;
		len = sizeof(pWriteMsgs->proto_id) + sizeof(pWriteMsgs->command);
		pWriteMsgs->u.Mode2.segnum = 0x00;
		pWriteMsgs->u.Mode2.Conversation_ID = 0x00;
		//uchDataBuffer[index++] = (seperation_time & 0xFF);/* STMIN byte0 */
		pWriteMsgs->u.Mode2.STmin1 = (seperation_time & 0xFF);/* STMIN byte0 */
		//	index++; /* Needed to skip the STMIN byte1 */'
		index = 0;
		for (int i = 0; i < 7; i++) /*7 since only 7 mesage to append in single USB frame*/
		{
			/* Ravi : Saparation time not to be handled in the 2534 dll.
			It needs to be handled in the firmware implementaion. This needs
				to be sent to firmware as a parameter on the USB after # of messages */
				/* if (seperation_time > 0) 			::Sleep (seperation_time); */

			nTotalDataLength += pCan->_data_len;
			memcpy(&pWriteMsgs->u.Mode2.Data_Bytes[index], &pCan->_data[0], pCan->_data_len);
			ulNumFramesTransmitted++;
			index += pCan->_data_len;
			(*frame_index) += 1;
			if (ulNumFramesTransmitted < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		//uchDataBuffer[4] =(unsigned char) (0x80 | (nTotalDataLength >> 8 & 0xFF) );
		//uchDataBuffer[3] =(unsigned char) ((nTotalDataLength) & 0xFF);
		pWriteMsgs->u.Mode2.Messagelength1 = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		pWriteMsgs->u.Mode2.Messagelength = (unsigned char)((nTotalDataLength) & 0xFF);
		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		if (WriteOutputReport(uchDataBuffer, 512)) // chiru 64
		{
			return J2534_ERR_FAILED;
		}
		else
		{
			//do nothing
		}
	}
	return J2534_STATUS_NOERROR;

#endif	
}


J2534ERROR CDeviceOEMTool::SendFDISO15765MsgToDevice(const int num_frames, int block_size, int* frame_index, int seperation_time)

{


#ifdef  GARUDA_BULK

	unsigned char uchDataBuffer[512];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames;
	}

	unsigned int index = 0;
	unsigned int nDataLengthIdx = 0;
	while ((*frame_index) < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		//unsigned int index = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
		uchDataBuffer[index++] = ECU_SENDMESSAGE;
		uchDataBuffer[index++] = 0x00; /* Segment Id. */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the conversation Id */
		uchDataBuffer[index++] = (seperation_time & 0xFF);/* STMIN byte0 */
		index++; /* Needed to skip the STMIN byte1 */
		for (int i = 0; i < 7; i++) /*7 since only 7 mesage to append in single USB frame*/
		{
			/* Ravi : Saparation time not to be handled in the 2534 dll.
			It needs to be handled in the firmware implementaion. This needs
				to be sent to firmware as a parameter on the USB after # of messages */
				/* if (seperation_time > 0) 			::Sleep (seperation_time); */

			nTotalDataLength += pCan->_data_len;
			memcpy(&uchDataBuffer[index], &pCan->_data[0], pCan->_data_len);
			index += pCan->_data_len;
			(*frame_index) += 1;
			if ((*frame_index) < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		uchDataBuffer[nDataLengthIdx + 4] = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		uchDataBuffer[nDataLengthIdx + 3] = (unsigned char)((nTotalDataLength) & 0xFF);

		nDataLengthIdx = nDataLengthIdx + 64;
		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		/*if(WriteOutputReport(uchDataBuffer,64))
		{
		return J2534_ERR_FAILED;
		}
		else
		{
		//do nothing
	}*/
	}

	if (index > 0)
	{
		if (dev)
		{
			if (usb_bulk_write(dev, EP_OUT, (char*)&uchDataBuffer[0], index, 1000)
				!= index)
			{
				TRACE("error: bulk write failed\n");
			}
			else
			{
				TRACE("error: bulk write Success\n");
				//ret_stat= FALSE;
			}
		}

	}
	return J2534_STATUS_NOERROR;

#endif
#if 0
//#ifdef  GARUDA_HID
#ifdef GARUDA_TCP
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames - (*frame_index);
	}

	unsigned long ulNumFramesTransmitted = 0;

	while (ulNumFramesTransmitted < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		unsigned int index = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
		uchDataBuffer[index++] = ECU_SENDMESSAGE;
		uchDataBuffer[index++] = 0x00; /* Segment Id. */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the mode and data lenght */
		index++; /* Needed to skip the conversation Id */
		uchDataBuffer[index++] = (seperation_time & 0xFF);/* STMIN byte0 */
		index++; /* Needed to skip the STMIN byte1 */
		for (int i = 0; i < 6; i++) /*6 since only 6 mesage to append in single USB frame*/
		{
			/* Ravi : Saparation time not to be handled in the 2534 dll.
			It needs to be handled in the firmware implementaion. This needs
				to be sent to firmware as a parameter on the USB after # of messages */
				/* if (seperation_time > 0) 			::Sleep (seperation_time); */

			nTotalDataLength += pCan->_data_len;
			memcpy(&uchDataBuffer[index], &pCan->_data[0], pCan->_data_len);
			ulNumFramesTransmitted++;
			index += pCan->_data_len;
			(*frame_index) += 1;
			if (ulNumFramesTransmitted < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		uchDataBuffer[4] = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		uchDataBuffer[3] = (unsigned char)((nTotalDataLength) & 0xFF);
		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		if (WriteOutputReport(uchDataBuffer, 512)) // chiru 64
		{
			return J2534_ERR_FAILED;
		}
		else
		{
			//do nothing
		}
	}
	return J2534_STATUS_NOERROR;

#endif
#endif
//#ifdef  GARUDA_HID
#ifdef GARUDA_TCP

	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	unsigned long ulFlags;
	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	ulFlags = 0x00000000;
	// Write to Log File.
	LogToDebugFile("SendToECU", DEBUGLOG_TYPE_COMMENT, " Continue to send SendISO15765messgToECU");

	int block_limit = 0;
	if (block_size < (num_frames - (*frame_index)))
	{
		block_limit = block_size;
	}
	else
	{
		block_limit = num_frames - (*frame_index);
	}

	unsigned long ulNumFramesTransmitted = 0;

	while (ulNumFramesTransmitted < block_limit)
	{
		unsigned long nTotalDataLength = 0;
		unsigned int index = 0;
		int len = 0;
		CCanMsg* pCan = (CCanMsg*)m_TxList.GetAt((*frame_index));
		BufferCommand_t* pWriteMsgs;
		pWriteMsgs = (BufferCommand_t*)uchDataBuffer;
		/*	uchDataBuffer[index++] = m_enChannelList[m_nChannelID];
			uchDataBuffer[index++] = ECU_SENDMESSAGE;
			uchDataBuffer[index++] = 0x00; /* Segment Id. */
			//	index++; /* Needed to skip the mode and data lenght */
			//	index++; /* Needed to skip the mode and data lenght */
			//	index++; /* Needed to skip the conversation Id */
		pWriteMsgs->proto_id = m_enChannelList[m_nChannelID];
		pWriteMsgs->command = ECU_SENDMESSAGE;
		len = sizeof(pWriteMsgs->proto_id) + sizeof(pWriteMsgs->command);
		pWriteMsgs->u.Mode2.segnum = 0x00;
		pWriteMsgs->u.Mode2.Conversation_ID = 0x00;
		//uchDataBuffer[index++] = (seperation_time & 0xFF);/* STMIN byte0 */
		pWriteMsgs->u.Mode2.STmin1 = (seperation_time & 0xFF);/* STMIN byte0 */
		//	index++; /* Needed to skip the STMIN byte1 */'
		index = 0;
		for (int i = 0; i < 7; i++) /*7 since only 7 mesage to append in single USB frame*/
		{
			/* Ravi : Saparation time not to be handled in the 2534 dll.
			It needs to be handled in the firmware implementaion. This needs
				to be sent to firmware as a parameter on the USB after # of messages */
				/* if (seperation_time > 0) 			::Sleep (seperation_time); */

			nTotalDataLength += pCan->_data_len;
			memcpy(&pWriteMsgs->u.Mode2.Data_Bytes[index], &pCan->_data[0], pCan->_data_len);
			ulNumFramesTransmitted++;
			index += pCan->_data_len;
			(*frame_index) += 1;
			if (ulNumFramesTransmitted < block_limit)
			{
				pCan = (CCanMsg*)m_TxList.GetAt(*frame_index);
			}
			else
			{
				break;
			}
		}
		//uchDataBuffer[4] =(unsigned char) (0x80 | (nTotalDataLength >> 8 & 0xFF) );
		//uchDataBuffer[3] =(unsigned char) ((nTotalDataLength) & 0xFF);
		pWriteMsgs->u.Mode2.Messagelength1 = (unsigned char)(0x80 | (nTotalDataLength >> 8 & 0xFF));
		pWriteMsgs->u.Mode2.Messagelength = (unsigned char)((nTotalDataLength) & 0xFF);
		/*Write the data to the device*/
		//if(!WriteOutputReport(uchDataBuffer,nDataLength))
		if (WriteOutputReport(uchDataBuffer, 512)) // chiru 64
		{
			return J2534_ERR_FAILED;
		}
		else
		{
			//do nothing
		}
	}
	return J2534_STATUS_NOERROR;

#endif	
}

//*****************************************************************************
//	Function Name	: GetPGNFromHeader
//	Input Params	: 
//	Output Params	: 
//	Description		: This function to get the PGN from the message id
//*****************************************************************************
bool CDeviceOEMTool::GetPGNParametersFromHeader(ULONG ulReqHdr, UCHAR& uchPriority, ULONG& ulPGN, UCHAR& uchPDUSpecific,
	UCHAR& uchPDUFormat, UCHAR& uchSrcAddr, UCHAR& uchDestAddr)
{
	bool bResult = TRUE;

	//Check whether Header is 11 bit or 29 bit Id
	if (ulReqHdr <= 0x7FF)
		return FALSE;

	//To get the Priority
	uchPriority = (UCHAR)((ulReqHdr >> 26) & 0x07);

	//To get the PDU Format
	uchPDUFormat = (UCHAR)((ulReqHdr >> 16) & 0xFF);

	//To get the PDU Specific
	uchPDUSpecific = (UCHAR)((ulReqHdr >> 8) & 0xFF);

	//To get the PGN & Destination Address
	//Global PGN's
	ulPGN = (ulReqHdr >> 8) & 0xFFFF;
	if (uchPDUFormat >= 0xF0)
	{
		uchDestAddr = 0xFF;
	}
	else //Specific destination PGN's
	{
		ulPGN = (ULONG)(ulPGN & 0xFF00);
		uchDestAddr = (UCHAR)((ulReqHdr >> 8) & 0xFF);
	}

	//To get the Src Address
	uchSrcAddr = (UCHAR)(ulReqHdr & 0xFF);

	return bResult;
}

//*****************************************************************************
//	Function Name	: GetPGNFromHeader
//	Input Params	: 
//	Output Params	: 
//	Description		: This function to get the PGN from the message id
//*****************************************************************************
bool CDeviceOEMTool::GetPGNParametersFromHeader(ULONG ulReqHdr, UCHAR& uchPriority, ULONG& ulPGN, UCHAR& uchSrcAddr, UCHAR& uchDestAddr)
{
	UCHAR uchPDUSpecific;
	UCHAR uchPDUFormat;
	bool bResult = TRUE;

	//Check whether Header is 11 bit or 29 bit Id
	if (ulReqHdr <= 0x7FF)
		return FALSE;

	//To get the Priority
	uchPriority = (UCHAR)((ulReqHdr >> 26) & 0x07);

	//To get the PDU Format
	uchPDUFormat = (UCHAR)((ulReqHdr >> 16) & 0xFF);

	//To get the PDU Specific
	uchPDUSpecific = (UCHAR)((ulReqHdr >> 8) & 0xFF);

	//To get the PGN & Destination Address
	//Global PGN's
	ulPGN = (ulReqHdr >> 8) & 0xFFFF;
	if (uchPDUFormat >= 0xF0)
	{
		uchDestAddr = 0xFF;
	}
	else //Specific destination PGN's
	{
		ulPGN = (ULONG)(ulPGN & 0xFF00);
		uchDestAddr = (UCHAR)((ulReqHdr >> 8) & 0xFF);
	}

	//To get the Src Address
	uchSrcAddr = (UCHAR)(ulReqHdr & 0xFF);

	return bResult;
}

//*****************************************************************************
//	Function Name	: ComputeJ1939Header
//	Input Params	: 
//	Output Params	: 
//	Description		: This function computes the Header from the I/P Parameters
//*****************************************************************************
ULONG CDeviceOEMTool::ComputeJ1939Header(UCHAR uchPriority, ULONG ulPGN, UCHAR uchSrcAddr, UCHAR uchDestAddr)
{
	ULONG ulHeader = 0x00;

	//Set Destination in Addr
	if (((ulPGN >> 8) & 0xFF) < 0xF0)
	{
		ulPGN = ulPGN & 0x1FF00;
		ulPGN |= uchDestAddr;
	}

	//Priority 	Reserved 	Data page 	PDU format 	PDU specific 	Source Address
	//3 bits 	1 bit 		1 bit 		8 bits 		8 bits 			8 bits
	ulHeader = (ULONG)((uchPriority << 26) | (ulPGN << 8) | uchSrcAddr);


	return ulHeader;
}
/******************************DOIP****************************************/
J2534ERROR CDeviceOEMTool::vDOIPServer(
									   char* sIPAddr,
								       unsigned short laddr,
	                                   unsigned int* pVIN,
	                                   unsigned int* pEID,
	                                   unsigned int* pGID)
{
	J2534ERROR ret_status = J2534_STATUS_NOERROR;
	int len = 16;

	memcpy((void*)server_ip_addr, sIPAddr, len);

	//Tester_logical_addr = laddr;
	ECU_logical_addr = laddr;

	return ret_status;

}
J2534ERROR CDeviceOEMTool::vDOIPClient(unsigned short laddr)
{
	m_ulLastErrorCode = DOIP_configure_client(laddr);
	return m_ulLastErrorCode;
}
J2534ERROR CDeviceOEMTool::vDOIPIPAddr(char* sIPAddr)
{
	m_ulLastErrorCode = DOIP_GET_IPAddr(sIPAddr);
	return m_ulLastErrorCode;
}
J2534ERROR CDeviceOEMTool::DOIP_configure_server(
												 char* sIPAddr,
												 unsigned short laddr,
												 unsigned int* pVIN,
												 unsigned int* pEID,
											     unsigned int* pGID)
{
	unsigned char ucReport[40];
	BufferCommand_t* req;
	InputBuffer_t* Inputbuffer;
	DWORD dwWaitStatus;
	J2534ERROR ret_status = J2534_ERR_FAILED;
	req = (BufferCommand_t*)ucReport;
	int len, cmd_prot_len;
	ZeroMemory(ucReport, 40);
	cmd_prot_len = sizeof(BufferCommand_t) - sizeof(req->u);
	memset(req, 0, sizeof(req));
	req->proto_id = DOIP_PROTOCOL_ID;
	req->command =DOIP_CLI_CMD_ADD_DOIP_SERVER;
	len = sizeof(req->u.doipserver.ipaddr);
	memcpy((void*)req->u.doipserver.ipaddr, sIPAddr, len);
	req->u.doipserver.ipaddr[len - 1] = '\0';
	req->u.doipserver.laddr = laddr; //0x0E80
//	memcpy((void*)req.u.doipserver.vin, pVIN, 20); //req.u.doipserver.vin);
//	memcpy((void*)req.u.doipserver.eid, pEID, 10);//req.u.doipserver.eid);
//	memcpy((void*)req.u.doipserver.gid, pGID, 10); //req.u.doipserver.gid);
	len = cmd_prot_len + sizeof(doip_cli_cmd_add_doip_server_t);

	ResetEvent(m_CmdAck);
//	Sleep(1500);
	if (WriteOutputReport(ucReport, len) != TRUE) {
		dwWaitStatus = WaitForSingleObject(m_CmdAck, DOIP_PROTO_WAIT);
		switch (dwWaitStatus) {
		case WAIT_OBJECT_0:
			 Inputbuffer = (InputBuffer_t*)bufCmdAck;
			if (Inputbuffer->proto_id == DOIP_PROTOCOL_ID &&
				Inputbuffer->command == DOIP_CLI_CMD_ADD_DOIP_SERVER&&
				Inputbuffer->u.ADD_SERVER.status == J2534_STATUS_NOERROR) {
				LogToDebugFile("DOIP_config", DEBUGLOG_TYPE_COMMENT, "DoIP_config");
				ret_status = J2534_STATUS_NOERROR;
				TRACE("DOIP: Config_DoIP client\n");
			}
			else {
				ret_status = J2534_ERR_NOT_SUPPORTED;
				TRACE("DOIP: Config_DoIP client failed\n");
			}
			break;
		case WAIT_TIMEOUT:
			TRACE("DOIP: TIMEOUT\n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		default:
			break;
		}
	}
	return ret_status;
}

J2534ERROR CDeviceOEMTool::DOIP_configure_client(unsigned short laddr)
{
	unsigned char ucReport[40];
	BufferCommand_t* req;
	DWORD dwWaitStatus;
	InputBuffer_t* Inputbuffer;
	req = (BufferCommand_t*)ucReport;
	ZeroMemory(ucReport, 40);
	J2534ERROR ret_status = J2534_ERR_FAILED;
	int len;
	memset(req, 0, sizeof(req));
	req->proto_id = DOIP_PROTOCOL_ID;
	req->command = DOIP_CLI_CMD_START_SESSION;
	req->u.doipclient.logical_addr = laddr; //0x0E80;//laddr;
    Tester_logical_addr = laddr;//0x0E80;//
	len = sizeof(BufferCommand_t) - sizeof(req->u) + sizeof(doip_cli_cmd_start_session_t);

	ResetEvent(m_CmdAck);
	if (WriteOutputReport(ucReport, len) != TRUE) {
		dwWaitStatus = WaitForSingleObject(m_CmdAck, DOIP_PROTO_WAIT);
		switch (dwWaitStatus) {
		case WAIT_OBJECT_0:
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
			if (Inputbuffer->proto_id == DOIP_PROTOCOL_ID &&
				Inputbuffer->command == DOIP_CLI_CMD_START_SESSION &&
				Inputbuffer->u.ADD_CLIENT.status == J2534_STATUS_NOERROR) {
				LogToDebugFile("DOIP_CLI_CMD_START_SESSION", DEBUGLOG_TYPE_COMMENT, "DoIP Sesson started");
				ret_status = J2534_STATUS_NOERROR;
				TRACE("DOIP: Started DoIP session\n");
			}
			else {
				ret_status = J2534_ERR_NOT_SUPPORTED;
				TRACE("DOIP: Starting session failed\n");
			}
			break;
		case WAIT_TIMEOUT:
			TRACE("DOIP: TIMEOUT\n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		default:
			break;
		}
	}
	return ret_status;
}

J2534ERROR CDeviceOEMTool::DOIP_GET_IPAddr(char* sIPAddr)
{
	unsigned char ucReport[40];
	BufferCommand_t req;
	DWORD dwWaitStatus;
	J2534ERROR ret_status = J2534_ERR_FAILED;
	int len;
	memset(&req, 0, sizeof(req));
	req.proto_id = DOIP_PROTOCOL_ID;
	req.command = DOIP_CLI_CMD_START_SESSION;

	len = sizeof(req.u.doipipaddr.ipaddr);
	memcpy((void*)req.u.doipipaddr.ipaddr, sIPAddr, len);
	req.u.diagmsg.ipaddr[len - 1] = '\0';
	memcpy((void*)server_ip_addr, sIPAddr, len);
	len = sizeof(BufferCommand_t) - sizeof(req.u) + sizeof(doip_cli_cmd_start_session_t);
	ResetEvent(m_CmdAck);
	return ret_status;
}

J2534ERROR CDeviceOEMTool::vDOIPSENDMSG( unsigned short dst_laddr,
	unsigned char* pDiagMsg,
	unsigned long msglen)
{
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	//	unsigned char* outputBuffer = NULL;
	//	outputBuffer = (unsigned char*)malloc(sizeof(unsigned char) * OUTPUTREPORTMAX);

	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	DWORD dwWaitStatus;
	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)uchDataBuffer;
	InputBuffer_t* Inputbuffer;
	J2534ERROR ret_status = J2534_ERR_FAILED;
	int len;
	unsigned long diagMessageByteLeft;
	unsigned long diagMessageLen = msglen - 4;//pstPassThruMsg->ulDataSize - 4;
	int DIOP_DIAG_HDR_LEN = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) + sizeof(doip_cli_cmd_diag_msg_t);
	int MAX_DIAG_PAC_LEN = OUTPUTREPORTMAX - DIOP_DIAG_HDR_LEN;

	pWriteMsgs->proto_id = DOIP_PROTOCOL_ID;
	pWriteMsgs->command = DOIP_CLI_CMD_SEND_DIAG_MSG;
	pWriteMsgs->u.diagmsg.seqNum = 0;
	len = sizeof(pWriteMsgs->u.diagmsg.ipaddr);
	memcpy((void*)pWriteMsgs->u.diagmsg.ipaddr, server_ip_addr, len);
#if 0
	int NoOfPackets = (diagMessageLen / MAX_DIAG_PAC_LEN);
	if ((diagMessageLen % MAX_DIAG_PAC_LEN) != 0)
	{
		NoOfPackets++;
	}
#endif
	diagMessageByteLeft = diagMessageLen;
	pWriteMsgs->u.diagmsg.dst_laddr = dst_laddr; //pstPassThruMsg->ucData[2] & 0x0F;
//	pWriteMsgs->u.diagmsg.dst_laddr = (pWriteMsgs->u.diagmsg.dst_laddr << 8) | pstPassThruMsg->ucData[3];
	int len1 = 4;
	while (diagMessageByteLeft != 0)
	{
		if (diagMessageByteLeft > MAX_DIAG_PAC_LEN)
		{
			pWriteMsgs->u.diagmsg.msg_len = MAX_DIAG_PAC_LEN;
			pWriteMsgs->u.diagmsg.lastpkt = 0;
		}
		else
		{
			pWriteMsgs->u.diagmsg.msg_len = diagMessageByteLeft;
			pWriteMsgs->u.diagmsg.lastpkt = 1;
		}
		if (diagMessageByteLeft > MAX_DIAG_PAC_LEN)
		{
			pWriteMsgs->u.diagmsg.seqNum++;
			memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pDiagMsg[len1], pWriteMsgs->u.diagmsg.msg_len);
			len = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) + sizeof(doip_cli_cmd_diag_msg_t) + pWriteMsgs->u.diagmsg.msg_len;
			WriteOutputReport(uchDataBuffer, len);
			len1 += pWriteMsgs->u.diagmsg.msg_len;
		}
		else
		{
			if (pWriteMsgs->u.diagmsg.seqNum)
			{
				pWriteMsgs->u.diagmsg.seqNum++;
				memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pDiagMsg[len1], pWriteMsgs->u.diagmsg.msg_len);
			}
			else
			{
				pWriteMsgs->u.diagmsg.seqNum++;
				memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pDiagMsg[4], pWriteMsgs->u.diagmsg.msg_len);
			}
		}
		//	pWriteMsgs->u.diagmsg.seqNum++;
		diagMessageByteLeft -= pWriteMsgs->u.diagmsg.msg_len;
		//memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pstPassThruMsg->ucData[4], pWriteMsgs->u.diagmsg.msg_len);
	}

	//	pWriteMsgs->u.diagmsg.seqNum++;
	len = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) + sizeof(doip_cli_cmd_diag_msg_t) + pWriteMsgs->u.diagmsg.msg_len; //diag_msg_len

	ResetEvent(m_CmdAck);
	if (WriteOutputReport(uchDataBuffer, len) != TRUE) {
		dwWaitStatus = WaitForSingleObject(m_CmdAck, DOIP_PROTO_WAIT);
		switch (dwWaitStatus) {
		case WAIT_OBJECT_0:
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
			if (Inputbuffer->proto_id == DOIP_PROTOCOL_ID &&
				Inputbuffer->command == DOIP_CLI_CMD_SEND_DIAG_MSG &&
				Inputbuffer->u.DAIG_MSG.status == J2534_STATUS_NOERROR) {
				LogToDebugFile("DIOP_DIAG_MSG", DEBUGLOG_TYPE_COMMENT, "DoIP diagmsg");
				ret_status = J2534_STATUS_NOERROR;
				TRACE("DOIP: Sent diag msg\n");
			}
			else {
				ret_status = J2534_ERR_NOT_SUPPORTED;
				TRACE("DOIP: Send failed - diagmsg\n");
			}
			break;
		case WAIT_TIMEOUT:
			TRACE("DOIP: TIMEOUT\n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		default:
			break;
		}
	}
	return ret_status;



}

J2534ERROR CDeviceOEMTool::SendDOIPMessage(PASSTHRU_MSG* pstPassThruMsg, unsigned char ucChannelId)
{
	unsigned char uchDataBuffer[OUTPUTREPORTMAX];
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];

	ZeroMemory(uchDataBuffer, OUTPUTREPORTMAX);
	DWORD dwWaitStatus;
	BufferCommand_t* pWriteMsgs;
	pWriteMsgs = (BufferCommand_t*)uchDataBuffer;
	InputBuffer_t* Inputbuffer;
	J2534ERROR ret_status = J2534_ERR_FAILED;
	int len;
	unsigned long diagMessageByteLeft;
	unsigned long diagMessageLen = pstPassThruMsg->ulDataSize - 4;
	int DIOP_DIAG_HDR_LEN = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) +sizeof(doip_cli_cmd_diag_msg_t);
	int MAX_DIAG_PAC_LEN = OUTPUTREPORTMAX - DIOP_DIAG_HDR_LEN ;

	pWriteMsgs->proto_id = DOIP_PROTOCOL_ID;
	pWriteMsgs->command = DOIP_CLI_CMD_SEND_DIAG_MSG;
	pWriteMsgs->u.diagmsg.seqNum = 0;
	len = sizeof(pWriteMsgs->u.diagmsg.ipaddr);
	memcpy((void*)pWriteMsgs->u.diagmsg.ipaddr, server_ip_addr, len);
#if 0
	int NoOfPackets = (diagMessageLen / MAX_DIAG_PAC_LEN);
	if ((diagMessageLen % MAX_DIAG_PAC_LEN) != 0)
	{
		NoOfPackets++;
	}
#endif
	diagMessageByteLeft = diagMessageLen;
	pWriteMsgs->u.diagmsg.dst_laddr = pstPassThruMsg->ucData[2] & 0x0F;
	pWriteMsgs->u.diagmsg.dst_laddr = (pWriteMsgs->u.diagmsg.dst_laddr << 8) | pstPassThruMsg->ucData[3];
	int len1 = 4;
	while (diagMessageByteLeft != 0)
	{
		if (diagMessageByteLeft > MAX_DIAG_PAC_LEN)
		{
			pWriteMsgs->u.diagmsg.msg_len = MAX_DIAG_PAC_LEN;
			pWriteMsgs->u.diagmsg.lastpkt = 0;
		}
		else
		{
			pWriteMsgs->u.diagmsg.msg_len = diagMessageByteLeft;
			pWriteMsgs->u.diagmsg.lastpkt = 1;
		}
		if (diagMessageByteLeft > MAX_DIAG_PAC_LEN)
		{
			pWriteMsgs->u.diagmsg.seqNum++;
			memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pstPassThruMsg->ucData[len1], pWriteMsgs->u.diagmsg.msg_len);
			len = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) + sizeof(doip_cli_cmd_diag_msg_t) + pWriteMsgs->u.diagmsg.msg_len;
		//	SaveBufferToHexTxt(uchDataBuffer, sizeof(uchDataBuffer), "uchDataBuffer_dump.txt");
			WriteOutputReport(uchDataBuffer, len);
			len1 += pWriteMsgs->u.diagmsg.msg_len;
		}
		else
		{
			if (pWriteMsgs->u.diagmsg.seqNum)
			{
				pWriteMsgs->u.diagmsg.seqNum++;
				memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pstPassThruMsg->ucData[len1], pWriteMsgs->u.diagmsg.msg_len);
			}
			else
			{
				pWriteMsgs->u.diagmsg.seqNum++;
				memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pstPassThruMsg->ucData[4], pWriteMsgs->u.diagmsg.msg_len);
			}
		}
	//	pWriteMsgs->u.diagmsg.seqNum++;
		diagMessageByteLeft -= pWriteMsgs->u.diagmsg.msg_len;
		//memcpy(&pWriteMsgs->u.diagmsg.diag_data[0], &pstPassThruMsg->ucData[4], pWriteMsgs->u.diagmsg.msg_len);
	}

//	pWriteMsgs->u.diagmsg.seqNum++;
	len = sizeof(BufferCommand_t) - sizeof(pWriteMsgs->u) + sizeof(doip_cli_cmd_diag_msg_t) + pWriteMsgs->u.diagmsg.msg_len; //diag_msg_len

	ResetEvent(m_CmdAck);
//	SaveBufferToHexTxt(uchDataBuffer, sizeof(uchDataBuffer), "uchDataBuffer_dump.txt");
	if (WriteOutputReport(uchDataBuffer,len) != TRUE) {
		dwWaitStatus = WaitForSingleObject(m_CmdAck, DOIP_PROTO_WAIT);
		switch (dwWaitStatus) {
		case WAIT_OBJECT_0:
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
			if (Inputbuffer->proto_id == DOIP_PROTOCOL_ID &&
				Inputbuffer->command == DOIP_CLI_CMD_SEND_DIAG_MSG &&
				Inputbuffer->u.DAIG_MSG.status == J2534_STATUS_NOERROR) {
				LogToDebugFile("DIOP_DIAG_MSG", DEBUGLOG_TYPE_COMMENT, "DoIP diagmsg");
				ret_status = J2534_STATUS_NOERROR;
				TRACE("DOIP: Sent diag msg\n");
			}
			else {
				ret_status = J2534_ERR_NOT_SUPPORTED;
				TRACE("DOIP: Send failed - diagmsg\n");
			}
			break;
		case WAIT_TIMEOUT:
			TRACE("DOIP: TIMEOUT\n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		default:
			break;
		}
	}
	return ret_status;
}


J2534ERROR CDeviceOEMTool::vDOIPClientDetails(char* Ipaddr,
	char* netmask,
	char* gwaddr,
	unsigned short laddr)
{

	J2534ERROR ret_status = J2534_STATUS_NOERROR;
	int len = 16;

	FILE* configFile;
	char line[MAX_LINE_LENGTH];
	char* ipAddress = NULL;
    
/*	configFile = fopen("Garuda.ini", "r");
	if (configFile == NULL) {
		fprintf(stderr, "error:unable to open config file.\n");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, MAX_LINE_LENGTH, configFile) != NULL) {
		if (strstr(line, "IPAddress") != NULL) {
			ipAddress = strtok(line, "=");
			ipAddress = strtok(NULL, "=");
			break;
		}
	}
	fclose(configFile);*/
//	memcpy((void*)client_ip_addr, ipAddress, len);
	memcpy((void*)client_ip_addr, Ipaddr, len);

	memcpy((void*)subnetaddr, netmask, len);

	memcpy((void*)Gwaddr, gwaddr, len);

//	ECU_logical_addr = laddr;
	Tester_logical_addr = laddr;

	return ret_status;

}


J2534ERROR CDeviceOEMTool::DOIPClientDetailsSEND(char* Ipaddr,
	char* netmask,
	char* gwaddr,
	unsigned short laddr)
{
	unsigned char ucReport[70];
	BufferCommand_t* ClientDetails;
	InputBuffer_t* Inputbuffer;
	DWORD dwWaitStatus;
	J2534ERROR ret_status = J2534_ERR_FAILED;
	ClientDetails = (BufferCommand_t*)ucReport;
	int len, cmd_prot_len;
	ZeroMemory(ucReport, 70);
	cmd_prot_len = sizeof(BufferCommand_t) - sizeof(ClientDetails->u);
	memset(ClientDetails, 0, sizeof(ClientDetails));
	ClientDetails->proto_id = DOIP_PROTOCOL_ID;
	ClientDetails->command = DOIP_CLI_DETAILS;
	len = sizeof(ClientDetails->u.doipclientdetails.ipaddr);
	memcpy((void*)ClientDetails->u.doipclientdetails.ipaddr, Ipaddr, len);
	ClientDetails->u.doipclientdetails.ipaddr[len - 1] = '\0';
	memcpy((void*)ClientDetails->u.doipclientdetails.subnet, netmask, len);
	ClientDetails->u.doipclientdetails.subnet[len - 1] = '\0';
	memcpy((void*)ClientDetails->u.doipclientdetails.Gwaddr, gwaddr, len);
	ClientDetails->u.doipclientdetails.Gwaddr[len - 1] = '\0';
	ClientDetails->u.doipclientdetails.laddr = laddr;//0XE080;//laddr;

	len = cmd_prot_len + sizeof(doipclientdetails_t);

	ResetEvent(m_CmdAck);
	if (WriteOutputReport(ucReport, len) != TRUE) {
		dwWaitStatus = WaitForSingleObject(m_CmdAck, DOIP_PROTO_WAIT);
		switch (dwWaitStatus) {
		case WAIT_OBJECT_0:
			Inputbuffer = (InputBuffer_t*)bufCmdAck;
			if (Inputbuffer->proto_id == DOIP_PROTOCOL_ID &&
				Inputbuffer->command == DOIP_CLI_DETAILS &&
				Inputbuffer->u.DOIP_CLIENT_RESPONSE.status == J2534_STATUS_NOERROR) {
				LogToDebugFile("DOIP_config", DEBUGLOG_TYPE_COMMENT, "DoIP_config");
				ret_status = J2534_STATUS_NOERROR;
				TRACE("DOIP: Config_DoIP client\n");
			}
			else {
				ret_status = J2534_ERR_NOT_SUPPORTED;
				TRACE("DOIP: Config_DoIP client failed\n");
			}
			break;
		case WAIT_TIMEOUT:
			TRACE("DOIP: TIMEOUT\n");
			m_ulLastErrorCode = J2534_ERR_TIMEOUT;
			break;
		default:
			break;
		}
	}
	return ret_status;

}

J2534ERROR CDeviceOEMTool::vDOIPSetTesterLogicalID(unsigned short Taddr)
{
	Tester_logical_addr = Taddr;
	return J2534_STATUS_NOERROR;
}

J2534ERROR CDeviceOEMTool::vDOIPSetECULogicalID(unsigned short Eaddr)
{
	ECU_logical_addr = Eaddr;
	return J2534_STATUS_NOERROR;
}

BOOL CDeviceOEMTool::validate_port(unsigned short addr)
{
	if ((addr >= 2000) && (addr <= 15000))
	{
		return TRUE;
	}
	return FALSE;
}
BOOL CDeviceOEMTool::validate_ip_range(char* ipaddr)
{
	while (*ipaddr) {
		if (*ipaddr < '0' || *ipaddr>'9') {
			return FALSE;
		}
		ipaddr++;
	}
	return TRUE;
}
BOOL CDeviceOEMTool::validate_ip(char* ipaddr)
{
	char *str, *ip_ptr;
	ip_ptr = (char*)calloc(1, sizeof(strlen(ipaddr) + 1));
	strcpy(ip_ptr, ipaddr);
	int num = 0, count = 0;
	if (ip_ptr == NULL) 
	{
		return FALSE;
	}
	if ((str = strtok(ip_ptr, ".")) == NULL)
	{
		return FALSE;
	}
	while (str) {
		if (validate_ip_range(str) < 0) {
			return FALSE;
		}
		num = atoi(str);
		if (num < 0 || num>255) {
			return FALSE;
		}
		if (str = strtok(NULL, "."))
			count++;
	}
	return TRUE;
}
/*************************************************************************************
			Garuda OEM TOOL TCP Device Interface Implementations
************************************************************************************/
BOOL CDeviceOEMTool::bOpenTCPInterfaceDevice()
{
	struct sockaddr_in sockaddr;
	WSADATA wsaData;
	int nPortNo = 9000;//5001
	//To initialize the winsock library
	if (WSAStartup(0x101, &wsaData))//0x101 wversion requested
	{
		// Write to Log File.
		LogToDebugFile("bOpenTCPInterfaceDevice", DEBUGLOG_TYPE_ERROR, "Win Sock Init Fail");
		return false;
	}

	//To create the socket
	m_serverSockId = socket(AF_INET, SOCK_STREAM, 0);
	if (m_serverSockId == INVALID_SOCKET)
	{
		LogToDebugFile("bOpenTCPInterfaceDevice", DEBUGLOG_TYPE_ERROR, "Create Sock Fail");
		return false;
	}

	LogToDebugFile("bOpenTCPInterfaceDevice", DEBUGLOG_TYPE_ERROR, "Create Sock Success");

	//To initialize the sockaddr_in structure
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(nPortNo);
	sockaddr.sin_addr.s_addr = inet_addr("192.168.1.1");	//"192.168.23.158"//172.31.0.1

	int flag = 1;
	int nResult = setsockopt(m_serverSockId, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
	if (nResult < 0)
		TRACE("\nError in Setsockopt");
	// Commented MAHA	
	if (connect(m_serverSockId, (struct sockaddr*)&sockaddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		DWORD DRResult = WSAGetLastError();
		LogToDebugFile("bOpenTCPInterfaceDevice", DEBUGLOG_TYPE_ERROR, "Connect Sock Failed");
		return false;
	}
	else
	{
		LogToDebugFile("bOpenTCPInterfaceDevice", DEBUGLOG_TYPE_ERROR, "Connect Sock Success");
		HidAttached = TRUE;
		HidDevHandle = (void*)m_serverSockId;
	}
	return true;
}
BOOL CDeviceOEMTool::ReadDataFromPort(SOCKET sockId, unsigned char* puchBuffer, int nBufferSize, int& nBytesRead)
{
	int nResult;
	int nRetryIdx;
	nBytesRead = 0;
	nRetryIdx = 0;
/*	int message_len;
	nResult == recv(sockId, (char*)&message_len, sizeof(message_len), 0);*/

	while (/*(nRetryIdx++ < MAX_ITERATIONS) && */(nBytesRead < nBufferSize))
	{
		//read the data from port
//		nResult = recv(sockId, (char*)puchBuffer + nBytesRead, message_len - nBytesRead, 0);

		nResult = recv(sockId, (char*)puchBuffer + nBytesRead, nBufferSize - nBytesRead, 0);
		if (nResult == 0 || nResult == SOCKET_ERROR)
		{
			return SOCKET_ERROR;
		}

		nBytesRead += nResult;
	}

	/*CString strTemp = puchBuffer;
	int nIdx;
	if(nIdx = strTemp.Find("*HELLO*") == -1)
	{
		return FALSE;
	}
	else
	{
		unsigned char chTempBuff[64];
		memcpy(chTempBuff,puchBuffer   + 7,64-7);

		nBufferSize = 7;
		nBytesRead = 0;

		while((nBytesRead < nBufferSize))
		{
			//read the data from port
			nResult = recv(sockId,(char*)puchBuffer + nBytesRead,nBufferSize - nBytesRead,0);
			if(nResult == 0 || nResult == SOCKET_ERROR)
			{
				return SOCKET_ERROR;
			}

			nBytesRead += nResult;
		}

		memcpy(chTempBuff + 64-7-1,puchBuffer,7);
		memcpy(puchBuffer,chTempBuff,64);
	}*/

	//if(nBytesRead == nBufferSize)
		//return FALSE;

	return FALSE;
}

J2534ERROR CDeviceOEMTool::vEnableRNDIS()
{
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	int ret;
	m_ulLastErrorCode = J2534_ERR_FAILED;
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);

	BufferCommand_t* EnableRNDIS;
	InputBuffer_t* Inputbuffer;

	std::string vendorID = "0x03EB"; 
	std::string productID = "0x5746";

	ret = FindRNDISDevices(vendorID, productID);

	if (ret == true)
	{
		EnableRNDIS = (BufferCommand_t*)uchDataBuffer;
		EnableRNDIS->proto_id = J2534_ENABLERNDIS;
		EnableRNDIS->command = 0x01;
		int len = sizeof(EnableRNDIS->proto_id) + sizeof(EnableRNDIS->command);

		len += sizeof(EnableRNDIS->u.Enable_RNDIS);

//		EnableRNDIS->u.Enable_RNDIS = ENABLERNDISSESSION;
		if (!WriteOutputReport(uchDataBuffer, len))
		{

			ReadInputReport();
//			Sleep(5000);
			if (InputReport[1] != 0)
			{

				TRACE("Got a command ack \n");

				/* Copy the command ack data to the buffer */
				for (int i = INPUTREPORTMAX; i >= 0; i--)
				{
					bufCmdAck[i] = InputReport[i];
				}
				Inputbuffer = (InputBuffer_t*)bufCmdAck;

				if (Inputbuffer->proto_id == J2534_ENABLERNDIS &&
					Inputbuffer->u.Enablerndis.Status == J2534_STATUS_NOERROR)
				{
					LogToDebugFile("vEnableRNDIS", DEBUGLOG_TYPE_COMMENT, "vLoggingStatus Successful");
					m_ulLastErrorCode = J2534_STATUS_NOERROR;
					return m_ulLastErrorCode;
				}
				else
				{
					//m_ulLastErrorCode = (J2534ERROR)bufCmdAck[3];
					m_ulLastErrorCode = (J2534ERROR)(Inputbuffer->u.Enablerndis.STARTSESSION);
					return m_ulLastErrorCode;
				}
			}

		}
	}
	else
	{
		// Write to Log File.
		if ((m_pclsLog != NULL) && (m_pclsLog->m_pfdLogFile != NULL))
		{
			sprintf(szBuffer, "OpenDeviceFail returned 0x%02X", m_ulLastErrorCode);
			m_pclsLog->Write("DeviceOEMTool.cpp", "vEnableRNDIS()",
				DEBUGLOG_TYPE_COMMENT, szBuffer);
		}
		return J2534_ERR_DEVICE_NOT_CONNECTED;
	}

}
int CDeviceOEMTool::FindRNDISDevices(const std::string& vendorID, const std::string& productID) {
	// Get device info set for all network devices
	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);// | DIGCF_DEVICEINTERFACE
	if (hDevInfo == INVALID_HANDLE_VALUE) {
		return 0;
	}
	SP_DEVINFO_DATA devInfoData;
	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	for (DWORD index = 0; SetupDiEnumDeviceInfo(hDevInfo, index, &devInfoData); ++index) {
			// Check if the device is a USB device
		if (IsRNDISDevice(hDevInfo, devInfoData, vendorID, productID)) {
				return true;
		}
	}
	
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return false;
}
BOOL CDeviceOEMTool::IsRNDISDevice(HDEVINFO hDevInfo, SP_DEVINFO_DATA& devInfoData, const std::string& vendorID, const std::string& productID) {
	DWORD dataType;
	BYTE buffer[1024];
	DWORD bufferSize = sizeof(buffer);

	// Get the hardware ID property for the device
	if (SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_HARDWAREID, &dataType, buffer, bufferSize, &bufferSize)) {
		// Convert the hardware ID to a string
		std::string hardwareId(reinterpret_cast<char*>(buffer));

		std::string searchVendorID = "VID_" + vendorID.substr(2);  
		std::string searchProductID = "PID_" + productID.substr(2); 

		// Check for the presence of VID and PID in the hardware ID
		if (hardwareId.find(searchVendorID) != std::string::npos && hardwareId.find(searchProductID) != std::string::npos) {
			return TRUE;  // The device matches the VID and PID
		}
	}

	return FALSE;
}

J2534ERROR CDeviceOEMTool::vDisableRNDIS()
{
	char    szBuffer[DEVICEBASE_ERROR_TEXT_SIZE];
	m_ulLastErrorCode = J2534_ERR_FAILED;
	unsigned char uchDataBuffer[80];
	ZeroMemory(uchDataBuffer, 80);

	BufferCommand_t* DisableRNDIS;

	DisableRNDIS = (BufferCommand_t*)uchDataBuffer;
	DisableRNDIS->proto_id = J2534_DISABLERNDIS;
	DisableRNDIS->command = 0x01;
	int len = sizeof(DisableRNDIS->proto_id) + sizeof(DisableRNDIS->command);

	if (!WriteOutputReport(uchDataBuffer, len))
	{
		return J2534_STATUS_NOERROR;
	}
}

/*void WriteHIDReportToLog(const unsigned char* ucReport, DWORD dwLength)
{
	TCHAR publicPath[MAX_PATH];

	// Get "C:\Users\Public\Documents" path
	if (SHGetFolderPath(NULL, CSIDL_COMMON_DOCUMENTS, NULL, SHGFP_TYPE_CURRENT, publicPath) == S_OK)
	{
		// Construct full file path
		CString logFilePath;
		logFilePath.Format(_T("%s\\DoIP_HID_Log.txt"), publicPath);

		// Open file in append mode
		std::ofstream logFile(logFilePath, std::ios::app);
		if (logFile.is_open())
		{
			logFile << "[HID Length: " << dwLength << "] ";
			for (DWORD i = 0; i < dwLength; ++i)
			{
				logFile << std::hex << std::uppercase << std::setw(2)
					<< std::setfill('0') << static_cast<int>(ucReport[i]) << " ";
			}
			logFile << std::endl;
			logFile.close();
		}
	}
}*/
/*void ComputeLogFileName()
{
	TCHAR path[MAX_PATH];
	HRESULT hr;
	CString logfilePath = _T("");
	CString garudalogfileFolder = _T("");
	CString commonDocumentPath(path);

	hr = SHGetFolderPath(NULL, CSIDL_COMMON_DOCUMENTS, NULL,
		SHGFP_TYPE_CURRENT, path);
	if (FAILED(hr))
		goto Exit;

	commonDocumentPath = path;

	//Create directory if not exists
	garudalogfileFolder = commonDocumentPath + "\\Garuda3";
	if (CreateDirectory(garudalogfileFolder, NULL) ||
		ERROR_ALREADY_EXISTS == GetLastError())
	{
		//To get the current time
		time_t tt;
		struct tm* ti;

		time(&tt);
		ti = localtime(&tt);

		//Formatiing file name
		logfilePath.Format(_T("%s\\Garuda3_J2534Log_%d_%0.2d_%0.2d_%0.2d_%0.2d_%0.2d.txt"),
			garudalogfileFolder, ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday, ti->tm_hour, ti->tm_min, ti->tm_sec);
	}
Exit:
	gpcLogPath = logfilePath;
}*/

/*std::string GetLogPath(void)
{
	std::string path = "";
	DWORD bufferSize = GetCurrentDirectory(0, NULL); // Get required buffer size
	if (bufferSize == 0) {
		return path;
	}

	std::vector<char> buffer(bufferSize);
	if (GetCurrentDirectory(bufferSize, buffer.data()) == 0) {
		return path;
	}

	path = buffer.data();

	return path;
}*/
/*void SaveBufferToFile(const unsigned char* data, size_t length, const std::string& filename)
{
	std::string path = GetLogPath();
	if (path.empty()) {
		return;
	}
	path += "\\" + filename;

	std::ofstream outFile(path, std::ios::binary);
	if (!outFile) {
		return; // could not open
	}
	outFile.write(reinterpret_cast<const char*>(data), length);
}*/
