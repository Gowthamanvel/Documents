/******************************************************************************
					Dearborn Electronics India Pvt Ltd.,
*****************************************************************************
 Project Name			: Innova Shop Software - OEM Tool - J2534 API
 File Name				: DeviceOEMTool.h
 Description			: Interface file for DeviceOEMTool class
 Date					: Jan 29, 2008
 Version				: 1.0
 Author					: Chakravarthy
 Revision				:
 Copyright (c) 2008 Dearborn Electronics India Pvt L, Inc

 File		 Date			Author						Description
 Version
_____________________________________________________________________________

 1.0		 Jan 29, 2008	Chakravarthy				Initial Version
_____________________________________________________________________________
*****************************************************************************/

#ifndef _CDEVICEOEMTOOL_H_
#define _CDEVICEOEMTOOL_H_

#include "DeviceBase.h"
#include "objbase.h"
#include <initguid.h>
#include "winuser.h"
#include "NewProtocol.h"
#include "usb.h"
#include "Winsock2.h"
#include "string"
//#include <iostream>

//#include <locale>
/*Directive for switching between Garuda and Innova DLL configuration*/
#define GARUDA_TOOL 

#define SWAP32(d) ((((uint8_t *)d)[0] << 24) | (((uint8_t *)d)[1] << 16) | (((uint8_t *)d)[2] << 8) | ((uint8_t *)d)[3])
#define PACKED __attribute__ ((__packed__))
//#define GARUDA_BULK
#define GARUDA_HID
#define GARUDA_TCP
//#define GARUDAHID
#define CANFD_BRS 0x01
extern "C"
{
#include "hidsdi.h"
#include <setupapi.h>
#include <dbt.h>
}

/*Macro definitions for INNOVA OEM TOOL USB DEVICE INTERFACE*/
#define INPUTREPORTMAX				513//chiru 65  // Defines the maximum number of bytes in input report
#define OUTPUTREPORTMAX				512 //chiru 64 // Maximum number of bytes in output report
#define MAX_PROTOCOL_NUM			255


#define EP_IN  0x82
#define EP_OUT 0x02
//Innova Kit
#ifdef GARUDA_TOOL
#define VID							0x0471
#define PID							0x5741

#define VID_2_0						0x03EB
#define PID_2_0						0x5746//0x5743
#else
#define VID							0x1720 // Vendor id of the innova device
#define PID							0x120 // Product id of the innova device
#endif
/*Set Programming Voltage constants*/
#define MIN_BAT_VOLTAGE				5000
#define MAX_BAT_VOLTAGE				20000
#define SHORT_TO_GROUND				0xFFFFFFFE
#define VOLTAGE_OFF					0xFFFFFFFF

#define CMD_SIZEOF_PROTO_CMD(x) (sizeof(x)- sizeof(x.u))

#define DOIP_PROTO_WAIT (5000)
#define IPV4_STR_ADDR_LEN  16
#define VEHICLE_ID_NUM_LEN 1
#define ENTITY_ID_LEN      1
#define GROUP_ID_LEN       1
#pragma pack(1)
typedef struct EnableComm
{
	uint32_t baudrate;
	uint32_t conn_flags;

}EnableComm_t;
typedef struct disablecom
{
	char ipaddr[IPV4_STR_ADDR_LEN];
}disablecom_t;
#pragma pack(1)
typedef struct StartFilter
{
	uint8_t filter_type;
	uint8_t Store_Mask;
	uint32_t Mask_Buffer;
	uint8_t Pattern_Length;
	uint32_t Pattern_Buffer;
}StartFilter_t;

#pragma pack(1)
typedef struct StopFilter
{
	uint8_t filter_type;
}StopFilter_t;

#pragma pack(1)
typedef struct WriteMsgs
{
	uint8_t segnum;
	uint8_t Messagelength;
	uint8_t Messagelength1;
	uint32_t TxFlags;
	uint32_t Msg_Id;
	uint8_t Data_Length;
	uint8_t Data_Bytes[0];
}WriteMsgs_t;

#pragma pack(1)
typedef struct Mode0
{
	uint8_t segnum;
	uint8_t Messagelength;
	uint8_t Messagelength1;
	uint32_t TxFlags;
	uint32_t Msg_Id;
	uint8_t Data_Bytes[0];
}CAN_Sendmsg_t;

#pragma pack(1)
typedef struct Mode1
{
	uint8_t segnum;
	uint8_t Messagelength;
	uint8_t Messagelength1;
	uint8_t Conversation_ID;
	uint32_t TxFlags;
	uint32_t Msg_Id;
	uint8_t Data_Bytes[0];
}CAN_Sendmsg_mode1;

typedef union union1
{
	struct Mode0 M0;
	struct Mode1 M1;
}u;

#pragma pack(1)
typedef struct Mode2
{
	uint8_t segnum;
	uint8_t Messagelength;
	uint8_t Messagelength1;
	uint8_t Conversation_ID;
	uint8_t STmin1;
	uint8_t STmin2;
	uint8_t Data_Bytes[0];
}CAN_sendmsg_mode2;


#pragma pack(1)
typedef struct StartPeriodicMsg
{
	uint8_t Start_Periodic;
	uint32_t Time_Interval;
	uint8_t PeriodicRefID;
	uint32_t TxFlags;
	uint8_t DataSize;
	uint32_t Msg_Id;
	uint8_t Data_Bytes[0];
}PeriodicMsg_t;

#pragma pack(1)
typedef struct StopPeriodicMsg
{
	uint8_t Stop_Periodic;
	uint32_t Reserved;
	uint8_t PeriodicRefID;
}PeriodicMsg;

#pragma pack(1)
typedef struct IOCTL
{
	uint32_t IOCTL_ID;
	uint8_t rsvd;
}IOCTL_T;

#pragma pack(1)
typedef struct GetConfig
{
	uint32_t IOCTL_ID;
	uint8_t rsvd;
	uint32_t Parameter;
}GetConfig_t;

#pragma pack(1)
typedef struct SendIOCTLData
{
	uint32_t IOCTL_ID;
	uint8_t rsvd;
	uint8_t data[0];
}SendIOCTLData_t;

#pragma pack(1)
struct SetConfig
{
	uint32_t parameter;
	uint32_t value;
};
typedef SetConfig SetConfig_t;

#pragma pack(1)
typedef struct doipserver {
	char ipaddr[IPV4_STR_ADDR_LEN]; /* Eg. "192.168.1.20" */
	uint16_t laddr;
	uint8_t vin[VEHICLE_ID_NUM_LEN];
	uint8_t eid[ENTITY_ID_LEN];
	uint8_t gid[GROUP_ID_LEN];
}doip_cli_cmd_add_doip_server_t;

#pragma pack(1)
typedef struct doipclient {
	uint16_t logical_addr;
}doip_cli_cmd_start_session_t;

#pragma pack(1)
typedef struct diagmsg {
	char ipaddr[IPV4_STR_ADDR_LEN];
	uint16_t seqNum;
	uint16_t lastpkt;
	uint16_t dst_laddr;
	uint32_t msg_len;
	uint8_t diag_data[];
}doip_cli_cmd_diag_msg_t;

#pragma pack(1)
typedef struct doipipaddr{
	char ipaddr[IPV4_STR_ADDR_LEN];
}doip_get_ip_addr;

#pragma pack(1)
typedef struct doipclientdetails {
	char ipaddr[IPV4_STR_ADDR_LEN];
	char subnet[IPV4_STR_ADDR_LEN];
	char Gwaddr[IPV4_STR_ADDR_LEN];
	uint16_t laddr;
}doipclientdetails_t;


#pragma pack(1)
struct BufferCommand
{
	uint32_t proto_id;
	uint8_t command;
	union {
		uint8_t Device_STARTSESSION;
		uint8_t Device_STOPSESSION;
		EnableComm_t EnableComm;
		disablecom_t disablecom;
		StartFilter_t StartFilter;
		StopFilter_t StopFilter;
		WriteMsgs_t WriteMsgs;
		CAN_Sendmsg_t Mode0;
		CAN_Sendmsg_mode1 Mode1;
		CAN_sendmsg_mode2 Mode2;
		PeriodicMsg_t StartPeriodicMsg;
		PeriodicMsg StopPeriodicMsg;
		IOCTL_T IOCTL;
		GetConfig_t GetConfig;
		SendIOCTLData_t SendIOCTLData;
		doip_cli_cmd_add_doip_server_t doipserver;
		doip_cli_cmd_start_session_t doipclient;
		doip_cli_cmd_diag_msg_t diagmsg;
		doip_get_ip_addr doipipaddr;
		doipclientdetails_t doipclientdetails;
		uint8_t Enable_RNDIS;
	}u;
};
typedef BufferCommand BufferCommand_t;


#pragma pack(1)
typedef struct StartSession
{
	uint8_t Device_STARTSESSION;
	uint8_t Status;
}SessionStart_t;

#pragma pack(1)
typedef struct Enablerndis
{
	uint8_t STARTSESSION;
	uint8_t Status;
}Enablerndis_t;

#pragma pack(1)
typedef struct StopSession
{
	uint8_t Device_STOPSESSION;
	uint8_t Status;
}SessionStop_t;

#pragma pack(1)
typedef struct EnableCom
{
	uint8_t status;
}EnableCom_t;

#pragma pack(1)
typedef struct DisableCom
{
	uint8_t status;
}DisableCom_t;

#pragma pack(1)
typedef struct STARTfilter
{
	uint8_t status;
	uint8_t Ref_Id;
}STARTfilter_t;

#pragma pack(1)
typedef struct STOPfilter
{
	uint8_t status;
}STOPfilter_t;


#pragma pack(1)
typedef struct Writemessages
{
	uint8_t status;
	uint8_t ERR_status;
}Writemessages_t;

#pragma pack(1)
typedef struct ReadMsgs
{
	uint8_t segnum;
	uint8_t mode;
	uint8_t messagelength;
	uint8_t messagelength1;
	uint32_t RxFlags;
	uint32_t TimeStamp;
	uint8_t Data_Bytes[0];
}ReadMsgs_t;

#pragma pack(1)
typedef struct ReadMsgsMode1
{
	uint8_t segnum;
	uint8_t mode;
	uint8_t messagelength;
	//	uint8_t messagelength1;
	uint16_t RxFlags;
	uint32_t TimeStamp;
	uint8_t Data_Bytes[0];
}ReadMsgsMode1_t;


#pragma pack(1)
typedef struct extendAddr
{
	uint32_t canid; //15
	uint8_t rsvd2;
	uint8_t PCItype; //20
	uint8_t usFF_DL;
	uint8_t Data_Bytes[0];
	//uint32_t rsvd;
};

#pragma pack(1)
typedef struct stdAddr
{
	uint32_t canid; 
	uint8_t PCItype; 
	uint8_t usFF_DL;
	uint8_t Data_Bytes[0];
	//uint32_t rsvd;
};

#pragma pack(1)
typedef struct ReadMsgsTP_Mode0
{
	uint8_t segnum;
	uint8_t mode; 
	uint16_t messagelength; 
	uint32_t RxFlags; 
	uint32_t TimeStamp; 
	union {
		uint8_t Data_Bytes[0]; 
		struct extendAddr extaddr;
		struct stdAddr stdaddr;
	} u;
}ReadMsgsTP_t;

typedef struct ReadMsgsTP_Mode1
{
	uint8_t segnum;
	uint8_t mode; 
	uint8_t messagelength; 
	uint16_t RxFlags; 
	uint32_t TimeStamp;
	union {
		uint8_t Data_Bytes[0];
		struct extendAddr extaddr;
		struct stdAddr stdaddr;
	}u;
}ReadMsgsTPMode1_t;

#pragma pack(1)
typedef struct IOctl
{
	uint8_t Response;
	uint8_t rsvd1;
	uint8_t status;
	uint8_t rsvd;
	union {
		uint32_t voltage;
		char databytes[0];
	}u;
}IOctl_t;
/*#pragma pack(1)
typedef struct doipioctl_t
{
	uint8_t databytes[0];
};*/
#pragma pack(1)
typedef struct Getconfig
{
	uint32_t rsvd;
	uint8_t status;
	uint8_t rsvd1;
	uint32_t parameter;
	uint8_t datarate;
	uint8_t value;
	uint8_t value1; 
}Getconfig_t;

#pragma pack(1)
typedef struct sendICOTL
{
	uint8_t rsvd;
	uint8_t status;
}sendIOCTL_t;

#pragma pack(1)
typedef struct startperiodic
{
	uint8_t status;
	uint8_t RefID;
}startperiodic_t;

#pragma pack(1)
typedef struct updateperiodic
{
	uint8_t status;
	uint8_t RefID;
}updateperiodic_t;

#pragma pack(1)
typedef struct stopperiodic
{
	uint8_t status;
}stopperiodic_t;

#pragma pack(1)
typedef struct GetRevision
{
	uint8_t status;
	uint8_t LM;
	uint8_t SL;
	uint8_t SR;
	char RM;
}GetRevision_t;
typedef struct GetSerailNo
{
	uint8_t status;
}GetSerialNo_t;
#pragma pack(1)
typedef struct ADD_SERVER
{
	uint8_t status;
}DOIP_ADD_SERVER_t;

#pragma pack(1)
typedef struct ADD_CLIENT
{
	uint8_t status;
}DOIP_ADD_CLIENT_t;

#pragma pack(1)
typedef struct DAIG_MSG
{
	uint8_t status;
}DOIP_DIAG_MSG_t;

#pragma pack(1)
typedef struct DOIP_rcv_msg
{
	uint8_t status;
	uint16_t SeqNum;
	uint16_t LastPkt;
	uint32_t Curlen;
//	uint16_t SrcAddr;
//	uint16_t DstAddr;
	uint8_t data[0];
}DOIP_RCV_MSG_t;

#pragma pack(1)
typedef struct DOIP_CLIENT_RESPONSE
{
	uint8_t status;
}DOIP_CLIENT_RESPONSE_t;


#pragma pack(1)
struct InputBuffer
{
	uint8_t Reserved;
	uint32_t proto_id;
	uint8_t command; 
	union {
		SessionStart_t StartSession;
		SessionStop_t StopSession;
		EnableCom_t   EnableCom;
		DisableCom_t  DisableCom;
		STARTfilter_t STARTfilter;
		STOPfilter_t STOPfilter;
		Writemessages_t Writemessages;
		ReadMsgs_t ReadMsgs;
		ReadMsgsMode1_t ReadMsgsMode1;
		ReadMsgsTP_t ReadMsgsTP; /* Mode 0 */
		ReadMsgsTPMode1_t ReadMsgTP1; /* Mode 1 */
		IOctl_t IOctl;
		Getconfig_t Getconfig;
		sendIOCTL_t sendIOCTL;
		startperiodic_t startperiodic;
		updateperiodic_t updateperiodic;
		stopperiodic_t stopperiodic;
		GetRevision_t GetRevision;
		GetSerialNo_t GetSerialNo;
		DOIP_ADD_SERVER_t ADD_SERVER;
		DOIP_ADD_CLIENT_t ADD_CLIENT;
		DOIP_DIAG_MSG_t  DAIG_MSG;
		DOIP_RCV_MSG_t DOIP_rcv_msg;
		DOIP_CLIENT_RESPONSE_t DOIP_CLIENT_RESPONSE;
		Enablerndis_t Enablerndis;
	} u;
};
typedef InputBuffer InputBuffer_t;

typedef struct
{
	unsigned char ucFuncID;
	bool bValid;
}
COEMTOOL_J1850PWM_LOOKUP_TABLE;
/*Jayasheela-added structure to hold consecutive frame,data lenght,dataindex */
typedef struct
{
	PASSTHRU_MSG stSaveMultSegmPassRxThruMsg;
	unsigned short usLeftDL;
	unsigned short usDataIndex;

	unsigned long ulLastRxTimeStamp;

	unsigned char uchSendPackets_MaxCount;
	unsigned char uchNoOfPackets;
	unsigned long ulDataBytes;
	unsigned long ulPGN;
	unsigned char uchDest;
	unsigned char uchSrc;

	bool			  bBAM;
	BYTE			  nBAMRTSPkts;
	DWORD			  nBAMRTSTotBytes;
	BYTE			  nBAMRTSSource;
	BYTE			  nBAMRTSNextPkt;
	BYTE			  nBAMRTSBytesReceived;
	DWORD			  nBAMRTSPGN;
	BYTE			  nBAMRTSHowPriority;

	BYTE			  nCTSRTSPkts;
	DWORD			  nCTSRTSTotBytes;
	BYTE			  nCTSRTSSource;
	BYTE			  nCTSRTSNextPkt;
	BYTE			  nCTSRTSBytesReceived;
	DWORD			  nCTSRTSPGN;
	BYTE			  nCTSRTSHowPriority;
	BYTE			  nCTSRTSMaxPacketsForCTS;
	BYTE			  nCTSRTSPacketCntForCTS;

}SAVE_MULTIPLE_SEGMENT_RXDATA;

class CDeviceOEMTool : public CDeviceBase
{
public:
	CDeviceOEMTool(CDebugLog* pclsDebugLog = NULL);
	~CDeviceOEMTool();

	//Operations
	virtual J2534ERROR vOpenDevice();
	virtual J2534ERROR vCloseDevice();
	virtual J2534ERROR vConnectProtocol(
		J2534_PROTOCOL	enProtocolID,
		unsigned long   ulFlags,
		unsigned long	ulBaudRate,
		DEVICEBASE_CALLBACK_RX_FUNC pfnCallback,
		DEVICEBASE_CALLBACK_FC_FUNC pfirstframefnCallback,
		DEVICEBASE_CALLBACK_ISO15765_SETRXSTATUS_FUNC psetRxstatusfnCallback,
		LPVOID			pVoid,
		unsigned long* pulChannelID);

	virtual J2534ERROR vDisconnectProtocol(unsigned long ulChannelID);

	virtual J2534ERROR vGetRevision(char* pchFirmwareVersion,
		char* pchDllVersion,
		char* pchApiVersion);
	virtual J2534ERROR vGetSerialNo(char* pSerialNo);

	virtual J2534ERROR vWriteMsgs(unsigned long	ulChannelID,
		PASSTHRU_MSG* pstPassThruMsg,
		unsigned long* pulNumMsgs);


	virtual J2534ERROR vStartPeriodic(unsigned long	ulChannelID,
		PASSTHRU_MSG* pstMsg,
		unsigned long	ulTimeInterval,
		unsigned long* pulPeriodicRefID);

	virtual J2534ERROR vUpdatePeriodic(unsigned long	ulChannelID,
		PASSTHRU_MSG* pstMsg,
		unsigned long	ulTimeInterval,
		unsigned long	pulPeriodicRefID);


	virtual J2534ERROR vStopPeriodic(unsigned long	ulChannelID,
		unsigned long	ulPeriodicRefID);

	virtual J2534ERROR vStartFilter(unsigned long	ulChannelID,
		J2534_FILTER	enFilterType,
		PASSTHRU_MSG* pstMask,
		PASSTHRU_MSG* pstPattern,
		PASSTHRU_MSG* pstFlowControl,
		unsigned long* pulFilterRefID);

	virtual J2534ERROR vStopFilter(unsigned long	ulChannelID,
		unsigned long	ulFilterRefID);

	virtual J2534ERROR vIoctl(unsigned long	ulChannelID,
		J2534IOCTLID enumIoctlID,
		void* pInput,
		void* pOutput);

	virtual J2534ERROR vProgrammingVoltage(unsigned long ulDeviceID,
		unsigned long ulPin,
		unsigned long ulVoltage);

	virtual BOOL  vIsDeviceConnected(BOOL bFlag = true);
	virtual J2534ERROR  vGetLastError(char* pErrorDescription);

	virtual J2534ERROR  vDOIPServer(
								    char* sIPAddr,
									unsigned short laddr,
									unsigned int* pVIN,
									unsigned int* pEID,
									unsigned int* pGID);
	virtual J2534ERROR vDOIPClient(unsigned short laddr);
	virtual J2534ERROR vDOIPIPAddr(char* sIPAddr);
	virtual J2534ERROR vDOIPSENDMSG(
									unsigned short dst_laddr,
									unsigned char* pDiagMsg,
									unsigned long msglen);
	virtual J2534ERROR vDOIPClientDetails(char* Ipaddr,
	                                      char* netmask,
		                                  char* gwaddr,
		                                  unsigned short laddr);
	virtual J2534ERROR vDOIPSetTesterLogicalID(unsigned short Taddr);
	virtual J2534ERROR vDOIPSetECULogicalID(unsigned short Eaddr);

	virtual J2534ERROR vEnableRNDIS();
	virtual J2534ERROR vDisableRNDIS();

#ifdef GARUDA_TOOL
	virtual J2534ERROR vLoggingStatus(unsigned long bLogFlag, SYSTEMTIME* Time);
	virtual	J2534ERROR vSessionCommand(unsigned long bsessionFlag);
#endif

public:

	SOCKET m_serverSockId;
	/*Innova OEM TOOL USB Device Interface Variable Declaration*/
	BOOL HidAttached;					// Used by member functions to make sure device enumerated
	HANDLE HidDevHandle;				// Handle for HID Device
	HANDLE ReadHandle;
	HANDLE WriteHandle;
	GUID HidGuid;						// holds GUID of device
	PSP_DEVICE_INTERFACE_DETAIL_DATA detailData;
	OVERLAPPED HIDOverlapped;
	DWORD dwError;
	ULONG Length;
	LPOVERLAPPED lpOverLap;
	DWORD NumberOfBytesRead;
	ULONG Required;
	HIDP_CAPS Capabilities;				// holds enumeration info
	HANDLE								hEventObject;
	UCHAR								OutputReport[OUTPUTREPORTMAX + 1];
//	UCHAR								OutputReport[OUTPUTREPORTMAX];
	UCHAR								InputReport[INPUTREPORTMAX];
	unsigned short						usFirmwareVersion;
	J2534_PROTOCOL						m_enChannelList[MAX_PROTOCOL_NUM];
	HANDLE								hCallBckThread;
	BOOL								m_bThreadQuit;
	int									m_nChannelID;
	BOOL								m_bLoopBack;
	J2534ERROR							m_ulLastErrorCode;

	/* Acknowledge message handle */
	HANDLE                              m_CmdAck;
	/*Fast and Fivebaud Int Handles*/
	HANDLE                              m_FastInit;
	HANDLE                              m_5BaudInit;
	BOOL                                m_bFastInitIssued;
	PASSTHRU_MSG                        m_ptFastInitResponse;
	BOOL                                m_bWriteDone;
	HANDLE								m_bSepTimeEvent;
	/*J1850 Function Look up table*/
	COEMTOOL_J1850PWM_LOOKUP_TABLE	m_FunctionTable[J1850PWM_LIMIT];

	/* Ravi : Integrated the ISO 15765 Variables */
	/*ISO15765 Related Variables*/
	unsigned int      m_nTxID;
	CPtrArray         m_TxList;
	CPtrArray         m_RxList;
	unsigned char     m_nFramePadValue;
	unsigned int	  m_nBlockSizeTx;
	WORD			  m_nSTminTx;
	BYTE			  m_ByteISO15765_BS;
	BYTE			  m_ByteISO15765_STMIN;
	unsigned long      m_FD_ISO15765_DATA_LENGTH;
	/*Jayasheela-added to hold no of wait flow control frames allowed */
	BYTE			  m_ByteISO15765_WFT_MAX;
	HANDLE			  m_FlowControlEvent;
	BOOL			  m_bFlowControlIssued;
	unsigned long	  m_ulJ1939_BRDCST_MIN_DELAY;

	/*Innova OEM TOOL USB Device Interface Functions Declaration*/
	BOOL bOpenHidDevice();	// Open the HID Device based on VID and PID
	//Reads the newest report from the device
	void  ReadInputReport();
	//Get Output Report size
	int GetOutputReportSize(void);
	int GetInputReportSize(void);
	int GetFeatureReportByteLength(void);
	//Writes the newest report from the device based on report number
	BOOL WriteOutputReport(unsigned char* ucReport, DWORD dwLength);
    BOOL validate_port(unsigned short );
    BOOL validate_ip(char*);
	BOOL validate_ip_range(char*);

	void CloseHandles();
	BOOL GetDeviceDetected() { return (HidAttached); }
	void DisplayInputReport();
	void PrepareForOverlappedTransfer();
	// gets the device capabilites and puts it in Capabilities
	void GetDeviceCapabilities(void);
	void LogToDebugFile(CString szFunct, int nDebugType,
		CString szLogInfo);
	BOOL bOpenTCPInterfaceDevice(); //Open the TCP enabled Garuda device based on PORT number
	usb_dev_handle* dev;
public:
	/*Device Initialize and communication Functions*/
	J2534ERROR InitUSBDevice();
	J2534ERROR CloseUSBDevice();
	int FindRNDISDevices(const std::string& vendorID, const std::string& productID);
	BOOL IsRNDISDevice(HDEVINFO hDevInfo, SP_DEVINFO_DATA& devInfoData, const std::string& vendorID, const std::string& productID);
	BOOL ReadDataFromPort(SOCKET sockId, unsigned char* puchBuffer, int nBufferSize, int& nBytesRead);
	/*Initialize Communication on Protocl*/
	J2534ERROR EnableCommuncation(unsigned long, unsigned long, J2534_PROTOCOL);

	/*Disable Communication*/
	J2534ERROR DisableCommuncation(unsigned long);

	/*Send Message Function*/
	J2534ERROR SendECUMessage(PASSTHRU_MSG*, unsigned char);
	J2534ERROR SendDOIPMessage(PASSTHRU_MSG*, unsigned char);
	J2534ERROR SendMultipleCANECUMessage(PASSTHRU_MSG*, unsigned char, unsigned long);

	/*Send message for 9141 / J1850VPWM / SCI  / CCD */
	J2534ERROR SendMultipleFrameECUMessages(PASSTHRU_MSG*, unsigned long ulChannelID);
	J2534ERROR SendSingleFrameECUMessage(unsigned char*, PASSTHRU_MSG*, int, unsigned long ulChannelID);

	/*Send ISO15765 message over the network*/
	J2534ERROR DecomposeISO15765Message(unsigned char*, short, unsigned long);
	J2534ERROR DecomposeFDISO15765Message(unsigned char*, short, unsigned long);
	J2534ERROR SendToDevice(unsigned int, unsigned char*, int, unsigned long, unsigned long);
	J2534ERROR SendISO15765Messages(unsigned long);
	void EmptyTxList(CPtrArray& ptrList);

	/*Send J1939 Message over the network*/
	J2534ERROR DecomposeJ1939Message(unsigned char*, short, unsigned long);
	J2534ERROR SendJ1939Messages(unsigned char ucProtocolid);
	J2534ERROR SendJ1939MsgToDevice(const int num_frames, int block_size, int* frame_index, int seperation_time, bool bBAM, unsigned char nStartPacketNo);
	unsigned long GetJ1939MsgIndex(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData, unsigned long ulProtocolId,
		unsigned long uchSrc, bool bBAMMsg = true);
	J2534ERROR SendJ1939SingleMessage(unsigned long ulMsgId,
		unsigned char* pData,
		unsigned char uchDataLength,
		unsigned long ulTxFlags,
		unsigned long ulProtocolId);


	/*IOCTL COMMANDS*/
	J2534ERROR GetConfig(SCONFIG* sIptPtrConfig, unsigned long ulChannelID);
	J2534ERROR SetConfig(SCONFIG* sIptPtrConfig, unsigned long ulChannelID);
	J2534ERROR FastInit(PASSTHRU_MSG*, PASSTHRU_MSG*, unsigned long ulChannelID);
	J2534ERROR FiveBaudInit(SBYTE_ARRAY*, SBYTE_ARRAY*, unsigned long ulChannelID);
	J2534ERROR SendIOCTLData(J2534IOCTLID, unsigned char*, int, unsigned long ulChannelID);
	J2534ERROR ProtectJ1939Address(SBYTE_ARRAY*, SBYTE_ARRAY*, unsigned long ulChannelID);
	unsigned long GetIndexToStoreMessage(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData);
	unsigned long GetMsgIndex(SAVE_MULTIPLE_SEGMENT_RXDATA* stSaveRxMultipleSegmData,
		PASSTHRU_MSG stPassRxThruMsg,
		unsigned char ucCANIDSize);
	J2534ERROR SendISO15765MsgToDevice(const int, int, int*, int);
	J2534ERROR SendFDISO15765MsgToDevice(const int, int, int*, int);
	//Added Functions for support J1939 Frame Id Parsing and Contructing
	bool GetPGNParametersFromHeader(ULONG ulReqHdr, UCHAR& uchPriority, ULONG& ulPGN, UCHAR& uchPDUSpecific,
		UCHAR& uchPDUFormat, UCHAR& uchSrcAddr, UCHAR& uchDestAddr);
	bool GetPGNParametersFromHeader(ULONG ulReqHdr, UCHAR& uchPriority, ULONG& ulPGN, UCHAR& uchSrcAddr, UCHAR& uchDestAddr);
	unsigned long ComputeJ1939Header(UCHAR uchPriority, ULONG ulPGN, UCHAR uchSrcAddr, UCHAR uchDestAddr);

	J2534ERROR DOIP_configure_server(char *,unsigned short , unsigned int *,unsigned int *,unsigned int *);
	J2534ERROR DOIP_configure_client(unsigned short);
	J2534ERROR DOIP_GET_IPAddr(char*);
	J2534ERROR DOIPClientDetailsSEND(char*, char*, char*, unsigned short);
	void WriteHIDReportToLog(const unsigned char* ucReport, DWORD dwLength);
};

#endif // !defined(AFX_DEVICEOEMTOOL_H__4F59517B_F1EC_4CEB_84FE_FBBB5D0900A1__INCLUDED_)
