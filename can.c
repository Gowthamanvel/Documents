
/**
 *	@file can.c
 *
 *	Copyright (c) 2023, Capgemini - Intelligent Devices
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "can.h"
#include "can_if.h"
#include "g3d.h"
#include "j2534_filter.h"
#include "data_logger.h"
#include "can_nl_if.h"
#include "usbhid.h"

static Dynamic_QStruct_t canBufInfo[CAN_CH_MAX] = { 0 };

#define MSGQ_FILE_PATH "/etc/init.d/run-g3d.sh"
//#define MSGQ_FILE_PATH "/usr/bin/run-g3d.sh"

struct mode2_tx_ctx {
	//pid_t g3dpid;
	pid_t txTask_pid;
	int txTask_msgid;
};

typedef struct mode2_tx_ctx mode2_tx_ctx_t;

mode2_tx_ctx_t m2ctx;

static inline void PRINT_TIMEDIFF(void)
{
	static struct timeval t1, t2, *pstart, *pend;
	static int val = 1;

	if (val) {
		gettimeofday(&t1, NULL);
		val = 0;
		pstart = &t2;
		pend = &t1;
	} else {
		gettimeofday(&t2, NULL);
		val = 1;
		pstart = &t1;
		pend = &t2;
	}

	printf("PKT: %02ld sec, %02ld us (%02ld ms)\n",
		(pend->tv_sec - pstart->tv_sec),
		(pend->tv_usec - pstart->tv_usec),
		(pend->tv_usec - pstart->tv_usec) / 1000);
}

int mode2_tx_create_msgq(void)
{
	key_t msgkey;
	int msgid;

	m2ctx.txTask_msgid = 0xFFFF;
	msgkey = ftok(MSGQ_FILE_PATH, 65);
	if (msgkey < 0) {
		DBG("ftok() failed");
		return -1;
	}

	msgid = msgget(msgkey, 0666 | IPC_CREAT);
	if (msgid < 0) {
		DBG("MsgQ create failed");
		/* Child process is already created */
		return -1;
	}

	m2ctx.txTask_msgid = msgid;

	DBG("mode2_tx_create_msgq: MsgQID 0x%x", msgid);

	return 0;
}

int mode2_tx_delete_msgq(void)
{
	int ret;

	ret = msgctl(m2ctx.txTask_msgid, IPC_RMID, NULL);
	m2ctx.txTask_msgid = 0xFFFF;
	if (ret == 0) {
		DBG("MsgQ is deleted");
		return 0;
	}

	return -1;
}

#define MILLISECONDS			(1000)
#define MODE2_TX_DEFAULT_TIMEOUT 	(100 * MILLISECONDS)
#define MODE2_TX_MSGRCV_NO_DATA_CNT	(100)

/* mode2 Tx process
 *
 * This process reads the messages from the message queue
 * and transmits the same to can
 *
 */

int mode2_tx_process(void)
{
	fd_set readfds;
	struct timeval timeout;
	mode2_msg_buf_t mbuf;
	int ret, msgrcv_no_data, msgflag;
	uint32_t stmin = MODE2_TX_DEFAULT_TIMEOUT;

	ret = mode2_tx_create_msgq();
	if (ret < 0) {
		DBG("mode2tx: msgq failed");
		return -1;
	}

	msgrcv_no_data = 0;
	msgflag = 0;
	printf("mode2_tx_process: pid %d\n", getpid());
	while (1) {
		if (msgrcv_no_data >= MODE2_TX_MSGRCV_NO_DATA_CNT) {
			stmin = MODE2_TX_DEFAULT_TIMEOUT;
			msgflag = 0;	/* msgrcv() is a blocking call now */
		}
		FD_ZERO(&readfds);
		FD_SET(1, &readfds);
		timeout.tv_sec = 0;
		timeout.tv_usec = (int)stmin;
		ret = select(1, &readfds, NULL, NULL, &timeout);
		if (ret == 0) {
			//DBG("Waiting in msgrcv()..");
			memset(&mbuf, 0, sizeof(mbuf));
			ret = msgrcv(m2ctx.txTask_msgid, &mbuf,
					sizeof(mbuf.m2_data) + sizeof(long), 1, msgflag);
			if ((ret < 0) || (ret < sizeof(mbuf.m2_data))) {
				if (msgrcv_no_data <=
						MODE2_TX_MSGRCV_NO_DATA_CNT) {
					msgrcv_no_data++;
				}
				continue;
			}

			if(stmin == MODE2_TX_DEFAULT_TIMEOUT)
			{
				//To generate the delay between flow control and first conseqeutive frame
				stmin = (mbuf.m2_data.stmin) * MILLISECONDS;
				ret = select(1, &readfds, NULL, NULL, &timeout);
			}
			else
			{
				stmin = (mbuf.m2_data.stmin) * MILLISECONDS;
			}
			// PRINT_TIMEDIFF();
			if(mbuf.m2_data.chan_num < 2) {
				/* for CAN frame */
				hexdump("msgrcv", &(mbuf.m2_data.frame.CAN),
						sizeof(mbuf.m2_data.frame.CAN), 0);
				(void)CAN_Mid_Transmit(mbuf.m2_data.chan_num,
							&(mbuf.m2_data.frame.CAN));
			} else if(mbuf.m2_data.chan_num < 4) {
				/* for CAN-FD frame */
				hexdump("msgrcv", &(mbuf.m2_data.frame.CANFD),
						sizeof(mbuf.m2_data.frame.CANFD), 0);
				(void)CAN_FD_Mid_Transmit(mbuf.m2_data.chan_num,
							&(mbuf.m2_data.frame.CANFD));
			}
			msgrcv_no_data = 0;
			msgflag = IPC_NOWAIT;
		} else if (ret < 0) {
			/** @TODO - do something to handle the error */
			/* error */
		}
	}
	/* TODO:
	 * Handle msgq close, process exit
	 */
	return 0;
}

int mode2_create_process(void)
{
	pid_t pid;
	int ret;

	ret = mode2_tx_create_msgq();
	if (ret < 0) {
		DBG("Failed to create MsgQ");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		DBG("fork() failed");
		return -1;
	}

	switch (pid) {
		case 0:
			mode2_tx_process();
			break;
		default:
			// m2ctx.g3dpid = getpid();
			m2ctx.txTask_pid = pid;
			// DBG("mode2_tx_process pid %d\n", m2ctx.txTask_pid);
	}

	return 0;
}

/* TODO: */
int mode2_delete_process(void)
{
	mode2_tx_delete_msgq();

	/* TODO: Delete the process */
	return 0;
}

#define CAN_FRAME_STRUCT(cur)	(sizeof(struct can_frame) - sizeof(cur->data) +\
					cur->can_dlc)
/* 
 * Add CAN data to the list
 *
 * On success, return MID_PASS 
 * On Failure, return MID_FAIL
 */
int mode2_queue_add_to_queue(int chan, char *cur, uint8_t stmin)
{
	static size_t count = 1;
	mode2_msg_buf_t mbuf;
	int ret;

	if (m2ctx.txTask_msgid == 0xFFFF) {
		DBG("MsgQ not created yet !!!!");
		return MID_FAIL;
	}

	mbuf.mtype = 1;
	if(chan < 2){
		/* This is a CAN frame */
		memcpy(&(mbuf.m2_data.frame.CAN), cur, sizeof(struct can_frame));
	} else {
		/* This is a CAN-FD frame */
		memcpy(&(mbuf.m2_data.frame.CANFD), cur, sizeof(struct canfd_frame));
	}
	mbuf.m2_data.chan_num = chan;
	mbuf.m2_data.stmin = stmin;
	//memcpy(&(mbuf.m2_data.frame), cur, CAN_FRAME_STRUCT(cur));

	DBG("msgsnd: count %lu, size %lu", count, sizeof(struct can_frame));
	count++;

	ret = msgsnd(m2ctx.txTask_msgid, &mbuf, sizeof(mbuf.m2_data) + sizeof(long), 0);
	if (ret < 0) {
		DBG("msgsnd failed");
		return MID_FAIL;
	}

	return MID_PASS;
}

int Is_DataLog_Active(void)
{
	return 0;
}

uint32_t swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);

	return (val << 16) | (val >> 16);
}

uint8_t CAN_Mid_Init(char *can, uint32_t baudrate)
{
	uint8_t ret;
	uint32_t chan;

	DBG("%s, set baud rate to %d\n", can, baudrate);

	if (strcmp(can, "can0") == 0) {
		chan = 0;
	} else if (strcmp(can, "can1") == 0) {
		chan = 1;
	} else {
		DBG("ERR_INVALID_CHANNEL_ID\n");
		return ERR_INVALID_CHANNEL_ID;
	}

	ret = can_if_reinit_chan(chan, baudrate);

	return (ret == 0) ? STATUS_NOERROR : ERR_FAILED;
}

void CAN_Mid_DeInit(char *p_channel)
{
	/* TODO: Nothing to be done */
}

uint8_t CAN_Mid_Disable(uint8_t p_channel)
{
	return STATUS_NOERROR;
}

uint8_t CAN_Mid_Enable(uint8_t p_channel, uint8_t p_connection_flag_U8)
{
	return STATUS_NOERROR;
}

void CAN_Mid_Get_Config(char *p_channel, CAN_Config_t config, uint32_t *value)
{
	switch (config) {
	case CAN_BAUDRATE:
		DBG("CAN_BAUDRATE\n");
		break;
	case CAN_SJW:
		DBG("CAN_SJW");
		break;
	case CAN_SAMPLING_POINT:
		DBG("CAN_SAMPLING_POINT");
		break;
	}
}

Mid_API_Status_t CAN_Mid_Transmit(CAN_CH_TypeDef channel,
					struct can_frame *frame)
{
	int bytes;
	Mid_API_Status_t fl_status = MID_PASS;

	if (frame == NULL) {
		return fl_status;
	}
#if 0
	if ((frame->can_id >> 31) == 1) {
		frame->can_id &= CAN_EFF_MASK;
		frame->can_id |= CAN_EFF_FLAG;
	}
#endif

	bytes = can_if_write(channel, (void *)frame, sizeof(struct can_frame));

	if (bytes < 0) {
		fl_status = MID_FAIL;
		DBG("can_write() failed\n");
	}

	return fl_status;
}

Mid_API_Status_t CAN_FD_Mid_Transmit(CAN_CH_TypeDef channel,
				     struct canfd_frame *frame)
{
	int bytes;
	Mid_API_Status_t fl_status = MID_PASS;

	if (frame == NULL) {
		return fl_status;
	}
#if 1
	if ((frame->can_id >> 31) == 1) {
		frame->can_id &= CAN_EFF_MASK;
		frame->can_id |= CAN_EFF_FLAG;
	}
#endif
	frame->flags = 0x00;
	frame->flags |= CANFD_FDF;
	frame->flags |= CANFD_BRS;
	frame->flags |= CANFD_ESI;
	channel -= CANFD_CH1; //Changing CAN_FD channel to can channel. 

	bytes = can_if_fd_write(channel, (void *)frame,
						sizeof(struct canfd_frame));

	if (bytes < 0) {
		fl_status = MID_FAIL;
		DBG("CAN_FD_Mid_Transmit failed\n");
	}

	return fl_status;
}

int CAN_ClearQ(int QUEUE)
{
	int fl_Status = 1;

	//int u8Status;

	switch (QUEUE) {
	case CAN1_TX_QUEUE:
		// u8Status = xQueueReset(xCAN1_TX_Queue);
		break;

	case CAN1_RX_QUEUE:
		// u8Status = xQueueReset(xCAN1_RX_Queue);
		break;

	case CAN2_TX_QUEUE:
		// u8Status = xQueueReset(xCAN2_TX_Queue);
		break;

	case CAN2_RX_QUEUE:
		// u8Status = xQueueReset(xCAN2_RX_Queue);
		break;

	default:
		break;
	}
#if 0
	if (pdFAIL == u8Status) {
		fl_Status = 0;
		//printf("\r\nRTOS DEBUG : Failed to Clear CAN Queue\r\n");
	}
#endif

	return fl_Status;
}

int getCAN1TXStatus(void)
{
	return 0;
}

uint32_t can_rx_handler(int c, uint8_t * buf, int length)
{
	int var, chan, len;
	uint32_t protoid, canid, msglen, rxFlags = 0, timestamp = 0;

	static int message_index_counter = 0;
	 static int total_length = 0;
	//uint64_t CANDataLoggingExtendedTime;
	static can_msg_resp_hdr_t *pRxpkt = NULL;
	can_msg_resp_data_log_hdr_t *pRxlogpkt = NULL;
	uint8_t *data_ptr = NULL;

	if (c >= CAN_CH_MAX) {
		DBG("Invalid CAN channel\n");
		return -1;
	}
	len = 0;
#if 0
	chan = (get_CAN_or_ISO15756_or_J1939() == J1939_PROTOCOL_ID) ?
	    GARUDA_J1939_CH1 : GARUDA_CAN_CH1;
#else
	pRxpkt = (can_msg_resp_hdr_t *) (canBufInfo[c].address);

DBG("Channel=%d\tCAN_ID=%x",c,get_CAN_FDCH1_or_ISO15765_FDCH1());
	if((c == 0) && ((get_CAN_or_ISO15756_or_J1939() == CAN_PROTOCOL_ID) || (get_CAN_or_ISO15756_or_J1939() == ISO15765_PROTO_ID) || (get_CAN_FD_or_ISO15756_FD() == CAN_FD_PROTOCOL_ID))) {
		DBG("Inside CAN_CH0");
		chan = GARUDA_CAN_CH1;
	} else if((c == 1) && ((get_CANCH1_or_ISO15756CH1_or_J1939CH1() == CAN_CH1_PROTO_ID) || (get_CANCH1_or_ISO15756CH1_or_J1939CH1() == ISO15765_CH1_PROTO_ID) || (get_CAN_FDCH1_or_ISO15765_FDCH1() == CAN_FD_CH1_PROTO_ID))) {
		chan = GARUDA_CAN_CH2;
		DBG("Inside CAN_CH1");
	} else {
		DBG("Inside error channel");
	}
#endif
#if 0
	struct can_frame *frame = (struct can_frame *)buf;

	canid = swap_uint32(frame->can_id);
	msglen = frame->can_dlc + 4;
	DBG("In handler canid: 0x%x\n", canid);
	var = J2534_checkFilter((uint8_t *)&canid, &(frame->data[0]),
					msglen, chan);
#else
	DBG("Buffer Length = %d\n",length);

	if (length == sizeof(struct can_frame)) {
		/* handle CAN-STD frame */
		struct can_frame *frame = (struct can_frame *)buf;

		DBG("can_id=0x%x\tcan_dlc=0x%x\tcan_data=0x%2x 0x%2x ...",
				frame->can_id, frame->can_dlc,
				frame->data[0],frame->data[1]);

		if ((frame->can_id >> 31) == 1) {
			frame->can_id &= CAN_EFF_MASK;
			rxFlags = 0x0000100;
		}

		canid = swap_uint32(frame->can_id);

		msglen = frame->can_dlc + 4;
		data_ptr= &(frame->data[0]);
		DBG("Swapped canid = 0x%x", canid);

		var = J2534_checkFilter((uint8_t *)&canid, &(frame->data[0]),
						msglen, chan);
		if(c == 0) {
			pRxpkt->proto = get_CAN_or_ISO15756_or_J1939();
		} else if(c == 1) {
			pRxpkt->proto = get_CANCH1_or_ISO15756CH1_or_J1939CH1();
		}
		protoid = pRxpkt->proto;
	} else if (length == sizeof(struct canfd_frame)) {
		/* handle CAN-FD frame */
		struct canfd_frame *frame = (struct canfd_frame *)buf;

		DBG("can_id=0x%x\tcan_dlc=0x%x\tcan_data=0x%2x 0x%2x...",
				frame->can_id, frame->len,
				frame->data[0],frame->data[1]);

		if (frame->flags & CANFD_BRS) {
			DBG("Bit rate switching happened.");
			DBG("(frame->flags = 0x%x & CANFD_BRS=0x%x) = 0x%x",
					frame->flags, CANFD_BRS,
					frame->flags & CANFD_BRS);
		} else {
			DBG("No bitrate switching happened.");
		}

		if ((frame->can_id >> 31) == 1) {
			frame->can_id &= CAN_EFF_MASK;
			rxFlags = 0x0000100;
		}

		canid = swap_uint32(frame->can_id);
		msglen = frame->len + 4;
		data_ptr= &(frame->data[0]);

		DBG("Swapped canid = 0x%x", canid);
#if 0
		/* chan for FD Channels are CAN_FD_CH0 = 6, CAN_FD_CH1 = 7
		 * instead of CAN_CH0 = 0 and CAN_CH1 = 1
		 */
		chan += 6;
#else
		if(chan == GARUDA_CAN_CH1) {
			chan = GARUDA_CAN_FD_CH1;
		}else if(chan == GARUDA_CAN_CH2) {
			chan = GARUDA_CAN_FD_CH2;
		} else {
			DBG("Error channel.");
		}
#endif		
		var = J2534_checkFilter((uint8_t *)&canid, &(frame->data[0]),
						msglen, chan);
		if(c == 0) {
			pRxpkt->proto = get_CAN_FD_or_ISO15756_FD();
		} else 	if(c == 1) {
			pRxpkt->proto = get_CAN_FDCH1_or_ISO15765_FDCH1();
		}
		protoid = pRxpkt->proto;
	} else {
		/* error frame */
		return -1;
	}
#endif

	if (var == J2534_PASS) {
#if COUNT_MONITER
		can1Rxcnt++;
		Garuda_Debug.CAN_Rx_Count++;
#endif
		DBG("J2534_PASS Proto ID = 0x%x",pRxpkt->proto);
		if (canBufInfo[c].CAN_MsgCount == 0) {
			canBufInfo[c].len = 4;
			if (Is_DataLog_Active())
				canBufInfo[c].len = 2;
		}

		len = canBufInfo[c].len;
		if( (canBufInfo[c].CAN_MsgCount == 3) || (canBufInfo[c].CAN_MsgCount == 0))
		memset((void *)canBufInfo[c].address, 0,
						HFCP_MAX_IN_SINGLE_FRAME);

		if (Is_DataLog_Active()) {
			pRxlogpkt = (can_msg_resp_data_log_hdr_t *)
						(canBufInfo[c].address);

			pRxlogpkt->d[0].msg_len = DATALOG_FIXED_PACKET_LENGTH +
							msglen;
			pRxlogpkt->d[0].rxflags = rxFlags;

			/**< Manage the Rx Timestamp */
			//get_extended_data_logging_timestamp(
			//			&CANDataLoggingExtendedTime);
			//get_extended_32Bit_data_logging_timestamp(
			//			&CANDataLoggingExtendedTime);

			pRxlogpkt->d[0].msgid = canid;
			len = msglen + sizeof(can_msg_resp_data_log_hdr_t)
			    - sizeof(pRxlogpkt->d)
			    + sizeof(struct can_msg_resp_data_log_payload)
			    - sizeof(pRxlogpkt->d[0].data);
			canBufInfo[c].CAN_MsgCount++;
			if ((len + MAX_DATALOG_FRAME_SIZE) >
			    MAX_USB_BUFFER_SIZE) {
				ERR("Len > MAX_USB_BUFFER_SIZE\n");
				return -1;
			}
		} else { 
			pRxpkt->proto   =  protoid;
			pRxpkt->command = CAN_Receive_msg;
			pRxpkt->seg_num = 0;	/* Segment number */

			/* If this d[0] should be changed to d[i], if a loop
			 * is used
			 */
			pRxpkt->d[message_index_counter].msg_len = CAN_FIXED_PACKET_LENGTH + msglen;
			pRxpkt->d[message_index_counter].rxflags = rxFlags;
			pRxpkt->d[message_index_counter].timestamp = timestamp;
			pRxpkt->d[message_index_counter].msgid = canid;
			
			printf("Message length before index 0: %d\n",pRxpkt->d[0].msg_len);
			memcpy(pRxpkt->d[message_index_counter].data, (void *)data_ptr,
					(msglen-4));

			printf("Message length after index 0: %d\n",pRxpkt->d[0].msg_len);

			len = (msglen-4) + sizeof(can_msg_resp_hdr_t)
				- sizeof(pRxpkt->d)
				+ (sizeof(struct can_msg_resp_payload)
				- sizeof(pRxpkt->d[message_index_counter].data));

			canBufInfo[c].CAN_MsgCount++;
			if (len > MAX_USB_BUFFER_SIZE) {
				ERR("len > MAX_USB_BUFFER_SIZE, len %d", len);
				return -1;
			}
			
			 message_index_counter++;

                         if(data_ptr[0] & 0x10 )
                         {
                                total_length = ( (data_ptr[0] & 0x0F) <<8) | data_ptr[1];
                         	total_length -= 6; 
                         }
 
                         if(data_ptr[0] & 0x20 )
                         {
                                total_length -= 7;
                         }
		}
	} else {
		//DBG("Doing nothing for filtering...");
		/*< Filter Fail, so Drop Frames */
		return -1;
	}

	if (Is_DataLog_Active()) {
		//TimeToWaitForCAN1Q = portMAX_DELAY;
	} else {
		//TimeToWaitForCAN1Q = 1;
	}

	if ( (canBufInfo[c].CAN_MsgCount >= 3) || ( (data_ptr[0] & 0xF0) != 0x20 ) || (total_length <=0)) {
		printf("CAN MESSAGE COUNT %d \n",canBufInfo[c].CAN_MsgCount);
		printf("Total length %d\n", total_length);
#if COUNT_MONITER
		CAN1TotalFrame += canBufInfo[c].CAN_MsgCount;
#endif
		if (Is_DataLog_Active()) {	//&& startLogging)
			pRxlogpkt->mode = (MODE | canBufInfo[c].CAN_MsgCount);
		} else {
			DBG("Proto ID = 0x%x", pRxpkt->proto);
			pRxpkt->mode = (MODE | canBufInfo[c].CAN_MsgCount);
			(void) host_write((void *)pRxpkt, len);
		}
		message_index_counter = 0;
		canBufInfo[c].CAN_MsgCount = 0; /* TODO: Handle this case */
	}

	return len;
}

