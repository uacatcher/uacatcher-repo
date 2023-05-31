#ifndef _PNFC
#define _PNFC

#include <termios.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdint.h>
#include <pty.h>
#include <net/if.h>
#include <ctype.h>
#include <linux/nfc.h>
#include <linux/tty.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <sys/ioctl.h>

#define NCIUARTSETDRIVER	_IOW('U', 0, char *)
#define NFC_TARGET_IDX_ANY -1

char buf[100]={'0'};
static struct nlmsg nlmsg;
int flag = 1;

struct pparam {
  int mfd;
  int sfd;
  int sock;
};

pthread_t th1,th2,th3,th4;
pid_t pid;
struct pparam res = {0};
int random_del1;
int random_del2;
int random_del3;
int random_del4;

int getmaster(void);
int getslave(int fdm);
int setserial(int fd, int ldisc);
int nfc_register(int fd);
void nfc_initialize();

//tty相关操作
int getpt (void);
int grantpt (int filedes);
int unlockpt (int filedes);

//nci相关命令
	const __u8 nci_reset_cmd[] = {0x20, 0x00, 0x01, 0x01};
	const __u8 nci_init_cmd[] = {0x20, 0x01, 0x00};
	const __u8 nci_set_config_cmd[] = {0x20, 0x02, 0x04, 0x01, 0x11, 0x01, 0x01};
	const __u8 nci_reset_rsp[] = {0x40, 0x00, 0x03, 0x00, 0x10, 0x01};
	const __u8 nci_init_rsp[] = {0x40, 0x01, 0x14, 0x00, 0x02, 0x0e, 0x02,
                             0x00, 0x03, 0x01, 0x02, 0x03, 0x02, 0xc8,
                             0x00, 0xff, 0x10, 0x00, 0x0e, 0x12, 0x00,
                             0x00, 0x04};
	const __u8 nci_set_config_rsp[] = {0x40, 0x02, 0x04, 0x00, 0x11, 0x01, 0x01};
	const __u8 nci_rf_disc_map_cmd[] = {0x21, 0x00, 0x07, 0x02, 0x04, 0x03,
                                    0x02, 0x05, 0x03, 0x03};
	const __u8 nci_rf_disc_map_rsp[] = {0x41, 0x00, 0x01, 0x00};

/* Message Type (MT) */
#define NCI_MT_DATA_PKT						0x00
#define NCI_MT_CMD_PKT						0x01
#define NCI_MT_RSP_PKT						0x02
#define NCI_MT_NTF_PKT						0x03

/* ---- NCI Packet structures ---- */
#define NCI_CTRL_HDR_SIZE					3
#define NCI_DATA_HDR_SIZE					3

#define nci_mt(hdr)			(((hdr)[0]>>5)&0x07)
#define nci_mt_set(hdr, mt)		((hdr)[0] |= (uint8_t)(((mt)&0x07)<<5))

/* Packet Boundary Flag (PBF) */
#define NCI_PBF_LAST						0x00
#define NCI_PBF_CONT						0x01

#define nci_pbf(hdr)			(uint8_t)(((hdr)[0]>>4)&0x01)
#define nci_pbf_set(hdr, pbf)		((hdr)[0] |= (uint8_t)(((pbf)&0x01)<<4))

/* Control Opcode manipulation */
#define nci_opcode_pack(gid, oid)	(uint16_t)((((uint16_t)((gid)&0x0f))<<8)|\
					((uint16_t)((oid)&0x3f)))
#define nci_opcode(hdr)			nci_opcode_pack(hdr[0], hdr[1])
#define nci_opcode_gid(op)		(uint8_t)(((op)&0x0f00)>>8)
#define nci_opcode_oid(op)		(uint8_t)((op)&0x003f)

/* Payload Length */
#define nci_plen(hdr)			(uint8_t)((hdr)[2])

/* GID values */
#define NCI_GID_CORE						0x0
#define NCI_GID_RF_MGMT						0x1
#define NCI_GID_NFCEE_MGMT					0x2
#define NCI_GID_PROPRIETARY					0xf

/* Connection ID */
#define nci_conn_id(hdr)		(uint8_t)(((hdr)[0])&0x0f)

#define NCI_OP_RF_DISCOVER_NTF		nci_opcode_pack(NCI_GID_RF_MGMT, 0x03)

#define NFC_NFCID1_MAXSIZE		10
#define NFC_SENSB_RES_MAXSIZE		12
#define NFC_SENSF_RES_MAXSIZE		18
#define NFC_ISO15693_UID_MAXSIZE	8

struct rf_tech_specific_params_nfca_poll {
	uint16_t	sens_res;
	uint8_t	nfcid1_len;	/* 0, 4, 7, or 10 Bytes */
	uint8_t	nfcid1[NFC_NFCID1_MAXSIZE];
	uint8_t	sel_res_len;	/* 0 or 1 Bytes */
	uint8_t	sel_res;
} __attribute__((packed));

struct rf_tech_specific_params_nfcb_poll {
	uint8_t	sensb_res_len;
	uint8_t	sensb_res[NFC_SENSB_RES_MAXSIZE];	/* 11 or 12 Bytes */
} __attribute__((packed));

struct rf_tech_specific_params_nfcf_poll {
	uint8_t	bit_rate;
	uint8_t	sensf_res_len;
	uint8_t	sensf_res[NFC_SENSF_RES_MAXSIZE];	/* 16 or 18 Bytes */
} __attribute__((packed));

struct rf_tech_specific_params_nfcv_poll {
	uint8_t	res_flags;
	uint8_t	dsfid;
	uint8_t	uid[NFC_ISO15693_UID_MAXSIZE];	/* 8 Bytes */
} __attribute__((packed));

struct nci_rf_discover_ntf {
	uint8_t	rf_discovery_id;
	uint8_t	rf_protocol;
	uint8_t	rf_tech_and_mode;
	uint8_t	rf_tech_specific_params_len;

	union {
		struct rf_tech_specific_params_nfca_poll nfca_poll;
		struct rf_tech_specific_params_nfcb_poll nfcb_poll;
		struct rf_tech_specific_params_nfcf_poll nfcf_poll;
		struct rf_tech_specific_params_nfcv_poll nfcv_poll;
	} rf_tech_specific_params;

	uint8_t	ntf_type;
} __attribute__((packed));

/* NFCEE Discovery Action */
#define NCI_NFCEE_DISCOVERY_ACTION_DISABLE			0x00
#define NCI_NFCEE_DISCOVERY_ACTION_ENABLE			0x01

/* NCI RF Technology and Mode */
#define NCI_NFC_A_PASSIVE_POLL_MODE				0x00
#define NCI_NFC_B_PASSIVE_POLL_MODE				0x01
#define NCI_NFC_F_PASSIVE_POLL_MODE				0x02
#define NCI_NFC_A_ACTIVE_POLL_MODE				0x03
#define NCI_NFC_F_ACTIVE_POLL_MODE				0x05
#define NCI_NFC_V_PASSIVE_POLL_MODE				0x06
#define NCI_NFC_A_PASSIVE_LISTEN_MODE				0x80
#define NCI_NFC_B_PASSIVE_LISTEN_MODE				0x81
#define NCI_NFC_F_PASSIVE_LISTEN_MODE				0x82
#define NCI_NFC_A_ACTIVE_LISTEN_MODE				0x83
#define NCI_NFC_F_ACTIVE_LISTEN_MODE				0x85

/* NCI Discover Notification Type */
#define NCI_DISCOVER_NTF_TYPE_LAST				0x00
#define NCI_DISCOVER_NTF_TYPE_LAST_NFCC				0x01
#define NCI_DISCOVER_NTF_TYPE_MORE				0x02
/* NFC socket protocols */
#define NFC_SOCKPROTO_RAW	0
#define NFC_SOCKPROTO_LLCP	1
#define NFC_SOCKPROTO_MAX	2

#endif
