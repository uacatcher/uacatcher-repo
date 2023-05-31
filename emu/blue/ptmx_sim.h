#ifndef _PTMX_SIM
#define _PTMX_SIM

#include <errno.h>
#include <fcntl.h>
#include <linux/rfkill.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <termios.h>
#include <pthread.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// macros and structs
#define bool uint8
#define true 1
#define false 0

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

struct sockaddr_hci {
        unsigned short hci_family;
        unsigned short hci_dev;
        unsigned short hci_channel;
};

#define HCIDEVUP   _IOW('H', 201, int)
#define HCISETSCAN _IOW('H', 221, int)
#define HCIINQUIRY _IOR('H', 240, int)

#define HCIUARTGETDEVICE        _IOR('U', 202, int)
#define HCIUARTSETFLAGS         _IOW('U', 203, int)
#define HCIUARTSETPROTO         _IOW('U', 200, int)
#define HCI_UART_RESET_ON_INIT  1

#define BTPROTO_HCI 1
#define ACL_LINK 1
#define SCAN_PAGE 2

typedef struct {
  uint8_t b[6];
} __attribute__((packed)) bdaddr_t;

#define HCI_COMMAND_PKT 1
#define HCI_EVENT_PKT 4
#define HCI_VENDOR_PKT 0xff

#define HCI_OP_WRITE_CA_TIMEOUT 0x0c16

struct hci_command_hdr {
  uint16_t opcode;
  uint8_t plen;
} __attribute__((packed));

struct hci_event_hdr {
  uint8_t evt;
  uint8_t plen;
} __attribute__((packed));

#define HCI_EV_CONN_COMPLETE 0x03
struct hci_ev_conn_complete {
  uint8_t status;
  uint16_t handle;
  bdaddr_t bdaddr;
  uint8_t link_type;
  uint8_t encr_mode;
} __attribute__((packed));

#define HCI_EV_CONN_REQUEST 0x04
struct hci_ev_conn_request {
  bdaddr_t bdaddr;
  uint8_t dev_class[3];
  uint8_t link_type;
} __attribute__((packed));

#define HCI_EV_REMOTE_FEATURES 0x0b
struct hci_ev_remote_features {
  uint8_t status;
  uint16_t handle;
  uint8_t features[8];
} __attribute__((packed));

#define HCI_EV_CMD_COMPLETE 0x0e
struct hci_ev_cmd_complete {
  uint8_t ncmd;
  uint16_t opcode;
} __attribute__((packed));

#define HCI_OP_WRITE_SCAN_ENABLE 0x0c1a

#define HCI_OP_READ_BUFFER_SIZE 0x1005
struct hci_rp_read_buffer_size {
  uint8_t status;
  uint16_t acl_mtu;
  uint8_t sco_mtu;
  uint16_t acl_max_pkt;
  uint16_t sco_max_pkt;
} __attribute__((packed));

#define HCI_OP_READ_BD_ADDR 0x1009
struct hci_rp_read_bd_addr {
  uint8_t status;
  bdaddr_t bdaddr;
} __attribute__((packed));

#define HCI_EV_LE_META 0x3e
struct hci_ev_le_meta {
  uint8_t subevent;
} __attribute__((packed));

#define HCI_EV_LE_CONN_COMPLETE 0x01
struct hci_ev_le_conn_complete {
  uint8_t status;
  uint16_t handle;
  uint8_t role;
  uint8_t bdaddr_type;
  bdaddr_t bdaddr;
  uint16_t interval;
  uint16_t latency;
  uint16_t supervision_timeout;
  uint8_t clk_accurancy;
} __attribute__((packed));

#define HCI_OP_READ_LOCAL_NAME 0x0c14
#define HCI_MAX_NAME_LENGTH             248
#define HCI_MAX_NAME_LENGTH_BUG         4
struct hci_rp_read_local_name {
        uint8     status;
        uint8     name[HCI_MAX_NAME_LENGTH];
} __attribute__((packed));

struct hci_rp_read_local_name_bug {
        uint8     status;
        uint8     name[HCI_MAX_NAME_LENGTH_BUG];
} __attribute__((packed));

#define HCI_OP_RESET 0x0c03
#define HCI_OP_READ_LOCAL_FEATURES 0x1003
#define HCI_OP_READ_LOCAL_VERSION 0x1001
#define HCI_OP_READ_CLASS_OF_DEV 0x0c23

struct hci_dev_req {
  uint16_t dev_id;
  uint32_t dev_opt;
};

struct vhci_vendor_pkt {
  uint8_t type;
  uint8_t opcode;
  uint16_t id;
};

struct pparam {
  int mfd;
  int sfd;
  int sock;
};
struct pparam res = {0};
// functions
void initialize_hci_uart();
int grantpt (int filedes);
int unlockpt (int filedes);
#endif
