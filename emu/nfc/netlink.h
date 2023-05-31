#ifndef _PNETLINK
#define _PNETLINK
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/in6.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/veth.h>

typedef int uint16;

struct nlmsg {
	char* pos;
	int nesting;
	struct nlattr* nested[8];
	char buf[4096];
};

void netlink_init(struct nlmsg* nlmsg, int typ, int flags,
			 const void* data, int size);

void netlink_attr(struct nlmsg* nlmsg, int typ,
			 const void* data, int size);

int netlink_send(struct nlmsg* nlmsg, int sock);

int netlink_query_family_id(struct nlmsg* nlmsg, int sock, const char* family_name, bool dofail);

#endif
