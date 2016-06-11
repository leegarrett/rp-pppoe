/***********************************************************************
*
* pppoe.c 
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Copyright (C) 1999 by Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
***********************************************************************/

static char const RCSID[] =
"$Id: pppoe.c,v 1.17 2000/01/10 22:09:50 dfs Exp $";

#include "pppoe.h"
#include <syslog.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif


#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/uio.h>

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

int DiscoveryState;
int DiscoverySocket = -1;
int SessionSocket   = -1;

int PPPState;
int PPPPacketSize;
unsigned char PPPXorValue;

unsigned char BroadcastAddr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char SourceAddr[ETH_ALEN];	/* Source hardware address */
unsigned char DestAddr[ETH_ALEN];	/* Destination hardware address */
char *IfName = NULL;		/* Interface name */
char *ServiceName = NULL;	/* Desired service name */
char *DesiredACName = NULL;	/* Desired access concentrator */
unsigned short Session;		/* Identifier for our session */
int Synchronous = 0;		/* True if using Sync PPP encapsulation */
FILE *DebugFile = NULL;		/* File for dumping debug output */
int optPrintACNames = 0;	/* Only print access concentrator names */
int NumPADOPacketsReceived = 0;	/* Number of PADO packets received */
int optInactivityTimeout = 0;	/* Inactivity timeout */
int optUseHostUnique = 0;       /* Use Host-Unique tag for multiple sessions */

struct PPPoETag cookie;		/* We have to send this if we get it */
struct PPPoETag relayId;	/* Ditto */

#define SET_STRING(var, val) do { if (var) free(var); var = strDup(val); } while(0);

unsigned short fcstab[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/**********************************************************************
*%FUNCTION: dumpHex
*%ARGUMENTS:
* buf -- buffer to dump
* len -- length of data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Dumps buffer to DebugFile in an easy-to-read format
***********************************************************************/
void
dumpHex(unsigned char const *buf, int len)
{
    int i;

    if (!DebugFile) return;
    for (i=0; i<len; i++) {
	if (i == len-1 || !((i+1)%16)) {
	    fprintf(DebugFile, "%02x\n", (unsigned) buf[i]);
	} else if (!((i+1)%8)) {
	    fprintf(DebugFile, "%02x-", (unsigned) buf[i]);
	} else {
	    fprintf(DebugFile, "%02x ", (unsigned) buf[i]);
	}
    }
}

/**********************************************************************
*%FUNCTION: dumpPacket
*%ARGUMENTS:
* packet -- a PPPoE packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Dumps the PPPoE packet to DebugFile in an easy-to-read format
***********************************************************************/
void
dumpPacket(struct PPPoEPacket *packet)
{
    int len = ntohs(packet->length);
    if (!DebugFile) return;
    fprintf(DebugFile, "PPPOE ");

    switch(ntohs(packet->ethHdr.h_proto)) {
    case ETH_PPPOE_DISCOVERY:
	fprintf(DebugFile, "Discovery ");
	break;
    case ETH_PPPOE_SESSION:
	fprintf(DebugFile, "Session ");
	break;
    }

    switch(packet->code) {
    case CODE_PADI: fprintf(DebugFile, "PADI "); break;
    case CODE_PADO: fprintf(DebugFile, "PADO "); break;
    case CODE_PADR: fprintf(DebugFile, "PADR "); break;
    case CODE_PADS: fprintf(DebugFile, "PADS "); break;
    case CODE_PADT: fprintf(DebugFile, "PADT "); break;
    case CODE_SESS: fprintf(DebugFile, "SESS "); break;
    }

    fprintf(DebugFile, "sess-id %d length %d\n",
	    (int) ntohs(packet->session),
	    len);

    /* Ugly... I apologize... */
    fprintf(DebugFile,
	    "SourceAddr %02x:%02x:%02x:%02x:%02x:%02x "
	    "DestAddr %02x:%02x:%02x:%02x:%02x:%02x\n",
	    (unsigned) packet->ethHdr.h_source[0],
	    (unsigned) packet->ethHdr.h_source[1],
	    (unsigned) packet->ethHdr.h_source[2],
	    (unsigned) packet->ethHdr.h_source[3],
	    (unsigned) packet->ethHdr.h_source[4],
	    (unsigned) packet->ethHdr.h_source[5],
	    (unsigned) packet->ethHdr.h_dest[0],
	    (unsigned) packet->ethHdr.h_dest[1],
	    (unsigned) packet->ethHdr.h_dest[2],
	    (unsigned) packet->ethHdr.h_dest[3],
	    (unsigned) packet->ethHdr.h_dest[4],
	    (unsigned) packet->ethHdr.h_dest[5]);
    dumpHex(packet->payload, ntohs(packet->length));
}

/**********************************************************************
*%FUNCTION: parsePacket
*%ARGUMENTS:
* packet -- the PPPoE discovery packet to parse
* func -- function called for each tag in the packet
* extra -- an opaque data pointer supplied to parsing function
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Parses a PPPoE discovery packet, calling "func" for each tag in the packet.
* "func" is passed the additional argument "extra".
***********************************************************************/
void parsePacket(struct PPPoEPacket *packet, ParseFunc *func, void *extra)
{
    unsigned int len = ntohs(packet->length);
    unsigned char *curTag;
    unsigned int tagType, tagLen;

    if (packet->ver != 1) {
	syslog(LOG_ERR, "Invalid PPPoE version %d", (int) packet->ver);
	return;
    }
    if (packet->type != 1) {
	syslog(LOG_ERR, "Invalid PPPoE type %d", (int) packet->type);
	return;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_DATA_LEN - 6) { /* 6-byte overhead for PPPoE header */
	syslog(LOG_ERR, "Invalid PPPoE packet length %u", len);
	return;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while(curTag - packet->payload < len) {
	/* Alignment is not guaranteed, so do this by hand... */
	tagType = (((unsigned int) curTag[0]) << 8) +
	    (unsigned int) curTag[1];
	tagLen = (((unsigned int) curTag[2]) << 8) +
	    (unsigned int) curTag[3];
	if (tagType == TAG_END_OF_LIST) {
	    return;
	}
	func(tagType, tagLen, curTag+4, extra);
	curTag = curTag + 4 + tagLen;
    }
}

/**********************************************************************
*%FUNCTION: parseForHostUniq
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data.
* extra -- user-supplied pointer.  This is assumed to be a pointer to int.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If a HostUnique tag is found which matches our PID, sets *extra to 1.
***********************************************************************/
void
parseForHostUniq(unsigned int type, unsigned int len, unsigned char *data,
		 void *extra)
{
    int *val = (int *) extra;
    if (type == TAG_HOST_UNIQ && len == sizeof(pid_t)) {
	pid_t tmp;
	memcpy(&tmp, data, len);
	if (tmp == getpid()) {
	    *val = 1;
	}
    }
}

/**********************************************************************
*%FUNCTION: packetIsForMe
*%ARGUMENTS:
* packet -- a received PPPoE packet
*%RETURNS:
* 1 if packet is for this PPPoE daemon; 0 otherwise.
*%DESCRIPTION:
* If we are using the Host-Unique tag, verifies that packet contains
* our unique identifier.
***********************************************************************/
int
packetIsForMe(struct PPPoEPacket *packet)
{
    int forMe = 0;

    /* If we're not using the Host-Unique tag, then accept the packet */
    if (!optUseHostUnique) return 1;

    parsePacket(packet, parseForHostUniq, &forMe);
    return forMe;
}

/**********************************************************************
*%FUNCTION: parsePADOTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.  Should point to a PacketCriteria structure
*          which gets filled in according to selected AC name and service
*          name.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADO packet
***********************************************************************/
void
parsePADOTags(unsigned int type, unsigned int len, unsigned char *data,
	      void *extra)
{
    struct PacketCriteria *pc = (struct PacketCriteria *) extra;

    switch(type) {
    case TAG_AC_NAME:
	if (optPrintACNames) {
	    printf("Access-Concentrator: %.*s\n", (int) len, data);
	}
	if (DesiredACName && len == strlen(DesiredACName) &&
	    !strncmp((char *) data, DesiredACName, len)) {
	    pc->acNameOK = 1;
	}
	break;
    case TAG_SERVICE_NAME:
	if (optPrintACNames && len > 0) {
	    printf("       Service-Name: %.*s\n", (int) len, data);
	}
	if (ServiceName && len == strlen(ServiceName) &&
	    !strncmp((char *) data, ServiceName, len)) {
	    pc->serviceNameOK = 1;
	}
	break;
    case TAG_AC_COOKIE:
	if (optPrintACNames) {
	    printf("Got a cookie\n");
	}
	cookie.type = htons(type);
	cookie.length = htons(len);
	memcpy(cookie.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	if (optPrintACNames) {
	    printf("Got a Relay-ID\n");
	}
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_SERVICE_NAME_ERROR:
	if (optPrintACNames) {
	    printf("Got a Service-Name-Error tag: %.*s", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: Service-Name-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    case TAG_AC_SYSTEM_ERROR:
	if (optPrintACNames) {
	    printf("Got a System-Error tag: %.*s", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: System-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    case TAG_GENERIC_ERROR:
	if (optPrintACNames) {
	    printf("Got a Generic-Error tag: %.*s", (int) len, data);
	} else {
	    syslog(LOG_ERR, "PADO: Generic-Error: %.*s", (int) len, data);
	    exit(1);
	}
	break;
    }
}

/**********************************************************************
*%FUNCTION: parseLogErrs
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks error tags out of a packet and logs them.
***********************************************************************/
void
parseLogErrs(unsigned int type, unsigned int len, unsigned char *data,
	     void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME_ERROR:
	syslog(LOG_ERR, "PADT: Service-Name-Error: %.*s", (int) len, data);
	break;
    case TAG_AC_SYSTEM_ERROR:
	syslog(LOG_ERR, "PADT: System-Error: %.*s", (int) len, data);
	break;
    case TAG_GENERIC_ERROR:
	syslog(LOG_ERR, "PADT: Generic-Error: %.*s", (int) len, data);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADSTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADS packet
***********************************************************************/
void
parsePADSTags(unsigned int type, unsigned int len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME:
	syslog(LOG_DEBUG, "PADS: Service-Name: '%.*s'", (int) len, data);
	break;
    case TAG_SERVICE_NAME_ERROR:
	syslog(LOG_ERR, "PADS: Service-Name-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_AC_SYSTEM_ERROR:
	syslog(LOG_ERR, "PADS: System-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_GENERIC_ERROR:
	syslog(LOG_ERR, "PADS: Generic-Error: %.*s", (int) len, data);
	exit(1);
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: printErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog.
***********************************************************************/
void
printErr(char const *str)
{
    fprintf(stderr, "pppoe: %s\n", str);
    if (!optPrintACNames) {
	syslog(LOG_ERR, "%s", str);
    }
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
    exit(1);
}

/**********************************************************************
*%FUNCTION: fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
fatal(char const *str)
{
    printErr(str);
    exit(1);
}

/**********************************************************************
*%FUNCTION: strDup
*%ARGUMENTS:
* str -- string to copy
*%RETURNS:
* A malloc'd copy of str.  Exits if malloc fails.
***********************************************************************/
char *
strDup(char const *str)
{
    char *copy = malloc(strlen(str)+1);
    if (!copy) {
	fatal("strdup failed");
    }
    strcpy(copy, str);
    return copy;
}

/**********************************************************************
*%FUNCTION: openInterface
*%ARGUMENTS:
* ifname -- name of interface
* type -- Ethernet frame type
* hwaddr -- if non-NULL, set to the hardware address
*%RETURNS:
* A raw socket for talking to the Ethernet card.  Exits on error.
*%DESCRIPTION:
* Opens a raw Ethernet socket
***********************************************************************/
int
openInterface(char const *ifname, unsigned short type, unsigned char *hwaddr)
{
    int optval=1;
    int fd;
    struct ifreq ifr;
    int domain, stype;

#ifdef HAVE_STRUCT_SOCKADDR_LL
    struct sockaddr_ll sa;
#else
    struct sockaddr sa;
#endif

    memset(&sa, 0, sizeof(sa));

#ifdef HAVE_STRUCT_SOCKADDR_LL
    domain = PF_PACKET;
    stype = SOCK_RAW;
#else
    domain = PF_INET;
    stype = SOCK_PACKET;
#endif

    if ((fd = socket(domain, stype, htons(type))) < 0) {
	/* Give a more helpful message for the common error case */
	if (errno == EPERM) {
	    fatal("Cannot create raw socket -- pppoe must be run as root.");
	}
	fatalSys("socket");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
	fatalSys("setsockopt");
    }

    /* Fill in hardware address */
    if (hwaddr) {
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
	    fatalSys("ioctl(SIOCGIFHWADDR)");
	}
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data,
	       sizeof(ifr.ifr_hwaddr.sa_data));
    }

    /* Sanity check on MTU */
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
	fatalSys("ioctl(SIOCGIFMTU)");
    }
    if (ifr.ifr_mtu < ETH_DATA_LEN) {
	char buffer[256];
	sprintf(buffer, "Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
		ifname, ifr.ifr_mtu, ETH_DATA_LEN);
	printErr(buffer);
    }

#ifdef HAVE_STRUCT_SOCKADDR_LL
    /* Get interface index */
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(type);

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	fatalSys("ioctl(SIOCFIGINDEX): Could not get interface index");
    }
    sa.sll_ifindex = ifr.ifr_ifindex;

#else
    strcpy(sa.sa_data, ifname);
#endif

    /* We're only interested in packets on specified interface */
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
	fatalSys("bind");
    }

    return fd;
}

/***********************************************************************
*%FUNCTION: sendPacket
*%ARGUMENTS:
* sock -- socket to send to
* pkt -- the packet to transmit
* size -- size of packet (in bytes)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Transmits a packet
***********************************************************************/
void
sendPacket(int sock, struct PPPoEPacket *pkt, int size)
{
#ifdef HAVE_STRUCT_SOCKADDR_LL
    if (send(sock, pkt, size, 0) < 0) {
	fatalSys("send (sendPacket)");
    }
#else
    struct sockaddr sa;
    strcpy(sa.sa_data, IfName);
    if (sendto(sock, pkt, size, 0, &sa, sizeof(sa)) < 0) {
	fatalSys("sendto (sendPacket)");
    }
#endif

    if (DebugFile) {
	fprintf(DebugFile, "SENT ");
	dumpPacket(pkt);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/***********************************************************************
*%FUNCTION: receivePacket
*%ARGUMENTS:
* sock -- socket to read from
* pkt -- place to store the received packet
* size -- set to size of packet in bytes
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Receives a packet
***********************************************************************/
void
receivePacket(int sock, struct PPPoEPacket *pkt, int *size)
{
    if ((*size = recv(sock, pkt, sizeof(struct PPPoEPacket), 0)) < 0) {
	fatalSys("recv (receivePacket)");
    }
    if (DebugFile) {
	fprintf(DebugFile, "RCVD ");
	dumpPacket(pkt);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/***********************************************************************
*%FUNCTION: sendPADI
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADI packet
***********************************************************************/
void
sendPADI()
{
    struct PPPoEPacket packet;
    unsigned char *cursor = packet.payload;
    struct PPPoETag *svc = (struct PPPoETag *) (&packet.payload);
    unsigned short namelen = 0;
    unsigned short plen;

    if (ServiceName) {
	namelen = (unsigned short) strlen(ServiceName);
    }
    plen = TAG_HDR_SIZE + namelen;

    memcpy(packet.ethHdr.h_dest, BroadcastAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, SourceAddr, ETH_ALEN);

    packet.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADI;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    if (ServiceName) {
	memcpy(svc->payload, ServiceName, strlen(ServiceName));
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (optUseHostUnique) {
	struct PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);

    sendPacket(DiscoverySocket, &packet, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: waitForPADO
*%ARGUMENTS:
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADO packet and copies useful information
***********************************************************************/
void
waitForPADO(int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct PPPoEPacket packet;
    int len;

    struct PacketCriteria pc;
    pc.acNameOK      = (DesiredACName)    ? 0 : 1;
    pc.serviceNameOK = (ServiceName)      ? 0 : 1;
	
    do {
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
	FD_ZERO(&readable);
	FD_SET(DiscoverySocket, &readable);
	
	r = select(DiscoverySocket+1, &readable, NULL, NULL, &tv);
	if (r < 0) {
	    fatalSys("select (waitForPADO)");
	}
	if (r == 0) return;        /* Timed out */
	
	/* Get the packet */
	receivePacket(DiscoverySocket, &packet, &len);

	/* If it's not for us, loop again */
	if (!packetIsForMe(&packet)) continue;

	if (packet.code == CODE_PADO) {
	    NumPADOPacketsReceived++;
	    if (optPrintACNames) {
		printf("--------------------------------------------------\n");
	    }
	    parsePacket(&packet, parsePADOTags, &pc);
	    if (pc.acNameOK && pc.serviceNameOK) {
		memcpy(DestAddr, packet.ethHdr.h_source, ETH_ALEN);
		if (optPrintACNames) {
		    printf("AC-Ethernet-Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			   (unsigned) DestAddr[0], 
			   (unsigned) DestAddr[1],
			   (unsigned) DestAddr[2],
			   (unsigned) DestAddr[3],
			   (unsigned) DestAddr[4],
			   (unsigned) DestAddr[5]);
		    continue;
		}
		DiscoveryState = STATE_RECEIVED_PADO;
		break;
	    }
	}
    } while (DiscoveryState != STATE_RECEIVED_PADO);
}

/***********************************************************************
*%FUNCTION: sendPADR
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADR packet
***********************************************************************/
void
sendPADR()
{
    struct PPPoEPacket packet;
    struct PPPoETag *svc = (struct PPPoETag *) packet.payload;
    unsigned char *cursor = packet.payload;

    unsigned short namelen = 0;
    unsigned short plen;

    if (ServiceName) {
	namelen = (unsigned short) strlen(ServiceName);
    }
    plen = TAG_HDR_SIZE + namelen;

    memcpy(packet.ethHdr.h_dest, DestAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, SourceAddr, ETH_ALEN);

    packet.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADR;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    if (ServiceName) {
	memcpy(svc->payload, ServiceName, strlen(ServiceName));
    }

    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (optUseHostUnique) {
	struct PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (cookie.type) {
	memcpy(cursor, &cookie, ntohs(cookie.length) + TAG_HDR_SIZE);
	cursor += ntohs(cookie.length) + TAG_HDR_SIZE;
	plen += ntohs(cookie.length) + TAG_HDR_SIZE;
    }

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);
    sendPacket(DiscoverySocket, &packet, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: waitForPADS
*%ARGUMENTS:
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADS packet and copies useful information
***********************************************************************/
void
waitForPADS(int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    struct PPPoEPacket packet;
    int len;

    do {
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	FD_ZERO(&readable);
	FD_SET(DiscoverySocket, &readable);

	r = select(DiscoverySocket+1, &readable, NULL, NULL, &tv);
	if (r < 0) {
	    fatalSys("select (waitForPADS)");
	}
	if (r == 0) return;

	/* Get the packet */
	receivePacket(DiscoverySocket, &packet, &len);

	/* If it's not for us, loop again */
	if (!packetIsForMe(&packet)) continue;

	/* Is it PADS?  */
	if (packet.code == CODE_PADS) {
	    /* Parse for goodies */
	    parsePacket(&packet, parsePADSTags, NULL);
	    DiscoveryState = STATE_SESSION;
	    break;
	}
    } while (DiscoveryState != STATE_SESSION);

    /* Don't bother with ntohs; we'll just end up converting it back... */
    Session = packet.session;

    syslog(LOG_DEBUG, "PPP session is %d", (int) ntohs(Session));
}

/**********************************************************************
*%FUNCTION: discovery
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Performs the PPPoE discovery phase
***********************************************************************/
void
discovery()
{
    int padiAttempts = 0;
    int padrAttempts = 0;
    int timeout = PADI_TIMEOUT;
    DiscoverySocket = openInterface(IfName, ETH_PPPOE_DISCOVERY, SourceAddr);

    do {
	padiAttempts++;
	if (padiAttempts > MAX_PADI_ATTEMPTS) {
	    fatal("Timeout waiting for PADO packets");
	}
	sendPADI();
	DiscoveryState = STATE_SENT_PADI;
	waitForPADO(timeout);
	timeout *= 2;
	if (optPrintACNames && NumPADOPacketsReceived) {
	    break;
	}
    } while (DiscoveryState == STATE_SENT_PADI);

    /* If we're only printing access concentrator names, we're done */
    if (optPrintACNames) {
	printf("--------------------------------------------------\n");
	exit(0);
    }

    timeout = PADI_TIMEOUT;
    do {
	padrAttempts++;
	if (padrAttempts > MAX_PADI_ATTEMPTS) {
	    fatal("Timeout waiting for PADS packets");
	}
	sendPADR();
	DiscoveryState = STATE_SENT_PADR;
	waitForPADS(timeout);
	timeout *= 2;
    } while (DiscoveryState == STATE_SENT_PADR);

    /* We're done. */
    DiscoveryState = STATE_SESSION;
    return;
}

/***********************************************************************
*%FUNCTION: sendSessionPacket
*%ARGUMENTS:
* packet -- the packet to send
# len -- length of data to send
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Transmits a session packet to the peer.
***********************************************************************/
void
sendSessionPacket(struct PPPoEPacket *packet, int len)
{
    packet->length = htons(len);
    sendPacket(SessionSocket, packet, len + HDR_SIZE);
}

/**********************************************************************
*%FUNCTION: syncReadFromPPP
*%ARGUMENTS:
* packet -- buffer in which to place PPPoE packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads from a synchronous PPP device and builds and transmits a PPPoE
* packet
***********************************************************************/
void
syncReadFromPPP(struct PPPoEPacket *packet)
{
    int r;
    struct iovec vec[2];
    unsigned char dummy[2];
    vec[0].iov_base = dummy;
    vec[0].iov_len = 2;
    vec[1].iov_base = packet->payload;
    vec[1].iov_len = ETH_DATA_LEN - PPPOE_OVERHEAD;

    /* Use scatter-read to throw away the PPP frame address bytes */
    r = readv(0, vec, 2);
    if (r < 0) {
	fatalSys("read (syncReadFromPPP)");
    }
    if (r == 0) {
	syslog(LOG_INFO, "end-of-file in syncReadFromPPP");
	exit(0);
    }

    if (r < 2) {
	fatal("too few characters read from PPP (syncReadFromPPP)");
    }
    if (DebugFile) {
	fprintf(DebugFile, "FROM PPP: %d bytes\n", r);
	dumpHex(packet->payload, r);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
    sendSessionPacket(packet, r-2);
}

/**********************************************************************
*%FUNCTION: asyncReadFromPPP
*%ARGUMENTS:
* packet -- buffer in which to place PPPoE packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads from an async PPP device and builds a PPPoE packet to transmit
***********************************************************************/
void
asyncReadFromPPP(struct PPPoEPacket *packet)
{
    unsigned char buf[READ_CHUNK];
    unsigned char *ptr = buf;
    unsigned char c;

    int r;

    r = read(0, buf, READ_CHUNK);
    if (r < 0) {
	fatalSys("read (asyncReadFromPPP)");
    }

    if (r == 0) {
	syslog(LOG_INFO, "end-of-file in asyncReadFromPPP");
	exit(0);
    }

    if (DebugFile) {
	fprintf(DebugFile, "FROM PPP: %d bytes\n", r);
	dumpHex(buf, r);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }

    while(r) {
	if (PPPState == STATE_WAITFOR_FRAME_ADDR) {
	    while(r) {
		--r;
		if (*ptr++ == FRAME_ADDR) {
		    PPPState = STATE_DROP_PROTO;
		    break;
		}
	    }
	}
	
	/* Still waiting... */
	if (PPPState == STATE_WAITFOR_FRAME_ADDR) return;

	while(r && PPPState == STATE_DROP_PROTO) {
	    --r;
	    if (*ptr++ == (FRAME_CTRL ^ FRAME_ENC)) {
		PPPState = STATE_BUILDING_PACKET;
	    }
	}

	if (PPPState == STATE_DROP_PROTO) return;

	/* Start building frame */
	while(r && PPPState == STATE_BUILDING_PACKET) {
	    --r;
	    c = *ptr++;
	    switch(c) {
	    case FRAME_ESC:
		PPPXorValue = FRAME_ENC;
		break;
	    case FRAME_FLAG:
		if (PPPPacketSize < 2) {
		    fatal("Packet too short from PPP (asyncReadFromPPP)");
		}
		sendSessionPacket(packet, PPPPacketSize-2);
		PPPPacketSize = 0;
		PPPXorValue = 0;
		PPPState = STATE_WAITFOR_FRAME_ADDR;
		break;
	    default:
		if (PPPPacketSize >= ETH_DATA_LEN - 4) {
		    syslog(LOG_ERR, "Packet too big!  Check MTU on PPP interface");
		    PPPPacketSize = 0;
		    PPPXorValue = 0;
		    PPPState = STATE_WAITFOR_FRAME_ADDR;
		} else {
		    packet->payload[PPPPacketSize++] = c ^ PPPXorValue;
		    PPPXorValue = 0;
		}
	    }
	}
    }
}

/**********************************************************************
*%FUNCTION: pppFCS16
*%ARGUMENTS:
* fcs -- current fcs
* cp -- a buffer's worth of data
* len -- length of buffer "cp"
*%RETURNS:
* A new FCS
*%DESCRIPTION:
* Updates the PPP FCS.
***********************************************************************/
unsigned short
pppFCS16(unsigned short fcs, 
	 unsigned char * cp, 
	 int len)
{
    while (len--)
	fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];
    
    return (fcs);
}

/**********************************************************************
*%FUNCTION: asyncReadFromEth
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to async PPP
* device.
***********************************************************************/
void
asyncReadFromEth()
{
    struct PPPoEPacket packet;
    int len;
    int plen;
    int i;
    unsigned char pppBuf[4096];
    unsigned char *ptr = pppBuf;
    unsigned char c;
    unsigned short fcs;
    unsigned char header[2] = {FRAME_ADDR, FRAME_CTRL};
    unsigned char tail[2];

    receivePacket(SessionSocket, &packet, &len);

    /* Sanity check */
    if (packet.code != CODE_SESS) {
	syslog(LOG_ERR, "Unexpected packet code %d", (int) packet.code);
	return;
    }
    if (packet.ver != 1) {
	syslog(LOG_ERR, "Unexpected packet version %d", (int) packet.ver);
	return;
    }
    if (packet.type != 1) {
	syslog(LOG_ERR, "Unexpected packet type %d", (int) packet.type);
	return;
    }
    if (packet.session != Session) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    plen = ntohs(packet.length);
    if (plen + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus length field in session packet %d (%d)",
	       (int) plen, (int) len);
	return;
    }

    /* Compute FCS */
    fcs = pppFCS16(PPPINITFCS16, header, 2);
    fcs = pppFCS16(fcs, packet.payload, plen) ^ 0xffff;
    tail[0] = fcs & 0x00ff;
    tail[1] = (fcs >> 8) & 0x00ff;

    /* Build a buffer to send to PPP */
    *ptr++ = FRAME_FLAG;
    *ptr++ = FRAME_ADDR;
    *ptr++ = FRAME_ESC;
    *ptr++ = FRAME_CTRL ^ FRAME_ENC;

    for (i=0; i<plen; i++) {
	c = packet.payload[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    for (i=0; i<2; i++) {
	c = tail[i];
	if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
	    *ptr++ = FRAME_ESC;
	    *ptr++ = c ^ FRAME_ENC;
	} else {
	    *ptr++ = c;
	}
    }
    *ptr++ = FRAME_FLAG;

    /* Ship it out */
    if (write(1, pppBuf, (ptr-pppBuf)) < 0) {
	fatalSys("asyncReadFromEth: write");
    }
    if (DebugFile) {
	fprintf(DebugFile, "TO PPP: %d bytes\n", ptr-pppBuf);
	dumpHex(pppBuf, ptr-pppBuf);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/**********************************************************************
*%FUNCTION: syncReadFromEth
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to sync PPP
* device.
***********************************************************************/
void
syncReadFromEth()
{
    struct PPPoEPacket packet;
    int len;
    int plen;
    struct iovec vec[2];
    unsigned char dummy[2];

    receivePacket(SessionSocket, &packet, &len);

    /* Sanity check */
    if (packet.code != CODE_SESS) {
	syslog(LOG_ERR, "Unexpected packet code %d", (int) packet.code);
	return;
    }
    if (packet.ver != 1) {
	syslog(LOG_ERR, "Unexpected packet version %d", (int) packet.ver);
	return;
    }
    if (packet.type != 1) {
	syslog(LOG_ERR, "Unexpected packet type %d", (int) packet.type);
	return;
    }
    if (packet.session != Session) {
	/* Not for us -- must be another session.  This is not an error,
	   so don't log anything.  */
	return;
    }
    plen = ntohs(packet.length);
    if (plen + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus length field in session packet %d (%d)",
	       (int) plen, (int) len);
	return;
    }

    /* Ship it out */
    vec[0].iov_base = dummy;
    dummy[0] = FRAME_ADDR;
    dummy[1] = FRAME_CTRL;
    vec[0].iov_len = 2;
    vec[1].iov_base = packet.payload;
    vec[1].iov_len = plen;

    if (writev(1, vec, 2) < 0) {
	fatalSys("syncReadFromEth: write");
    }

    if (DebugFile) {
	fprintf(DebugFile, "TO PPP: %d bytes\n", plen);
	dumpHex(packet.payload, plen);
	fprintf(DebugFile, "\n");
	fflush(DebugFile);
    }
}

/**********************************************************************
*%FUNCTION: sessionDiscoveryPacket
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* We got a discovery packet during the session stage.  This most likely
* means a PADT.
***********************************************************************/
void
sessionDiscoveryPacket()
{
    struct PPPoEPacket packet;
    int len;

    receivePacket(DiscoverySocket, &packet, &len);

    /* Sanity check */
    if (packet.code != CODE_PADT) {
	syslog(LOG_DEBUG, "Got discovery packet (code %d) during session",
	       (int) packet.code);
	return;
    }

    /* It's a PADT, all right.  Is it for us? */
    if (packet.session != Session) {
	/* Nope, ignore it */
	return;
    }

    syslog(LOG_INFO,
	   "Session terminated -- received PADT from access concentrator");
    parsePacket(&packet, parseLogErrs, NULL);
    exit(0);
}

/**********************************************************************
*%FUNCTION: session
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Handles the "session" phase of PPPoE
***********************************************************************/
void
session()
{
    fd_set readable;
    struct PPPoEPacket packet;
    struct timeval tv;
    struct timeval *tvp = NULL;
    int maxFD = 0;
    int r;

    /* Open a session socket */
    SessionSocket = openInterface(IfName, ETH_PPPOE_SESSION, NULL);

    /* Prepare for select() */
    if (SessionSocket > maxFD) maxFD = SessionSocket;
    if (DiscoverySocket > maxFD) maxFD = DiscoverySocket;
    maxFD++;

    /* Fill in the constant fields of the packet to save time */
    memcpy(packet.ethHdr.h_dest, DestAddr, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, SourceAddr, ETH_ALEN);
    packet.ethHdr.h_proto = htons(ETH_PPPOE_SESSION);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_SESS;
    packet.session = Session;

    PPPState = STATE_WAITFOR_FRAME_ADDR;
    PPPPacketSize = 0;
    PPPXorValue = 0;

    for (;;) {
	if (optInactivityTimeout > 0) {
	    tv.tv_sec = optInactivityTimeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	FD_ZERO(&readable);
	FD_SET(0, &readable);     /* ppp packets come from stdin */
	FD_SET(DiscoverySocket, &readable);
	FD_SET(SessionSocket, &readable);
	r = select(maxFD, &readable, NULL, NULL, tvp);
	if (r < 0) {
	    fatalSys("select (session)");
	}
	if (r == 0) { /* Inactivity timeout */
	    syslog(LOG_ERR, "Inactivity timeout... something wicked happened");
	    exit(1);
	}

	/* Handle ready sockets */
	if (FD_ISSET(0, &readable)) {
	    if (Synchronous) {
		syncReadFromPPP(&packet);
	    } else {
		asyncReadFromPPP(&packet);
	    }
	}
	if (FD_ISSET(SessionSocket, &readable)) {
	    if (Synchronous) {
		syncReadFromEth();
	    } else {
		asyncReadFromEth();
	    }
	}
	if (FD_ISSET(DiscoverySocket, &readable)) {
	    sessionDiscoveryPacket();
	}
    }
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- program name
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage information and exits.
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s)\n",
	    DEFAULT_IF);
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds\n");
    fprintf(stderr, "   -D filename    -- Log debugging information in filename\n");
    fprintf(stderr, "   -V             -- Print version and exit\n");
    fprintf(stderr, "   -A             -- Print access concentrator names and exit\n");
    fprintf(stderr, "   -S name        -- Set desired service name\n");
    fprintf(stderr, "   -C name        -- Set desired access concentrator name\n");
    fprintf(stderr, "   -U             -- Use Host-Unique to allow multiple PPPoE sessions\n");
    fprintf(stderr, "   -s             -- Use synchronous PPP encapsulation.  If you do this,\n");
    fprintf(stderr, "                     then you MUST supply the `sync' option to pppd.\n");
    fprintf(stderr, "   -h             -- Print usage info\n\n");
    fprintf(stderr, "PPPoE Version %s, Copyright (C) 1999 Roaring Penguin Software Inc.\n", VERSION);
    fprintf(stderr, "PPPoE comes with ABSOLUTELY NO WARRANTY.\n\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under the terms of the GNU General Public License, version 2\n");
    fprintf(stderr, "or (at your option) any later version.\n\n");
    fprintf(stderr, "http://www.roaringpenguin.com\n");
    exit(0);
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- count and values of command-line arguments
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Main program
***********************************************************************/
int
main(int argc, char *argv[])
{
    int opt;

    /* No cookie or relay-ID yet */
    cookie.type = 0;
    relayId.type = 0;

    /* Initialize syslog */
    openlog("pppoe", LOG_PID, LOG_DAEMON);

    while((opt = getopt(argc, argv, "I:VAT:D:hS:C:Us")) != -1) {
	switch(opt) {
	case 'S':
	    SET_STRING(ServiceName, optarg);
	    break;
	case 'C':
	    SET_STRING(DesiredACName, optarg);
	    break;
	case 's':
	    Synchronous = 1;
	    break;
	case 'U':
	    optUseHostUnique = 1;
	    break;
	case 'D':
	    DebugFile = fopen(optarg, "w");
	    if (!DebugFile) {
		fprintf(stderr, "Could not open %s: %s\n",
			optarg, strerror(errno));
		exit(1);
	    }
	case 'T':
	    optInactivityTimeout = (int) strtol(optarg, NULL, 10);
	    if (optInactivityTimeout < 0) {
		optInactivityTimeout = 0;
	    }
	    break;
	case 'I':
	    SET_STRING(IfName, optarg);
	    break;
	case 'V':
	    printf("Roaring Penguin PPPoE Version %s\n", VERSION);
	    exit(0);
	case 'A':
	    optPrintACNames = 1;
	    break;
	case 'h':
	    usage(argv[0]);
	    break;
	default:
	    usage(argv[0]);
	}
    }

    /* Pick a default interface name */
    if (!IfName) {
	IfName = DEFAULT_IF;
    }

    discovery();
    session();
    exit(0);
}
