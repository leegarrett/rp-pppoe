/***********************************************************************
*
* pppoe-server.c
*
* Implementation of a user-space PPPoE server
*
* Copyright (C) 2000 Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id: pppoe-server.c,v 1.55 2001/09/06 15:11:28 dfs Exp $
*
***********************************************************************/

static char const RCSID[] =
"$Id: pppoe-server.c,v 1.55 2001/09/06 15:11:28 dfs Exp $";

#include "config.h"

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define _POSIX_SOURCE 1 /* For sigaction defines */
#endif

#define _BSD_SOURCE 1 /* for gethostname */

#include "pppoe-server.h"
#include "md5.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <signal.h>

#ifdef HAVE_LICENSE
#include "license.h"
#include "licensed-only/servfuncs.h"
static struct License const *ServerLicense;
#else
#define control_session_started(x) (void) 0
#define control_session_terminated(x) (void) 0
#define control_exit() (void) 0
#define realpeerip peerip
#endif

static void alarmHandler(int sig);
static void processPacket(Interface *i);

static void startPPPD(ClientSession *sess);
static void sendErrorPADS(int sock, unsigned char *source, unsigned char *dest,
			  int errorTag, char *errorMsg);

#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
        syslog(LOG_ERR, "Would create too-long packet"); \
        return; \
    } \
} while(0)

/* An array of client sessions */
ClientSession *Sessions = NULL;
ClientSession *FreeSessions = NULL;
ClientSession *LastFreeSession = NULL;
ClientSession *BusySessions = NULL;

/* Interfaces we're listening on */
Interface interfaces[MAX_INTERFACES];
int NumInterfaces = 0;

/* The number of session slots */
size_t NumSessionSlots;

/* Number of active sessions */
size_t NumActiveSessions = 0;

/* Offset of first session */
size_t SessOffset = 0;

/* Use Linux kernel-mode PPPoE? */
static int UseLinuxKernelModePPPoE = 0;

/* Pipe written on reception of SIGCHLD */
static int Pipe[2] = {-1, -1};
static int ReapPending = 0;
static int PleaseTerminate = 0;
int GotAlarm = 0;
static int HaveSetAlarm = 0;
static struct sigaction OldAlarmHandler;
static int TerminateSignal = 0;
static int Debug = 0;
static int CheckPoolSyntax = 0;

/* Synchronous mode */
static int Synchronous = 0;

/* Random seed for cookie generation */
#define SEED_LEN 16
#define MD5_LEN 16
#define COOKIE_LEN (MD5_LEN + sizeof(pid_t)) /* Cookie is 16-byte MD5 + PID of server */

static unsigned char CookieSeed[SEED_LEN];

#define MAXLINE 512

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

/* Access concentrator name */
char *ACName = NULL;

/* Options to pass to pppoe process */
char PppoeOptions[SMALLBUF] = "";

/* Our local IP address */
unsigned char LocalIP[IPV4ALEN] = {10, 0, 0, 1}; /* Counter optionally STARTS here */
unsigned char RemoteIP[IPV4ALEN] = {10, 67, 15, 1}; /* Counter STARTS here */

/* Do we increment local IP for each connection? */
int IncrLocalIP = 0;

/* Do we randomize session numbers? */
int RandomizeSessionNumbers = 0;

/* Do we pass the "unit" option to pppd?  (2.4 or greater) */
int PassUnitOptionToPPPD = 0;

static PPPoETag hostUniq;
static PPPoETag relayId;
static PPPoETag receivedCookie;
static PPPoETag requestedService;

#define HOSTNAMELEN 256

static int
sockInUse(int s)
{
    int i;
    for (i=0; i<NumInterfaces; i++) {
	if (s == interfaces[i].sock) return 1;
    }
    return 0;
}

/**********************************************************************
*%FUNCTION: incrementIPAddress (static)
*%ARGUMENTS:
* addr -- a 4-byte array representing IP address
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Increments addr in-place
***********************************************************************/
static void
incrementIPAddress(unsigned char ip[IPV4ALEN])
{
    ip[3]++;
    if (!ip[3]) {
	ip[2]++;
	if (!ip[2]) {
	    ip[1]++;
	    if (!ip[1]) {
		ip[0]++;
	    }
	}
    }
}

/**********************************************************************
*%FUNCTION: killAllSessions
*%ARGUMENTS:
* myAddr -- My Ethernet address
* sock -- discovery socket
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills all pppd processes (and hence all PPPoE sessions)
***********************************************************************/
void
killAllSessions(void)
{
    ClientSession *sess = BusySessions;
    while(sess) {
	kill(sess->pid, SIGTERM);
	sess = sess->next;
    }
    reapAllSessions();
}

/**********************************************************************
*%FUNCTION: parseAddressPool
*%ARGUMENTS:
* fname -- name of file containing IP address pool.
* install -- if true, install IP addresses in sessions.
*%RETURNS:
* Number of valid IP addresses found.
*%DESCRIPTION:
* Reads a list of IP addresses from a file.
***********************************************************************/
static int
parseAddressPool(char const *fname, int install)
{
    FILE *fp = fopen(fname, "r");
    int numAddrs = 0;
    unsigned int a, b, c, d;
    unsigned int e, f, g, h;
    char line[MAXLINE];

    if (!fp) {
	sysErr("Cannot open address pool file");
	exit(1);
    }

    while (!feof(fp)) {
	if (!fgets(line, MAXLINE, fp)) {
	    break;
	}
	if ((sscanf(line, "%u.%u.%u.%u:%u.%u.%u.%u",
		    &a, &b, &c, &d, &e, &f, &g, &h) == 8) &&
	    a < 256 && b < 256 && c < 256 && d < 256 &&
	    e < 256 && f < 256 && g < 256 && h < 256) {

	    /* Both specified (local:remote) */
	    if (install) {
		Sessions[numAddrs].myip[0] = (unsigned char) a;
		Sessions[numAddrs].myip[1] = (unsigned char) b;
		Sessions[numAddrs].myip[2] = (unsigned char) c;
		Sessions[numAddrs].myip[3] = (unsigned char) d;
		Sessions[numAddrs].peerip[0] = (unsigned char) e;
		Sessions[numAddrs].peerip[1] = (unsigned char) f;
		Sessions[numAddrs].peerip[2] = (unsigned char) g;
		Sessions[numAddrs].peerip[3] = (unsigned char) h;
#ifdef HAVE_LICENSE
		memcpy(Sessions[numAddrs].realpeerip,
		       Sessions[numAddrs].peerip, IPV4ALEN);
#endif
	    }
	    numAddrs++;
	} else if ((sscanf(line, "%u.%u.%u.%u-%u", &a, &b, &c, &d, &e) == 5) &&
		   a < 256 && b < 256 && c < 256 && d < 256 && e < 256) {
	    /* Remote specied as a.b.c.d-e.  Example: 1.2.3.4-8 yields:
	       1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7, 1.2.3.8 */
	    /* Swap d and e so that e >= d */
	    if (e < d) {
		f = d;
		d = e;
		e = f;
	    }
	    if (install) {
		while (d <= e) {
		    Sessions[numAddrs].peerip[0] = (unsigned char) a;
		    Sessions[numAddrs].peerip[1] = (unsigned char) b;
		    Sessions[numAddrs].peerip[2] = (unsigned char) c;
		    Sessions[numAddrs].peerip[3] = (unsigned char) d;
#ifdef HAVE_LICENSE
		    memcpy(Sessions[numAddrs].realpeerip,
			   Sessions[numAddrs].peerip, IPV4ALEN);
#endif
		d++;
		numAddrs++;
		}
	    } else {
		numAddrs += (e-d) + 1;
	    }
	} else if ((sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) &&
		   a < 256 && b < 256 && c < 256 && d < 256) {
	    /* Only remote specified */
	    if (install) {
		Sessions[numAddrs].peerip[0] = (unsigned char) a;
		Sessions[numAddrs].peerip[1] = (unsigned char) b;
		Sessions[numAddrs].peerip[2] = (unsigned char) c;
		Sessions[numAddrs].peerip[3] = (unsigned char) d;
#ifdef HAVE_LICENSE
		memcpy(Sessions[numAddrs].realpeerip,
		       Sessions[numAddrs].peerip, IPV4ALEN);
#endif
	    }
	    numAddrs++;
	}
    }
    if (!numAddrs) {
	rp_fatal("No valid ip addresses found in pool file");
    }
    return numAddrs;
}

/**********************************************************************
*%FUNCTION: parsePADITags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADI packet
***********************************************************************/
void
parsePADITags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME:
	/* Should do something -- currently ignored */
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADRTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADR packet
***********************************************************************/
void
parsePADRTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    case TAG_AC_COOKIE:
	receivedCookie.type = htons(type);
	receivedCookie.length = htons(len);
	memcpy(receivedCookie.payload, data, len);
	break;
    case TAG_SERVICE_NAME:
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: reapSessions
*%ARGUMENTS:
* nohang -- if true, use WNOHANG in "waitpid" call.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reaps children which have exited and removes their sessions
**********************************************************************/
void
reapSessions(int nohang)
{
    int status;
    pid_t pid;
    ClientSession *session;
    ClientSession *prev;
    int flags = 0;
    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;

    /* If we must not hang around, set flag... */
    if (nohang) flags = WNOHANG;

    memset(&conn, 0, sizeof(conn));

    /* Initialize fields of conn which do not depend on peer */
    conn.useHostUniq = 0;

    GotAlarm = 0;

    for(;;) {
	errno = 0;

	/* If we MUST hang around, set an alarm for 30 seconds.  If 30 seconds
	   elapse without seeing a dead kid, punt... */
	if (!nohang) setAlarm(30);

	while((pid = waitpid(-1, &status, flags)) > 0) {
	    /* Timed out waiting for kids */
	    if (GotAlarm) return;
	    /* Search on the busy list */
	    session = BusySessions;
	    prev = NULL;
	    while(session) {
		if (session->pid == pid) {
		    break;
		}
		prev = session;
		session = session->next;
	    }
	    if (!session) {
		syslog(LOG_ERR, "Child %d died but couldn't find session!",
		       (int) pid);
	    } else {
		/* Remove from busy list */
		if (prev) {
		    prev->next = session->next;
		} else {
		    BusySessions = session->next;
		}

		/* Add to end of free sessions */
		session->next = NULL;
		if (LastFreeSession) {
		    LastFreeSession->next = session;
		    LastFreeSession = session;
		} else {
		    FreeSessions = session;
		    LastFreeSession = session;
		}
		syslog(LOG_INFO,
		       "Session %d closed for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s",
		       ntohs(session->sess),
		       session->eth[0], session->eth[1], session->eth[2],
		       session->eth[3], session->eth[4], session->eth[5],
		       (int) session->realpeerip[0], (int) session->realpeerip[1],
		       (int) session->realpeerip[2], (int) session->realpeerip[3],
		       session->ethif->name);
		memcpy(conn.myEth, session->ethif->mac, ETH_ALEN);
		conn.discoverySocket = session->ethif->sock;
		conn.session = session->sess;
		memcpy(conn.peerEth, session->eth, ETH_ALEN);
		if (session->flags & FLAG_RECVD_PADT) {
		    sendPADT(&conn, "RP-PPPoE: Received PADT from peer");
		} else {
		    sendPADT(&conn, "RP-PPPoE: Child pppd process terminated");
		}
		session->pid = 0;
		NumActiveSessions--;
		control_session_terminated(session);
	    }
	    if (!nohang) setAlarm(30);
	}
	/* Timed out waiting for kids */
	if (GotAlarm) break;

	/* Some other error -- quit */
	if (errno != EINTR) break;
    }
    if (!nohang) setAlarm(0);
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
    char buf[SMALLBUF];
    snprintf(buf, SMALLBUF, "%s: %s", str, strerror(errno));
    printErr(buf);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    printErr(str);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: genCookie
*%ARGUMENTS:
* peerEthAddr -- peer Ethernet address (6 bytes)
* myEthAddr -- my Ethernet address (6 bytes)
* seed -- random cookie seed to make things tasty (16 bytes)
* cookie -- buffer which is filled with server PID and 
*           md5 sum of previous items
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Forms the md5 sum of peer MAC address, our MAC address and seed, useful
* in a PPPoE Cookie tag.
***********************************************************************/
void
genCookie(unsigned char const *peerEthAddr,
	  unsigned char const *myEthAddr,
	  unsigned char const *seed,
	  unsigned char *cookie)
{
    struct MD5Context ctx;
    pid_t pid = getpid();

    MD5Init(&ctx);
    MD5Update(&ctx, peerEthAddr, ETH_ALEN);
    MD5Update(&ctx, myEthAddr, ETH_ALEN);
    MD5Update(&ctx, seed, SEED_LEN);
    MD5Final(cookie, &ctx);
    memcpy(cookie+MD5_LEN, &pid, sizeof(pid));
}

/**********************************************************************
*%FUNCTION: processPADI
*%ARGUMENTS:
* ethif -- Interface
* packet -- PPPoE PADI packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADO packet back to client
***********************************************************************/
void
processPADI(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket pado;
    PPPoETag acname;
    PPPoETag servname;
    PPPoETag cookie;
    size_t acname_len;
    unsigned char *cursor = pado.payload;
    UINT16_t plen;

    int sock = ethif->sock;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_ERR, "PADI packet from non-unicast source address");
	return;
    }

    acname.type = htons(TAG_AC_NAME);
    acname_len = strlen(ACName);
    acname.length = htons(acname_len);
    memcpy(acname.payload, ACName, acname_len);

    servname.type = htons(TAG_SERVICE_NAME);
    servname.length = 0;

    relayId.type = 0;
    hostUniq.type = 0;
    parsePacket(packet, parsePADITags, NULL);

    /* Generate a cookie */
    cookie.type = htons(TAG_AC_COOKIE);
    cookie.length = htons(COOKIE_LEN);
    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookie.payload);

    /* Construct a PADO packet */
    memcpy(pado.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pado.ethHdr.h_source, myAddr, ETH_ALEN);
    pado.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pado.ver = 1;
    pado.type = 1;
    pado.code = CODE_PADO;
    pado.session = 0;
    plen = TAG_HDR_SIZE + acname_len;

    CHECK_ROOM(cursor, pado.payload, acname_len+TAG_HDR_SIZE);
    memcpy(cursor, &acname, acname_len + TAG_HDR_SIZE);
    cursor += acname_len + TAG_HDR_SIZE;

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE);
    memcpy(cursor, &servname, TAG_HDR_SIZE);
    cursor += TAG_HDR_SIZE;
    plen += TAG_HDR_SIZE;

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE + COOKIE_LEN);
    memcpy(cursor, &cookie, TAG_HDR_SIZE + COOKIE_LEN);
    cursor += TAG_HDR_SIZE + COOKIE_LEN;
    plen += TAG_HDR_SIZE + COOKIE_LEN;

    if (relayId.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(hostUniq.length)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pado.length = htons(plen);
    sendPacket(NULL, sock, &pado, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: processPADT
*%ARGUMENTS:
* ethif -- interface
* packet -- PPPoE PADT packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills session whose session-ID is in PADT packet.
***********************************************************************/
void
processPADT(Interface *ethif, PPPoEPacket *packet, int len)
{
    size_t i;

    unsigned char *myAddr = ethif->mac;

    /* Ignore PADT's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Get session's index */
    i = ntohs(packet->session) - 1 - SessOffset;
    if (i >= NumSessionSlots) return;
    if (Sessions[i].sess != packet->session) {
	syslog(LOG_ERR, "Session index %u doesn't match session number %u",
	       (unsigned int) i, (unsigned int) ntohs(packet->session));
	return;
    }

    
    if (Sessions[i].pid) {
	/* If source MAC does not match, do not kill session */
	if (memcmp(packet->ethHdr.h_source, Sessions[i].eth, ETH_ALEN)) {
	    syslog(LOG_WARNING, "PADT for session %u received from "
		   "%02X:%02X:%02X:%02X:%02X:%02X; should be from "
		   "%02X:%02X:%02X:%02X:%02X:%02X",
		   (unsigned int) ntohs(packet->session),
		   packet->ethHdr.h_source[0],
		   packet->ethHdr.h_source[1],
		   packet->ethHdr.h_source[2],
		   packet->ethHdr.h_source[3],
		   packet->ethHdr.h_source[4],
		   packet->ethHdr.h_source[5],
		   Sessions[i].eth[0],
		   Sessions[i].eth[1],
		   Sessions[i].eth[2],
		   Sessions[i].eth[3],
		   Sessions[i].eth[4],
		   Sessions[i].eth[5]);
	    return;
	}
	Sessions[i].flags |= FLAG_RECVD_PADT;
	parsePacket(packet, parseLogErrs, NULL);
	kill(Sessions[i].pid, SIGTERM);
    }
}

/**********************************************************************
*%FUNCTION: processPADR
*%ARGUMENTS:
* ethif -- Ethernet interface
* packet -- PPPoE PADR packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet back to client and starts a PPP session if PADR
* packet is OK.
***********************************************************************/
void
processPADR(Interface *ethif, PPPoEPacket *packet, int len)
{
    unsigned char cookieBuffer[COOKIE_LEN];
    ClientSession *cliSession;
    pid_t child;
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    PPPoETag servname;
    int i;
    int sock = ethif->sock;
    unsigned char *myAddr = ethif->mac;

    /* Initialize some globals */
    relayId.type = 0;
    hostUniq.type = 0;
    receivedCookie.type = 0;
    requestedService.type = 0;

    /* Ignore PADR's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Ignore PADR's from non-unicast addresses */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_ERR, "PADR packet from non-unicast source address");
	return;
    }

    parsePacket(packet, parsePADRTags, NULL);

    /* Check that everything's cool */
    if (!receivedCookie.type) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Is cookie kosher? */
    if (receivedCookie.length != htons(COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookieBuffer);
    if (memcmp(receivedCookie.payload, cookieBuffer, COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Check service name -- we only offer service "" */
    if (!requestedService.type) {
	syslog(LOG_ERR, "Received PADR packet with no SERVICE_NAME tag");
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: No service name tag");
	return;
    }

    if (requestedService.length) {
	syslog(LOG_ERR, "Received PADR packet asking for unsupported service %.*s", (int) ntohs(requestedService.length), requestedService.payload);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: Invalid service name tag");
	return;
    }

#ifdef HAVE_LICENSE
    /* Are we licensed for this many sessions? */
    if (License_NumLicenses("PPPOE-SESSIONS") <= NumActiveSessions) {
	syslog(LOG_ERR, "Insufficient session licenses (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: No session licenses available");
	return;
    }
#endif
    /* Looks cool... find a slot for the session */
    if (!FreeSessions) {
	syslog(LOG_ERR, "No client slots available (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: No client slots available");
	return;
    }

    /* Remove from free sessions list */
    cliSession = FreeSessions;
    if (cliSession == LastFreeSession) {
	LastFreeSession = NULL;
    }
    FreeSessions = cliSession->next;

    /* Put on busy sessions list */
    cliSession->next = BusySessions;
    BusySessions = cliSession;

    /* Set up client session peer Ethernet address */
    memcpy(cliSession->eth, packet->ethHdr.h_source, ETH_ALEN);
    cliSession->ethif = ethif;
    cliSession->flags = 0;

    /* Create child process, send PADS packet back */
    child = fork();
    if (child < 0) {
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: Unable to start session process");
	return;
    }
    if (child != 0) {
	/* In the parent process.  Mark pid in session slot */
	cliSession->pid = child;
	NumActiveSessions++;
	control_session_started(cliSession);
	return;
    }

    /* In the child process.  */

    /* Close all file descriptors except for socket */
    closelog();
    for (i=0; i<CLOSEFD; i++) {
	if (i != sock) {
	    close(i);
	}
    }

    openlog("pppoe-server", LOG_PID, LOG_DAEMON);
    /* pppd has a nasty habit of killing all processes in its process group.
       Start a new session to stop pppd from killing us! */
    setsid();

    /* Send PADS and Start pppd */
    memcpy(pads.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, myAddr, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;
    
    pads.session = cliSession->sess;
    plen = 0;
    
    servname.type = htons(TAG_SERVICE_NAME);
    servname.length = 0;
    
    memcpy(cursor, &servname, TAG_HDR_SIZE);
    cursor += TAG_HDR_SIZE;
    plen += TAG_HDR_SIZE;
    
    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));

    /* Close sock; don't need it any more */
    close(sock);

    startPPPD(cliSession);
}

/**********************************************************************
*%FUNCTION: childHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGCHLD.  Writes one byte to Pipe to wake up the select
* loop and cause reaping of dead sessions
***********************************************************************/
static void
childHandler(int sig)
{
    if (!ReapPending) {
	ReapPending = 1;
	write(Pipe[1], &ReapPending, 1);
    }
}


/**********************************************************************
*%FUNCTION: termHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGTERM or SIGINT.  Causes all sessions to be killed!
***********************************************************************/
static void
termHandler(int sig)
{
    TerminateSignal = sig;
    PleaseTerminate = 1;
    if (!ReapPending) {
	ReapPending = 1;
	write(Pipe[1], &ReapPending, 1);
    }
}

void
setAlarm(unsigned int secs)
{
    struct sigaction act;
    GotAlarm = 0;
    if (!secs) {
	alarm(0);
	/* Clear alarm */
	if (HaveSetAlarm) {
	    HaveSetAlarm = 0;
	    sigaction(SIGALRM, &OldAlarmHandler, NULL);
	}
    } else {
	/* Set alarm */
	if (!HaveSetAlarm) {
	    act.sa_handler = alarmHandler;
	    act.sa_flags = 0;
	    sigaction(SIGALRM, &act, &OldAlarmHandler);
	    HaveSetAlarm = 1;
	}
	alarm(secs);
    }

}

/**********************************************************************
*%FUNCTION: alarmHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGALRM
***********************************************************************/
static void
alarmHandler(int sig)
{
    if (HaveSetAlarm) {
	sigaction(SIGALRM, &OldAlarmHandler, NULL);
	HaveSetAlarm = 0;
    }
    GotAlarm = 1;
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- argv[0] from main
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage instructions
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
#ifdef USE_BPF
    fprintf(stderr, "   -I if_name     -- Specify interface (REQUIRED)\n");
#else
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
	    DEFAULT_IF);
#endif
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds.\n");
    fprintf(stderr, "   -C name        -- Set access concentrator name.\n");
    fprintf(stderr, "   -m MSS         -- Clamp incoming and outgoing MSS options.\n");
    fprintf(stderr, "   -L ip          -- Set local IP address.\n");
    fprintf(stderr, "   -l             -- Increment local IP address for each session.\n");
    fprintf(stderr, "   -R ip          -- Set start address of remote IP pool.\n");
    fprintf(stderr, "   -p fname       -- Optain IP address pool from specified file.\n");
    fprintf(stderr, "   -N num         -- Allow 'num' concurrent sessions.\n");
    fprintf(stderr, "   -o offset      -- Assign session numbers starting at offset+1.\n");
    fprintf(stderr, "   -f disc:sess   -- Set Ethernet frame types (hex).\n");
    fprintf(stderr, "   -s             -- Use synchronous PPP mode.\n");
#ifdef HAVE_LINUX_KERNEL_PPPOE
    fprintf(stderr, "   -k             -- Use kernel-mode PPPoE.\n");
#endif
    fprintf(stderr, "   -u             -- Pass 'unit' option to pppd.\n");
    fprintf(stderr, "   -r             -- Randomize session numbers.\n");
    fprintf(stderr, "   -d             -- Debug session creation.\n");
    fprintf(stderr, "   -P             -- Check pool file for correctness and exit.\n");
    fprintf(stderr, "   -h             -- Print usage information.\n\n");
    fprintf(stderr, "PPPoE-Server Version %s, Copyright (C) 2001 Roaring Penguin Software Inc.\n", VERSION);

#ifndef HAVE_LICENSE
    /* The licensed version of the software is not GPL'd, but is virtually
       the same as the GPL'd version.  I will GPL all licensed features
       within a year of their introduction to the non-GPL'd version, similar
       to the way Ghostscript's licensing scheme worked in the past. */

    fprintf(stderr, "PPPoE-Server comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under the terms of the GNU General Public License, version 2\n");
    fprintf(stderr, "or (at your option) any later version.\n");
#endif
    fprintf(stderr, "http://www.roaringpenguin.com\n");
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- usual suspects
*%RETURNS:
* Exit status
*%DESCRIPTION:
* Main program of PPPoE server
***********************************************************************/
int
main(int argc, char **argv)
{

    FILE *fp;
    int i, j;
    int opt;
    int d[IPV4ALEN];
    int beDaemon = 1;
    int found;
    struct sigaction act;
    int maxFD;
    unsigned int discoveryType, sessionType;
    char *addressPoolFname = NULL;

#ifdef HAVE_LICENSE
    int ctrlfd;
#endif

#ifndef HAVE_LINUX_KERNEL_PPPOE
    char *options = "hI:C:L:R:T:m:FN:f:o:sp:lrudP";
#else
    char *options = "hI:C:L:R:T:m:FN:f:o:skp:lrudP";
#endif

    memset(interfaces, 0, sizeof(interfaces));

    /* Initialize syslog */
    openlog("pppoe-server", LOG_PID, LOG_DAEMON);

    /* Default number of session slots */
    NumSessionSlots = DEFAULT_MAX_SESSIONS;
    NumActiveSessions = 0;

    /* Parse command-line options */
    while((opt = getopt(argc, argv, options)) != -1) {
	switch(opt) {
#ifdef HAVE_LINUX_KERNEL_PPPOE
	case 'k':
	    UseLinuxKernelModePPPoE = 1;
	    break;
#endif
	case 'd':
	    Debug = 1;
	    break;
	case 'P':
	    CheckPoolSyntax = 1;
	    break;
	case 'u':
	    PassUnitOptionToPPPD = 1;
	    break;

	case 'r':
	    RandomizeSessionNumbers = 1;
	    break;

	case 'l':
	    IncrLocalIP = 1;
	    break;

	case 'p':
	    addressPoolFname = optarg;
	    break;

	case 's':
	    Synchronous = 1;
	    /* Pass the Synchronous option on to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -s");
	    break;

	case 'f':
	    if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
		fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
		exit(EXIT_FAILURE);
	    }
	    Eth_PPPOE_Discovery = (UINT16_t) discoveryType;
	    Eth_PPPOE_Session   = (UINT16_t) sessionType;
	    /* This option gets passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'F':
	    beDaemon = 0;
	    break;

	case 'N':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt <= 0) {
		fprintf(stderr, "-N: Value must be positive\n");
		exit(EXIT_FAILURE);
	    }
	    NumSessionSlots = opt;
	    break;

	case 'o':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt < 0) {
		fprintf(stderr, "-o: Value must be non-negative\n");
		exit(EXIT_FAILURE);
	    }
	    SessOffset = (size_t) opt;
	    break;

	case 'I':
	    if (NumInterfaces >= MAX_INTERFACES) {
		fprintf(stderr, "Too many -I options (max %d)\n",
			MAX_INTERFACES);
		exit(EXIT_FAILURE);
	    }
	    found = 0;
	    for (i=0; i<NumInterfaces; i++) {
		if (!strncmp(interfaces[i].name, optarg, IFNAMSIZ)) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		strncpy(interfaces[NumInterfaces].name, optarg, IFNAMSIZ);
		NumInterfaces++;
	    }
	    break;

	case 'C':
	    SET_STRING(ACName, optarg);
	    break;

	case 'L':
	case 'R':
	    /* Get local/remote IP address */
	    if (sscanf(optarg, "%d.%d.%d.%d", &d[0], &d[1], &d[2], &d[3]) != 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    for (i=0; i<IPV4ALEN; i++) {
		if (d[i] < 0 || d[i] > 255) {
		    usage(argv[0]);
		    exit(EXIT_FAILURE);
		}
		if (opt == 'L') {
		    LocalIP[i] = (unsigned char) d[i];
		} else {
		    RemoteIP[i] = (unsigned char) d[i];
		}
	    }
	    break;

	case 'T':
	case 'm':
	    /* These just get passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	}
    }

#ifdef HAVE_LICENSE
    License_ReadFile("/etc/rp/license.txt");
    ServerLicense = License_GetFeature("PPPOE-SERVER");
    if (!ServerLicense) {
	fprintf(stderr, "License: GetFeature failed: %s\n",
		License_ErrorMessage());
	exit(1);
    }
#endif
    
#ifdef USE_LINUX_PACKET
#ifndef HAVE_STRUCT_SOCKADDR_LL
    fprintf(stderr, "The PPPoE server does not work on Linux 2.0 kernels.\n");
    exit(EXIT_FAILURE);
#endif
#endif

    if (!NumInterfaces) {
	strcpy(interfaces[0].name, DEFAULT_IF);
	NumInterfaces = 1;
    }
    
    if (!ACName) {
	ACName = malloc(HOSTNAMELEN);
	if (gethostname(ACName, HOSTNAMELEN) < 0) {
	    fatalSys("gethostname");
	}
    }

    /* If address pool filename given, count number of addresses */
    if (addressPoolFname) {
	NumSessionSlots = parseAddressPool(addressPoolFname, 0);
	if (CheckPoolSyntax) {
	    printf("%d\n", NumSessionSlots);
	    exit(0);
	}
    }

    /* Max 65534 - SessOffset sessions */
    if (NumSessionSlots + SessOffset > 65534) {
	fprintf(stderr, "-N and -o options must add up to at most 65534\n");
	exit(EXIT_FAILURE);
    }

    /* Allocate memory for sessions */
    Sessions = calloc(NumSessionSlots, sizeof(ClientSession));
    if (!Sessions) {
	rp_fatal("Cannot allocate memory for session slots");
    }

    /* Fill in local addresses first (let pool file override later */
    for (i=0; i<NumSessionSlots; i++) {
	memcpy(Sessions[i].myip, LocalIP, sizeof(LocalIP));
	if (IncrLocalIP) {
	    incrementIPAddress(LocalIP);
	}
    }

    /* Fill in remote IP addresses from pool (may also overwrite local ips) */
    if (addressPoolFname) {
	(void) parseAddressPool(addressPoolFname, 1);
    }

    /* For testing -- generate sequential remote IP addresses */
    for (i=0; i<NumSessionSlots; i++) {
	Sessions[i].pid = 0;
	Sessions[i].sess = htons(i+1+SessOffset);

	if (!addressPoolFname) {
	    memcpy(Sessions[i].peerip, RemoteIP, sizeof(RemoteIP));
#ifdef HAVE_LICENSE
	    memcpy(Sessions[i].realpeerip, RemoteIP, sizeof(RemoteIP));
#endif
	    incrementIPAddress(RemoteIP);
	}
    }

    /* Initialize our random cookie.  Try /dev/urandom; if that fails,
       use PID and rand() */
    fp = fopen("/dev/urandom", "r");
    if (fp) {
	unsigned int x;
	fread(&x, 1, sizeof(x), fp);
	srand(x);
	fread(&CookieSeed, 1, SEED_LEN, fp);
	fclose(fp);
    } else {
	srand((unsigned int) getpid() * (unsigned int) time(NULL));
	CookieSeed[0] = getpid() & 0xFF;
	CookieSeed[1] = (getpid() >> 8) & 0xFF;
	for (i=2; i<SEED_LEN; i++) {
	    CookieSeed[i] = (rand() >> (i % 9)) & 0xFF;
	}
    }

    if (RandomizeSessionNumbers) {
	int *permutation;
	int tmp;
	permutation = malloc(sizeof(int) * NumSessionSlots);
	if (!permutation) {
	    fprintf(stderr, "Could not allocate memory to randomize session numbers\n");
	    exit(EXIT_FAILURE);
	}
	for (i=0; i<NumSessionSlots; i++) {
	    permutation[i] = i;
	}
	for (i=0; i<NumSessionSlots-1; i++) {
	    j = i + rand() % (NumSessionSlots - i);
	    if (j != i) {
		tmp = permutation[j];
		permutation[j] = permutation[i];
		permutation[i] = tmp;
	    }
	}
	/* Link sessions together */
	FreeSessions = &Sessions[permutation[0]];
	LastFreeSession = &Sessions[permutation[NumSessionSlots-1]];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[permutation[i]].next = &Sessions[permutation[i+1]];
	}
	Sessions[permutation[NumSessionSlots-1]].next = NULL;
	free(permutation);
    } else {
	/* Link sessions together */
	FreeSessions = &Sessions[0];
	LastFreeSession = &Sessions[NumSessionSlots - 1];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[i].next = &Sessions[i+1];
	}
	Sessions[NumSessionSlots-1].next = NULL;
    }

    if (Debug) {
	/* Dump session array and exit */
	ClientSession *ses = FreeSessions;
	while(ses) {
	    printf("Session %d local %d.%d.%d.%d remote %d.%d.%d.%d\n",
		   ntohs(ses->sess),
		   ses->myip[0], ses->myip[1],
		   ses->myip[2], ses->myip[3],
		   ses->peerip[0], ses->peerip[1],
		   ses->peerip[2], ses->peerip[3]);
	    ses = ses->next;
	}
	exit(0);
    }

    /* Open all the interfaces */
    for (i=0; i<NumInterfaces; i++) {
	interfaces[i].sock = openInterface(interfaces[i].name, Eth_PPPOE_Discovery, interfaces[i].mac);
    }

    /* Daemonize -- UNIX Network Programming, Vol. 1, Stevens */
    if (beDaemon) {
	i = fork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    /* parent */
	    exit(EXIT_SUCCESS);
	}
	setsid();
	signal(SIGHUP, SIG_IGN);
	i = fork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}

	chdir("/");
	closelog();
	for (i=0; i<CLOSEFD; i++) {
	    if (!sockInUse(i)) {
		close(i);
	    }
	}
	/* We nuked our syslog descriptor... */
	openlog("pppoe-server", LOG_PID, LOG_DAEMON);
    }

    /* Set signal handler for SIGCHLD */
    act.sa_handler = childHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &act, NULL) < 0) {
	fatalSys("sigaction");
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* Set signal handlers for SIGTERM and SIGINT */
    act.sa_handler = termHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &act, NULL) < 0 ||
	sigaction(SIGINT, &act, NULL) < 0) {
	fatalSys("sigaction");
    }

    /* Set up pipe for signal handler */
    if (pipe(Pipe) < 0) {
	fatalSys("pipe");
    }

    /* Control channel */
#ifdef HAVE_LICENSE
    control_init(argc, argv);
    ctrlfd = control_getfd();
#endif

    /* Main server loop */
    maxFD = Pipe[0];
    for (i = 0; i<NumInterfaces; i++) {
	if (interfaces[i].sock > maxFD) maxFD = interfaces[i].sock;
    }
#ifdef HAVE_LICENSE
    if (ctrlfd > maxFD) maxFD = ctrlfd;
#endif
    maxFD++;

    for(;;) {
	fd_set readable;
	FD_ZERO(&readable);
#ifdef HAVE_LICENSE
	if (ctrlfd >= 0) {
	    FD_SET(ctrlfd, &readable);
	}
#endif
	for (i=0; i<NumInterfaces; i++) {
	    FD_SET(interfaces[i].sock, &readable);
	}
	FD_SET(Pipe[0], &readable);

	while(1) {
	    i = select(maxFD, &readable, NULL, NULL, NULL);
	    if (i >= 0 || errno != EINTR) break;
	}

	if (PleaseTerminate) {
	    syslog(LOG_INFO, "Terminating on signal %d -- killing all PPPoE sessions", TerminateSignal);
	    killAllSessions();
	    control_exit();
	    exit(0);
	}

	if (i < 0) {
	    fatalSys("select");
	}

#ifdef HAVE_LICENSE
	if (License_Expired(ServerLicense)) {
	    syslog(LOG_INFO, "Server license has expired -- killing all PPPoE sessions");
	    killAllSessions();
	    control_exit();
	    exit(0);
	}
#endif

	if (FD_ISSET(Pipe[0], &readable)) {
	    /* Clear pipe */
	    char buf[SMALLBUF];
	    read(Pipe[0], buf, SMALLBUF);
	}

	if (ReapPending) {
	    reapFinishedSessions();
	    ReapPending = 0;
	}
	for (i=0; i<NumInterfaces; i++) {
	    if (FD_ISSET(interfaces[i].sock, &readable)) {
		processPacket(&interfaces[i]);
	    }
	}
#ifdef HAVE_LICENSE
	if (ctrlfd >= 0 && FD_ISSET(ctrlfd, &readable)) {
	    control_readable();
	}
#endif
    }
    return 0;
}

static void
processPacket(Interface *i)
{
    int len;
    PPPoEPacket packet;
    int sock = i->sock;

    if (receivePacket(sock, &packet, &len) < 0) {
	return;
    }
	
    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	syslog(LOG_ERR, "Bogus PPPoE length field (%u)",
	       (unsigned int) ntohs(packet.length));
	return;
    }

    /* Sanity check on packet */
    if (packet.ver != 1 || packet.type != 1) {
	/* Syslog an error */
	return;
    }
    switch(packet.code) {
    case CODE_PADI:
	processPADI(i, &packet, len);
	break;
    case CODE_PADR:
	processPADR(i, &packet, len);
	break;
    case CODE_PADT:
	/* Kill the child */
	processPADT(i, &packet, len);
	break;
    case CODE_SESS:
	/* Ignore SESS -- children will handle them */
	break;
    case CODE_PADO:
    case CODE_PADS:
	/* Ignore PADO and PADS totally */
	break;
    default:
	/* Syslog an error */
	break;
    }
}

/**********************************************************************
*%FUNCTION: sendErrorPADS
*%ARGUMENTS:
* sock -- socket to write to
* source -- source Ethernet address
* dest -- destination Ethernet address
* errorTag -- error tag
* errorMsg -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet with an error message
***********************************************************************/
void
sendErrorPADS(int sock,
	      unsigned char *source,
	      unsigned char *dest,
	      int errorTag,
	      char *errorMsg)
{
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    PPPoETag err;
    int elen = strlen(errorMsg);

    memcpy(pads.ethHdr.h_dest, dest, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, source, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;
    
    pads.session = htons(0);
    plen = 0;
    
    err.type = htons(errorTag);
    err.length = htons(elen);
    
    memcpy(err.payload, errorMsg, elen);
    memcpy(cursor, &err, TAG_HDR_SIZE+elen);
    cursor += TAG_HDR_SIZE + elen;
    plen += TAG_HDR_SIZE + elen;
    
    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));
}
	      

/**********************************************************************
*%FUNCTION: startPPPDUserMode
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for user-mode PPPoE
***********************************************************************/
void
startPPPDUserMode(ClientSession *session)
{
    /* Leave some room */
    char *argv[32];

    char buffer[SMALLBUF];

    int c = 0;

    argv[c++] = "pppd";
    argv[c++] = "pty";

    snprintf(buffer, SMALLBUF, "%s -n -I %s -e %d:%02x:%02x:%02x:%02x:%02x:%02x%s",
	     PPPOE_PATH, session->ethif->name,
	     ntohs(session->sess),
	     session->eth[0], session->eth[1], session->eth[2],
	     session->eth[3], session->eth[4], session->eth[5],
	     PppoeOptions);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }

    argv[c++] = "file";
    argv[c++] = PPPOE_SERVER_OPTIONS;

    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d:%d.%d.%d.%d",
	    (int) session->myip[0], (int) session->myip[1],
	    (int) session->myip[2], (int) session->myip[3],
	    (int) session->peerip[0], (int) session->peerip[1],
	    (int) session->peerip[2], (int) session->peerip[3]);
    syslog(LOG_INFO,
	   "Session %d created for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s",
	   ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
    argv[c++] = "nodetach";
    argv[c++] = "noaccomp";
    argv[c++] = "nobsdcomp";
    argv[c++] = "nodeflate";
    argv[c++] = "nopcomp";
    argv[c++] = "novj";
    argv[c++] = "novjccomp";
    argv[c++] = "default-asyncmap";
    if (Synchronous) {
	argv[c++] = "sync";
    }
    if (PassUnitOptionToPPPD) {
	argv[c++] = "unit";
	sprintf(buffer, "%d", ntohs(session->sess) - 1 - SessOffset);
	argv[c++] = buffer;
    }
    argv[c++] = NULL;

    execv(PPPD_PATH, argv);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: startPPPDLinuxKernelMode
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for kernel-mode PPPoE on Linux
***********************************************************************/
void
startPPPDLinuxKernelMode(ClientSession *session)
{
    /* Leave some room */
    char *argv[32];

    int c = 0;

    char buffer[SMALLBUF];

    argv[c++] = "pppd";
    argv[c++] = "plugin";
    argv[c++] = PLUGIN_PATH;
    argv[c++] = session->ethif->name;
    snprintf(buffer, SMALLBUF, "%d:%02x:%02x:%02x:%02x:%02x:%02x",
	     ntohs(session->sess),
	     session->eth[0], session->eth[1], session->eth[2],
	     session->eth[3], session->eth[4], session->eth[5]);
    argv[c++] = "rp_pppoe_sess";
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
    argv[c++] = "file";
    argv[c++] = PPPOE_SERVER_OPTIONS;

    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d:%d.%d.%d.%d",
	    (int) session->myip[0], (int) session->myip[1],
	    (int) session->myip[2], (int) session->myip[3],
	    (int) session->peerip[0], (int) session->peerip[1],
	    (int) session->peerip[2], (int) session->peerip[3]);
    syslog(LOG_INFO,
	   "Session %d created for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s",
	   ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
    argv[c++] = "nodetach";
    argv[c++] = "noaccomp";
    argv[c++] = "nobsdcomp";
    argv[c++] = "nodeflate";
    argv[c++] = "nopcomp";
    argv[c++] = "novj";
    argv[c++] = "novjccomp";
    argv[c++] = "default-asyncmap";
    if (PassUnitOptionToPPPD) {
	argv[c++] = "unit";
	sprintf(buffer, "%d", ntohs(session->sess) - 1 - SessOffset);
	argv[c++] = buffer;
    }
    argv[c++] = NULL;
    execv(PPPD_PATH, argv);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: startPPPD
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD
***********************************************************************/
void
startPPPD(ClientSession *session)
{
    if (UseLinuxKernelModePPPoE) startPPPDLinuxKernelMode(session);
    else startPPPDUserMode(session);
}

