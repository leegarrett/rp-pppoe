/**********************************************************************
*
* pppoe-server.h
*
* Definitions for PPPoE server
*
* Copyright (C) 2001 Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id: pppoe-server.h,v 1.8 2001/07/05 13:43:22 dfs Exp $
*
***********************************************************************/

#include "pppoe.h"

#define MAX_USERNAME_LEN 31
/* An Ethernet interface */
typedef struct {
    char name[IFNAMSIZ+1];	/* Interface name */
    int sock;			/* Socket for discovery frames */
    unsigned char mac[ETH_ALEN]; /* MAC address */
} Interface;

#define FLAG_RECVD_PADT      1
#define FLAG_USER_SET        2
#define FLAG_IP_SET          4

/* A client session */
typedef struct ClientSessionStruct {
    struct ClientSessionStruct *next; /* In list of free or active sessions */
    pid_t pid;			/* PID of child handling session */
    Interface *ethif;		/* Ethernet interface */
    unsigned char myip[IPV4ALEN]; /* Local IP address */
    unsigned char peerip[IPV4ALEN];	/* Desired IP address of peer */
    UINT16_t sess;		/* Session number */
    unsigned char eth[ETH_ALEN]; /* Peer's Ethernet address */
    int flags;			/* Various flags */
#ifdef HAVE_LICENSE
    char user[MAX_USERNAME_LEN+1]; /* Authenticated user-name */
    unsigned char realpeerip[IPV4ALEN]; /* Actual IP address -- may be assigned
					   by RADIUS server */
#endif
} ClientSession;

/* Hack for daemonizing */
#define CLOSEFD 64

/* Max. number of interfaces to listen on */
#define MAX_INTERFACES 64

/* Max. 64 sessions by default */
#define DEFAULT_MAX_SESSIONS 64

/* An array of client sessions */
extern ClientSession *Sessions;

/* Interfaces we're listening on */
extern Interface interfaces[MAX_INTERFACES];
extern int NumInterfaces;

/* The number of session slots */
extern size_t NumSessionSlots;

/* The number of active sessions */
extern size_t NumActiveSessions;

/* Offset of first session */
extern size_t SessOffset;

/* Access concentrator name */
extern char *ACName;

extern unsigned char LocalIP[IPV4ALEN];
extern unsigned char RemoteIP[IPV4ALEN];

/* Do we increment local IP for each connection? */
extern int IncrLocalIP;

/* Free sessions */
extern ClientSession *FreeSessions;

/* When a session is freed, it is added to the end of the free list */
extern ClientSession *LastFreeSession;

/* Busy sessions */
extern ClientSession *BusySessions;

extern int GotAlarm;

extern void setAlarm(unsigned int secs);
extern void killAllSessions(void);
extern void reapSessions(int nohang);

#define reapFinishedSessions() reapSessions(1)
#define reapAllSessions() reapSessions(0)
