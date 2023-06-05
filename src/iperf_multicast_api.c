/*---------------------------------------------------------------
 * Copyright (c) 2023
 * Broadcom Corporation
 * All Rights Reserved.
 *---------------------------------------------------------------
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 *
 * Redistributions of source code must retain the above
 * copyright notice, this list of conditions and
 * the following disclaimers.
 *
 *
 * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimers in the documentation and/or other materials
 * provided with the distribution.
 *
 *
 * Neither the name of Broadcom Coporation,
 * nor the names of its contributors may be used to endorse
 * or promote products derived from this Software without
 * specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE CONTIBUTORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ________________________________________________________________
 *
 * iperf_multicast_api.c
 * pull iperf multicast code for maitainability
 *
 * by Robert J. McMahon (rjmcmahon@rjmcmahon.com, bob.mcmahon@broadcom.com)
 *
 *
 * Joins the multicast group or source and group (SSM S,G)
 *
 * taken from: https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.1.0/com.ibm.zos.v2r1.hale001/ipv6d0141001708.htm
 *
 * Multicast function	                                        IPv4	                   IPv6	                Protocol-independent
 * ==================                                           ====                       ====                 ====================
 * Level of specified option on setsockopt()/getsockopt()	IPPROTO_IP	           IPPROTO_IPV6	IPPROTO_IP or IPPROTO_IPV6
 * Join a multicast group	                                IP_ADD_MEMBERSHIP          IPV6_JOIN_GROUP	MCAST_JOIN_GROUP
 * Leave a multicast group or leave all sources of that
 *   multicast group	                                        IP_DROP_MEMBERSHIP	   IPV6_LEAVE_GROUP	MCAST_LEAVE_GROUP
 * Select outbound interface for sending multicast datagrams	IP_MULTICAST_IF	           IPV6_MULTICAST_IF	NA
 * Set maximum hop count	                                IP_MULTICAST_TTL	   IPV6_MULTICAST_HOPS	NA
 * Enable multicast loopback	                                IP_MULTICAST_LOOP	   IPV6_MULTICAST_LOOP	NA
 * Join a source multicast group	                        IP_ADD_SOURCE_MEMBERSHIP   NA	                MCAST_JOIN_SOURCE_GROUP
 * Leave a source multicast group	                        IP_DROP_SOURCE_MEMBERSHIP  NA	                MCAST_LEAVE_SOURCE_GROUP
 * Block data from a source to a multicast group	        IP_BLOCK_SOURCE   	   NA	                MCAST_BLOCK_SOURCE
 * Unblock a previously blocked source for a multicast group	IP_UNBLOCK_SOURCE	   NA	                MCAST_UNBLOCK_SOURCE
 *
 *
 * Reminder:  The os will decide which version of IGMP or MLD to use.   This may be controlled by system settings, e.g.:
 *
 * [rmcmahon@lvnvdb0987:~/Code/ssm/iperf2-code] $ sysctl -a | grep mld | grep force
 * net.ipv6.conf.all.force_mld_version = 0
 * net.ipv6.conf.default.force_mld_version = 0
 * net.ipv6.conf.lo.force_mld_version = 0
 * net.ipv6.conf.eth0.force_mld_version = 0
 *
 * [rmcmahon@lvnvdb0987:~/Code/ssm/iperf2-code] $ sysctl -a | grep igmp | grep force
 * net.ipv4.conf.all.force_igmp_version = 0
 * net.ipv4.conf.default.force_igmp_version = 0
 * net.ipv4.conf.lo.force_igmp_version = 0
 * net.ipv4.conf.eth0.force_igmp_version = 0
 *
 * ------------------------------------------------------------------- */
#include "headers.h"
#include "Settings.hpp"
#include "iperf_multicast_api.h"
#include "SocketAddr.h"
#include "util.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

static unsigned int mcast_iface (struct thread_Settings *inSettings) {
    unsigned int iface=0;
    /* Set the interface or any */
    if (inSettings->mIfrname) {
#if HAVE_NET_IF_H
	iface = if_nametoindex(inSettings->mIfrname);
	FAIL_errno(!iface, "mcast if_nametoindex", inSettings);
#else
	fprintf(stderr, "multicast bind to device not supported on this platform\n");
#endif
    }
    return iface;
}


// IP_MULTICAST_ALL is on be default, disable it here.
// If set to 1, the socket will receive messages from all the groups that have been joined
// globally on the whole system.  Otherwise, it will deliver messages only from the
// groups that have been explicitly joined (for example via the IP_ADD_MEMBERSHIP option)
// on this particular socket.
#if SUPPORT_MULTICAST_ALL
static int iperf_multicast_all_disable (struct thread_Settings *inSettings) {
    int rc = 0;
#if HAVE_DECL_IP_MULTICAST_ALL
    int mc_all = 0;
    rc = setsockopt(inSettings->mSock, IPPROTO_IP, IP_MULTICAST_ALL, (void*) &mc_all, sizeof(mc_all));
    FAIL_errno(rc == SOCKET_ERROR, "ip_multicast_all", inSettings);
#endif
    return rc;
}
#endif

// This is the older mulitcast join code. Both SSM and binding the
// an interface requires the newer socket options.  Using the older
// code here will maintain compatiblity with previous iperf versions
static int iperf_multicast_join_v4_legacy (struct thread_Settings *inSettings) {
#if HAVE_DECL_IP_ADD_MEMBERSHIP
    struct ip_mreq mreq;
    memcpy(&mreq.imr_multiaddr, SockAddr_get_in_addr(&inSettings->local), sizeof(mreq.imr_multiaddr));
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    int rc = setsockopt(inSettings->mSock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			(char*)(&mreq), sizeof(mreq));
    FAIL_errno(rc == SOCKET_ERROR, "multicast join", inSettings);
#if SUPPORT_MULTICAST_ALL
    iperf_multicast_all_disable(inSettings);
#endif
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
}

static int iperf_multicast_join_v4_pi (struct thread_Settings *inSettings) {
#if HAVE_DECL_MCAST_JOIN_GROUP
    int rc;
    socklen_t socklen = sizeof(struct sockaddr_storage);
    struct group_req group_req;
    struct sockaddr_in *group;

    memset(&group_req, 0, sizeof(struct group_req));

    group_req.gr_interface = mcast_iface(inSettings);
    group=(struct sockaddr_in *)(&group_req.gr_group);
    group->sin_family = AF_INET;
    /* Set the group */
    rc=getsockname(inSettings->mSock,(struct sockaddr *)(group), &socklen);
    FAIL_errno(rc == SOCKET_ERROR, "mcast join group getsockname", inSettings);
    group->sin_port = 0;    /* Ignored */
    rc = setsockopt(inSettings->mSock, IPPROTO_IP, MCAST_JOIN_GROUP, \
		    (const char *)(&group_req), sizeof(struct group_source_req));
    FAIL_errno(rc == SOCKET_ERROR, "mcast join group", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
    return rc;
}


static int iperf_multicast_join_v6 (struct thread_Settings *inSettings) {
#if (HAVE_DECL_IPV6_JOIN_GROUP || HAVE_DECL_IPV6_ADD_MEMBERSHIP)
    struct ipv6_mreq mreq;
    memcpy(&mreq.ipv6mr_multiaddr, SockAddr_get_in6_addr(&inSettings->local), sizeof(mreq.ipv6mr_multiaddr));
    mreq.ipv6mr_interface = mcast_iface(inSettings);
#if HAVE_DECL_IPV6_JOIN_GROUP
    int rc = setsockopt(inSettings->mSock, IPPROTO_IPV6, IPV6_JOIN_GROUP, \
			(char*)(&mreq), sizeof(mreq));
#else
    int rc = setsockopt(inSettings->mSock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, \
			(char*)(&mreq), sizeof(mreq));
#endif
    FAIL_errno(rc == SOCKET_ERROR, "multicast v6 join", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
}

static int iperf_multicast_join_v6_pi (struct thread_Settings *inSettings) {
#if HAVE_DECL_MCAST_JOIN_GROUP
    int rc;
    socklen_t socklen = sizeof(struct sockaddr_storage);
    struct group_req group_req;
    struct sockaddr_in6 *group;

    memset(&group_req, 0, sizeof(struct group_req));

    group_req.gr_interface = mcast_iface(inSettings);
    group=(struct sockaddr_in6*)(&group_req.gr_group);
    group->sin6_family = AF_INET6;
    /* Set the group */
    rc=getsockname(inSettings->mSock,(struct sockaddr *)(group), &socklen);
    FAIL_errno(rc == SOCKET_ERROR, "mcast v6 join group getsockname", inSettings);
    group->sin6_port = 0;    /* Ignored */
    rc = -1;
    rc = setsockopt(inSettings->mSock, IPPROTO_IPV6, MCAST_JOIN_GROUP, (const char *)(&group_req),
		    sizeof(struct group_source_req));
    FAIL_errno(rc == SOCKET_ERROR, "mcast v6 join group", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
}


static int iperf_multicast_ssm_join_v4 (struct thread_Settings *inSettings) {
#if HAVE_SSM_MULTICAST
    int rc;
    struct sockaddr_in *group;
    struct sockaddr_in *source;

    // Fill out both structures because we don't which one will succeed
    // and both may need to be tried
#if HAVE_STRUCT_IP_MREQ_SOURCE
    struct ip_mreq_source imr;
    memset (&imr, 0, sizeof (imr));
#endif
#if HAVE_STRUCT_GROUP_SOURCE_REQ
    struct group_source_req group_source_req;
    memset(&group_source_req, 0, sizeof(struct group_source_req));
    group_source_req.gsr_interface = mcast_iface(inSettings);
    group=(struct sockaddr_in *)(&group_source_req.gsr_group);
    source=(struct sockaddr_in *)(&group_source_req.gsr_source);
#else
    struct sockaddr_in imrgroup;
    struct sockaddr_in imrsource;
    group = &imrgroup;
    source = &imrsource;
#endif
    source->sin_family = AF_INET;
    group->sin_family = AF_INET;
    /* Set the group */
    socklen_t socklen = sizeof(struct sockaddr_storage);
    rc=getsockname(inSettings->mSock,(struct sockaddr *)(group), &socklen);
    FAIL_errno(rc == SOCKET_ERROR, "mcast join source group getsockname", inSettings);
    group->sin_port = 0;    /* Ignored */

    /* Set the source, apply the S,G */
    rc=inet_pton(AF_INET,inSettings->mSSMMulticastStr,&source->sin_addr);
    FAIL_errno(rc != 1, "mcast join source pton", inSettings);
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    source->sin_len = group->sin_len;
#endif
    source->sin_port = 0;    /* Ignored */
    rc = -1;

#if HAVE_DECL_MCAST_JOIN_SOURCE_GROUP
    rc = setsockopt(inSettings->mSock,IPPROTO_IP,MCAST_JOIN_SOURCE_GROUP, (const char *)(&group_source_req),
		    sizeof(struct group_source_req));
#endif

#if (HAVE_DECL_IP_ADD_SOURCE_MEMBERSHIP && HAVE_STRUCT_IP_MREQ_SOURCE)
    // Some operating systems will have MCAST_JOIN_SOURCE_GROUP but still fail
    // In those cases try the IP_ADD_SOURCE_MEMBERSHIP
    if (rc < 0) {
#if HAVE_STRUCT_IP_MREQ_SOURCE_IMR_MULTIADDR_S_ADDR
	imr.imr_multiaddr = ((const struct sockaddr_in *)group)->sin_addr;
	imr.imr_sourceaddr = ((const struct sockaddr_in *)source)->sin_addr;
#else
	// Some Android versions declare mreq_source without an s_addr
	imr.imr_multiaddr = ((const struct sockaddr_in *)group)->sin_addr.s_addr;
	imr.imr_sourceaddr = ((const struct sockaddr_in *)source)->sin_addr.s_addr;
#endif
	rc = setsockopt (inSettings->mSock, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, (char*)(&imr), sizeof (imr));
    }
#endif
    FAIL_errno(rc == SOCKET_ERROR, "mcast v4 join ssm", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
}

static int iperf_multicast_ssm_join_v6 (struct thread_Settings *inSettings) {
#if (HAVE_IPV6_MULTICAST && HAVE_SSM_MULTICAST && HAVE_DECL_MCAST_JOIN_SOURCE_GROUP)
    int rc;

    // Here it's either an SSM S,G multicast join or a *,G with an interface specifier
    // Use the newer socket options when these are specified
    socklen_t socklen = sizeof(struct sockaddr_storage);
    struct group_source_req group_source_req;
    struct sockaddr_in6 *group;
    struct sockaddr_in6 *source;

    memset(&group_source_req, 0, sizeof(struct group_source_req));

    group_source_req.gsr_interface = mcast_iface(inSettings);
    group=(struct sockaddr_in6*)(&group_source_req.gsr_group);
    source=(struct sockaddr_in6*)(&group_source_req.gsr_source);
    source->sin6_family = AF_INET6;
    group->sin6_family = AF_INET6;
    /* Set the group */
    rc=getsockname(inSettings->mSock,(struct sockaddr *)(group), &socklen);
    FAIL_errno(rc == SOCKET_ERROR, "mcast join source group getsockname", inSettings);
    group->sin6_port = 0;    /* Ignored */

    /* Set the source, apply the S,G */
    rc=inet_pton(AF_INET6, inSettings->mSSMMulticastStr,&source->sin6_addr);
    FAIL_errno(rc != 1, "mcast v6 join source group pton", inSettings);
    source->sin6_port = 0;    /* Ignored */
#if HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    source->sin6_len = group->sin6_len;
#endif
    rc = setsockopt(inSettings->mSock,IPPROTO_IPV6,MCAST_JOIN_SOURCE_GROUP, (const char *)(&group_source_req),
		    sizeof(struct group_source_req));
    FAIL_errno(rc == SOCKET_ERROR, "mcast v6 join source group", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_JOIN_SUCCESS : IPERF_MULTICAST_JOIN_FAIL);
#else
    return IPERF_MULTICAST_JOIN_UNSUPPORTED;
#endif
}

int iperf_multicast_join (struct thread_Settings *inSettings) {
    int rc = IPERF_MULTICAST_JOIN_FAIL;
    if (!isSSMMulticast(inSettings)) {
	// *.G join
	if (!SockAddr_isIPv6(&inSettings->local)) {
	    rc = iperf_multicast_join_v4_legacy(inSettings);
	    if (rc != IPERF_MULTICAST_JOIN_SUCCESS) {
		rc = iperf_multicast_join_v4_pi(inSettings);
	    }
	} else {
	    rc = iperf_multicast_join_v6_pi(inSettings);
	    if (rc != IPERF_MULTICAST_JOIN_SUCCESS) {
		rc = iperf_multicast_join_v6(inSettings);
	    }
	}
    } else {
	// SSM or S,G join
	if (!SockAddr_isIPv6(&inSettings->local)) {
	    rc = iperf_multicast_ssm_join_v4(inSettings);
	} else {
	    rc = iperf_multicast_ssm_join_v6(inSettings);
	}
    }
    return rc;
}


int iperf_multicast_sendif_v4 (struct thread_Settings *inSettings) {
    int rc = IPERF_MULTICAST_SENDIF_FAIL;
#if HAVE_DECL_IP_MULTICAST_IF
    struct in_addr interface_addr;
    memcpy(&interface_addr, SockAddr_get_in_addr(&inSettings->local), sizeof(interface_addr));
    rc = setsockopt(inSettings->mSock, IPPROTO_IP, IP_MULTICAST_IF,
			(char*)(&interface_addr), sizeof(interface_addr));
    FAIL_errno(rc == SOCKET_ERROR, "v4 multicast if", inSettings);
    return ((rc == 0) ? IPERF_MULTICAST_SENDIF_SUCCESS : IPERF_MULTICAST_SENDIF_FAIL);
#endif
    return rc;
}

int iperf_multicast_sendif_v6 (struct thread_Settings *inSettings) {
    int rc = IPERF_MULTICAST_SENDIF_FAIL;
#if HAVE_DECL_IPV6_MULTICAST_IF
    if (inSettings->mIfrnametx) {
	unsigned int ifindex = if_nametoindex(inSettings->mIfrnametx);
	if (ifindex) {
	    rc = setsockopt(inSettings->mSock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
	    if (rc == 0) {
		rc = IPERF_MULTICAST_SENDIF_SUCCESS;
	    }
	}
    }
#endif
    return rc;
}
