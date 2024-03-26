/*---------------------------------------------------------------
 * Copyright (c) 2020
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
 * reporter output routines
 *
 * by Robert J. McMahon (rjmcmahon@rjmcmahon.com, bob.mcmahon@broadcom.com)
 * -------------------------------------------------------------------
 */
#include <math.h>
#include "headers.h"
#include "Settings.hpp"
#include "Reporter.h"
#include "Locale.h"
#include "SocketAddr.h"
#include "iperf_formattime.h"
#include "dscp.h"

// These static variables are not thread safe but ok to use becase only
// the repoter thread usses them
#define SNBUFFERSIZE 512
#define SNBUFFEREXTENDSIZE 512
static char outbuffer[SNBUFFERSIZE]; // Buffer for printing
static char outbufferext[SNBUFFEREXTENDSIZE]; // Buffer for printing

#define LLAWBUFSIZE 100
static char netpower_buf[100];

static int HEADING_FLAG(report_bw) = 0;
static int HEADING_FLAG(report_client_bb_bw) = 0;
static int HEADING_FLAG(report_bw_jitter_loss) = 0;
static int HEADING_FLAG(report_bw_read_enhanced) = 0;
static int HEADING_FLAG(report_bw_read_enhanced_netpwr) = 0;
static int HEADING_FLAG(report_bw_write_enhanced) = 0;
static int HEADING_FLAG(report_bw_write_enhanced_fq) = 0;
static int HEADING_FLAG(report_write_enhanced_write) = 0;
static int HEADING_FLAG(report_bw_write_enhanced_netpwr) = 0;
static int HEADING_FLAG(report_bw_pps_enhanced) = 0;
static int HEADING_FLAG(report_bw_pps_enhanced_isoch) = 0;
static int HEADING_FLAG(report_bw_jitter_loss_pps) = 0;
static int HEADING_FLAG(report_bw_jitter_loss_enhanced) = 0;
static int HEADING_FLAG(report_bw_jitter_loss_enhanced_isoch) = 0;
static int HEADING_FLAG(report_write_enhanced_isoch) = 0;
static int HEADING_FLAG(report_frame_jitter_loss_enhanced) = 0;
static int HEADING_FLAG(report_frame_tcp_enhanced) = 0;
static int HEADING_FLAG(report_frame_read_tcp_enhanced_triptime) = 0;
static int HEADING_FLAG(report_udp_fullduplex) = 0;
static int HEADING_FLAG(report_sumcnt_bw) = 0;
static int HEADING_FLAG(report_sumcnt_bw_read_enhanced) = 0;
static int HEADING_FLAG(report_sumcnt_bw_read_triptime) = 0;
static int HEADING_FLAG(report_sumcnt_bw_write_enhanced) = 0;
static int HEADING_FLAG(report_sumcnt_bw_pps_enhanced) = 0;
static int HEADING_FLAG(report_bw_jitter_loss_enhanced_triptime) = 0;
static int HEADING_FLAG(report_bw_jitter_loss_enhanced_isoch_triptime) = 0;
static int HEADING_FLAG(report_sumcnt_bw_jitter_loss) = 0;
static int HEADING_FLAG(report_burst_read_tcp) = 0;
static int HEADING_FLAG(report_burst_write_tcp) = 0;
static int HEADING_FLAG(report_bw_isoch_enhanced_netpwr) = 0;
static int HEADING_FLAG(report_sumcnt_udp_enhanced) = 0;
static int HEADING_FLAG(report_sumcnt_udp_triptime) = 0;
static int HEADING_FLAG(reportCSV_bw_read_enhanced) = 0;
static int HEADING_FLAG(reportCSV_bw_write_enhanced) = 0;
static int HEADING_FLAG(reportCSV_bw_jitter_loss_pps) = 0;
static int HEADING_FLAG(reportCSV_client_bb_bw_tcp) = 0;

void reporter_default_heading_flags (int flag) {
    HEADING_FLAG(report_bw) = flag;
    HEADING_FLAG(report_client_bb_bw) = flag;
    HEADING_FLAG(report_sumcnt_bw) = flag;
    HEADING_FLAG(report_bw_jitter_loss) = flag;
    HEADING_FLAG(report_bw_read_enhanced) = flag;
    HEADING_FLAG(report_bw_read_enhanced_netpwr) = flag;
    HEADING_FLAG(report_bw_write_enhanced) = flag;
    HEADING_FLAG(report_bw_write_enhanced_fq) = flag;
    HEADING_FLAG(report_write_enhanced_write) = flag;
    HEADING_FLAG(report_write_enhanced_isoch) = flag;
    HEADING_FLAG(report_bw_write_enhanced_netpwr) = flag;
    HEADING_FLAG(report_bw_pps_enhanced) = flag;
    HEADING_FLAG(report_bw_pps_enhanced_isoch) = flag;
    HEADING_FLAG(report_bw_jitter_loss_pps) = flag;
    HEADING_FLAG(report_bw_jitter_loss_enhanced) = flag;
    HEADING_FLAG(report_bw_jitter_loss_enhanced_isoch) = flag;
    HEADING_FLAG(report_frame_jitter_loss_enhanced) = flag;
    HEADING_FLAG(report_frame_tcp_enhanced) = flag;
    HEADING_FLAG(report_frame_read_tcp_enhanced_triptime) = flag;
    HEADING_FLAG(report_sumcnt_bw_read_enhanced) = flag;
    HEADING_FLAG(report_sumcnt_bw_read_triptime) = flag;
    HEADING_FLAG(report_sumcnt_bw_write_enhanced) = flag;
    HEADING_FLAG(report_udp_fullduplex) = flag;
    HEADING_FLAG(report_sumcnt_bw_jitter_loss) = flag;
    HEADING_FLAG(report_sumcnt_bw_pps_enhanced) = flag;
    HEADING_FLAG(report_burst_read_tcp) = flag;
    HEADING_FLAG(report_burst_write_tcp) = flag;
    HEADING_FLAG(report_bw_isoch_enhanced_netpwr) = flag;
    HEADING_FLAG(report_sumcnt_udp_enhanced) = flag;
    HEADING_FLAG(report_sumcnt_udp_triptime) = flag;
    HEADING_FLAG(reportCSV_bw_read_enhanced) = 0;
    HEADING_FLAG(reportCSV_bw_write_enhanced) = 0;
    HEADING_FLAG(reportCSV_bw_jitter_loss_pps) = 0;
    HEADING_FLAG(reportCSV_client_bb_bw_tcp) = 0;
}

//
// flush when
//
// o) it's a final report
// o) this is the sum report (all preceding interval reports need flush)
// o) below the flush rate limiter
//
#define FLUSH_RATE_LIMITER 1000 //units is microseconds
static inline void cond_flush (struct TransferInfo *stats) {
    static struct timeval prev={0,0};
    struct timeval now;
    TimeGetNow(now);
    if (stats->final || (stats->type == SUM_REPORT) || !(TimeDifferenceUsec(now, prev) < FLUSH_RATE_LIMITER)) {
	fflush(stdout);
	prev = now;
    }
}

static inline void _print_stats_common (struct TransferInfo *stats) {
    assert(stats!=NULL);
    outbuffer[0] = '\0';
    outbufferext[0] = '\0';
    byte_snprintf(outbuffer, sizeof(outbuffer), (double) stats->cntBytes, toupper((int)stats->common->Format));
    if (stats->ts.iEnd < SMALLEST_INTERVAL_SEC) {
        stats->cntBytes = 0;
    }
    byte_snprintf(outbufferext, sizeof(outbufferext), (double)stats->cntBytes / (stats->ts.iEnd - stats->ts.iStart), \
		  stats->common->Format);
    outbuffer[sizeof(outbuffer)-1]='\0';
    outbufferext[sizeof(outbufferext)-1]='\0';
}

static inline void _output_outoforder(struct TransferInfo *stats) {
    if (stats->cntOutofOrder > 0) {
	printf(report_outoforder,
	       stats->common->transferIDStr, stats->ts.iStart,
	       stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
    }
    if (stats->l2counts.cnt) {
	printf(report_l2statistics,
	       stats->common->transferIDStr, stats->ts.iStart,
	       stats->ts.iEnd, stats->l2counts.cnt, stats->l2counts.lengtherr,
	       stats->l2counts.udpcsumerr, stats->l2counts.unknown, (stats->common->Omit ? report_omitted : ""));
    }
}

//
//  Little's law is L = lambda * W, where L is queue depth,
//  lambda the arrival rate and W is the processing time
//
#define LLAW_LOWERBOUNDS -1e7

static inline void human_format_llawbuf(char *dststr, size_t len, double inP) {
    if (inP < LLAW_LOWERBOUNDS) {
	char oobstr[] = "OBL";
	if (len > sizeof(oobstr))
	    strcpy(dststr, oobstr);
    } else {
        //force to adpative bytes for human readable
        byte_snprintf(dststr, len, inP, 'A');
	dststr[len-1] = '\0';
    }
}

#if 0
static inline void set_llawbuf_frames (int lambda, double meantransit, double variance, intmax_t framecnt) {
    int Lvar = 0;
    int L  = round(lambda * meantransit);
    if (variance > 0.0) {
	Lvar  = round(lambda * variance);
    } else {
	Lvar = 0;
    }
    snprintf(llaw_buf, sizeof(llaw_buf), "%" PRIdMAX "/%d(%d) frames", framecnt, L, Lvar);
    llaw_buf[sizeof(llaw_buf) - 1] = '\0';
}
#endif

#define NETPWR_LOWERBOUNDS -1e7
static inline void set_netpowerbuf(double meantransit, struct TransferInfo *stats) {
    if (meantransit == 0.0) {
	strcpy(netpower_buf, "NAN");
    } else {
	double netpwr = NETPOWERCONSTANT * (((double) stats->cntBytes) / (stats->ts.iEnd - stats->ts.iStart) / meantransit);
	if (netpwr <  NETPWR_LOWERBOUNDS) {
	    strcpy(netpower_buf, "OBL");
	} else if (netpwr > 100)  {
	    snprintf(netpower_buf, sizeof(netpower_buf), "%.0f", netpwr);
	} else if (netpwr > 10)  {
	    snprintf(netpower_buf, sizeof(netpower_buf), "%.2f", netpwr);
	} else {
	    snprintf(netpower_buf, sizeof(netpower_buf), "%.6f", netpwr);
	}
    }
}

//TCP Output
void tcp_output_fullduplex (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_bw_sum_fullduplex_format, stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_fullduplex_sum (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_sum_bw_format, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_fullduplex_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_bw_sum_fullduplex_enhanced_format, stats->common->transferID, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_bw_format, stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
//TCP read or server output
void tcp_output_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_read_enhanced);
    _print_stats_common(stats);
    printf(report_bw_read_enhanced_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7],
	   (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_read_triptime (struct TransferInfo *stats) {
    double meantransit;
    HEADING_PRINT_COND(report_bw_read_enhanced_netpwr);
    char llaw_bufstr[LLAWBUFSIZE];
    human_format_llawbuf(llaw_bufstr, sizeof(llaw_bufstr), ((stats->final) ? stats->fInP : stats->iInP));
    _print_stats_common(stats);
    if (!stats->final) {
        meantransit = (stats->transit.current.cnt > 0) ? (stats->transit.current.sum / stats->transit.current.cnt) : 0;
	set_netpowerbuf(meantransit, stats);
	printf(report_bw_read_enhanced_netpwr_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       (meantransit * 1e3),
	       (stats->transit.current.cnt < 2) ? 0 : stats->transit.current.min * 1e3,
	       (stats->transit.current.cnt < 2) ? 0 : stats->transit.current.max * 1e3,
	       (stats->transit.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->transit.current.m2 / (stats->transit.current.cnt - 1))),
	       stats->transit.current.cnt,
	       stats->transit.current.cnt ? (long) ((double)stats->cntBytes / (double) stats->transit.current.cnt) : 0,
	       llaw_bufstr,
	       netpower_buf,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       (stats->common->Omit ? report_omitted : ""));
    } else {
        meantransit = (stats->transit.total.cnt > 0) ? (stats->transit.total.sum / stats->transit.total.cnt) : 0;
	set_netpowerbuf(meantransit, stats);
	printf(report_bw_read_enhanced_netpwr_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       (meantransit * 1e3),
	       stats->transit.total.min * 1e3,
	       stats->transit.total.max * 1e3,
	       (stats->transit.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->transit.total.m2 / (stats->transit.total.cnt - 1))),
	       stats->transit.total.cnt,
	       stats->transit.total.cnt ? (long) ((double)stats->cntBytes / (double) stats->transit.total.cnt) : 0,
	       llaw_bufstr,
	       netpower_buf,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       (stats->common->Omit ? report_omitted : ""));
    }
    if (stats->framelatency_histogram) {
	histogram_print(stats->framelatency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    cond_flush(stats);
}
void tcp_output_read_enhanced_isoch (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_isoch_enhanced_netpwr);
    _print_stats_common(stats);
    double meantransit;
    if (!stats->final) {
        meantransit = (stats->isochstats.transit.current.cnt > 0) ? (stats->isochstats.transit.current.sum / stats->isochstats.transit.current.cnt) : 0;
        set_netpowerbuf(meantransit, stats);
	printf(report_bw_isoch_enhanced_netpwr_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       (meantransit * 1e3),
	       (stats->isochstats.transit.current.cnt < 2) ? 0 : stats->isochstats.transit.current.min * 1e3,
	       (stats->isochstats.transit.current.cnt < 2) ? 0 : stats->isochstats.transit.current.max * 1e3,
	       (stats->isochstats.transit.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->isochstats.transit.current.m2 / (stats->isochstats.transit.current.cnt - 1))),
	       stats->isochstats.transit.current.cnt,
	       stats->isochstats.transit.current.cnt ? (long) ((double)stats->cntBytes / (double) stats->isochstats.transit.current.cnt) : 0,
	       netpower_buf,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       (stats->common->Omit ? report_omitted : ""));
    } else {
        meantransit = (stats->isochstats.transit.total.cnt > 0) ? (stats->isochstats.transit.total.sum / stats->isochstats.transit.total.cnt) : 0;
        set_netpowerbuf(meantransit, stats);
	printf(report_bw_isoch_enhanced_netpwr_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       (meantransit * 1e3),
	       stats->isochstats.transit.total.min * 1e3,
	       stats->isochstats.transit.total.max * 1e3,
	       (stats->isochstats.transit.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->isochstats.transit.total.m2 / (stats->isochstats.transit.total.cnt - 1))),
	       stats->isochstats.transit.total.cnt,
	       stats->isochstats.transit.total.cnt ? (long) ((double)stats->cntBytes / (double) stats->isochstats.transit.total.cnt) : 0,
	       netpower_buf,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       (stats->common->Omit ? report_omitted : ""));
    }
    if (stats->framelatency_histogram) {
	histogram_print(stats->framelatency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    cond_flush(stats);
}

void tcp_output_frame_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_frame_tcp_enhanced);
    _print_stats_common(stats);
    printf(report_bw_read_enhanced_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7],
	   (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_frame_read_triptime (struct TransferInfo *stats) {
    fprintf(stderr, "FIXME\n");
}
void tcp_output_burst_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_burst_read_tcp);
    _print_stats_common(stats);
    if (!stats->final) {
	set_netpowerbuf(stats->transit.current.mean, stats);
	printf(report_burst_read_tcp_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->transit.current.mean * 1e3,
	       (1e2 * stats->transit.current.mean * stats->common->FPS), // (1e3 / 100%)
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       netpower_buf,
	       (stats->common->Omit ? report_omitted : ""));
    } else {
	printf(report_burst_read_tcp_final_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->transit.total.mean * 1e3,
	       (stats->transit.total.cnt < 2) ? 0 : stats->transit.total.min * 1e3,
	       (stats->transit.total.cnt < 2) ? 0 : stats->transit.total.max * 1e3,
	       (stats->transit.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->transit.total.m2 / (stats->transit.total.cnt - 1))),
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.bins[0],
	       stats->sock_callstats.read.bins[1],
	       stats->sock_callstats.read.bins[2],
	       stats->sock_callstats.read.bins[3],
	       stats->sock_callstats.read.bins[4],
	       stats->sock_callstats.read.bins[5],
	       stats->sock_callstats.read.bins[6],
	       stats->sock_callstats.read.bins[7],
	       (stats->common->Omit ? report_omitted : ""));
    }
    cond_flush(stats);
}

//TCP write or client output
void tcp_output_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_bw_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_write_bb (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_client_bb_bw);
    _print_stats_common(stats);
    char rps_string[80];
    if (stats->final) {
        double rps = ((stats->fBBrunning > 0) && (stats->bbrtt.total.cnt > 0)) ? ((double) stats->bbrtt.total.cnt / stats->fBBrunning) : 0;
	if (rps < 10)
	    snprintf(rps_string, sizeof(rps_string), "%0.1f", rps);
	else
	    snprintf(rps_string, sizeof(rps_string), "%0.0f", rps);
	rps_string[sizeof(rps_string) - 1] = '\0';

#if HAVE_TCP_STATS
	printf(report_client_bb_bw_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->bbrtt.total.cnt,
	       (stats->bbrtt.total.mean * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.min * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.max * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.total.m2 / (stats->bbrtt.total.cnt - 1))),
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       rps_string,
	       (stats->common->Omit ? report_omitted : ""));
#else
	printf(report_client_bb_bw_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->bbrtt.total.cnt,
	       (stats->bbrtt.total.mean * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.min * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.max * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.total.m2 / (stats->bbrtt.total.cnt - 1))),
	       rps_string,
	       (stats->common->Omit ? report_omitted : ""));
#endif
	if (isTripTime(stats->common)) {
	    printf(report_client_bb_bw_triptime_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   stats->bbowdto.total.cnt,
		   (stats->bbowdto.total.mean * 1e3),
		   (stats->bbowdto.total.cnt < 2) ? 0 : (stats->bbowdto.total.min * 1e3),
		   (stats->bbowdto.total.cnt < 2) ? 0 : (stats->bbowdto.total.max * 1e3),
		   (stats->bbowdto.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbowdto.total.m2 / (stats->bbowdto.total.cnt - 1))),
		   (stats->bbowdfro.total.mean * 1e3),
		   (stats->bbowdfro.total.cnt < 2) ? 0 : (stats->bbowdfro.total.min * 1e3),
		   (stats->bbowdfro.total.cnt < 2) ? 0 : (stats->bbowdfro.total.max * 1e3),
		   (stats->bbowdfro.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbowdfro.total.m2 / (stats->bbowdfro.total.cnt - 1))),
		   (stats->bbasym.total.mean * 1e3),
		   (stats->bbasym.total.cnt < 2) ? 0 : (stats->bbasym.total.min * 1e3),
		   (stats->bbasym.total.cnt < 2) ? 0 : (stats->bbasym.total.max * 1e3),
		   (stats->bbasym.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbasym.total.m2 / (stats->bbasym.total.cnt - 1))),
		   (stats->common->Omit ? report_omitted : ""));
	}
	if (stats->bbowdto_histogram) {
	    stats->bbowdto_histogram->final = 1;
	    histogram_print(stats->bbowdto_histogram, stats->ts.iStart, stats->ts.iEnd);
	}
	if (stats->bbowdfro_histogram) {
	    stats->bbowdfro_histogram->final = 1;
	    histogram_print(stats->bbowdfro_histogram, stats->ts.iStart, stats->ts.iEnd);
	}
	if (stats->bbrtt_histogram) {
	    stats->bbrtt_histogram->final = 1;
	    histogram_print(stats->bbrtt_histogram, stats->ts.iStart, stats->ts.iEnd);
	}
	if (isTripTime(stats->common) && (stats->bb_clocksync_error > 0)) {
	    printf(report_client_bb_triptime_clocksync_error, stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd, stats->bb_clocksync_error);
	}
    } else {
	double rps = ((stats->bbrtt.current.cnt > 0) && (stats->iBBrunning > 0)) ? ((double) stats->bbrtt.current.cnt / stats->iBBrunning) : 0;
	if (rps < 10)
	    snprintf(rps_string, sizeof(rps_string), "%0.1f", rps);
	else
	    snprintf(rps_string, sizeof(rps_string), "%0.0f", rps);
	rps_string[sizeof(rps_string) - 1] = '\0';

#if HAVE_TCP_STATS
	printf(report_client_bb_bw_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->bbrtt.current.cnt,
	       (stats->bbrtt.current.mean * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.min * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.max * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.current.m2 / (stats->bbrtt.current.cnt - 1))),
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       rps_string,
	       (stats->common->Omit ? report_omitted : ""));
#else
	printf(report_client_bb_bw_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->bbrtt.current.cnt,
	       (stats->bbrtt.current.mean * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.min * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.max * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.current.m2 / (stats->bbrtt.current.cnt - 1))),
	       rps_string,
	       (stats->common->Omit ? report_omitted : ""));
#endif
	if (isTripTime(stats->common)) {
	    printf(report_client_bb_bw_triptime_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   stats->bbowdto.current.cnt,
		   (stats->bbowdto.current.mean * 1e3),
		   (stats->bbowdto.current.cnt < 2) ? 0 : (stats->bbowdto.current.min * 1e3),
		   (stats->bbowdto.current.cnt < 2) ? 0 : (stats->bbowdto.current.max * 1e3),
		   (stats->bbowdto.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbowdto.current.m2 / (stats->bbowdto.current.cnt - 1))),
		   (stats->bbowdfro.current.mean * 1e3),
		   (stats->bbowdfro.current.cnt < 2) ? 0 : (stats->bbowdfro.current.min * 1e3),
		   (stats->bbowdfro.current.cnt < 2) ? 0 : (stats->bbowdfro.current.max * 1e3),
		   (stats->bbowdfro.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbowdfro.current.m2 / (stats->bbowdfro.current.cnt - 1))),
		   (stats->bbasym.current.mean * 1e3),
		   (stats->bbasym.current.cnt < 2) ? 0 : (stats->bbasym.current.min * 1e3),
		   (stats->bbasym.current.cnt < 2) ? 0 : (stats->bbasym.current.max * 1e3),
		   (stats->bbasym.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbasym.current.m2 / (stats->bbasym.current.cnt - 1))),
		   (stats->common->Omit ? report_omitted : ""));
	}
	if (isHistogram(stats->common)) {
	    if (stats->bbowdto_histogram) {
		stats->bbowdto_histogram->final = 0;
		histogram_print(stats->bbowdto_histogram, stats->ts.iStart, stats->ts.iEnd);
	    }
	    if (stats->bbowdfro_histogram) {
		stats->bbowdfro_histogram->final = 0;
		histogram_print(stats->bbowdfro_histogram, stats->ts.iStart, stats->ts.iEnd);
	    }
	    if (stats->bbrtt_histogram) {
		stats->bbrtt_histogram->final = 0;
		histogram_print(stats->bbrtt_histogram, stats->ts.iStart, stats->ts.iEnd);
	    }
	}
    }
    cond_flush(stats);
}

void tcp_output_burst_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_burst_write_tcp);
    _print_stats_common(stats);
#if HAVE_TCP_STATS
    set_netpowerbuf((stats->transit.current.mean + stats->sock_callstats.write.tcpstats.rtt), stats);
    printf(report_burst_write_tcp_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->transit.current.mean,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   stats->sock_callstats.write.tcpstats.retry,
	   stats->sock_callstats.write.tcpstats.cwnd,
	   stats->sock_callstats.write.tcpstats.rtt,
	   netpower_buf,
	   (stats->common->Omit ? report_omitted : ""));
 #else
    printf(report_burst_write_tcp_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->transit.current.mean,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   (stats->common->Omit ? report_omitted : ""));
#endif
    cond_flush(stats);
}

void tcp_output_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_write_enhanced);
    _print_stats_common(stats);
#if !(HAVE_TCP_STATS)
    printf(report_bw_write_enhanced_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   (stats->common->Omit ? report_omitted : ""));
#else
    set_netpowerbuf(stats->sock_callstats.write.tcpstats.rtt * 1e-6, stats);
    if (stats->sock_callstats.write.tcpstats.cwnd > 0) {
	printf(report_bw_write_enhanced_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
#if HAVE_TCP_INFLIGHT
	       stats->sock_callstats.write.tcpstats.bytes_in_flight,
	       stats->sock_callstats.write.tcpstats.packets_in_flight,
#endif
	       stats->sock_callstats.write.tcpstats.cwnd,
#if HAVE_TCP_INFLIGHT
	       stats->sock_callstats.write.tcpstats.cwnd_packets,
#endif
	       stats->sock_callstats.write.tcpstats.rtt,
	       stats->sock_callstats.write.tcpstats.rttvar,
	       netpower_buf,
	       (stats->common->Omit ? report_omitted : ""));
    } else {
	printf(report_bw_write_enhanced_nocwnd_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.rtt,
	       netpower_buf,
	       (stats->common->Omit ? report_omitted : ""));
    }
#endif
#if HAVE_DECL_TCP_NOTSENT_LOWAT
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
#endif
    cond_flush(stats);
}

void tcp_output_write_enhanced_fq (struct TransferInfo *stats) {
#if (HAVE_DECL_SO_MAX_PACING_RATE)
    HEADING_PRINT_COND(report_bw_write_enhanced_fq);
    _print_stats_common(stats);
#if !(HAVE_TCP_STATS)
    printf(report_bw_write_enhanced_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   (stats->common->Omit ? report_omitted : ""));
#else
    set_netpowerbuf(stats->sock_callstats.write.tcpstats.rtt * 1e-6, stats);
    char pacingrate[40];
    if (!stats->final) {
	byte_snprintf(pacingrate, sizeof(pacingrate), stats->FQPacingRateCurrent, 'a');
	pacingrate[39] = '\0';
    } else {
	pacingrate[0] = '\0';
    }
    if (stats->sock_callstats.write.tcpstats.cwnd > 0) {
	if (!stats->final) {
	    printf(report_bw_write_enhanced_fq_format,
		   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   stats->sock_callstats.write.WriteCnt,
		   stats->sock_callstats.write.WriteErr,
		   stats->sock_callstats.write.tcpstats.retry,
		   stats->sock_callstats.write.tcpstats.cwnd,
		   stats->sock_callstats.write.tcpstats.rtt,
		   stats->sock_callstats.write.tcpstats.rttvar,
		   pacingrate, netpower_buf,
		   (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_bw_write_enhanced_fq_final_format,
		   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   stats->sock_callstats.write.WriteCnt,
		   stats->sock_callstats.write.WriteErr,
		   stats->sock_callstats.write.tcpstats.retry,
		   stats->sock_callstats.write.tcpstats.cwnd,
		   stats->sock_callstats.write.tcpstats.rtt,
		   stats->sock_callstats.write.tcpstats.rttvar,
		   netpower_buf,
		   (stats->common->Omit ? report_omitted : ""));
	}
    } else {
	printf(report_bw_write_enhanced_nocwnd_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.rtt,
	       netpower_buf,
	       (stats->common->Omit ? report_omitted : ""));
    }
#endif
#if HAVE_DECL_TCP_NOTSENT_LOWAT
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
#endif
    cond_flush(stats);
#endif
}

void tcp_output_write_enhanced_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_write_enhanced_write);
    _print_stats_common(stats);
#if !(HAVE_TCP_STATS)
    printf(report_write_enhanced_write_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   stats->write_mmm.current.mean * 1e3,
	   stats->write_mmm.current.min * 1e3,
	   stats->write_mmm.current.max * 1e3,
	   (stats->write_mmm.current.cnt < 2) ? 0 : (1e-3 * sqrt(stats->write_mmm.current.m2 / (stats->write_mmm.current.cnt - 1))),
	   stats->write_mmm.current.cnt,
	   (stats->common->Omit ? report_omitted : ""));
#else
    set_netpowerbuf(stats->sock_callstats.write.tcpstats.rtt * 1e-6, stats);
    if (stats->sock_callstats.write.tcpstats.cwnd > 0) {
	printf(report_write_enhanced_write_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       netpower_buf,
	       stats->write_mmm.current.mean * 1e-3,
	       stats->write_mmm.current.min * 1e-3,
	       stats->write_mmm.current.max * 1e-3,
	       (stats->write_mmm.current.cnt < 2) ? 0 : (1e-3 * sqrt(stats->write_mmm.current.m2 / (stats->write_mmm.current.cnt - 1))),
	       stats->write_mmm.current.cnt,
	       (stats->common->Omit ? report_omitted : ""));
    } else {
	printf(report_write_enhanced_nocwnd_write_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.rtt,
	       netpower_buf,
	       stats->write_mmm.current.mean * 1e3,
	       stats->write_mmm.current.min * 1e3,
	       stats->write_mmm.current.max * 1e3,
	       (stats->write_mmm.current.cnt < 2) ? 0 : (1e3 * sqrt(stats->write_mmm.current.m2 / (stats->write_mmm.current.cnt - 1))),
	       stats->write_mmm.current.cnt, (stats->common->Omit ? report_omitted : ""));
    }
#endif
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->write_histogram) {
	histogram_print(stats->write_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    cond_flush(stats);
}

void tcp_output_write_enhanced_isoch (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_write_enhanced_isoch);
    _print_stats_common(stats);
#if !(HAVE_TCP_STATS)
    printf(report_write_enhanced_isoch_format,
	   stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   stats->isochstats.cntFrames, stats->isochstats.cntFramesMissed, stats->isochstats.cntSlips, (stats->common->Omit ? report_omitted : ""));
#else
    set_netpowerbuf(stats->sock_callstats.write.tcpstats.rtt * 1e-6, stats);
    if (stats->sock_callstats.write.tcpstats.cwnd > 0) {
	printf(report_write_enhanced_isoch_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       stats->isochstats.cntFrames, stats->isochstats.cntFramesMissed, stats->isochstats.cntSlips,
	       netpower_buf,(stats->common->Omit ? report_omitted : ""));
    } else {
	printf(report_write_enhanced_isoch_nocwnd_format,
	       stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.rtt,
	       stats->isochstats.cntFrames, stats->isochstats.cntFramesMissed, stats->isochstats.cntSlips,
	       netpower_buf,(stats->common->Omit ? report_omitted : ""));
    }
#endif
#if HAVE_DECL_TCP_NOTSENT_LOWAT
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
#endif
    cond_flush(stats);
}


//UDP output
void udp_output_fullduplex (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_udp_fullduplex);
    _print_stats_common(stats);
    printf(report_udp_fullduplex_format, stats->common->transferIDStr, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, \
	   stats->cntDatagrams, (stats->cntIPG && (stats->IPGsum > 0.0) ? (stats->cntIPG / stats->IPGsum) : 0.0),(stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void udp_output_fullduplex_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_udp_fullduplex);
    _print_stats_common(stats);
    printf(report_udp_fullduplex_enhanced_format, stats->common->transferID, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, \
	   stats->cntDatagrams, (stats->cntIPG && (stats->IPGsum > 0.0) ? (stats->cntIPG / stats->IPGsum) : 0.0),(stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void udp_output_fullduplex_sum (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_udp_fullduplex);
    _print_stats_common(stats);
    printf(report_udp_fullduplex_sum_format, stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, \
	   stats->cntDatagrams, (stats->cntIPG && (stats->IPGsum > 0.0) ? (stats->cntIPG / stats->IPGsum) : 0.0),(stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}


void udp_output_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_jitter_loss);
    _print_stats_common(stats);
    if (!stats->cntIPG) {
	printf(report_bw_jitter_loss_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       0.0, stats->cntError,
	       stats->cntDatagrams,
	       0.0,(stats->common->Omit ? report_omitted : ""));
    } else {
	printf(report_bw_jitter_loss_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),  \
	       stats->cntError, stats->cntDatagrams,
	       (100.0 * stats->cntError) / stats->cntDatagrams, (stats->common->Omit ? report_omitted : ""));
    }
    _output_outoforder(stats);
    cond_flush(stats);
}

void udp_output_read_triptime (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_jitter_loss_enhanced_triptime);
    _print_stats_common(stats);

    if (!stats->cntIPG) {
	printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       0.0, stats->cntError,
	       stats->cntDatagrams,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.cntReadTimeo,
#if HAVE_DECL_MSG_TRUNC
	       stats->sock_callstats.read.cntReadErrLen,
#endif
	       0.0,0.0,0.0,0.0,0.0,0.0,(stats->common->Omit ? report_omitted : ""));
    } else {
	if ((stats->transit.current.min > UNREALISTIC_LATENCYMINMAX) ||
	    (stats->transit.current.min < UNREALISTIC_LATENCYMINMIN)) {
	    printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (stats->cntIPG / stats->IPGsum),
		   stats->sock_callstats.read.cntRead,
#if HAVE_DECL_MSG_TRUNC
		   stats->sock_callstats.read.cntReadTimeo,
		   stats->sock_callstats.read.cntReadErrLen,(stats->common->Omit ? report_omitted : ""));
#else
	    stats->sock_callstats.read.cntReadTimeo, (stats->common->Omit ? report_omitted : ""));
#endif
	} else {
	    double meantransit;
	    double variance;
	    char llaw_bufstr[LLAWBUFSIZE];
	    int lambda =  ((stats->IPGsum > 0.0) ? (round (stats->cntIPG / stats->IPGsum)) : 0.0);
	    if (!stats->final) {
		meantransit = (stats->transit.current.cnt > 0) ? (stats->transit.current.sum / stats->transit.current.cnt) : 0;
		variance = (stats->transit.current.cnt < 2) ? 0 : \
		    (sqrt(stats->transit.current.m2 / (stats->transit.current.cnt - 1)));
		snprintf(llaw_bufstr, sizeof(llaw_bufstr), "%.0f(%.0f) pkts", stats->iInP, ((double) lambda * variance));
	    } else {
		meantransit = (stats->transit.total.cnt > 0) ? (stats->transit.total.sum / stats->transit.total.cnt) : 0;
		variance = (stats->transit.total.cnt < 2) ? 0 :	\
		    (sqrt(stats->transit.total.m2 / (stats->transit.total.cnt - 1)));
		snprintf(llaw_bufstr, sizeof(llaw_bufstr), "%.0f(%.0f) pkts", stats->fInP, ((double) lambda * variance));
	    }
	    llaw_bufstr[sizeof(llaw_bufstr)-1] = '\0';
	    set_netpowerbuf(meantransit, stats);
	    printf(report_bw_jitter_loss_enhanced_triptime_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),  \
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (meantransit * 1e3),
		   ((stats->final ? stats->transit.total.min : stats->transit.current.min) * 1e3),
		   ((stats->final ? stats->transit.total.max : stats->transit.current.max) * 1e3),
		   (stats->final ? (stats->transit.total.cnt < 2) : (stats->transit.current.cnt < 2)) ? 0 : (1e3 * variance), // convert from sec to ms
		   (stats->cntIPG / stats->IPGsum),
		   stats->cntIPG,
		   llaw_bufstr,
		   stats->sock_callstats.read.cntRead,
		   stats->sock_callstats.read.cntReadTimeo,
#if HAVE_DECL_MSG_TRUNC
		   stats->sock_callstats.read.cntReadErrLen,
#endif
		   netpower_buf, (stats->common->Omit ? report_omitted : ""));
	}
    }
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->jitter_histogram) {
	histogram_print(stats->jitter_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    _output_outoforder(stats);
    cond_flush(stats);
}
void udp_output_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_jitter_loss_enhanced);
    _print_stats_common(stats);
    if (!stats->cntIPG) {
	printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       0.0, stats->cntError,
	       stats->cntDatagrams,
	       stats->sock_callstats.read.cntRead,
	       stats->sock_callstats.read.cntReadTimeo,
#if HAVE_DECL_MSG_TRUNC
	       stats->sock_callstats.read.cntReadErrLen,
#endif
	       0.0,0.0,0.0,0.0,0.0,0.0, (stats->common->Omit ? report_omitted : ""));
    } else {
	if ((stats->transit.current.min > UNREALISTIC_LATENCYMINMAX) ||
	    (stats->transit.current.min < UNREALISTIC_LATENCYMINMIN)) {
	    printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (stats->cntIPG / stats->IPGsum),
		   stats->sock_callstats.read.cntRead,
#if HAVE_DECL_MSG_TRUNC
		   stats->sock_callstats.read.cntReadTimeo,
		   stats->sock_callstats.read.cntReadErrLen, (stats->common->Omit ? report_omitted : ""));
#else
	    stats->sock_callstats.read.cntReadTimeo, (stats->common->Omit ? report_omitted : ""));
#endif
	} else {
	    double meantransit;
	    double variance;
	    if (!stats->final) {
		meantransit = (stats->transit.current.cnt > 0) ? (stats->transit.current.sum / stats->transit.current.cnt) : 0;
		variance = (stats->transit.current.cnt < 2) ? 0 : \
		    (sqrt(stats->transit.current.m2 / (stats->transit.current.cnt - 1)));
	    } else {
		meantransit = (stats->transit.total.cnt > 0) ? (stats->transit.total.sum / stats->transit.total.cnt) : 0;
		variance = (stats->transit.total.cnt < 2) ? 0 :	\
		    (sqrt(stats->transit.total.m2 / (stats->transit.total.cnt - 1)));
	    }
	    set_netpowerbuf(meantransit, stats);
	    printf(report_bw_jitter_loss_enhanced_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),  \
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (meantransit * 1e3),
		   ((stats->final ? stats->transit.total.min : stats->transit.current.min) * 1e3),
		   ((stats->final ? stats->transit.total.max : stats->transit.current.max) * 1e3),
		   (stats->final ? (stats->transit.total.cnt < 2) : (stats->transit.current.cnt < 2)) ? 0 : (1e3 * variance), // convert from sec to ms
		   (stats->cntIPG / stats->IPGsum),
		   stats->sock_callstats.read.cntRead,
		   stats->sock_callstats.read.cntReadTimeo,
#if HAVE_DECL_MSG_TRUNC
		   stats->sock_callstats.read.cntReadErrLen,
#endif
		   netpower_buf, (stats->common->Omit ? report_omitted : ""));
	}
    }
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->jitter_histogram) {
	histogram_print(stats->jitter_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    _output_outoforder(stats);
    cond_flush(stats);
}
void udp_output_read_triptime_isoch (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_jitter_loss_enhanced_isoch_triptime);
    _print_stats_common(stats);
    if (!stats->cntIPG) {
	printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
	       stats->ts.iStart, stats->ts.iEnd,
	       outbuffer, outbufferext,
	       0.0, stats->cntError,
	       stats->cntDatagrams,
	       0.0,0.0,0.0,0.0,0.0,0.0);

    } else {
	// If the min latency is out of bounds of a realistic value
	// assume the clocks are not synched and suppress the
	// latency output
	if ((stats->transit.current.min > UNREALISTIC_LATENCYMINMAX) ||
	    (stats->transit.current.min < UNREALISTIC_LATENCYMINMIN)) {
	    printf(report_bw_jitter_loss_suppress_enhanced_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (stats->cntIPG / stats->IPGsum), (stats->common->Omit ? report_omitted : ""));
	} else {
	    double frame_meantransit = (stats->isochstats.transit.current.cnt > 0) ? (stats->isochstats.transit.current.sum / stats->isochstats.transit.current.cnt) : 0;
	    double meantransit = (stats->transit.current.cnt > 0) ? (stats->transit.current.sum / stats->transit.current.cnt) : 0;
	    set_netpowerbuf(meantransit, stats);
	    printf(report_bw_jitter_loss_enhanced_isoch_format, stats->common->transferIDStr,
		   stats->ts.iStart, stats->ts.iEnd,
		   outbuffer, outbufferext,
		   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),  \
		   stats->cntError, stats->cntDatagrams,
		   (100.0 * stats->cntError) / stats->cntDatagrams,
		   (meantransit * 1e3),
		   stats->transit.current.min * 1e3,
		   stats->transit.current.max * 1e3,
		   (stats->transit.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->transit.current.m2 / (stats->transit.current.cnt - 1))),
		   (stats->cntIPG / stats->IPGsum),
		   stats->isochstats.cntFrames, stats->isochstats.cntFramesMissed,
		   (frame_meantransit * 1e3),
		   stats->isochstats.transit.current.min * 1e3,
		   stats->isochstats.transit.current.max * 1e3,
		   (stats->isochstats.transit.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->isochstats.transit.current.m2 / (stats->isochstats.transit.current.cnt - 1))),
		   netpower_buf, (stats->common->Omit ? report_omitted : ""));
#if 0
	    if (stats->final) {
	      printf("***** Jitter MMM = %f/%f/%f\n",stats->inline_jitter.total.mean, stats->inline_jitter.total.min, stats->inline_jitter.total.max);
	    }
#endif
	}
    }
    if (stats->latency_histogram) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->jitter_histogram) {
	histogram_print(stats->jitter_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->framelatency_histogram) {
	histogram_print(stats->framelatency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    _output_outoforder(stats);
    cond_flush(stats);
}
void udp_output_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_bw_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void udp_output_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_pps_enhanced);
    _print_stats_common(stats);
    printf(report_bw_pps_enhanced_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   stats->sock_callstats.write.WriteTimeo,
	   (stats->cntIPG ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void udp_output_write_enhanced_isoch (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_pps_enhanced_isoch);
    _print_stats_common(stats);
    printf(report_bw_pps_enhanced_isoch_format, stats->common->transferIDStr,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   (stats->cntIPG ? (stats->cntIPG / stats->IPGsum) : 0.0),
	   stats->isochstats.cntFrames, stats->isochstats.cntFramesMissed, stats->isochstats.cntSlips, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

// Sum reports
void udp_output_sum_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_sum_bw_jitter_loss_format,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->cntError, stats->cntDatagrams,
	   ((100.0 * stats->cntError) / stats->cntDatagrams),
           (stats->common->Omit ? report_omitted : ""));
    if ((stats->cntOutofOrder > 0)  && stats->final) {
	printf(report_sum_outoforder,
	       stats->ts.iStart,
	       stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
    }
    cond_flush(stats);
}
void udp_output_sumcnt (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_format, stats->slot_thread_downcount,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    if ((stats->cntOutofOrder > 0) && stats->final) {
	if (isSumOnly(stats->common)) {
	    printf(report_sumcnt_outoforder,
		   stats->threadcnt_final,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_outoforder,
		   stats->common->transferIDStr, stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	}
    }
    cond_flush(stats);
}
void udp_output_sumcnt_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_jitter_loss);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_jitter_loss_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount), stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, \
	   stats->cntError, stats->cntDatagrams, (stats->cntIPG && (stats->IPGsum > 0.0) ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    if ((stats->cntOutofOrder > 0)  && stats->final) {
	if (isSumOnly(stats->common)) {
	    printf(report_sumcnt_outoforder,
		   (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_sum_outoforder,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder,(stats->common->Omit ? report_omitted : ""));
	}
    }
    cond_flush(stats);
}

void udp_output_sumcnt_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_read_enhanced);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_read_enhanced_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),  \
	   stats->cntError, stats->cntDatagrams,
	   (100.0 * stats->cntError) / stats->cntDatagrams, (stats->common->Omit ? report_omitted : ""));
    if ((stats->cntOutofOrder > 0)  && stats->final) {
	if (isSumOnly(stats->common)) {
	    printf(report_sumcnt_outoforder,
		   (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_sum_outoforder,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	}
    }
    cond_flush(stats);
}

void udp_output_sumcnt_read_triptime (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_udp_triptime);
    _print_stats_common(stats);
    printf(report_sumcnt_udp_triptime_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount), stats->ts.iStart, stats->ts.iEnd, outbuffer, outbufferext, \
	   stats->cntError, stats->cntDatagrams, stats->cntIPG, (stats->final ? stats->fInP : stats->iInP), \
	   (stats->cntIPG && (stats->IPGsum > 0.0) ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    if ((stats->cntOutofOrder > 0) && stats->final) {
	if (isSumOnly(stats->common)) {
	    printf(report_sumcnt_outoforder,
		   stats->threadcnt_final,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_sum_outoforder,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	}
    }
    cond_flush(stats);
}

void udp_output_sum_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_sum_bw_format, stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void udp_output_sumcnt_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void udp_output_sum_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_udp_enhanced);
    _print_stats_common(stats);
    printf(report_sumcnt_udp_enhanced_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->cntError, stats->cntDatagrams,
	   (stats->cntIPG ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    if (stats->latency_histogram && stats->final) {
	histogram_print(stats->latency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if (stats->jitter_histogram && stats->final) {
	histogram_print(stats->jitter_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    if ((stats->cntOutofOrder > 0)  && stats->final) {
	if (isSumOnly(stats->common)) {
	    printf(report_sumcnt_outoforder,
		   stats->threadcnt_final,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	} else {
	    printf(report_sum_outoforder,
		   stats->ts.iStart,
		   stats->ts.iEnd, stats->cntOutofOrder, (stats->common->Omit ? report_omitted : ""));
	}
    }
    cond_flush(stats);
}
void udp_output_sum_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_pps_enhanced);
    _print_stats_common(stats);
    printf(report_sum_bw_pps_enhanced_format,
	    stats->ts.iStart, stats->ts.iEnd,
	    outbuffer, outbufferext,
	    stats->sock_callstats.write.WriteCnt,
	    stats->sock_callstats.write.WriteErr,
	   ((stats->cntIPG && (stats->IPGsum > 0.0)) ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void udp_output_sumcnt_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_pps_enhanced);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_pps_enhanced_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	    stats->ts.iStart, stats->ts.iEnd,
	    outbuffer, outbufferext,
	    stats->sock_callstats.write.WriteCnt,
	    stats->sock_callstats.write.WriteErr,
	   ((stats->cntIPG && (stats->IPGsum > 0.0)) ? (stats->cntIPG / stats->IPGsum) : 0.0), (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_sum_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_sum_bw_format,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sum_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_read_enhanced);
    _print_stats_common(stats);
    printf(report_sum_bw_read_enhanced_format,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7], (stats->common->Omit ? report_omitted : ""));
    if (stats->framelatency_histogram && stats->final) {
	histogram_print(stats->framelatency_histogram, stats->ts.iStart, stats->ts.iEnd);
    }
    cond_flush(stats);
}
void tcp_output_sumcnt_read (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sumcnt_read_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_read_enhanced);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_read_enhanced_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7], (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sumcnt_read_triptime (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_read_triptime);
    _print_stats_common(stats);
    char llaw_bufstr[LLAWBUFSIZE];
    human_format_llawbuf(llaw_bufstr, sizeof(llaw_bufstr), ((stats->final) ? stats->fInP : stats->iInP));
    printf(report_sumcnt_bw_read_triptime_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   llaw_bufstr,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7], (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

void tcp_output_sum_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw);
    _print_stats_common(stats);
    printf(report_sum_bw_format,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sumcnt_write (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext, (stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sum_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_bw_write_enhanced);
    _print_stats_common(stats);
    printf(report_sum_bw_write_enhanced_format,
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr
#if HAVE_TCP_STATS
	   ,stats->sock_callstats.write.tcpstats.retry
#endif
	   ,(stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}
void tcp_output_sumcnt_write_enhanced (struct TransferInfo *stats) {
    HEADING_PRINT_COND(report_sumcnt_bw_write_enhanced);
    _print_stats_common(stats);
    printf(report_sumcnt_bw_write_enhanced_format, (stats->final ? stats->threadcnt_final: stats->slot_thread_downcount),
	   stats->ts.iStart, stats->ts.iEnd,
	   outbuffer, outbufferext,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr
#if HAVE_TCP_STATS
	   ,stats->sock_callstats.write.tcpstats.retry
#endif
	   ,(stats->common->Omit ? report_omitted : ""));
    cond_flush(stats);
}

// CSV outputs
void format_ips_port_string (struct TransferInfo *stats, bool sum) {
    char local_addr[REPORT_ADDRLEN];
    char remote_addr[REPORT_ADDRLEN];
    uint16_t local_port;
    uint16_t remote_port;
    int swap = (stats->common->ThreadMode == kMode_Server);
    int reverse = (isServerReverse(stats->common) || isReverse(stats->common));
    struct sockaddr *local = (swap ? (struct sockaddr*)&stats->common->peer : (struct sockaddr*)&stats->common->local);
    struct sockaddr *peer = (swap ? (struct sockaddr*)&stats->common->local : (struct sockaddr*)&stats->common->peer);

    if (local->sa_family == AF_INET) {
	if (isHideIPs(stats->common)) {
	    inet_ntop_hide(AF_INET, &((struct sockaddr_in*)local)->sin_addr,
			   local_addr, REPORT_ADDRLEN);
	} else {
	    inet_ntop(AF_INET, &((struct sockaddr_in*)local)->sin_addr,
		      local_addr, REPORT_ADDRLEN);
	}
	if (!reverse && sum)
	    local_port = 0;
	else
	    local_port = ntohs(((struct sockaddr_in*)local)->sin_port);
    } else {
#if HAVE_IPV6
        if (local->sa_family == AF_INET6) {
	    inet_ntop(AF_INET6, &((struct sockaddr_in6*)local)->sin6_addr,
		      local_addr, REPORT_ADDRLEN);
	    if (swap && sum)
		local_port = 0;
	    else
		local_port = ntohs(((struct sockaddr_in6*)local)->sin6_port);
	} else
#endif
	{
	    local_addr[0] = '\0';
	    local_port = 0;
	}
    }

    if (peer->sa_family == AF_INET) {
	if (isHideIPs(stats->common)) {
	    inet_ntop_hide(AF_INET, &((struct sockaddr_in*)peer)->sin_addr,
			   remote_addr, REPORT_ADDRLEN);
	} else {
	    inet_ntop(AF_INET, &((struct sockaddr_in*)peer)->sin_addr,
		      remote_addr, REPORT_ADDRLEN);
	}
	if (reverse && sum)
	    remote_port = 0;
	else
	    remote_port = ntohs(((struct sockaddr_in*)peer)->sin_port);
    } else {
#if HAVE_IPV6
        if (local->sa_family == AF_INET6) {
	    inet_ntop(AF_INET6, &((struct sockaddr_in6*)peer)->sin6_addr,
		      remote_addr, REPORT_ADDRLEN);
	    if (!swap && sum)
		remote_port = 0;
	    else
		remote_port = ntohs(((struct sockaddr_in6*)peer)->sin6_port);
	} else
#endif
	{
	    remote_addr[0] = '\0';
	    remote_port = 0;
	}
    }

    snprintf((char *)&stats->csv_peer, CSVPEERLIMIT, reportCSV_peer,
	     local_addr, local_port,
	     remote_addr, remote_port);
    stats->csv_peer[(CSVPEERLIMIT-1)] = '\0';
#if 0 // use to debug CSV ouput
    printf("*** output = %s swap=%d reverse=%d sum=%d\n", stats->csv_peer, swap, reverse, sum);
#endif
}

static inline void _print_stats_csv_timestr(struct TransferInfo *stats,
					    char *timestr, int buflen)
{
    iperf_formattime(timestr,
		     buflen,
		     (!stats->final ? stats->ts.nextTime : stats->ts.packetTime),
		     isEnhanced(stats->common),
		     isUTC(stats->common),
		     (isEnhanced(stats->common) ? CSVTZ : CSV));
}

static inline intmax_t _print_stats_csv_speed(struct TransferInfo *stats)
{
  return (intmax_t) (((stats->cntBytes > 0) && (stats->ts.iEnd -  stats->ts.iStart) > 0.0)
		     ? (((double)stats->cntBytes * 8.0) / (stats->ts.iEnd -  stats->ts.iStart))
		     : 0);
}

void udp_output_basic_csv (struct TransferInfo *stats) {
    char timestr[120];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
    printf(reportCSV_bw_jitter_loss_format,
	    timestr,
	    stats->csv_peer,
	    stats->common->transferID,
	    stats->ts.iStart,
	    stats->ts.iEnd,
	    stats->cntBytes,
	    speed,
	    (stats->final) ? ((stats->inline_jitter.total.sum / (double) stats->inline_jitter.total.cnt) * 1e3) : (stats->jitter * 1e3),
	    stats->cntError,
	    stats->cntDatagrams,
	    (100.0 * stats->cntError) / stats->cntDatagrams, stats->cntOutofOrder );
    cond_flush(stats);
}

void udp_output_enhanced_csv (struct TransferInfo *stats) {
    HEADING_PRINT_COND(reportCSV_bw_jitter_loss_pps);
    char timestr[120];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
    printf(reportCSV_bw_jitter_loss_pps_format,
	   timestr,
	   stats->csv_peer,
	   stats->common->transferID,
	   stats->ts.iStart,
	   stats->ts.iEnd,
	   stats->cntBytes,
	   speed,
	   (stats->jitter * 1e3),
	   stats->cntError,
	   stats->cntDatagrams,
	   (100.0 * stats->cntError) / stats->cntDatagrams,
	   stats->cntOutofOrder,
	   stats->sock_callstats.write.WriteCnt,
	   stats->sock_callstats.write.WriteErr,
	   (stats->cntIPG ? (stats->cntIPG / stats->IPGsum) : 0.0));
    cond_flush(stats);
}

void tcp_output_basic_csv (struct TransferInfo *stats) {
    char timestr[120];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
    printf(reportCSV_bw_format,
	   timestr,
	   stats->csv_peer,
	   stats->common->transferID,
	   stats->ts.iStart,
	   stats->ts.iEnd,
	   stats->cntBytes,
	   speed);
    cond_flush(stats);
}

void tcp_output_read_enhanced_csv (struct TransferInfo *stats) {
    HEADING_PRINT_COND(reportCSV_bw_read_enhanced);
    char timestr[80];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
    printf(reportCSV_bw_read_enhanced_format,
	   timestr,
	   stats->csv_peer,
	   stats->common->transferID,
	   stats->ts.iStart,
	   stats->ts.iEnd,
	   stats->cntBytes,
	   speed,
	   stats->sock_callstats.read.cntRead,
	   stats->sock_callstats.read.bins[0],
	   stats->sock_callstats.read.bins[1],
	   stats->sock_callstats.read.bins[2],
	   stats->sock_callstats.read.bins[3],
	   stats->sock_callstats.read.bins[4],
	   stats->sock_callstats.read.bins[5],
	   stats->sock_callstats.read.bins[6],
	   stats->sock_callstats.read.bins[7]);
    cond_flush(stats);
}

void tcp_output_write_enhanced_csv (struct TransferInfo *stats) {
    HEADING_PRINT_COND(reportCSV_bw_write_enhanced);
    char timestr[120];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
#if !(HAVE_TCP_STATS)
    printf(reportCSV_bw_write_enhanced_format,
	   timestr,
	   stats->csv_peer,
	   stats->common->transferID,
	   stats->ts.iStart,
	   stats->ts.iEnd,
	   stats->cntBytes,
	   speed,
	   -1,
	   -1,
	   -1,
	   -1,
	   0,
	   0);
#else
    if (stats->common->transferID == -1) {
	/* Sums */
	printf(reportCSV_bw_write_enhanced_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       -1,
	       0,
	       0);
    } else if (stats->sock_callstats.write.tcpstats.cwnd > 0) {
	printf(reportCSV_bw_write_enhanced_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       stats->sock_callstats.write.tcpstats.rttvar);
    } else {
	printf(reportCSV_bw_write_enhanced_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->sock_callstats.write.WriteCnt,
	       stats->sock_callstats.write.WriteErr,
	       stats->sock_callstats.write.tcpstats.retry,
	       -1,
	       stats->sock_callstats.write.tcpstats.rtt,
	       0);
    }
#endif
    cond_flush(stats);
}

void tcp_output_write_bb_csv (struct TransferInfo *stats) {
    HEADING_PRINT_COND(reportCSV_client_bb_bw_tcp);
    char timestr[120];
    _print_stats_csv_timestr(stats, timestr, sizeof(timestr));
    intmax_t speed = _print_stats_csv_speed(stats);
    if (stats->final) {
        double rps = ((stats->fBBrunning > 0) && (stats->bbrtt.total.cnt > 0)) ? ((double) stats->bbrtt.total.cnt / stats->fBBrunning) : 0;

#if HAVE_TCP_STATS
	printf(reportCSV_client_bb_bw_tcp_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->bbrtt.total.cnt,
	       (stats->bbrtt.total.mean * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.min * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.max * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.total.m2 / (stats->bbrtt.total.cnt - 1))),
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       rps);
#else
	printf(reportCSV_client_bb_bw_tcp_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->bbrtt.total.cnt,
	       (stats->bbrtt.total.mean * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.min * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : (stats->bbrtt.total.max * 1e3),
	       (stats->bbrtt.total.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.total.m2 / (stats->bbrtt.total.cnt - 1))),
	       -1,
	       -1,
	       -1,
	       rps);
#endif
    } else {
	double rps = ((stats->bbrtt.current.cnt > 0) && (stats->iBBrunning > 0)) ? ((double) stats->bbrtt.current.cnt / stats->iBBrunning) : 0;

#if HAVE_TCP_STATS
	printf(reportCSV_client_bb_bw_tcp_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->bbrtt.current.cnt,
	       (stats->bbrtt.current.mean * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.min * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.max * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.current.m2 / (stats->bbrtt.current.cnt - 1))),
	       stats->sock_callstats.write.tcpstats.retry,
	       stats->sock_callstats.write.tcpstats.cwnd,
	       stats->sock_callstats.write.tcpstats.rtt,
	       rps);
#else
	printf(reportCSV_client_bb_bw_tcp_format,
	       timestr,
	       stats->csv_peer,
	       stats->common->transferID,
	       stats->ts.iStart,
	       stats->ts.iEnd,
	       stats->cntBytes,
	       speed,
	       stats->bbrtt.current.cnt,
	       (stats->bbrtt.current.mean * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.min * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : (stats->bbrtt.current.max * 1e3),
	       (stats->bbrtt.current.cnt < 2) ? 0 : 1e3 * (sqrt(stats->bbrtt.current.m2 / (stats->bbrtt.current.cnt - 1))),
	       -1,
	       -1,
	       -1,
	       rps);
#endif
    }
    cond_flush(stats);
}

/*
 * Report the client or listener Settings in default style
 */
static void output_window_size (struct ReportSettings *report) {
    int winsize = getsock_tcp_windowsize(report->common->socket, (report->common->ThreadMode != kMode_Client ? 0 : 1));
    byte_snprintf(outbuffer, sizeof(outbuffer), winsize, \
		  ((toupper(report->common->Format) == 'B') ? 'B' : 'A'));
    outbuffer[(sizeof(outbuffer)-1)] = '\0';
    printf("%s: %s", (isUDP(report->common) ? udp_buffer_size : tcp_window_size), outbuffer);
    if (report->common->winsize_requested == 0) {
        printf(" %s", window_default);
    } else if (winsize != report->common->winsize_requested) {
        byte_snprintf(outbuffer, sizeof(outbuffer), report->common->winsize_requested,
                       toupper((int)report->common->Format));
	outbuffer[(sizeof(outbuffer)-1)] = '\0';
	printf(warn_window_requested, outbuffer);
    }
    fflush(stdout);
}
static void reporter_output_listener_settings (struct ReportSettings *report) {
    if (report->common->PortLast > report->common->Port) {
	printf(server_pid_portrange, (isUDP(report->common) ? "UDP" : "TCP"), \
	       report->common->Port, report->common->PortLast, report->pid);
    } else {
	printf(isEnhanced(report->common) ? server_pid_port : server_port,
	       (isUDP(report->common) ? ((isIPV6(report->common) && isEnhanced(report->common)) ? "UDP (v6)" : "UDP") : \
		((isIPV6(report->common) && isEnhanced(report->common)) ? "TCP (v6)" : "TCP")), report->common->Port, report->pid);
    }
    if (isUDP(report->common) && isWorkingLoadUp(report->common) && isWorkingLoadDown(report->common)) {
	printf(server_working_load_port, "TCP", report->common->Port);
    }
    if (report->common->Localhost != NULL) {
	if (isEnhanced(report->common) && !SockAddr_isMulticast(&report->local)) {
	    if (report->common->Ifrname) {
		printf(bind_address_iface, report->common->Localhost, report->common->Ifrname);
	    } else {
		char *host_ip = (char *) malloc(REPORT_ADDRLEN);
		if (host_ip != NULL) {
		    if (((struct sockaddr*)(&report->common->local))->sa_family == AF_INET) {
		      if (isHideIPs(report->common)) {
			inet_ntop_hide(AF_INET, &((struct sockaddr_in*)(&report->common->local))->sin_addr,
				       host_ip, REPORT_ADDRLEN);
		      } else {
			inet_ntop(AF_INET, &((struct sockaddr_in*)(&report->common->local))->sin_addr,
				  host_ip, REPORT_ADDRLEN);
		      }
		    }
#if HAVE_IPV6
		    else {
			inet_ntop(AF_INET6, &((struct sockaddr_in6*)(&report->common->local))->sin6_addr,
				  host_ip, REPORT_ADDRLEN);
		    }
#endif
		    printf(bind_address, host_ip);
		    free(host_ip);
		}
	    }
	}
	if (SockAddr_isMulticast(&report->local)) {
	    if(!report->common->SSMMulticastStr)
		if (!report->common->Ifrname)
		    printf(join_multicast, report->common->Localhost);
		else
		    printf(join_multicast_starg_dev, report->common->Localhost,report->common->Ifrname);
	    else if(!report->common->Ifrname)
		printf(join_multicast_sg, report->common->SSMMulticastStr, report->common->Localhost);
	    else
		printf(join_multicast_sg_dev, report->common->SSMMulticastStr, report->common->Localhost, report->common->Ifrname);
        }
    }
    if (isTunDev(report->common) || isTapDev(report->common)) {
	printf(bind_address_iface_taptun, report->common->Ifrname);
    }
    if (isEnhanced(report->common)) {
	if (!(isUDP(report->common))) {
	    byte_snprintf(outbuffer, sizeof(outbuffer), report->common->BufLen, toupper((int)report->common->Format));
	    byte_snprintf(outbufferext, sizeof(outbufferext), report->common->BufLen / 8, 'A');
	    outbuffer[(sizeof(outbuffer)-1)] = '\0';
	    outbufferext[(sizeof(outbufferext)-1)] = '\0';
	    printf("%s: %s (Dist bin width=%s)\n", server_read_size, outbuffer, outbufferext);
	} else {
	    byte_snprintf(outbuffer, sizeof(outbuffer), report->common->BufLen, 'B');
	    outbuffer[(sizeof(outbuffer)-1)] = '\0';
	    printf("%s: %s \n", server_read_size, outbuffer);
	}

    }
#if HAVE_DECL_TCP_CONGESTION
    if (isCongestionControl(report->common) || isEnhanced(report->common)) {
	char cca[40] = "";
	Socklen_t len = sizeof(cca);
	if (getsockopt(report->common->socket, IPPROTO_TCP, TCP_CONGESTION, &cca, &len) == 0) {
	    cca[len]='\0';
	}
	if (report->common->Congestion)	{
	    fprintf(stdout,"TCP congestion control default set to %s using %s\n", report->common->Congestion, cca);
	} else if (strlen(cca)) {
	    fprintf(stdout,"TCP congestion control default %s\n", cca);
	}
    }
#endif
    if (isOverrideTOS(report->common)) {
	fprintf(stdout, "Reflected TOS will be set to 0x%x (dscp=%d,ecn=%d)\n", report->common->RTOS, \
		DSCP_VALUE(report->common->RTOS), ECN_VALUE(report->common->RTOS));
    }
    if (isPrintMSS(report->common)) {
        if (isTCPMSS(report->common)) {
	    printf(report_mss, report->sockmaxseg);
	} else {
	    printf(report_default_mss, report->sockmaxseg);
	}
    }
    if (report->common->TOS) {
	fprintf(stdout, "TOS will be set to 0x%x (dscp=%d,ecn=%d)\n", report->common->TOS, \
	    DSCP_VALUE(report->common->RTOS), ECN_VALUE(report->common->RTOS));
    }
    if (isUDP(report->common)) {
	if (isSingleClient(report->common)) {
	    fprintf(stdout, "WARN: Suggested to use lower case -u instead of -U (to avoid serialize & bypass of reporter thread)\n");
	} else if (isSingleClient(report->common)) {
	    fprintf(stdout, "Server set to single client traffic mode per -U (serialize traffic tests)\n");
	}
    } else if (isSingleClient(report->common)) {
	fprintf(stdout, "Server set to single client traffic mode (serialize traffic tests)\n");
    }
    if (isMulticast(report->common) && (report->common->Port == report->common->PortLast)) {
	fprintf(stdout, "Server set to single client traffic mode (per multicast receive)\n");
    }
    if (isHistogram(report->common)) {
	fprintf(stdout, "Enabled receive histograms bin-width=%0.3f ms, bins=%d (clients should use --trip-times)\n", \
		((1e3 * report->common->HistBinsize) / pow(10,report->common->HistUnits)), report->common->HistBins);
    }
    if (isJitterHistogram(report->common)) {
	fprintf(stdout, "Enabled jitter histograms (bin-width=%d us)\n", report->common->jitter_binwidth);
    }
    if (isFrameInterval(report->common)) {
#if HAVE_FASTSAMPLING
	fprintf(stdout, "Frame or burst interval reporting (feature is experimental)\n");
#else
	fprintf(stdout, "Frame or burst interval reporting (feature is experimental, ./configure --enable-fastsampling suggested)\n");
#endif
    }
    output_window_size(report);
    printf("\n");
    if (isPermitKey(report->common) && report->common->PermitKey) {
	if (report->common->ListenerTimeout > 0) {
	    fprintf(stdout, "Permit key is '%s' (timeout in %0.1f seconds)\n", report->common->PermitKey, report->common->ListenerTimeout);
	} else {
	    fprintf(stdout, "Permit key is '%s' (WARN: no timeout)\n", report->common->PermitKey);
	}
    }
    fflush(stdout);
}
static void reporter_output_client_settings (struct ReportSettings *report) {
    char *hoststr = (isHideIPs(report->common) ? report->common->HideHost \
		      : report->common->Host);
    if (!report->common->Ifrnametx) {
	printf(isEnhanced(report->common) ? client_pid_port : client_port, hoststr,
	       (isUDP(report->common) ? "UDP" : "TCP"), report->common->Port, report->pid, \
	       (!report->common->threads ? 1 : report->common->threads),
	       (!report->common->threads ? 1 : report->common->working_load_threads));
    } else {
	printf(client_pid_port_dev, hoststr,
	       (isUDP(report->common) ? "UDP" : "TCP"), report->common->Port, report->pid, \
	       report->common->Ifrnametx, (!report->common->threads ? 1 : report->common->threads),
	       (!report->common->threads ? 1 : report->common->working_load_threads));
    }
    if ((isEnhanced(report->common) || isNearCongest(report->common)) && !isUDP(report->common) && !isBounceBack(report->common)) {
	byte_snprintf(outbuffer, sizeof(outbuffer), report->common->BufLen, 'B');
	outbuffer[(sizeof(outbuffer)-1)] = '\0';
	if (!isBurstSize(report->common)) {
	    if (isTcpWriteTimes(report->common)) {
		printf("%s: %s (write timer enabled)\n", client_write_size, outbuffer);
	    } else {
		printf("%s: %s\n", client_write_size, outbuffer);
	    }
	} else {
	    byte_snprintf(outbufferext, sizeof(outbufferext), report->common->BurstSize, 'B');
	    outbufferext[(sizeof(outbufferext)-1)] = '\0';
	    if (isTcpWriteTimes(report->common)) {
		printf("%s: %s  Burst size: %s (write timer enabled)\n", client_write_size, outbuffer, outbufferext);
	    } else {
		printf("%s: %s  Burst size: %s\n", client_write_size, outbuffer, outbufferext);
	    }
	}
    }
    if (isIsochronous(report->common)) {
	char meanbuf[40];
	char variancebuf[40];
	byte_snprintf(meanbuf, sizeof(meanbuf), report->isochstats.mMean, 'a');
	byte_snprintf(variancebuf, sizeof(variancebuf), report->isochstats.mVariance, 'a');
	meanbuf[39]='\0'; variancebuf[39]='\0';
	printf(client_isochronous, report->isochstats.mFPS, meanbuf, variancebuf, (report->isochstats.mBurstInterval/1000.0), (report->isochstats.mBurstIPG/1000.0));
    }
    if (isBounceBack(report->common)) {
	char tmplbuf[40];
	byte_snprintf(tmplbuf, sizeof(tmplbuf), report->common->bbsize, 'A');
	tmplbuf[39]='\0';
	char tmprbuf[40];
	byte_snprintf(tmprbuf, sizeof(tmprbuf), report->common->bbreplysize, 'A');
	tmprbuf[39]='\0';
	if (isTcpQuickAck(report->common)) {
	    printf(client_bounceback, tmplbuf, tmprbuf, report->common->bbhold);
	} else {
	    printf(client_bounceback_noqack, tmplbuf, tmprbuf, report->common->bbhold);
	}
	if (report->common->FPS > 0) {
	    printf(client_bbburstperiodcount, report->common->bbcount, (1.0 / report->common->FPS));
	}
    } else {
	if (isPeriodicBurst(report->common) && (report->common->FPS > 0)) {
	    char tmpbuf[40];
	    byte_snprintf(tmpbuf, sizeof(tmpbuf), report->common->BurstSize, 'A');
	    tmpbuf[39]='\0';
	    if (report->common->bbcount) {
		printf(client_burstperiodcount, tmpbuf, report->common->bbcount, (1.0 / report->common->FPS));
	    } else {
		printf(client_burstperiod, tmpbuf, (1.0 / report->common->FPS));
	    }
	}
    }
    if (isFQPacing(report->common)) {
	char prate[40];
	byte_snprintf(prate, sizeof(prate), report->common->FQPacingRate, 'a');
	prate[39] = '\0';
	if (isFQPacingStep(report->common)) {
	    char pratestep[40];
	    byte_snprintf(pratestep, sizeof(pratestep), report->common->FQPacingRateStep, 'a');
	    pratestep[39] = '\0';
	    printf(client_fq_pacing_step,prate, pratestep);
	} else {
	    byte_snprintf(outbuffer, sizeof(outbuffer), report->common->FQPacingRate, 'a');
	    outbuffer[(sizeof(outbuffer)-1)] = '\0';
	    printf(client_fq_pacing,outbuffer);
	}
    }
    if (isPrintMSS(report->common)) {
        if (isTCPMSS(report->common)) {
	    printf(report_mss, report->sockmaxseg);
	} else {
	    printf(report_default_mss, report->sockmaxseg);
	}
    }
#if HAVE_DECL_TCP_CONGESTION
    if (isCongestionControl(report->common) || isEnhanced(report->common)) {
	char cca[40] = "";
	Socklen_t len = sizeof(cca);
	if (getsockopt(report->common->socket, IPPROTO_TCP, TCP_CONGESTION, &cca, &len) == 0) {
	    cca[len]='\0';
	}
	if (report->common->Congestion)	{
	    fprintf(stdout,"TCP congestion control set to %s using %s\n", report->common->Congestion, cca);
	} else if (strlen(cca)) {
	    fprintf(stdout,"TCP congestion control using %s\n", cca);
	}
    }
    if ((isWorkingLoadUp(report->common) || isWorkingLoadDown(report->common)) && isLoadCCA(report->common)) {
	fprintf(stdout,"TCP working load congestion control set to %s\n", report->common->LoadCCA);
    }
#endif
    if (isEnhanced(report->common)) {
	fprintf(stdout, "TOS set to 0x%x (dscp=%d,ecn=%d)", report->common->TOS, \
		DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS));
	if (ECN_VALUE(report->common->TOS)) {
	    fprintf(stdout, " (warn ecn bits set)");
	}
        if (isNoDelay(report->common)) {
	    fprintf(stdout," and nodelay (Nagle off)");
	} else {
	    fprintf(stdout," (Nagle on)");
	}
	fprintf(stdout, "\n");
    }
    if (isNearCongest(report->common)) {
	if (report->common->rtt_weight == NEARCONGEST_DEFAULT) {
	    fprintf(stdout, "TCP near-congestion delay weight set to %2.4f (use --near-congestion=<value> to change)\n", report->common->rtt_weight);
	} else {
	    fprintf(stdout, "TCP near-congestion delay weight set to %2.4f\n", report->common->rtt_weight);
	}
    }
    if (isSingleClient(report->common)) {
	fprintf(stdout, "WARN: Client set to bypass reporter thread per -U (suggest use lower case -u instead)\n");
    }
    if ((isIPG(report->common) || isUDP(report->common)) && !isIsochronous(report->common)) {
	byte_snprintf(outbuffer, sizeof(outbuffer), report->common->pktIPG, 'a');
	outbuffer[(sizeof(outbuffer)-1)] = '\0';
#ifdef HAVE_KALMAN
        printf(client_datagram_size_kalman, report->common->BufLen, report->common->pktIPG);
#else
        printf(client_datagram_size, report->common->BufLen, report->common->pktIPG);
#endif
    }
    if (isConnectOnly(report->common)) {
	fprintf(stdout, "TCP three-way-handshake (3WHS) only\n");
    } else {
	output_window_size(report);
	printf("\n");
#if HAVE_DECL_TCP_NOTSENT_LOWAT
	if (isWritePrefetch(report->common)) {
	    fprintf(stdout, "Event based writes (pending queue watermark at %d bytes)\n", report->common->WritePrefetch);
	}
#endif
	if (isHistogram(report->common)) {
	    if (!isBounceBack(report->common)) {
		fprintf(stdout, "Enabled write histograms bin-width=%0.3f ms, bins=%d\n", \
			((1e3 * report->common->HistBinsize) / pow(10,report->common->HistUnits)), report->common->HistBins);
	    } else {
		fprintf(stdout, "Set bounceback histograms to bin-width=%0.3f ms, bins=%d\n", \
			((1e3 * report->common->HistBinsize) / pow(10,report->common->HistUnits)), report->common->HistBins);
	    }
	}
    }
    fflush(stdout);
}

#define MINSAMPLES_FORVARIANCE 25
void reporter_connect_printf_tcp_final (struct ConnectionInfo * report) {
    if (report->connect_times.cnt >= MINSAMPLES_FORVARIANCE) {
        double variance = (sqrt(report->connect_times.m2 / (report->connect_times.cnt - 1)));
        fprintf(stdout, "[ CT] final connect times (min/avg/max/stdev) = %0.3f/%0.3f/%0.3f/%0.3f ms (tot/err) = %" PRIdMAX "/%" PRIdMAX "\n", \
		report->connect_times.min,  \
	        (report->connect_times.sum / report->connect_times.cnt), \
		report->connect_times.max, variance,  \
		(report->connect_times.cnt + report->connect_times.err), \
		report->connect_times.err);
    } else if (report->connect_times.cnt > 2) {
	fprintf(stdout, "[ CT] final connect times (min/avg/max) = %0.3f/%0.3f/%0.3f ms (tot/err) = %" PRIdMAX "/%" PRIdMAX "\n", \
		report->connect_times.min,  \
		(report->connect_times.sum / report->connect_times.cnt), \
		report->connect_times.max, \
		(report->connect_times.cnt + report->connect_times.err), \
		report->connect_times.err);
    }
    fflush(stdout);
}

void reporter_print_connection_report (struct ConnectionInfo *report) {
    assert(report->common);
    // copy the inet_ntop into temp buffers, to avoid overwriting
    char local_addr[REPORT_ADDRLEN];
    char remote_addr[REPORT_ADDRLEN];
    struct sockaddr *local = ((struct sockaddr*)&report->common->local);
    struct sockaddr *peer = ((struct sockaddr*)&report->common->peer);
    outbuffer[0]='\0';
    outbufferext[0]='\0';
    char *b = &outbuffer[0];
#if HAVE_DECL_TCP_WINDOW_CLAMP
    if (!isUDP(report->common) && isRxClamp(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (%s%d)", "clamp=", report->common->ClampSize);
	b += strlen(b);
    }
#endif
#if HAVE_DECL_TCP_NOTSENT_LOWAT
    if (!isUDP(report->common) && (report->common->socket > 0) && isWritePrefetch(report->common))  {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (%s%d)", "prefetch=", report->common->WritePrefetch);
	b += strlen(b);
    }
#endif
    if (isIsochronous(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (isoch)");
	b += strlen(b);
    }
    if (isPeriodicBurst(report->common) && (report->common->ThreadMode != kMode_Client) && !isServerReverse(report->common)) {
#if HAVE_FASTSAMPLING
	snprintf(b, SNBUFFERSIZE-strlen(b), " (burst-period=%0.4fs)", (1.0 / report->common->FPS));
#else
	snprintf(b, SNBUFFERSIZE-strlen(b), " (burst-period=%0.2fs)", (1.0 / report->common->FPS));
#endif
	b += strlen(b);
    }
    if (isFullDuplex(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (full-duplex)");
	b += strlen(b);
    } else if (isServerReverse(report->common) || isReverse(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (reverse)");
	b += strlen(b);
	if (isFQPacing(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (fq)");
	    b += strlen(b);
	}
    }
    if (isTxStartTime(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (epoch-start)");
	b += strlen(b);
    }
    if (isBounceBack(report->common)) {
	if (isTcpQuickAck(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (bb w/quickack req/reply/hold=%d/%d/%d)", report->common->bbsize, \
		     report->common->bbreplysize, report->common->bbhold);
	} else {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (bb req/reply/hold=%d/%d/%d)", report->common->bbsize, \
		     report->common->bbreplysize, report->common->bbhold);
	}
	b += strlen(b);
    }
    if (isL2LengthCheck(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (l2mode)");
	b += strlen(b);
    }
    if (isUDP(report->common) && isNoUDPfin(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (no-udp-fin)");
	b += strlen(b);
    }
    if (isTripTime(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (trip-times)");
	b += strlen(b);
    }
    if (isEnhanced(report->common)) {
        if (isCongestionControl(report->common)) {
#if HAVE_DECL_TCP_CONGESTION
	    char cca[40] = "";
	    Socklen_t len = sizeof(cca);
	    int rc;
	    if ((rc = getsockopt(report->common->socket, IPPROTO_TCP, TCP_CONGESTION, &cca, &len)) == 0) {
	        cca[len]='\0';
	    }
	    if (rc != SOCKET_ERROR) {
	        snprintf(b, SNBUFFERSIZE-strlen(b), " (sock=%d/%s)", report->common->socket, cca);
	        b += strlen(b);
	    }
#endif
	} else {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (sock=%d)", report->common->socket);
	    b += strlen(b);
	}
    }
    if (isOverrideTOS(report->common)) {
	if (isFullDuplex(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (tos rx/tx=0x%x,dscp=%d,ecn=%d, /0x%x,dscp=%d,ecn=%d)", report->common->TOS, \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS), \
		     report->common->RTOS, \
		     DSCP_VALUE(report->common->RTOS), ECN_VALUE(report->common->RTOS));
	} else if (isReverse(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (tos rx=0x%x,dscp=%d,ecn=%d)", report->common->TOS,  \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS));
	}
	b += strlen(b);
    } else if (report->common->TOS) {
	if (isFullDuplex(report->common) || isBounceBack(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (tos rx/tx=0x%x,dscp=%d,ecn=%d/0x%x,dscp=%d,ecn=%d)", report->common->TOS, \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS), \
		     report->common->TOS, \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS));
	} else if (isReverse(report->common)) {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (tos rx=0x%x,dscp=%d,ecn=%d)", report->common->TOS, \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS));
	} else {
	    snprintf(b, SNBUFFERSIZE-strlen(b), " (tos tx=0x%x,dscp=%d,ecn=%d)", report->common->TOS, \
		     DSCP_VALUE(report->common->TOS), ECN_VALUE(report->common->TOS));
	}
	b += strlen(b);
    }
    if (isEnhanced(report->common) || isPeerVerDetect(report->common)) {
	if (report->peerversion[0] != '\0') {
	    snprintf(b, SNBUFFERSIZE-strlen(b), "%s", report->peerversion);
	    b += strlen(b);
	}
    }
#if HAVE_DECL_TCP_QUICKACK
    if (isTcpQuickAck(report->common) && !isBounceBack(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (qack)");
	b += strlen(b);
    }
#endif
#if HAVE_TCP_STATS
    if (!isUDP(report->common) && (report->tcpinitstats.isValid) && isEnhanced(report->common)) {
	snprintf(b, SNBUFFERSIZE-strlen(b), " (icwnd/mss/irtt=%u/%u/%u)", \
		 report->tcpinitstats.cwnd, report->tcpinitstats.mss_negotiated, report->tcpinitstats.rtt);
	b += strlen(b);
    }
#endif
    if ((isFullDuplex(report->common) || !isServerReverse(report->common)) \
	&& (isEnhanced(report->common) || isConnectOnly(report->common))) {
	if (report->connect_timestamp.tv_sec > 0) {
	    char timestr[80];
	    iperf_formattime(timestr, sizeof(timestr), report->connect_timestamp, \
		     isEnhanced(report->common), isUTC(report->common), YearThruSecTZ);
	    if (!isUDP(report->common) && (report->common->ThreadMode == kMode_Client) && (report->tcpinitstats.connecttime > 0)) {
		snprintf(b, SNBUFFERSIZE-strlen(b), " (ct=%4.2f ms) on %s", report->tcpinitstats.connecttime, timestr);
	    } else {
		snprintf(b, SNBUFFERSIZE-strlen(b), " on %s", timestr);
	    }
	    b += strlen(b);
	}
    }
    if (local->sa_family == AF_INET) {
	if (isHideIPs(report->common)) {
	    inet_ntop_hide(AF_INET, &((struct sockaddr_in*)local)->sin_addr, local_addr, REPORT_ADDRLEN);
	} else {
	    inet_ntop(AF_INET, &((struct sockaddr_in*)local)->sin_addr, local_addr, REPORT_ADDRLEN);
	}
    }
#if HAVE_IPV6
    else {
	inet_ntop(AF_INET6, &((struct sockaddr_in6*)local)->sin6_addr, local_addr, REPORT_ADDRLEN);
    }
#endif
    if (peer->sa_family == AF_INET) {
	if (isHideIPs(report->common)) {
	    inet_ntop_hide(AF_INET, &((struct sockaddr_in*)peer)->sin_addr, remote_addr, REPORT_ADDRLEN);
	} else {
	    inet_ntop(AF_INET, &((struct sockaddr_in*)peer)->sin_addr, remote_addr, REPORT_ADDRLEN);
	}
    }
#if HAVE_IPV6
    else {
	inet_ntop(AF_INET6, &((struct sockaddr_in6*)peer)->sin6_addr, remote_addr, REPORT_ADDRLEN);
    }
#endif
#if HAVE_IPV6
    if (report->common->KeyCheck) {
	if (isEnhanced(report->common) && report->common->Ifrname && (strlen(report->common->Ifrname) < SNBUFFERSIZE-strlen(b))) {
	    printf(report_peer_dev, report->common->transferIDStr, local_addr, report->common->Ifrname, \
		   (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : \
		    ntohs(((struct sockaddr_in6*)local)->sin6_port)), \
		   remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) : \
				 ntohs(((struct sockaddr_in6*)peer)->sin6_port)), outbuffer);
	} else {
	    printf(report_peer, report->common->transferIDStr, local_addr, \
		   (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : \
		    ntohs(((struct sockaddr_in6*)local)->sin6_port)), \
		   remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) : \
				 ntohs(((struct sockaddr_in6*)peer)->sin6_port)), outbuffer);
	}
    } else {
	printf(report_peer_fail, local_addr, \
	       (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : \
		ntohs(((struct sockaddr_in6*)local)->sin6_port)), \
	       remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) : \
			     ntohs(((struct sockaddr_in6*)peer)->sin6_port)), outbuffer);
    }

#else
    if (report->common->KeyCheck) {
	if (isEnhanced(report->common) && report->common->Ifrname  && (strlen(report->common->Ifrname) < SNBUFFERSIZE-strlen(b))) {
	    printf(report_peer_dev, report->common->transferIDStr, local_addr, report->common->Ifrname, \
		   local_addr, (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : 0), \
		   remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) :  0), \
		   outbuffer);
	} else {
	    printf(report_peer, report->common->transferIDStr, \
		   local_addr, (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : 0), \
		   remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) :  0), \
		   outbuffer);
	}
    } else {
	printf(report_peer_fail, local_addr, (local->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)local)->sin_port) : 0), \
	       remote_addr, (peer->sa_family == AF_INET ? ntohs(((struct sockaddr_in*)peer)->sin_port) :  0), \
	       outbuffer);
    }
#endif
    if ((report->common->ThreadMode == kMode_Client) && !isServerReverse(report->common)) {
	if (isTxHoldback(report->common) || isTxStartTime(report->common)) {
	    struct timeval now;
	    TimeGetNow(now);
	    int seconds_from_now;
	    if (isTxHoldback(report->common)) {
		seconds_from_now = report->txholdbacktime.tv_sec;
		if (report->txholdbacktime.tv_usec > 0)
		    seconds_from_now++;
	    } else {
		seconds_from_now = ceil(TimeDifference(report->epochStartTime, now));
	    }
	    struct timeval start;
	    start = now;
	    char start_timebuf[80];
	    start.tv_sec = now.tv_sec + seconds_from_now;
	    char now_timebuf[80];
	    iperf_formattime(now_timebuf, sizeof(now_timebuf), now, \
			     isEnhanced(report->common), isUTC(report->common), YearThruSecTZ);
	    iperf_formattime(start_timebuf, sizeof(start_timebuf), start, \
			     isEnhanced(report->common), isUTC(report->common), YearThruSec);
	    if (seconds_from_now > 0) {
		printf(client_report_epoch_start_current, report->common->transferID, seconds_from_now, \
		       start_timebuf, now_timebuf);
	    } else if (!isBounceBack(report->common)) {
		printf(warn_start_before_now, report->common->transferID, report->epochStartTime.tv_sec, \
		       report->epochStartTime.tv_usec, start_timebuf, now_timebuf);
	    }
	}
    }
    fflush(stdout);
}

void reporter_print_settings_report (struct ReportSettings *report) {
    assert(report != NULL);
    report->pid =  (int)  getpid();
    printf("%s", separator_line);
    if (report->common->ThreadMode == kMode_Listener) {
	reporter_output_listener_settings(report);
    } else {
	reporter_output_client_settings(report);
    }
    printf("%s", separator_line);
    fflush(stdout);
}

void reporter_peerversion (struct ConnectionInfo *report, uint32_t upper, uint32_t lower) {
    if (!upper || !lower) {
	report->peerversion[0]='\0';
    } else {
	int rel, major, minor, alpha;
	rel = (upper & 0xFFFF0000) >> 16;
	major = (upper & 0x0000FFFF);
	minor = (lower & 0xFFFF0000) >> 16;
	alpha = (lower & 0x0000000F);
	snprintf(report->peerversion, (PEERVERBUFSIZE-10), " (peer %d.%d.%d)", rel, major, minor);
	switch(alpha) {
	case 0:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1,"-dev)");
	    break;
	case 1:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1,"-rc)");
	    break;
	case 2:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1,"-rc2)");
	    break;
	case 3:
	    break;
	case 4:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1,"-private)");
	    break;
	case 5:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1,"-master)");
	    break;
	default:
	    sprintf(report->peerversion + strlen(report->peerversion) - 1, "-unk)");
	}
	report->peerversion[PEERVERBUFSIZE-1]='\0';
    }
}

void reporter_print_server_relay_report (struct ServerRelay *report) {
    printf(server_reporting, report->info.common->transferID);
    if (isTripTime(report->info.common) || isEnhanced(report->info.common)) {
	udp_output_read_triptime(&report->info);
    } else {
	udp_output_read(&report->info);
    }
    fflush(stdout);
}
