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
 * iperf_formattime
 * wrapper around strftime.c for iperf supported formatting
 *
 * by Robert J. McMahon (rjmcmahon@rjmcmahon.com, bob.mcmahon@broadcom.com)
 * -------------------------------------------------------------------
 */
#include "headers.h"
#include "util.h"
#include "iperf_formattime.h"

inline void iperf_formattime (char *timestr, int buflen, struct timeval timestamp, bool prec_ms, bool utc_time, enum TimeFormatType ftype) {
    if (buflen > 0) {
	struct tm ts ;
	ts = (utc_time ? *gmtime(&timestamp.tv_sec) : *localtime(&timestamp.tv_sec));
	switch (ftype) {
	case YearThruSec:
	    strftime(timestr, buflen, "%Y-%m-%d %H:%M:%S", &ts);
	    if (prec_ms) {
		int currlen = strlen(timestr);
		if (currlen > 5) {
		    snprintf((timestr + currlen), 5, ".%.3d", (int) (timestamp.tv_usec/1000));
		}
	    }
	    break;
	case YearThruSecTZ:
	    strftime(timestr, buflen, "%Y-%m-%d %H:%M:%S", &ts);
	    int currlen = strlen(timestr);
	    if (prec_ms) {
		if (currlen > 5) {
		    snprintf((timestr + currlen), 5, ".%.3d", (int) (timestamp.tv_usec/1000));
		    currlen = strlen(timestr);
		}
	    }
	    if ((buflen - currlen) > 5) {
		strftime((timestr + currlen), (buflen - currlen), " (%Z)", &ts);
	    }
	    break;
	case CSV:
	    strftime(timestr, buflen, "%Y%m%d%H%M%S", &ts);
	    if (prec_ms) {
		int currlen = strlen(timestr);
		if (currlen > 5) {
		    snprintf((timestr + currlen), 5, ".%.3d", (int) (timestamp.tv_usec/1000));
		}
	    }
	    break;
	case CSVTZ:
	    strftime(timestr, buflen, "%z:%Y%m%d%H%M%S", &ts);
	    if (prec_ms) {
		int currlen = strlen(timestr);
		if (currlen > 5) {
		    snprintf((timestr + currlen), 5, ".%.3d", (int) (timestamp.tv_usec/1000));
		}
	    }
	    break;
	default:
	    FAIL_exit(1, "iperf_formattime program error");
	}
	timestr[buflen - 1] = '\0'; // make sure string is null terminated
    }
}
