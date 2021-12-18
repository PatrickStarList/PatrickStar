/****************************************************************************
 *
 * Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "PatrickStar_debug.h"
#include "decode.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"

#include "spp_session.h"
#include "session_api.h"
#include "PatrickStar_session.h"

#include "stream_common.h"
#include "PatrickStar_stream_tcp.h"
#include "PatrickStar_stream_udp.h"
#include "PatrickStar_stream_icmp.h"

#include "parser.h"

#include "reg_test.h"

#include "profiler.h"
#include "sfPolicy.h"
#ifdef PERF_PROFILING
PreprocStats s5IcmpPerfStats;
#endif


/*  G L O B A L S  **************************************************/
static SessionCache* icmp_lws_cache = NULL;

/*  P R O T O T Y P E S  ********************************************/
static void StreamParseIcmpArgs(char *, StreamIcmpPolicy *);
static void StreamPrintIcmpConfig(StreamIcmpPolicy *);

void StreamInitIcmp( void )
{
    if (icmp_lws_cache == NULL)
    {
        icmp_lws_cache = session_api->init_session_cache( SESSION_PROTO_ICMP, 0, NULL );
    }
}

void StreamIcmpPolicyInit(StreamIcmpConfig *config, char *args)
{
    if (config == NULL)
        return;

    config->num_policies++;

    StreamParseIcmpArgs(args, &config->default_policy);

    StreamPrintIcmpConfig(&config->default_policy);
}

static void StreamParseIcmpArgs(char *args, StreamIcmpPolicy *s5IcmpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;

    s5IcmpPolicy->session_timeout = STREAM_DEFAULT_SSN_TIMEOUT;
    //s5IcmpPolicy->flags = 0;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 0, &num_toks, 0);

        for (i = 0; i < num_toks; i++)
        {
            stoks = mSplit(toks[i], " ", 2, &s_toks, 0);

            if (s_toks == 0)
            {
                FatalError("%s(%d) => Missing parameter in Stream ICMP config.\n",
                    file_name, file_line);
            }

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5IcmpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]) || *endPtr)
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  Integer parameter required.\n",
                            file_name, file_line);
                }

                if ((s5IcmpPolicy->session_timeout > STREAM_MAX_SSN_TIMEOUT) ||
                    (s5IcmpPolicy->session_timeout < STREAM_MIN_SSN_TIMEOUT))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  "
                        "Must be between %d and %d\n",
                        file_name, file_line,
                        STREAM_MIN_SSN_TIMEOUT, STREAM_MAX_SSN_TIMEOUT);
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream ICMP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Invalid Stream ICMP policy option\n",
                            file_name, file_line);
            }

            mSplitFree(&stoks, s_toks);
        }

        mSplitFree(&toks, num_toks);
    }
}

static void StreamPrintIcmpConfig(StreamIcmpPolicy *s5IcmpPolicy)
{
    LogMessage("Stream ICMP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", s5IcmpPolicy->session_timeout);
}

void IcmpSessionCleanup(SessionControlBlock *ssn)
{
    if (ssn->ha_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (ssn->ha_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }
}

uint32_t StreamGetIcmpPrunes(void)
{
    if( icmp_lws_cache )
        return session_api->get_session_prune_count( SESSION_PROTO_ICMP );
    else
        return s5stats.icmp_prunes;
}

void StreamResetIcmpPrunes(void)
{
    session_api->reset_session_prune_count( SESSION_PROTO_ICMP );
}

void StreamResetIcmp(void)
{
    session_api->purge_session_cache(icmp_lws_cache);
    session_api->clean_protocol_session_pool( SESSION_PROTO_ICMP );
}

void StreamCleanIcmp(void)
{
    if ( icmp_lws_cache )
        s5stats.icmp_prunes = session_api->get_session_prune_count( SESSION_PROTO_ICMP );

    /* Clean up session cache */
    session_api->delete_session_cache( SESSION_PROTO_ICMP );
    icmp_lws_cache = NULL;
}

void StreamIcmpConfigFree(StreamIcmpConfig *config)
{
    if (config == NULL)
        return;

    free(config);
}

int StreamVerifyIcmpConfig(StreamIcmpConfig *config, tSfPolicyId policy_id)
{
    if (config == NULL)
        return -1;

    if (!icmp_lws_cache)
        return -1;

    if (config->num_policies == 0)
        return -1;

    return 0;
}

int StreamProcessIcmp(Packet *p, SessionControlBlock *scb) 
{
#ifdef LYC_MODULE
    PROFILE_VARS;

    PREPROC_PROFILE_START( s5IcmpPerfStats);
    StreamIcmpPolicy *policy = scb->proto_policy;
    if (scb->proto_policy == NULL)
    {
        scb->proto_policy = ( ( StreamConfig * ) scb->stream_config )->icmp_config;
        policy = (StreamIcmpPolicy *)scb->proto_policy;
    }

    if (scb->session_established == false)
    {
        s5stats.active_icmp_sessions++;
        scb->session_established = true;
    }
    if (likely(policy))
        session_api->set_expire_timer(p, scb, policy->session_timeout);
    PREPROC_PROFILE_END( s5IcmpPerfStats );
#endif
    return 0;
}

#ifdef SNORT_RELOAD
void SessionICMPReload(uint32_t max_sessions, uint16_t pruningTimeout, uint16_t nominalTimeout)
{
    SessionReload(icmp_lws_cache, max_sessions, pruningTimeout, nominalTimeout
#ifdef REG_TEST
            , "ICMP"
#endif
            );
}

unsigned SessionICMPReloadAdjust(unsigned maxWork)
{
    return SessionProtocolReloadAdjust(icmp_lws_cache, session_configuration->max_icmp_sessions, 
            maxWork, 0
#ifdef REG_TEST
            , "ICMP"
#endif
            );
}
#endif

size_t get_icmp_used_mempool()
{
    if (icmp_lws_cache && icmp_lws_cache->protocol_session_pool)
        return icmp_lws_cache->protocol_session_pool->used_memory;

    return 0;
}
