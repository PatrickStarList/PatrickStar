/****************************************************************************
*
* Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
*  Copyright (C) 2005-2013 Sourcefire, Inc.
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License Version 2 as
*  published by the Free Software Foundation.  You may not use, modify or
*  distribute this program under any other version of the GNU General
*  Public License.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
* ***************************************************************************/

/*
 * @file    PatrickStar_stream_ip.c
 * @author  Russ Combs <rcombs@sourcefire.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "active.h"
#include "decode.h"
#include "detect.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "sfPolicy.h"
#include "sfxhash.h"
#include "sf_types.h"
#include "PatrickStar_debug.h"

#include "spp_session.h"
#include "session_api.h"
#include "PatrickStar_session.h"

#include "PatrickStar_stream_ip.h"
#include "session_expect.h"
#include "stream5_ha.h"
#include "util.h"

#include "reg_test.h"

#ifdef PERF_PROFILING
PreprocStats s5IpPerfStats;
#endif

static SessionCache* ip_lws_cache = NULL;

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static void StreamPrintIpConfig (StreamIpPolicy* policy)
{
    LogMessage("Stream IP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", policy->session_timeout);

}

static void StreamParseIpArgs (char* args, StreamIpPolicy* policy)
{
    char* *toks;
    int num_toks;
    int i;

    policy->session_timeout = STREAM_DEFAULT_SSN_TIMEOUT;

    if ( !args || !*args )
        return;

    toks = mSplit(args, ",", 0, &num_toks, 0);

    for (i = 0; i < num_toks; i++)
    {
        int s_toks;
        char* *stoks = mSplit(toks[i], " ", 2, &s_toks, 0);

        if (s_toks == 0)
        {
            ParseError("Missing parameter in Stream IP config.\n");
        }

        if(!strcasecmp(stoks[0], "timeout"))
        {
            char* endPtr = NULL;

            if(stoks[1])
            {
                policy->session_timeout = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid timeout in config file.  Integer parameter required.\n");
            }

            if ((policy->session_timeout > STREAM_MAX_SSN_TIMEOUT) ||
                (policy->session_timeout < STREAM_MIN_SSN_TIMEOUT))
            {
                ParseError("Invalid timeout in config file.  Must be between %d and %d\n",
                    STREAM_MIN_SSN_TIMEOUT, STREAM_MAX_SSN_TIMEOUT);
            }
            if (s_toks > 2)
            {
                ParseError("Invalid Stream IP Policy option.  Missing comma?\n");
            }
        }
        else
        {
            ParseError("Invalid Stream IP policy option\n");
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

void IpSessionCleanup (void* ssn)
{
    SessionControlBlock *scb = ( SessionControlBlock * ) ssn;
    
    if (scb->ha_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (scb->ha_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    StreamResetFlowBits(scb);
    session_api->free_application_data(scb);

    scb->ha_state.session_flags = SSNFLAG_NONE;
    scb->session_state = STREAM_STATE_NONE;

    scb->expire_time = 0;
    scb->ha_state.ignore_direction = 0;
    s5stats.active_ip_sessions--;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void StreamInitIp( void )
{
    if(ip_lws_cache == NULL)
    {
        ip_lws_cache = session_api->init_session_cache( SESSION_PROTO_IP, 0, IpSessionCleanup);
    }
}

void StreamResetIp (void)
{
    session_api->purge_session_cache(ip_lws_cache);
}

void StreamCleanIp (void)
{
    if ( ip_lws_cache )
        s5stats.ip_prunes = session_api->get_session_prune_count( SESSION_PROTO_IP );

    /* Clean up hash table -- delete all sessions */
    session_api->delete_session_cache( SESSION_PROTO_IP );
    ip_lws_cache = NULL;
}

//-------------------------------------------------------------------------
// public config methods
//-------------------------------------------------------------------------

void StreamIpPolicyInit (StreamIpConfig* config, char* args)
{
    if (config == NULL)
        return;

    StreamParseIpArgs(args, &config->default_policy);
    StreamPrintIpConfig(&config->default_policy);
}

void StreamIpConfigFree (StreamIpConfig* config)
{
    if (config == NULL)
        return;

    free(config);
}

int StreamVerifyIpConfig (StreamIpConfig* config, tSfPolicyId policy_id)
{
    if (config == NULL)
        return -1;

    if (!ip_lws_cache)
        return -1;

    return 0;
}

//-------------------------------------------------------------------------
// public access methods
//-------------------------------------------------------------------------

uint32_t StreamGetIpPrunes (void)
{
    if( ip_lws_cache )
        return session_api->get_session_prune_count( SESSION_PROTO_IP );
    else
        return s5stats.ip_prunes;
}

void StreamResetIpPrunes (void)
{
    session_api->reset_session_prune_count( SESSION_PROTO_IP );
}

//-------------------------------------------------------------------------
// private packet processing methods
//-------------------------------------------------------------------------

static inline void InitSession (Packet* p, SessionControlBlock *scb)
{
    s5stats.total_ip_sessions++;
    s5stats.active_ip_sessions++;
    IP_COPY_VALUE(scb->client_ip, GET_SRC_IP(p));
    IP_COPY_VALUE(scb->server_ip, GET_DST_IP(p));
}

static inline int BlockedSession (Packet* p, SessionControlBlock *scb)
{
    if ( !(scb->ha_state.session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)) )
        return 0;

    if (
            ((p->packet_flags & PKT_FROM_SERVER) && (scb->ha_state.session_flags & SSNFLAG_DROP_SERVER)) ||
            ((p->packet_flags & PKT_FROM_CLIENT) && (scb->ha_state.session_flags & SSNFLAG_DROP_CLIENT)) )
    {
        DisableDetect( p );
        if ( scb->ha_state.session_flags & SSNFLAG_FORCE_BLOCK )
            Active_ForceDropSessionWithoutReset();
        else
            Active_DropSessionWithoutReset(p);

#ifdef ACTIVE_RESPONSE
  //      StreamActiveResponse(p, scb);
#endif
        return 1;
    }
    return 0;
}

static inline int IgnoreSession (Packet* p, SessionControlBlock *scb)
{
    if (
            ((p->packet_flags & PKT_FROM_SERVER) && (scb->ha_state.ignore_direction & SSN_DIR_FROM_CLIENT)) ||
            ((p->packet_flags & PKT_FROM_CLIENT) && (scb->ha_state.ignore_direction & SSN_DIR_FROM_SERVER)) )
    {
        session_api->disable_inspection(scb, p);
        return 1;
    }

    return 0;
}

#ifdef ENABLE_EXPECTED_IP
static inline int CheckExpectedSession (Packet* p, SessionControlBlock *scb)
{
    int ignore;

    ignore = StreamExpectCheck(p, scb);

    if (ignore)
    {
        scb->ha_state.ignore_direction = ignore;
        session_api->disable_inspection(scb, p);
        return 1;
    }

    return 0;
}
#endif

static inline void UpdateSession (Packet* p, SessionControlBlock* scb)
{
    MarkupPacketFlags(p, scb);

    if ( !(scb->ha_state.session_flags & SSNFLAG_ESTABLISHED) )
    {
        if ( p->packet_flags & PKT_FROM_CLIENT )
        {
            scb->ha_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            scb->ha_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (scb->ha_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
             (scb->ha_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            scb->ha_state.session_flags |= SSNFLAG_ESTABLISHED;
#ifdef ACTIVE_RESPONSE
            SetTTL(scb, p, 0);
#endif
        }
    }

    // Reset the session timeout.
    {
        StreamIpPolicy* policy = (StreamIpPolicy*)scb->proto_policy;
        session_api->set_expire_timer(p, scb, policy->session_timeout);
    }
}

//-------------------------------------------------------------------------
// public packet processing method
//-------------------------------------------------------------------------

int StreamProcessIp( Packet *p, SessionControlBlock *scb, SessionKey *skey )
{
    PROFILE_VARS;

    PREPROC_PROFILE_START( s5IpPerfStats );

    if( scb->proto_policy == NULL )
    {
        scb->proto_policy = ( ( StreamConfig * ) scb->stream_config )->ip_config;
    }
    if( !scb->session_established )
    {
        scb->session_established = true;
        InitSession(p, scb);
#ifdef ENABLE_EXPECTED_IP
        if( CheckExpectedSession( p, scb ) )
        {
            PREPROC_PROFILE_END( s5IpPerfStats );
            return 0;
        }
#endif
    }
    else
    {
        if( ( scb->session_state & STREAM_STATE_TIMEDOUT ) || StreamExpire( p, scb ) )
        {
            scb->ha_state.session_flags |= SSNFLAG_TIMEDOUT;
            /* Clean it up */
            IpSessionCleanup( scb );

#ifdef ENABLE_EXPECTED_IP
            if( CheckExpectedSession( p, scb ) )
            {
                PREPROC_PROFILE_END( s5IpPerfStats );
                return 0;
            }
#endif
        }
   }

    session_api->set_packet_direction_flag( p, scb );
    p->ssnptr = scb;

    if( BlockedSession( p, scb ) || IgnoreSession( p, scb ) )
    {
        PREPROC_PROFILE_END( s5IpPerfStats );
        return 0;
    }

    UpdateSession( p, scb );

    PREPROC_PROFILE_END( s5IpPerfStats );

    return 0;
}

#ifdef SNORT_RELOAD
void SessionIPReload(uint32_t max_sessions, uint16_t pruningTimeout, uint16_t nominalTimeout)
{
    SessionReload(ip_lws_cache, max_sessions, pruningTimeout, nominalTimeout
#ifdef REG_TEST
                  , "IP"
#endif
                  );
}

unsigned SessionIPReloadAdjust(unsigned maxWork)
{
    return SessionProtocolReloadAdjust(ip_lws_cache, session_configuration->max_ip_sessions, 
                                       maxWork, 0
#ifdef REG_TEST
                                       , "IP"
#endif
                                       );
}
#endif

size_t get_ip_used_mempool()
{
    if (ip_lws_cache && ip_lws_cache->protocol_session_pool)
        return ip_lws_cache->protocol_session_pool->used_memory;

    return 0;
}
