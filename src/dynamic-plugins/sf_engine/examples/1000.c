/*
 * VRT RULES
 *
 * Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This file is autogenerated via rules2c, by Brian Caswell <bmc@sourcefire.com>
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_PatrickStar_plugin_api.h"
#include "sf_PatrickStar_packet.h"


/* declare detection functions */
int rule1000eval(void *p);

/* declare rule data structures */
/* precompile the stuff that needs pre-compiled */
/* flow:established, to_server; */
static FlowFlags rule1000flow0 =
{
    FLOW_ESTABLISHED|FLOW_TO_SERVER
};

static RuleOption rule1000option0 =
{
    OPTION_TYPE_FLOWFLAGS,
    { &rule1000flow0 }
};
// content:"/bdir.htr", payload uri, nocase, relative;
static ContentInfo rule1000content1 =
{
    (u_int8_t *)("/bdir.htr"), /* pattern (now in PatrickStar content format) */
    0, /* depth */
    0, /* offset */
    CONTENT_NOCASE|CONTENT_RELATIVE|CONTENT_BUF_URI, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0, /* increment length*/
    0,                      /* holder for fp offset */
    0,                      /* holder for fp length */
    0,                      /* holder for fp only */
    NULL, // offset_refId
    NULL, // depth_refId
    NULL, // offset_location
    NULL  // depth_location
};

static RuleOption rule1000option1 =
{
    OPTION_TYPE_CONTENT,
    { &rule1000content1 }
};

/* references for.ruleid 1000 */
/* reference:bugtraq "2280"; */
static RuleReference rule1000ref1 =
{
    "bugtraq", /* type */
    "2280" /* value */
};

/* reference:nessus "10577"; */
static RuleReference rule1000ref2 =
{
    "nessus", /* type */
    "10577" /* value */
};

static RuleReference *rule1000refs[] =
{
    &rule1000ref1,
    &rule1000ref2,
    NULL
};

static RuleMetaData rule1000meta1 =
{
    "service http"
};

static RuleMetaData *rule1000meta[] =
{
    &rule1000meta1,
    NULL
};

RuleOption *rule1000options[] =
{
    &rule1000option0,
    &rule1000option1,
    NULL
};

Rule rule1000 = {
   /* rule header, akin to => tcp any any -> any any */
   {
       IPPROTO_TCP, /* proto */
       "$EXTERNAL_NET", /* SRCIP     */
       "any", /* SRCPORT   */
       0, /* DIRECTION */
       "$HTTP_SERVERS", /* DSTIP     */
       "$HTTP_PORTS", /* DSTPORT   */
   },
   /* metadata */
   {
       3,  /* genid (HARDCODED!!!) */
       1000, /* sigid */
       12, /* revision */

       "web-application-activity", /* classification */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "WEB-IIS bdir.htr access",     /* message */
       rule1000refs, /* ptr to references */
       rule1000meta /* Meta data */
   },
   rule1000options, /* ptr to rule options */
   NULL, // &rule1000eval, /* use the built in detection function */
   0, /* am I initialized yet? */
   0, /* number of options */
   0,  /* don't alert */
   NULL /* ptr to internal data... setup during rule registration */
};


/* detection functions */
int rule1000eval(void *p) {
    const u_int8_t *cursor_uri = 0;
    //const u_int8_t *cursor_raw = 0;
    //const u_int8_t *cursor_normal = 0;


    // flow:established, to_server;
    if (checkFlow(p, rule1000options[0]->option_u.flowFlags) > 0 ) {
        // content:"/bdir.htr", payload uri, nocase, relative;
        if (contentMatch(p, rule1000options[1]->option_u.content, &cursor_uri) > 0) {
            return RULE_MATCH;
        }
    }
    return RULE_NOMATCH;
}
