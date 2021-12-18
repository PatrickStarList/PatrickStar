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
#include "detection_lib_meta.h"

/* declare detection functions */
int rule1915eval(void *p);
char *hex(u_char *, int);

/* declare rule data structures */
/* precompile the stuff that needs pre-compiled */
/* content for sid 1915 */
// content:"|00 01 86 B8|", offset 12, depth 4;
static ContentInfo rule1915content1 =
{
    (u_int8_t *)("|00 01 86 B8|"), /* pattern (now in PatrickStar content format) */
    4, /* depth */
    12, /* offset */
    CONTENT_BUF_NORMALIZED, /* flags */ // XXX - need to add CONTENT_FAST_PATTERN support
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

static RuleOption rule1915option1 =
{
    OPTION_TYPE_CONTENT,
    { &rule1915content1 }
};

/* references for sid 1915 */
static RuleReference *rule1915refs[] =
{
    NULL
};

RuleOption *rule1915options[] =
{
    &rule1915option1,
    NULL
};

Rule rule1915 = {

   /* rule header, akin to => tcp any any -> any any               */{
       IPPROTO_UDP, /* proto */
       "$EXTERNAL_NET", /* SRCIP     */
       "any", /* SRCPORT   */
       0, /* DIRECTION */
       "$HOME_NET", /* DSTIP     */
       "any", /* DSTPORT   */
   },
   /* metadata */
   {
       RULE_GID,  /* genid (HARDCODED!!!) */
       1915, /* sigid */
       9, /* revision */

       "attempted-admin", /* classification */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       "RPC STATD UDP monitor mon_name format string exploit attempt",     /* message */
       rule1915refs, /* ptr to references */
       NULL /* Meta data */
   },
   rule1915options, /* ptr to rule options */
    NULL,                               /* Use internal eval func */
    0,                                  /* Not initialized */
    0,                                  /* Rule option count, used internally */
    0,                                  /* Flag with no alert, used internally */
    NULL /* ptr to internal data... setup during rule registration */
};

#if 0
char *hex(u_char *xdata, int length)
{
    int x;
    char *rval;
    char *buf;

    buf = (char *)malloc(length * 2 + 1);
    if (buf == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to allocate memory\n");
    }

    rval = buf;

    for(x=0; x < length; x++)
    {
        snprintf(buf, 3, "%02X", xdata[x]);
        buf += 2;
    }

    rval[length * 2] = '\0';

    return rval;
}
#endif

/* detection functions */

int rule1915eval(void *p) {
    /* cursors, formally known as doe_ptr */
    const u_int8_t *cursor_normal = 0;

    //SFSnortPacket *sp = (SFSnortPacket *) p;

    // content:"|00 01 86 B8|", offset 12, depth 4;
    if (contentMatch(p, rule1915options[0]->option_u.content, &cursor_normal) > 0) {
        return RULE_MATCH;
    }
    return RULE_NOMATCH;
}
