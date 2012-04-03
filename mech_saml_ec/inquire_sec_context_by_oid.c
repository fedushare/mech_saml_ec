/*
 * Copyright (c) 2011, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Return extended properties of a context handle.
 */

#include "gssapiP_eap.h"

static void
zeroAndReleaseBufferSet(gss_buffer_set_t *dataSet)
{
    OM_uint32 tmpMinor;
    gss_buffer_set_t set = *dataSet;
    size_t i;

    if (set == GSS_C_NO_BUFFER_SET)
        return;

    for (i = 0; i <set->count; i++)
        memset(set->elements[i].value, 0, set->elements[i].length);

    gss_release_buffer_set(&tmpMinor, dataSet);
}

static OM_uint32
inquireSessionKey(OM_uint32 *minor,
                  const gss_ctx_id_t ctx,
                  const gss_OID desired_object GSSEAP_UNUSED,
                  gss_buffer_set_t *dataSet)
{
    OM_uint32 major;
    gss_buffer_desc buf;

    major = GSS_S_UNAVAILABLE;
    *minor = GSSEAP_KEY_UNAVAILABLE;
    if (GSS_ERROR(major))
        zeroAndReleaseBufferSet(dataSet);

    return major;
}

static OM_uint32
inquireNegoExKey(OM_uint32 *minor,
                  const gss_ctx_id_t ctx,
                  const gss_OID desired_object,
                  gss_buffer_set_t *dataSet)
{
    OM_uint32 major, tmpMinor;
    int bInitiatorKey;
    gss_buffer_desc salt;
    gss_buffer_desc key = GSS_C_EMPTY_BUFFER;
    size_t keySize;

    bInitiatorKey = CTX_IS_INITIATOR(ctx);

    major = GSS_S_UNAVAILABLE;
    *minor = GSSEAP_KEY_UNAVAILABLE;

    if (key.value != NULL) {
        memset(key.value, 0, key.length);
        gss_release_buffer(&tmpMinor, &key);
    }
    if (GSS_ERROR(major))
        zeroAndReleaseBufferSet(dataSet);

    return major;
}

static struct {
    gss_OID_desc oid;
    OM_uint32 (*inquire)(OM_uint32 *, const gss_ctx_id_t,
                         const gss_OID, gss_buffer_set_t *);
} inquireCtxOps[] = {
    {
        /* GSS_C_INQ_SSPI_SESSION_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05" },
        inquireSessionKey
    },
    {
        /* GSS_C_INQ_NEGOEX_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x06" },
        inquireNegoExKey
    },
    {
        /* GSS_C_INQ_NEGOEX_VERIFY_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x07" },
        inquireNegoExKey
    },
};

OM_uint32 GSSAPI_CALLCONV
gss_inquire_sec_context_by_oid(OM_uint32 *minor,
                               const gss_ctx_id_t ctx,
                               const gss_OID desired_object,
                               gss_buffer_set_t *data_set)
{
    OM_uint32 major;
    int i;

    *data_set = GSS_C_NO_BUFFER_SET;

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

#if 0
    if (!CTX_IS_ESTABLISHED(ctx)) {
        *minor = GSSEAP_CONTEXT_INCOMPLETE;
        major = GSS_S_NO_CONTEXT;
        goto cleanup;
    }
#endif

    major = GSS_S_UNAVAILABLE;
    *minor = GSSEAP_BAD_CONTEXT_OPTION;

    for (i = 0; i < sizeof(inquireCtxOps) / sizeof(inquireCtxOps[0]); i++) {
        if (oidEqual(&inquireCtxOps[i].oid, desired_object)) {
            major = (*inquireCtxOps[i].inquire)(minor, ctx,
                                                 desired_object, data_set);
            break;
        }
    }

    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
