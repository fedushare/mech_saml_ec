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
 * Copyright 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Message protection services: wrap with scatter-gather API.
 */

#include "gssapiP_eap.h"

unsigned char
rfc4121Flags(gss_ctx_id_t ctx, int receiving)
{
    unsigned char flags;
    int isAcceptor;

    isAcceptor = !CTX_IS_INITIATOR(ctx);
    if (receiving)
        isAcceptor = !isAcceptor;

    flags = 0;
    if (isAcceptor)
        flags |= TOK_FLAG_SENDER_IS_ACCEPTOR;

    if ((ctx->flags & CTX_FLAG_KRB_REAUTH) &&
        (ctx->gssFlags & GSS_C_MUTUAL_FLAG))
        flags |= TOK_FLAG_ACCEPTOR_SUBKEY;

    return flags;
}

OM_uint32
gssEapWrapOrGetMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int conf_req_flag,
                   int *conf_state,
                   gss_iov_buffer_desc *iov,
                   int iov_count,
                   enum gss_eap_token_type toktype)
{
    *minor = GSSEAP_KEY_UNAVAILABLE;
    return GSS_S_UNAVAILABLE;
}

OM_uint32 GSSAPI_CALLCONV
gss_wrap_iov(OM_uint32 *minor,
             gss_ctx_id_t ctx,
             int conf_req_flag,
             gss_qop_t qop_req,
             int *conf_state,
             gss_iov_buffer_desc *iov,
             int iov_count)
{
    OM_uint32 major;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    if (qop_req != GSS_C_QOP_DEFAULT) {
        *minor = GSSEAP_UNKNOWN_QOP;
        return GSS_S_UNAVAILABLE;
    }

    *minor = 0;

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSEAP_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    major = gssEapWrapOrGetMIC(minor, ctx, conf_req_flag, conf_state,
                               iov, iov_count, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
