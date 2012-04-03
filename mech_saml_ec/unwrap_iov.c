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
 * Message protection services: unwrap with scatter-gather API.
 */

#include "gssapiP_eap.h"

int
rotateLeft(void *ptr, size_t bufsiz, size_t rc)
{
    void *tbuf;

    if (bufsiz == 0)
        return 0;
    rc = rc % bufsiz;
    if (rc == 0)
        return 0;

    tbuf = GSSEAP_MALLOC(rc);
    if (tbuf == NULL)
        return ENOMEM;

    memcpy(tbuf, ptr, rc);
    memmove(ptr, (char *)ptr + rc, bufsiz - rc);
    memcpy((char *)ptr + bufsiz - rc, tbuf, rc);
    GSSEAP_FREE(tbuf);

    return 0;
}

/*
 * Split a STREAM | SIGN_DATA | DATA into
 *         HEADER | SIGN_DATA | DATA | PADDING | TRAILER
 */
static OM_uint32
unwrapStream(OM_uint32 *minor,
             gss_ctx_id_t ctx,
             int *conf_state,
             gss_qop_t *qop_state,
             gss_iov_buffer_desc *iov,
             int iov_count,
             enum gss_eap_token_type toktype)
{
    unsigned char *ptr;
    OM_uint32 code = 0, major = GSS_S_FAILURE;
    int conf_req_flag;
    int i = 0, j;
    gss_iov_buffer_desc *tiov = NULL;
    gss_iov_buffer_t stream, data = NULL;
    gss_iov_buffer_t theader, tdata = NULL, tpadding, ttrailer;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
#endif

    GSSEAP_ASSERT(toktype == TOK_TYPE_WRAP);

    if (toktype != TOK_TYPE_WRAP) {
        code = GSSEAP_WRONG_TOK_ID;
        goto cleanup;
    }

    stream = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_STREAM);
    GSSEAP_ASSERT(stream != NULL);

    if (stream->buffer.length < 16) {
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    ptr = (unsigned char *)stream->buffer.value;
    ptr += 2; /* skip token type */

    tiov = (gss_iov_buffer_desc *)GSSEAP_CALLOC((size_t)iov_count + 2,
                                                sizeof(gss_iov_buffer_desc));
    if (tiov == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    /* HEADER */
    theader = &tiov[i++];
    theader->type = GSS_IOV_BUFFER_TYPE_HEADER;
    theader->buffer.value = stream->buffer.value;
    theader->buffer.length = 16;

    /* n[SIGN_DATA] | DATA | m[SIGN_DATA] */
    for (j = 0; j < iov_count; j++) {
        OM_uint32 type = GSS_IOV_BUFFER_TYPE(iov[j].type);

        if (type == GSS_IOV_BUFFER_TYPE_DATA) {
            if (data != NULL) {
                /* only a single DATA buffer can appear */
                code = GSSEAP_BAD_STREAM_IOV;
                goto cleanup;
            }

            data = &iov[j];
            tdata = &tiov[i];
        }
        if (type == GSS_IOV_BUFFER_TYPE_DATA ||
            type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            tiov[i++] = iov[j];
    }

    if (data == NULL) {
        /* a single DATA buffer must be present */
        code = GSSEAP_BAD_STREAM_IOV;
        goto cleanup;
    }

    /* PADDING | TRAILER */
    tpadding = &tiov[i++];
    tpadding->type = GSS_IOV_BUFFER_TYPE_PADDING;
    tpadding->buffer.length = 0;
    tpadding->buffer.value = NULL;

    ttrailer = &tiov[i++];
    ttrailer->type = GSS_IOV_BUFFER_TYPE_TRAILER;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_init(krbContext, &ctx->rfc3961Key, ETYPE_NULL, &krbCrypto);
    if (code != 0)
        goto cleanup;
#endif

    {
        size_t ec, rrc;
        size_t krbHeaderLen = 0;
        size_t krbTrailerLen = 0;

        conf_req_flag = ((ptr[0] & TOK_FLAG_WRAP_CONFIDENTIAL) != 0);
        ec = conf_req_flag ? load_uint16_be(ptr + 2) : 0;
        rrc = load_uint16_be(ptr + 4);

        if (rrc != 0) {
            code = rotateLeft((unsigned char *)stream->buffer.value + 16,
                              stream->buffer.length - 16, rrc);
            if (code != 0)
                goto cleanup;
            store_uint16_be(0, ptr + 4); /* set RRC to zero */
        }

        if (conf_req_flag) {
            theader->buffer.length += krbHeaderLen; /* length validated later */
        }

        ttrailer->buffer.length = ec + (conf_req_flag ? 16 : 0 /* E(Header) */) +
                                  krbTrailerLen;
        ttrailer->buffer.value = (unsigned char *)stream->buffer.value +
            stream->buffer.length - ttrailer->buffer.length;
    }

    /* IOV: -----------0-------------+---1---+--2--+----------------3--------------*/
    /* CFX: GSS-Header | Kerb-Header | Data  |     | EC | E(Header) | Kerb-Trailer */
    /* GSS: -------GSS-HEADER--------+-DATA--+-PAD-+----------GSS-TRAILER----------*/

    /* validate lengths */
    if (stream->buffer.length < theader->buffer.length +
        tpadding->buffer.length +
        ttrailer->buffer.length) {
        major = GSS_S_DEFECTIVE_TOKEN;
        code = GSSEAP_TOK_TRUNC;
        goto cleanup;
    }

    /* setup data */
    tdata->buffer.length = stream->buffer.length - ttrailer->buffer.length -
        tpadding->buffer.length - theader->buffer.length;

    GSSEAP_ASSERT(data != NULL);

    if (data->type & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
        code = gssEapAllocIov(tdata, tdata->buffer.length);
        if (code != 0)
            goto cleanup;

        memcpy(tdata->buffer.value,
               (unsigned char *)stream->buffer.value + theader->buffer.length,
               tdata->buffer.length);
    } else {
        tdata->buffer.value = (unsigned char *)stream->buffer.value +
                              theader->buffer.length;
    }

    GSSEAP_ASSERT(i <= iov_count + 2);

    *data = *tdata;

cleanup:
    if (tiov != NULL)
        GSSEAP_FREE(tiov);
#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
#endif

    *minor = code;

    return major;
}

OM_uint32
gssEapUnwrapOrVerifyMIC(OM_uint32 *minor,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_eap_token_type toktype)
{
    OM_uint32 major;

    *minor = GSSEAP_KEY_UNAVAILABLE;
    return GSS_S_UNAVAILABLE;
}

OM_uint32 GSSAPI_CALLCONV
gss_unwrap_iov(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               int *conf_state,
               gss_qop_t *qop_state,
               gss_iov_buffer_desc *iov,
               int iov_count)
{
    OM_uint32 major;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    *minor = 0;

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSEAP_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    major = gssEapUnwrapOrVerifyMIC(minor, ctx, conf_state, qop_state,
                                    iov, iov_count, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
