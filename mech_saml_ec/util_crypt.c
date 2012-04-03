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
 * Copyright 2001, 2008 by the Massachusetts Institute of Technology.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Message protection services: cryptography helpers.
 */

#include "gssapiP_eap.h"

gss_iov_buffer_t
gssEapLocateIov(gss_iov_buffer_desc *iov, int iov_count, OM_uint32 type)
{
    int i;
    gss_iov_buffer_t p = GSS_C_NO_IOV_BUFFER;

    if (iov == GSS_C_NO_IOV_BUFFER)
        return GSS_C_NO_IOV_BUFFER;

    for (i = iov_count - 1; i >= 0; i--) {
        if (GSS_IOV_BUFFER_TYPE(iov[i].type) == type) {
            if (p == GSS_C_NO_IOV_BUFFER)
                p = &iov[i];
            else
                return GSS_C_NO_IOV_BUFFER;
        }
    }

    return p;
}

void
gssEapIovMessageLength(gss_iov_buffer_desc *iov,
                       int iov_count,
                       size_t *data_length_p,
                       size_t *assoc_data_length_p)
{
    int i;
    size_t data_length = 0, assoc_data_length = 0;

    GSSEAP_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    *data_length_p = *assoc_data_length_p = 0;

    for (i = 0; i < iov_count; i++) {
        OM_uint32 type = GSS_IOV_BUFFER_TYPE(iov[i].type);

        if (type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            assoc_data_length += iov[i].buffer.length;

        if (type == GSS_IOV_BUFFER_TYPE_DATA ||
            type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            data_length += iov[i].buffer.length;
    }

    *data_length_p = data_length;
    *assoc_data_length_p = assoc_data_length;
}

void
gssEapReleaseIov(gss_iov_buffer_desc *iov, int iov_count)
{
    int i;
    OM_uint32 min_stat;

    GSSEAP_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    for (i = 0; i < iov_count; i++) {
        if (iov[i].type & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
            gss_release_buffer(&min_stat, &iov[i].buffer);
            iov[i].type &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
        }
    }
}

int
gssEapIsIntegrityOnly(gss_iov_buffer_desc *iov, int iov_count)
{
    int i;
    int has_conf_data = 0;

    GSSEAP_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    for (i = 0; i < iov_count; i++) {
        if (GSS_IOV_BUFFER_TYPE(iov[i].type) == GSS_IOV_BUFFER_TYPE_DATA) {
            has_conf_data = 1;
            break;
        }
    }

    return (has_conf_data == 0);
}

int
gssEapAllocIov(gss_iov_buffer_t iov, size_t size)
{
    GSSEAP_ASSERT(iov != GSS_C_NO_IOV_BUFFER);
    GSSEAP_ASSERT(iov->type & GSS_IOV_BUFFER_FLAG_ALLOCATE);

    iov->buffer.length = size;
    iov->buffer.value = GSSEAP_MALLOC(size);
    if (iov->buffer.value == NULL) {
        iov->buffer.length = 0;
        return ENOMEM;
    }

    iov->type |= GSS_IOV_BUFFER_FLAG_ALLOCATED;

    return 0;
}
