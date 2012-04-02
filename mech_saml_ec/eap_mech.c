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
 * Initialisation and finalise functions.
 */

#include "gssapiP_eap.h"

void gssEapFinalize(void) GSSEAP_DESTRUCTOR;

OM_uint32
gssEapInitiatorInit(OM_uint32 *minor)
{
    OM_uint32 major;

    initialize_eapg_error_table();

    *minor = 0;
    return GSS_S_COMPLETE;
}

void
gssEapFinalize(void)
{
#ifdef GSSEAP_ENABLE_ACCEPTOR
    OM_uint32 minor;

    gssEapAttrProvidersFinalize(&minor);
#endif
#ifdef MECH_EAP
    eap_peer_unregister_methods();
#endif
}

#ifdef GSSEAP_CONSTRUCTOR
static void gssEapInitiatorInitAssert(void) GSSEAP_CONSTRUCTOR;

static void
gssEapInitiatorInitAssert(void)
{
    OM_uint32 major, minor;

    major = gssEapInitiatorInit(&minor);

    GSSEAP_ASSERT(!GSS_ERROR(major));
}
#endif
