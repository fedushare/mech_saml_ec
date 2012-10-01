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
 * Local authorization services.
 */

#include "gssapiP_eap.h"

OM_uint32 GSSAPI_CALLCONV
gssspi_authorize_localname(OM_uint32 *minor,
                           const gss_name_t name,
                           gss_const_buffer_t local_user,
                           gss_const_OID local_nametype)
{
    *minor = 0;

    if ((name != NULL) &&
	(name->username.value != NULL) &&
	(local_user != NULL) &&
	(local_user->value != NULL)) {

      if ((name->username.length == local_user->length) &&
	  !strncmp(name->username.value, local_user->value, local_user->length)) {
          if (MECH_SAML_EC_DEBUG) {
              char *s_name = calloc(name->username.length+1, sizeof(char));
              snprintf(s_name, name->username.length, "%s", (char*)name->username.value);
              char *s_local_user = calloc(local_user->length+1, sizeof(char));
              snprintf(s_local_user, local_user->length, "%s", (char*)local_user->value);
              fprintf(stderr, "gssspi_authorize_localname: Success comparing "
                      "LENGTHS(%d)(%d) NAMES(%s)(%s)\n", name->username.length,
                      local_user->length, s_name, s_local_user);
          }

	return GSS_S_COMPLETE;

      } else {
          char *s_name = calloc(name->username.length+1, sizeof(char));
          snprintf(s_name, name->username.length, "%s", (char*)name->username.value);
          char *s_local_user = calloc(local_user->length+1, sizeof(char));
          snprintf(s_local_user, local_user->length, "%s", (char*)local_user->value);
          fprintf(stderr, "gssspi_authorize_localname: Failure comparing "
                  "LENGTHS(%d)(%d) NAMES(%s)(%s)\n", name->username.length,
                  local_user->length, s_name, s_local_user);
      }
    }

    return GSS_S_UNAUTHORIZED;
}
