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
 * Establish a security context on the initiator (client). These functions
 * wrap around libeap.
 */

#include "gssapiP_eap.h"

#include <libxml/xmlreader.h>
#include <curl/curl.h>

#include <sys/types.h>
#include <pwd.h>

#define SAML_EC_IDP		"SAML_EC_IDP"
#define SAML_EC_USER_CERT	"SAML_EC_USER_CERT"
#define SAML_EC_USER_KEY	"SAML_EC_USER_KEY"

#define SOAP_FAULT_MSG "<?xml version='1.0' encoding='UTF-8'?>" \
		"<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">" \
		"  <S:Header/>" \
		"  <S:Body>" \
		"    <S:Fault>" \
		"      <faultcode>S:Server</faultcode>" \
		"      <faultstring>General Failure</faultstring>" \
		"    </S:Fault>" \
		"  </S:Body>" \
		"</S:Envelope>"

static xmlChar *gl_generated_key = NULL;

#ifdef MECH_EAP

static OM_uint32
policyVariableToFlag(enum eapol_bool_var variable)
{
    OM_uint32 flag = 0;

    switch (variable) {
    case EAPOL_eapSuccess:
        flag = CTX_FLAG_EAP_SUCCESS;
        break;
    case EAPOL_eapRestart:
        flag = CTX_FLAG_EAP_RESTART;
        break;
    case EAPOL_eapFail:
        flag = CTX_FLAG_EAP_FAIL;
        break;
    case EAPOL_eapResp:
        flag = CTX_FLAG_EAP_RESP;
        break;
    case EAPOL_eapNoResp:
        flag = CTX_FLAG_EAP_NO_RESP;
        break;
    case EAPOL_eapReq:
        flag = CTX_FLAG_EAP_REQ;
        break;
    case EAPOL_portEnabled:
        flag = CTX_FLAG_EAP_PORT_ENABLED;
        break;
    case EAPOL_altAccept:
        flag = CTX_FLAG_EAP_ALT_ACCEPT;
        break;
    case EAPOL_altReject:
        flag = CTX_FLAG_EAP_ALT_REJECT;
        break;
    }

    return flag;
}

static struct eap_peer_config *
peerGetConfig(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.eapPeerConfig;
}

static Boolean
peerGetBool(void *data, enum eapol_bool_var variable)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    flag = policyVariableToFlag(variable);

    return ((ctx->flags & flag) != 0);
}

static void
peerSetBool(void *data, enum eapol_bool_var variable,
            Boolean value)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    flag = policyVariableToFlag(variable);

    if (value)
        ctx->flags |= flag;
    else
        ctx->flags &= ~(flag);
}

static unsigned int
peerGetInt(void *data, enum eapol_int_var variable)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    GSSEAP_ASSERT(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        return ctx->initiatorCtx.idleWhile;
        break;
    }

    return 0;
}

static void
peerSetInt(void *data, enum eapol_int_var variable,
           unsigned int value)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    GSSEAP_ASSERT(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        ctx->initiatorCtx.idleWhile = value;
        break;
    }
}

static struct wpabuf *
peerGetEapReqData(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.reqData;
}

static void
peerSetConfigBlob(void *ctx GSSEAP_UNUSED,
                  struct wpa_config_blob *blob GSSEAP_UNUSED)
{
}

static const struct wpa_config_blob *
peerGetConfigBlob(void *ctx GSSEAP_UNUSED,
                  const char *name GSSEAP_UNUSED)
{
    return NULL;
}

static void
peerNotifyPending(void *ctx GSSEAP_UNUSED)
{
}

static struct eapol_callbacks gssEapPolicyCallbacks = {
    peerGetConfig,
    peerGetBool,
    peerSetBool,
    peerGetInt,
    peerSetInt,
    peerGetEapReqData,
    peerSetConfigBlob,
    peerGetConfigBlob,
    peerNotifyPending,
};

#ifdef GSSEAP_DEBUG
extern int wpa_debug_level;
#endif

static OM_uint32
peerConfigInit(OM_uint32 *minor, gss_ctx_id_t ctx)
{
    OM_uint32 major;
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;
    gss_buffer_desc identity = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc realm = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t cred = ctx->cred;

    eapPeerConfig->identity = NULL;
    eapPeerConfig->identity_len = 0;
    eapPeerConfig->anonymous_identity = NULL;
    eapPeerConfig->anonymous_identity_len = 0;
    eapPeerConfig->password = NULL;
    eapPeerConfig->password_len = 0;

    GSSEAP_ASSERT(cred != GSS_C_NO_CREDENTIAL);

    eapPeerConfig->fragment_size = 1024;
#ifdef GSSEAP_DEBUG
    wpa_debug_level = 0;
#endif

    GSSEAP_ASSERT(cred->name != GSS_C_NO_NAME);

    if ((cred->name->flags & (NAME_FLAG_NAI | NAME_FLAG_SERVICE)) == 0) {
        *minor = GSSEAP_BAD_INITIATOR_NAME;
        return GSS_S_BAD_NAME;
    }

    /* identity */
    major = gssEapDisplayName(minor, cred->name, &identity, NULL);
    if (GSS_ERROR(major))
        return major;

    eapPeerConfig->identity = (unsigned char *)identity.value;
    eapPeerConfig->identity_len = identity.length;

    krbPrincRealmToGssBuffer(cred->name->krbPrincipal, &realm);

    /* anonymous_identity */
    eapPeerConfig->anonymous_identity = GSSEAP_MALLOC(realm.length + 2);
    if (eapPeerConfig->anonymous_identity == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    eapPeerConfig->anonymous_identity[0] = '@';
    memcpy(eapPeerConfig->anonymous_identity + 1, realm.value, realm.length);
    eapPeerConfig->anonymous_identity[1 + realm.length] = '\0';
    eapPeerConfig->anonymous_identity_len = 1 + realm.length;

    /* password */
    eapPeerConfig->password = (unsigned char *)cred->password.value;
    eapPeerConfig->password_len = cred->password.length;

    /* certs */
    eapPeerConfig->ca_cert = (unsigned char *)cred->caCertificate.value;
    eapPeerConfig->subject_match = (unsigned char *)cred->subjectNameConstraint.value;
    eapPeerConfig->altsubject_match = (unsigned char *)cred->subjectAltNameConstraint.value;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
peerConfigFree(OM_uint32 *minor,
               gss_ctx_id_t ctx)
{
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;

    if (eapPeerConfig->identity != NULL) {
        GSSEAP_FREE(eapPeerConfig->identity);
        eapPeerConfig->identity = NULL;
        eapPeerConfig->identity_len = 0;
    }

    if (eapPeerConfig->anonymous_identity != NULL) {
        GSSEAP_FREE(eapPeerConfig->anonymous_identity);
        eapPeerConfig->anonymous_identity = NULL;
        eapPeerConfig->anonymous_identity_len = 0;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

#endif

/*
 * Mark an initiator context as ready for cryptographic operations
 */
static OM_uint32
initReady(OM_uint32 *minor, gss_ctx_id_t ctx, OM_uint32 reqFlags)
{
    OM_uint32 major;
    const unsigned char *key;
    size_t keyLength;

#ifdef MECH_EAP
#if 1
    /* XXX actually check for mutual auth */
    if (reqFlags & GSS_C_MUTUAL_FLAG)
        ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
#endif
    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed, &ctx->encryptionType);
#else
    /* encryption type already set in processSAMLRequest */
    GSSEAP_ASSERT(ctx->encryptionType != ENCTYPE_NULL);
#endif
    if (GSS_ERROR(major))
        return major;

#ifdef MECH_EAP
    if (!eap_key_available(ctx->initiatorCtx.eap)) {
        *minor = GSSEAP_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    key = eap_get_eapKeyData(ctx->initiatorCtx.eap, &keyLength);

    if (keyLength < EAP_EMSK_LEN) {
        *minor = GSSEAP_KEY_TOO_SHORT;
        return GSS_S_UNAVAILABLE;
    }

    major = gssEapDeriveRfc3961Key(minor,
                                   &key[EAP_EMSK_LEN / 2],
                                   EAP_EMSK_LEN / 2,
                                   ctx->encryptionType,
                                   &ctx->rfc3961Key);
#else
    major = gssEapDeriveRfc3961Key(minor,
                                   gl_generated_key,
                                   strlen(gl_generated_key),
                                   ctx->encryptionType,
                                   &ctx->rfc3961Key);
#endif
    if (GSS_ERROR(major))
        return major;

    major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                      &ctx->checksumType);
    if (GSS_ERROR(major))
        return major;

    major = sequenceInit(minor,
                         &ctx->seqState,
                         ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

#ifndef MECH_EAP
    ctx->gssFlags |= GSS_C_PROT_READY_FLAG;
#endif

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
initBegin(OM_uint32 *minor,
          gss_ctx_id_t ctx,
          gss_name_t target,
          gss_OID mech,
          OM_uint32 reqFlags GSSEAP_UNUSED,
          OM_uint32 timeReq,
          gss_channel_bindings_t chanBindings GSSEAP_UNUSED)
{
    OM_uint32 major;
    gss_cred_id_t cred = ctx->cred;

    GSSEAP_ASSERT(cred != GSS_C_NO_CREDENTIAL);

    if (cred->expiryTime)
        ctx->expiryTime = cred->expiryTime;
    else if (timeReq == 0 || timeReq == GSS_C_INDEFINITE)
        ctx->expiryTime = 0;
    else
        ctx->expiryTime = time(NULL) + timeReq;

    /*
     * The credential mutex protects its name, however we need to
     * explicitly lock the acceptor name (unlikely as it may be
     * that it has attributes set on it).
     */
    major = gssEapDuplicateName(minor, cred->name, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (target != GSS_C_NO_NAME) {
        GSSEAP_MUTEX_LOCK(&target->mutex);

        major = gssEapDuplicateName(minor, target, &ctx->acceptorName);
        if (GSS_ERROR(major)) {
            GSSEAP_MUTEX_UNLOCK(&target->mutex);
            return major;
        }
        if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "TARGET NAME IS (%.*s)\n",
                    target->username.length,  (char *)(target->username.value));

        GSSEAP_MUTEX_UNLOCK(&target->mutex);
    }

    major = gssEapCanonicalizeOid(minor,
                                  mech,
                                  OID_FLAG_NULL_VALID | OID_FLAG_MAP_NULL_TO_DEFAULT_MECH,
                                  &ctx->mechanismUsed);
    if (GSS_ERROR(major))
        return major;

    /* If credentials were provided, check they're usable with this mech */
    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
        *minor = GSSEAP_CRED_MECH_MISMATCH;
        return GSS_S_BAD_MECH;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmInitError(OM_uint32 *minor,
                  gss_cred_id_t cred GSSEAP_UNUSED,
                  gss_ctx_id_t ctx GSSEAP_UNUSED,
                  gss_name_t target GSSEAP_UNUSED,
                  gss_OID mech GSSEAP_UNUSED,
                  OM_uint32 reqFlags GSSEAP_UNUSED,
                  OM_uint32 timeReq GSSEAP_UNUSED,
                  gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                  gss_buffer_t inputToken,
                  gss_buffer_t outputToken GSSEAP_UNUSED,
                  OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;
    unsigned char *p;

    if (inputToken->length < 8) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    p = (unsigned char *)inputToken->value;

    major = load_uint32_be(&p[0]);
    *minor = ERROR_TABLE_BASE_eapg + load_uint32_be(&p[4]);

    if (!GSS_ERROR(major) || !IS_WIRE_ERROR(*minor)) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_BAD_ERROR_TOKEN;
    }

    GSSEAP_ASSERT(GSS_ERROR(major));

    return major;
}

#ifdef GSSEAP_DEBUG
static OM_uint32
eapGssSmInitVendorInfo(OM_uint32 *minor,
                       gss_cred_id_t cred GSSEAP_UNUSED,
                       gss_ctx_id_t ctx GSSEAP_UNUSED,
                       gss_name_t target GSSEAP_UNUSED,
                       gss_OID mech GSSEAP_UNUSED,
                       OM_uint32 reqFlags GSSEAP_UNUSED,
                       OM_uint32 timeReq GSSEAP_UNUSED,
                       gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                       gss_buffer_t inputToken GSSEAP_UNUSED,
                       gss_buffer_t outputToken,
                       OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    major = makeStringBuffer(minor, "JANET(UK)", outputToken);
    if (GSS_ERROR(major))
        return major;

    return GSS_S_CONTINUE_NEEDED;
}
#endif

static OM_uint32
eapGssSmInitAcceptorName(OM_uint32 *minor,
                         gss_cred_id_t cred GSSEAP_UNUSED,
                         gss_ctx_id_t ctx,
                         gss_name_t target GSSEAP_UNUSED,
                         gss_OID mech GSSEAP_UNUSED,
                         OM_uint32 reqFlags GSSEAP_UNUSED,
                         OM_uint32 timeReq GSSEAP_UNUSED,
                         gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                         gss_buffer_t inputToken GSSEAP_UNUSED,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    if (GSSEAP_SM_STATE(ctx) == GSSEAP_STATE_INITIAL &&
        ctx->acceptorName != GSS_C_NO_NAME) {

        /* Send desired target name to acceptor */
        major = gssEapDisplayName(minor, ctx->acceptorName,
                                  outputToken, NULL);
        if (GSS_ERROR(major))
            return major;
    } else if (inputToken != GSS_C_NO_BUFFER &&
               ctx->acceptorName == GSS_C_NO_NAME) {
        /* Accept target name hint from acceptor */
        major = gssEapImportName(minor, inputToken,
                                 GSS_C_NT_USER_NAME,
                                 ctx->mechanismUsed,
                                 &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    /*
     * Currently, other parts of the code assume that the acceptor name
     * is available, hence this check.
     */
    if (ctx->acceptorName == GSS_C_NO_NAME) {
        *minor = GSSEAP_NO_ACCEPTOR_NAME;
        return GSS_S_FAILURE;
    }

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitIdentity(OM_uint32 *minor,
                     gss_cred_id_t cred GSSEAP_UNUSED,
                     gss_ctx_id_t ctx,
                     gss_name_t target GSSEAP_UNUSED,
                     gss_OID mech GSSEAP_UNUSED,
                     OM_uint32 reqFlags GSSEAP_UNUSED,
                     OM_uint32 timeReq GSSEAP_UNUSED,
                     gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                     gss_buffer_t inputToken GSSEAP_UNUSED,
                     gss_buffer_t outputToken GSSEAP_UNUSED,
                     OM_uint32 *smFlags)
{
    *smFlags |= SM_FLAG_FORCE_SEND_TOKEN;

    GSSEAP_ASSERT((ctx->flags & CTX_FLAG_KRB_REAUTH) == 0);
    GSSEAP_ASSERT(inputToken == GSS_C_NO_BUFFER);

    /* makeStringBuffer(minor, "n,,", outputToken); */

    GSSEAP_SM_TRANSITION_NEXT(ctx);

    *minor = 0;

    return GSS_S_CONTINUE_NEEDED;
}

static void
freeChildren(xmlNode *a_node)
{
    xmlNode *cur_node = NULL;

    cur_node = a_node->children;
    while (cur_node) {
          xmlNode *next_node = cur_node->next;
          xmlUnlinkNode(cur_node);
          xmlFreeNode(cur_node);          cur_node = next_node;
    }
}

size_t
write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    int numbytes = size * nmemb;
    OM_uint32 tmpMinor;

    if (addToStringBuffer(&tmpMinor, buffer, numbytes, userp) == GSS_S_COMPLETE)
        return numbytes;
    else
        return -1;
}

char curl_err_msg[CURL_ERROR_SIZE+1];

OM_uint32
sendToIdP(OM_uint32 *minor, xmlDocPtr doc, char *idp,
          gss_cred_id_t cred, gss_buffer_t response)
{
    CURL *curl = NULL;
    CURLcode res = 0;
    xmlChar *mem = NULL;
    int size = 0;
    char *user = cred->name->username.value;
    char *password = cred->password.value;
    char *certfile = getenv(SAML_EC_USER_CERT);
    char *keyfile = getenv(SAML_EC_USER_KEY);
    OM_uint32 major = GSS_S_COMPLETE;

    if (MECH_SAML_EC_DEBUG)
        fprintf(stdout, "USER IS (%s)\n", user?:"");

    if ((certfile && !keyfile) || (keyfile && !certfile)) {
        fprintf(stderr, "NOTICE: One of either SAML_EC_USER_CERT or "
                        "SAML_EC_USER_KEY is not set. Unable to use "
                        "certificate authentication.\n");
        certfile = keyfile = NULL;
    }

    if ((user && !password) || (password && !user)) {
        fprintf(stderr, "NOTICE: One of either username or "
                        "password is NULL. Unable to use username/password "
                        "for authentication.\n");
        user = password = NULL;
    }

    if (certfile && keyfile) {
        if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "DOING HTTPS POST to IdP (%s) using Cert Auth cert"
                    " (%s) key (%s)\n", idp, certfile, keyfile);
    }
    if (user && password) {
        if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "DOING HTTPS POST to IdP (%s) using Basic Auth user"
                    " (%s)\n", idp, user);
    }
    if (!user && !password && !certfile && !keyfile) {
        fprintf(stderr, "ERROR: NO user/password info in credential; "
                        "please supply a credential acquired with "
                        "gss_acquire_cred_with_password() or variants;\n"
                        "You can also alternatively specify client cert/key "
                        "files by setting env vars SAML_EC_USER_CERT and "
                        "SAML_EC_USER_KEY. Client certificate will be used "
                        "if set instead of username/password.\n");
        *minor = GSSEAP_BAD_CRED_OPTION;
        return GSS_S_FAILURE;
    }

    xmlDocDumpFormatMemory(doc, &mem, &size, 0);
    if (mem == NULL || size == 0) {
        fprintf(stderr, "ERROR: xmlDocDumpFormatMemory failed to parse "
                        "the XML doc to be sent to IdP\n");
        *minor = GSSEAP_BAD_CONTEXT_TOKEN;
        return GSS_S_FAILURE;
    }

    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "ERROR: curl_easy_init failed\n");
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
    }

    if ((res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_msg)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_URL, idp)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) != CURLE_OK ||
        /* Per curl_easy_opt(3) this is for FTP but perhaps also for HTTP? */
        (res = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL)) != CURLE_OK ||
        (user && ((res = curl_easy_setopt(curl, CURLOPT_USERNAME, user)) != CURLE_OK ||
                  (res = curl_easy_setopt(curl, CURLOPT_PASSWORD, password)) != CURLE_OK ||
                  (res = curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC)) != CURLE_OK)) ||
        (certfile && ((res = curl_easy_setopt(curl, CURLOPT_SSLCERT, certfile)) != CURLE_OK ||
                      (res = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM")) != CURLE_OK ||
                      (res = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT)) != CURLE_OK)) ||
        (keyfile && ((res = curl_easy_setopt(curl, CURLOPT_SSLKEY, keyfile)) != CURLE_OK ||
                      (res = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM")) != CURLE_OK ||
                      (res = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "")) != CURLE_OK)) ||
        (res = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_POST, 1)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mem)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, size)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, response)) != CURLE_OK ||
        (res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data)) != CURLE_OK) {
        fprintf(stderr, "ERROR: curl_easy_setopt failure; %s\n", curl_easy_strerror(res));
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    res = curl_easy_perform(curl);
    if (res) {
        fprintf(stderr, "ERROR: curl_easy_perform failed with return code "
                        "(%d) and error (%s)\n", res, curl_err_msg);
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    long http_code = 0;
    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: curl_easy_getinfo failed with return code "
                        "(%d) and error (%s)\n", res, curl_err_msg);
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }
    if (http_code != 200) {
        fprintf(stderr, "ERROR: HTTPS failed with status code (%d)\n",
                                 http_code);
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    char *content_type = NULL;
    res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
    if (res != CURLE_OK) {
        fprintf(stderr, "ERROR: curl_easy_getinfo failed with return code "
                        "(%d) and error (%s)\n", res, curl_err_msg);
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }
    if (content_type == NULL) {
        fprintf(stderr, "ERROR: IdP DID NOT SEND A CONTENT TYPE IN HEADER.\n");
        *minor = GSSEAP_BAD_USAGE;
        major = GSS_S_FAILURE;
        goto cleanup;
    } else {
        if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "CONTENT TYPE FROM IDP IS: %s", content_type);
        if (!strcasestr(content_type, "xml")) {
            fprintf(stderr, "ERROR: IdP DID NOT SEND XML DOCUMENT BACK.\n");
            *minor = GSSEAP_BAD_USAGE;
            major = GSS_S_FAILURE;
            goto cleanup;
        }
    }

    major = GSS_S_COMPLETE;

cleanup:
    if (mem)
        xmlFree(mem);
    mem = NULL;

    if (curl)
        curl_easy_cleanup(curl);
    curl = NULL;

    return major;
}

OM_uint32
processSAMLRequest(OM_uint32 *minor, gss_ctx_id_t ctx, OM_uint32 req_flags,
                 gss_channel_bindings_t input_chan_bindings,
                 gss_buffer_t request, gss_buffer_t response)
{
    char *idp = getenv(SAML_EC_IDP);
    xmlDocPtr doc_from_sp = NULL;
    xmlDocPtr doc_from_idp = NULL;
    xmlNode *header_from_sp = NULL;
    xmlNode *header_to_idp = NULL;
    xmlNode *signature_value = NULL;
    xmlNode *mutual_auth = NULL;
    xmlNode *elem = NULL;
    xmlNode *session_key = NULL;
    xmlNode *encryption_type = NULL;
    xmlNode *gen_key = NULL;
    xmlNode *cb_elem = NULL;
    gss_buffer_desc response_from_idp = {0, NULL};
    OM_uint32 major = GSS_S_COMPLETE;
    OM_uint32 tmpMinor = 0;

    if (MECH_SAML_EC_DEBUG)
        fprintf(stdout, "IdP IS (%s)\n", idp?:"");

    if (idp == NULL) {
        fprintf(stderr, "ERROR: NO IDP specified; please specify an IdP"
                " using the environment variable (%s)\n", SAML_EC_IDP);
        *minor = GSSEAP_BAD_SERVICE_NAME;
        return GSS_S_FAILURE;
    }

    doc_from_sp = xmlReadMemory(request->value, request->length, "FROMSP", NULL, 0);
    if (doc_from_sp != NULL) {
        if (MECH_SAML_EC_DEBUG) {
            fprintf(stdout, "\n\nREQUEST FROM SP AS SEEN BY XML:\n");
            xmlDocDump(stdout, doc_from_sp);
        }
    } else {
        fprintf(stderr, "ERROR: Failure parsing document from SP:\n%.*s\n",
                        request->length, request->value);
        *minor = GSSEAP_BAD_CONTEXT_TOKEN;
        return GSS_S_FAILURE;
    }

    /* Exclude header */
    header_from_sp = getXmlElement(xmlDocGetRootElement(doc_from_sp), "Header", MECH_SAML_EC_SOAP11_NS);
    if (header_from_sp == NULL) {
        fprintf(stderr, "ERROR: No Header in SAML Request from SP\n");
        *minor = GSSEAP_BAD_TOK_HEADER;
        major = GSS_S_FAILURE;
        goto cleanup;
    }
    header_to_idp = xmlCopyNode(header_from_sp, 0 /* no children or props */);
    xmlUnlinkNode(header_from_sp);

    char *cb_data = NULL;

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS &&
        input_chan_bindings->application_data.length != 0 &&
        base64Encode(input_chan_bindings->application_data.value,
            input_chan_bindings->application_data.length, &cb_data) != -1) {
        char *cb_type = NULL;

        major = readChannelBindingsType(&tmpMinor, &cb_type);
        if (major != GSS_S_COMPLETE) {
            fprintf(stderr, "ERROR: Couldn't find Channel Bindings Type\n");
            goto cleanup;
        }

        cb_elem = xmlNewNode(NULL, "ChannelBindings");
        xmlNsPtr cb_ns = xmlNewNs(cb_elem, MECH_SAML_EC_CB_NS, "cb");
        xmlSetNs(cb_elem, cb_ns);
        xmlAddChild(header_to_idp, cb_elem);
        xmlAddPrevSibling(xmlDocGetRootElement(doc_from_sp)->children, header_to_idp);
        xmlSetNs(header_to_idp, xmlDocGetRootElement(doc_from_sp)->ns);
        xmlSetProp(cb_elem, "Type", cb_type /* "tls-server-end-point" */);
        xmlSetNsProp(cb_elem, header_to_idp->ns, "actor", "http://schemas.xmlsoap.org/soap/actor/next");
        xmlSetNsProp(cb_elem, header_to_idp->ns, "mustUnderstand", "1");
        xmlNodeSetContent(cb_elem, cb_data);
        if (cb_data != NULL) {
            GSSEAP_FREE(cb_data); cb_data = NULL;
        }
        free(cb_type); cb_type = NULL;
    }

    if ((session_key = getXmlElement(header_from_sp, "SessionKey", MECH_SAML_EC_SAMLEC_NS)) != NULL) {
        char *algorithm = xmlGetNsProp(session_key, "EncType", MECH_SAML_EC_SAMLEC_NS);
        
        if (algorithm != NULL) {
            fprintf(stderr, "ERROR: Algorithm (%s) NOT supported\n", algorithm);
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        encryption_type = getXmlElement(session_key, "EncType", MECH_SAML_EC_SAMLEC_NS);
        ctx->encryptionType = ENCTYPE_NULL;
        while (ctx->encryptionType == ENCTYPE_NULL && encryption_type != NULL) {
            char *tmp = xmlNodeGetContent(encryption_type);

            if (tmp == NULL) {
                fprintf(stderr, "ERROR: Failure of xmlNodeGetContent for "
                                "EncType in SessionKey.");
                *minor = GSSEAP_BAD_TOK_HEADER;
                major = GSS_S_FAILURE;
                goto cleanup;
            }
            krbStringToEnctype(tmp, &ctx->encryptionType);
            encryption_type = encryption_type->next;
            xmlFree(tmp); tmp = NULL;
        }

        if (ctx->encryptionType == ENCTYPE_NULL) {
            fprintf(stderr, "ERROR: EncType is non-existent in SessionKey or is empty.");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }
    } else {
        fprintf(stderr, "ERROR: Authentication Request from Service Provider"
                " doesn't contain SessionKey header block\n");
        *minor = GSSEAP_BAD_TOK_HEADER;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    signature_value = getXmlElement(xmlDocGetRootElement(doc_from_sp), "SignatureValue", MECH_SAML_EC_DS_NS);
/* TODO VSY: Delete this: Corrupt the signature for testing purposes 
if (signature_value != NULL) {
xmlChar *val = xmlNodeGetContent(signature_value);
val[0] = 'M';
xmlNodeSetContent(signature_value, val);
}
*/

    if (MECH_SAML_EC_DEBUG) {
        fprintf(stdout, "\nSENDING TO IDP:\n");
        xmlDocDump(stdout, doc_from_sp);
    }

    /* Send doc to IdP */
    /* TODO: Error checking here and elsewhere */
    major = sendToIdP(minor, doc_from_sp, idp, ctx->cred, &response_from_idp);
    if (major != GSS_S_COMPLETE) {
        fprintf(stderr, "ERROR: Failure communicating with IdP\n");
        goto cleanup;
    }

    if (response_from_idp.value == NULL) {
        fprintf(stderr, "ERROR: No response from IdP\n");
        *minor = GSSEAP_IDENTITY_SERVICE_UNKNOWN_ERROR;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    if (MECH_SAML_EC_DEBUG)
        fprintf(stdout, "\n\nRECEIVED FROM IDP:\n%s\n", (char *) response_from_idp.value);

    /* Empty the header from IdP and populate with RelayState from
     *     header received from SP */
    doc_from_idp = xmlReadMemory(response_from_idp.value,
                  response_from_idp.length, "FROMIDP", NULL, 0);
    if (doc_from_idp == NULL) {
        fprintf(stderr, "ERROR: No response from IdP\n");
        *minor = GSSEAP_IDENTITY_SERVICE_UNKNOWN_ERROR;
        major = GSS_S_FAILURE;
        goto cleanup;
    } else {
        xmlNode *header_from_idp = NULL;
        xmlNode *relay_state = NULL;
        xmlNode *request_from_sp = NULL;
        xmlNode *response_from_idp = NULL;
        char *responseConsumerURL = NULL;
        char *AssertionConsumerServiceURL = NULL;

        if (MECH_SAML_EC_DEBUG) {
            fprintf(stdout, "AS SEEN BY XML:\n");
            xmlDocDump(stdout, doc_from_idp);
        }

        /* Compare responseConsumerURL from original request with
         * AssertionConsumerServiceURL from response from IdP */
        request_from_sp = getXmlElement(header_from_sp, "Request", MECH_SAML_EC_PAOS_NS);
        if (request_from_sp == NULL) {
            fprintf(stderr, "ERROR: No Request element in SAML Request Header from SP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        responseConsumerURL = xmlGetProp(request_from_sp, "responseConsumerURL");
        if (responseConsumerURL == NULL) {
            fprintf(stderr, "ERROR: No responseConsumerURL attribute in SAML Request Header from SP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        response_from_idp = getXmlElement(xmlDocGetRootElement(doc_from_idp), "Response", MECH_SAML_EC_ECP_NS);
        if (response_from_idp == NULL) {
            fprintf(stderr, "ERROR: No Response element in SAML Response from IdP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        AssertionConsumerServiceURL = xmlGetProp(response_from_idp, "AssertionConsumerServiceURL");
        if (AssertionConsumerServiceURL == NULL) {
            fprintf(stderr, "ERROR: No AssertionConsumerServiceURL attribute in SAML Response from IdP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        if(strcmp(responseConsumerURL, AssertionConsumerServiceURL)) {
            fprintf(stderr, "ERROR: responseConsumerURL (%s) and "
                    "AssertionConsumerServiceURL (%s) do not match\n",
                    responseConsumerURL, AssertionConsumerServiceURL);
            *minor = GSSEAP_PEER_AUTH_FAILURE;
            major = GSS_S_FAILURE;
            goto cleanup;
        } else if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "NOTE: responseConsumerURL (%s) and "
                    "AssertionConsumerServiceURL (%s) match\n",
                    responseConsumerURL, AssertionConsumerServiceURL);

        if(strlen(AssertionConsumerServiceURL) != ctx->acceptorName->username.length
           ||
           strncmp(AssertionConsumerServiceURL, ctx->acceptorName->username.value,
                   ctx->acceptorName->username.length)) {
            fprintf(stderr, "ERROR: Target name (%.*s) and "
                    "AssertionConsumerServiceURL (%s) do not match\n",
                    ctx->acceptorName->username.length,
                    ctx->acceptorName->username.value, AssertionConsumerServiceURL);
            *minor = GSSEAP_PEER_AUTH_FAILURE;
            major = GSS_S_FAILURE;
            goto cleanup;
        } else if (MECH_SAML_EC_DEBUG)
            fprintf(stdout, "NOTE: Target name (%.*s) and "
                    "AssertionConsumerServiceURL (%s) match\n",
                    ctx->acceptorName->username.length,
                    ctx->acceptorName->username.value, AssertionConsumerServiceURL);

        mutual_auth = getXmlElement(xmlDocGetRootElement(doc_from_idp), "RequestAuthenticated", MECH_SAML_EC_ECP_NS);
        if (mutual_auth != NULL) {
            if (MECH_SAML_EC_DEBUG)
                fprintf(stdout, "NOTE: IdP has reported ecp:RequestAuthenticated\n");
            ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
        } else if (signature_value != NULL) { // SP did send a signature across
            /* VSY TODO: ecp:RequestAuthenticated not yet supported by most
               IdPs, so assume mutual auth succeeded if we are forced */
            if (getenv("MECH_SAML_EC_FORCE_MUTUAL_AUTH_FLAG")) {
                fprintf(stderr, "WARNING: IdP did NOT report ecp:RequestAuthenticated"
                            " but server did send a sign request and "
                            "MECH_SAML_EC_FORCE_MUTUAL_AUTH_FLAG is set in "
                            "environment so force-setting GSS_C_MUTUAL_FLAG assuming "
                            " IdP has checked signature but has not implemented "
                            "ecp:RequestAuthenticated yet!!!\n");
                ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
            } else {
                fprintf(stderr, "ERROR: IdP did NOT report ecp:RequestAuthenticated"
                            " but server did sign the request. To force-set GSS_C_MUTUAL_FLAG assuming "
                            " IdP has checked the signature set "
                            "MECH_SAML_EC_FORCE_MUTUAL_AUTH_FLAG in environment!!!\n");
                *minor = GSSEAP_PEER_AUTH_FAILURE;
                major = GSS_S_FAILURE;
                goto cleanup;
            }
        }

        /* TODO VSY: DELETE THIS GeneratedKey ADDED FOR TEST PURPOSES!!! */
        if ((elem = getXmlElement(xmlDocGetRootElement(doc_from_idp), "GeneratedKey", MECH_SAML_EC_SAMLEC_NS)) == NULL && getenv("MECH_SAML_EC_FORCE_SAMPLE_KEY")) {
            xmlNsPtr samlec_ns;
            fprintf(stderr, "WARNING: No GeneratedKey in SAML Response from IdP; "
                            "Since MECH_SAML_EC_FORCE_SAMPLE_KEY is set in the "
                            "environment, forcing use of a sample key!\n");
            elem = getXmlElement(xmlDocGetRootElement(doc_from_idp), "Response", MECH_SAML_EC_ECP_NS);
            gen_key = xmlNewNode(NULL, "GeneratedKey");
            // Check if this NS already exists?
            samlec_ns = xmlNewNs(gen_key, MECH_SAML_EC_SAMLEC_NS, "samlec");
            xmlSetNs(gen_key, samlec_ns);
            xmlNodeSetContent(gen_key, "3w1wSBKUosRLsU69xGK7dg==");
            xmlAddNextSibling(elem, gen_key);
        }

        if ((gen_key = getXmlElement(xmlDocGetRootElement(doc_from_idp), "GeneratedKey", MECH_SAML_EC_SAMLEC_NS)) != NULL) {
            gl_generated_key = xmlNodeGetContent(gen_key);

            /* Add SessionKey/EncType as sibling of gen_key */
            session_key = xmlNewNode(NULL, "SessionKey");
            xmlNsPtr samlec_ns = xmlNewNs(session_key, MECH_SAML_EC_SAMLEC_NS, "samlec");
            xmlSetNs(session_key, samlec_ns);

            gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;
            char *tmp = NULL;
            krb5_context krbContext;
            GSSEAP_KRB_INIT(&krbContext);
            if  (krbEnctypeToString(krbContext, ctx->encryptionType, "", &buffer) != 0 ||
                 bufferToString(&tmpMinor, &buffer, &tmp) != GSS_S_COMPLETE) {
                fprintf(stderr, "ERROR: Failed to convert context's encryption type to string\n");
                *minor = GSSEAP_KEY_UNAVAILABLE;
                major = GSS_S_FAILURE;
                goto cleanup;
            }
            encryption_type = xmlNewNode(samlec_ns, "EncType");
            xmlNodeSetContent(encryption_type, tmp);
            if (MECH_SAML_EC_DEBUG)
                fprintf(stdout, "NOTE: Encryption Type for session key is (%s)\n", tmp);
            GSSEAP_FREE(buffer.value); buffer.value = NULL;
            free(tmp); tmp = NULL;
            xmlAddChild(session_key, encryption_type);
            xmlAddNextSibling(gen_key, session_key);

            /* Exclude GeneratedKey from header block since there should be
               a copy in the (encrypted) assertion that the SP can get the
               key from. */
            xmlUnlinkNode(gen_key);
            xmlFreeNode(gen_key); gen_key = NULL;
        } else { // RFC requires support for GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG
            fprintf(stderr, "ERROR: No GeneratedKey in SAML header block from IdP; "
                            "To force use of a sample key set "
                            "MECH_SAML_EC_FORCE_SAMPLE_KEY in the "
                            "environment!\n");
            *minor = GSSEAP_KEY_UNAVAILABLE;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        if (getXmlElement(xmlDocGetRootElement(doc_from_idp), "Delegated",
                                          MECH_SAML_EC_SAMLEC_NS) != NULL)
            if (req_flags & GSS_C_DELEG_FLAG) {
                ctx->gssFlags |= GSS_C_DELEG_FLAG;
                if (MECH_SAML_EC_DEBUG)
                    fprintf(stdout, "NOTE: Credential being delegated to acceptor\n");
            } else {
                fprintf(stderr, "ERROR: Credential Delegation was NOT requested "
                            "but IdP has delegated a credential possibly at  "
                            "the request of the server. \n");
                *minor = GSSEAP_BAD_CONTEXT_OPTION;
                major = GSS_S_FAILURE;
                goto cleanup;
            }

        header_from_idp = getXmlElement(xmlDocGetRootElement(doc_from_idp), "Header", MECH_SAML_EC_SOAP11_NS);
        if (header_from_idp == NULL) {
            fprintf(stderr, "ERROR: No Header element in SAML Response from IdP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        /* Leave existing content in place. */
        /* freeChildren(header_from_idp); */
        relay_state = getXmlElement(header_from_sp, "RelayState", MECH_SAML_EC_ECP_NS);
        if (relay_state == NULL) {
            fprintf(stderr, "ERROR: No RelayState element in SAML Request from SP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        if (xmlAddChild(header_from_idp, xmlCopyNode(relay_state, 1)) == NULL) {
            fprintf(stderr, "ERROR: Failure adding RelayState to Header from IdP\n");
            *minor = GSSEAP_BAD_TOK_HEADER;
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        if (MECH_SAML_EC_DEBUG) {
            fprintf(stdout, "SENDING TO SP >>>>>>>>>>>>>>>>>>>\n");
            xmlDocDump(stdout, doc_from_idp);
        }

        xmlDocDumpMemory(doc_from_idp, (char *)&response->value,
                  (int *)&response->length);
        major = GSS_S_COMPLETE;
    }

cleanup:
    if (doc_from_sp)
        xmlFreeDoc(doc_from_sp);

    if (doc_from_idp)
        xmlFreeDoc(doc_from_idp);

    if (response_from_idp.value)
        gss_release_buffer(&tmpMinor, &response_from_idp);

    return major;
}

static OM_uint32
eapGssSmInitAuthenticate(OM_uint32 *minor,
                         gss_cred_id_t cred GSSEAP_UNUSED,
                         gss_ctx_id_t ctx,
                         gss_name_t target GSSEAP_UNUSED,
                         gss_OID mech GSSEAP_UNUSED,
                         OM_uint32 reqFlags GSSEAP_UNUSED,
                         OM_uint32 timeReq GSSEAP_UNUSED,
                         gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                         gss_buffer_t inputToken GSSEAP_UNUSED,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags)
{
    OM_uint32 major;
    OM_uint32 tmpMinor;
    struct wpabuf *resp = NULL;
    char *saml_response = NULL;

    *minor = 0;

    GSSEAP_ASSERT(inputToken != GSS_C_NO_BUFFER);

#ifdef MECH_EAP
    major = peerConfigInit(minor, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    GSSEAP_ASSERT(ctx->initiatorCtx.eap != NULL);
    GSSEAP_ASSERT(ctx->flags & CTX_FLAG_EAP_PORT_ENABLED);

    ctx->flags |= CTX_FLAG_EAP_REQ; /* we have a Request from the acceptor */

    wpabuf_set(&ctx->initiatorCtx.reqData,
               inputToken->value, inputToken->length);

    major = GSS_S_CONTINUE_NEEDED;

    eap_peer_sm_step(ctx->initiatorCtx.eap);
    if (ctx->flags & CTX_FLAG_EAP_RESP) {
        ctx->flags &= ~(CTX_FLAG_EAP_RESP);

        resp = eap_get_eapRespData(ctx->initiatorCtx.eap);
    } else if (ctx->flags & CTX_FLAG_EAP_SUCCESS) {
        major = initReady(minor, ctx, req_flags);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->flags &= ~(CTX_FLAG_EAP_SUCCESS);
        major = GSS_S_CONTINUE_NEEDED;
        GSSEAP_SM_TRANSITION_NEXT(ctx);
    } else if (ctx->flags & CTX_FLAG_EAP_FAIL) {
        major = GSS_S_DEFECTIVE_CREDENTIAL;
        *minor = GSSEAP_PEER_AUTH_FAILURE;
    } else {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_PEER_BAD_MESSAGE;
    }

cleanup:
    if (resp != NULL) {
        OM_uint32 tmpMajor;
        gss_buffer_desc respBuf;

        GSSEAP_ASSERT(major == GSS_S_CONTINUE_NEEDED);

        respBuf.length = wpabuf_len(resp);
        respBuf.value = (void *)wpabuf_head(resp);

        tmpMajor = duplicateBuffer(&tmpMinor, &respBuf, outputToken);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }

        *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;
    }

    wpabuf_set(&ctx->initiatorCtx.reqData, NULL, 0);
    peerConfigFree(&tmpMinor, ctx);

    GSSEAP_SM_TRANSITION_NEXT(ctx);
        *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;
#else
    major = GSS_S_UNAVAILABLE;
#endif

    return major;
}

static OM_uint32
eapGssSmInitGssFlags(OM_uint32 *minor,
                     gss_cred_id_t cred GSSEAP_UNUSED,
                     gss_ctx_id_t ctx,
                     gss_name_t target GSSEAP_UNUSED,
                     gss_OID mech GSSEAP_UNUSED,
                     OM_uint32 reqFlags GSSEAP_UNUSED,
                     OM_uint32 timeReq GSSEAP_UNUSED,
                     gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                     gss_buffer_t inputToken GSSEAP_UNUSED,
                     gss_buffer_t outputToken,
                     OM_uint32 *smFlags GSSEAP_UNUSED)
{
    unsigned char wireFlags[4];
    gss_buffer_desc flagsBuf;

    store_uint32_be(ctx->gssFlags & GSSEAP_WIRE_FLAGS_MASK, wireFlags);

    flagsBuf.length = sizeof(wireFlags);
    flagsBuf.value = wireFlags;

    return duplicateBuffer(minor, &flagsBuf, outputToken);
}

static OM_uint32
eapGssSmInitGssChannelBindings(OM_uint32 *minor,
                               gss_cred_id_t cred GSSEAP_UNUSED,
                               gss_ctx_id_t ctx,
                               gss_name_t target GSSEAP_UNUSED,
                               gss_OID mech GSSEAP_UNUSED,
                               OM_uint32 reqFlags GSSEAP_UNUSED,
                               OM_uint32 timeReq GSSEAP_UNUSED,
                               gss_channel_bindings_t chanBindings,
                               gss_buffer_t inputToken GSSEAP_UNUSED,
                               gss_buffer_t outputToken,
                               OM_uint32 *smFlags)
{
    OM_uint32 major;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS)
        buffer = chanBindings->application_data;

    major = gssEapWrap(minor, ctx, 1, GSS_C_QOP_DEFAULT,
                       &buffer, NULL, outputToken);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_ASSERT(outputToken->value != NULL);

    *minor = 0;
    *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitInitiatorMIC(OM_uint32 *minor,
                         gss_cred_id_t cred GSSEAP_UNUSED,
                         gss_ctx_id_t ctx,
                         gss_name_t target GSSEAP_UNUSED,
                         gss_OID mech GSSEAP_UNUSED,
                         OM_uint32 reqFlags GSSEAP_UNUSED,
                         OM_uint32 timeReq GSSEAP_UNUSED,
                         gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                         gss_buffer_t inputToken GSSEAP_UNUSED,
                         gss_buffer_t outputToken,
                         OM_uint32 *smFlags)
{
    OM_uint32 major;

    major = gssEapMakeTokenMIC(minor, ctx, outputToken);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_SM_TRANSITION_NEXT(ctx);

    *minor = 0;
    *smFlags |= SM_FLAG_OUTPUT_TOKEN_CRITICAL;

    return GSS_S_CONTINUE_NEEDED;
}
 
static OM_uint32
eapGssSmInitAcceptorMIC(OM_uint32 *minor,
                        gss_cred_id_t cred GSSEAP_UNUSED,
                        gss_ctx_id_t ctx,
                        gss_name_t target GSSEAP_UNUSED,
                        gss_OID mech GSSEAP_UNUSED,
                        OM_uint32 reqFlags GSSEAP_UNUSED,
                        OM_uint32 timeReq GSSEAP_UNUSED,
                        gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken GSSEAP_UNUSED,
                        OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    major = gssEapVerifyTokenMIC(minor, ctx, inputToken);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_ESTABLISHED);

    *minor = 0;

    return GSS_S_COMPLETE;
}

static struct gss_eap_sm eapGssInitiatorSm[] = {
    {
        ITOK_TYPE_CONTEXT_ERR,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_ALL & ~(GSSEAP_STATE_INITIAL),
        0,
        eapGssSmInitError
    },
#ifdef MECH_EAP
    {
        ITOK_TYPE_ACCEPTOR_NAME_RESP,
        ITOK_TYPE_ACCEPTOR_NAME_REQ,
        GSSEAP_STATE_INITIAL | GSSEAP_STATE_AUTHENTICATE,
        0,
        eapGssSmInitAcceptorName
    },
#endif
#ifdef GSSEAP_DEBUG
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_VENDOR_INFO,
        GSSEAP_STATE_INITIAL,
        0,
        eapGssSmInitVendorInfo
    },
#endif
    {
        ITOK_TYPE_NONE,
#if 1 /* def MECH_EAP */
        ITOK_TYPE_NONE,
#else
        ITOK_TYPE_EAP_REQ,
#endif
        GSSEAP_STATE_INITIAL,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitIdentity
    },
    {
        ITOK_TYPE_EAP_REQ,
        ITOK_TYPE_EAP_RESP,
        GSSEAP_STATE_AUTHENTICATE,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitAuthenticate
    },
#ifdef MECH_EAP
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_GSS_FLAGS,
        GSSEAP_STATE_INITIATOR_EXTS,
        0,
        eapGssSmInitGssFlags
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_GSS_CHANNEL_BINDINGS,
        GSSEAP_STATE_INITIATOR_EXTS,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitGssChannelBindings
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_INITIATOR_MIC,
        GSSEAP_STATE_INITIATOR_EXTS,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitInitiatorMIC
    },
    /* other extensions go here */
    {
        ITOK_TYPE_ACCEPTOR_MIC,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_ACCEPTOR_EXTS,
        SM_ITOK_FLAG_REQUIRED,
        eapGssSmInitAcceptorMIC
    }
#endif
};

OM_uint32
gssEapInitSecContext(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t ctx,
                     gss_name_t target_name,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;
    int initialContextToken = (ctx->mechanismUsed == GSS_C_NO_OID);

    /*
     * XXX is acquiring the credential lock here necessary? The password is
     * mutable but the contract could specify that this is not updated whilst
     * a context is being initialized.
     */
    if (cred != GSS_C_NO_CREDENTIAL)
        GSSEAP_MUTEX_LOCK(&cred->mutex);
#if 0
    else {
        *minor = GSSEAP_BAD_CRED_OPTION;
        return GSS_S_NO_CRED;
    }
#endif

    if (ctx->cred == GSS_C_NO_CREDENTIAL) {
        major = gssEapResolveInitiatorCred(minor, cred, target_name, &ctx->cred);
        if (GSS_ERROR(major))
            goto cleanup;

        GSSEAP_ASSERT(ctx->cred != GSS_C_NO_CREDENTIAL);
    }

    GSSEAP_MUTEX_LOCK(&ctx->cred->mutex);

    GSSEAP_ASSERT(ctx->cred->flags & CRED_FLAG_RESOLVED);
    GSSEAP_ASSERT(ctx->cred->flags & CRED_FLAG_INITIATE);

    if (initialContextToken) {
        major = initBegin(minor, ctx, target_name, mech_type,
                          req_flags, time_req, input_chan_bindings);
        if (GSS_ERROR(major))
            goto cleanup;
    }

#ifdef MECH_EAP
    major = gssEapSmStep(minor,
                         cred,
                         ctx,
                         target_name,
                         mech_type,
                         req_flags,
                         time_req,
                         input_chan_bindings,
                         input_token,
                         output_token,
                         eapGssInitiatorSm,
                         sizeof(eapGssInitiatorSm) / sizeof(eapGssInitiatorSm[0]));
#else
    if (initialContextToken) {
        gss_buffer_desc innerToken = GSS_C_EMPTY_BUFFER;

        /* Holder-of-key (HOK) not supported yet */
        major = makeStringBuffer(minor, ",", &innerToken);
        if (major != GSS_S_COMPLETE)
            goto cleanup;

        if (req_flags & GSS_C_MUTUAL_FLAG) {
            major = addToStringBuffer(minor, MECH_SAML_EC_MUTUAL_AUTH, strlen(MECH_SAML_EC_MUTUAL_AUTH), &innerToken);
            if (major != GSS_S_COMPLETE)
                goto cleanup;
        }
        major = addToStringBuffer(minor, ",", strlen(","), &innerToken);
            if (major != GSS_S_COMPLETE)
                goto cleanup;

        if (req_flags & GSS_C_DELEG_FLAG) {
            major = addToStringBuffer(minor, MECH_SAML_EC_DELEG_REQ, strlen(MECH_SAML_EC_DELEG_REQ), &innerToken);
            if (major != GSS_S_COMPLETE)
                goto cleanup;
        }

        major = gssEapMakeToken(minor, ctx, &innerToken, -1,
                   output_token);
        if (major == GSS_S_COMPLETE) {
            major = GSS_S_CONTINUE_NEEDED;
            ctx->state = GSSEAP_STATE_AUTHENTICATE;
        }
    } else {
        major = processSAMLRequest(minor, ctx, req_flags, input_chan_bindings,
                                     input_token, output_token);
        if (major != GSS_S_COMPLETE) {
            fprintf(stderr, "ERROR: SOAP FAULT RESPONSE BEING SENT>>>>>>>>>>>>>>>\n");
            makeStringBuffer(&tmpMinor, SOAP_FAULT_MSG, output_token);
        } else {
            ctx->state = GSSEAP_STATE_ESTABLISHED;
            major = initReady(minor, ctx, req_flags);
        }
    }
#endif
    if (GSS_ERROR(major))
        goto cleanup;

    if (actual_mech_type != NULL) {
        OM_uint32 tmpMajor;

        tmpMajor = gssEapCanonicalizeOid(&tmpMinor, ctx->mechanismUsed, 0, actual_mech_type);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (time_rec != NULL)
        gssEapContextTime(&tmpMinor, ctx, time_rec);

    GSSEAP_ASSERT(CTX_IS_ESTABLISHED(ctx) || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    if (cred != GSS_C_NO_CREDENTIAL)
        GSSEAP_MUTEX_UNLOCK(&cred->mutex);
    if (ctx->cred != GSS_C_NO_CREDENTIAL)
        GSSEAP_MUTEX_UNLOCK(&ctx->cred->mutex);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_init_sec_context(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t *context_handle,
                     gss_name_t target_name,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            *minor = GSSEAP_WRONG_SIZE;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        ctx->flags |= CTX_FLAG_INITIATOR;

        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    major = gssEapInitSecContext(minor,
                                 cred,
                                 ctx,
                                 target_name,
                                 mech_type,
                                 req_flags,
                                 time_req,
                                 input_chan_bindings,
                                 input_token,
                                 actual_mech_type,
                                 output_token,
                                 ret_flags,
                                 time_rec);

    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);
#ifndef MECH_EAP
    else if (MECH_SAML_EC_DEBUG)
        printBuffer(stdout, output_token);
#endif

    return major;
}
