#include "ent_auth.h"
#include "ent_config.h"
#include "ent_ldap.h"
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ev.h>
#include "LDAPMessage.h"

#define BUF_SIZE 2048

typedef struct ent_ldap
{
    bool anonymous;
} ent_ldap_t;

static void ent_debug(const char *str, LDAPMessage_t *msg)
{
    if (!config.debug) {
        return;
    }
    fprintf(stdout, "%s\n", str);
    asn_fprint(stdout, &asn_DEF_LDAPMessage, msg);
    fprintf(stdout, "\n");
}

static char *ent_decode(char *buf, ssize_t cnt, LDAPMessage_t *msg)
{
    asn_dec_rval_t rc =
        ber_decode(0, &asn_DEF_LDAPMessage, (void **)&msg, buf, cnt);

    if (rc.code != RC_OK) {
        fprintf(stderr, "DER decoder\n");
        ASN_STRUCT_FREE(asn_DEF_LDAPMessage, msg);
        return NULL;
    }

    if ((ssize_t)rc.consumed != cnt) {
        fprintf(stderr, "Unconsumed data: %zu %zi\n", rc.consumed, cnt);
        ASN_STRUCT_FREE(asn_DEF_LDAPMessage, msg);
        return NULL;
    }

    ent_debug("<<<<<<<<", msg);

    return buf;
}

static ssize_t ent_send(ev_io *watcher, LDAPMessage_t *msg)
{
    char buf[BUF_SIZE] = {0};
    asn_enc_rval_t rc =
        der_encode_to_buffer(&asn_DEF_LDAPMessage, msg, &buf, BUF_SIZE);

    ent_debug(">>>>>>>>", msg);

    ssize_t cnt = write(watcher->fd, buf, rc.encoded);
    if (cnt < 0) {
        perror("Write");
    } else if (rc.encoded != cnt) {
        fprintf(stderr, "Send error\n");
    }

    return cnt;
}

static enum ent_state ent_bind(ev_io *watcher, LDAPMessage_t *req)
{
    ent_ldap_t *data = (ent_ldap_t *)watcher->data;
    data->anonymous = true;

    LDAPMessage_t res = {
        .messageID = req->messageID,
        .protocolOp = {.present = LDAPMessage__protocolOp_PR_bindResponse}};
    BindResponse_t *bindres = &res.protocolOp.choice.bindResponse;

    BindRequest_t *bindreq = &req->protocolOp.choice.bindRequest;
    bindres->resultCode = BindResponse__resultCode_operationsError;
    OCTET_STRING_fromString(&bindres->diagnosticMessage, "Error");

    if (bindreq->name.size == 0) {
        if (config.anonymous) {
            bindres->resultCode = BindResponse__resultCode_success;
            OCTET_STRING_fromString(&bindres->diagnosticMessage, "Anonymous");
        }
    } else if (bindreq->authentication.present ==
               AuthenticationChoice_PR_simple) {
        const char *cn = (const char *)bindreq->name.buf;
        uint8_t *comma = (uint8_t *)index(cn, ',');
        if (!comma || strncmp(cn, "cn=", 3) ||
            strcmp((const char *)comma + 1, (const char *)config.basedn)) {
            bindres->resultCode = BindResponse__resultCode_invalidDNSyntax;
            OCTET_STRING_fromString(&bindres->diagnosticMessage,
                                    "Invalid DN Syntax");
            OCTET_STRING_fromString(&bindres->matchedDN,
                                    (const char *)config.basedn);
        } else {
            uint8_t username[BUF_SIZE] = {0};
            strncpy((char *)username, cn + 3, comma - (bindreq->name.buf + 3));
            uint8_t *password = bindreq->authentication.choice.simple.buf;

            uint8_t status[BUF_SIZE] = {0};
            if (ent_auth(username, password, status, BUF_SIZE)) {
                bindres->resultCode = BindResponse__resultCode_success;
                data->anonymous = false;
            } else {
                bindres->resultCode =
                    BindResponse__resultCode_invalidCredentials;
            }
            OCTET_STRING_fromString(&bindres->diagnosticMessage,
                                    (const char *)status);
        }
    } else {
        bindres->resultCode = BindResponse__resultCode_authMethodNotSupported;
        OCTET_STRING_fromString(&bindres->diagnosticMessage,
                                "Auth method not supported");
    }

    ssize_t ret = ent_send(watcher, &res);

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, &res);

    if (ret < 0) {
        return ENT_CLOSE;
    } else {
        return ENT_WAIT_READ;
    }
}

static enum ent_state ent_search(ev_io *watcher, LDAPMessage_t *req)
{
    /* (uid=$username$) => cn=$username$,BASEDN */
    ent_ldap_t *data = (ent_ldap_t *)watcher->data;

    LDAPMessage_t res = {
        .messageID = req->messageID,
        .protocolOp = {.present = LDAPMessage__protocolOp_PR_searchResDone}};
    SearchResultDone_t *done = &res.protocolOp.choice.searchResDone;

    SearchRequest_t *searchreq = &req->protocolOp.choice.searchRequest;

    const char *baseobj = (const char *)searchreq->baseObject.buf;
    AttributeValueAssertion_t *attr = &searchreq->filter.choice.equalityMatch;
    if (data->anonymous && !config.anonymous) {
        done->resultCode = LDAPResult__resultCode_insufficientAccessRights;
        OCTET_STRING_fromString(&done->diagnosticMessage,
                                "Anonymous access not allowed");
    } else if (strcmp(baseobj, (const char *)config.basedn) &&
               strcmp(baseobj, "")) {
        done->resultCode = LDAPResult__resultCode_other;
        OCTET_STRING_fromString(&done->diagnosticMessage,
                                "BaseObject is invalid");
        OCTET_STRING_fromString(&done->matchedDN, (const char *)config.basedn);
    } else if (searchreq->filter.present != Filter_PR_equalityMatch ||
               strcmp((const char *)attr->attributeDesc.buf, "uid")) {
        done->resultCode = LDAPResult__resultCode_other;
        OCTET_STRING_fromString(&done->diagnosticMessage,
                                "Filter is not supported");
    } else {
        res.protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
        SearchResultEntry_t *entry = &res.protocolOp.choice.searchResEntry;

        uint8_t cn[BUF_SIZE] = {0};
        snprintf((char *)cn, BUF_SIZE, "cn=%s,%s", attr->assertionValue.buf,
                 config.basedn);
        OCTET_STRING_fromString(&entry->objectName, (const char *)cn);

        if (ent_send(watcher, &res) < 0) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, &res);
            return ENT_CLOSE;
        }

        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, &res);
        bzero(&res, sizeof(LDAPMessage_t));

        res.messageID = req->messageID;
        res.protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
        done = &res.protocolOp.choice.searchResDone;
        done->resultCode = LDAPResult__resultCode_success;
        OCTET_STRING_fromString(&done->diagnosticMessage, "OK");
    }

    ssize_t ret = ent_send(watcher, &res);

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, &res);

    if (ret < 0) {
        return ENT_CLOSE;
    } else {
        return ENT_WAIT_READ;
    }
}

enum ent_state ent_read(struct ev_loop *loop, ev_io *watcher)
{
    char buf[BUF_SIZE] = {0};
    ssize_t cnt = read(watcher->fd, buf, BUF_SIZE);

    if (cnt == 0) {
        return ENT_CLOSE;
    }

    if (cnt <= 0) {
        perror("Read");
        return ENT_CLOSE;
    }

    LDAPMessage_t req = {0};
    if (!ent_decode(buf, cnt, &req)) {
        return ENT_CLOSE;
    }

    enum ent_state ret = ENT_CLOSE;
    switch (req.protocolOp.present) {
    case LDAPMessage__protocolOp_PR_bindRequest:
        ret = ent_bind(watcher, &req);
        break;
    case LDAPMessage__protocolOp_PR_searchRequest:
        ret = ent_search(watcher, &req);
        break;
    case LDAPMessage__protocolOp_PR_unbindRequest:
        break;
    default:
        /* Unsupported */
        break;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, &req);
    bzero(&req, sizeof(LDAPMessage_t));

    return ret;
}

enum ent_state ent_init(struct ev_loop *loop, ev_io *watcher)
{
    ent_ldap_t *data = calloc(1, sizeof(ent_ldap_t));
    if (!data) {
        perror("Calloc");
        exit(EXIT_FAILURE);
    }
    data->anonymous = true;
    watcher->data = (void *)data;
    return ENT_WAIT_READ;
}

void ent_free(struct ev_loop *loop, ev_io *watcher)
{
    if (watcher->data) {
        free(watcher->data);
    }
}
