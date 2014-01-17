/*
 * Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <strings.h>
#include <security/pam_appl.h>
#define EV_COMPAT3 0 /* Use the ev 4.X API.*/
#include <ev.h>
#include "asn1/LDAPMessage.h"


#define LISTENQ 128
#define LDAP_PORT 389
#define BUF_SIZE 16384

#define BASEDN "dc=entente"

#define fail(msg) do { perror(msg); return; } while (0);
#define ev_close(loop, watcher) do { \
	ev_io_stop(loop, watcher); \
	close(watcher->fd); \
	free(watcher); \
} while ( 0 )
#define ldapmessage_free(msg) asn_DEF_LDAPMessage.free_struct(&asn_DEF_LDAPMessage, msg, 0)

#ifdef DEBUG
#define LDAP_DEBUG(msg) asn_fprint(stdout, &asn_DEF_LDAPMessage, msg)
#else
#define LDAP_DEBUG(msg)
#endif

#define _setenv(name, value) do { \
	if ( setenv(name, value, 1) < 0 ) { \
		perror("setenv"); \
		exit(1); \
	} \
} while ( 0 )

int ldap_start();
void accept_cb(ev_loop *loop, ev_io *watcher, int revents);
void read_cb(ev_loop *loop, ev_io *watcher, int revents);

void ldap_bind(int msgid, BindRequest_t *req, ev_loop *loop, ev_io *watcher);
void ldap_search(int msgid, SearchRequest_t *req, ev_loop *loop, ev_io *watcher);
ssize_t ldap_send(LDAPMessage_t *msg, ev_loop *loop, ev_io *watcher);

typedef struct {
	const char *user, *pw;
	ev_tstamp delay;
} auth_pam_data_t;
int auth_pam(const char *user, const char *pw, const char **msg, ev_tstamp *delay);
int auth_pam_talker(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr);

typedef struct {
	LDAPMessage_t *res;
	LDAPDN_t *ldapdn;
	ev_io *watcher;
} ldap_delay_data_t;
void ldap_delay_cb(EV_P_ ev_timer *w, int revents);

char *cn2name(const char *cn);
void settings(int argc, char **argv);
int daemonize = 0;

int main(int argc, char **argv)
{
	settings(argc, argv);
	if (daemonize && daemon(0, 0)) {
		perror("daemon");
		exit(1);
	}
	return ldap_start();
}

int ldap_start()
{
	int serv_sd;
	int opt = 1;
	struct sockaddr_in servaddr;

	ev_loop *loop = EV_DEFAULT;
	ev_io w_accept;

	if ((serv_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	if (setsockopt(serv_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		return 1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl((getenv("ENTENTE_LOOPBACK")
					  && strcmp(getenv("ENTENTE_LOOPBACK"), "false") == 0)
					 ? INADDR_ANY : INADDR_LOOPBACK);
	servaddr.sin_port = htons(atoi(getenv("ENTENTE_PORT")));

	if (bind(serv_sd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(serv_sd, LISTENQ) < 0) {
		perror("listen");
		return 1;
	}

	ev_io_init(&w_accept, accept_cb, serv_sd, EV_READ);
	ev_io_start(loop, &w_accept);

	ev_run(loop, 0);

	return 0;
}

void accept_cb(ev_loop *loop, ev_io *watcher, int revents)
{
	int client_sd;

	ev_io *w_client;

	if (EV_ERROR & revents)
		fail("got invalid event");

	if ((client_sd = accept(watcher->fd, NULL, NULL)) < 0)
		fail("accept error");

	w_client = malloc(sizeof(ev_io));
	if (!w_client)
		fail("malloc");

	ev_io_init(w_client, read_cb, client_sd, EV_READ);
	ev_io_start(loop, w_client);
}

void read_cb(ev_loop *loop, ev_io *watcher, int revents)
{
	char buf[BUF_SIZE];
	ssize_t buf_cnt;

	LDAPMessage_t *req = NULL;
	asn_dec_rval_t rdecode;

	if (EV_ERROR & revents)
		fail("got invalid event");

	bzero(buf, sizeof(buf));
	buf_cnt = recv(watcher->fd, buf, sizeof(buf), 0);

	if (buf_cnt <= 0) {
		ev_close(loop, watcher);
		if (buf_cnt < 0)
			fail("read");
		return;
	}

	/* from asn1c's FAQ: If you want data to be BER or DER encoded, just invoke der_encode(). */
	rdecode = asn_DEF_LDAPMessage.ber_decoder(0, &asn_DEF_LDAPMessage, (void **)&req, buf, buf_cnt, 0);

	if (rdecode.code != RC_OK || (ssize_t) rdecode.consumed != buf_cnt) {
		perror((rdecode.code != RC_OK) ? "der_decoder" : "consumed");
		ev_close(loop, watcher);

		ldapmessage_free(req);
		return;
	}

	LDAP_DEBUG(req);
	switch (req->protocolOp.present) {
	case LDAPMessage__protocolOp_PR_bindRequest:
		ldap_bind(req->messageID, &req->protocolOp.choice.bindRequest, loop, watcher);
		break;
	case LDAPMessage__protocolOp_PR_searchRequest:
		ldap_search(req->messageID, &req->protocolOp.choice.searchRequest, loop, watcher);
		break;
	case LDAPMessage__protocolOp_PR_unbindRequest:
		ev_close(loop, watcher);
		break;
	default:
		perror("_|_");
		ev_close(loop, watcher);
	}

	ldapmessage_free(req);
}

void ldap_bind(int msgid, BindRequest_t *req, ev_loop *loop, ev_io *watcher)
{
	ev_tstamp delay = 0.0;

	LDAPDN_t *ldapdn = OCTET_STRING_new_fromBuf(&asn_DEF_LDAPString, (const char *)req->name.buf, req->name.size);
	LDAPMessage_t *res = calloc(1, sizeof(LDAPMessage_t));
	if (res == NULL)
		fail("calloc");
	res->messageID = msgid;
	res->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
	BindResponse_t *bindResponse = &res->protocolOp.choice.bindResponse;
	bindResponse->matchedDN = *ldapdn;

	if (getenv("ENTENTE_ANONYMOUS") && req->name.size == 0) {
		/* allow anonymous */
		asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_success);
	} else if (req->authentication.present == AuthenticationChoice_PR_simple) {
		/* simple auth */
		const char *user = cn2name((const char *)req->name.buf);
		const char *pw = (const char *)req->authentication.choice.simple.buf;
		const char *status = NULL;
		if (!user) {
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_invalidDNSyntax);
		} else if (PAM_SUCCESS != auth_pam(user, pw, &status, &delay)) {
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_invalidCredentials);
			OCTET_STRING_fromString(&bindResponse->diagnosticMessage, status);
		} else {	/* Success! */
			asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_success);
		}
		free((void *)user);
		free((void *)status);
	} else {
		/* sasl or anonymous auth */
		asn_long2INTEGER(&bindResponse->resultCode, BindResponse__resultCode_authMethodNotSupported);
	}
	if (delay > 0.0) {
		ev_timer *delay_timer = calloc(1, sizeof(ev_timer));
		ldap_delay_data_t *data = calloc(1, sizeof(ldap_delay_data_t));
		data->res = res;
		data->ldapdn = ldapdn;
		data->watcher = watcher;
		ev_timer_init(delay_timer, ldap_delay_cb, delay, 0.0);
		delay_timer->data = data;
		/* Stop the connection watcher to stop other requests while delayed. */
		ev_io_stop(loop, watcher);
		ev_timer_start(loop, delay_timer);
	} else {
		ldap_send(res, loop, watcher);
		ldapmessage_free(res);
		free(ldapdn);
	}
}

void ldap_search(int msgid, SearchRequest_t *req, ev_loop *loop, ev_io *watcher)
{
	/* (user=$username$) => cn=$username$,BASEDN */

	char user[BUF_SIZE] = "";
	int bad_dn = strcmp((const char *)req->baseObject.buf, BASEDN) != 0
	    && strcmp((const char *)req->baseObject.buf, "") != 0;

	AttributeValueAssertion_t *attr = &req->filter.choice.equalityMatch;
	int bad_filter = req->filter.present != Filter_PR_equalityMatch
	    || strcmp((const char *)attr->attributeDesc.buf, "user") != 0;

	LDAPMessage_t *res;
	SearchResultEntry_t *searchResEntry;
	SearchResultDone_t *searchDone;

	res = calloc(1, sizeof(LDAPMessage_t));
	if (res == NULL)
		fail("calloc");
	res->messageID = msgid;

	if (!bad_dn && !bad_filter) {
		/* result of search */
		res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;

		searchResEntry = &res->protocolOp.choice.searchResEntry;
		strcat(user, "cn=");
		strcat(user, (const char *)attr->assertionValue.buf);
		strcat(user, "," BASEDN);

		OCTET_STRING_fromString(&searchResEntry->objectName, user);

		if (ldap_send(res, loop, watcher) <= 0) {
			free(searchResEntry->objectName.buf);
			ldapmessage_free(res);
			return;
		}

		free(searchResEntry->objectName.buf);
		bzero(searchResEntry, sizeof(*searchResEntry));
	}

	/* search is done */
	res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
	searchDone = &res->protocolOp.choice.searchResDone;
	if (bad_dn) {
		asn_long2INTEGER(&searchDone->resultCode, LDAPResult__resultCode_other);
		OCTET_STRING_fromString(&searchDone->diagnosticMessage, "baseobject is unvalid");
	} else if (bad_filter) {
		asn_long2INTEGER(&searchDone->resultCode, LDAPResult__resultCode_other);
		OCTET_STRING_fromString(&searchDone->diagnosticMessage, "This filter isn't support");
	} else {
		asn_long2INTEGER(&searchDone->resultCode, LDAPResult__resultCode_success);
		OCTET_STRING_fromString(&searchDone->matchedDN, BASEDN);
	}

	ldap_send(res, loop, watcher);
	ldapmessage_free(res);
}

ssize_t ldap_send(LDAPMessage_t *msg, ev_loop *loop, ev_io *watcher)
{
	char buf[BUF_SIZE];
	ssize_t buf_cnt;
	asn_enc_rval_t rencode;

	LDAP_DEBUG(msg);

	bzero(buf, sizeof(buf));
	rencode = der_encode_to_buffer(&asn_DEF_LDAPMessage, msg, &buf, sizeof(buf));
	buf_cnt = write(watcher->fd, buf, rencode.encoded);

	if (rencode.encoded != buf_cnt) {
		ev_close(loop, watcher);
		perror("ldap_send");
		return -1;
	}
	return buf_cnt;
}

int auth_pam(const char *user, const char *pw, const char **msg, ev_tstamp *delay)
{
	char status[BUF_SIZE];
	int pam_res = -1;
	auth_pam_data_t data;
	struct pam_conv conv_info;
	pam_handle_t *pamh = NULL;

	data.user = user;
	data.pw = pw;
	data.delay = 0.0;
	conv_info.conv = &auth_pam_talker;
	conv_info.appdata_ptr = (void *)&data;
	/* Start pam. */
	if (PAM_SUCCESS != (pam_res = pam_start("entente", user, &conv_info, &pamh))) {
		sprintf(status, "PAM: Could not start pam service: %s\n", pam_strerror(pamh, pam_res));
	} else {
		/* Set failure delay handler function. */
		if (PAM_SUCCESS != (pam_res = pam_set_item(pamh, PAM_FAIL_DELAY, &auth_pam_delay)))
			sprintf(status, "PAM: Could not set failure delay handler: %s\n", pam_strerror(pamh, pam_res));
		/* Try auth. */
		else if (PAM_SUCCESS != (pam_res = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
			sprintf(status, "PAM: user %s - not authenticated: %s\n", user, pam_strerror(pamh, pam_res));
		/* Check that the account is healthy. */
		else if (PAM_SUCCESS != (pam_res = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
			sprintf(status, "PAM: user %s - invalid account: %s", user, pam_strerror(pamh, pam_res));
		else		/* success */
			status[0] = '\0';
		pam_end(pamh, PAM_SUCCESS);
	}
	*msg = strdup(status);
	*delay = data.delay;
	return pam_res;
}

int auth_pam_talker(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i;
	struct pam_response *res = 0;
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	if (!resp || !msg || !data)
		return PAM_CONV_ERR;

	if (NULL == (res = malloc(num_msg * sizeof(struct pam_response))))
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		/* initialize to safe values */
		res[i].resp_retcode = 0;
		res[i].resp = 0;

		/* select response based on requested output style */
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			res[i].resp = strdup(data->user);
			break;
		case PAM_PROMPT_ECHO_OFF:
			res[i].resp = strdup(data->pw);
			break;
		default:
			if (res)
				free(res);
			return PAM_CONV_ERR;
		}
	}
	/* everything okay, set PAM response values */
	*resp = res;
	return PAM_SUCCESS;
}

void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	/* Only set the delay if the auth failed. */
	if (PAM_SUCCESS != retval)
		data->delay = usec_delay * 1.0e-6;
}

void ldap_delay_cb(ev_loop *loop, ev_timer *w, int revents)
{
	ldap_delay_data_t *data = w->data;

	ldap_send(data->res, loop, data->watcher);
	/* Restart the connection watcher. */
	ev_io_start(loop, data->watcher);
	free(data->ldapdn);
	ldapmessage_free(data->res);
	free(data);
	free(w);
}

char *cn2name(const char *cn)
{
	/* cn=$username$,BASEDN => $username$ */
	char *pos = index(cn, ',');

	if (!pos || strncmp(cn, "cn=", 3) != 0 || strcmp(pos + 1, BASEDN) != 0)
		return NULL;
	return strndup(cn + 3, pos - (cn + 3));
}

void settings(int argc, char **argv)
{
	int c;
	char buf[8];

	while ((c = getopt(argc, argv, "ab:dlp:")) != -1) {
		switch (c) {
		case 'a':
			_setenv("ENTENTE_ANONYMOUS", "true");
			break;
		case 'b':
			_setenv("ENTENTE_BASEDN", optarg);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'l':
			_setenv("ENTENTE_LOOPBACK", "true");
			break;
		case 'p':
			_setenv("ENTENTE_PORT", optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s [-a] [-b dc=entente] [-l] [-p 389] [-d]\n", argv[0]);
			exit(1);
		}
	}

	if (getenv("ENTENTE_BASEDN") == NULL)
		_setenv("ENTENTE_BASEDN", BASEDN);

	if (getenv("ENTENTE_PORT") == NULL) {
		sprintf(buf, "%d", LDAP_PORT);
		_setenv("ENTENTE_PORT", buf);
	}
}
