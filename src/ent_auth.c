#include "ent_auth.h"
#include "ent_config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

typedef struct ent_auth_data
{
    const uint8_t *username;
    const uint8_t *password;
} ent_auth_data_t;

static void ent_free_res(int num_msg, struct pam_response *res)
{
    if (!res) {
        return;
    }
    for (int i = 0; i < num_msg; i++) {
        if (!res[i].resp) {
            continue;
        }
        bzero(res[i].resp, strlen(res[i].resp));
        free(res[i].resp);
        res[i].resp = NULL;
    }
    free(res);
}

static int ent_auth_conv(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata_ptr)
{
    ent_auth_data_t *data = (ent_auth_data_t *)appdata_ptr;
    struct pam_response *res = calloc(num_msg, sizeof(struct pam_response));

    if (!resp || !msg || !data || !res) {
        return PAM_CONV_ERR;
    }

    *resp = NULL;
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            res[i].resp = strdup((const char *)data->username);
            break;
        case PAM_PROMPT_ECHO_OFF:
            res[i].resp = strdup((const char *)data->password);
            break;
        default:
            ent_free_res(i, res);
            return PAM_CONV_ERR;
        }
        if (!res[i].resp) {
            ent_free_res(i, res);
            return PAM_CONV_ERR;
        }
    }
    *resp = res;
    return PAM_SUCCESS;
}

static void ent_auth_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
    /* Dummy */
}

bool ent_auth(const uint8_t *username, const uint8_t *password, uint8_t *status,
              size_t size)
{
    ent_auth_data_t auth_data = {.username = username, .password = password};
    struct pam_conv auth_conv = {.conv = &ent_auth_conv,
                                 .appdata_ptr = (void *)&auth_data};
    pam_handle_t *pamh = NULL;

    /* Start pam */
    int res = pam_start((const char *)config.service, (const char *)username,
                        &auth_conv, &pamh);

    if (res != PAM_SUCCESS) {
        snprintf((char *)status, size, "PAM: Could not start pam service: %s\n",
                 pam_strerror(pamh, res));
        pam_end(pamh, PAM_SUCCESS);
        return false;
    }

    /* Set failure delay handler function */
    union
    {
        void (*delay_fn)(int retval, unsigned usec_delay, void *appdata_ptr);
        void *fn_ptr;
    } item = {.delay_fn = ent_auth_delay};
    res = pam_set_item(pamh, PAM_FAIL_DELAY, item.fn_ptr);
    if (res != PAM_SUCCESS) {
        snprintf((char *)status, size,
                 "PAM: Could not set failure delay handler: %s\n",
                 pam_strerror(pamh, res));
        pam_end(pamh, PAM_SUCCESS);
        return false;
    }

    /* Try to auth */
    res = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (res != PAM_SUCCESS) {
        snprintf((char *)status, size, "PAM: user %s - not authenticated: %s\n",
                 username, pam_strerror(pamh, res));
        pam_end(pamh, PAM_SUCCESS);
        return false;
    }

    /* Check that the account is healthy */
    res = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (res != PAM_SUCCESS) {
        snprintf((char *)status, size, "PAM: user %s - invalid account: %s",
                 username, pam_strerror(pamh, res));
        pam_end(pamh, PAM_SUCCESS);
        return false;
    }

    snprintf((char *)status, size, "PAM: Success");
    pam_end(pamh, PAM_SUCCESS);

    return true;
}
