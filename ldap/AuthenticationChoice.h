/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Lightweight-Directory-Access-Protocol-V3"
 * 	found in "../ldap.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef _AuthenticationChoice_H_
#define _AuthenticationChoice_H_

#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include "SaslCredentials.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AuthenticationChoice_PR {
    AuthenticationChoice_PR_NOTHING, /* No components present */
    AuthenticationChoice_PR_simple,
    AuthenticationChoice_PR_sasl,
    /* Extensions may appear below */

} AuthenticationChoice_PR;

/* AuthenticationChoice */
typedef struct AuthenticationChoice
{
    AuthenticationChoice_PR present;
    union AuthenticationChoice_u
    {
        OCTET_STRING_t simple;
        SaslCredentials_t sasl;
        /*
         * This type is extensible,
         * possible extensions are below.
         */
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AuthenticationChoice_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AuthenticationChoice;

#ifdef __cplusplus
}
#endif

#endif /* _AuthenticationChoice_H_ */
#include <asn_internal.h>
