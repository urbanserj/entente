/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Lightweight-Directory-Access-Protocol-V3"
 * 	found in "../ldap.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef _SearchResultDone_H_
#define _SearchResultDone_H_

#include <asn_application.h>

/* Including external dependencies */
#include "LDAPResult.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SearchResultDone */
typedef LDAPResult_t SearchResultDone_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SearchResultDone;
asn_struct_free_f SearchResultDone_free;
asn_struct_print_f SearchResultDone_print;
asn_constr_check_f SearchResultDone_constraint;
ber_type_decoder_f SearchResultDone_decode_ber;
der_type_encoder_f SearchResultDone_encode_der;
xer_type_decoder_f SearchResultDone_decode_xer;
xer_type_encoder_f SearchResultDone_encode_xer;

#ifdef __cplusplus
}
#endif

#endif /* _SearchResultDone_H_ */
#include <asn_internal.h>
