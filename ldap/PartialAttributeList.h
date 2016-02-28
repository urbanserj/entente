/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Lightweight-Directory-Access-Protocol-V3"
 * 	found in "../ldap.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef _PartialAttributeList_H_
#define _PartialAttributeList_H_

#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PartialAttribute;

/* PartialAttributeList */
typedef struct PartialAttributeList
{
    A_SEQUENCE_OF(struct PartialAttribute) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PartialAttributeList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PartialAttributeList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PartialAttribute.h"

#endif /* _PartialAttributeList_H_ */
#include <asn_internal.h>
