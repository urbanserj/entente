/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Lightweight-Directory-Access-Protocol-V3"
 * 	found in "../ldap.asn1"
 * 	`asn1c -fcompound-names`
 */

#include "SearchRequest.h"

static int scope_3_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
                              asn_app_constraint_failed_f *ctfailcb,
                              void *app_key)
{
    /* Replace with underlying type checker */
    td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
    return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void scope_3_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)
{
    td->free_struct = asn_DEF_NativeEnumerated.free_struct;
    td->print_struct = asn_DEF_NativeEnumerated.print_struct;
    td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
    td->ber_decoder = asn_DEF_NativeEnumerated.ber_decoder;
    td->der_encoder = asn_DEF_NativeEnumerated.der_encoder;
    td->xer_decoder = asn_DEF_NativeEnumerated.xer_decoder;
    td->xer_encoder = asn_DEF_NativeEnumerated.xer_encoder;
    td->uper_decoder = asn_DEF_NativeEnumerated.uper_decoder;
    td->uper_encoder = asn_DEF_NativeEnumerated.uper_encoder;
    if (!td->per_constraints)
        td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
    td->elements = asn_DEF_NativeEnumerated.elements;
    td->elements_count = asn_DEF_NativeEnumerated.elements_count;
    /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined
     * explicitly */
}

static void scope_3_free(asn_TYPE_descriptor_t *td, void *struct_ptr,
                         int contents_only)
{
    scope_3_inherit_TYPE_descriptor(td);
    td->free_struct(td, struct_ptr, contents_only);
}

static int scope_3_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
                         int ilevel, asn_app_consume_bytes_f *cb, void *app_key)
{
    scope_3_inherit_TYPE_descriptor(td);
    return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t scope_3_decode_ber(asn_codec_ctx_t *opt_codec_ctx,
                                         asn_TYPE_descriptor_t *td,
                                         void **structure, const void *bufptr,
                                         size_t size, int tag_mode)
{
    scope_3_inherit_TYPE_descriptor(td);
    return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size,
                           tag_mode);
}

static asn_enc_rval_t scope_3_encode_der(asn_TYPE_descriptor_t *td,
                                         void *structure, int tag_mode,
                                         ber_tlv_tag_t tag,
                                         asn_app_consume_bytes_f *cb,
                                         void *app_key)
{
    scope_3_inherit_TYPE_descriptor(td);
    return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t scope_3_decode_xer(asn_codec_ctx_t *opt_codec_ctx,
                                         asn_TYPE_descriptor_t *td,
                                         void **structure,
                                         const char *opt_mname,
                                         const void *bufptr, size_t size)
{
    scope_3_inherit_TYPE_descriptor(td);
    return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr,
                           size);
}

static asn_enc_rval_t scope_3_encode_xer(asn_TYPE_descriptor_t *td,
                                         void *structure, int ilevel,
                                         enum xer_encoder_flags_e flags,
                                         asn_app_consume_bytes_f *cb,
                                         void *app_key)
{
    scope_3_inherit_TYPE_descriptor(td);
    return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static int derefAliases_8_constraint(asn_TYPE_descriptor_t *td,
                                     const void *sptr,
                                     asn_app_constraint_failed_f *ctfailcb,
                                     void *app_key)
{
    /* Replace with underlying type checker */
    td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
    return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void derefAliases_8_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)
{
    td->free_struct = asn_DEF_NativeEnumerated.free_struct;
    td->print_struct = asn_DEF_NativeEnumerated.print_struct;
    td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
    td->ber_decoder = asn_DEF_NativeEnumerated.ber_decoder;
    td->der_encoder = asn_DEF_NativeEnumerated.der_encoder;
    td->xer_decoder = asn_DEF_NativeEnumerated.xer_decoder;
    td->xer_encoder = asn_DEF_NativeEnumerated.xer_encoder;
    td->uper_decoder = asn_DEF_NativeEnumerated.uper_decoder;
    td->uper_encoder = asn_DEF_NativeEnumerated.uper_encoder;
    if (!td->per_constraints)
        td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
    td->elements = asn_DEF_NativeEnumerated.elements;
    td->elements_count = asn_DEF_NativeEnumerated.elements_count;
    /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined
     * explicitly */
}

static void derefAliases_8_free(asn_TYPE_descriptor_t *td, void *struct_ptr,
                                int contents_only)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    td->free_struct(td, struct_ptr, contents_only);
}

static int derefAliases_8_print(asn_TYPE_descriptor_t *td,
                                const void *struct_ptr, int ilevel,
                                asn_app_consume_bytes_f *cb, void *app_key)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t derefAliases_8_decode_ber(asn_codec_ctx_t *opt_codec_ctx,
                                                asn_TYPE_descriptor_t *td,
                                                void **structure,
                                                const void *bufptr, size_t size,
                                                int tag_mode)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size,
                           tag_mode);
}

static asn_enc_rval_t derefAliases_8_encode_der(asn_TYPE_descriptor_t *td,
                                                void *structure, int tag_mode,
                                                ber_tlv_tag_t tag,
                                                asn_app_consume_bytes_f *cb,
                                                void *app_key)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t derefAliases_8_decode_xer(asn_codec_ctx_t *opt_codec_ctx,
                                                asn_TYPE_descriptor_t *td,
                                                void **structure,
                                                const char *opt_mname,
                                                const void *bufptr, size_t size)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr,
                           size);
}

static asn_enc_rval_t derefAliases_8_encode_xer(asn_TYPE_descriptor_t *td,
                                                void *structure, int ilevel,
                                                enum xer_encoder_flags_e flags,
                                                asn_app_consume_bytes_f *cb,
                                                void *app_key)
{
    derefAliases_8_inherit_TYPE_descriptor(td);
    return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static int memb_sizeLimit_constraint_1(asn_TYPE_descriptor_t *td,
                                       const void *sptr,
                                       asn_app_constraint_failed_f *ctfailcb,
                                       void *app_key)
{
    long value;

    if (!sptr) {
        _ASN_CTFAIL(app_key, td, sptr, "%s: value not given (%s:%d)", td->name,
                    __FILE__, __LINE__);
        return -1;
    }

    value = *(const long *)sptr;

    if ((value >= 0 && value <= 2147483647)) {
        /* Constraint check succeeded */
        return 0;
    } else {
        _ASN_CTFAIL(app_key, td, sptr, "%s: constraint failed (%s:%d)",
                    td->name, __FILE__, __LINE__);
        return -1;
    }
}

static int memb_timeLimit_constraint_1(asn_TYPE_descriptor_t *td,
                                       const void *sptr,
                                       asn_app_constraint_failed_f *ctfailcb,
                                       void *app_key)
{
    long value;

    if (!sptr) {
        _ASN_CTFAIL(app_key, td, sptr, "%s: value not given (%s:%d)", td->name,
                    __FILE__, __LINE__);
        return -1;
    }

    value = *(const long *)sptr;

    if ((value >= 0 && value <= 2147483647)) {
        /* Constraint check succeeded */
        return 0;
    } else {
        _ASN_CTFAIL(app_key, td, sptr, "%s: constraint failed (%s:%d)",
                    td->name, __FILE__, __LINE__);
        return -1;
    }
}

static const asn_INTEGER_enum_map_t asn_MAP_scope_value2enum_3[] = {
    {0, 10, "baseObject"},
    {1, 11, "singleLevel"},
    {2, 12, "wholeSubtree"}
    /* This list is extensible */
};
static const unsigned int asn_MAP_scope_enum2value_3[] = {
    0, /* baseObject(0) */
    1, /* singleLevel(1) */
    2  /* wholeSubtree(2) */
       /* This list is extensible */
};
static const asn_INTEGER_specifics_t asn_SPC_scope_specs_3 = {
    asn_MAP_scope_value2enum_3, /* "tag" => N; sorted by tag */
    asn_MAP_scope_enum2value_3, /* N => "tag"; sorted by N */
    3,                          /* Number of elements in the maps */
    4,                          /* Extensions before this member */
    1,                          /* Strict enumeration */
    0,                          /* Native long size */
    0};
static const ber_tlv_tag_t asn_DEF_scope_tags_3[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (10 << 2))};
static /* Use -fall-defs-global to expose */
    asn_TYPE_descriptor_t asn_DEF_scope_3 = {
        "scope", "scope", scope_3_free, scope_3_print, scope_3_constraint,
        scope_3_decode_ber, scope_3_encode_der, scope_3_decode_xer,
        scope_3_encode_xer, 0, 0, /* No PER support, use "-gen-PER" to enable */
        0,                        /* Use generic outmost tag fetcher */
        asn_DEF_scope_tags_3,
        sizeof(asn_DEF_scope_tags_3) / sizeof(asn_DEF_scope_tags_3[0]), /* 1 */
        asn_DEF_scope_tags_3, /* Same as above */
        sizeof(asn_DEF_scope_tags_3) / sizeof(asn_DEF_scope_tags_3[0]), /* 1 */
        0,                     /* No PER visible constraints */
        0, 0,                  /* Defined elsewhere */
        &asn_SPC_scope_specs_3 /* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_derefAliases_value2enum_8[] = {
    {0, 17, "neverDerefAliases"},
    {1, 16, "derefInSearching"},
    {2, 19, "derefFindingBaseObj"},
    {3, 11, "derefAlways"}};
static const unsigned int asn_MAP_derefAliases_enum2value_8[] = {
    3, /* derefAlways(3) */
    2, /* derefFindingBaseObj(2) */
    1, /* derefInSearching(1) */
    0  /* neverDerefAliases(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_derefAliases_specs_8 = {
    asn_MAP_derefAliases_value2enum_8, /* "tag" => N; sorted by tag */
    asn_MAP_derefAliases_enum2value_8, /* N => "tag"; sorted by N */
    4,                                 /* Number of elements in the maps */
    0,                                 /* Enumeration is not extensible */
    1,                                 /* Strict enumeration */
    0,                                 /* Native long size */
    0};
static const ber_tlv_tag_t asn_DEF_derefAliases_tags_8[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (10 << 2))};
static /* Use -fall-defs-global to expose */
    asn_TYPE_descriptor_t asn_DEF_derefAliases_8 = {
        "derefAliases", "derefAliases", derefAliases_8_free,
        derefAliases_8_print, derefAliases_8_constraint,
        derefAliases_8_decode_ber, derefAliases_8_encode_der,
        derefAliases_8_decode_xer, derefAliases_8_encode_xer, 0,
        0, /* No PER support, use "-gen-PER" to enable */
        0, /* Use generic outmost tag fetcher */
        asn_DEF_derefAliases_tags_8,
        sizeof(asn_DEF_derefAliases_tags_8) /
            sizeof(asn_DEF_derefAliases_tags_8[0]), /* 1 */
        asn_DEF_derefAliases_tags_8,                /* Same as above */
        sizeof(asn_DEF_derefAliases_tags_8) /
            sizeof(asn_DEF_derefAliases_tags_8[0]), /* 1 */
        0, /* No PER visible constraints */
        0,
        0,                            /* Defined elsewhere */
        &asn_SPC_derefAliases_specs_8 /* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SearchRequest_1[] = {
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, baseObject),
     (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, &asn_DEF_LDAPDN,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "baseObject"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, scope),
     (ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 0, &asn_DEF_scope_3,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "scope"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, derefAliases),
     (ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 0, &asn_DEF_derefAliases_8,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "derefAliases"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, sizeLimit),
     (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, &asn_DEF_NativeInteger,
     memb_sizeLimit_constraint_1, 0, /* PER is not compiled, use -gen-PER */
     0, "sizeLimit"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, timeLimit),
     (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, &asn_DEF_NativeInteger,
     memb_timeLimit_constraint_1, 0, /* PER is not compiled, use -gen-PER */
     0, "timeLimit"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, typesOnly),
     (ASN_TAG_CLASS_UNIVERSAL | (1 << 2)), 0, &asn_DEF_BOOLEAN,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "typesOnly"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, filter),
     -1 /* Ambiguous tag (CHOICE?) */, 0, &asn_DEF_Filter,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "filter"},
    {ATF_NOFLAGS, 0, offsetof(struct SearchRequest, attributes),
     (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, &asn_DEF_AttributeSelection,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "attributes"},
};
static const ber_tlv_tag_t asn_DEF_SearchRequest_tags_1[] = {
    (ASN_TAG_CLASS_APPLICATION | (3 << 2)),
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))};
static const asn_TYPE_tag2member_t asn_MAP_SearchRequest_tag2el_1[] = {
    {(ASN_TAG_CLASS_UNIVERSAL | (1 << 2)), 5, 0, 0},   /* typesOnly */
    {(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 3, 0, 1},   /* sizeLimit */
    {(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 4, -1, 0},  /* timeLimit */
    {(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0},   /* baseObject */
    {(ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 1, 0, 1},  /* scope */
    {(ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 2, -1, 0}, /* derefAliases */
    {(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 7, 0, 0},  /* attributes */
    {(ASN_TAG_CLASS_CONTEXT | (0 << 2)), 6, 0, 0},     /* and */
    {(ASN_TAG_CLASS_CONTEXT | (1 << 2)), 6, 0, 0},     /* or */
    {(ASN_TAG_CLASS_CONTEXT | (2 << 2)), 6, 0, 0},     /* not */
    {(ASN_TAG_CLASS_CONTEXT | (3 << 2)), 6, 0, 0},     /* equalityMatch */
    {(ASN_TAG_CLASS_CONTEXT | (4 << 2)), 6, 0, 0},     /* substrings */
    {(ASN_TAG_CLASS_CONTEXT | (5 << 2)), 6, 0, 0},     /* greaterOrEqual */
    {(ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0},     /* lessOrEqual */
    {(ASN_TAG_CLASS_CONTEXT | (7 << 2)), 6, 0, 0},     /* present */
    {(ASN_TAG_CLASS_CONTEXT | (8 << 2)), 6, 0, 0},     /* approxMatch */
    {(ASN_TAG_CLASS_CONTEXT | (9 << 2)), 6, 0, 0}      /* extensibleMatch */
};
static asn_SEQUENCE_specifics_t asn_SPC_SearchRequest_specs_1 = {
    sizeof(struct SearchRequest),   offsetof(struct SearchRequest, _asn_ctx),
    asn_MAP_SearchRequest_tag2el_1, 17, /* Count of tags in the map */
    0,                              0,
    0, /* Optional elements (not needed) */
    7, /* Start extensions */
    9  /* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_SearchRequest = {
    "SearchRequest", "SearchRequest", SEQUENCE_free, SEQUENCE_print,
    SEQUENCE_constraint, SEQUENCE_decode_ber, SEQUENCE_encode_der,
    SEQUENCE_decode_xer, SEQUENCE_encode_xer, 0,
    0, /* No PER support, use "-gen-PER" to enable */
    0, /* Use generic outmost tag fetcher */
    asn_DEF_SearchRequest_tags_1,
    sizeof(asn_DEF_SearchRequest_tags_1) /
            sizeof(asn_DEF_SearchRequest_tags_1[0]) -
        1,                        /* 1 */
    asn_DEF_SearchRequest_tags_1, /* Same as above */
    sizeof(asn_DEF_SearchRequest_tags_1) /
        sizeof(asn_DEF_SearchRequest_tags_1[0]), /* 2 */
    0, /* No PER visible constraints */
    asn_MBR_SearchRequest_1,
    8,                             /* Elements count */
    &asn_SPC_SearchRequest_specs_1 /* Additional specs */
};
