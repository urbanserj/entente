/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Lightweight-Directory-Access-Protocol-V3"
 * 	found in "../ldap.asn1"
 * 	`asn1c -fcompound-names`
 */

#include "BindResponse.h"

static int resultCode_2_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
static void resultCode_2_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td)
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

static void resultCode_2_free(asn_TYPE_descriptor_t *td, void *struct_ptr,
                              int contents_only)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    td->free_struct(td, struct_ptr, contents_only);
}

static int resultCode_2_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
                              int ilevel, asn_app_consume_bytes_f *cb,
                              void *app_key)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t resultCode_2_decode_ber(asn_codec_ctx_t *opt_codec_ctx,
                                              asn_TYPE_descriptor_t *td,
                                              void **structure,
                                              const void *bufptr, size_t size,
                                              int tag_mode)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size,
                           tag_mode);
}

static asn_enc_rval_t resultCode_2_encode_der(asn_TYPE_descriptor_t *td,
                                              void *structure, int tag_mode,
                                              ber_tlv_tag_t tag,
                                              asn_app_consume_bytes_f *cb,
                                              void *app_key)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t resultCode_2_decode_xer(asn_codec_ctx_t *opt_codec_ctx,
                                              asn_TYPE_descriptor_t *td,
                                              void **structure,
                                              const char *opt_mname,
                                              const void *bufptr, size_t size)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr,
                           size);
}

static asn_enc_rval_t resultCode_2_encode_xer(asn_TYPE_descriptor_t *td,
                                              void *structure, int ilevel,
                                              enum xer_encoder_flags_e flags,
                                              asn_app_consume_bytes_f *cb,
                                              void *app_key)
{
    resultCode_2_inherit_TYPE_descriptor(td);
    return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static const asn_INTEGER_enum_map_t asn_MAP_resultCode_value2enum_2[] = {
    {0, 7, "success"},
    {1, 15, "operationsError"},
    {2, 13, "protocolError"},
    {3, 17, "timeLimitExceeded"},
    {4, 17, "sizeLimitExceeded"},
    {5, 12, "compareFalse"},
    {6, 11, "compareTrue"},
    {7, 22, "authMethodNotSupported"},
    {8, 20, "strongerAuthRequired"},
    {10, 8, "referral"},
    {11, 18, "adminLimitExceeded"},
    {12, 28, "unavailableCriticalExtension"},
    {13, 23, "confidentialityRequired"},
    {14, 18, "saslBindInProgress"},
    {16, 15, "noSuchAttribute"},
    {17, 22, "undefinedAttributeType"},
    {18, 21, "inappropriateMatching"},
    {19, 19, "constraintViolation"},
    {20, 22, "attributeOrValueExists"},
    {21, 22, "invalidAttributeSyntax"},
    {32, 12, "noSuchObject"},
    {33, 12, "aliasProblem"},
    {34, 15, "invalidDNSyntax"},
    {36, 25, "aliasDereferencingProblem"},
    {48, 27, "inappropriateAuthentication"},
    {49, 18, "invalidCredentials"},
    {50, 24, "insufficientAccessRights"},
    {51, 4, "busy"},
    {52, 11, "unavailable"},
    {53, 18, "unwillingToPerform"},
    {54, 10, "loopDetect"},
    {64, 15, "namingViolation"},
    {65, 20, "objectClassViolation"},
    {66, 19, "notAllowedOnNonLeaf"},
    {67, 15, "notAllowedOnRDN"},
    {68, 18, "entryAlreadyExists"},
    {69, 25, "objectClassModsProhibited"},
    {71, 19, "affectsMultipleDSAs"},
    {80, 5, "other"}};
static const unsigned int asn_MAP_resultCode_enum2value_2[] = {
    10, /* adminLimitExceeded(11) */
    37, /* affectsMultipleDSAs(71) */
    23, /* aliasDereferencingProblem(36) */
    21, /* aliasProblem(33) */
    18, /* attributeOrValueExists(20) */
    7,  /* authMethodNotSupported(7) */
    27, /* busy(51) */
    5,  /* compareFalse(5) */
    6,  /* compareTrue(6) */
    12, /* confidentialityRequired(13) */
    17, /* constraintViolation(19) */
    35, /* entryAlreadyExists(68) */
    24, /* inappropriateAuthentication(48) */
    16, /* inappropriateMatching(18) */
    26, /* insufficientAccessRights(50) */
    19, /* invalidAttributeSyntax(21) */
    25, /* invalidCredentials(49) */
    22, /* invalidDNSyntax(34) */
    30, /* loopDetect(54) */
    31, /* namingViolation(64) */
    14, /* noSuchAttribute(16) */
    20, /* noSuchObject(32) */
    33, /* notAllowedOnNonLeaf(66) */
    34, /* notAllowedOnRDN(67) */
    36, /* objectClassModsProhibited(69) */
    32, /* objectClassViolation(65) */
    1,  /* operationsError(1) */
    38, /* other(80) */
    2,  /* protocolError(2) */
    9,  /* referral(10) */
    13, /* saslBindInProgress(14) */
    4,  /* sizeLimitExceeded(4) */
    8,  /* strongerAuthRequired(8) */
    0,  /* success(0) */
    3,  /* timeLimitExceeded(3) */
    28, /* unavailable(52) */
    11, /* unavailableCriticalExtension(12) */
    15, /* undefinedAttributeType(17) */
    29  /* unwillingToPerform(53) */
};
static const asn_INTEGER_specifics_t asn_SPC_resultCode_specs_2 = {
    asn_MAP_resultCode_value2enum_2, /* "tag" => N; sorted by tag */
    asn_MAP_resultCode_enum2value_2, /* N => "tag"; sorted by N */
    39,                              /* Number of elements in the maps */
    0,                               /* Enumeration is not extensible */
    1,                               /* Strict enumeration */
    0,                               /* Native long size */
    0};
static const ber_tlv_tag_t asn_DEF_resultCode_tags_2[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (10 << 2))};
static /* Use -fall-defs-global to expose */
    asn_TYPE_descriptor_t asn_DEF_resultCode_2 = {
        "resultCode", "resultCode", resultCode_2_free, resultCode_2_print,
        resultCode_2_constraint, resultCode_2_decode_ber,
        resultCode_2_encode_der, resultCode_2_decode_xer,
        resultCode_2_encode_xer, 0,
        0, /* No PER support, use "-gen-PER" to enable */
        0, /* Use generic outmost tag fetcher */
        asn_DEF_resultCode_tags_2,
        sizeof(asn_DEF_resultCode_tags_2) /
            sizeof(asn_DEF_resultCode_tags_2[0]), /* 1 */
        asn_DEF_resultCode_tags_2,                /* Same as above */
        sizeof(asn_DEF_resultCode_tags_2) /
            sizeof(asn_DEF_resultCode_tags_2[0]), /* 1 */
        0, /* No PER visible constraints */
        0,
        0,                          /* Defined elsewhere */
        &asn_SPC_resultCode_specs_2 /* Additional specs */
};

static asn_TYPE_member_t asn_MBR_BindResponse_1[] = {
    {ATF_NOFLAGS, 0, offsetof(struct BindResponse, resultCode),
     (ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 0, &asn_DEF_resultCode_2,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "resultCode"},
    {ATF_NOFLAGS, 0, offsetof(struct BindResponse, matchedDN),
     (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, &asn_DEF_LDAPDN,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "matchedDN"},
    {ATF_NOFLAGS, 0, offsetof(struct BindResponse, diagnosticMessage),
     (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, &asn_DEF_LDAPString,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "diagnosticMessage"},
    {ATF_POINTER, 2, offsetof(struct BindResponse, referral),
     (ASN_TAG_CLASS_CONTEXT | (3 << 2)), -1, /* IMPLICIT tag at current level */
     &asn_DEF_Referral, 0, /* Defer constraints checking to the member type */
     0,                    /* PER is not compiled, use -gen-PER */
     0, "referral"},
    {ATF_POINTER, 1, offsetof(struct BindResponse, serverSaslCreds),
     (ASN_TAG_CLASS_CONTEXT | (7 << 2)), -1, /* IMPLICIT tag at current level */
     &asn_DEF_OCTET_STRING,
     0, /* Defer constraints checking to the member type */
     0, /* PER is not compiled, use -gen-PER */
     0, "serverSaslCreds"},
};
static const ber_tlv_tag_t asn_DEF_BindResponse_tags_1[] = {
    (ASN_TAG_CLASS_APPLICATION | (1 << 2)),
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))};
static const asn_TYPE_tag2member_t asn_MAP_BindResponse_tag2el_1[] = {
    {(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 1},  /* matchedDN */
    {(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 2, -1, 0}, /* diagnosticMessage */
    {(ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 0, 0, 0}, /* resultCode */
    {(ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0},    /* referral */
    {(ASN_TAG_CLASS_CONTEXT | (7 << 2)), 4, 0, 0}     /* serverSaslCreds */
};
static asn_SEQUENCE_specifics_t asn_SPC_BindResponse_specs_1 = {
    sizeof(struct BindResponse),   offsetof(struct BindResponse, _asn_ctx),
    asn_MAP_BindResponse_tag2el_1, 5, /* Count of tags in the map */
    0,                             0,
    0, /* Optional elements (not needed) */
    4, /* Start extensions */
    6  /* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_BindResponse = {
    "BindResponse", "BindResponse", SEQUENCE_free, SEQUENCE_print,
    SEQUENCE_constraint, SEQUENCE_decode_ber, SEQUENCE_encode_der,
    SEQUENCE_decode_xer, SEQUENCE_encode_xer, 0,
    0, /* No PER support, use "-gen-PER" to enable */
    0, /* Use generic outmost tag fetcher */
    asn_DEF_BindResponse_tags_1,
    sizeof(asn_DEF_BindResponse_tags_1) /
            sizeof(asn_DEF_BindResponse_tags_1[0]) -
        1,                       /* 1 */
    asn_DEF_BindResponse_tags_1, /* Same as above */
    sizeof(asn_DEF_BindResponse_tags_1) /
        sizeof(asn_DEF_BindResponse_tags_1[0]), /* 2 */
    0,                                          /* No PER visible constraints */
    asn_MBR_BindResponse_1,
    5,                            /* Elements count */
    &asn_SPC_BindResponse_specs_1 /* Additional specs */
};