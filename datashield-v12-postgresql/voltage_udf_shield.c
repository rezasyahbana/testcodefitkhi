// voltage_udf_shield.c
// Pustaka untuk fungsi config_id: shield, unshield, shieldmask.

#include "voltage_udf_common.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(shield);
PG_FUNCTION_INFO_V1(unshield);
PG_FUNCTION_INFO_V1(shieldmask);

Datum shield(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int config_id = PG_GETARG_INT32(2);
    const CredentialNode* creds = get_credentials_by_id(config_id);
    PG_RETURN_TEXT_P(_internal_protect(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, creds->identity, creds->sharedsecret));
}

Datum unshield(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int config_id = PG_GETARG_INT32(2);
    const CredentialNode* creds = get_credentials_by_id(config_id);
    PG_RETURN_TEXT_P(_internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, creds->identity, creds->sharedsecret, false));
}

Datum shieldmask(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int config_id = PG_GETARG_INT32(2);
    const CredentialNode* creds = get_credentials_by_id(config_id);
    PG_RETURN_TEXT_P(_internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, creds->identity, creds->sharedsecret, true));
}