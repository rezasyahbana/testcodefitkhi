// voltage_udf_raw.c
// Pustaka untuk fungsi raw: shield_raw, unshield_raw, mask_raw.

#include "voltage_udf_common.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(protectdata_raw);
PG_FUNCTION_INFO_V1(accessdata_raw);
PG_FUNCTION_INFO_V1(maskdata_raw);

Datum protectdata_raw(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char* identity = text_to_cstring(PG_GETARG_TEXT_PP(2));
    const char* shared_secret = text_to_cstring(PG_GETARG_TEXT_PP(3));
    PG_RETURN_TEXT_P(_internal_protect(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, identity, shared_secret));
}

Datum accessdata_raw(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char* identity = text_to_cstring(PG_GETARG_TEXT_PP(2));
    const char* shared_secret = text_to_cstring(PG_GETARG_TEXT_PP(3));
    PG_RETURN_TEXT_P(_internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, identity, shared_secret, false));
}

Datum maskdata_raw(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char* identity = text_to_cstring(PG_GETARG_TEXT_PP(2));
    const char* shared_secret = text_to_cstring(PG_GETARG_TEXT_PP(3));
    PG_RETURN_TEXT_P(_internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, identity, shared_secret, true));
}