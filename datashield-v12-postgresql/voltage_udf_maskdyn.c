// voltage_udf_maskdyn.c
// Pustaka untuk fungsi masking dinamis: maskdyn_raw dan shieldmaskdyn.

#include "voltage_udf_common.h"

PG_MODULE_MAGIC;

// --- Deklarasi Fungsi Lokal ---
PG_FUNCTION_INFO_V1(maskdyn_raw);
PG_FUNCTION_INFO_V1(shieldmaskdyn);
static void parse_mask_pattern(const char* pattern, int* leading, int* trailing, char* mask_char);
static text* perform_dynamic_masking(const char* decrypted_str, int decrypted_len, const char* mask_pattern);


// --- Implementasi Helper Functions untuk Masking Dinamis ---

/**
 * @brief Mem-parsing pola masking kustom seperti 'f6l4*' atau 'f0l4X'.
 */
static void parse_mask_pattern(const char* pattern, int* leading, int* trailing, char* mask_char) {
    int lead = 0, trail = 0;
    char m_char = 'X'; // Karakter masking default
    const char *p = pattern;

    if (*p == 'f' || *p == 'F') {
        p++;
        while (isdigit((unsigned char)*p)) {
            lead = lead * 10 + (*p - '0');
            p++;
        }
    }
    if (*p == 'l' || *p == 'L') {
        p++;
        while (isdigit((unsigned char)*p)) {
            trail = trail * 10 + (*p - '0');
            p++;
        }
    }
    if (*p != '\0') {
        m_char = *p;
    }

    *leading = lead;
    *trailing = trail;
    *mask_char = m_char;
}

/**
 * @brief Menerapkan logika masking kustom ke string yang sudah didekripsi.
 */
static text* perform_dynamic_masking(const char* decrypted_str, int decrypted_len, const char* mask_pattern) {
    int leading, trailing;
    char mask_char;
    
    parse_mask_pattern(mask_pattern, &leading, &trailing, &mask_char);

    // Jika panjang data kurang dari jumlah unmasked, kembalikan data asli
    if ((leading + trailing) >= decrypted_len) {
        text* result = (text*)palloc(VARHDRSZ + decrypted_len);
        SET_VARSIZE(result, VARHDRSZ + decrypted_len);
        memcpy(VARDATA(result), decrypted_str, decrypted_len);
        return result;
    }
    
    text* result = (text*)palloc(VARHDRSZ + decrypted_len);
    SET_VARSIZE(result, VARHDRSZ + decrypted_len);
    char* masked_data = VARDATA(result);

    // Salin bagian awal yang tidak dimasking
    if (leading > 0) {
        memcpy(masked_data, decrypted_str, leading);
    }
    
    // Isi bagian tengah dengan karakter masking
    int masked_len = decrypted_len - leading - trailing;
    if (masked_len > 0) {
        memset(masked_data + leading, mask_char, masked_len);
    }
    
    // Salin bagian akhir yang tidak dimasking
    if (trailing > 0) {
        memcpy(masked_data + leading + masked_len, decrypted_str + leading + masked_len, trailing);
    }
    
    return result;
}


// --- Implementasi UDF ---

Datum maskdyn_raw(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }

    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char* identity = text_to_cstring(PG_GETARG_TEXT_PP(2));
    const char* shared_secret = text_to_cstring(PG_GETARG_TEXT_PP(3));
    const char* mask_pattern = text_to_cstring(PG_GETARG_TEXT_PP(4));

    // Lakukan dekripsi terlebih dahulu
    text* decrypted_text = _internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, identity, shared_secret, false);
    
    // Lakukan masking kustom pada hasil dekripsi
    text* final_result = perform_dynamic_masking(VARDATA_ANY(decrypted_text), VARSIZE_ANY_EXHDR(decrypted_text), mask_pattern);
    
    pfree(decrypted_text);
    PG_RETURN_TEXT_P(final_result);
}

Datum shieldmaskdyn(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) PG_RETURN_NULL();
    text* input_data = PG_GETARG_TEXT_PP(0);
    if (is_blank(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data))) {
        PG_RETURN_TEXT_P(input_data);
    }
    
    const char* format = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int config_id = PG_GETARG_INT32(2);
    const char* mask_pattern = text_to_cstring(PG_GETARG_TEXT_PP(3));

    const CredentialNode* creds = get_credentials_by_id(config_id);
    
    // Panggil implementasi maskdyn_raw secara internal
    text* decrypted_text = _internal_access(VARDATA_ANY(input_data), VARSIZE_ANY_EXHDR(input_data), format, creds->identity, creds->sharedsecret, false);
    text* final_result = perform_dynamic_masking(VARDATA_ANY(decrypted_text), VARSIZE_ANY_EXHDR(decrypted_text), mask_pattern);
    
    pfree(decrypted_text);
    PG_RETURN_TEXT_P(final_result);
}