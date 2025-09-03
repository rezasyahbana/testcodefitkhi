// voltage_udf_common.h (Versi Perbaikan Final)
// Berisi logika inti: caching state, inisialisasi Voltage, dan fungsi pekerja internal.

#ifndef VOLTAGE_UDF_COMMON_H
#define VOLTAGE_UDF_COMMON_H

// --- Standard C and PostgreSQL Headers ---
#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/hsearch.h"
#include "executor/spi.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include <ctype.h>

// --- Voltage Simple API Headers ---
#include "veapi.h"
#include "vefpe.h"

// --- Definisi Struktur untuk Cache ---

// Menyimpan kredensial yang diambil dari database
typedef struct CredentialNode {
    int32 config_id;
    char identity[256];
    char sharedsecret[256];
} CredentialNode;

// Menyimpan objek FPE yang sudah diinisialisasi
typedef struct FPENode {
    char key[1024]; // Kunci cache: format|identity|sharedsecret|protect_flag
    VeFPE fpe;
} FPENode;


// --- Variabel Global Statis untuk State Management ---
static HTAB *fpe_cache = NULL;
static HTAB *credential_cache = NULL;
static VeLibCtx libctx = NULL;
static bool voltage_initialized = false;


// --- Deklarasi Fungsi (Prototypes) ---
void init_voltage_context_if_needed(void);
const CredentialNode* get_credentials_by_id(int config_id);
text* _internal_protect(const char* plaintext_str, int plaintext_len, const char* format, const char* identity, const char* shared_secret);
text* _internal_access(const char* ciphertext_str, int ciphertext_len, const char* format, const char* identity, const char* shared_secret, bool is_masked);
static inline bool is_blank(const char *str, int len);


// --- Implementasi Fungsi ---

static inline bool is_blank(const char *str, int len) {
    if (len == 0) return true;
    for (int i = 0; i < len; i++) {
        if (!isspace((unsigned char)str[i])) {
            return false;
        }
    }
    return true;
}

static void cleanup_voltage(int code, Datum arg) {
    if (fpe_cache) {
        HASH_SEQ_STATUS status;
        FPENode *fpe_node;
        hash_seq_init(&status, fpe_cache);
        while ((fpe_node = (FPENode *) hash_seq_search(&status)) != NULL) {
            if (fpe_node->fpe) VeDestroyFPE(&(fpe_node->fpe));
        }
        hash_destroy(fpe_cache);
        fpe_cache = NULL;
    }
    if (credential_cache) {
        hash_destroy(credential_cache);
        credential_cache = NULL;
    }
    if (libctx) {
        VeDestroyLibCtx(&libctx);
        libctx = NULL;
    }
    voltage_initialized = false;
}

void init_voltage_context_if_needed(void) {
    if (voltage_initialized) return;
    MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);
    
    HASHCTL ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.keysize = 1024;
    ctl.entrysize = sizeof(FPENode);
    fpe_cache = hash_create("Voltage FPE Object Cache", 256, &ctl, HASH_ELEM | HASH_STRINGS);

    memset(&ctl, 0, sizeof(ctl));
    ctl.keysize = sizeof(int32);
    ctl.entrysize = sizeof(CredentialNode);
    credential_cache = hash_create("Voltage Credential Cache", 32, &ctl, HASH_ELEM);

    VeLibCtxParams libParams = VeLibCtxParamsDefaults;
    libParams.policyURL = "https://voltage-pp-0000.opentext.co.id/policy/clientPolicy.xml";
    libParams.trustStorePath = "/opt/voltage/simpleapi/trustStore";
    libParams.clientIdProduct = "PostgreSQLUDF_Opt";
    libParams.clientIdProductVersion = "3.1.0";
    libParams.enableMemoryCache = 1; // Mengaktifkan cache internal SimpleAPI
    libParams.allowShortFPE = 1;     // Mengizinkan enkripsi data pendek

    // FIX: Deklarasikan 'status' sebelum digunakan
    int status = VeCreateLibCtx(&libParams, &libctx);

    if (status != 0 || libctx == NULL) {
        const char* error_details = VeGetErrorDetails(libctx);
        MemoryContextSwitchTo(oldcontext);
        elog(ERROR, "Failed to create Voltage libctx: %d. Details: %s", status, error_details ? error_details : "No details available.");
    }

    on_proc_exit(cleanup_voltage, (Datum)0);
    voltage_initialized = true;
    MemoryContextSwitchTo(oldcontext);
}

VeFPE get_cached_fpe(const char* format, const char* identity, const char* shared_secret, int protect) {
    char key[1024];
    FPENode *node;
    bool found;
    snprintf(key, sizeof(key), "%s|%s|%s|%d", format, identity, shared_secret, protect);
    node = (FPENode *) hash_search(fpe_cache, key, HASH_FIND, &found);
    if (found && node->fpe != NULL) return node->fpe;
    
    VeFPE new_fpe = NULL;
    VeFPEParams fpeParams = VeFPEParamsDefaults;
    fpeParams.protect = protect;
    fpeParams.access = !protect;
    fpeParams.format = format;
    fpeParams.sharedSecret = shared_secret;
    fpeParams.identity = identity;
    
    // FIX: Deklarasikan 'status' sebelum digunakan
    int status = VeCreateFPE(libctx, &fpeParams, &new_fpe);
    if (status != 0) {
        elog(ERROR, "VeCreateFPE failed for key [%s] with status: %d. Details: %s", key, status, VeGetErrorDetails(libctx));
    }
    
    node = (FPENode *) hash_search(fpe_cache, key, HASH_ENTER, &found);
    if(found && node->fpe != NULL) {
        VeDestroyFPE(&(node->fpe));
    }
    node->fpe = new_fpe;
    return new_fpe;
}

const CredentialNode* get_credentials_by_id(int config_id) {
    CredentialNode *node;
    bool found;
    init_voltage_context_if_needed();
    node = (CredentialNode *) hash_search(credential_cache, &config_id, HASH_FIND, &found);
    if (found) return node;

    if (SPI_connect() != SPI_OK_CONNECT) elog(ERROR, "SPI_connect failed");
    char query[256];
    snprintf(query, sizeof(query), "SELECT identity, sharedsecret FROM datashield.credentials WHERE config_id = %d", config_id);
    if (SPI_exec(query, 1) != SPI_OK_SELECT) {
        SPI_finish();
        elog(ERROR, "SPI_exec failed for query: %s", query);
    }
    if (SPI_processed == 0) {
        SPI_finish();
        elog(ERROR, "Configuration ID %d not found in datashield.credentials", config_id);
    }
    char *identity_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    char *sharedsecret_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
    if (identity_str == NULL || sharedsecret_str == NULL) {
        SPI_finish();
        elog(ERROR, "NULL identity or sharedsecret found for config_id %d", config_id);
    }
    
    node = (CredentialNode *) hash_search(credential_cache, &config_id, HASH_ENTER, &found);
    node->config_id = config_id;
    strncpy(node->identity, identity_str, sizeof(node->identity) - 1);
    node->identity[sizeof(node->identity) - 1] = '\0';
    strncpy(node->sharedsecret, sharedsecret_str, sizeof(node->sharedsecret) - 1);
    node->sharedsecret[sizeof(node->sharedsecret) - 1] = '\0';

    pfree(identity_str);
    pfree(sharedsecret_str);
    SPI_finish();
    return node;
}

text* _internal_protect(const char* plaintext_str, int plaintext_len, const char* format, const char* identity, const char* shared_secret) {
    init_voltage_context_if_needed();
    VeFPE fpe = get_cached_fpe(format, identity, shared_secret, 1);
    
    // FIX: Deklarasikan 'buffer_size' sebelum digunakan
    int buffer_size = plaintext_len * 4 + 256; 
    unsigned char* ciphertext_buf = (unsigned char*)palloc(buffer_size);

    VeProtectParams params = VeProtectParamsDefaults;
    params.plaintext = (const unsigned char*)plaintext_str;
    params.plaintextSize = plaintext_len;
    params.ciphertext = ciphertext_buf;
    params.ciphertextBufferSize = buffer_size;
    
    // FIX: Deklarasikan 'status' sebelum digunakan
    int status = VeProtect(fpe, &params);
    if (status != 0) {
        pfree(ciphertext_buf);
        elog(ERROR, "VeProtect failed with status: %d. Details: %s", status, VeGetErrorDetails(libctx));
    }

    text* result = (text*)palloc(VARHDRSZ + params.ciphertextSize);
    SET_VARSIZE(result, VARHDRSZ + params.ciphertextSize);
    memcpy(VARDATA(result), ciphertext_buf, params.ciphertextSize);
    
    pfree(ciphertext_buf);
    return result;
}

text* _internal_access(const char* ciphertext_str, int ciphertext_len, const char* format, const char* identity, const char* shared_secret, bool is_masked) {
    init_voltage_context_if_needed();
    VeFPE fpe = get_cached_fpe(format, identity, shared_secret, 0);

    int buffer_size = ciphertext_len + 256;
    unsigned char* plaintext_buf = (unsigned char*)palloc(buffer_size);

    VeAccessParams params = VeAccessParamsDefaults;
    params.ciphertext = (const unsigned char*)ciphertext_str;
    params.ciphertextSize = ciphertext_len;
    params.plaintext = plaintext_buf;
    params.plaintextBufferSize = buffer_size;
    params.masked = is_masked ? 1 : 0; // Mengaktifkan masking bawaan API
    
    // FIX: Deklarasikan 'status' sebelum digunakan
    int status = VeAccess(fpe, &params);
    if (status != 0) {
        pfree(plaintext_buf);
        elog(ERROR, "VeAccess failed with status: %d. Details: %s", status, VeGetErrorDetails(libctx));
    }

    text* result = (text*)palloc(VARHDRSZ + params.plaintextSize);
    SET_VARSIZE(result, VARHDRSZ + params.plaintextSize);
    memcpy(VARDATA(result), plaintext_buf, params.plaintextSize);

    pfree(plaintext_buf);
    return result;
}

#endif // VOLTAGE_UDF_COMMON_H