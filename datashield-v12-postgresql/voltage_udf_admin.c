// voltage_udf_admin.c (Versi Optimal)
// Membersihkan kedua cache: kredensial dan objek FPE.

#include "voltage_udf_common.h" // Menggunakan header umum yang sama

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(datashield_cache_reload);

/**
 * @brief UDF untuk membersihkan semua cache in-memory (kredensial dan objek FPE).
 * Memaksa panggilan UDF berikutnya untuk mengambil ulang kredensial dari DB dan membuat ulang objek FPE.
 * Penting untuk dijalankan setelah ada perubahan pada tabel datashield.credentials.
 */
Datum datashield_cache_reload(PG_FUNCTION_ARGS) {
    // Pastikan konteks utama sudah diinisialisasi
    init_voltage_context_if_needed();

    // 1. Membersihkan FPE Object Cache
    if (fpe_cache != NULL) {
        HASH_SEQ_STATUS status;
        FPENode *fpe_node;

        // Penting: Hancurkan setiap objek VeFPE di dalam cache sebelum menghancurkan cache itu sendiri
        hash_seq_init(&status, fpe_cache);
        while ((fpe_node = (FPENode *) hash_seq_search(&status)) != NULL) {
            if (fpe_node->fpe) {
                VeDestroyFPE(&(fpe_node->fpe));
            }
        }
        
        hash_destroy(fpe_cache);
        
        // Buat kembali FPE cache yang kosong
        HASHCTL ctl;
        memset(&ctl, 0, sizeof(ctl));
        ctl.keysize = 1024;
        ctl.entrysize = sizeof(FPENode);
        // Pastikan alokasi terjadi di memori konteks yang sama
        ctl.hcxt = TopMemoryContext;
        fpe_cache = hash_create("Voltage FPE Object Cache", 256, &ctl, HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
    }

    // 2. Membersihkan Credential Cache
    if (credential_cache != NULL) {
        hash_destroy(credential_cache);
        
        HASHCTL ctl;
        memset(&ctl, 0, sizeof(ctl));
        ctl.keysize = sizeof(int32);
        ctl.entrysize = sizeof(CredentialNode);
        ctl.hcxt = TopMemoryContext;
        credential_cache = hash_create("Voltage Credential Cache", 32, &ctl, HASH_ELEM | HASH_CONTEXT);
    }

    PG_RETURN_TEXT_P(cstring_to_text("SUCCESS: Credential and FPE Object caches have been reloaded."));
}