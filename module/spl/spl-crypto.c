#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <sys/crypto/sha2.h>
#include <sys/crypto/rijndael.h>

#include <sys/crypto/sun_ccm.h>
#include <sys/crypto/sun_gcm.h>

// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
//#define ZFS_CRYPTO_VERBOSE




enum cipher_type_t {
    CIPHER_TYPE_STREAM = 0,
    CIPHER_TYPE_BLOCK,
    CIPHER_TYPE_MAC,
};

enum param_type_t {
    PARAM_TYPE_NONE = 0,
    PARAM_TYPE_CCM,
    PARAM_TYPE_GCM,
    PARAM_TYPE_CTR
};

struct cipher_map_s {
    enum cipher_type_t type;
    enum param_type_t param_type;
    char *solaris_name;

    void (*setkey)(rijndael_ctx *, uint8_t *, uint32_t);

    int (*enc)(rijndael_ctx *,
               crypto_data_t *,
               crypto_data_t *,
               uint8_t *,
               uint32_t,
               uint32_t);

    int (*dec)(rijndael_ctx *,
               crypto_data_t *,
               crypto_data_t *,
               uint8_t *,
               uint32_t,
               uint32_t);
};

typedef struct cipher_map_s cipher_map_t;

static cipher_map_t cipher_map[] =
{
    /* 0, not used, must be defined */
    { CIPHER_TYPE_MAC, PARAM_TYPE_NONE, "NULL Cipher", NULL, NULL, NULL },

    { CIPHER_TYPE_STREAM, PARAM_TYPE_CCM, "CKM_AES_CCM",
      sun_ccm_setkey, sun_ccm_encrypt_and_auth, sun_ccm_decrypt_and_auth },

    { CIPHER_TYPE_STREAM, PARAM_TYPE_GCM, "CKM_AES_GCM",
      sun_gcm_setkey, sun_gcm_encrypt_and_auth, sun_gcm_decrypt_and_auth },

    { CIPHER_TYPE_BLOCK, PARAM_TYPE_GCM, "CKM_AES_CTR",
      sun_gcm_setkey, sun_gcm_encrypt_and_auth, sun_gcm_decrypt_and_auth },

    { CIPHER_TYPE_MAC, PARAM_TYPE_NONE, "CKM_SHA256_HMAC_GENERAL",
      NULL, NULL, NULL },
};

#define NUM_CIPHER_MAP (sizeof(cipher_map) / sizeof(cipher_map_t))



int crypto_get_buffer(crypto_data_t *solaris_buffer, unsigned int *index,
                      uint8_t **addr, uint64_t *size)
{
    struct uio *uio = NULL;

    switch(solaris_buffer->cd_format) {
    case CRYPTO_DATA_RAW: // One buffer.
        // Only one buffer available, asking for any other is wrong
        if (*index != 0)
            return 0;

        *size = solaris_buffer->cd_length;
        *addr = solaris_buffer->cd_raw.iov_base;
        return *size;

    case CRYPTO_DATA_UIO: // Multiple buffers.
        uio = solaris_buffer->cd_uio;

        // Outside the range of available iovecs?
        if (*index >= uio_iovcnt(uio)) return 0;

        if (uio_getiov( uio,
                        *index,
                        (user_addr_t *)addr,
                        size) == 0) {
            *index = *index + 1;
            return *size;
        }
        // Failed
        return 0;

    case CRYPTO_DATA_MBLK: // network mbufs, not supported
    default:
        cmn_err(CE_PANIC, "spl-crypto: map->cd_format of unsupported type=%d",
                solaris_buffer->cd_format);
        return 0;
    } // switch cd_format
    return 0;
}



/*
 * Compute the CCM/GCM 'iv' for the counter.
 */
static int spl_crypto_map_iv(unsigned char *iv, int len,
                             crypto_mechanism_t *mech)
{
    cipher_map_t *cm = NULL;

    // Make sure we are to use iv
    if (!mech || !mech->cm_param || (len < 16)) goto clear;

    cm = &cipher_map[ mech->cm_type ];

    switch(cm->param_type) {

    case PARAM_TYPE_CCM:
        {
            CK_AES_CCM_PARAMS *ccm_param = (CK_AES_CCM_PARAMS *)mech->cm_param;
            if (!ccm_param || !ccm_param->nonce) goto clear;

            memcpy(iv, ccm_param->nonce, ccm_param->ulNonceSize);
            return ccm_param->ulNonceSize;

        }
        break;


    case PARAM_TYPE_GCM:
        {
            CK_AES_GCM_PARAMS *gcm_param = (CK_AES_GCM_PARAMS *)mech->cm_param;
            uint32_t ivlen;
            if (!gcm_param || !gcm_param->pIv) goto clear;

            /*
             * Unfortunately, the implementations between FreeBSD and
             * Linux differ in handling the case of GCM ivlen != 12.
             * So we force ivlen = 12 for now.
             */

            ivlen = gcm_param->ulIvLen;
            if (ivlen != 12) ivlen = 12;

            memset(iv, 0, len);
            memcpy(iv, gcm_param->pIv, MIN(gcm_param->ulIvLen, ivlen));

            return 12;
        }
        break;

    case PARAM_TYPE_CTR:
        {
            CK_AES_CTR_PARAMS *ctr_param = (CK_AES_CTR_PARAMS *)mech->cm_param;
            if (!ctr_param) goto clear;

            memset(iv, 0, 16);
            memcpy(iv, ctr_param->cb, ctr_param->ulCounterBits >> 3);
            /* Linux crypto API does not let you change ivlen */
            //return ctr_param->ulCounterBits >> 3;
            return 16;
        }

    default:
        break;
    }

 clear:
    memset(iv, 0, len);
    return 0;
}


int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl,
               crypto_data_t *mac, crypto_call_req_t *cr)
{
    int ret = CRYPTO_FAILED;
    SHA256_CTX sha;
    u_int8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t *addr;
    user_size_t size;
    unsigned int index;

    SHA256_Init(&sha);

    index = 0;
    while(crypto_get_buffer(data, &index, &addr, &size)) {
        SHA256_Update(&sha, addr, size);
    }
    SHA256_Final(digest, &sha);

    // FIXME, doesn't handle split digest buffer
    index = 0;
    if (crypto_get_buffer(mac, &index, &addr, &size) &&
        (size >= SHA256_DIGEST_LENGTH)) {
        memcpy(addr, digest, SHA256_DIGEST_LENGTH);
    }

    ret = CRYPTO_SUCCESS;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("spl-crypto: mac returning %d\n", ret);
#endif
    return ret;
}






static int crypto_encrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *plaintext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *crypttext,
                                 crypto_call_req_t *cr)
{
    size_t maclen = 0;
    rijndael_ctx   cc_aes;
    int ret;
    cipher_map_t *cm = NULL;
    uint8_t iv[16];
    uint32_t ivlen = 0;

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    maclen = crypttext->cd_length - plaintext->cd_length;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt_stream: %04lx: maclen %ld\n",
           plaintext->cd_length, maclen);
#endif

    // in CTR mode, we have no authtag
    if (cm->param_type == PARAM_TYPE_CTR)
        maclen = 0;

    cm->setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ivlen = spl_crypto_map_iv(iv, sizeof(iv), mech);

    // encrypt
    ret = cm->enc(&cc_aes,
                  plaintext,
                  crypttext,
                  iv,
                  ivlen,
                  maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt_stream: result %d\n",
           ret);
#endif

    if (!ret) return CRYPTO_SUCCESS;

    return CRYPTO_FAILED;
}



static int crypto_decrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *crypttext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *plaintext,
                                 crypto_call_req_t *cr)
{
    size_t maclen = 0;
    rijndael_ctx   cc_aes;
    int ret = CRYPTO_FAILED;
    uint8_t iv[16];
    uint32_t ivlen = 0;
    cipher_map_t *cm = NULL;

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    maclen = crypttext->cd_length - plaintext->cd_length;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt_stream: %04lx : maclen %ld\n",
           plaintext->cd_length, maclen);
#endif

    // in CTR mode, we have no authtag
    if (cm->param_type == PARAM_TYPE_CTR)
        maclen = 0;

    cm->setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ivlen = spl_crypto_map_iv(iv, sizeof(iv), mech);

    // encrypt
    ret = cm->dec(&cc_aes,
                  crypttext,
                  plaintext,
                  iv,
                  ivlen,
                  maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt_stream: return %d\n", ret);
#endif

    if (ret == EBADMSG) {
        cmn_err(CE_WARN, "crypto: decrypt verify failed.");
        return CRYPTO_INVALID_MAC;
    }

    if (!ret) return CRYPTO_SUCCESS;

    return CRYPTO_FAILED;
}


static int crypto_encrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *plaintext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *ciphertext,
                                crypto_call_req_t *cr)
{
    int ret;

    ret = crypto_encrypt_stream(mech, plaintext, key, tmpl,
                                ciphertext, cr);

    return ret;
}

static int crypto_decrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *ciphertext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *plaintext,
                                crypto_call_req_t *cr)
{
    int ret;

    ret = crypto_decrypt_stream(mech, ciphertext, key, tmpl,
                                plaintext, cr);

    // No authtag used with plain CTR
    if (ret == EBADMSG) ret = CRYPTO_SUCCESS;

    return ret;
}



int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    switch(cm->type) {
    case CIPHER_TYPE_STREAM:
        return crypto_encrypt_stream(mech, plaintext, key, tmpl,
                                     ciphertext, cr);
    case CIPHER_TYPE_BLOCK:
        return crypto_encrypt_block(mech, plaintext, key, tmpl,
                                    ciphertext, cr);
    case CIPHER_TYPE_MAC:
        return crypto_mac(mech, plaintext, key, tmpl,
                          ciphertext, cr);
    }

    return CRYPTO_FAILED;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    switch(cm->type) {
    case CIPHER_TYPE_STREAM:
        return crypto_decrypt_stream(mech, ciphertext, key, tmpl,
                                     plaintext, cr);

    case CIPHER_TYPE_BLOCK:
        return crypto_decrypt_block(mech, ciphertext, key, tmpl,
                                    plaintext, cr);
    case CIPHER_TYPE_MAC:
        return crypto_mac(mech, plaintext, key, tmpl,
                          ciphertext, cr);
    }

    return CRYPTO_FAILED;
}





int crypto_create_ctx_template(crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_ctx_template_t *tmpl, int kmflag)
{
    return 0;
}

void crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
    return;
}


/*
 *
 * This function maps between Solaris cipher string, and Linux cipher string.
 * It is always used as 'early test' on cipher availability, so we include
 * testing the cipher here.
 *
 */
crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    int i;

    if (!name || !*name) {
        printf("Invalid crypto name\n");
        return CRYPTO_MECH_INVALID;
    }

    for (i = 0; i < NUM_CIPHER_MAP; i++) {

        if (cipher_map[i].solaris_name &&
            !strcmp(cipher_map[i].solaris_name, name)) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("called crypto_mech2id '%s' (returning %d)\n",
                   name, i);
#endif

            return i; // Index into list.
        }
    } // for all cipher maps

    printf("spl-crypto: mac2id returning INVALID for '%s'\n", name);
    return CRYPTO_MECH_INVALID;
}




