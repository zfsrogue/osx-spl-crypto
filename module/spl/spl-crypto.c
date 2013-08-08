#include <sys/crypto/api.h>
#include <sys/cmn_err.h>


// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
//#define ZFS_CRYPTO_VERBOSE


/*
 * The Crypto API has a bug, to work around it, we can allocate a new linear
 * DST buffer, and copy. Which is not as efficient.
 * The modules sun-ccm etc, was written to avoid this bug,
 * and the need for copy.
 */
//#define ZFS_COPYDST


/*
 * Linux cipher types, and the Solaris equivalent.
 *
 * This is an indexed structure. First entry is not used, since return
 * of zero is considered failure. First cipher match, returns "1", then
 * "1" is used to look up the cipher name, and optional hmac.
 *
 */

enum cipher_type_t {
    CIPHER_TYPE_AEAD = 0,
    CIPHER_TYPE_BLK,
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
    int power_on_test; /* If 0, check cipher exists. Set to 1 after that */
    char *linux_name;
    char *hmac_name;   /* optional hmac if not part of linux_name */
};

typedef struct cipher_map_s cipher_map_t;

static cipher_map_t cipher_map[] =
{
    /* 0, not used, must be defined */
    { CIPHER_TYPE_MAC, PARAM_TYPE_NONE, "NULL Cipher", 0, NULL, NULL },
#if 0
    // TODO, attempt to make the MAC be the same as Solaris
    { CIPHER_TYPE_AEAD, PARAM_TYPE_CCM,
      "CKM_AES_CCM", 0, "sun-ctr(aes)", "hmac(sha256)" },
#else
    { CIPHER_TYPE_AEAD, PARAM_TYPE_CCM,
      "CKM_AES_CCM", 0, "sun-ccm(aes)", NULL },
#endif
    { CIPHER_TYPE_AEAD, PARAM_TYPE_GCM,
      "CKM_AES_GCM", 0, "sun-gcm(aes)", NULL },
    { CIPHER_TYPE_BLK,  PARAM_TYPE_NONE,
      "CKM_AES_CTR", 0, "sun-ctr(aes)", NULL },
    { CIPHER_TYPE_MAC,  PARAM_TYPE_NONE,
      "CKM_SHA256_HMAC_GENERAL", 0, NULL, "hmac(sha256)" },
};

#define NUM_CIPHER_MAP (sizeof(cipher_map) / sizeof(cipher_map_t))



void spl_crypto_map_iv(unsigned char *iv, int len, crypto_mechanism_t *mech)
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

            // 'iv' is set as, from Solaris kernel sources;
            // In ZFS-crypt, the "nonceSize" is often 12
            // q = (uint8_t)((15 - nonceSize) & 0xFF);
            // cb[0] = 0x07 & (q-1);
            // cb[1..12] = supplied nonce
            // The counter, and length, is handled inside crypto, so we just
            // clear it here. (set it to 1)
            memset(&iv[ccm_param->ulNonceSize+1], 0,
                   len-ccm_param->ulNonceSize-2); // skip flags, and [15]
            iv[0] = (( 15-ccm_param->ulNonceSize-1 )&7);
            memcpy(&iv[1], ccm_param->nonce, ccm_param->ulNonceSize);
            iv[15] = 0x01;
            return;
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

            return;
        }
        break;

    case PARAM_TYPE_CTR:
        {
            CK_AES_CTR_PARAMS *ctr_param = (CK_AES_CTR_PARAMS *)mech->cm_param;
            if (!ctr_param) goto clear;

            memset(iv, 0, len);
            memcpy(iv, ctr_param->cb, ctr_param->ulCounterBits >> 3);
            return;
        }

    default:
        break;
    }

 clear:
    memset(iv, 0, len);
}



int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
    int ret = CRYPTO_FAILED;
    return ret;
}






int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
    return CRYPTO_FAILED;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{

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

    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

    return CRYPTO_MECH_INVALID;
}





