/*------------------------------------------------------------------
 * utils.c - Generic functions used by all the example apps
 *
 * August, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "est_ossl_util.h"
#include "est_locl.h"

/*
 * Key wrap algorithm optionally used to protect private keys
 */
#define EST_PRIVATE_KEY_ENC EVP_aes_128_cbc()

/*
 * Reads a file into an unsigned char array.
 * The array should not be allocated prior to calling this
 * function.  The return value is the size of the file
 * read into the array.
 */
int read_binary_file (char *filename, unsigned char **contents)
{
    FILE *fp;
    int len;

    fp = fopen(filename, "rb");
    if (!fp) {
	printf("\nUnable to open %s for reading\n", filename);
	return -1;
    }

    /*
     * Determine the size of the file
     */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *contents = malloc(len + 1);
    if (!*contents) {
	printf("\nmalloc fail\n");
        fclose(fp);
	return -2;
    }

    if (1 != fread(*contents, len, 1, fp)) {
	printf("\nfread failed\n");
        fclose(fp);
	return -2;
    }
    
    /*
     * put the terminator at the end of the buffer
     */
    *(*contents+len) = 0x00;
    fclose(fp);
    return (len);
}

/*
 * Generic function to write a binary file from
 * raw data.
 */
void write_binary_file (char *filename, unsigned char *contents, int len) 
{
    FILE *fp;

    fp = fopen(filename, "wb");
    if (!fp) {
	printf("\nUnable to open %s for writing\n", filename);
	return;
    }
    fwrite(contents, sizeof(char), len, fp);
    fclose(fp);
}

/*
 * Simple function to display hex data to stdout
 * This is used for debugging
 */
void dumpbin (unsigned char *buf, int len)
{
    int i;

    fflush(stdout);
    printf("\ndumpbin (%lu bytes):\n", (long unsigned)len);
    for (i = 0; i < len; i++) {
        /*if (buf[i] >= 0xA)*/ printf("%c", buf[i]);
        //if (i%32 == 31) printf("\n");
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Helper functions to load in/generate private keys
 */

unsigned char *BIO_copy_data(BIO *out, int *data_lenp) {
    unsigned char *data, *tdata;
    int data_len;

    data_len = BIO_get_mem_data(out, &tdata);
    data = malloc(data_len+1);
    if (data) {
        memcpy(data, tdata, data_len);
	data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
	if (data_lenp) {
	    *data_lenp = data_len;
	}
    } else {
        EST_LOG_ERR("malloc failed");
    }
    return data;
}

/* ISARA: BEGIN */
struct param {
    char *key;
    char *value;
};

char *generate_private_HSS_key (pem_password_cb *cb)
{
    struct param opts[] = {
        { "winternitz_value", "8" },
        { "tree_height", "10" },
        { NULL, NULL }
    };
    struct param *popts = opts;
    char *key_data = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HSS, NULL);
    if (!ctx) {
        ossl_dump_ssl_errors();
        EST_LOG_ERR("Error creating pkey context for id %d", EVP_PKEY_HSS);
        goto end;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EST_LOG_ERR("Error initializing keygen for id %d", EVP_PKEY_HSS);
        ossl_dump_ssl_errors();
        goto end;
    }

    if (popts != NULL) {
        while (popts->key != NULL) {
            if (EVP_PKEY_CTX_ctrl_str(ctx, popts->key, popts->value) <= 0) {
                EST_LOG_ERR("Error setting params %s = %s", popts->key, popts->value);
                ossl_dump_ssl_errors();
                goto end;
            }
            popts++;
        }

    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EST_LOG_ERR("Error doing keygen for id %d", EVP_PKEY_HSS);
        ossl_dump_ssl_errors();
        goto end;
    }

    do {
        BIO *out = BIO_new(BIO_s_mem());
        if (!out) {
            break;
        }
        PEM_write_bio_PrivateKey(out, pkey, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
        key_data = (char *)BIO_copy_data(out, NULL);
        BIO_free(out);
        if (key_data && !strstr(key_data, "-----BEGIN PRIVATE KEY-----")) {
            // happens if passphrase entered via STDIN does not verify or has less than 4 characters
            free(key_data);
            key_data = NULL;
        }
    } while (cb && !key_data);

end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return (key_data);
}
/* ISARA: END */

char *generate_private_RSA_key (int key_size, pem_password_cb *cb)
{
    char *key_data = NULL;

    RSA *rsa = RSA_new();
    if (!rsa) {
        return NULL;
    }
    BIGNUM *bn = BN_new();
    if (!bn) {
        RSA_free(rsa);
        return NULL;
    }

    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, key_size, bn, NULL);

    do {
        BIO *out = BIO_new(BIO_s_mem());
        if (!out) {
            break;
        }
        PEM_write_bio_RSAPrivateKey(out, rsa, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
        key_data = (char *)BIO_copy_data(out, NULL);
        BIO_free(out);
        if (key_data && !key_data[0]) {
            // happens if passphrase entered via STDIN does not verify or has less than 4 characters
            free(key_data);
            key_data = NULL;
        }
    } while (cb && !key_data);

    RSA_free(rsa);
    BN_free(bn);
    return (key_data);
}

char *generate_private_EC_key (int curve_nid, pem_password_cb *cb)
{
    EC_KEY *eckey;
    EC_GROUP *group = NULL;
    char *key_data = NULL;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

    /*
     * Generate an EC key
     */

    eckey = EC_KEY_new();
    if (!eckey) {
        return NULL;
    }

    group = EC_GROUP_new_by_curve_name(curve_nid);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
    EC_GROUP_set_point_conversion_form(group, form);
    EC_KEY_set_group(eckey, group);
    if (!EC_KEY_generate_key(eckey)) {
        return (NULL);
    }

    do {
        BIO *out = BIO_new(BIO_s_mem());
        if (!out) {
            break;
        }
        PEM_write_bio_ECPKParameters(out, group);
        PEM_write_bio_ECPrivateKey(out, eckey, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
        key_data = (char *)BIO_copy_data(out, NULL);
        BIO_free(out);
        if (key_data && !strstr(key_data, "-----BEGIN EC PRIVATE KEY-----")) {
            // happens if passphrase entered via STDIN does not verify or has less than 4 characters
            free(key_data);
            key_data = NULL;
        }
    } while (cb && !key_data);

    EC_KEY_free(eckey);
    return (key_data);
}

/*
 * Helper function that can be used to write out a private key
 */
char *private_key_to_PEM (const EVP_PKEY* pkey, pem_password_cb *cb) {
    char *pkey_pem = NULL;
    BIO *out = BIO_new(BIO_s_mem());
    if (out) {
        PEM_write_bio_PrivateKey(out, (EVP_PKEY *)pkey, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
    pkey_pem = (char *)BIO_copy_data(out, NULL);
    BIO_free(out);
    }
    return (pkey_pem);
}

/*
 * Helper function to load a private key from a string
 */
EVP_PKEY *load_private_key (const unsigned char *key, int key_len, int format, pem_password_cb *cb)
{
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;

    if (key == NULL) {
        EST_LOG_ERR("No key data provided");
        return NULL;
    }

    in = BIO_new_mem_buf((unsigned char *)key, key_len);
    if (in == NULL) {
        EST_LOG_ERR("Unable to open the provided key buffer");
        return (NULL);
    }

    switch (format) {
    case EST_FORMAT_PEM:
        pkey = PEM_read_bio_PrivateKey(in, NULL, cb, NULL);
        break;
    case EST_FORMAT_DER:
        pkey = d2i_PrivateKey_bio(in, NULL);
        break;
    default:
        EST_LOG_ERR("Invalid key format");
        break;
    }
    BIO_free(in);

    return (pkey);
}

/*
 * Helper function to load a private key from a file
 */
EVP_PKEY *read_private_key(const char *key_file, pem_password_cb *cb)
{
    BIO *keyin;
    EVP_PKEY *priv_key;

    /*
     * Read in the private key
     */
    keyin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(keyin, key_file) <= 0) {
    EST_LOG_ERR("Unable to read private key file %s", key_file);
    return(NULL);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead.
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, cb, NULL);
    if (priv_key == NULL) {
    EST_LOG_ERR("Error while parsing PEM encoded private key from file %s", key_file);
    ossl_dump_ssl_errors();
    }
    BIO_free(keyin);

    return (priv_key);
}

/* ISARA: BEGIN */
ENGINE *setup_engine(const char *engine)
{
    ENGINE *e = NULL;
    if ((e = ENGINE_by_id(engine)) == NULL) {
        EST_LOG_ERR("Invalid engine \"%s\"", engine);
        return NULL;
    }

    if (!ENGINE_init(e)) {
        EST_LOG_ERR("The engine did not initialize correctly");
        ENGINE_free(e);
        return NULL;
    }

    if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
        EST_LOG_ERR("Unable to use this engine");
        ENGINE_free(e);
        return NULL;
    }

    EST_LOG_INFO("Engine \"%s\" set", ENGINE_get_id(e));
    return e;
}

void release_engine(ENGINE *e)
{
    if (e != NULL) {
        /* Free our "structural" reference. */
        ENGINE_free(e);
    }
}

int set_pkey_filename(EVP_PKEY *pkey, const char *filename) {
    int rv = EST_ERR_X509_PUBKEY;
    EVP_PKEY_CTX *tmpctx = NULL;

    if (pkey->type == NID_hss) {
        /* Create a temporary context */
        tmpctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (tmpctx == NULL) {
            EST_LOG_ERR("Could not create context");
            goto err;
        }

        /* Send the control string. */
        if (EVP_PKEY_CTX_ctrl_str(tmpctx, "private_key_file", filename) <= 0) {
            EST_LOG_ERR("Couldn't set HSS private key file.");
            goto err;
        }

        /* All the work for the tmpctx is done. */
        EVP_PKEY_CTX_free(tmpctx);
        tmpctx = NULL;
    }

    rv = EST_ERR_NONE;

err:
    if (tmpctx != NULL) {
        EVP_PKEY_CTX_free(tmpctx);
    }

    return rv;
}
/* ISARA: END */
