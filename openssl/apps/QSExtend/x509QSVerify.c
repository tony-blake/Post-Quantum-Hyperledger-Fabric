/** @file openssl_x509QSVerify.c Verification of the QS multiple public key algorithm certificates.
 *
 * Isara Corporation Quantum Safe EST Proprietary Software License
 * Statement
 *
 * LICENSE AGREEMENT: The Product(s) that reference this license include
 * embedded proprietary software and software “plug-ins” in source code or
 * object code or both (the “Software”) and accompanying materials (the
 * “Documentation”) that are subject to the license terms and restrictions
 * described below (the “License"). If you do not agree to the License
 * terms, do not use the Product, notify Isara Corporation (“Isara”) by
 * electronic mail at sales@isara.com and erase any copies of the Product
 * in your possession. If you are entering into this License on behalf of
 * a company or other legal entity, you represent that you have the right
 * to bind that entity to all terms, and “you” refers both to you
 * personally and such entity.
 *
 * USE AND DISTRIBUTION: You may use the Software only in the form and in
 * the Product(s) delivered to you for the purposes of integration,
 * development and testing with your own products and/or as part of a
 * monitoring and/or control group beta test with third parties that agree
 * in writing to be bound by the terms of this License.
 *
 * ADDITIONAL RESTRICTIONS: You shall not use, modify, reproduce, reverse
 * engineer, disassemble, decompile or otherwise attempt to derive source
 * code from the Software (except to the extent that such limitations may
 * not be prohibited by law), sublicense, or distribute the Software or
 * Documentation other than as permitted by this License. You shall not
 * remove any proprietary notices, labels or marks on the Product(s) “ZIP
 * file”, Software or Documentation. No license is granted to use or
 * reproduce any Isara trademarks.
 *
 * OWNERSHIP AND NOTICE: Except for the limited rights granted above,
 * Isara and its suppliers retain all right, title and interest in and to
 * the Software and Documentation, including copyrights, patents, trade
 * secrets and other proprietary rights. Certain components of the
 * Software that are subject to open source and third party licenses, the
 * terms and conditions of which can found at https://github.com/cisco and
 * select the applicable hash-sigs or libest license filed on the Github
 * repository. If you require additional guidance, notify sales@isara.com
 * for assistance. As a condition of the License, you agree to comply with
 * all of the foregoing open source and third party license terms. Unless
 * required by applicable law, such components are provided on an ‘AS IS’
 * BASIS, WITHOUT EXPRESS OR IMPLIED WARRANTIES OR CONDITIONS OF ANY KIND.
 *
 * WARRANTY DISCLAIMER: THE SOFTWARE AND DOCUMENTATION ARE PROVIDED TO YOU
 * "AS IS", AND YOU ASSUME THE ENTIRE RISK OF THEIR USE. ISARA AND ITS
 * SUPPLIERS MAKES NO WARRANTIES OR CONDITIONS, EXPRESS, IMPLIED,
 * STATUTORY OR IN ANY COMMUNICATION WITH YOU, AND ISARA CORPORATION
 * EXPRESSLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT WITH RESPECT TO THE
 * SOFTWARE (INCLUDING ANY MODIFICATIONS MADE THERETO BY ANY PERSON
 * WHETHER OR NOT AN EMPLOYEE OR CONTRACTOR OF ISARA) OR DOCUMENTATION
 * PROVIDED TO YOU. ISARA EMPLOYEES AND OTHER PERSONNEL ARE NOT AUTHORIZED
 * TO MAKE ANY WARRANTY THAT IS INCONSISTENT WITH THIS DISCLAIMER.
 *
 * LIMITATION OF LIABILITY: IN NO EVENT WILL ISARA OR ITS SUPPLIERS AND
 * SUPPLIERS BE LIABLE FOR LOSS OF DATA, LOST PROFITS, COST OF COVER, OR
 * OTHER SPECIAL, INCIDENTAL, PUNITIVE, CONSEQUENTIAL, OR INDIRECT DAMAGES
 * ARISING FROM USE OF THE SOFTWARE OR DOCUMENTATION, HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, AND REGARDLESS OF WHETHER ISARA OR ITS
 * SUPPLIERS HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  ISARA
 * AND ITS SUPPLIERS BEAR NO LIABILITY FOR ANY PROGRAMS OR DATA STORED IN
 * OR USED WITH THIS PRODUCT, INCLUDING THE COST OF RECOVERING SUCH
 * PROGRAMS OR DATA.
 *
 * Copyright (c) 2017 ISARA Corporation. All Rights Reserved. This file
 * contains Proprietary information of Isara Corporation. Unauthorized
 * copying or use of this file via any medium is strictly prohibited.
 * Written by Anthony Hu, anthony.hu@isara.com; Daniel Van Geest,
 * daniel.vangeest@isara.com, December, 2017.
 */

/* Modified.  Was genpkey.c.
 */

/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../apps/apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

static int x509qsverify_load_certs(BIO *err, BIO *bio,
                      const char *pass, ENGINE *e,
                      STACK_OF(X509) **pcerts)
{
    int i;
    STACK_OF(X509_INFO) *xis = NULL;
    X509_INFO *xi;
    int rv = 0;

    xis = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);

    if (pcerts) {
        *pcerts = sk_X509_new_null();
        if (!*pcerts)
            goto end;
    }

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        if (xi->x509 && pcerts) {
            if (!sk_X509_push(*pcerts, xi->x509))
                goto end;
            xi->x509 = NULL;
        }
    }

    if (pcerts && sk_X509_num(*pcerts) > 0)
        rv = 1;

 end:

    if (xis)
        sk_X509_INFO_pop_free(xis, X509_INFO_free);

    if (rv == 0) {
        if (pcerts) {
            sk_X509_pop_free(*pcerts, X509_free);
            *pcerts = NULL;
        }
        BIO_printf(err, "unable to load certificates.\n");
        ERR_print_errors(err);
    }
    return rv;
}

#define X509_NAME_LINE_LENGTH 128

/* on WIN16 you need to add `_far _loadds` */
static int cb(int ok, X509_STORE_CTX *ctx) {
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    int cert_error = X509_STORE_CTX_get_error(ctx);
    int cert_depth = X509_STORE_CTX_get_error_depth(ctx);
    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    ASN1_BIT_STRING *new_sig = NULL;
    X509 * alt_free_cert = NULL;
    X509 *issuer = NULL;

    int qs_pub_key_ind = -1;
    X509_EXTENSION *qs_pub_key_ext = NULL;

    int qs_sigalg_ind = -1;
    X509_ALGOR *qssigalg = NULL;
    X509_EXTENSION *qs_sigalg_ext = NULL;

    int alg_nid = -1;
    int qs_sigval_ind = -1;
    X509_EXTENSION *qs_sigval_ext = NULL;
    X509_EXTENSION *new_qs_sigval_ext = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    ASN1_BIT_STRING *qssig = NULL;
    EVP_PKEY * qs_pub_key = NULL;
    X509_ALGOR *algo_holder = NULL;

    char cert_name[X509_NAME_LINE_LENGTH];

    if (!ok) {
        if (current_cert) {
            X509_NAME_print_ex_fp(stderr,
                                  X509_get_subject_name(current_cert),
                                  0, XN_FLAG_ONELINE);
            fprintf(stderr, "\n");
        }
        printf("%serror %d at %d depth lookup:%s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
        case X509_V_ERR_CERT_HAS_EXPIRED:

            /*
             * since we are just checking the certificates, it is ok if they
             * are self signed. But we should still warn the user.
             */

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;

        }
    }

    if (chain == NULL) {
        fprintf(stderr, "Error getting a certificate chain to verify.\n");
        goto end;
    }

    if (current_cert == NULL) {
        fprintf(stderr, "Error getting a certificate to verify.\n");
        goto end;
    }

    if (sk_X509_num(chain) - 1 == cert_depth) {
        /* This is a root cert.  If it is self signed then there is no point
         * in verifying it. If is is NOT self signed then we don't have the
         * signer cert so we cannot verify it.
         */
        goto end;
    }

    /* This is where the QS verification actually is done. */
    ok = 0;

    /* Grab the next cert in the stack. That should be the issuer. OpenSSL
     * should have checked that for us so we don't bother with any checks.
     * We simply get the QS public key out of the extensions and convert
     * it to a pkey.
     */
    issuer = sk_X509_value(chain, cert_depth + 1);
    if (issuer == NULL) {
        fprintf(stderr, "Error finding the issuer certificate.\n");
        goto end;
    }

    /* Find the issuer's ALT public key extension. */
    qs_pub_key_ind = X509_get_ext_by_NID(issuer, NID_subj_alt_pub_key, -1);
    if (qs_pub_key_ind < 0) {
        fprintf(stderr, "Error finding the issuer's ALT pulbic key extension.\n");
        goto end;
    }

    /* Get the issuer's ALT public key extension. */
    qs_pub_key_ext = X509_get_ext(issuer, qs_pub_key_ind);
    if (qs_pub_key_ext == NULL) {
        fprintf(stderr, "Error getting the issuer's ALT public key extension.\n");
        goto end;
    }

    /* ASN.1 parse the ALT public key extension. */
    sapki = X509V3_EXT_d2i(qs_pub_key_ext);
    if (sapki == NULL) {
        fprintf(stderr, "Error converting the issuer's ALT public key extension into ASN.1.\n");
        goto end;
    }

    /* Convert the x509 formatted public key into a pkey */
    x509_pub_qs = X509_PUBKEY_new();
    if (x509_pub_qs == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        goto end;
    }
    X509_ALGOR_free(x509_pub_qs->algor);
    ASN1_BIT_STRING_free(x509_pub_qs->public_key);

    x509_pub_qs->algor = sapki->algor;
    x509_pub_qs->public_key = sapki->public_key;
    x509_pub_qs->pkey = NULL;

    qs_pub_key = X509_PUBKEY_get(x509_pub_qs);

    x509_pub_qs->algor = NULL;
    x509_pub_qs->public_key = NULL;
    X509_PUBKEY_free(x509_pub_qs);
    x509_pub_qs = NULL;

    if (qs_pub_key == NULL) {
        fprintf(stderr, "Error converting ALT public key into a PKEY.\n");
        goto end;
    }

    /* Find the ALT signature algorithm extension and convert it into data. */
    qs_sigalg_ind = X509_get_ext_by_NID(current_cert, NID_alt_sigalg, -1);
    if (qs_sigalg_ind < 0) {
        fprintf(stderr, "Error finding the certificate's ALT signature algorithm extension.\n");
        goto end;
    }

    qs_sigalg_ext = X509_get_ext(current_cert, qs_sigalg_ind);
    if (qs_sigalg_ext == NULL) {
        fprintf(stderr, "Error getting the certificate's ALT signature algorithm extension.\n");
        goto end;
    }

    qssigalg = X509V3_EXT_d2i(qs_sigalg_ext);
    if (qssigalg == NULL) {
        fprintf(stderr, "Error converting the issuer's ALT signature algorithm extension into ASN.1.\n");
        goto end;
    }

    /* Find the ALT signature extension and convert it into data. */
    qs_sigval_ind = X509_get_ext_by_NID(current_cert, NID_alt_sigval, -1);
    if (qs_sigval_ind < 0) {
        fprintf(stderr, "Error finding the certificate's ALT signature extension.\n");
        goto end;
    }

    qs_sigval_ext = X509_get_ext(current_cert, qs_sigval_ind);
    if (qs_sigval_ext == NULL) {
        fprintf(stderr, "Error getting the certificate's ALT signature extension.\n");
        goto end;
    }

    qssig = X509V3_EXT_d2i(qs_sigval_ext);
    if (qssig == NULL) {
        fprintf(stderr, "Error converting the issuer's ALT signature extension into ASN.1.\n");
        goto end;
    }

    /* Ensure that the signature algorithm specified in the signature extension
     * and the alogrithm of the issuer's public key matches. We can't use
     * X509_ALGOR_cmp() because the OIDs don't match. The signature one includes
     * information about the digest. We don't worry about digest and parameter
     * mismatch as the actual verification will catch that.
     */
    if (OBJ_find_sigid_algs(OBJ_obj2nid(qssigalg->algorithm), NULL, &alg_nid) == 0) {
        fprintf(stderr, "Couldn't get the algorithm ID from the ALT signature.\n");
        goto end;
    }

    if (alg_nid != OBJ_obj2nid(sapki->algor->algorithm)) {
        fprintf(stderr, "Issuer public key algorithm does not match signature algorithm\n");
        goto end;
    }

    new_sig = M_ASN1_BIT_STRING_dup(qssig);
    if (new_sig == NULL) {
        fprintf(stderr, "Error duplicating the ALT signature.\n");
        goto end;
    }

    /* Now duplicate the current certificate, remove the ALT signature extension
     * and verify against that. We hid the classical algorithm during the signing
     * process so we also have to do it again to verify against the same thing.
     */
    alt_free_cert = X509_dup(current_cert);
    if (alt_free_cert == NULL) {
        fprintf(stderr, "Error duplicating the certificate.\n");
        goto end;
    }

    qs_sigval_ind = X509_get_ext_by_NID(alt_free_cert, NID_alt_sigval, -1);
    if (qs_sigval_ind < 0) {
        fprintf(stderr, "Error getting the ALT signature extension.\n");
        goto end;
    }

    new_qs_sigval_ext = X509_get_ext(alt_free_cert, qs_sigval_ind);
    if (new_qs_sigval_ext == NULL) {
        fprintf(stderr, "Error getting duplicate ALT signature extension to deallocate it.\n");
        goto end;
    }

    if (X509_delete_ext(alt_free_cert, qs_sigval_ind) == NULL) {
        fprintf(stderr, "Error removing the ALT signature extension.\n");
        goto end;
    }

    algo_holder = alt_free_cert->cert_info->signature;
    alt_free_cert->cert_info->signature = NULL;

    /* Encoded data is being cached.  See https://www.openssl.org/docs/man1.1.0/crypto/X509_sign.html.
     * Setting this flag ensures the cache is ignored.
     */
    alt_free_cert->cert_info->enc.modified = 1;

    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF), qssigalg,
                         new_sig, alt_free_cert->cert_info, qs_pub_key) <= 0) {
        printf("QS verification FAILED!\n");
        goto end;
    }

    ok = 1;

end:
    printf ("%d : %s : %s\n", cert_depth, ok == 1 ? "ok" : "not ok", X509_NAME_oneline(X509_get_subject_name(current_cert), cert_name, X509_NAME_LINE_LENGTH));

    if (chain)
        sk_X509_pop_free(chain, X509_free);
    if (sapki)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    if (qssig)
        ASN1_BIT_STRING_free(qssig);
    if (alt_free_cert)
        X509_free(alt_free_cert);
    if (qs_pub_key)
        EVP_PKEY_free(qs_pub_key);
    if (new_sig)
        ASN1_BIT_STRING_free(new_sig);
    if (qssigalg)
        X509_ALGOR_free(qssigalg);
    if (new_qs_sigval_ext)
        X509_EXTENSION_free(new_qs_sigval_ext);
    if (algo_holder)
        X509_ALGOR_free(algo_holder);

    return ok;
}

#undef PROG
#define PROG    x509QSVerify_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args;
    int badarg = 0;
    int ret = 1;
    int err_code = 0;

    ENGINE *e = NULL;
    BIO *bio_cert = NULL;
    BIO *bio_trusted = NULL;
    BIO *bio_untrusted = NULL;

    X509 *cert = NULL;
    STACK_OF(X509) *trusted = NULL;
    STACK_OF(X509) *untrusted = NULL;

    X509_STORE *cert_store = NULL;
    X509_STORE_CTX *cert_store_ctx = NULL;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();
    ENGINE_load_dynamic();

    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
            if (e == NULL)
                goto end;
        } else if (strcmp(*args, "-root") == 0) {
            if (!args[1])
                goto bad;
            bio_trusted = BIO_new_file(*(++args), "rb");
        } else if (strcmp(*args, "-untrusted") == 0) {
            if (!args[1])
                goto bad;
            bio_untrusted = BIO_new_file(*(++args), "rb");
        } else if (strcmp(*args, "-cert") == 0) {
            if (!args[1])
                goto bad;
            bio_cert = BIO_new_file(*(++args), "rb");
        } else {
            badarg = 1;
        }
        args++;
    }

    if (bio_trusted == NULL)
        badarg = 1;

    if (bio_cert == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl x509QSVerify [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use Engine library <e>\n");
        BIO_printf(bio_err,
                   "-root file         The self signed X509 root certificates concatenated into a single file.\n");
        BIO_printf(bio_err,
                   "-untrusted file    All the untrusted certificates concatenated into a single file.\n");
        BIO_printf(bio_err,
                   "-cert file         The certificate to be verified.\n");
        goto end;
    }

    cert_store = X509_STORE_new();
    if (cert_store == NULL) {
        goto end;
    }

    X509_STORE_set_verify_cb(cert_store, cb);

    if (x509qsverify_load_certs(bio_err, bio_trusted, NULL, NULL, &trusted) == 0) {
        BIO_printf(bio_err, "Error loading trusted certs.\n");
        goto end;
    }

    if (bio_untrusted != NULL) {
        if (x509qsverify_load_certs(bio_err, bio_untrusted, NULL, NULL, &untrusted) == 0) {
            BIO_printf(bio_err, "Error loading untrusted certs.\n");
            goto end;
        }
    }

    cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Error loading cert to be verified.\n");
        goto end;
    }

    cert_store_ctx = X509_STORE_CTX_new();
    if (cert_store_ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    X509_STORE_set_flags(cert_store, 0);

    if (X509_STORE_CTX_init(cert_store_ctx, cert_store, cert, untrusted) == 0) {
        ERR_print_errors(bio_err);
        goto end;
    }
    X509_STORE_CTX_trusted_stack(cert_store_ctx, trusted);

    if((X509_verify_cert(cert_store_ctx) == 1) && ((err_code = X509_STORE_CTX_get_error(cert_store_ctx)) == X509_V_OK)) {
        ret = 0;
    } else {
        BIO_printf(bio_err, "Certificate chain verification failed with error code %d.\n", err_code);
    }

 end:
    if (ret == 0)
        BIO_printf(bio_err, "Success!!\n");
    else
        ERR_print_errors(bio_err);

    if (bio_cert)
        BIO_free_all(bio_cert);
    if (bio_trusted)
        BIO_free_all(bio_trusted);
    if (bio_untrusted)
        BIO_free_all(bio_untrusted);
    if (cert)
        X509_free(cert);
    if (trusted)
        sk_X509_pop_free(trusted, X509_free);
    if (untrusted)
        sk_X509_pop_free(untrusted, X509_free);
    if (cert_store)
        X509_STORE_free(cert_store);
    if (cert_store_ctx) {
        X509_STORE_CTX_cleanup(cert_store_ctx);
        X509_STORE_CTX_free(cert_store_ctx);
    }
    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
