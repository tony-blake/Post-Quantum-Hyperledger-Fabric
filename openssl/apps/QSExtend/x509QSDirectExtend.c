/** @file x509QSDirectExtend.c Load QS keypair and traditional X509 certificates and use them to create a multiple public key algorithm certificate.
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
#include <openssl/x509v3.h>

#undef PROG
#define PROG    x509QSDirectExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args;
    int badarg = 0;
    int ret = 1;
    int self_sign = 0;
    char *passin = NULL;
    char *passin_qs = NULL;
    char *passargin = NULL;
    char *passargin_qs = NULL;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *pkey_qs_pub = NULL;
    EVP_PKEY *classical_privkey = NULL;

    BIO *bio_x509in = NULL;
    BIO *bio_x509out = NULL;
    const char *file_priv = NULL;
    const char *file_qs_pub = NULL;
    const char *file_qs_priv = NULL;

    X509_ALGOR *algor_for_qssigalg = NULL;
    X509_EXTENSION *ext_qssigalg = NULL;

    X509 *cert = NULL;
    ASN1_BIT_STRING *qs_sigval_as_asn1bitstring = NULL;

    int snid = -1;
    X509_EXTENSION *ext_qssig = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    X509_PUBKEY *x509_sig_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    X509_EXTENSION *ext_sapki = NULL;

    unsigned char *sign_in = NULL;
    size_t sign_in_size = 0;
    unsigned char *sign_out = NULL;
    size_t sign_out_size = 0;

    X509_ALGOR *algo_holder = NULL;

    EVP_MD_CTX mctx;

    const EVP_MD *md_alg = EVP_sha512();

    EVP_MD_CTX_init(&mctx);
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
        } else if (strcmp(*args, "-x509in") == 0) {
            if (!args[1])
                goto bad;
            bio_x509in = BIO_new_file(*(++args), "rb");
        } else if (strcmp(*args, "-x509out") == 0) {
            if (!args[1])
                goto bad;
            bio_x509out = BIO_new_file(*(++args), "wb");
        } else if (strcmp(*args, "-privin") == 0) {
            if (!args[1])
                goto bad;
            file_priv = *(++args);
        } else if (strcmp(*args, "-pubqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_pub = *(++args);
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-self_sign") == 0) {
            if (!args[1])
                goto bad;
            self_sign = 1;
        } else if (strcmp(*argv, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "-passinqs") == 0) {
            if (--argc < 1)
                goto bad;
            passargin_qs = *(++argv);
        } else {
            badarg = 1;
        }
        args++;
    }

    if (file_priv == NULL)
        badarg = 1;

    if (bio_x509in == NULL)
        badarg = 1;

    if (bio_x509out == NULL)
        badarg = 1;

    if ((file_qs_pub == NULL) && (self_sign == 0))
        badarg = 1;

    if ((file_qs_pub != NULL) && (self_sign == 1))
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl x509QSDirectExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-x509in file       The X509 certificate in pem format.\n");
        BIO_printf(bio_err,
                   "-x509out file      The X509 MPKA certificate in pem format with new ALT extensions.\n");
        BIO_printf(bio_err,
                   "-privin file       The private key used to sign the original x509 certificate in pem format.\n");
        BIO_printf(bio_err,
                   "-pubqs file        The public QS key.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key. \n");
        BIO_printf(bio_err,
                   "-self_sign         The public key should be obtained from the private key.\n");
        BIO_printf(bio_err,
                   "-passin            The private key password source.\n");
        BIO_printf(bio_err,
                   "-passinqs          The private QS key password source.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password for the private key.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin_qs, NULL, &passin_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password for the QS private key.\n");
        goto end;
    }

    cert = PEM_read_bio_X509(bio_x509in, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Bad certificate\n");
        goto end;
    }

    classical_privkey = load_key(bio_err, file_priv, FORMAT_PEM, 0, passin, e, "Classical Private Key");
    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    pkey_qs_priv = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, passin_qs, e, "QS Private Key");
    if (pkey_qs_priv == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Read the QS Public key to be embedded in the QS req if it was specified.
     * If not check the private key.
     */
    if (file_qs_pub == NULL) {
        pkey_qs_pub = pkey_qs_priv;
    } else {
        pkey_qs_pub = load_pubkey(bio_err, file_qs_pub, FORMAT_PEM, 0, NULL, e, "QS Public Key");
        if (pkey_qs_pub == NULL) {
            /* load_pubkey() has already printed an appropriate message. */
            goto end;
        }
    }

    /* Ensure the private key is actually a QS key */
    if (pkey_qs_priv->type != NID_hss) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum safe algorithm.\n");
        goto end;
    }

    /* Ensure the public key is actually a QS key */
    if (pkey_qs_pub->type != NID_hss) {
        BIO_puts(bio_err, "The provided public key is not compatable with a quantum safe algorithm.\n");
        goto end;
    }

    if (pkey_qs_priv->type == NID_hss) {
        /* Create a temporary context */
        tmpctx = EVP_PKEY_CTX_new(pkey_qs_priv, NULL);
        if (tmpctx == NULL) {
           BIO_printf(bio_err, "Could not create context.\n");
           goto end;
        }
        /* Send the control string. */
        if (EVP_PKEY_CTX_ctrl_str(tmpctx, set_hss_private_key_file_ctrl_string, file_qs_priv) <= 0) {
            BIO_printf(bio_err, "Couldn't set HSS private key file.\n");
            goto end;
        }

        /* All the work for the tmpctx is done. */
        EVP_PKEY_CTX_free(tmpctx);
        tmpctx = NULL;
    }

    /* Convert the private key into an x509 public key.  This lets us
     * get the algorithm identifier of the private key so we can associate
     * it with the signature.
     */
    X509_PUBKEY_set(&x509_sig_qs, pkey_qs_priv);

     /* Convert the pkey in to an x509 public key.  This is the standard way
      * of doing it for x509 subject public key.
      */
    X509_PUBKEY_set(&x509_pub_qs, pkey_qs_pub);

    sapki = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    if (sapki == NULL) {
        BIO_puts(bio_err, "Error converting public key to x509 pubkey\n");
        goto end;
    }

    X509_ALGOR_free(sapki->algor);
    ASN1_BIT_STRING_free(sapki->public_key);
    sapki->algor = x509_pub_qs->algor;
    sapki->public_key = x509_pub_qs->public_key;

    /* Create and insert QS signature algorithm as an extension. */

    /* Duplicate the algorithm for the signature. */
    algor_for_qssigalg = X509_ALGOR_dup(x509_sig_qs->algor);
    if (algor_for_qssigalg == NULL) {
        BIO_puts(bio_err, "Error duplicating signature algor.\n");
        goto end;
    }

    /* Make sure that the right digest is set. */
    if (!OBJ_find_sigid_by_algs(&snid, NID_sha512, EVP_PKEY_id(pkey_qs_priv))) {
        BIO_puts(bio_err, "Error getting NID for digest/signature algorithm combination.\n");
        goto end;
    }

    /* Set the Object ID based on the NID in and then convert into an extension. */
    if (X509_ALGOR_set0(algor_for_qssigalg, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0) == 0) {
        BIO_puts(bio_err, "Error setting algorithm object ID.\n");
        goto end;
    }

    ext_qssigalg = X509V3_EXT_i2d(NID_alt_sigalg, 0, algor_for_qssigalg);
    if (ext_qssigalg == NULL) {
        BIO_puts(bio_err, "Error creating signature algorithm extension.\n");
        goto end;
    }

    /* Insert QS signature algorithm as an extension. */
    if (X509_add_ext(cert, ext_qssigalg, -1) == 0) {
        BIO_puts(bio_err, "Error adding signature algorithm extension.\n");
        goto end;
    }

    /* Create and insert QS public key as an extension. */
    ext_sapki = X509V3_EXT_i2d(NID_subj_alt_pub_key, 0, sapki);
    sapki->algor = NULL;
    sapki->public_key = NULL;
    if (ext_sapki == NULL) {
        BIO_puts(bio_err, "Error converting x509 pubkey to extension.\n");
        goto end;
    }

    if (X509_add_ext(cert, ext_sapki, -1) == 0) {
        BIO_puts(bio_err, "Error adding public key as extension\n");
        goto end;
    }

    /* Sign the cert with the QS private key. */
    if (EVP_DigestSignInit(&mctx, NULL, md_alg, NULL, pkey_qs_priv) < 1) {
        BIO_puts(bio_err, "Error doing EVP digest initialization\n");
        goto end;
    }

    /* We want to hide the classical algorithm during the QS signing process */
    algo_holder = cert->cert_info->signature;
    cert->cert_info->signature = NULL;

    /* Originally we were calling X509_sign_ctx() but this was not a good idea.
     * We had to stop because of the following code in ASN1_item_sign_ctx() it:
     *
     *   if (algor1)
     *       X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
     *   if (algor2)
     *       X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);
     *
     * Those lines were modifying AlgorithmIdentifier in the X509 cert.  That
     * would change the resulting digest result which is a side effect we would
     * like to avoid.
     *
     * Most of the code below here until we create the signature as an extension
     * is based off of ASN1_item_sign_ctx() and X509_get0_signature().
     */

    cert->cert_info->enc.modified = 1;

    sign_in_size = ASN1_item_i2d((ASN1_VALUE *)cert->cert_info, &sign_in, ASN1_ITEM_rptr(X509_CINF));

    sign_out_size = EVP_PKEY_size(pkey_qs_priv);
    sign_out = OPENSSL_malloc(sign_out_size);
    if ((sign_in == NULL) || (sign_out == NULL)) {
        BIO_puts(bio_err, "Memory allocation error for signing input or output.\n");
        goto end;
    }

    if (!EVP_DigestSignUpdate(&mctx, sign_in, sign_in_size)
        || !EVP_DigestSignFinal(&mctx, sign_out, &sign_out_size)) {
        BIO_puts(bio_err, "EVP digest/sign operation error.\n");
        goto end;
    }

    /* Done the QS signing process; bring back the signature algo specifier. */
    cert->cert_info->signature = algo_holder;
    algo_holder = NULL;

    qs_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
    if (qs_sigval_as_asn1bitstring == NULL) {
         BIO_puts(bio_err, "ASN1 bit string memory allocation error.\n");
         goto end;
    }

    qs_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    qs_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    qs_sigval_as_asn1bitstring->data = sign_out;
    qs_sigval_as_asn1bitstring->length = sign_out_size;

    /* Transferred ownership of the buffer to qs_sigval_as_asn1bitstring. */
    sign_out = NULL;
    sign_out_size = 0;

    /* Create QS signature as an extension. */
    ext_qssig = X509V3_EXT_i2d(NID_alt_sigval, 0, qs_sigval_as_asn1bitstring);
    if (ext_qssig == NULL) {
        BIO_puts(bio_err, "Error creating signature extension.\n");
        goto end;
    }

    /* Insert QS signature as an extension. */
    if (X509_add_ext(cert, ext_qssig, -1) == 0) {
        BIO_puts(bio_err, "Error adding signature extension\n");
        goto end;
    }

    /* Re-sign the certificate with the original classical private key. */
    if (X509_sign(cert, classical_privkey, NULL) == 0) {
        BIO_puts(bio_err, "Error generating classical signature.\n");
        goto end;
    }

    /* write the new signed ciertificate with extensions in it. */
    if (PEM_write_bio_X509(bio_x509out, cert) == 0) {
        BIO_puts(bio_err, "Error writing new certificate.\n");
        goto end;
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    EVP_MD_CTX_cleanup(&mctx);
    if (tmpctx)
        EVP_PKEY_CTX_free(tmpctx);
    if (bio_x509in)
        BIO_free_all(bio_x509in);
    if (bio_x509out)
        BIO_free_all(bio_x509out);
    if (cert)
        X509_free(cert);
    if (pkey_qs_pub == pkey_qs_priv)
        pkey_qs_pub = NULL;
    if (pkey_qs_pub)
        EVP_PKEY_free(pkey_qs_pub);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (x509_pub_qs)
        X509_PUBKEY_free(x509_pub_qs);
    if (x509_sig_qs)
        X509_PUBKEY_free(x509_sig_qs);
    if (sapki)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    if (algor_for_qssigalg)
        X509_ALGOR_free(algor_for_qssigalg);
    if (algo_holder)
        X509_ALGOR_free(algo_holder);

    OPENSSL_free(sign_out);
    OPENSSL_free(sign_in);
    if (qs_sigval_as_asn1bitstring)
        ASN1_BIT_STRING_free(qs_sigval_as_asn1bitstring);
    if (ext_sapki)
        X509_EXTENSION_free(ext_sapki);
    if (ext_qssig)
        X509_EXTENSION_free(ext_qssig);
    if (ext_qssigalg)
        X509_EXTENSION_free(ext_qssigalg);

    if (passargin && passin)
        OPENSSL_free(passin);
    if (passargin_qs && passin_qs)
        OPENSSL_free(passin_qs);
    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
