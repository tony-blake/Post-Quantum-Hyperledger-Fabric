/** @file x509QSExtend.c Load QS CSR and traditional X.509 certificate and use them to create a multiple public key algorithm certificate.
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
#include <openssl/asn1_mac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

SUBJECT_ALT_PUBLIC_KEY_INFO *get_SAPKI_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_subj_alt_pub_key);
    ASN1_const_CTX c;
    ASN1_STRING *s = NULL;
    long length = 0;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_SEQUENCE)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    s = so->value.sequence;
    c.p = ASN1_STRING_data(s);
    length = ASN1_STRING_length(s);
    c.max = c.p + length;
    if (!asn1_GetSequence(&c, &length)) {
        fprintf (stderr, "Attribute internal ASN.1 format error.\n") ;
        goto err;
    }

    c.q = c.p;
    sapki = d2i_SUBJECT_ALT_PUBLIC_KEY_INFO(NULL, &c.p, c.slen);
    if (sapki == NULL) {
        fprintf (stderr, "Invalid ALT public key attribute.\n") ;
        goto err;
    }
    c.slen -= (c.p - c.q);
    c.q = c.p;

    if (!asn1_const_Finish(&c)) {
        fprintf (stderr, "Attribute had junk after the ASN.1 data.\n") ;
        goto err;
    }

    return sapki;

err:
    SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    return NULL;
}

ASN1_BIT_STRING *get_ALTSIG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_alt_sigval);
    ASN1_BIT_STRING *altsig = NULL;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_BIT_STRING)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    altsig = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_BIT_STRING, NULL);
    if (altsig == NULL) {
        fprintf (stderr, "Couldn't get ASN1 data from attribute.\n") ;
        goto err;
    }

    return altsig;

err:
    return NULL;
}

X509_ALGOR *get_ALTSIGALG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_alt_sigalg);
    X509_ALGOR *altsigalg = NULL;
    ASN1_STRING *s = NULL;
    const unsigned char *data = NULL;
    long length = 0;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_SEQUENCE)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    s = so->value.sequence;
    data = ASN1_STRING_data(s);
    length = ASN1_STRING_length(s);
    altsigalg = d2i_X509_ALGOR(NULL, &data, length);
    return altsigalg;

err:
    return NULL;
}

#undef PROG
#define PROG    x509QSExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args;
    int badarg = 0;
    int ret = 1;
    char *passin = NULL;
    char *passin_qs = NULL;
    char *passargin = NULL;
    char *passargin_qs = NULL;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *pkey_qs_pub = NULL;
    EVP_PKEY *classical_privkey = NULL;
    X509_REQ *req = NULL;
    X509_REQ *tmpreq = NULL;
    EVP_PKEY *tmppkey = NULL;

    BIO *bio_x509in = NULL;
    BIO *bio_x509out = NULL;
    BIO *bio_req = NULL;
    const char *file_priv = NULL;
    const char *file_qs_priv = NULL;

    X509_ALGOR *algor_for_qssigalg = NULL;
    X509_EXTENSION *ext_qssigalg = NULL;

    X509 *cert = NULL;
    ASN1_BIT_STRING *qs_sigval_as_asn1bitstring = NULL;

    int alg_nid = -1;
    int snid = -1;
    X509_EXTENSION *ext_qssig = NULL;
    X509_ALGOR *qssig_algor = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    X509_PUBKEY *x509_sig_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_in = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_out = NULL;
    X509_EXTENSION *ext_sapki = NULL;

    unsigned char *sign_in = NULL;
    size_t sign_in_size = 0;
    unsigned char *sign_out = NULL;
    size_t sign_out_size = 0;

    X509_ATTRIBUTE *qs_pub_key_attr = NULL;
    int qs_pub_key_ind = -1;

    X509_ATTRIBUTE *qs_sigval_attr = NULL;
    int qs_sigval_ind = -1;
    X509_ALGOR *algo_holder = NULL;

    X509_ATTRIBUTE *qs_sigalg_attr = NULL;
    int qs_sigalg_ind = -1;

    EVP_MD_CTX mctx;
    STACK_OF(X509_EXTENSION) *req_exts = NULL;

    ASN1_BIT_STRING *req_qssig = NULL;
    X509_ALGOR *req_qssigalg = NULL;

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
        } else if (strcmp(*args, "-reqin") == 0) {
            if (!args[1])
                goto bad;
            bio_req = BIO_new_file(*(++args), "rb");
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
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

    if (bio_req == NULL)
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl x509QSExtend [options]\n");
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
                   "-reqin file        The certificate signing request containing the ALT public key extension.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key. \n");
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

    /* Read in the req which contains the public key */
    req = PEM_read_bio_X509_REQ(bio_req, NULL, NULL, NULL);
    if (req == NULL) {
        BIO_printf(bio_err, "Bad certificate signing request.\n");
        goto end;
    }

    /* Get the ALT public key attribute. */
    qs_pub_key_ind = X509_REQ_get_attr_by_NID(req, NID_subj_alt_pub_key, -1);
    if (qs_pub_key_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT public key attribute.\n");
        goto end;
    }

    qs_pub_key_attr = X509_REQ_get_attr(req, qs_pub_key_ind);
    if (qs_pub_key_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT public key attribute.\n");
        goto end;
    }

    sapki_in = get_SAPKI_from_ATTRIBUTE(qs_pub_key_attr);
    if (sapki_in == NULL) {
        fprintf(stderr, "Error converting the req's ALT public key attribute into ASN.1.\n");
        goto end;
    }

    /* Convert the ALT public key attribute to a pkey. */
    x509_pub_qs = X509_PUBKEY_new();
    if (x509_pub_qs == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        goto end;
    }

    X509_ALGOR_free(x509_pub_qs->algor);
    ASN1_BIT_STRING_free(x509_pub_qs->public_key);

    x509_pub_qs->algor = sapki_in->algor;
    x509_pub_qs->public_key = sapki_in->public_key;
    x509_pub_qs->pkey = NULL;

    pkey_qs_pub = X509_PUBKEY_get(x509_pub_qs);

    x509_pub_qs->algor = NULL;
    x509_pub_qs->public_key = NULL;
    X509_PUBKEY_free(x509_pub_qs);
    x509_pub_qs = NULL;

    if (pkey_qs_pub == NULL) {
        BIO_printf(bio_err, "Bad QS public key.\n");
        goto end;
    }

    /* Get the ALT signature attribute. */
    qs_sigval_ind = X509_REQ_get_attr_by_NID(req, NID_alt_sigval, -1);
    if (qs_sigval_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT signature attribute.\n");
        goto end;
    }

    qs_sigval_attr = X509_REQ_get_attr(req, qs_sigval_ind);
    if (qs_sigval_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT signature attribute.\n");
        goto end;
    }

    /* Remove the ALT signature attribute to make it look the same as when it
     * was signed.
     */
    if (X509_REQ_delete_attr(req, qs_sigval_ind) == 0) {
        fprintf(stderr, "Error getting the req's ALT signature attribute.\n");
        goto end;
    }

    req_qssig = get_ALTSIG_from_ATTRIBUTE(qs_sigval_attr);
    if (req_qssig == NULL) {
        fprintf(stderr, "Error converting the req's ALT signature attribute into ASN.1.\n");
        goto end;
    }

    /* Get the ALT signature algorithm attribute. */
    qs_sigalg_ind = X509_REQ_get_attr_by_NID(req, NID_alt_sigalg, -1);
    if (qs_sigalg_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT signature algorithm attribute index.\n");
        goto end;
    }

    qs_sigalg_attr = X509_REQ_get_attr(req, qs_sigalg_ind);
    if (qs_sigalg_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT signature algorithm attribute.\n");
        goto end;
    }

    req_qssigalg = get_ALTSIGALG_from_ATTRIBUTE(qs_sigalg_attr);
    if (req_qssigalg == NULL) {
        fprintf(stderr, "Error converting the req's ALT signature attribute into ASN.1.\n");
        goto end;
    }

    /* Ensure that the signature algorithm of the sig and the alogrithm of the public key
     * match. We can't use X509_ALGOR_cmp() because the OIDs don't match. The
     * signature OID includes information about the digest. We don't worry about digest
     * and parameter mismatch as the actual verification will catch that.
     */
    if (OBJ_find_sigid_algs(OBJ_obj2nid(req_qssigalg->algorithm), NULL, &alg_nid) == 0) {
        fprintf(stderr, "Couldn't get the algorithm ID from the ALT signature.\n");
        goto end;
    }

    if (alg_nid != OBJ_obj2nid(sapki_in->algor->algorithm)) {
        fprintf(stderr, "Issuer public key algorithm does not match signature algorithm\n");
        fprintf(stderr, "Issuer: %s\n", OBJ_nid2ln(OBJ_obj2nid(sapki_in->algor->algorithm)));
        fprintf(stderr, "Current: %s\n", OBJ_nid2ln(OBJ_obj2nid(req_qssigalg->algorithm)));
        goto end;
    }

    req->req_info->enc.modified = 1;

    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_REQ_INFO), req_qssigalg,
                         req_qssig, req->req_info, pkey_qs_pub) <= 0) {
        printf("QS verification FAILED!\n");
        goto end;
    }

    /* We do not do verification of the classical signature as we assume it was
     * done during the creation of the classical chain. Now that the req is
     * verified, we can construct the cert.
     */

    /* Read in the classical cert. */
    cert = PEM_read_bio_X509(bio_x509in, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Bad certificate\n");
        goto end;
    }

    /* Read in the classical private key that will be used to re-sign
     * this cert.
     */
    classical_privkey = load_key(bio_err, file_priv, FORMAT_PEM, 0, passin, e, "Classical Private Key");
    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Read in the QS private key that will be used to create the QS
     * signature.
     */
    pkey_qs_priv = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, passin_qs, e, "QS Private Key");
    if (pkey_qs_priv == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Ensure the private key is actually a QS key */
    if (pkey_qs_priv->type != NID_hss) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum safe algorithm.\n");
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

    /* Make sure the public key is actually QS. */
    if (pkey_qs_pub->type != NID_hss) {
        BIO_puts(bio_err, "The provided public key is not compatible with a quantum safe algorithm.\n");
        goto end;
    }

    /* Convert the private key into an x509 public key.  This lets us
     * get the algorithm identifier of the private key so we can associate
     * it with the signature.
     */
    X509_PUBKEY_set(&x509_sig_qs, pkey_qs_priv);

    /* Convert the pkey into an x509 format public key. */
    X509_PUBKEY_set(&x509_pub_qs, pkey_qs_pub);

    sapki_out = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    X509_ALGOR_free(sapki_out->algor);
    ASN1_BIT_STRING_free(sapki_out->public_key);
    sapki_out->algor = x509_pub_qs->algor;
    sapki_out->public_key = x509_pub_qs->public_key;

    /* The next few blocks of code create and insert the QS signature algorithm
     * as an extension.
     */

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

    /* Set the Object ID based on the NID and then convert into an extension. */
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
    ext_sapki = X509V3_EXT_i2d(NID_subj_alt_pub_key, 0, sapki_out);
    sapki_out->algor = NULL;
    sapki_out->public_key = NULL;
    if (ext_sapki == NULL) {
        BIO_puts(bio_err, "Error converting x509 pubkey to extension.\n");
        goto end;
    }

    /* Add the ALT public key extension to the cert. */
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
     * would change the resulting digest result which is a side effect we want
     * to avoid.
     *
     * Most of the code below here until we create the signature as an extension
     * is based on ASN1_item_sign_ctx() and X509_get0_signature().
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

    /* write the new signed certificate with extensions in it. */
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
    if (tmpreq)
        X509_REQ_free(tmpreq);
    if (tmppkey)
        EVP_PKEY_free(tmppkey);
    if (bio_req)
        BIO_free_all(bio_req);
    if (bio_x509in)
        BIO_free_all(bio_x509in);
    if (bio_x509out)
        BIO_free_all(bio_x509out);
    if (cert)
        X509_free(cert);
    if (pkey_qs_pub)
        EVP_PKEY_free(pkey_qs_pub);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (req)
        X509_REQ_free(req);

    if (sapki_in)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_in);
    if (sapki_out)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_out);
    if (algor_for_qssigalg)
        X509_ALGOR_free(algor_for_qssigalg);
    if (req_qssigalg)
        X509_ALGOR_free(req_qssigalg);
    if (x509_pub_qs)
        X509_PUBKEY_free(x509_pub_qs);
    if (x509_sig_qs)
        X509_PUBKEY_free(x509_sig_qs);
    if (qssig_algor)
        X509_ALGOR_free(qssig_algor);
    if (algo_holder)
        X509_ALGOR_free(algo_holder);

    /* We used OPENSSL_malloc() to allocate this so we do not use the custom
     * free functions to free it.
     */
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

    /* Not sure why I don't need to free qs_pub_key_ext */
    if (qs_sigval_attr)
        X509_ATTRIBUTE_free(qs_sigval_attr);
    if (req_exts)
        sk_X509_EXTENSION_pop_free(req_exts, X509_EXTENSION_free);

    /* I don't need to free (qs_sigalg_attr becuase it is still referenced by
     * the req.
     */
    if (passargin && passin)
        OPENSSL_free(passin);
    if (passargin_qs && passin_qs)
        OPENSSL_free(passin_qs);

    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}
