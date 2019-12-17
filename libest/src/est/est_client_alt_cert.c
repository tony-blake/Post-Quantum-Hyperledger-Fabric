/** @file est_client_alt_cert.c
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
 * Written by Daniel Van Geest, daniel.vangeest@isara.com, December,
 * 2017.
 */
#include "est_client_alt.h"

#include "est.h"
#include "est_locl.h"
#include "est_ossl_util.h"
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509v3.h>

EVP_PKEY *est_client_cert_get_alt_pubkey(X509 *cert)
{
    int alt_pub_key_ind = -1;
    X509_EXTENSION *alt_pub_key_ext = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    X509_PUBKEY *x509_pub_alt = NULL;
    EVP_PKEY *alt_pubkey = NULL;

    /* Find the issuer's ALT public key extension. */
    alt_pub_key_ind = X509_get_ext_by_NID(cert, NID_subj_alt_pub_key, -1);
    if (alt_pub_key_ind < 0) {
        EST_LOG_ERR("Error finding the issuer's ALT public key extension");
        goto end;
    }

    /* Get the issuer's ALT public key extension. */
    alt_pub_key_ext = X509_get_ext(cert, alt_pub_key_ind);
    if (alt_pub_key_ext == NULL) {
        EST_LOG_ERR("Error getting the issuer's ALT public key extension");
        goto end;
    }

    /* ASN.1 parse the ALT public key extension. */
    sapki = X509V3_EXT_d2i(alt_pub_key_ext);
    if (sapki == NULL) {
        EST_LOG_ERR("Error converting the issuer's ALT public key extension into ASN.1");
        goto end;
    }

    /* Convert the x509 formatted public key into a pkey */
    x509_pub_alt = X509_PUBKEY_new();
    if (x509_pub_alt == NULL) {
        EST_LOG_ERR("Memory allocation error");
        goto end;
    }
    X509_ALGOR_free(x509_pub_alt->algor);
    ASN1_BIT_STRING_free(x509_pub_alt->public_key);

    x509_pub_alt->algor = sapki->algor;
    x509_pub_alt->public_key = sapki->public_key;
    x509_pub_alt->pkey = NULL;

    alt_pubkey = X509_PUBKEY_get(x509_pub_alt);

    x509_pub_alt->algor = NULL;
    x509_pub_alt->public_key = NULL;
    X509_PUBKEY_free(x509_pub_alt);
    x509_pub_alt = NULL;

    if (alt_pubkey == NULL) {
        EST_LOG_ERR("Error converting alt public key into a PKEY");
        goto end;
    }

end:
    if (sapki) {
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    }

    return alt_pubkey;
}

#define X509_NAME_LINE_LENGTH 128

int est_client_cert_verify_alt_signature(X509_STORE_CTX *ctx)
{
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    X509 *issuer_cert = NULL;
    int cert_depth = X509_STORE_CTX_get_error_depth(ctx);
    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    int alt_sigval_ind = -1;
    X509_EXTENSION *alt_sigval_ext = NULL;
    X509_EXTENSION *new_alt_sigval_ext = NULL;
    EVP_PKEY *alt_pub_key = NULL;
    X509_ALGOR *algo_holder = NULL;

    int issuer_has_alt_pubkey = 0;
    int subject_has_alt_sigval = 0;
    int subject_has_alt_sigalg = 0;

    int alt_sigalg_ind = -1;
    X509_ALGOR *alt_sigalg = NULL;
    X509_EXTENSION *alt_sigalg_ext = NULL;

    int alg_nid = -1;
    ASN1_BIT_STRING *alt_sigval = NULL;
    ASN1_BIT_STRING *new_sig = NULL;
    X509 * alt_free_cert = NULL;
    char cert_name[X509_NAME_LINE_LENGTH] = { 0 };
    char issuer_name[X509_NAME_LINE_LENGTH] = { 0 };
    int ok = 0;

    if (current_cert == NULL || chain == NULL) {
        EST_LOG_ERR("Error getting chain or cert");
        ossl_dump_ssl_errors();
        goto end;
    }

    if (sk_X509_num(chain) - 1 == cert_depth) {
        /* Root cert, verify that it is self-signed */
        issuer_cert = current_cert;
    } else {
        issuer_cert = sk_X509_value(chain, cert_depth + 1);
        if (issuer_cert == NULL) {
            EST_LOG_ERR("Error finding the issuer certificate");
            ossl_dump_ssl_errors();
            goto end;
        }
    }

    issuer_has_alt_pubkey = X509_get_ext_by_NID(issuer_cert, NID_subj_alt_pub_key, -1) >= 0;
    subject_has_alt_sigalg = X509_get_ext_by_NID(current_cert, NID_alt_sigalg, -1) >= 0;
    subject_has_alt_sigval = X509_get_ext_by_NID(current_cert, NID_alt_sigval, -1) >= 0;

    /* Check that the alt extensions, if they exist, are used in a valid combination */
    if (issuer_has_alt_pubkey && !subject_has_alt_sigval) {
        EST_LOG_ERR("Invalid subject cert, issuer has alt public key but subject doesn't have alt signature");
        goto end;
    } else if (!issuer_has_alt_pubkey && subject_has_alt_sigval) {
        EST_LOG_ERR("Invalid subject cert, issuer doesn't have alt public key but subject has alt signature");
        goto end;
    } else if (subject_has_alt_sigval != subject_has_alt_sigalg) {
        EST_LOG_ERR("Invalid subject cert, has alt sig alg=%d, has alt sig val=%d", subject_has_alt_sigalg, subject_has_alt_sigval);
        goto end;
    }

    /* The alt extensions are consistent, so if there's no alt signature then there's noting to verify and it's all good. */
    if (!subject_has_alt_sigval) {
        ok = 1;
        goto end;
    }

    /* Find the issuer's ALT public key extension. */
    alt_pub_key = est_client_cert_get_alt_pubkey(issuer_cert);
    if (alt_pub_key == NULL) {
        EST_LOG_ERR("Error getting alt public key from cert");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Find the ALT signature value extensions and convert it to an ASN.1 thing. */
    alt_sigalg_ind = X509_get_ext_by_NID(current_cert, NID_alt_sigalg, -1);
    if (alt_sigalg_ind < 0) {
        EST_LOG_ERR("Error finding the certificate's ALT signature algorithm extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigalg_ext = X509_get_ext(current_cert, alt_sigalg_ind);
    if (alt_sigalg_ext == NULL) {
        EST_LOG_ERR("Error getting the certificate's ALT signature algorithm extension.");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigalg = X509V3_EXT_d2i(alt_sigalg_ext);
    if (alt_sigalg == NULL) {
        EST_LOG_ERR("Error converting the issuer's ALT signature algorithm extension into ASN.1.");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Find the ALT signature value extension and convert it to an ASN.1 thing. */
    alt_sigval_ind = X509_get_ext_by_NID(current_cert, NID_alt_sigval, -1);
    if (alt_sigval_ind < 0) {
        EST_LOG_ERR("Error finding the certificate's ALT signature extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigval_ext = X509_get_ext(current_cert, alt_sigval_ind);
    if (alt_sigval_ext == NULL) {
        EST_LOG_ERR("Error getting the certificate's ALT signature extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigval = X509V3_EXT_d2i(alt_sigval_ext);
    if (alt_sigval == NULL) {
        EST_LOG_ERR("Error converting the issuer's ALT signature extension into ASN.1");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Ensure that the signature algorithm specified in the signature algorithm extension
     * and the algorithm of the issuer's public key matches.
     */
    if (OBJ_find_sigid_algs(OBJ_obj2nid(alt_sigalg->algorithm), NULL, &alg_nid) == 0) {
        EST_LOG_ERR("Couldn't get the algorithm ID from the ALT signature.");
        ossl_dump_ssl_errors();
        goto end;
    }

    if (alg_nid != alt_pub_key->type) {
        EST_LOG_ERR("Issuer public key algorithm does not match signature algorithm.");
        goto end;
    }

    new_sig = ASN1_OCTET_STRING_dup(alt_sigval);
    if (new_sig == NULL) {
        EST_LOG_ERR("Error duplicating the ALT signature");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Now duplicate the current certificate, remove the ALT signature extension
     * and verify against that. We hid the classical algorithm during the signing
     * process so we also have to do it again to verify against the same thing.
     */
    alt_free_cert = X509_dup(current_cert);
    if (alt_free_cert == NULL) {
        EST_LOG_ERR("Error duplicating the certificate");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigval_ind = X509_get_ext_by_NID(alt_free_cert, NID_alt_sigval, -1);
    if (alt_sigval_ind < 0) {
        EST_LOG_ERR("Error getting the ALT signature extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    new_alt_sigval_ext = X509_get_ext(alt_free_cert, alt_sigval_ind);
    if (new_alt_sigval_ext == NULL) {
        EST_LOG_ERR("Error getting duplicate ALT signature extension to deallocate it");
        ossl_dump_ssl_errors();
        goto end;
    }

    if (X509_delete_ext(alt_free_cert, alt_sigval_ind) == NULL) {
        EST_LOG_ERR("Error removing the ALT signature extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    algo_holder = alt_free_cert->cert_info->signature;
    alt_free_cert->cert_info->signature = NULL;

    /* Stuff is being cached.  See https://www.openssl.org/docs/man1.1.0/crypto/X509_sign.html.
     */
    alt_free_cert->cert_info->enc.modified = 1;

    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF), alt_sigalg,
                         new_sig, alt_free_cert->cert_info, alt_pub_key) <= 0) {
        EST_LOG_ERR("Alt signature verification FAILED!");
        ossl_dump_ssl_errors();
        goto end;
    }

    ok = 1;

end:
    EST_LOG_INFO("cert=%s, issuer=%s: %s",
        X509_NAME_oneline(X509_get_subject_name(current_cert), cert_name, X509_NAME_LINE_LENGTH),
        X509_NAME_oneline(X509_get_subject_name(issuer_cert), issuer_name, X509_NAME_LINE_LENGTH),
        ok == 1 ? "ok" : "not ok");

    if (chain) {
        sk_X509_pop_free(chain, X509_free);
    }
    if (alt_sigalg) {
        X509_ALGOR_free(alt_sigalg);
    }
    if (alt_free_cert) {
        X509_free(alt_free_cert);
    }
    if (alt_pub_key) {
        EVP_PKEY_free(alt_pub_key);
    }
    if (new_sig) {
        ASN1_BIT_STRING_free(new_sig);
    }
    if (alt_sigval) {
        ASN1_BIT_STRING_free(alt_sigval);
    }
    if (new_alt_sigval_ext) {
        X509_EXTENSION_free(new_alt_sigval_ext);
    }
    if (algo_holder) {
        X509_ALGOR_free(algo_holder);
    }

    return (ok);
}

/*
 * This function does a sanity check on the Alternative
 * extensions of the X509 prior to attempting to
 * convert the X509 to a CSR for a reenroll
 * operation.
 *
 * Returns an EST_ERROR code
 */
EST_ERROR est_client_cert_check_alt_sig_sanity (X509 *cert)
{
    int idx = 0;

    idx = X509_get_ext_by_NID(cert, NID_alt_sigval, -1);
    if (idx < 0) {
        EST_LOG_ERR("The certificate provided does not contain an ALT signature.");
        return (EST_ERR_BAD_X509);
    }

    idx = X509_get_ext_by_NID(cert, NID_alt_sigalg, -1);
    if (idx < 0) {
        EST_LOG_ERR("The certificate provided does not contain an ALT signature algorithm.");
        return (EST_ERR_BAD_X509);
    }

    return (EST_ERR_NONE);
}
