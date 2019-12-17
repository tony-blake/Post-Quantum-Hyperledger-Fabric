/** @file est_server_alt.c
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
#include "est_server_alt.h"

#include "est.h"
#include "est_locl.h"
#include "est_ossl_util.h"
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509v3.h>

/*
 * Convert an X509 attribute to a SubjectAltPublicKeyInfo object.
 */
static SUBJECT_ALT_PUBLIC_KEY_INFO *get_SAPKI_from_ATTRIBUTE(X509_ATTRIBUTE *attr)
{
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

/*
 * Convert an X509 attribute to a Alt Signature Value BIT STRING.
 */
static ASN1_BIT_STRING *get_ALTSIGVAL_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

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

/*
 * Convert an X509 attribute to a Alt Signature Algorithm object.
 */
static X509_ALGOR *get_ALTSIGALG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

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

/*
 * Fetch the alternative public key from the CSR.
 */
static EVP_PKEY *req_get_alt_pubkey(X509_REQ *req)
{
    int alt_pub_key_ind = -1;
    X509_ATTRIBUTE *alt_pub_key_attr = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_in = NULL;
    X509_PUBKEY *x509_pub_alt = NULL;
    EVP_PKEY *pkey_alt_pub = NULL;

    /* Find and get the ALT public key attribute and convert it to a pkey. */
    alt_pub_key_ind = X509_REQ_get_attr_by_NID(req, NID_subj_alt_pub_key, -1);
    if (alt_pub_key_ind < 0) {
        goto end;
    }

    alt_pub_key_attr = X509_REQ_get_attr(req, alt_pub_key_ind);
    if (alt_pub_key_attr == NULL) {
        EST_LOG_ERR("Error getting the req's ALT public key attribute.");
        goto end;
    }

    sapki_in = get_SAPKI_from_ATTRIBUTE(alt_pub_key_attr);
    if (sapki_in == NULL) {
        EST_LOG_ERR("Error converting the req's ALT public key attribute into ASN.1.");
        goto end;
    }

    x509_pub_alt = X509_PUBKEY_new();
    if (x509_pub_alt == NULL) {
        EST_LOG_ERR("Memory allocation error.");
        goto end;
    }

    X509_ALGOR_free(x509_pub_alt->algor);
    ASN1_BIT_STRING_free(x509_pub_alt->public_key);

    x509_pub_alt->algor = sapki_in->algor;
    x509_pub_alt->public_key = sapki_in->public_key;
    x509_pub_alt->pkey = NULL;

    pkey_alt_pub = X509_PUBKEY_get(x509_pub_alt);

    x509_pub_alt->algor = NULL;
    x509_pub_alt->public_key = NULL;
    X509_PUBKEY_free(x509_pub_alt);
    x509_pub_alt = NULL;

    if (pkey_alt_pub == NULL) {
        EST_LOG_ERR("Bad alternative public key.");
        goto end;
    }

end:
    if (sapki_in) {
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_in);
    }

    return pkey_alt_pub;
}

/*
 * Verify the alternative signature in the CSR.
 */
static int req_alt_verify(X509_REQ *req, EVP_PKEY *alt_pkey)
{
    int rv = -1;
    int alt_sigval_ind = -1;
    X509_ATTRIBUTE *alt_sigval_attr = NULL;
    ASN1_BIT_STRING *req_altsig = NULL;
    int alt_sigalg_ind = -1;
    X509_ATTRIBUTE *alt_sigalg_attr = NULL;
    X509_ALGOR *req_altsigalg = NULL;
    int alg_nid = -1;

    /* Find and get the ALT signature extension. */
    alt_sigval_ind = X509_REQ_get_attr_by_NID(req, NID_alt_sigval, -1);
    if (alt_sigval_ind < 0) {
        EST_LOG_ERR("Error finding the req's ALT signature extension.");
        goto end;
    }

    alt_sigval_attr = X509_REQ_get_attr(req, alt_sigval_ind);
    if (alt_sigval_attr == NULL) {
        EST_LOG_ERR("Error getting the req's ALT signature extension.");
        goto end;
    }

    /* Remove the attribute to make it look the same as when it was signed. */
    if (X509_REQ_delete_attr(req, alt_sigval_ind) == 0) {
        EST_LOG_ERR("Error getting the req's ALT signature extension.");
        goto end;
    }

    req_altsig = get_ALTSIGVAL_from_ATTRIBUTE(alt_sigval_attr);
    if (req_altsig == NULL) {
        EST_LOG_ERR("Error converting the req's ALT signature extension into ASN.1.");
        goto end;
    }

    /* Find and get the ALT signature algorithm extension. */
    alt_sigalg_ind = X509_REQ_get_attr_by_NID(req, NID_alt_sigalg, -1);
    if (alt_sigalg_ind < 0) {
        EST_LOG_ERR("Error finding the req's ALT signature algorithm extension index.");
        goto end;
    }

    alt_sigalg_attr = X509_REQ_get_attr(req, alt_sigalg_ind);
    if (alt_sigalg_attr == NULL) {
        EST_LOG_ERR("Error getting the req's ALT signature algorithm extension.");
        goto end;
    }

    req_altsigalg = get_ALTSIGALG_from_ATTRIBUTE(alt_sigalg_attr);
    if (req_altsigalg == NULL) {
        EST_LOG_ERR("Error converting the req's ALT signature extension into ASN.1.");
        goto end;
    }

    /* Ensure that the signature algorithm of the sig and the alogrithm of the public key
     * matches. We can't use X509_ALGOR_cmp() because the OIDs don't match. The
     * signature one includes information about the digest. We don't worry about digest
     * and parameter mismatch as the actual verification will catch that.
     */
    if (OBJ_find_sigid_algs(OBJ_obj2nid(req_altsigalg->algorithm), NULL, &alg_nid) == 0) {
        EST_LOG_ERR("Couldn't get the algorithm ID from the ALT signature.");
        goto end;
    }

    if (alg_nid != alt_pkey->type) {
        EST_LOG_ERR("Issuer public key algorithm does not match signature algorithm");
        EST_LOG_ERR("Issuer: %s", OBJ_nid2ln(alt_pkey->type));
        EST_LOG_ERR("Current: %s", OBJ_nid2ln(OBJ_obj2nid(req_altsigalg->algorithm)));
        goto end;
    }

    req->req_info->enc.modified = 1;

    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_REQ_INFO), req_altsigalg,
                         req_altsig, req->req_info, alt_pkey) <= 0) {
        EST_LOG_ERR("Alternative signature verification FAILED!");
        rv = 0;
        goto end;
    }

    rv = 1;

end:
    if (alt_sigval_attr) {
        X509_ATTRIBUTE_free(alt_sigval_attr);
    }
    if (req_altsigalg) {
        X509_ALGOR_free(req_altsigalg);
    }

    return rv;
}

/*
 * Add the Subject Alternative Public Key extension to a certificate.
 */
static EST_ERROR cert_add_alt_pubkey(X509 *cert, EVP_PKEY *pub_alt_key)
{
    X509_PUBKEY *x509_pub_alt = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_out = NULL;
    X509_EXTENSION *ext_altspki = NULL;

    EST_ERROR rv = EST_ERR_UNKNOWN;

    /* Convert the pkey into an x509 format public key. */
    X509_PUBKEY_set(&x509_pub_alt, pub_alt_key);
    if (x509_pub_alt == NULL) {
        EST_LOG_ERR("Couldn't create X509 alternative public key");
        ossl_dump_ssl_errors();
        goto end;
    }

    sapki_out = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    X509_ALGOR_free(sapki_out->algor);
    ASN1_BIT_STRING_free(sapki_out->public_key);
    sapki_out->algor = x509_pub_alt->algor;
    sapki_out->public_key = x509_pub_alt->public_key;

    /* Create and insert alt public key as an extension */
    ext_altspki = X509V3_EXT_i2d(NID_subj_alt_pub_key, 0, sapki_out);
    sapki_out->algor = NULL;
    sapki_out->public_key = NULL;
    if (ext_altspki == NULL) {
        EST_LOG_ERR("Error converting x509 pubkey to extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Add the alt public key extension to the cert. */
    if (X509_add_ext(cert, ext_altspki, -1) == 0) {
        EST_LOG_ERR("Error adding public key as extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    rv = EST_ERR_NONE;

end:
    if (ext_altspki) {
        X509_EXTENSION_free(ext_altspki);
    }
    if (sapki_out) {
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_out);
    }
    if (x509_pub_alt != NULL) {
        X509_PUBKEY_free(x509_pub_alt);
    }

    return rv;
}

/*
 * Add the Alt Signature Algoritm and correctly calculated Alt Signature Value
 * extensions to the certificate.
 */
static EST_ERROR cert_alt_sign(X509 *cert, EVP_PKEY *pkey_alt_priv, const EVP_MD *alt_md)
{
    X509_PUBKEY *x509_sig_alt = NULL;
    X509_ALGOR *algor_for_altsigalg = NULL;
    X509_EXTENSION *ext_altsigalg = NULL;
    EVP_MD_CTX mctx;
    X509_ALGOR *algo_holder = NULL;
    unsigned char *sign_in = NULL;
    size_t sign_in_size = 0;
    unsigned char *sign_out = NULL;
    size_t sign_out_size = 0;
    ASN1_BIT_STRING *alt_sigval_as_asn1bitstring = NULL;
    int snid = -1;
    X509_EXTENSION *ext_altsigval = NULL;

    EST_ERROR rv = EST_ERR_UNKNOWN;

    /* Convert the private key into an x509 public key.  This will allow us
     * to get the algorithm identifier of the private key so we can associate
     * it with the signature.
     */
    X509_PUBKEY_set(&x509_sig_alt, pkey_alt_priv);
    if (x509_sig_alt == NULL) {
        EST_LOG_ERR("Couldn't create X509 alternative public key");
        ossl_dump_ssl_errors();
        goto end;
    }

    algor_for_altsigalg = X509_ALGOR_dup(x509_sig_alt->algor);
    if (algor_for_altsigalg == NULL) {
        EST_LOG_ERR("Error duplicating public key algor");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Make sure that the right digest is set. */
    if (!OBJ_find_sigid_by_algs(&snid, EVP_MD_nid(alt_md), EVP_PKEY_id(pkey_alt_priv))) {
        EST_LOG_ERR("Error getting sigin with NID");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Set the Object ID based on the NID in and then convert into an extension. */
    if (X509_ALGOR_set0(algor_for_altsigalg, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0) == 0) {
        EST_LOG_ERR("Error setting algorithm object ID.");
        goto end;
    }

    ext_altsigalg = X509V3_EXT_i2d(NID_alt_sigalg, 0, algor_for_altsigalg);
    if (ext_altsigalg == NULL) {
        EST_LOG_ERR("Error creating signature algorithm extension.");
        goto end;
    }

    /* Insert alt signature algorithm as an extension. */
    if (X509_add_ext(cert, ext_altsigalg, -1) == 0) {
        EST_LOG_ERR("Error adding signature algorithm extension.");
        goto end;
    }

    /*
     * Sign the tbsCert
     */
    EVP_MD_CTX_init(&mctx);

    if (EVP_DigestSignInit(&mctx, NULL, alt_md, NULL, pkey_alt_priv) < 1) {
        EST_LOG_ERR("Error doing EVP digest initialization");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* We want to hide the classical algorithm during the alternative signing process */
    algo_holder = cert->cert_info->signature;
    cert->cert_info->signature = NULL;

    cert->cert_info->enc.modified = 1;

    sign_in_size = ASN1_item_i2d((ASN1_VALUE *)cert->cert_info, &sign_in, ASN1_ITEM_rptr(X509_CINF));

    sign_out_size = EVP_PKEY_size(pkey_alt_priv);
    sign_out = OPENSSL_malloc(sign_out_size);
    if ((sign_in == NULL) || (sign_out == NULL)) {
        EST_LOG_ERR("Memory allocation error for signing input or output");
        ossl_dump_ssl_errors();
        goto end;
    }

    if (!EVP_DigestSignUpdate(&mctx, sign_in, sign_in_size)
        || !EVP_DigestSignFinal(&mctx, sign_out, &sign_out_size)) {
        EST_LOG_ERR("EVP digest/sign operation error. Did you run out of HSS one-time-keys?");
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Done the alt signing process; bring back the signature algo specifier. */
    cert->cert_info->signature = algo_holder;
    algo_holder = NULL;

    alt_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
    if (alt_sigval_as_asn1bitstring == NULL) {
        EST_LOG_ERR("ASN1 bit string memory allocation error");
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    alt_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    alt_sigval_as_asn1bitstring->data = sign_out;
    alt_sigval_as_asn1bitstring->length = sign_out_size;

    sign_out = NULL;
    sign_out_size = 0;

    ext_altsigval = X509V3_EXT_i2d(NID_alt_sigval, 0, alt_sigval_as_asn1bitstring);
    if (ext_altsigval == NULL) {
        EST_LOG_ERR("Error creating signature extension.");
        ossl_dump_ssl_errors();
        goto end;
    }

    if (X509_add_ext(cert, ext_altsigval, -1) == 0) {
        EST_LOG_ERR("Error adding signature extension");
        ossl_dump_ssl_errors();
        goto end;
    }

    rv = EST_ERR_NONE;

end:
    if (ext_altsigval) {
        X509_EXTENSION_free(ext_altsigval);
    }
    if (alt_sigval_as_asn1bitstring) {
        ASN1_BIT_STRING_free(alt_sigval_as_asn1bitstring);
    }
    OPENSSL_free(sign_out);
    OPENSSL_free(sign_in);
    if (algo_holder) {
        X509_ALGOR_free(algo_holder);
    }
    EVP_MD_CTX_cleanup(&mctx);
    if (ext_altsigalg) {
        X509_EXTENSION_free(ext_altsigalg);
    }
    if (algor_for_altsigalg) {
        X509_ALGOR_free(algor_for_altsigalg);
    }
    if (x509_sig_alt != NULL) {
        X509_PUBKEY_free(x509_sig_alt);
    }

    return rv;
}

/*
 * This function performs a simple sanity check on a PKCS10
 * CSR.  It will check the alt signature in the CSR.
 * Returns 0 for success, non-zero if the sanity check failed.
 */
int est_server_req_check_alt_csr (X509_REQ *req)
{
    EVP_PKEY *pub_key = NULL;
    int rc = 0;
    int has_alt_spki = 0;
    int has_alt_sigval = 0;
    int has_alt_sigalg = 0;

    has_alt_spki = (X509_REQ_get_attr_by_NID(req, NID_subj_alt_pub_key, -1) >= 0);
    has_alt_sigval = (X509_REQ_get_attr_by_NID(req, NID_alt_sigval, -1) >= 0);
    has_alt_sigalg = (X509_REQ_get_attr_by_NID(req, NID_alt_sigalg, -1) >= 0);

    if (has_alt_spki != has_alt_sigval || has_alt_sigval != has_alt_sigalg) {
        EST_LOG_ERR("CSR has misconfigured alt extensions");
        return 1;
    } else if (!has_alt_spki) {
        EST_LOG_INFO("CSR doesn't have alt extensions, nothing to verify");
        return 0;
    }

    /*
     * Extract the alt public key from the CSR
     */
    if ((pub_key = req_get_alt_pubkey(req)) == NULL) {
        EST_LOG_INFO("CSR doesn't have alt public key");
        return 1;
    }

    /*
     * Verify the alt signature in the CSR
     */
    rc = req_alt_verify(req, pub_key);
    EVP_PKEY_free(pub_key);

    /*
     * Check the result
     */
    if (rc < 0) {
        EST_LOG_ERR("CSR alternative signature check failed");
        return 1;
    } else if (rc == 0) {
        EST_LOG_ERR("CSR alternative signature mismatch");
        return 1;
    } else {
        return 0;
    }
}

/*
 * Add all the alternative public-key algorithm extensions to the certificate.
 */
EST_ERROR est_server_cert_add_alt_extensions(X509 *cert, X509_REQ *csr, EVP_PKEY *alt_priv_key, const EVP_MD *alt_md)
{
    EVP_PKEY *alt_pub_key = NULL;
    EST_ERROR rv = EST_ERR_UNKNOWN;

    /*
     * If the CSR contains an alt public key, add it to the certificate
     */
    alt_pub_key = req_get_alt_pubkey(csr);
    if (alt_pub_key) {
        rv = cert_add_alt_pubkey(cert, alt_pub_key);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Error adding alt public key to cert");
            ossl_dump_ssl_errors();
            goto end;
        }
    }

    /*
     * Sign the certificate with the alt private key and add the alt signature
     * as an extension in the certificate.
     */
    rv = cert_alt_sign(cert, alt_priv_key, alt_md);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Error adding alt signature to cert");
        ossl_dump_ssl_errors();
        goto end;
    }

end:
    if (alt_pub_key != NULL) {
        EVP_PKEY_free(alt_pub_key);
    }

    return rv;
}
