/** @file est_client_csr.c
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

/*
 * Create Subject Alt Public Key Info attribute for addition to a CSR.
 */
static X509_ATTRIBUTE *create_SAPKI_ATTRIBUTE(SUBJECT_ALT_PUBLIC_KEY_INFO *sapki) {
    unsigned char *p = NULL;
    unsigned char *data = NULL;
    ASN1_STRING *seq = NULL;
    int i = 0;
    int total = 0;
    X509_ATTRIBUTE *attr = NULL;

    i = i2d_SUBJECT_ALT_PUBLIC_KEY_INFO(sapki, NULL);
    if (i < 0) {
        EST_LOG_ERR("Failed to get ASN.1 size of SAPKI attribute.");
        goto end;
    }

    total = ASN1_object_size(1,i,V_ASN1_SEQUENCE);

    data = OPENSSL_malloc(total);
    if (data == NULL) {
        EST_LOG_ERR("Memory failure during SAPKI attribute creation.");
        goto end;
    }

    p=data;
    ASN1_put_object(&p, 1, i, V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
    i = i2d_SUBJECT_ALT_PUBLIC_KEY_INFO(sapki, &p);
    if (i < 0) {
        EST_LOG_ERR("Failed to ASN.1 encode the SAPKI attribute.");
        goto end;
    }

    seq = ASN1_STRING_new();
    if (!ASN1_STRING_set(seq, data, total)) {
        EST_LOG_ERR("Failed to alloc/set string for SAPKI attribute.");
        ASN1_STRING_free(seq);
        goto end;
    }

    attr = X509_ATTRIBUTE_create(NID_subj_alt_pub_key, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        EST_LOG_ERR("Failed to create the SAPKI attribute.");
        goto end;
    }

end:
    OPENSSL_free(data);
    return attr;
}

/*
 * Create Alt Signature Value attribute for addition to a CSR.
 */
static X509_ATTRIBUTE *create_ALTSIG_ATTRIBUTE(ASN1_BIT_STRING *altsig) {
    X509_ATTRIBUTE *attr = NULL;

    attr = X509_ATTRIBUTE_create(NID_alt_sigval, V_ASN1_BIT_STRING, altsig);
    if (attr == NULL) {
        EST_LOG_ERR("Failed to create the ALTSIG attribute.");
        goto end;
    }

end:
    return attr;
}

/*
 * Create Alt Signature Algorithm attribute for addition to a CSR.
 */
static X509_ATTRIBUTE *create_ALTSIGALG_ATTRIBUTE(X509_ALGOR *altsigalg) {
    X509_ATTRIBUTE *attr = NULL;
    unsigned char *p = NULL;
    unsigned char *data = NULL;
    ASN1_STRING *astr = NULL;
    int i = 0;

    i = i2d_X509_ALGOR(altsigalg, NULL);
    if (i < 0) {
        EST_LOG_ERR("Failed to get ASN.1 size of ALTSIGALG attribute.");
        goto end;
    }

    data = OPENSSL_malloc(i);
    if (data == NULL) {
        EST_LOG_ERR("Memory failure during ALTSIGALG attribute creation.");
        goto end;
    }

    p=data;
    i = i2d_X509_ALGOR(altsigalg, &p);
    if (i < 0) {
        EST_LOG_ERR("Failed to ASN.1 encode the ALTSIGALG attribute.");
        goto end;
    }

    astr = ASN1_STRING_new();
    if (!ASN1_STRING_set(astr, data, i)) {
        EST_LOG_ERR("Failed to alloc/set string for ALTSIGALG attribute.");
        ASN1_STRING_free(astr);
        goto end;
    }

    attr = X509_ATTRIBUTE_create(NID_alt_sigalg, V_ASN1_SEQUENCE, astr);
    if (attr == NULL) {
        ASN1_STRING_free(astr);
        EST_LOG_ERR("Failed to create the ALTSIGALG attribute.");
        goto end;
    }

end:
    OPENSSL_free(data);
    return attr;
}

/*
 * Add the Alt Signature Algorithm attribure to a CSR.
 */
static EST_ERROR req_add_alt_sig_algor (X509_REQ *csr, EVP_PKEY *alt_priv_key)
{
    EST_ERROR rv = EST_ERR_NONE;
    X509_PUBKEY *x509_sig_alt = NULL;
    X509_ALGOR *altsig_algor = NULL;
    int snid = -1;
    X509_ATTRIBUTE *attr_altsigalg = NULL;

    X509_PUBKEY_set(&x509_sig_alt, alt_priv_key);

    altsig_algor = X509_ALGOR_dup(x509_sig_alt->algor);
    if (altsig_algor == NULL) {
        EST_LOG_ERR("Error duplicating public key algor");
        rv = EST_ERR_MALLOC;
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Make sure that the right digest is set. */
    if (!OBJ_find_sigid_by_algs(&snid, NID_sha512, EVP_PKEY_id(alt_priv_key))) {
        EST_LOG_ERR("Error getting NID for digest/signature algorithm combination");
        rv = EST_ERR_X509_ATTR;
        ossl_dump_ssl_errors();
        goto end;
    }

    if (X509_ALGOR_set0(altsig_algor, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0) == 0) {
        EST_LOG_ERR("Error setting algorithm object ID");
        rv = EST_ERR_X509_ATTR;
        ossl_dump_ssl_errors();
        goto end;
    }

    attr_altsigalg = create_ALTSIGALG_ATTRIBUTE(altsig_algor);

    /* Add the ALT signature algorithm extension so the signing process includes it.
     */
    if (X509_REQ_add1_attr(csr, attr_altsigalg) == 0) {
        EST_LOG_ERR("Error adding signature algorithm as extension");
        rv = EST_ERR_X509_ATTR;
        ossl_dump_ssl_errors();
        goto end;
    }

    csr->req_info->enc.modified = 1;

end:
    if (attr_altsigalg) {
        X509_ATTRIBUTE_free(attr_altsigalg);
    }
    if (altsig_algor) {
        X509_ALGOR_free(altsig_algor);
    }
    if (x509_sig_alt) {
        X509_PUBKEY_free(x509_sig_alt);
    }

    return rv;
}

/*
 * Sign the CSR with the Alt private key and add the Alt Signature Value
 * attribute to the CSR.
 */
static EST_ERROR req_alt_key_sign (X509_REQ *csr, EVP_PKEY *alt_priv_key)
{
    EST_ERROR rv = EST_ERR_NONE;
    X509_PUBKEY *x509_sig_alt = NULL;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    const EVP_MD *md_alg = EVP_sha512();

    unsigned char *sign_in = NULL;
    size_t sign_in_size = 0;
    unsigned char *sign_out = NULL;
    size_t sign_out_size = 0;

    ASN1_BIT_STRING *alt_sigval_as_asn1bitstring = NULL;
    X509_ATTRIBUTE *attr_altsig = NULL;

    X509_PUBKEY_set(&x509_sig_alt, alt_priv_key);

    /* Sign the req with the alt private key. */
    if (EVP_DigestSignInit(&mctx, NULL, md_alg, NULL, alt_priv_key) < 1) {
        EST_LOG_ERR("Error doing EVP digest initialization");
        rv = EST_ERR_X509_SIGN;
        ossl_dump_ssl_errors();
        goto end;
    }

    sign_in_size = ASN1_item_i2d((ASN1_VALUE *)csr->req_info, &sign_in, ASN1_ITEM_rptr(X509_REQ_INFO));

    sign_out_size = EVP_PKEY_size(alt_priv_key);
    sign_out = OPENSSL_malloc(sign_out_size);
    if ((sign_in == NULL) || (sign_out == NULL)) {
        EST_LOG_ERR("Memory allocation error for signing input or output");
        rv = EST_ERR_MALLOC;
        ossl_dump_ssl_errors();
        goto end;
    }

    if (!EVP_DigestSignUpdate(&mctx, sign_in, sign_in_size)
        || !EVP_DigestSignFinal(&mctx, sign_out, &sign_out_size)) {
        EST_LOG_ERR("EVP digest/sign operation error. Did you run out of HSS one-time-keys?");
        rv = EST_ERR_X509_SIGN;
        ossl_dump_ssl_errors();
        goto end;
    }

    /* Prepare an ASN1 bit string for the alt signature extension. */
    alt_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
    if (alt_sigval_as_asn1bitstring == NULL) {
        EST_LOG_ERR("ASN1 bit string memory allocation error");
        rv = EST_ERR_MALLOC;
        ossl_dump_ssl_errors();
        goto end;
    }

    alt_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    alt_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    alt_sigval_as_asn1bitstring->data = sign_out;
    alt_sigval_as_asn1bitstring->length = sign_out_size;

    /* Prevent a double free. */
    sign_out = NULL;
    sign_out_size = 0;

    attr_altsig = create_ALTSIG_ATTRIBUTE(alt_sigval_as_asn1bitstring);
    if (attr_altsig == NULL) {
        EST_LOG_ERR("Error creating signature extension");
        goto end;
    }
    alt_sigval_as_asn1bitstring = NULL;

    if (X509_REQ_add1_attr(csr, attr_altsig) == 0) {
        EST_LOG_ERR("Error adding signature as extension");
        goto end;
    }

    csr->req_info->enc.modified = 1;

end:
    if (attr_altsig) {
        X509_ATTRIBUTE_free(attr_altsig);
    }
    OPENSSL_free(sign_out);
    OPENSSL_free(sign_in);
    if (alt_sigval_as_asn1bitstring) {
        ASN1_BIT_STRING_free(alt_sigval_as_asn1bitstring);
    }
    if (x509_sig_alt) {
        X509_PUBKEY_free(x509_sig_alt);
    }
    EVP_MD_CTX_cleanup(&mctx);

    return rv;
}

/*
 * Adds the Alt Signature Algorithm and properly computed Alt Signature Value
 * attributes to the CSR.
 */
EST_ERROR est_client_req_alt_sign (X509_REQ *csr, EVP_PKEY *alt_pkey)
{
	EST_ERROR rv = EST_ERR_NONE;

    rv = req_add_alt_sig_algor(csr, alt_pkey);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to add alterantive signature algorithm to certificate request");
        return rv;
    }

    rv = req_alt_key_sign(csr, alt_pkey);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to create multiple public-key algorithm certificate request");
        return rv;
    }

    return rv;
}

/*
 * The Alt SPKI, Signature Value and Signature Algorithm extensions may have
 * been copied from a cert into a new CSR when creating the CSR from an
 * existing cert while re-registering.  Remove these extensions from the CSR
 * the appropriate alt values will be added as attributes to the CSR later.
 */
EST_ERROR est_client_req_remove_copied_alt_extensions (X509_REQ *csr)
{
    int idx = 0;
    int ossl_rv = 0;
    STACK_OF(X509_EXTENSION) *exts = NULL;

    exts = X509_REQ_get_extensions(csr);
    if (exts != NULL) {
        idx = X509v3_get_ext_by_NID(exts, NID_subj_alt_pub_key, -1);
        if (idx >= 0) {
            if (X509v3_delete_ext(exts, idx) == NULL) {
                EST_LOG_ERR("Failed to delete Subject-Alt-Public-Key REQ extension.");
                return EST_ERR_X509_ATTR;
            }
        }

        idx = X509v3_get_ext_by_NID(exts, NID_alt_sigval, -1);
        if (idx >= 0) {
            if (X509v3_delete_ext(exts, idx) == NULL) {
                EST_LOG_ERR("Failed to delete Alt-Signature-Value REQ extension.");
                return EST_ERR_X509_ATTR;
            }
        }

        idx = X509v3_get_ext_by_NID(exts, NID_alt_sigalg, -1);
        if (idx >= 0) {
            if (X509v3_delete_ext(exts, idx) == NULL) {
                EST_LOG_ERR("Failed to delete Alt-Signature-Algorithm REQ extension.");
                return EST_ERR_X509_ATTR;
            }
        }

        idx = X509_REQ_get_attr_by_NID(csr, NID_ext_req, -1);
        if (idx < 0) {
            EST_LOG_ERR("Failed find REQ extensions.");
            return EST_ERR_X509_ATTR;
        }

        if (X509_REQ_delete_attr(csr, idx) == NULL) {
            EST_LOG_ERR("Failed to delete REQ extensions.");
            return EST_ERR_X509_ATTR;
        }

        ossl_rv = X509_REQ_add_extensions(csr, exts);
        if (!ossl_rv) {
            EST_LOG_ERR("Failed to re-add REQ extensions.");
            return EST_ERR_X509_ATTR;
        }
    }

    return EST_ERR_NONE;
}

/*
 * Add an alternative public key to the CSR.
 */
EST_ERROR est_client_csr_add_alt_pubkey (X509_REQ *csr, EVP_PKEY *alt_pub_key)
{
    EST_ERROR rv = EST_ERR_NONE;
    X509_PUBKEY *x509_pub_alt = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    X509_ATTRIBUTE *attr_sapki = NULL;

    X509_PUBKEY_set(&x509_pub_alt, alt_pub_key);

    sapki = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    if (sapki == NULL) {
        EST_LOG_ERR("Error allocating x509 pubkey");
        rv = EST_ERR_MALLOC;
        ossl_dump_ssl_errors();
        goto end;
    }

    X509_ALGOR_free(sapki->algor);
    ASN1_BIT_STRING_free(sapki->public_key);

    sapki->algor = x509_pub_alt->algor;
    sapki->public_key = x509_pub_alt->public_key;

    attr_sapki = create_SAPKI_ATTRIBUTE(sapki);
    sapki->algor = NULL;
    sapki->public_key = NULL;
    if (attr_sapki == NULL) {
        EST_LOG_ERR("Error converting x509 alt pubkey to attribute.");
        rv = EST_ERR_X509_PUBKEY;
        ossl_dump_ssl_errors();
        goto end;
    }

    if (X509_REQ_add1_attr(csr, attr_sapki) == 0) {
        EST_LOG_ERR("Error adding alt public key attribute.");
        goto end;
    }

end:
    if (x509_pub_alt) {
        X509_PUBKEY_free(x509_pub_alt);
    }
    if (sapki) {
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    }
    if (attr_sapki) {
        X509_ATTRIBUTE_free(attr_sapki);
    }

    return rv;
}

/*
 * This function is used to clear any Alt Signature
 * attributes in an X509 CSR.  This is used because the
 * contents of the CSR may have changed, so the Alt
 * Signature needs to be regenerated.
 */
EST_ERROR est_client_req_remove_alt_sig_attributes (X509_REQ *csr)
{
    int idx = 0;

    idx = X509_REQ_get_attr_by_NID(csr, NID_alt_sigalg, -1);
    if (idx >= 0) {
        if (X509_REQ_delete_attr(csr, idx) == NULL) {
            EST_LOG_ERR("Failed delete Alt Signature Algorithm attribute.");
            return EST_ERR_X509_ATTR;
        }
    }

    idx = X509_REQ_get_attr_by_NID(csr, NID_alt_sigval, -1);
    if (idx >= 0) {
        if (X509_REQ_delete_attr(csr, idx) == NULL) {
            EST_LOG_ERR("Failed delete Alt Signature Value attribute.");
            return EST_ERR_X509_ATTR;
        }
    }

    return EST_ERR_NONE;
}
