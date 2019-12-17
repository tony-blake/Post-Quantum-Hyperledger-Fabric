/** @file v3_qr.c
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
 * Written by Jerry Sui, jerry.sui@isara.com; Daniel Van Geest,
 * daniel.vangeest@isara.com, December, 2017.
 */

#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

/* ====================================================================
 * General output.
 * ====================================================================
 */
static int bitstring_print(BIO *bp, const char *prefix, const ASN1_BIT_STRING *str, int off)
{
    int n = 0;
    int i = 0;

    if (str == NULL || str->length == 0) {
        return 1;
    }

    if (BIO_printf(bp, "%s", prefix) <= 0) {
        return 0;
    }

    n = str->length;
    for (i = 0; i < n; i++) {
        if ((i % 15) == 0) {
            if (BIO_puts(bp, "\n") <= 0 || !BIO_indent(bp, off + 4, 128))
                return 0;
        }

        if (BIO_printf(bp, "%02x%s", str->data[i], ((i + 1) == n) ? "" : ":")
            <= 0) {
            return 0;
        }
    }

    if (BIO_write(bp, "\n", 1) <= 0) {
        return 0;
    }

    return 1;
}

/* ====================================================================
 * ALT Public Key Extension.
 * ====================================================================
 */
static int i2r_SUBJECT_ALT_PUBLIC_KEY_INFO(X509V3_EXT_METHOD *method,
                                 SUBJECT_ALT_PUBLIC_KEY_INFO *altpub, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_subject_alt_public_key_info = {
    NID_subj_alt_pub_key,
    X509V3_EXT_MULTILINE, ASN1_ITEM_ref(SUBJECT_ALT_PUBLIC_KEY_INFO),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R) i2r_SUBJECT_ALT_PUBLIC_KEY_INFO, NULL,
    NULL
};

/* This is the same as the definition of the X509 subject public key in x_pubkey.c  */
ASN1_SEQUENCE(SUBJECT_ALT_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_ALT_PUBLIC_KEY_INFO, algor, X509_ALGOR),
        ASN1_SIMPLE(SUBJECT_ALT_PUBLIC_KEY_INFO, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SUBJECT_ALT_PUBLIC_KEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(SUBJECT_ALT_PUBLIC_KEY_INFO)

static int i2r_SUBJECT_ALT_PUBLIC_KEY_INFO(X509V3_EXT_METHOD *method,
                                 SUBJECT_ALT_PUBLIC_KEY_INFO *alt_pub, BIO *out,
                                 int indent)
{

    X509_PUBKEY *x509_pub = NULL;
    EVP_PKEY * pkey_pub = NULL;
    int ret = 0;

    x509_pub = X509_PUBKEY_new();
    if (x509_pub == NULL) {
        goto end;
    }

    /* Prevent the leaking of memory */
    X509_ALGOR_free(x509_pub->algor);
    ASN1_BIT_STRING_free(x509_pub->public_key);

    x509_pub->algor = alt_pub->algor;
    x509_pub->public_key = alt_pub->public_key;

    pkey_pub = X509_PUBKEY_get(x509_pub);
    if (pkey_pub == NULL) {
        goto end;
    }
    BIO_indent(out, indent, 128);
    BIO_printf(out, "%s\n", OBJ_nid2ln(OBJ_obj2nid(alt_pub->algor->algorithm)));
    EVP_PKEY_print_public(out, pkey_pub, indent, NULL);
    ret = 1;

end:
    if (pkey_pub)
        EVP_PKEY_free(pkey_pub);
    if(x509_pub) {
        /* Prevent a double free */
        x509_pub->algor = NULL;
        x509_pub->public_key = NULL;
        X509_PUBKEY_free(x509_pub);
    }

    return ret;
}

/* ====================================================================
 * ALT Signature Value Extension.
 * ====================================================================
 */
static int i2r_ALT_SIGNATURE_VALUE(X509V3_EXT_METHOD *method,
                                 ASN1_BIT_STRING *signature, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_alt_sigval = {
    NID_alt_sigval, 0, ASN1_ITEM_ref(ASN1_BIT_STRING),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_ALT_SIGNATURE_VALUE, NULL,
    NULL
};

static int i2r_ALT_SIGNATURE_VALUE(X509V3_EXT_METHOD *method,
                                 ASN1_BIT_STRING *signature, BIO *out,
                                 int indent)
{
    BIO_printf(out, "%*s", indent, "");
    if (signature) {
        bitstring_print(out, "Signature: ", signature, indent);
    }
    return 1;
}

/* ====================================================================
 * ALT Signature Algorithm Extension.
 * ====================================================================
 */
static int i2r_ALT_SIGALG(X509V3_EXT_METHOD *method,
                                 X509_ALGOR *sigalg, BIO *out,
                                 int indent);

const X509V3_EXT_METHOD v3_alt_sigalg = {
    NID_alt_sigalg, 0, ASN1_ITEM_ref(X509_ALGOR),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_ALT_SIGALG, NULL,
    NULL
};

static int i2r_ALT_SIGALG(X509V3_EXT_METHOD *method,
                                 X509_ALGOR *sigalg, BIO *out,
                                 int indent)
{
    BIO_indent(out, indent, 128);
    BIO_printf(out, "%s\n", OBJ_nid2ln(OBJ_obj2nid(sigalg->algorithm)));
    return 1;
}
