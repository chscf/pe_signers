#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/asn1t.h>

#define ERR_OK		0

typedef int 		ss_return_t;
typedef uint32_t 	ss_uint32_t;
typedef uint8_t		ss_byte_t;
typedef char		ss_char_t;

typedef struct _ss_blob
{
	ss_uint32_t tag;
	ss_uint32_t length;
	ss_byte_t  *data;
}
ss_blob_t;

typedef struct SIGNATURE_st {
	PKCS7 *p7;
	int md_nid;
	ASN1_STRING *digest;
	time_t signtime;
	char *url;
	char *desc;
	char *purpose;
	char *level;
	CMS_ContentInfo *timestamp;
	time_t time;
	ASN1_STRING *blob;
} SIGNATURE;

DEFINE_STACK_OF(SIGNATURE)
DECLARE_ASN1_FUNCTIONS(SIGNATURE)

/*
 * ASN.1 definitions (more or less from official MS Authenticode docs)
*/

typedef struct {
	int type;
	union {
		ASN1_BMPSTRING *unicode;
		ASN1_IA5STRING *ascii;
	} value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString)

ASN1_CHOICE(SpcString) = {
	ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)


typedef struct {
	ASN1_OCTET_STRING *classId;
	ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)

ASN1_SEQUENCE(SpcSerializedObject) = {
	ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)


typedef struct {
	int type;
	union {
		ASN1_IA5STRING *url;
		SpcSerializedObject *moniker;
		SpcString *file;
	} value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink)

ASN1_CHOICE(SpcLink) = {
	ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
	ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
	ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)

typedef struct {
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

ASN1_SEQUENCE(TimeStampAccuracy) = {
	ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)

typedef struct {
	SpcString *programName;
	SpcLink   *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)

ASN1_SEQUENCE(SpcSpOpusInfo) = {
	ASN1_EXP_OPT(SpcSpOpusInfo, programName, SpcString, 0),
	ASN1_EXP_OPT(SpcSpOpusInfo, moreInfo, SpcLink, 1)
} ASN1_SEQUENCE_END(SpcSpOpusInfo)

IMPLEMENT_ASN1_FUNCTIONS(SpcSpOpusInfo)

typedef struct {
	ASN1_OBJECT *algorithm;
	ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)

typedef struct {
	AlgorithmIdentifier *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

typedef struct {
	ASN1_INTEGER *version;
	ASN1_OBJECT *policy_id;
	MessageImprint *messageImprint;
	ASN1_INTEGER *serial;
	ASN1_GENERALIZEDTIME *time;
	TimeStampAccuracy *accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER *nonce;
	GENERAL_NAME *tsa;
	STACK_OF(X509_EXTENSION) *extensions;
} TimeStampToken;

DECLARE_ASN1_FUNCTIONS(TimeStampToken)

ASN1_SEQUENCE(TimeStampToken) = {
	ASN1_SIMPLE(TimeStampToken, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, policy_id, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampToken, messageImprint, MessageImprint),
	ASN1_SIMPLE(TimeStampToken, serial, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, time, ASN1_GENERALIZEDTIME),
	ASN1_OPT(TimeStampToken, accuracy, TimeStampAccuracy),
	ASN1_OPT(TimeStampToken, ordering, ASN1_FBOOLEAN),
	ASN1_OPT(TimeStampToken, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(TimeStampToken, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampToken, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TimeStampToken)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampToken)

#define INVALID_TIME ((time_t)-1)

/* Microsoft OID Authenticode */
#define SPC_INDIRECT_DATA_OBJID      "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID     "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID       "1.3.6.1.4.1.311.2.1.12"
#define SPC_PE_IMAGE_DATA_OBJID      "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID           "1.3.6.1.4.1.311.2.1.25"
#define SPC_SIPINFO_OBJID            "1.3.6.1.4.1.311.2.1.30"
#define SPC_PE_IMAGE_PAGE_HASHES_V1  "1.3.6.1.4.1.311.2.3.1" /* SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2  "1.3.6.1.4.1.311.2.3.2" /* SHA256 */
#define SPC_NESTED_SIGNATURE_OBJID   "1.3.6.1.4.1.311.2.4.1"
/* Microsoft OID Time Stamping */
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_RFC3161_OBJID            "1.3.6.1.4.1.311.3.3.1"
/* Microsoft OID Crypto 2.0 */
#define MS_CTL_OBJID                 "1.3.6.1.4.1.311.10.1"
/* Microsoft OID Microsoft_Java */
#define MS_JAVA_SOMETHING            "1.3.6.1.4.1.311.15.1"

#define SPC_UNAUTHENTICATED_DATA_BLOB_OBJID  "1.3.6.1.4.1.42921.1.2.1"

/* Public Key Cryptography Standards PKCS#9 */
#define PKCS9_MESSAGE_DIGEST         "1.2.840.113549.1.9.4"
#define PKCS9_SIGNING_TIME           "1.2.840.113549.1.9.5"
#define PKCS9_COUNTER_SIGNATURE      "1.2.840.113549.1.9.6"


#define WIN_CERT_REVISION_2             0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002

static int append_signature_list(STACK_OF(SIGNATURE) **signatures, PKCS7 *p7, int allownest);

static time_t asn1_get_time_t(ASN1_TIME *s)
{
	struct tm tm;

	if (ASN1_TIME_to_tm(s, &tm)) {
		return mktime(&tm);
	} else {
		return INVALID_TIME;
	}
}

static time_t si_get_time(PKCS7_SIGNER_INFO *si)
{
	STACK_OF(X509_ATTRIBUTE) *auth_attr;
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_UTCTIME *time = NULL;
	time_t posix_time;
	char object_txt[128];
	int i;

	auth_attr = PKCS7_get_signed_attributes(si);  /* cont[0] */
	if (auth_attr)
		for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
			attr = X509at_get_attr(auth_attr, i);
			object = X509_ATTRIBUTE_get0_object(attr);
			if (object == NULL)
				return INVALID_TIME; /* FAILED */
			object_txt[0] = 0x00;
			OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
			if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
				/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
				time = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
			}
		}
	posix_time = asn1_get_time_t(time);
	return posix_time;
}

/*
 * Create new CMS_ContentInfo struct for Authenticode Timestamp.
 * This struct does not contain any TimeStampToken as specified in RFC 3161.
 */
static CMS_ContentInfo *cms_get_timestamp(PKCS7_SIGNED *p7_signed, PKCS7_SIGNER_INFO *countersignature)
{
	CMS_ContentInfo *cms = NULL;
	PKCS7_SIGNER_INFO *si;
	PKCS7 *p7 = NULL, *content = NULL;
	unsigned char *p = NULL;
	const unsigned char *q;
	int i, len = 0;

	p7 = PKCS7_new();
	si = sk_PKCS7_SIGNER_INFO_value(p7_signed->signer_info, 0);
	if (si == NULL)
		goto out;

	/* Create new signed PKCS7 timestamp structure. */
	if (!PKCS7_set_type(p7, NID_pkcs7_signed))
		goto out;
	if (!PKCS7_add_signer(p7, countersignature))
		goto out;
	for (i = 0; i < sk_X509_num(p7_signed->cert); i++) {
		if (!PKCS7_add_certificate(p7, sk_X509_value(p7_signed->cert, i)))
			goto out;
	}

	/* Create new encapsulated NID_id_smime_ct_TSTInfo content. */
	content = PKCS7_new();
	content->d.other = ASN1_TYPE_new();
	content->type = OBJ_nid2obj(NID_id_smime_ct_TSTInfo);
	ASN1_TYPE_set1(content->d.other, V_ASN1_OCTET_STRING, si->enc_digest);
	/* Add encapsulated content to signed PKCS7 timestamp structure:
	   p7->d.sign->contents = content */
	if (!PKCS7_set_content(p7, content)) {
		PKCS7_free(content);
		goto out;
	}

	/* Convert PKCS7 into CMS_ContentInfo */
	if (((len = i2d_PKCS7(p7, NULL)) <= 0) || (p = OPENSSL_malloc(len)) == NULL) {
		//printf("Failed to convert pkcs7: %d\n", len);
		goto out;
	}
	len = i2d_PKCS7(p7, &p);
	p -= len;
	q = p;
	cms = d2i_CMS_ContentInfo(NULL, &q, len);
	OPENSSL_free(p);

out:
	if (!cms)
	{
		//ERR_print_errors_fp(stdout);
	}
	PKCS7_free(p7);
	return cms;
}

static time_t cms_get_time(CMS_ContentInfo *cms)
{
	ASN1_OCTET_STRING **pos;
	const unsigned char *p = NULL;
	TimeStampToken *token = NULL;
	ASN1_GENERALIZEDTIME *asn1_time = NULL;
	time_t posix_time = INVALID_TIME;

	pos  = CMS_get0_content(cms);
	if (pos != NULL && *pos != NULL) {
		p = (*pos)->data;
		token = d2i_TimeStampToken(NULL, &p, (*pos)->length);
		if (token) {
			asn1_time = token->time;
			posix_time = asn1_get_time_t(asn1_time);
			TimeStampToken_free(token);
		}
	}
	return posix_time;
}

static void get_signed_attributes(SIGNATURE *signature, STACK_OF(X509_ATTRIBUTE) *auth_attr)
{
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	char object_txt[128];
	const unsigned char *data;
	int i;

	for (i=0; i<X509at_get_attr_count(auth_attr); i++) {
		attr = X509at_get_attr(auth_attr, i);
		object = X509_ATTRIBUTE_get0_object(attr);
		if (object == NULL)
			continue;
		object_txt[0] = 0x00;
		OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
		if (!strcmp(object_txt, PKCS9_MESSAGE_DIGEST)) {
			/* PKCS#9 message digest - Policy OID: 1.2.840.113549.1.9.4 */
			signature->digest  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_OCTET_STRING, NULL);
		} else if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
			/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
			ASN1_UTCTIME *time;
			time = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL);
			signature->signtime = asn1_get_time_t(time);
		} else if (!strcmp(object_txt, SPC_SP_OPUS_INFO_OBJID)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.2.1.12 */
			SpcSpOpusInfo *opus;
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			opus = d2i_SpcSpOpusInfo(NULL, &data, value->length);
			if (opus->moreInfo && opus->moreInfo->type == 0)
				signature->url = OPENSSL_strdup((char *)opus->moreInfo->value.url->data);
			if (opus->programName) {
				if (opus->programName->type == 0) {
					unsigned char *data;
					int len = ASN1_STRING_to_UTF8(&data, opus->programName->value.unicode);
					if (len >= 0) {
						signature->desc = OPENSSL_strndup((char *)data, len);
						OPENSSL_free(data);
					}
				} else {
					signature->desc = OPENSSL_strdup((char *)opus->programName->value.ascii->data);
				}
			}
			SpcSpOpusInfo_free(opus);
		} else if (!strcmp(object_txt, SPC_STATEMENT_TYPE_OBJID)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.2.1.11 */
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			signature->purpose = (char *)ASN1_STRING_get0_data(value);
		} else if (!strcmp(object_txt, MS_JAVA_SOMETHING)) {
			/* Microsoft OID: 1.3.6.1.4.1.311.15.1 */
			value  = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			signature->level = (char *)ASN1_STRING_get0_data(value);
		}
	}
}

void signature_free(SIGNATURE *signature)
{
	if (signature->timestamp) {
		CMS_ContentInfo_free(signature->timestamp);
		ERR_clear_error();
	}
	PKCS7_free(signature->p7);
	/* If memory has not been allocated nothing is done */
	OPENSSL_free(signature->url);
	OPENSSL_free(signature->desc);
	OPENSSL_free(signature);
}

static void get_unsigned_attributes(STACK_OF(SIGNATURE) **signatures, SIGNATURE *signature,
		STACK_OF(X509_ATTRIBUTE) *unauth_attr, PKCS7 *p7, int allownest)
{
	X509_ATTRIBUTE *attr;
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	char object_txt[128];
	const unsigned char *data;
	int i, j;

	for (i=0; i<X509at_get_attr_count(unauth_attr); i++) {
		attr = X509at_get_attr(unauth_attr, i);
		object = X509_ATTRIBUTE_get0_object(attr);
		if (object == NULL)
			continue;
		object_txt[0] = 0x00;
		OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
		if (!strcmp(object_txt, PKCS9_COUNTER_SIGNATURE)) {
			/* Authenticode Timestamp - Policy OID: 1.2.840.113549.1.9.6 */
			PKCS7_SIGNER_INFO *countersi;
			CMS_ContentInfo *timestamp = NULL;
			time_t time;
			value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			countersi = d2i_PKCS7_SIGNER_INFO(NULL, &data, value->length);
			if (countersi == NULL)
				continue;
			time = si_get_time(countersi);
			if (time != INVALID_TIME) {
				timestamp = cms_get_timestamp(p7->d.sign, countersi);
				if (timestamp) {
					signature->time = time;
					signature->timestamp = timestamp;
				} else {
					//printf("Error: Authenticode Timestamp could not be decoded correctly\n\n");
					PKCS7_SIGNER_INFO_free(countersi);
				}
			} else {
				//printf("Error: PKCS9_TIMESTAMP_SIGNING_TIME attribute not found\n\n");
				PKCS7_SIGNER_INFO_free(countersi);
			}
		} else if (!strcmp(object_txt, SPC_RFC3161_OBJID)) {
			/* RFC3161 Timestamp - Policy OID: 1.3.6.1.4.1.311.3.3.1 */
			CMS_ContentInfo *timestamp = NULL;
			time_t time;
			value = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL);
			if (value == NULL)
				continue;
			data = ASN1_STRING_get0_data(value);
			timestamp = d2i_CMS_ContentInfo(NULL, &data, value->length);
			if (timestamp) {
				time = cms_get_time(timestamp);
				if (time != INVALID_TIME) {
					signature->time = time;
					signature->timestamp = timestamp;
				} else {
					//printf("Error: Corrupt RFC3161 Timestamp embedded content\n\n");
					//ERR_print_errors_fp(stdout);
				}
			} else {
				//printf("Error: RFC3161 Timestamp could not be decoded correctly\n\n");
				//ERR_print_errors_fp(stdout);
			}
		} else if (allownest && !strcmp(object_txt, SPC_NESTED_SIGNATURE_OBJID)) {
			/* Nested Signature - Policy OID: 1.3.6.1.4.1.311.2.4.1 */
			PKCS7 *nested;
			for (j=0; j<X509_ATTRIBUTE_count(attr); j++) {
				value = X509_ATTRIBUTE_get0_data(attr, j, V_ASN1_SEQUENCE, NULL);
				if (value == NULL)
					continue;
				data = ASN1_STRING_get0_data(value);
				nested = d2i_PKCS7(NULL, &data, value->length);
				if (nested)
					(void)append_signature_list(signatures, nested, 0);
			}
		} else if (!strcmp(object_txt, SPC_UNAUTHENTICATED_DATA_BLOB_OBJID)) {
			/* Unauthenticated Data Blob - Policy OID: 1.3.6.1.4.1.42921.1.2.1 */
			signature->blob = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTF8STRING, NULL);
		} else
		{
			//printf("Unsupported Policy OID: %s\n\n", object_txt);
		}
	}
}

static int append_signature_list(STACK_OF(SIGNATURE) **signatures, PKCS7 *p7, int allownest)
{
	SIGNATURE *signature = NULL;
	PKCS7_SIGNER_INFO *si;
	STACK_OF(X509_ATTRIBUTE) *auth_attr, *unauth_attr;

	si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
	if (si == NULL)
		return 0; /* FAILED */

	signature = OPENSSL_malloc(sizeof(SIGNATURE));
	signature->p7 = p7;
	signature->md_nid = OBJ_obj2nid(si->digest_alg->algorithm);
	signature->digest = NULL;
	signature->signtime = INVALID_TIME;
	signature->url = NULL;
	signature->desc = NULL;
	signature->purpose = NULL;
	signature->level = NULL;
	signature->timestamp = NULL;
	signature->time = INVALID_TIME;
	signature->blob = NULL;

	auth_attr = PKCS7_get_signed_attributes(si);  /* cont[0] */
	if (auth_attr)
		get_signed_attributes(signature, auth_attr);

	unauth_attr = PKCS7_get_attributes(si); /* cont[1] */
	if (unauth_attr)
		get_unsigned_attributes(signatures, signature, unauth_attr, p7, allownest);

	if (!sk_SIGNATURE_unshift(*signatures, signature)) {
		signature_free(signature);
		return 0; /* FAILED */
	}

	return 1; /* OK */
}

ss_return_t
ss_crypt_openssl_pkcs7_get_signers_new(
		ss_blob_t *sigp7_bin,
		ss_char_t ***signer_list)
{
	ss_return_t ret = ERR_OK;
	BIO *in = 0x0;
	PKCS7 *p7 = 0x0;
	ss_char_t **tmp_list = 0x0;
	ss_uint32_t num_signers = 0;
	STACK_OF(SIGNATURE) *signatures = sk_SIGNATURE_new_null();
	int i;
	STACK_OF(X509) *signers = 0x0;
	X509 *cert = 0x0;
	SIGNATURE *signature = 0x0;
	char *subject = 0x0;
	char *issuer = 0x0;

	*signer_list = 0x0;

	in = BIO_new(BIO_s_mem());
	if (in && sigp7_bin)
	{
		BIO_write(in, sigp7_bin->data, sigp7_bin->length);
		p7 = PEM_read_bio_PKCS7(in,NULL,NULL,NULL);
	}

	if (!append_signature_list(&signatures, p7, 1)) {
		//printf("Failed to create signature list\n\n");
		goto out;
	}

	num_signers = sk_SIGNATURE_num(signatures);

	if (num_signers == 0)
		goto out;

	tmp_list = (ss_char_t **)calloc(sizeof(ss_char_t *)*(num_signers+1),1);

	for (i = 0; i < sk_SIGNATURE_num(signatures); i++) {
		signature = sk_SIGNATURE_value(signatures, i);

		signers = PKCS7_get0_signers(signature->p7, NULL, 0);
		num_signers = sk_X509_num(signers);

		if (!num_signers || (num_signers != 1))
		{
			*signer_list = 0x0;
			ret = ERR_OK;
			goto out;
		}

		cert = sk_X509_value(signers, 0);
		subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		tmp_list[i] = strdup(subject);

		OPENSSL_free(subject);
		OPENSSL_free(issuer);
		sk_X509_free(signers);
	}

	*signer_list = tmp_list;

out:
	if (in) BIO_free(in);
	if (p7) PKCS7_free(p7);

	printf("%d\n", num_signers);

	return ret;
}

int main(int argc, char **argv)
{
	FILE *f = 0x0;
	struct stat st;
	char *p7_filename = 0x0;
	ss_blob_t p7_bin;
	ss_char_t **signers = 0x0;
	int i;
	
	p7_filename = argv[1];
	
	if (stat(p7_filename, &st) == -1)
	{
		perror("stat");
		return -1;
	}
	
	f = fopen(p7_filename, "rb");
	if (!f)
	{
		perror("fopen");
		return -1;
	}
	
	p7_bin.data = (ss_byte_t *)calloc(st.st_size,1);
	p7_bin.length = st.st_size;
	
	fread(p7_bin.data, st.st_size, 1, f);
	fclose(f);
	
	ss_crypt_openssl_pkcs7_get_signers_new(&p7_bin, &signers);
	if (signers)
	{
		i = 0;
		while (signers[i])
		{
			printf("%s\n", signers[i]);
			i++;
		}
	}

	return 0;
}
