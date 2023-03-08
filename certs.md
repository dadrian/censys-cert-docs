# Certificates Dataset

## Schema

### Fingerprints

* `fingerprint_sha256`
* `fingerprint_sha1`
* `fingerprint_md5`

Each certificate fingerprint is the hash of the DER-encoded bytes of the
certificate with the specified algorithm, represented as a lowercase hex string
with no spaces.

* `spki_fingerprint_sha256`
* `parent_spki_fingerprint_sha256`

The SPKI fingerprint is the hash of DER-encoded bytes of the Subject Public Key
Info (SPKI). The parent SPKI fingerprint is the SPKI fingerprint for all [valid
issuers](#validation) of the certificate. It will be equal to the
`parsed.subject_key_info.fingerprint_sha256` field in the parent.

\TODO: Example query

* `tbs_fingerprint_sha256`
* `tbs_no_ct_fingerprint_sha256`

The TBS fingerprint is the fingerprint of the to-be-signed portion of the
DER-encoded bytes of the certificate, which is effectively all of the
certificate _except_ for the signature. The TBS fingerprint includes the issuer,
so it is not effective for finding cross-signatures.

The "TBS No CT Fingerprint" (`tbs_no_ct_fingerprint_sha256`) is the fingerprint
of the DER-encoded bytes of the TBS certificate with the SCT poison extension
removed. This field will match between a certificate and any of its associated
precertificates.

\TODO: How are precertificates collapsed
\TODO: Example query

### Names

The top-level `names` field is the union of all the names a certificate is valid for. This includes:
* `parsed.extensions.subject_alt_name.dns_names`
* `parsed.extensions.subject_alt_name.ip_addresses`
* Any DNS names in the common name (CN) within the `subject_dn`.

\TODO confirm this

In trusted Web PKI certificates, this field will most commonly be identical to
the DNS names in the Subject Alternative Name on leaf certificates, and empty on
root and intermediate certificates.

### Parsed

The `parsed` structure is a representation of the ASN.1 schema of an X.509
certificate in structured form. Each field corresponds to a field defined in
[RFC 5280][rfc-5280] or the [baseline requirements][brs] (BRs). 

* `issuer`
* `subject`
* `issuer_dn`
* `subject_dn`

Both the issuer and the subject are structured identically, and correspond to
information about the subject and issuer of the certificate, respectively. Both
are an X.509 distinguished name, and are represented as a series of possibly
repeating key-value identifiers for fields like `common_name` and
`organization`. These fields are defined in [RFC 5280][rfc-5280]. Distinguished
names are allowed to use repeating values in X.509. This causes each of the
subfields of `subject` and `issuer` to be repeated in the schema. This can make
querying difficult.

To help simply this in the schema, the `subject_dn` and `issuer_dn` fields
represent their respective distinguished name sequences as a single text string
of comma-separated and alphabetized key-value pairs. Well-known keys are
represented using their standardized two-letter format, such as `CN` for Common
Name. This may be more convenient to query than the structured version in some cases. 

* `validity_period.not_before`
* `validity_period.not_after`
* `validity_period.length_seconds`

The `validty_period` structure fields corresponding to the
Not Before and Not After timestamp included in the certificate. To simplify
length calculations, it also includes the `length_seconds` field for the
non-inclusive second count calculated by subtracting the Not Before from the Not
After (i.e. `[not_before, not_after)`). Historically, there is confusion within
the BRs and RFC about whether or not this time range should be inclusive or
non-inclusive. To determine the fully inclusive certificate lifetime, add 1 to
`length_seconds`.

\TODO: example query

* subject_key_info
* signature

The `subject_key_info` corresponds with the Subject Public Key Information
(SPKI) structure defined in [RFC 5280][rfc-5280]. This structure includes the
public key associated with the certificate, including the type information (RSA,
ECDSA, etc) about the key. Only one of `subject_key_info.{rsa,dsa,ecdsa}` will
be non-null at any given time. This will correspond with the value of
`subject_key_info.key_algorithm`. The `subject_key_info.fingerprint_sha256` is
the hex-encoded SHA256 of the DER-encoded bytes of the SPKI. This hash is
commonly used to identify certificate parents via the top-level field
`parent_spki_fingerprint_sha256`. 

\TODO: example query

The `signature` is the raw bytes of the DER-encoding of the signature, which
will be encoded as per the algorithm defined in the `subject_key_info`.


\TODO: verify this

* `extensions`
* `unknown_extensions`

\TODO: see my feedback on this

* `redacted`

This field is true if the names in the certificate are redacted per RFC \TK.

* `version`
* `serial_number`

The `version` is the integer X.509 version encoded in the certificate. 
The full list of fields in the `parsed` object is available in the
[reference][censys-cert-reference].

### Validation

## BigQuery Tables

BigQuery is case-insensitive

`certificates`: \TODO 

`certificates_all`: \TODO

## Examples

[rfc-5280]: https://www.rfc-editor.org/rfc/rfc5280
[brs]: https://cabforum.org/baseline-requirements-documents/