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
Info. The parent SPKI fingerprint is the SPKI fingerprint for all [valid
issuers](#validation) of the certificate. 

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

### Parsed

### Validation

## BigQuery Tables

`certificates`: \TODO 

`certificates_all`: \TODO

## Examples