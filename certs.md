# Certificates Dataset

## Schema

### Fingerprints

* `fingerprint_sha256`
* `fingerprint_sha1`
* `fingerprint_md5`

Each certificate fingerprint is the hash of the DER-encoded bytes of the
certificate with the specified algorithm, represented as a lowercase hex string
with no spaces. In BigQuery, hashes are stored as raw bytes, and are not hex-encoded.

```censys
55623fdda1e95b7f682780187ac106619bea9ab8dad69a9aaea42e0685132df5
```
```bigquery
SELECT COUNT(*) FROM `censys-io.certificates_v2.certificates` 
WHERE fingerprint_sha256 = FROM_HEX("55623fdda1e95b7f682780187ac106619bea9ab8dad69a9aaea42e0685132df5")
-- Returns 1
```

* `spki_fingerprint_sha256`
* `parent_spki_fingerprint_sha256`

The SPKI fingerprint is the hash of DER-encoded bytes of the Subject Public Key
Info (SPKI). It is identical to the `parsed.subject_key_info.fingerprint_sha256`
field. The parent SPKI fingerprint is the SPKI fingerprint for all [valid
issuers](#validation) of the certificate. It will be equal to the
`parsed.subject_key_info.fingerprint_sha256` field in the _parent_ certificate. 

For example, to find verisons of the Let's Encrypt Root X1 RSA key, and any intermediate it signed:
```censys
parsed.subject_key_info.fingerprint_sha256: 0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3 OR
parent_spki_fingerpint_sha256: 0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3
```
```bigquery
SELECT fingerprint_sha256 FROM `censys-io.certificates_v2.certificates` 
WHERE
  parsed.subject_key_info.fingerprint_sha256 = FROM_HEX("0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3")
  OR
  parent_spki_fingerpint_sha256 = FROM_HEX("0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3")
```

* `tbs_fingerprint_sha256`
* `tbs_no_ct_fingerprint_sha256`
* `precert`

The TBS fingerprint is the fingerprint of the to-be-signed portion of the
DER-encoded bytes of the certificate, which is effectively all of the
certificate _except_ for the signature. The TBS fingerprint includes the issuer,
so it is not effective for finding cross-signatures.

The "TBS No CT Fingerprint" (`tbs_no_ct_fingerprint_sha256`) is the fingerprint
of the DER-encoded bytes of the TBS certificate with the SCT poison extension
removed. This field will match between a certificate and any of its associated
precertificates.

All known precertificates are available in BigQuery in the `certificates_all`
table. The `certificates` tables removes precertificates when there is a
corresponding final certificate known to Censys. If no final certificate is
known to Censys (e.g, because it is not logged and not served publicly), the
corresponding precertificate is included in the `certificates` table. The
`precert` field is a boolean and indicates when an entry is a precertificate.

\TODO: How are precertificates collapsed in the web interface

```bigquery
-- Breakdown of certificate vs precertificate in the deduplicated dataset for
-- unexpired certificates currently trusted by Chrome
SELECT COUNT(*), precert
FROM `censys-io.certificates_v2.certificates`
WHERE
  validation.chrome.is_trusted = TRUE
  AND not_valid_after > CURRENT_TIMESTAMP()
```

```bigquery
-- Among all trusted precerts, how many transparency logs do they appear in?
SELECT
    COUNT(*), ARRAY_LEN(ct.entries) AS num_logs
FROM `censys-io.certificates_v2.certificates_all` 
WHERE
    precert = TRUE
    AND validation.chrome.is_trusted = TRUE
    -- Optimization to partition query
    AND not_valid_after > CURRENT_TIMESTAMP()
GROUP BY 2
```

### Names

The top-level `names` field is the union of all the names a certificate is valid for. This includes:
* `parsed.extensions.subject_alt_name.dns_names`
* `parsed.extensions.subject_alt_name.ip_addresses`
* Any DNS names in the common name (CN) within the `subject_dn`.

\TODO confirm this

In trusted Web PKI certificates, this field will most commonly be identical to
the DNS names in the Subject Alternative Name on leaf certificates, and empty on
root and intermediate certificates.

```censys
censys.io AND validation.chrome.is_valid = TRUE
```
```bigquery
-- All unexpired certificates for any subdomain of censys.io
SELECT names, fingerprint_sha256, not_valid_after
FROM `censys-io.certificates_v2.certificates` 
WHERE EXISTS(SELECT * FROM UNNEST(names) AS n WHERE NET.REG_DOMAIN(n) = "censys.io")
    AND validation.chrome.is_valid = TRUE
    -- Optimization to partition query
    AND not_valid_after > CURRENT_TIMESTAMP() 
ORDER BY not_valid_after ASC
```

### Parsed

The `parsed` structure is a representation of the ASN.1 schema of an X.509
certificate in structured form. Each field corresponds to a field defined in
[RFC 5280][rfc-5280] or the [baseline requirements][brs] (BRs). The full list of
fields in the `parsed` object is available in the
[reference][censys-cert-reference].

* `parsed.issuer`
* `parsed.subject`
* `parsed.issuer_dn`
* `parsed.subject_dn`

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

* `parsed.validity_period.not_before`
* `parsed.validity_period.not_after`
* `parsed.validity_period.length_seconds`
* `not_valid_after`

The `parsed.validity_period` structure fields corresponding to the
Not Before and Not After timestamp included in the certificate. To simplify
length calculations, it also includes the `length_seconds` field for the
non-inclusive second count calculated by subtracting the Not Before from the Not
After (i.e. `[not_before, not_after)`). Historically, there is confusion within
the BRs and RFC about whether or not this time range should be inclusive or
non-inclusive. To determine the fully inclusive certificate lifetime, add 1 to
`length_seconds`.

\TODO: example query

The top-level `not_valid_after` field is only availble in BigQuery and is
identical to `parsed.validity_period.not_after`. Storing it at the top level
allows the table to be partioned on this field, which means that when it is used
in a `WHERE` clause, BigQuery can drastically reduce the amount of data scanned
to answer the query. Since many queries are over the set of unexpired
certificates, querying against `not_valid_after` instead of
`parsed.validity_period.not_after` is an easy cost and time optimization in BigQuery.

\TODO: example query

* `parsed.subject_key_info`

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

* `parsed.signature`

The `signature` contains the signature algorithm in use, the DER-encoded value
of the signature, and boolean to indicate if it's self-signed.  

\BUG: See feedback

* `extensions`
* `unknown_extensions`

\TODO: see my feedback on this

* `redacted`

This field is true if the names in the certificate are using Domain Label
Redaction. This was never standardized, and ultimately drpped from RFC 9192.

* `version`
* `serial_number`

The `version` is the integer X.509 version encoded in the certificate. The
`serial_number` is an unsigned decimal string. 

```censys
parsed.serial_number: 12345
```
```bigquery
SELECT fingerprint_sha256
FROM `censys-io.certificates_v2.certificates`
WHERE parsed.serial_number = CAST(12345 AS STRING)
```

### Validation and Revocation

The `validation` structure contains the result of certificate validation and
path building for multiple different root stores. Each root store has the same
set of fields. The trust information is exposed as `validation.$ROOT_STORE.*`
(e.g. `validation.chrome.*`). The root stores are:

* `nss`: The root store managed by Mozilla and used in Firefox and many Linux distributions.
* `microsoft`: The root store used on Windows
* `apple`:  The root store used on MacOS and iOS.
* `google_ct_primary`: The union of all of the root stores used by the Google-operated [certificate transparency logs][ct-logs].
* `chrome`: The [Chrome Root Store][crs], used by the Google Chrome web browser

Censys identifies the set of all candidate intermediate certificates across its
entire dataset, and attempts to build _all_ paths for every certificate through
the set of intermediates, and ending at a root in the root store. It does this
for all root stores it validates against. The validation does not implement name
constraints, or any platform-specific validation rules, such as certificate
transparency policies, that may be included in validator implementations
maintained by operators of various roots stores (e.g. [CCV][ccv]).

* `validation.$ROOT_STORE.type`

This indicates if a certificate is a leaf, intermediate, or root. Roots are
defined by their inclusion in a root store. Leaf certificates are certificates
that do not have `parsed.extensions.basic_constraints.is_ca` set to `true`.
Intermediates have `is_ca` set, but are not roots.

* `validation.$ROOT_STORE.is_valid`
* `validation.$ROOT_STORE.ever_valid`
* `validation.$ROOT_STORE.has_trusted_path`
* `validation.$ROOT_STORE.had_trusted_path`
* `validation.$ROOT_STORE.in_revocation_set`

There are three main validity checks implemented by the Censys verifier: path
building, expiration, and revocation. The `is_valid` field indicates if the
certificate currently passes all validation checks, meaning it is not expired or
revoked, and has a valid path through unexpired certificates to a trusted root
included in the root store. The `ever_valid` field indicates if this was true at
the time of the certificates expiration, ignoring revocation---did there exist
some time period in which the certificate was unexpired and chained to a root?

\TODO: Is revocation on certificates in the path checked during path building, or just on the cert?

The `had_trusted_path` and `has_trusted_path` indicate if the certificate
currently or at the time of its expiration, could build a path to a trusted
root, regardless of revocation status. In practice, `ever_valid` and
`had_trusted_path` are always identical.

* `validation.$ROOT_STORE.chains`

Chains is a list of trusted paths to the root store. The paths are valid at the
time specified in `validated_at` for unexpired certificates, and at 1 second
before `validity_period.not_after` for expired certificates. Each path is an
array of hex SHA256 fingerprints of the certificates. The zeroth element in the path is the leaf

\TODO: What is `validated_at` set to in practice in the dataset? Is it always timeof data pipeline, or is it set to 1 second before validity period on expired certs

Most revocation information is root store independent, and exposed under the
top-level `revocation` field. However, root stores may ship some variant on a
"certificate revocation set" as part of their validation library or user agent,
such as the Chrome [CRLSet][crlset] or Firefox [OneCRL][onecrl]. The
`in_revocation_set` boolean indicates if a certificate is explicitly revoked as
part of the revocation set associated with a root store. Censys checks the
revocation sets for the following root stores and exposes it as the
`in_revocation_set` boolean for each root store under the `validation` object:
* NSS ([OneCRL][onecrl])
* Microsoft (\TK) ????
* Apple (\TK) ?????
* Chrome ([CRLSet][crlset])

\TODO: Verify which revocation sets are checked and link them

* `validation_level`

The top-level `validation_level` field contains the identity validation type
performed by the certification authority when the certificate was issued: Domain
Validation (DV), Organization Validation (OV), or Extended Validation (EV). It
does not indicate anything about the root store trust validation.

* `revocation`

CA-provided revocation information is stored in the top-level `revocation`
structure. There are two forms of revocation information available:
certificate-revocation lists (CRLs), and the online certificate status protocol
(OCSP). Both CRLs and OCSP are operated by the issuing certification authority
and serve the same information. However, some CAs only provide OCSP. The
CA/Browser Forum (CABF) is in the process of requiring all CAs to provide CRLs,
while simultaneously making OCSP optional. Once CRLs are required, Censys will
stop checking OCSP.

\TODO: see feedback

* `revocation.crl`
* `revocation.ocsp`
* `revoked`

The structure of the `crl` and `ocsp` fields are identical, and indicate if a
certificate was revoked, and if so, what the reason was for the revocation. The
top-level `revoked` field that indicates if a certificate is revoked. It is true
if either `revocation.crl.revoked` or `revocation.ocsp.revoked` are true.

\TODO: example query

## Certificate Transparency and Precerts

The `ct` object contains which [certificate transparency][ct-logs] (CT) logs have
entries for a certificate. `ct.entries` is a repeated set of key/value pairs
where the `key` is the log name, and the `value` is the index and timestamp in
the log.

\TODO example queries

* `precert`
* `tbs_no_ct_fingerprint_sha256`

A precert is a special type of certificate that can be logged to CT before
issuing the final "real" certificate. Precertificates are identified by the
inclusion of a special CT "poison" extension (`parsed.extensions.ct_poison`).
The top-level `precert` variable is true if `parsed.extensions.ct_poison` is
true. Both precertificates and certificates can be logged to CT logs, and each
will have separate entries in the logs. Not all final certificates are logged.

The certificates dataset deduplicates final certificates and their corresponding
precertificates when both are present, by excluding the precertificates from the
dataset. If a precertificate is present as a row in the certificates dataset, it
means that Censys has not seen the corresponding final certificate. This may be
because the certificate was not issued, or more likely, because the final
certificate was not logged and Censys has not yet observed it in use on a host.

The `ct.entries` are not unified between the precertificate and the certificate.
They reflect the actual log entries corresponding to the precertificate or the
final certificate, not both.

Final certificates may contain the _signed certificate timestamp_ (SCT)
extension, which indicate that a precertificate was logged to a specific set of
logs. SCTs are exposed in the `parsed.extensions.signed_certificate_timestamp`
field. The `log_id` of an SCT is the raw bytes of the ID in the SCT, and
corresponds with values from the [CT log list][ctlogs], not the human-friendly
log name used as the `key` in each entry from `ct.entries`.

\TODO: example query using both tables?
\TODO: example query about embedded SCTs
\TODO: example query constrasting log entries to embedded SCTs

## ZLint

Censys lints all certificates with [ZLint][zlint], which checks for consistency
with standards such as [RFC 5280][rfc-5280] and other relevant PKI requirements
such as the [Baseline Requirements][brs].

* `zlint.version`
* `zlint.timestamp`
* `zlint.notices_present`
* `zlint.warnings_present`
* `zlint.errors_present`
* `zlint.fatals_present`
* `zlint.failed_lints`

ZLint is composed of a series of "lints", each of which runs against every
certificate, and emits either _OK_, N/A, a _Notice_, a _Warning_, an _Error_, or
_Fatal_.  The top-level `zlint` object contains all the metadata on and output
from ZLint. Censys executes the default set of lints for ZLint, which is static
across versions. To determine the full set of lints execute, check the ZLint
documentation for the version indicated in `zlint.version`. Censys records the
name of each lint that outputs a notice, warning, or error result in the
`zlint.failed_lints` field. Censys does not record lints that output N/A or OK.

\TODO: verify if this is all certificates, or just trusted certificates

## Metadata

* `labels`

This contains the same set of tags as the online interface.

\TODO: enumerate common tags

* `added_at`
* `modified_at`
* `inserted_at`

\TODO: what is the difference between added_at and inserted_at?

* `validated_at`
* `not_valid_after`

\TODO: repeate information from earlier, verify `validated_at` semantics

* `parse_status`

\TODO: mention this in the parsed section, repeat information here

## BigQuery Tables

BigQuery is case-insensitive

`certificates`: \TODO 

`certificates_all`: \TODO

## Examples

[rfc-5280]: https://www.rfc-editor.org/rfc/rfc5280
[brs]: https://cabforum.org/baseline-requirements-documents/
[ct-logs]: https://certificate.transparency.dev/logs/
[crs]: https://source.chromium.org/chromium/chromium/src/+/main:net/data/ssl/chrome_root_store/
[ccv]: https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md#what-is-the-chrome-certificate-verifier
[onecrl]: https://wiki.mozilla.org/CA/Revocation_Checking_in_Firefox
[crlset]: https://www.chromium.org/Home/chromium-security/crlsets/
[zlint]: https://github.com/zmap/zlint