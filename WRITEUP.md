Acme Health's Patient Intake API processes PHI but inherited several technical control weaknesses. I selected the HIPAA Security Rule as the primary framework and implemented a code-based compliance baseline covering encryption, access control, transmission security, contingency protection and audit controls.

Terraform establishes the security baseline, OPA prevents regression, GitHub Actions enforces the controls during change, and OSCAL provides traceability between requirements, implementation and evidence.

## Gap remediation

| Gap    | Issue                                  | HIPAA mapping                      | Priority |
| ------ | -------------------------------------- | ---------------------------------- | -------- |
| GAP-01 | S3 uses SSE-S3 instead of customer CMK | `164.312(a)(2)(iv)`                | 🔴       |
| GAP-02 | DynamoDB uses AWS-owned encryption key | `164.312(a)(2)(iv)`                | 🔴       |
| GAP-03 | S3 does not deny non-TLS requests      | `164.312(e)(1)`                    | 🔴       |
| GAP-04 | S3 has no versioning                   | `164.308(a)(7)`                    | 🔴       |
| GAP-05 | Lambda is not in a VPC                 | `164.312(e)(1)`                    | 🟠       |
| GAP-06 | No reserved concurrency/DLQ/X-Ray      | No direct HIPAA mapping in starter | 🟡       |
| GAP-07 | Lambda IAM has `dynamodb:*` / `s3:*`   | `164.312(a)(1)`                    | 🔴       |
| GAP-08 | API Gateway lacks access logging       | `164.312(b)`                       | 🔴       |

## Control-to-code traceability (GAP-06 skipped)

| HIPAA control       | Gap    | Terraform                                                                                                 | Rego                                 | Evidence         | OSCAL   |
| ------------------- | ------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------ | ---------------- | ------- |
| `164.312(a)(2)(iv)` | GAP-01 | `aws_s3_bucket.uploads`, `aws_s3_bucket_server_side_encryption_configuration.uploads`, `aws_kms_key.acme` | `gap01_s3_cmk_encryption.rego`       | Signed CI bundle | `sc-28` |
| `164.312(a)(2)(iv)` | GAP-02 | `aws_dynamodb_table.intake`, `aws_kms_key.acme`                                                           | `gap02_dynamodb_cmk_encryption.rego` | Signed CI bundle | `sc-28` |
| `164.312(e)(1)`     | GAP-03 | `aws_s3_bucket_policy.uploads_tls`                                                                        | `gap03_s3_tls.rego`                  | Signed CI bundle | `sc-8`  |
| `164.308(a)(7)`     | GAP-04 | `aws_s3_bucket_versioning.uploads`                                                                        | `gap04_s3_versioning.rego`           | Signed CI bundle | `cp-9`  |
| `164.312(e)(1)`     | GAP-05 | `aws_lambda_function.intake`, `aws_security_group.lambda`, `aws_subnet.private`                           | `gap05_lambda_vpc.rego`              | Signed CI bundle | `sc-7`  |
| `164.312(a)(1)`     | GAP-07 | `aws_iam_role_policy_attachment.lambda_vpc_access`, `aws_iam_role_policy.lambda_inline`                   | `gap07_lambda_least_privilege.rego`  | Signed CI bundle | `ac-6`  |
| `164.312(b)`        | GAP-08 | `aws_apigatewayv2_stage.default`, `aws_cloudwatch_log_group.api`                                          | `gap08_api_logging.rego`             | Signed CI bundle | `au-2`  |

The implementation statements in the OSCAL component-definition provide the corresponding control-level traceability and reference the Terraform resources above. Evidence links point to the signed CI evidence bundle stored in the S3 evidence vault.

## Framework and scope decisions

HIPAA was selected as the primary framework because the scenario is a telehealth application processing PHI and the starter GAPS.md already identifies HIPAA Security Rule mappings for the relevant weaknesses.

HIPAA does not provide an official OSCAL catalog in the starter project. The OSCAL implementation therefore uses the official NIST SP 800-53 Rev. 5 OSCAL catalog as the technical control vocabulary, while retaining the HIPAA control IDs in the implementation properties and descriptions. This avoids creating a custom catalog while maintaining traceability to the declared HIPAA requirements.

GAP-06 was not remediated because its reserved concurrency, dead-letter queue and X-Ray recommendations do not have a direct HIPAA Security Rule mapping in the starter assessment. Also due to time constraint, the implementation scope was therefore kept focused on the documented HIPAA gaps rather than introducing additional controls without a declared framework requirement.

CloudTrail was implemented as a separate capstone baseline requirement with a dedicated multi-region trail, log file validation and a dedicated S3 bucket. The CloudTrail bucket uses SSE-S3 rather than the application CMK because the CMK requirement was scoped to the starter application's S3 and DynamoDB data stores and the evidence vault.

## Policy-as-code

Seven Rego policies were implemented, each corresponding to a documented gap:

* `gap01_s3_cmk_encryption.rego`
* `gap02_dynamodb_cmk_encryption.rego`
* `gap03_s3_tls.rego`
* `gap04_s3_versioning.rego`
* `gap05_lambda_vpc.rego`
* `gap07_lambda_least_privilege.rego`
* `gap08_api_logging.rego`

Each policy includes framework, control ID, severity, gap ID and remediation metadata and has a corresponding test fixture covering the expected compliant and non-compliant cases.

The complete Conftest policy suite passes with 7/7 tests.

## CI/CD compliance gate

GitHub Actions executes the compliance workflow on pull requests and pushes to `main`.

The workflow performs:

1. Terraform formatting, validation and plan generation.
2. OPA unit tests.
3. Conftest policy evaluation against the Terraform plan.
4. Terraform apply only after the policy gate succeeds on `main`.
5. Evidence bundle generation.
6. Keyless Cosign signing using GitHub Actions OIDC.
7. Upload of the signed evidence bundle, SHA-256 digest and Cosign bundle to the S3 evidence vault.

The repository history contains both a successful compliant run (merged) and a red pull request (blocked and left open) where the policy gate blocked a deliberate removal of S3 versioning.

## Evidence integrity

The CI pipeline produces three related evidence objects:

* Signed evidence bundle: `.tar.gz`
* SHA-256 digest: `.tar.gz.sha256`
* Cosign signature bundle: `.tar.gz.sig.bundle`

The evidence vault uses S3 versioning, SSE-KMS encryption and Object Lock in GOVERNANCE mode.

The submitted evidence bundle was independently verified by:

* Recomputing the SHA-256 digest and matching it to the stored digest.
* Verifying the Cosign signature using the GitHub Actions OIDC identity.
* Confirming Object Lock retention on the evidence bundle, SHA-256 digest and Cosign signature bundle.

Cosign verification returned Verified OK, and the recomputed SHA-256 digest matched the stored digest. This provides an auditable chain from the CI run to the signed evidence stored in the evidence vault.

## OSCAL validation

The OSCAL profile selects the NIST SP 800-53 Rev. 5 controls implemented by the component:

SC-28 — Protection of Information at Rest
SC-8 — Transmission and Confidentiality
SC-7 — Boundary Protection
CP-9 — System Backup
AC-6 — Least Privilege
AU-2 — Event Logging

The component-definition contains seven implementation statements corresponding to GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-07 and GAP-08. Each statement references actual Terraform resources and a signed evidence object.

The OSCAL profile and component-definition were validated using OSCAL Trestle.

## Remaining limitations

The implementation focuses on the documented starter gaps and the capstone baseline rather than attempting to implement every possible AWS or HIPAA security enhancement.

In particular, GAP-06 remains open because its recommendations were not directly mapped to a HIPAA Security Rule requirement in the starter assessment. WAF, API throttling and other additional hardening measures were also not treated as separate HIPAA controls where they were not part of the documented gap mapping.

The result is intended as a reproducible compliance-engineering baseline rather than a claim that the complete Acme Health environment is fully HIPAA compliant.
