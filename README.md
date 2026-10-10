# cgep-app-starter - OLD README - SEE BELOW FOR ADDITION FOR THIS CAPSTONE

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## What you build on top

Fork the repo into your own `cgep-capstone` and add:

1. **Layer 1 — GRC baseline (Terraform).** KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.
2. **Layer 2 — OPA policy suite (Rego).** Five or more policies that catch the named gaps in [GAPS.md](GAPS.md). Each policy maps to at least one control from the framework you choose.
3. **Layer 3 — GitHub Actions pipeline.** Plan → Conftest gate → apply → Cosign sign → upload to vault.
4. **Layer 4 — OSCAL component.** A `component-definition.json` describing how your governed system implements its controls.

Full brief: `docs/labs/07_01_capstone_brief.md` in the course content repo.

## Framework mapping is required

Your capstone must declare a primary framework: **HIPAA Security Rule**, **SOC 2 Trust Services Criteria**, or **CMMC Level 2**. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's `control-implementations` reference your framework's catalog.

A starter mapping is in [FRAMEWORKS.md](FRAMEWORKS.md). It is not the only valid mapping. You're expected to defend yours.

## Cost

Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

## Layout

```
cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
    └── intake.sh
```

## License

MIT. Fork freely. Submissions remain learners' own work.

---

# CGE-P Capstone Implementation

This repository extends the original `cgep-app-starter` with a security and compliance engineering baseline for the Acme Health Patient Intake API.

The primary framework selected for this implementation is the **HIPAA Security Rule**.

## What was added for this capstone by Tee Wei

## Grader verification 

This repository implements the CGE-P capstone using the **HIPAA Security Rule**. See [`WRITEUP.md`](WRITEUP.md) for implementation details and design decisions.

Generate the Terraform plan

From the repository root:

```bash
cd terraform
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
cd ..
```

From the repository root, run the Rego unit tests:

```bash
opa test ./policy
```

To evaluate a Terraform plan against the security policies using Conftest, first generate a plan in JSON format using the repository's Terraform configuration, then run:

```bash
conftest test terraform/plan.json --policy policy/ --all-namespaces
```

* **Policy enforcement:** The [`policy/`](policy/) directory contains seven Rego policies covering GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-07, and GAP-08. OPA tests validate policy behavior, while Conftest evaluates the Terraform plan against these policies.

* **CI demonstration:** Review the [GitHub Actions history](https://github.com/teewei2000/cgep-capstone/actions) for successful pipeline runs and the intentionally failing GAP-04 regression test. This demonstrates that the policy gate blocks a Terraform plan when S3 bucket versioning is disabled.

* **OSCAL:** Review [`oscal/components/component-acme.json`](oscal/components/component-acme.json) and [`oscal/profiles/cge-p-minimum.json`](oscal/profiles/cge-p-minimum.json) for the machine-readable component and control profile. Validation was performed using OSCAL Trestle.

* **Evidence integrity:** The evidence bundle for run `37212597897` is stored in `s3://cgep-capstone-evidence-497f6467/capstone/runs/37212597897/`, alongside its SHA-256 digest and Cosign signature bundle. (Note: The S3 evidence vault retains bundles from multiple CI runs, with each run's evidence stored under a separate run-specific prefix.)

* **Documentation:** [`GAPS.md`](GAPS.md) documents the security gaps, [`FRAMEWORKS.md`](FRAMEWORKS.md) describes the framework mappings, and [`WRITEUP.md`](WRITEUP.md) explains the implementation and design trade-offs.


### Layer 1 — Terraform GRC baseline

The Terraform configuration adds:

* Customer-managed AWS KMS key with key rotation
* CMK encryption for the starter S3 uploads bucket
* CMK encryption for the starter DynamoDB table
* S3 TLS enforcement
* S3 versioning
* Lambda deployment into the starter VPC/private subnets
* Lambda IAM least-privilege hardening
* API Gateway access logging
* Dedicated S3 evidence vault with versioning, SSE-KMS and Object Lock
* Dedicated multi-region CloudTrail with log-file validation

The original starter workload resources remain in place and are hardened rather than replaced.

## Layer 2 — Policy as code

Seven Rego policies enforce the documented gaps in `GAPS.md`:

```text
policy/
├── gap01_s3_cmk_encryption.rego
├── gap02_dynamodb_cmk_encryption.rego
├── gap03_s3_tls.rego
├── gap04_s3_versioning.rego
├── gap05_lambda_vpc.rego
├── gap07_lambda_least_privilege.rego
└── gap08_api_logging.rego
```

Each policy contains framework, control ID, severity, gap ID and remediation metadata and has a corresponding test covering compliant and non-compliant cases.

Run the policy tests locally:

```bash
opa test ./policy
```

Run the policies against a Terraform plan:

```bash
conftest test plan.json --policy policy --all-namespaces
```

The complete policy suite passes with **7/7 tests**.

## Layer 3 — GitHub Actions compliance gate

The workflow is defined in:

```text
.github/workflows/capstone.yml
```

The workflow supports pull-request verification and, when the push trigger for main is enabled, execution after changes are pushed to main.

It performs:

```text
Terraform format / validate / plan
        ↓
OPA unit tests
        ↓
Conftest policy gate
        ↓
Evidence bundle generation
        ↓
Cosign keyless signing
        ↓
S3 evidence vault upload
```

To satisfy the capstone requirement “Apply on merge to main,” the workflow is configured to trigger on pushes to main, including pull-request merges. Terraform Apply runs after the policy gate succeeds, applying the approved infrastructure changes. Because the workflow also runs on direct pushes to main, those pushes can trigger deployment as well.

The repository history contains both:

* a successful compliant pull request that was merged
* a final test green pull request that was passed and left unmerged
* a red pull request that was blocked by the policy gate and left unmerged

The red pull request deliberately removed S3 versioning and was blocked by the GAP-04 policy.

## Layer 4 — OSCAL

The OSCAL implementation is located under:

```text
oscal/
├── components/
│   └── component-acme.json
└── profiles/
    └── cge-p-minimum.json
```

The component-definition (component-acme.json) describes seven implemented requirements corresponding to GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-07 and GAP-08.

The OSCAL implementation uses the official **NIST SP 800-53 Rev. 5 OSCAL catalog** as the machine-readable control vocabulary while retaining the corresponding HIPAA Security Rule IDs in the implementation properties and descriptions.

The selected OSCAL controls are:

```text
SC-28  Protection of Information at Rest
SC-8   Transmission and Confidentiality
SC-7   Boundary Protection
CP-9   System Backup
AC-6   Least Privilege
AU-2   Event Logging
```

Implementation statements reference actual Terraform resources and signed evidence objects.

The profile and component-definition have been validated with **OSCAL Trestle**.

## Evidence vault

The CI pipeline produces three evidence objects:

```text
evidence-<run>.tar.gz
evidence-<run>.tar.gz.sha256
evidence-<run>.tar.gz.sig.bundle
```

Example from GitHub Actions run 37212597897, referenced in the OSCAL evidence:
```text
capstone/runs/37212597897/evidence-37212597897-9eb7b54a0c07636ade0fd1a63baa77b0da672d79.tar.gz
capstone/runs/37212597897/evidence-37212597897-9eb7b54a0c07636ade0fd1a63baa77b0da672d79.tar.gz.sha256
capstone/runs/37212597897/evidence-37212597897-9eb7b54a0c07636ade0fd1a63baa77b0da672d79.tar.gz.sig.bundle
```

The evidence vault uses:

* S3 versioning
* SSE-KMS encryption
* S3 Object Lock in GOVERNANCE mode

The evidence bundle was independently verified by:

1. Recomputing the SHA-256 digest and matching the stored digest.
2. Verifying the Cosign signature using the GitHub Actions OIDC identity.
3. Confirming Object Lock retention on the evidence bundle, digest and signature bundle.

Cosign verification returned:

```text
Verified OK
```

## Framework and scope decisions

The **HIPAA Security Rule** was selected because the Acme Health scenario is a telehealth application processing PHI and the starter `GAPS.md` already provides HIPAA mappings for the relevant weaknesses.

GAP-06 was deliberately left outside the implemented control set because its reserved concurrency, dead-letter queue and X-Ray recommendations do not have a direct HIPAA Security Rule mapping in the starter assessment.

CloudTrail was implemented separately as a capstone baseline requirement.

The implementation is intended as a reproducible compliance-engineering baseline and does not claim that the complete Acme Health environment is fully HIPAA compliant.

## Repository additions

```text
cgep-capstone/
├── .github/
│   └── workflows/
│       └── capstone.yml
├── policy/
├── oscal/
├── terraform/
├── test/
├── FRAMEWORKS.md
├── GAPS.md
├── README.md
└── WRITEUP.md
```
