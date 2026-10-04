Acme Health's Patient Intake API processes PHI but inherited several technical control weaknesses. I selected the HIPAA Security Rule as the primary framework and implemented a code-based compliance baseline covering encryption, access control, transmission security, contingency protection and audit controls. 

Terraform establishes the baseline, OPA prevents regression, GitHub Actions enforces the controls during change, and OSCAL provides traceability between requirements, implementation and evidence.

| Gap    | Issue                                  | HIPAA mapping                      | Priority |
| ------ | -------------------------------------- | ---------------------------------- | -------- |
| GAP-01 | S3 uses SSE-S3 instead of customer CMK | `164.312(a)(2)(iv)`                | 🔴       |
| GAP-02 | DynamoDB uses AWS-owned encryption key | `164.312(a)(2)(iv)`                | 🔴       |
| GAP-03 | S3 doesn't deny non-TLS requests       | `164.312(e)(1)`                    | 🔴       |
| GAP-04 | S3 has no versioning                   | `164.308(a)(7)`                    | 🔴       |
| GAP-05 | Lambda isn't in VPC                    | `164.312(e)(1)`                    | 🟠       |
| GAP-06 | No reserved concurrency/DLQ/X-Ray      | No direct HIPAA mapping in starter | 🟡       |
| GAP-07 | Lambda IAM has `dynamodb:*` / `s3:*`   | `164.312(a)(1)`                    | 🔴       |
| GAP-08 | API Gateway lacks access logging       | `164.312(b)`                       | 🔴       |

| HIPAA control       | Gap(s)     | Terraform               | Rego                | Evidence       | OSCAL          |
| ------------------- | ---------- | ----------------------- | ------------------- | -------------- | -------------- |
| `164.312(a)(2)(iv)` | GAP-01, 02 | KMS + S3/DDB CMK        | encryption policies | Terraform plan | implementation |
| `164.312(e)(1)`     | GAP-03, 05 | TLS policy + Lambda VPC | TLS/VPC policies    | Terraform plan | implementation |
| `164.308(a)(7)`     | GAP-04     | S3 versioning           | versioning policy   | bucket config  | implementation |
| `164.312(a)(1)`     | GAP-07     | IAM least privilege     | IAM policy          | IAM/plan       | implementation |
| `164.312(b)`        | GAP-08     | API logging             | API logging policy  | API GW config  | implementation |

