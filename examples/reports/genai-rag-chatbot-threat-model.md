# Threat Model: Employee GenAI Assistant

| | |
|---|---|
| **Generated** | 2026-11-06 |
| **Owner** | Digital Workplace team |
| **Stage** | design |
| **Criticality** | Medium |
| **Users** | employees, admins |
| **Regulatory scope** | GLBA |

Internal chatbot that answers employee questions using company policy and procedure documents. Runs on a shared EKS cluster and calls Amazon Bedrock through a VPC endpoint.

## Executive summary

**Overall residual risk: 🟠 High** (highest-rated threat that is not fully mitigated)

**Inherited platform controls (AWS Landing Zone, Shared EKS Platform, Enterprise GenAI Gateway):** 10 threats fully mitigated by the platform and 3 more reduced. Overall residual risk would still be 🟠 High without them, but they take **5 High/Critical threats** off the go-live list. See *Inherited platform controls*.

| Rating | Open without platform controls | Open / partially mitigated | Mitigated |
|---|---|---|---|
| 🔴 Critical | 0 | 0 | 0 |
| 🟠 High | 10 | 5 | 0 |
| 🟡 Medium | 17 | 11 | 1 |
| 🟢 Low | 0 | 1 | 14 |

**Top risks to address:**

1. **Sensitive information disclosure through the model** on *Amazon Bedrock (Claude)* (🟠 High, open). Add: `pii_filter`, `dlp`
1. **Retrieval returns data the user isn't allowed to see** on *Bedrock Knowledge Base* (🟠 High, open). Add: `permission_aware_retrieval`
1. **Unknown sensitive data in storage** on *Policy documents (S3)* (🟠 High, open). Add: `data_classification_scanning`
1. **Unknown sensitive data in storage** on *Bedrock Knowledge Base* (🟠 High, open). Add: `data_classification_scanning`
1. **Over-privileged workload identity** on *Chatbot API* (🟠 High, open). Add: `least_privilege_iam`

⚠️ The intake left **1 open question** (see *Questions for the app team*). Answering them may add or change findings.

## Scope

| Component | Type | Zone | Platform | Internet-facing | Data | App team controls | Inherited controls |
|---|---|---|---|---|---|---|---|
| **Employee** (`employee`) | user | corp | — | No | — | — | — |
| **Internal load balancer** (`alb`) | load_balancer | app-vpc | — | No | — | sso, mfa, tls | segmentation |
| **Chatbot API** (`chatbot-api`) | container_workload | app-vpc | eks | No | internal, confidential | workload_identity | admission_control, image_scanning, image_signing, imds_v2, network_policy, non_root, runtime_detection, segmentation, vuln_scanning, workload_identity |
| **Amazon Bedrock (Claude)** (`bedrock`) | llm | aws-managed | genai-gateway | No | — | private_endpoint | guardrails, invocation_logging, model_allowlist, prompt_injection_filter, segmentation, token_quota |
| **Bedrock Knowledge Base** (`knowledge-base`) | vector_store | aws-managed | — | No | internal, confidential | private_endpoint | encryption_cmk, segmentation |
| **Policy documents (S3)** (`docs-bucket`) | object_storage | aws-managed | — | No | internal, confidential | — | encryption_cmk, public_access_block, segmentation |
| **Invocation logs (CloudWatch → SIEM)** (`logs`) | logging | aws-managed | — | No | confidential | — | segmentation |
| **GitHub Actions pipeline** (`pipeline`) | ci_cd | corp | none | No | — | branch_protection, deploy_approvals, secrets_scanning | — |

**Application-wide controls** (apply to every component): `sso`, `audit_logging`, `logging_siem`

## Inherited platform controls

Controls the app team gets from the cloud platforms it builds on. **Preventive** controls are guardrails that block non-compliant deployments; **detective** controls catch drift after the fact, so they reduce a threat but never fully mitigate it on their own. The platform team owns these controls and their evidence.

### AWS Landing Zone (`aws-lz`)

Applies to: whole application · Owner: Cloud Platform Engineering

Multi-account AWS organization (Control Tower) with SCPs, org-wide security services, and a log archive account.

| Control | Covers | Enforcement | Mechanism | Evidence |
|---|---|---|---|---|
| `segmentation` | all components | Preventive | Account per application and environment; prod and non-prod in separate OUs | AWS Organizations OU structure; account vending pipeline |
| `public_access_block` | object_storage | Preventive | Account-level S3 Block Public Access; SCP denies s3:PutAccountPublicAccessBlock | SCP p-deny-s3-public; Wiz control 'S3 public access' |
| `encryption_cmk` | object_storage, database, queue, vector_store | Detective | AWS Config conformance pack flags resources without a customer-managed KMS key; auto-ticketed | Config conformance pack 'data-protection'; Wiz CSPM |
| `imds_v2` | vm, container_workload | Preventive | SCP requires ec2:MetadataHttpTokens=required on RunInstances; hop limit 1 in golden AMI launch templates | SCP p-require-imdsv2 |
| `runtime_detection` | vm, container_workload, serverless_function | Preventive | GuardDuty (incl. Runtime Monitoring) enabled org-wide by delegated admin; SCP denies disabling it | GuardDuty delegated admin console; SCP p-protect-security-services |
| `vuln_scanning` | vm, container_workload, serverless_function | Detective | Amazon Inspector and Wiz agentless scanning across all accounts | Wiz vulnerability dashboard |
| `model_allowlist` | llm, ai_agent | Preventive | SCP restricts bedrock:InvokeModel to AI-governance-approved model ARNs | SCP p-bedrock-approved-models; AI governance model register |
| `audit_logging` | app | Preventive | Organization CloudTrail (management + data events) to the log archive account. Covers the cloud control plane, not application logs. | Org trail config; SCP p-protect-cloudtrail |
| `log_immutability` | app | Preventive | Log archive bucket with S3 Object Lock (compliance mode) in a separate account | Log archive account bucket policy |
| `privileged_access_management` | app | Preventive | Human prod access only through IAM Identity Center permission sets with JIT approval; IAM users denied by SCP | SCP p-deny-iam-users; JIT approval logs |
| `mfa` | app | Preventive | IAM Identity Center requires MFA for all console and CLI sessions (workforce users, not app end users) | Identity Center MFA settings |

### Shared EKS Platform (`eks`)

Applies to: Chatbot API · Owner: Container Platform team · Builds on: `aws-lz`

Multi-tenant EKS clusters with Kyverno, Istio, and default-deny networking. Builds on the AWS Landing Zone.

| Control | Covers | Enforcement | Mechanism | Evidence |
|---|---|---|---|---|
| `admission_control` | container_workload | Preventive | Kyverno policies in Enforce mode (Pod Security 'restricted' profile plus org policies) | Kyverno policy reports; cluster-policies repo |
| `non_root` | container_workload | Preventive | Kyverno rejects privileged pods and runAsNonRoot=false | Kyverno policy require-run-as-nonroot |
| `image_scanning` | container_workload | Preventive | Admission webhook blocks images with critical CVEs or no scan result | Kyverno policy block-critical-cves; Wiz image scanning |
| `image_signing` | container_workload | Preventive | Kyverno verifyImages requires a Cosign signature from the platform pipeline | Kyverno policy verify-image-signature |
| `network_policy` | container_workload | Preventive | Namespaces are created with default-deny ingress and egress NetworkPolicies | Namespace vending templates |
| `workload_identity` | container_workload | Detective | EKS Pod Identity is the standard; Wiz flags static AWS keys found in pods or images | Wiz secrets-in-workloads findings |
| `mtls` | flow | Preventive | Istio STRICT mTLS PeerAuthentication mesh-wide | Istio mesh config |
| `tls` | flow | Preventive | Istio STRICT mTLS (TLS 1.2+) between all in-mesh workloads | Istio mesh config |

### Enterprise GenAI Gateway (`genai-gateway`)

Applies to: Amazon Bedrock (Claude) · Owner: AI Platform team · Builds on: `aws-lz`

Central gateway that all LLM calls go through. Applies guardrails, quotas, and logging. Builds on the AWS Landing Zone.

| Control | Covers | Enforcement | Mechanism | Evidence |
|---|---|---|---|---|
| `guardrails` | llm | Preventive | Gateway attaches the enterprise Bedrock Guardrail to every request; direct model access denied by SCP | Gateway config; SCP p-bedrock-gateway-only |
| `prompt_injection_filter` | llm | Preventive | Bedrock Guardrails prompt attack filter set to HIGH at the gateway | Enterprise guardrail definition |
| `token_quota` | llm | Preventive | Per-app token budgets enforced by the gateway | Gateway quota config |
| `invocation_logging` | llm | Preventive | Gateway logs request metadata and content to the SIEM | SIEM index genai-gateway |
| `model_allowlist` | llm | Preventive | Gateway only routes to models in the AI governance register | Gateway model routing table |

## Data flow diagram

Boxes are trust zones. Dotted arrows are unencrypted flows.

```mermaid
flowchart LR
    subgraph n_zone_corp["Corporate network"]
        n_employee(["Employee"])
        n_pipeline["GitHub Actions pipeline"]
    end
    subgraph n_zone_app_vpc["Application VPC (EKS)"]
        n_alb["Internal load balancer"]
        n_chatbot_api["Chatbot API"]
    end
    subgraph n_zone_aws_managed["AWS managed services"]
        n_bedrock{{"Amazon Bedrock (Claude)"}}
        n_knowledge_base[("Bedrock Knowledge Base")]
        n_docs_bucket[("Policy documents (S3)")]
        n_logs[("Invocation logs (CloudWatch → SIEM)")]
    end
    n_employee -->|"F1: HTTPS · internal"| n_alb
    n_alb -->|"F2: HTTPS · internal"| n_chatbot_api
    n_chatbot_api -->|"F3: HTTPS (VPC endpoint) · internal, confidential"| n_bedrock
    n_bedrock -->|"F4: Retrieval · confidential"| n_knowledge_base
    n_docs_bucket -->|"F5: Ingestion sync · confidential"| n_knowledge_base
    n_bedrock -->|"F6: Invocation logging · confidential"| n_logs
    n_pipeline -->|"F7: Deploy"| n_chatbot_api
```

### Trust boundary crossings

Threats concentrate where data crosses between zones.

| Flow | From → To | Zones | Protocol | Data | Encrypted | Authenticated |
|---|---|---|---|---|---|---|
| F1 | Employee → Internal load balancer | corp → app-vpc | HTTPS | internal | Yes | Yes |
| F3 | Chatbot API → Amazon Bedrock (Claude) | app-vpc → aws-managed | HTTPS (VPC endpoint) | internal, confidential | Yes | Yes |
| F7 | GitHub Actions pipeline → Chatbot API | corp → app-vpc | Deploy | — | Yes | Yes |

## Threat register

Sorted by risk score (likelihood × impact, 1–25). ⬇ platform = inherited platform controls changed the status.

| ID | Risk | Threat | Target | STRIDE | L | I | Score | Status | Missing controls |
|---|---|---|---|---|---|---|---|---|---|
| T-001 | 🟠 High | Sensitive information disclosure through the model | Amazon Bedrock (Claude) | I | 3 | 4 | **12** | Open | pii_filter, dlp |
| T-002 | 🟠 High | Retrieval returns data the user isn't allowed to see | Bedrock Knowledge Base | I | 3 | 4 | **12** | Open | permission_aware_retrieval |
| T-003 | 🟠 High | Unknown sensitive data in storage | Policy documents (S3) | I | 3 | 4 | **12** | Open | data_classification_scanning |
| T-004 | 🟠 High | Unknown sensitive data in storage | Bedrock Knowledge Base | I | 3 | 4 | **12** | Open | data_classification_scanning |
| T-005 | 🟠 High | Over-privileged workload identity | Chatbot API | E | 3 | 4 | **12** | Open | least_privilege_iam |
| T-006 | 🟡 Medium | Pipeline compromise or unauthorized deployment | GitHub Actions pipeline | TE | 2 | 5 | **10** | Partially mitigated | least_privilege_iam |
| T-007 | 🟡 Medium | Model output trusted by downstream systems | Amazon Bedrock (Claude) | TE | 3 | 3 | **9** | Open | output_validation |
| T-008 | 🟡 Medium | Infrastructure misconfiguration reaches production | GitHub Actions pipeline | TI | 3 | 3 | **9** | Open | iac_scanning |
| T-009 | 🟡 Medium | Vulnerable container images | Chatbot API | TE | 3 | 3 | **9** | Partially mitigated ⬇ platform | patching |
| T-010 | 🟡 Medium | Sensitive data written to logs | Invocation logs (CloudWatch → SIEM) | I | 3 | 3 | **9** | Open | log_redaction, restricted_log_access |
| T-011 | 🟡 Medium | Indirect prompt injection through retrieved content | Amazon Bedrock (Claude) | T | 2 | 4 | **8** | Partially mitigated ⬇ platform | content_write_controls |
| T-012 | 🟡 Medium | Data destruction or ransomware | Policy documents (S3) | TD | 2 | 4 | **8** | Open | backups, object_lock |
| T-013 | 🟡 Medium | Long-lived static credentials in workloads | Chatbot API | SI | 2 | 4 | **8** | Partially mitigated | secrets_manager |
| T-014 | 🟡 Medium | Uncontrolled outbound traffic enables data exfiltration | Chatbot API | I | 2 | 4 | **8** | Open | egress_control |
| T-015 | 🟡 Medium | System prompt leakage | Amazon Bedrock (Claude) | I | 3 | 2 | **6** | Open | no_secrets_in_prompts |
| T-016 | 🟡 Medium | Logs can be altered or disabled | Invocation logs (CloudWatch → SIEM) | R | 2 | 3 | **6** | Open | log_immutability, restricted_log_access |
| T-017 | 🟡 Medium | Direct prompt injection and jailbreaks | Amazon Bedrock (Claude) | TE | 2 | 3 | **6** | Mitigated ⬇ platform | — |
| T-018 | 🟢 Low | Container escape via privileged or root containers | Chatbot API | E | 1 | 5 | **5** | Mitigated ⬇ platform | — |
| T-019 | 🟢 Low | Privileged / admin access without strong controls | Employee GenAI Assistant | SE | 1 | 5 | **5** | Mitigated ⬇ platform | — |
| T-020 | 🟢 Low | Data store reachable from public networks | Amazon Bedrock (Claude) | I | 1 | 5 | **5** | Mitigated | — |
| T-021 | 🟢 Low | Data store reachable from public networks | Policy documents (S3) | I | 1 | 5 | **5** | Mitigated ⬇ platform | — |
| T-022 | 🟢 Low | Data store reachable from public networks | Bedrock Knowledge Base | I | 1 | 5 | **5** | Mitigated | — |
| T-023 | 🟢 Low | Unbounded consumption and cost abuse | Amazon Bedrock (Claude) | D | 2 | 2 | **4** | Partially mitigated ⬇ platform | rate_limiting |
| T-024 | 🟢 Low | Unapproved or compromised models | Amazon Bedrock (Claude) | T | 1 | 4 | **4** | Mitigated ⬇ platform | — |
| T-025 | 🟢 Low | Untrusted or tampered container images | Chatbot API | T | 1 | 4 | **4** | Mitigated ⬇ platform | — |
| T-026 | 🟢 Low | Node credential theft through the instance metadata service | Chatbot API | EI | 1 | 4 | **4** | Mitigated ⬇ platform | — |
| T-027 | 🟢 Low | Weak or missing user authentication | Internal load balancer | S | 1 | 4 | **4** | Mitigated | — |
| T-028 | 🟢 Low | Secrets committed to code or configuration | GitHub Actions pipeline | I | 1 | 4 | **4** | Mitigated | — |
| T-029 | 🟢 Low | AI activity not logged for investigation | Amazon Bedrock (Claude) | R | 1 | 3 | **3** | Mitigated ⬇ platform | — |
| T-030 | 🟢 Low | Malicious activity in running containers goes undetected | Chatbot API | RT | 1 | 3 | **3** | Mitigated ⬇ platform | — |
| T-031 | 🟢 Low | Insufficient audit logging | Employee GenAI Assistant | R | 1 | 3 | **3** | Mitigated | — |
| T-032 | 🟢 Low | Lateral movement between workloads | Chatbot API | E | 1 | 3 | **3** | Mitigated ⬇ platform | — |

## Required before go-live

Critical and High threats that are not fully mitigated. Fix these, or document a risk acceptance with a named owner and an expiry date.

| ID | Threat | Target | Controls to add |
|---|---|---|---|
| T-001 | Sensitive information disclosure through the model | Amazon Bedrock (Claude) | pii_filter, dlp |
| T-002 | Retrieval returns data the user isn't allowed to see | Bedrock Knowledge Base | permission_aware_retrieval |
| T-003 | Unknown sensitive data in storage | Policy documents (S3) | data_classification_scanning |
| T-004 | Unknown sensitive data in storage | Bedrock Knowledge Base | data_classification_scanning |
| T-005 | Over-privileged workload identity | Chatbot API | least_privilege_iam |

## Threat details

### T-001 · Sensitive information disclosure through the model

**🟠 High** · score 12 (L3 × I4) · Open · rule `AI-03`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Information disclosure
- **Threat:** Prompts and responses can contain PII or confidential data, whether typed by users or pulled in from retrieval.
- **Recommended mitigations:**
  - `pii_filter`: PII detection and masking on prompts and responses
  - `dlp`: Data loss prevention on content
- **References:** OWASP LLM02:2025 Sensitive Information Disclosure

### T-002 · Retrieval returns data the user isn't allowed to see

**🟠 High** · score 12 (L3 × I4) · Open · rule `AI-04`

- **Target:** Bedrock Knowledge Base (component)
- **STRIDE:** Information disclosure
- **Threat:** If retrieval uses the application's access instead of the user's, any user can get answers drawn from any document in the knowledge base.
- **Recommended mitigations:**
  - `permission_aware_retrieval`: Retrieval filtered by the requesting user's entitlements
- **References:** OWASP LLM08:2025 Vector and Embedding Weaknesses

### T-003 · Unknown sensitive data in storage

**🟠 High** · score 12 (L3 × I4) · Open · rule `DA-02`

- **Target:** Policy documents (S3) (component)
- **STRIDE:** Information disclosure
- **Threat:** Teams often store more sensitive data than they realize (e.g. PII in documents or exports). Without scanning, it isn't protected or classified correctly.
- **Recommended mitigations:**
  - `data_classification_scanning`: Scanned for sensitive data (Macie, Purview, Sensitive Data Protection)
- **References:** Amazon Macie / Microsoft Purview / GCP Sensitive Data Protection

### T-004 · Unknown sensitive data in storage

**🟠 High** · score 12 (L3 × I4) · Open · rule `DA-02`

- **Target:** Bedrock Knowledge Base (component)
- **STRIDE:** Information disclosure
- **Threat:** Teams often store more sensitive data than they realize (e.g. PII in documents or exports). Without scanning, it isn't protected or classified correctly.
- **Recommended mitigations:**
  - `data_classification_scanning`: Scanned for sensitive data (Macie, Purview, Sensitive Data Protection)
- **References:** Amazon Macie / Microsoft Purview / GCP Sensitive Data Protection

### T-005 · Over-privileged workload identity

**🟠 High** · score 12 (L3 × I4) · Open · rule `ID-04`

- **Target:** Chatbot API (component)
- **STRIDE:** Elevation of privilege
- **Threat:** If the workload's role has broader permissions than it needs, any compromise of the workload becomes a compromise of everything that role can reach.
- **Recommended mitigations:**
  - `least_privilege_iam`: IAM roles scoped to exactly what the component needs
- **References:** MITRE ATT&CK T1078.004 Cloud Accounts

### T-006 · Pipeline compromise or unauthorized deployment

**🟡 Medium** · score 10 (L2 × I5) · Partially mitigated · rule `CI-01`

- **Target:** GitHub Actions pipeline (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** The pipeline can change production. A compromised pipeline, developer account, or workflow can push malicious code or infrastructure changes.
- **Controls in place:** branch_protection (app team), deploy_approvals (app team)
- **Recommended mitigations:**
  - `least_privilege_iam`: IAM roles scoped to exactly what the component needs
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1195 Supply Chain Compromise; OWASP Top 10 CI/CD Security Risks

### T-007 · Model output trusted by downstream systems

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `AI-06`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** If model output is rendered in a browser or passed to code, SQL, or APIs without validation, it can cause XSS, injection, or unintended actions.
- **Recommended mitigations:**
  - `output_validation`: Model output validated or encoded before use
- **References:** OWASP LLM05:2025 Improper Output Handling

### T-008 · Infrastructure misconfiguration reaches production

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `CI-02`

- **Target:** GitHub Actions pipeline (component)
- **STRIDE:** Tampering, Information disclosure
- **Threat:** Without IaC scanning, insecure Terraform (public buckets, open security groups) is deployed and only found later by CSPM, if at all.
- **Recommended mitigations:**
  - `iac_scanning`: IaC scanned in the pipeline (Checkov, Wiz Code, Trivy)
- **References:** Checkov / Wiz Code / Trivy config

### T-009 · Vulnerable container images

**🟡 Medium** · score 9 (L3 × I3) · Partially mitigated · rule `CT-01`

- **Target:** Chatbot API (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** Images built on outdated or bloated base images carry exploitable CVEs into production.
- **Controls in place:** image_scanning (inherited: Shared EKS Platform, preventive)
- **Without platform controls:** 🟠 High (score 12, open)
- **Recommended mitigations:**
  - `patching`: Patching within defined SLAs
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** CIS Kubernetes Benchmark; NIST SP 800-190

### T-010 · Sensitive data written to logs

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `DA-04`

- **Target:** Invocation logs (CloudWatch → SIEM) (component)
- **STRIDE:** Information disclosure
- **Threat:** Logs often capture request bodies, tokens, or AI prompts. They are usually readable by more people than the source data.
- **Recommended mitigations:**
  - `log_redaction`: Sensitive fields redacted before logging
  - `restricted_log_access`: Log access limited to those who need it
- **References:** OWASP Logging Cheat Sheet

### T-011 · Indirect prompt injection through retrieved content

**🟡 Medium** · score 8 (L2 × I4) · Partially mitigated · rule `AI-02`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Tampering
- **Threat:** Instructions hidden in documents, emails, or web pages that the model reads can change its behavior. There is no complete fix; limit who can write content and what the model can do.
- **Controls in place:** prompt_injection_filter (inherited: Enterprise GenAI Gateway, preventive)
- **Without platform controls:** 🟠 High (score 12, open)
- **Recommended mitigations:**
  - `content_write_controls`: Only approved people and processes can add knowledge-base content
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** OWASP LLM01:2025 Prompt Injection

### T-012 · Data destruction or ransomware

**🟡 Medium** · score 8 (L2 × I4) · Open · rule `DA-03`

- **Target:** Policy documents (S3) (component)
- **STRIDE:** Tampering, Denial of service
- **Threat:** An attacker or mistake could delete or encrypt the data. Without protected backups, recovery may be impossible.
- **Recommended mitigations:**
  - `backups`: Backups isolated from production and tested
  - `object_lock`: Write-once / immutable storage for critical data
- **References:** MITRE ATT&CK T1485 Data Destruction

### T-013 · Long-lived static credentials in workloads

**🟡 Medium** · score 8 (L2 × I4) · Partially mitigated · rule `ID-03`

- **Target:** Chatbot API (component)
- **STRIDE:** Spoofing, Information disclosure
- **Threat:** Workloads that use static keys or passwords can have them leaked through code, images, logs, or environment variables, and the keys keep working until someone rotates them.
- **Controls in place:** workload_identity (app team)
- **Recommended mitigations:**
  - `secrets_manager`: Secrets pulled from a secrets manager, not stored in code or config
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1552 Unsecured Credentials

### T-014 · Uncontrolled outbound traffic enables data exfiltration

**🟡 Medium** · score 8 (L2 × I4) · Open · rule `NW-04`

- **Target:** Chatbot API (component)
- **STRIDE:** Information disclosure
- **Threat:** If the workload can reach any destination on the internet, an attacker who compromises it can send sensitive data out or download tools.
- **Recommended mitigations:**
  - `egress_control`: Outbound traffic restricted to an allow-list
- **References:** MITRE ATT&CK T1041 Exfiltration Over C2 Channel

### T-015 · System prompt leakage

**🟡 Medium** · score 6 (L3 × I2) · Open · rule `AI-11`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Information disclosure
- **Threat:** Attackers can often extract the system prompt. Secrets or access rules placed in it will be exposed.
- **Recommended mitigations:**
  - `no_secrets_in_prompts`: No secrets or authorization logic in system prompts
- **References:** OWASP LLM07:2025 System Prompt Leakage

### T-016 · Logs can be altered or disabled

**🟡 Medium** · score 6 (L2 × I3) · Open · rule `LG-02`

- **Target:** Invocation logs (CloudWatch → SIEM) (component)
- **STRIDE:** Repudiation
- **Threat:** An attacker with enough access may delete logs or turn logging off to hide activity.
- **Recommended mitigations:**
  - `log_immutability`: Logs stored write-once in a separate account
  - `restricted_log_access`: Log access limited to those who need it
- **References:** MITRE ATT&CK T1562.008 Disable or Modify Cloud Logs

### T-023 · Unbounded consumption and cost abuse

**🟢 Low** · score 4 (L2 × I2) · Partially mitigated · rule `AI-08`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Denial of service
- **Threat:** Heavy or abusive use can run up large costs or exhaust quotas for everyone.
- **Controls in place:** token_quota (inherited: Enterprise GenAI Gateway, preventive)
- **Without platform controls:** 🟡 Medium (score 6, open)
- **Recommended mitigations:**
  - `rate_limiting`: Rate limits per client or user
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** OWASP LLM10:2025 Unbounded Consumption

### Mitigated threats

These threats apply to the design, and all listed controls are in place. App team controls are self-reported, so verify them (e.g. CSPM findings, config review). Inherited controls are verified through the platform's evidence.

- T-017 · **Direct prompt injection and jailbreaks** on *Amazon Bedrock (Claude)* (residual Medium, controls: guardrails (inherited: Enterprise GenAI Gateway, preventive), prompt_injection_filter (inherited: Enterprise GenAI Gateway, preventive))
- T-018 · **Container escape via privileged or root containers** on *Chatbot API* (residual Low, controls: admission_control (inherited: Shared EKS Platform, preventive), non_root (inherited: Shared EKS Platform, preventive))
- T-019 · **Privileged / admin access without strong controls** on *Employee GenAI Assistant* (residual Low, controls: mfa (inherited: AWS Landing Zone, preventive), privileged_access_management (inherited: AWS Landing Zone, preventive))
- T-020 · **Data store reachable from public networks** on *Amazon Bedrock (Claude)* (residual Low, controls: private_endpoint (app team))
- T-021 · **Data store reachable from public networks** on *Policy documents (S3)* (residual Low, controls: public_access_block (inherited: AWS Landing Zone, preventive))
- T-022 · **Data store reachable from public networks** on *Bedrock Knowledge Base* (residual Low, controls: private_endpoint (app team))
- T-024 · **Unapproved or compromised models** on *Amazon Bedrock (Claude)* (residual Low, controls: model_allowlist (inherited: Enterprise GenAI Gateway, preventive))
- T-025 · **Untrusted or tampered container images** on *Chatbot API* (residual Low, controls: image_signing (inherited: Shared EKS Platform, preventive), admission_control (inherited: Shared EKS Platform, preventive))
- T-026 · **Node credential theft through the instance metadata service** on *Chatbot API* (residual Low, controls: imds_v2 (inherited: AWS Landing Zone, preventive), workload_identity (app team))
- T-027 · **Weak or missing user authentication** on *Internal load balancer* (residual Low, controls: sso (app team), mfa (app team))
- T-028 · **Secrets committed to code or configuration** on *GitHub Actions pipeline* (residual Low, controls: secrets_scanning (app team))
- T-029 · **AI activity not logged for investigation** on *Amazon Bedrock (Claude)* (residual Low, controls: invocation_logging (inherited: Enterprise GenAI Gateway, preventive))
- T-030 · **Malicious activity in running containers goes undetected** on *Chatbot API* (residual Low, controls: runtime_detection (inherited: AWS Landing Zone, preventive))
- T-031 · **Insufficient audit logging** on *Employee GenAI Assistant* (residual Low, controls: audit_logging (inherited: AWS Landing Zone, preventive), logging_siem (app team))
- T-032 · **Lateral movement between workloads** on *Chatbot API* (residual Low, controls: network_policy (inherited: Shared EKS Platform, preventive), segmentation (inherited: AWS Landing Zone, preventive))

## Questions for the app team

**Missing from the intake:**

- [ ] What data moves on flow F7 (GitHub Actions pipeline → Chatbot API)? Set `data`.

**To confirm during the review:**

*Amazon Bedrock (Claude)*
- [ ] Are PII filters applied to prompts and responses?
- [ ] Where does model output go, and is it encoded or validated first?
- [ ] Who can add or edit documents in the knowledge base?
- [ ] Does the system prompt contain any secrets, keys, or authorization logic?
- [ ] Are there per-user rate limits and token quotas?

*Bedrock Knowledge Base*
- [ ] Are retrieval results filtered by the requesting user's entitlements?
- [ ] Is this store scanned for sensitive data?

*Policy documents (S3)*
- [ ] Is this store scanned for sensitive data?
- [ ] Are backups isolated from the production account and tested?

*Chatbot API*
- [ ] What exactly can this workload's IAM role / managed identity do?
- [ ] Which base images are used, and does the pipeline fail on critical CVEs?
- [ ] How does this workload authenticate to cloud services and databases?
- [ ] Which external destinations does this workload actually need to reach?

*GitHub Actions pipeline*
- [ ] Who can merge and deploy to production? Are approvals required?
- [ ] Is Terraform scanned in the pipeline, and can it block a deploy?

*Invocation logs (CloudWatch → SIEM)*
- [ ] What sensitive fields can end up in logs, and who can read them?
- [ ] Are logs stored in a separate account with write-once retention?

## Method

- Threats come from a rule-based library (STRIDE, OWASP Top 10 for LLM Applications 2025, cloud and container threats). Each rule fires when the architecture matches its conditions.
- **Likelihood and impact** start from the rule's base score (1–5), then: +1 likelihood if internet-facing; +1 impact for highly sensitive data (restricted, customer PII, PCI, credentials); ±1 impact for high/low application criticality; −1 likelihood if some listed controls are in place, −2 if all are.
- **Inherited controls** from the platform baseline count the same as app team controls, except that detective-only coverage can't fully mitigate a threat. Each finding is also scored without them, to show what the platforms contribute.
- **Ratings:** Critical 20–25 · High 12–19 · Medium 6–11 · Low 1–5.
- This is a starting point for a threat modeling session, not a replacement for one. Controls are as reported by the app team and should be verified.
