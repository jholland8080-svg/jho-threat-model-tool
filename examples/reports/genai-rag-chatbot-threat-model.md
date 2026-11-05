# Threat Model: Employee GenAI Assistant

| | |
|---|---|
| **Generated** | 2026-11-05 |
| **Owner** | Digital Workplace team |
| **Stage** | design |
| **Criticality** | Medium |
| **Users** | employees, admins |
| **Regulatory scope** | GLBA |

Internal chatbot that answers employee questions using company policy and procedure documents. Runs on a shared EKS cluster and calls Amazon Bedrock through a VPC endpoint.

## Executive summary

**Overall residual risk: 🟠 High** (highest-rated threat that is not fully mitigated)

| Rating | Open / partially mitigated | Mitigated |
|---|---|---|
| 🔴 Critical | 0 | 0 |
| 🟠 High | 7 | 0 |
| 🟡 Medium | 14 | 0 |
| 🟢 Low | 1 | 10 |

**Top risks to address:**

1. **Privileged / admin access without strong controls** on *Employee GenAI Assistant* (🟠 High, open). Add: `mfa`, `privileged_access_management`
1. **Indirect prompt injection through retrieved content** on *Amazon Bedrock (Claude)* (🟠 High, open). Add: `content_write_controls`, `prompt_injection_filter`
1. **Sensitive information disclosure through the model** on *Amazon Bedrock (Claude)* (🟠 High, open). Add: `pii_filter`, `dlp`
1. **Retrieval returns data the user isn't allowed to see** on *Bedrock Knowledge Base* (🟠 High, open). Add: `permission_aware_retrieval`
1. **Unknown sensitive data in storage** on *Policy documents (S3)* (🟠 High, open). Add: `data_classification_scanning`

⚠️ The intake left **1 open question** (see *Questions for the app team*). Answering them may add or change findings.

## Scope

| Component | Type | Zone | Internet-facing | Data | Controls |
|---|---|---|---|---|---|
| **Employee** (`employee`) | user | corp | No | — | — |
| **Internal load balancer** (`alb`) | load_balancer | app-vpc | No | — | sso, mfa, tls |
| **Chatbot API** (`chatbot-api`) | container_workload | app-vpc | No | internal, confidential | workload_identity, image_scanning, admission_control, non_root, network_policy |
| **Amazon Bedrock (Claude)** (`bedrock`) | llm | aws-managed | No | — | private_endpoint, guardrails, model_allowlist, invocation_logging |
| **Bedrock Knowledge Base** (`knowledge-base`) | vector_store | aws-managed | No | internal, confidential | private_endpoint |
| **Policy documents (S3)** (`docs-bucket`) | object_storage | aws-managed | No | internal, confidential | public_access_block, encryption_cmk |
| **Invocation logs (CloudWatch → SIEM)** (`logs`) | logging | aws-managed | No | confidential | — |
| **GitHub Actions pipeline** (`pipeline`) | ci_cd | corp | No | — | branch_protection, deploy_approvals, secrets_scanning |

**Application-wide controls** (apply to every component): `sso`, `audit_logging`, `logging_siem`

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

Sorted by risk score (likelihood × impact, 1–25).

| ID | Risk | Threat | Target | STRIDE | L | I | Score | Status | Missing controls |
|---|---|---|---|---|---|---|---|---|---|
| T-001 | 🟠 High | Privileged / admin access without strong controls | Employee GenAI Assistant | SE | 3 | 5 | **15** | Open | mfa, privileged_access_management |
| T-002 | 🟠 High | Indirect prompt injection through retrieved content | Amazon Bedrock (Claude) | T | 3 | 4 | **12** | Open | content_write_controls, prompt_injection_filter |
| T-003 | 🟠 High | Sensitive information disclosure through the model | Amazon Bedrock (Claude) | I | 3 | 4 | **12** | Open | pii_filter, dlp |
| T-004 | 🟠 High | Retrieval returns data the user isn't allowed to see | Bedrock Knowledge Base | I | 3 | 4 | **12** | Open | permission_aware_retrieval |
| T-005 | 🟠 High | Unknown sensitive data in storage | Policy documents (S3) | I | 3 | 4 | **12** | Open | data_classification_scanning |
| T-006 | 🟠 High | Unknown sensitive data in storage | Bedrock Knowledge Base | I | 3 | 4 | **12** | Open | data_classification_scanning |
| T-007 | 🟠 High | Over-privileged workload identity | Chatbot API | E | 3 | 4 | **12** | Open | least_privilege_iam |
| T-008 | 🟡 Medium | Pipeline compromise or unauthorized deployment | GitHub Actions pipeline | TE | 2 | 5 | **10** | Partially mitigated | least_privilege_iam |
| T-009 | 🟡 Medium | Direct prompt injection and jailbreaks | Amazon Bedrock (Claude) | TE | 3 | 3 | **9** | Partially mitigated | prompt_injection_filter |
| T-010 | 🟡 Medium | Model output trusted by downstream systems | Amazon Bedrock (Claude) | TE | 3 | 3 | **9** | Open | output_validation |
| T-011 | 🟡 Medium | Infrastructure misconfiguration reaches production | GitHub Actions pipeline | TI | 3 | 3 | **9** | Open | iac_scanning |
| T-012 | 🟡 Medium | Vulnerable container images | Chatbot API | TE | 3 | 3 | **9** | Partially mitigated | patching |
| T-013 | 🟡 Medium | Malicious activity in running containers goes undetected | Chatbot API | RT | 3 | 3 | **9** | Open | runtime_detection |
| T-014 | 🟡 Medium | Sensitive data written to logs | Invocation logs (CloudWatch → SIEM) | I | 3 | 3 | **9** | Open | log_redaction, restricted_log_access |
| T-015 | 🟡 Medium | Node credential theft through the instance metadata service | Chatbot API | EI | 2 | 4 | **8** | Partially mitigated | imds_v2 |
| T-016 | 🟡 Medium | Data destruction or ransomware | Policy documents (S3) | TD | 2 | 4 | **8** | Open | backups, object_lock |
| T-017 | 🟡 Medium | Long-lived static credentials in workloads | Chatbot API | SI | 2 | 4 | **8** | Partially mitigated | secrets_manager |
| T-018 | 🟡 Medium | Uncontrolled outbound traffic enables data exfiltration | Chatbot API | I | 2 | 4 | **8** | Open | egress_control |
| T-019 | 🟡 Medium | Unbounded consumption and cost abuse | Amazon Bedrock (Claude) | D | 3 | 2 | **6** | Open | token_quota, rate_limiting |
| T-020 | 🟡 Medium | System prompt leakage | Amazon Bedrock (Claude) | I | 3 | 2 | **6** | Open | no_secrets_in_prompts |
| T-021 | 🟡 Medium | Logs can be altered or disabled | Invocation logs (CloudWatch → SIEM) | R | 2 | 3 | **6** | Open | log_immutability, restricted_log_access |
| T-022 | 🟢 Low | Container escape via privileged or root containers | Chatbot API | E | 1 | 5 | **5** | Mitigated | — |
| T-023 | 🟢 Low | Data store reachable from public networks | Amazon Bedrock (Claude) | I | 1 | 5 | **5** | Mitigated | — |
| T-024 | 🟢 Low | Data store reachable from public networks | Policy documents (S3) | I | 1 | 5 | **5** | Mitigated | — |
| T-025 | 🟢 Low | Data store reachable from public networks | Bedrock Knowledge Base | I | 1 | 5 | **5** | Mitigated | — |
| T-026 | 🟢 Low | Untrusted or tampered container images | Chatbot API | T | 1 | 4 | **4** | Partially mitigated | image_signing |
| T-027 | 🟢 Low | Unapproved or compromised models | Amazon Bedrock (Claude) | T | 1 | 4 | **4** | Mitigated | — |
| T-028 | 🟢 Low | Weak or missing user authentication | Internal load balancer | S | 1 | 4 | **4** | Mitigated | — |
| T-029 | 🟢 Low | Secrets committed to code or configuration | GitHub Actions pipeline | I | 1 | 4 | **4** | Mitigated | — |
| T-030 | 🟢 Low | AI activity not logged for investigation | Amazon Bedrock (Claude) | R | 1 | 3 | **3** | Mitigated | — |
| T-031 | 🟢 Low | Insufficient audit logging | Employee GenAI Assistant | R | 1 | 3 | **3** | Mitigated | — |
| T-032 | 🟢 Low | Lateral movement between workloads | Chatbot API | E | 1 | 3 | **3** | Mitigated | — |

## Required before go-live

Critical and High threats that are not fully mitigated. Fix these, or document a risk acceptance with a named owner and an expiry date.

| ID | Threat | Target | Controls to add |
|---|---|---|---|
| T-001 | Privileged / admin access without strong controls | Employee GenAI Assistant | mfa, privileged_access_management |
| T-002 | Indirect prompt injection through retrieved content | Amazon Bedrock (Claude) | content_write_controls, prompt_injection_filter |
| T-003 | Sensitive information disclosure through the model | Amazon Bedrock (Claude) | pii_filter, dlp |
| T-004 | Retrieval returns data the user isn't allowed to see | Bedrock Knowledge Base | permission_aware_retrieval |
| T-005 | Unknown sensitive data in storage | Policy documents (S3) | data_classification_scanning |
| T-006 | Unknown sensitive data in storage | Bedrock Knowledge Base | data_classification_scanning |
| T-007 | Over-privileged workload identity | Chatbot API | least_privilege_iam |

## Threat details

### T-001 · Privileged / admin access without strong controls

**🟠 High** · score 15 (L3 × I5) · Open · rule `ID-02`

- **Target:** Employee GenAI Assistant (app)
- **STRIDE:** Spoofing, Elevation of privilege
- **Threat:** Administrators or support staff have elevated access. Compromise of one admin account can expose the whole application and its data.
- **Recommended mitigations:**
  - `mfa`: Multi-factor authentication enforced
  - `privileged_access_management`: Just-in-time, approved, logged admin access
- **References:** MITRE ATT&CK T1078.004 Cloud Accounts

### T-002 · Indirect prompt injection through retrieved content

**🟠 High** · score 12 (L3 × I4) · Open · rule `AI-02`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Tampering
- **Threat:** Instructions hidden in documents, emails, or web pages that the model reads can change its behavior. There is no complete fix; limit who can write content and what the model can do.
- **Recommended mitigations:**
  - `content_write_controls`: Only approved people and processes can add knowledge-base content
  - `prompt_injection_filter`: Prompt attack / injection detection (e.g. Prompt Shields)
- **References:** OWASP LLM01:2025 Prompt Injection

### T-003 · Sensitive information disclosure through the model

**🟠 High** · score 12 (L3 × I4) · Open · rule `AI-03`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Information disclosure
- **Threat:** Prompts and responses can contain PII or confidential data, whether typed by users or pulled in from retrieval.
- **Recommended mitigations:**
  - `pii_filter`: PII detection and masking on prompts and responses
  - `dlp`: Data loss prevention on content
- **References:** OWASP LLM02:2025 Sensitive Information Disclosure

### T-004 · Retrieval returns data the user isn't allowed to see

**🟠 High** · score 12 (L3 × I4) · Open · rule `AI-04`

- **Target:** Bedrock Knowledge Base (component)
- **STRIDE:** Information disclosure
- **Threat:** If retrieval uses the application's access instead of the user's, any user can get answers drawn from any document in the knowledge base.
- **Recommended mitigations:**
  - `permission_aware_retrieval`: Retrieval filtered by the requesting user's entitlements
- **References:** OWASP LLM08:2025 Vector and Embedding Weaknesses

### T-005 · Unknown sensitive data in storage

**🟠 High** · score 12 (L3 × I4) · Open · rule `DA-02`

- **Target:** Policy documents (S3) (component)
- **STRIDE:** Information disclosure
- **Threat:** Teams often store more sensitive data than they realize (e.g. PII in documents or exports). Without scanning, it isn't protected or classified correctly.
- **Recommended mitigations:**
  - `data_classification_scanning`: Scanned for sensitive data (Macie, Purview, Sensitive Data Protection)
- **References:** Amazon Macie / Microsoft Purview / GCP Sensitive Data Protection

### T-006 · Unknown sensitive data in storage

**🟠 High** · score 12 (L3 × I4) · Open · rule `DA-02`

- **Target:** Bedrock Knowledge Base (component)
- **STRIDE:** Information disclosure
- **Threat:** Teams often store more sensitive data than they realize (e.g. PII in documents or exports). Without scanning, it isn't protected or classified correctly.
- **Recommended mitigations:**
  - `data_classification_scanning`: Scanned for sensitive data (Macie, Purview, Sensitive Data Protection)
- **References:** Amazon Macie / Microsoft Purview / GCP Sensitive Data Protection

### T-007 · Over-privileged workload identity

**🟠 High** · score 12 (L3 × I4) · Open · rule `ID-04`

- **Target:** Chatbot API (component)
- **STRIDE:** Elevation of privilege
- **Threat:** If the workload's role has broader permissions than it needs, any compromise of the workload becomes a compromise of everything that role can reach.
- **Recommended mitigations:**
  - `least_privilege_iam`: IAM roles scoped to exactly what the component needs
- **References:** MITRE ATT&CK T1078.004 Cloud Accounts

### T-008 · Pipeline compromise or unauthorized deployment

**🟡 Medium** · score 10 (L2 × I5) · Partially mitigated · rule `CI-01`

- **Target:** GitHub Actions pipeline (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** The pipeline can change production. A compromised pipeline, developer account, or workflow can push malicious code or infrastructure changes.
- **Controls in place:** branch_protection, deploy_approvals
- **Recommended mitigations:**
  - `least_privilege_iam`: IAM roles scoped to exactly what the component needs
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1195 Supply Chain Compromise; OWASP Top 10 CI/CD Security Risks

### T-009 · Direct prompt injection and jailbreaks

**🟡 Medium** · score 9 (L3 × I3) · Partially mitigated · rule `AI-01`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** Users can craft prompts that override the system's instructions or safety rules.
- **Controls in place:** guardrails
- **Recommended mitigations:**
  - `prompt_injection_filter`: Prompt attack / injection detection (e.g. Prompt Shields)
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** OWASP LLM01:2025 Prompt Injection

### T-010 · Model output trusted by downstream systems

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `AI-06`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** If model output is rendered in a browser or passed to code, SQL, or APIs without validation, it can cause XSS, injection, or unintended actions.
- **Recommended mitigations:**
  - `output_validation`: Model output validated or encoded before use
- **References:** OWASP LLM05:2025 Improper Output Handling

### T-011 · Infrastructure misconfiguration reaches production

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `CI-02`

- **Target:** GitHub Actions pipeline (component)
- **STRIDE:** Tampering, Information disclosure
- **Threat:** Without IaC scanning, insecure Terraform (public buckets, open security groups) is deployed and only found later by CSPM, if at all.
- **Recommended mitigations:**
  - `iac_scanning`: IaC scanned in the pipeline (Checkov, Wiz Code, Trivy)
- **References:** Checkov / Wiz Code / Trivy config

### T-012 · Vulnerable container images

**🟡 Medium** · score 9 (L3 × I3) · Partially mitigated · rule `CT-01`

- **Target:** Chatbot API (component)
- **STRIDE:** Tampering, Elevation of privilege
- **Threat:** Images built on outdated or bloated base images carry exploitable CVEs into production.
- **Controls in place:** image_scanning
- **Recommended mitigations:**
  - `patching`: Patching within defined SLAs
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** CIS Kubernetes Benchmark; NIST SP 800-190

### T-013 · Malicious activity in running containers goes undetected

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `CT-05`

- **Target:** Chatbot API (component)
- **STRIDE:** Repudiation, Tampering
- **Threat:** Crypto-miners, shells, and unexpected processes in containers go unnoticed without runtime monitoring.
- **Recommended mitigations:**
  - `runtime_detection`: Runtime threat detection (Falco, GuardDuty, Defender, Wiz Sensor)
- **References:** MITRE ATT&CK T1496 Resource Hijacking

### T-014 · Sensitive data written to logs

**🟡 Medium** · score 9 (L3 × I3) · Open · rule `DA-04`

- **Target:** Invocation logs (CloudWatch → SIEM) (component)
- **STRIDE:** Information disclosure
- **Threat:** Logs often capture request bodies, tokens, or AI prompts. They are usually readable by more people than the source data.
- **Recommended mitigations:**
  - `log_redaction`: Sensitive fields redacted before logging
  - `restricted_log_access`: Log access limited to those who need it
- **References:** OWASP Logging Cheat Sheet

### T-015 · Node credential theft through the instance metadata service

**🟡 Medium** · score 8 (L2 × I4) · Partially mitigated · rule `CT-04`

- **Target:** Chatbot API (component)
- **STRIDE:** Elevation of privilege, Information disclosure
- **Threat:** A compromised pod that can reach the EC2 metadata service can steal the node's IAM role, which usually has more access than the pod.
- **Controls in place:** workload_identity
- **Recommended mitigations:**
  - `imds_v2`: IMDSv2 enforced with hop limit 1
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1552.005 Cloud Instance Metadata API

### T-016 · Data destruction or ransomware

**🟡 Medium** · score 8 (L2 × I4) · Open · rule `DA-03`

- **Target:** Policy documents (S3) (component)
- **STRIDE:** Tampering, Denial of service
- **Threat:** An attacker or mistake could delete or encrypt the data. Without protected backups, recovery may be impossible.
- **Recommended mitigations:**
  - `backups`: Backups isolated from production and tested
  - `object_lock`: Write-once / immutable storage for critical data
- **References:** MITRE ATT&CK T1485 Data Destruction

### T-017 · Long-lived static credentials in workloads

**🟡 Medium** · score 8 (L2 × I4) · Partially mitigated · rule `ID-03`

- **Target:** Chatbot API (component)
- **STRIDE:** Spoofing, Information disclosure
- **Threat:** Workloads that use static keys or passwords can have them leaked through code, images, logs, or environment variables, and the keys keep working until someone rotates them.
- **Controls in place:** workload_identity
- **Recommended mitigations:**
  - `secrets_manager`: Secrets pulled from a secrets manager, not stored in code or config
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1552 Unsecured Credentials

### T-018 · Uncontrolled outbound traffic enables data exfiltration

**🟡 Medium** · score 8 (L2 × I4) · Open · rule `NW-04`

- **Target:** Chatbot API (component)
- **STRIDE:** Information disclosure
- **Threat:** If the workload can reach any destination on the internet, an attacker who compromises it can send sensitive data out or download tools.
- **Recommended mitigations:**
  - `egress_control`: Outbound traffic restricted to an allow-list
- **References:** MITRE ATT&CK T1041 Exfiltration Over C2 Channel

### T-019 · Unbounded consumption and cost abuse

**🟡 Medium** · score 6 (L3 × I2) · Open · rule `AI-08`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Denial of service
- **Threat:** Heavy or abusive use can run up large costs or exhaust quotas for everyone.
- **Recommended mitigations:**
  - `token_quota`: Token quotas / budgets per user or app
  - `rate_limiting`: Rate limits per client or user
- **References:** OWASP LLM10:2025 Unbounded Consumption

### T-020 · System prompt leakage

**🟡 Medium** · score 6 (L3 × I2) · Open · rule `AI-11`

- **Target:** Amazon Bedrock (Claude) (component)
- **STRIDE:** Information disclosure
- **Threat:** Attackers can often extract the system prompt. Secrets or access rules placed in it will be exposed.
- **Recommended mitigations:**
  - `no_secrets_in_prompts`: No secrets or authorization logic in system prompts
- **References:** OWASP LLM07:2025 System Prompt Leakage

### T-021 · Logs can be altered or disabled

**🟡 Medium** · score 6 (L2 × I3) · Open · rule `LG-02`

- **Target:** Invocation logs (CloudWatch → SIEM) (component)
- **STRIDE:** Repudiation
- **Threat:** An attacker with enough access may delete logs or turn logging off to hide activity.
- **Recommended mitigations:**
  - `log_immutability`: Logs stored write-once in a separate account
  - `restricted_log_access`: Log access limited to those who need it
- **References:** MITRE ATT&CK T1562.008 Disable or Modify Cloud Logs

### T-026 · Untrusted or tampered container images

**🟢 Low** · score 4 (L1 × I4) · Partially mitigated · rule `CT-02`

- **Target:** Chatbot API (component)
- **STRIDE:** Tampering
- **Threat:** Without signing and admission checks, an attacker or mistake can deploy an image that didn't come from the approved pipeline.
- **Controls in place:** admission_control
- **Recommended mitigations:**
  - `image_signing`: Container images signed and verified
- **Score adjustments:** -1 likelihood: some listed controls in place
- **References:** MITRE ATT&CK T1195 Supply Chain Compromise; SLSA

### Mitigated threats

These threats apply to the design, and all listed controls are reported as in place. Verify the controls actually exist (e.g. CSPM findings, config review).

- T-022 · **Container escape via privileged or root containers** on *Chatbot API* (residual Low, controls: admission_control, non_root)
- T-023 · **Data store reachable from public networks** on *Amazon Bedrock (Claude)* (residual Low, controls: private_endpoint)
- T-024 · **Data store reachable from public networks** on *Policy documents (S3)* (residual Low, controls: public_access_block)
- T-025 · **Data store reachable from public networks** on *Bedrock Knowledge Base* (residual Low, controls: private_endpoint)
- T-027 · **Unapproved or compromised models** on *Amazon Bedrock (Claude)* (residual Low, controls: model_allowlist)
- T-028 · **Weak or missing user authentication** on *Internal load balancer* (residual Low, controls: sso, mfa)
- T-029 · **Secrets committed to code or configuration** on *GitHub Actions pipeline* (residual Low, controls: secrets_scanning)
- T-030 · **AI activity not logged for investigation** on *Amazon Bedrock (Claude)* (residual Low, controls: invocation_logging)
- T-031 · **Insufficient audit logging** on *Employee GenAI Assistant* (residual Low, controls: audit_logging, logging_siem)
- T-032 · **Lateral movement between workloads** on *Chatbot API* (residual Low, controls: network_policy)

## Questions for the app team

**Missing from the intake:**

- [ ] What data moves on flow F7 (GitHub Actions pipeline → Chatbot API)? Set `data`.

**To confirm during the review:**

*Employee GenAI Assistant*
- [ ] Who has admin or production access, and is it just-in-time and logged?

*Amazon Bedrock (Claude)*
- [ ] Who can add or edit documents in the knowledge base?
- [ ] Are PII filters applied to prompts and responses?
- [ ] Which guardrails are enabled, and has the app been red-teamed?
- [ ] Where does model output go, and is it encoded or validated first?
- [ ] Are there per-user rate limits and token quotas?
- [ ] Does the system prompt contain any secrets, keys, or authorization logic?

*Bedrock Knowledge Base*
- [ ] Are retrieval results filtered by the requesting user's entitlements?
- [ ] Is this store scanned for sensitive data?

*Policy documents (S3)*
- [ ] Is this store scanned for sensitive data?
- [ ] Are backups isolated from the production account and tested?

*Chatbot API*
- [ ] What exactly can this workload's IAM role / managed identity do?
- [ ] Which base images are used, and does the pipeline fail on critical CVEs?
- [ ] What runtime detection covers this cluster (Falco, GuardDuty, Defender, Wiz Sensor)?
- [ ] Is IMDSv2 enforced with a hop limit of 1? Do pods use Pod Identity / IRSA?
- [ ] How does this workload authenticate to cloud services and databases?
- [ ] Which external destinations does this workload actually need to reach?
- [ ] Can only signed images from approved registries run?

*GitHub Actions pipeline*
- [ ] Who can merge and deploy to production? Are approvals required?
- [ ] Is Terraform scanned in the pipeline, and can it block a deploy?

*Invocation logs (CloudWatch → SIEM)*
- [ ] What sensitive fields can end up in logs, and who can read them?
- [ ] Are logs stored in a separate account with write-once retention?

## Method

- Threats come from a rule-based library (STRIDE, OWASP Top 10 for LLM Applications 2025, cloud and container threats). Each rule fires when the architecture matches its conditions.
- **Likelihood and impact** start from the rule's base score (1–5), then: +1 likelihood if internet-facing; +1 impact for highly sensitive data (restricted, customer PII, PCI, credentials); ±1 impact for high/low application criticality; −1 likelihood if some listed controls are in place, −2 if all are.
- **Ratings:** Critical 20–25 · High 12–19 · Medium 6–11 · Low 1–5.
- This is a starting point for a threat modeling session, not a replacement for one. Controls are as reported by the app team and should be verified.
