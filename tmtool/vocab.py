"""Shared vocabulary: component types, data classes, and the controls the threat library understands."""

COMPONENT_TYPES = {
    "user": "A person using the system (employee, customer, admin)",
    "external_system": "A system outside our control that we exchange data with",
    "saas": "A SaaS product or vendor service",
    "load_balancer": "Load balancer or ingress",
    "api_gateway": "API gateway or AI gateway",
    "web_app": "Web front end or web application",
    "api": "Backend API service",
    "container_workload": "Workload running in containers (EKS, AKS, OpenShift, ECS)",
    "serverless_function": "Lambda, Azure Functions, Cloud Run functions",
    "vm": "Virtual machine",
    "database": "Relational or NoSQL database",
    "object_storage": "S3, Blob Storage, GCS",
    "queue": "Queue, topic, or event bus",
    "secrets_store": "Secrets Manager, Key Vault",
    "identity_provider": "Entra ID, Okta, Cognito",
    "llm": "Hosted model service (Bedrock, Azure OpenAI, Vertex AI)",
    "vector_store": "Vector database or knowledge base used for retrieval (RAG)",
    "ai_agent": "AI agent that can call tools or take actions",
    "ci_cd": "CI/CD pipeline and source repositories",
    "logging": "Log storage, SIEM, or monitoring",
}

DATA_CLASSES = {
    "public": "Approved for public release",
    "internal": "Internal business data",
    "confidential": "Confidential business data",
    "restricted": "Highest internal classification",
    "pii": "Personal data about employees or others",
    "customer_pii": "Personal data about customers",
    "pci": "Payment card data (PAN, CVV, track data)",
    "credentials": "Passwords, keys, tokens",
}

# Any of these makes data "sensitive" for rule matching.
SENSITIVE_DATA = {"confidential", "restricted", "pii", "customer_pii", "pci", "credentials"}

# These raise impact by one when present.
HIGHLY_SENSITIVE_DATA = {"restricted", "customer_pii", "pci", "credentials"}

CRITICALITY = ("low", "medium", "high")

USER_GROUPS = ("employees", "customers", "partners", "admins")

REGULATORY = ("pci", "glba", "sox", "nydfs", "sr11-7", "hipaa", "gdpr")

CONTROLS = {
    # Identity
    "sso": "Single sign-on through the corporate or customer identity provider",
    "mfa": "Multi-factor authentication enforced",
    "privileged_access_management": "Just-in-time, approved, logged admin access",
    "workload_identity": "Short-lived workload credentials (Pod Identity / IRSA, managed identity, Workload Identity)",
    "secrets_manager": "Secrets pulled from a secrets manager, not stored in code or config",
    "least_privilege_iam": "IAM roles scoped to exactly what the component needs",
    "authz_checks": "Per-request, per-record authorization checks",
    "service_auth": "Service-to-service authentication (signed tokens, IAM auth)",
    # Network
    "waf": "Web application firewall in front of the component",
    "rate_limiting": "Rate limits per client or user",
    "autoscaling": "Autoscaling to absorb load",
    "private_endpoint": "Reachable only through private endpoints / VPC endpoints",
    "public_access_block": "Public access explicitly disabled",
    "egress_control": "Outbound traffic restricted to an allow-list",
    "network_policy": "Default-deny network policies between workloads",
    "segmentation": "Network / account segmentation from other environments",
    "tls": "TLS 1.2+ in transit",
    "mtls": "Mutual TLS between services",
    # Vulnerability and hardening
    "vuln_scanning": "Regular vulnerability scanning",
    "patching": "Patching within defined SLAs",
    "image_scanning": "Container image scanning that blocks critical CVEs",
    "image_signing": "Container images signed and verified",
    "admission_control": "Admission policies (Kyverno, Gatekeeper, SCCs, Pod Security Admission)",
    "non_root": "Containers run as non-root, not privileged",
    "imds_v2": "IMDSv2 enforced with hop limit 1",
    "runtime_detection": "Runtime threat detection (Falco, GuardDuty, Defender, Wiz Sensor)",
    "input_validation": "Input validated against an expected schema",
    "parameterized_queries": "Parameterized queries or ORM; no string-built SQL",
    "message_validation": "Consumers validate message schema and source",
    "multi_az": "Deployed across multiple availability zones",
    # Data
    "encryption_cmk": "Encrypted with a customer-managed key",
    "data_classification_scanning": "Scanned for sensitive data (Macie, Purview, Sensitive Data Protection)",
    "backups": "Backups isolated from production and tested",
    "object_lock": "Write-once / immutable storage for critical data",
    "dlp": "Data loss prevention on content",
    "tokenization": "Sensitive values replaced with tokens",
    "data_minimization": "Only the data needed is collected or sent",
    "pci_data_masking": "Card data masked or removed before it reaches prompts, transcripts, or logs",
    "vendor_risk_assessment": "Vendor reviewed through third-party risk management",
    # Logging
    "audit_logging": "Security-relevant actions are audit-logged",
    "logging_siem": "Logs forwarded to the SIEM with detections",
    "log_redaction": "Sensitive fields redacted before logging",
    "restricted_log_access": "Log access limited to those who need it",
    "log_immutability": "Logs stored write-once in a separate account",
    # CI/CD
    "branch_protection": "Protected branches with required reviews",
    "deploy_approvals": "Approvals required for production deploys",
    "iac_scanning": "IaC scanned in the pipeline (Checkov, Wiz Code, Trivy)",
    "secrets_scanning": "Repos and pipelines scanned for secrets",
    # AI
    "guardrails": "Model guardrails enabled (Bedrock Guardrails, Azure Content Safety, Model Armor)",
    "prompt_injection_filter": "Prompt attack / injection detection (e.g. Prompt Shields)",
    "content_write_controls": "Only approved people and processes can add knowledge-base content",
    "pii_filter": "PII detection and masking on prompts and responses",
    "permission_aware_retrieval": "Retrieval filtered by the requesting user's entitlements",
    "least_privilege_tools": "Agent tools limited to the minimum scopes needed",
    "human_approval": "Human approval required for high-impact AI actions",
    "output_validation": "Model output validated or encoded before use",
    "model_allowlist": "Only models approved through AI governance can be used",
    "token_quota": "Token quotas / budgets per user or app",
    "invocation_logging": "Model invocation metadata or content logged to the SIEM",
    "human_review": "Human review of AI output before decisions",
    "grounding_checks": "Grounding / citation checks on responses",
    "no_secrets_in_prompts": "No secrets or authorization logic in system prompts",
    "tool_allowlist": "Only approved tools / MCP servers can be connected",
}
