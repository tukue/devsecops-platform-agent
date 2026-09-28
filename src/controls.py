"""Cloud-agnostic security controls with backward-compatible category mapping."""

CONTROL_TAXONOMY = (
    {
        "id": "identity.least-privilege",
        "category": "IAM",
        "owner": "Platform Security",
        "signals": ("wildcard permission", "action: *", "resource: *", "permission boundary"),
        "validation": "Verify effective permissions are limited to the required actions and resources.",
    },
    {
        "id": "identity.access-management",
        "category": "IAM",
        "owner": "Platform Security",
        "signals": ("iam", "identity", "rbac", "mfa", "trust policy", "assume role"),
        "validation": "Review effective identity permissions and authentication controls.",
    },
    {
        "id": "network.public-ingress",
        "category": "Network",
        "owner": "Cloud Platform",
        "signals": ("0.0.0.0/0", "publicly accessible", "public ingress", "security group allows"),
        "validation": "Confirm ingress is limited to approved ports and trusted CIDRs.",
    },
    {
        "id": "network.unrestricted-egress",
        "category": "Network",
        "owner": "Cloud Platform",
        "signals": ("unrestricted egress", "allow all egress"),
        "validation": "Confirm egress is restricted to required destinations and ports.",
    },
    {
        "id": "network.segmentation",
        "category": "Network",
        "owner": "Cloud Platform",
        "signals": ("network policy", "security group", "firewall", "ingress", "egress", "vpc"),
        "validation": "Verify network segmentation and firewall rules match the approved design.",
    },
    {
        "id": "network.dns-security",
        "category": "Network",
        "owner": "Cloud Platform",
        "signals": ("dnssec", "dns resolution", "dns over udp"),
        "validation": "Verify DNSSEC signing and validate responses with a DNSSEC-aware resolver.",
    },
    {
        "id": "container.privileged-workload",
        "category": "Container",
        "owner": "Container Platform",
        "signals": ("privileged", "runs as root", "cluster-admin"),
        "validation": "Verify the workload runs non-root with only required capabilities.",
    },
    {
        "id": "container.image-hardening",
        "category": "Container",
        "owner": "Container Platform",
        "signals": ("container", "kubernetes", "docker", "image", "pod", "workload"),
        "validation": "Verify the image is patched, scanned, and deployed with hardened runtime settings.",
    },
    {
        "id": "secrets.exposure",
        "category": "Secrets",
        "owner": "Platform Security",
        "signals": ("secret", "private key", "hardcoded password", "credential", "api key", "token"),
        "validation": "Confirm the secret is revoked or rotated and no longer appears in source or runtime configuration.",
    },
    {
        "id": "secrets.rotation",
        "category": "Secrets",
        "owner": "Platform Security",
        "signals": ("secret rotation", "rotate secrets", "no rotation", "stale credentials"),
        "validation": "Confirm rotation succeeds and dependent services use the current secret.",
    },
    {
        "id": "storage.public-access",
        "category": "Data",
        "owner": "Data Platform",
        "signals": ("public s3 bucket", "public bucket", "anonymous access", "public access", "publicly accessible bucket"),
        "validation": "Confirm public access is removed and approved consumers retain only required access.",
    },
    {
        "id": "data.encryption-at-rest",
        "category": "Data",
        "owner": "Data Platform",
        "signals": ("unencrypted", "no encryption", "encryption", "database", "rds"),
        "validation": "Confirm encryption at rest is enabled and the approved key-management policy is applied.",
    },
    {
        "id": "data.encryption-in-transit",
        "category": "Data",
        "owner": "Data Platform",
        "signals": ("http instead of https", "unencrypted channel", "tls", "https", "encryption in transit"),
        "validation": "Verify TLS negotiation, certificate validity, and service health over the encrypted path.",
    },
    {
        "id": "data.backup-protection",
        "category": "Data",
        "owner": "Data Platform",
        "signals": ("backup retention", "backup retention policy", "restore procedures"),
        "validation": "Verify backup retention settings and perform a scheduled restore test.",
    },
    {
        "id": "data.protection",
        "category": "Data",
        "owner": "Data Platform",
        "signals": ("customer records", "backup", "pii", "phi", "data"),
        "validation": "Confirm access, audit, encryption, and backup controls meet the data classification policy.",
    },
)


def resolve_control(finding, category=None):
    """Resolve the most specific stable control without changing legacy categories."""
    normalized = finding.lower()
    for control in CONTROL_TAXONOMY:
        if category and control["category"] != category:
            continue
        if any(signal in normalized for signal in control["signals"]):
            return control

    for control in CONTROL_TAXONOMY:
        if control["category"] == category:
            return control
    return None
