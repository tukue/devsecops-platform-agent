"""Provider adapters isolate cloud-specific finding normalization and guidance."""

import re

AWS_SERVICE_MARKERS = {
    "iam": "AWS IAM",
    "s3": "AWS S3",
    "rds": "Amazon RDS",
    "ec2": "Amazon EC2",
    "lambda": "AWS Lambda",
    "security group": "Amazon VPC Security Group",
    "cloudtrail": "AWS CloudTrail",
    "ecr": "Amazon ECR",
    "eks": "Amazon EKS",
}

AWS_REMEDIATION_OVERLAYS = {
    "identity.least-privilege": "Use IAM Access Analyzer and scope policy actions and resources to the minimum required.",
    "network.public-ingress": "Review the affected security group and restrict inbound rules to approved ports and CIDRs.",
    "storage.public-access": "Enable S3 Block Public Access and remove unintended bucket policy or ACL grants.",
    "data.encryption-at-rest": "Enable the relevant AWS encryption setting and validate the approved KMS key policy.",
    "secrets.exposure": "Rotate the affected value and move it to AWS Secrets Manager or another approved secret store.",
    "container.privileged-workload": "Use EKS Pod Security controls and a non-root security context before redeployment.",
    "logging.audit-coverage": "Enable and validate CloudTrail coverage for the required accounts and regions.",
}


def _contains_marker(finding, marker):
    return bool(re.search(r"\b%s\b" % re.escape(marker), finding.lower()))


def is_aws_finding(finding):
    normalized = finding.lower()
    return _contains_marker(normalized, "aws") or any(
        _contains_marker(normalized, marker) for marker in AWS_SERVICE_MARKERS
    )


class GenericProviderAdapter:
    provider = "generic"

    def can_handle(self, finding, metadata=None):
        return True

    def normalize(self, finding, metadata=None):
        normalized = dict(metadata or {})
        normalized.setdefault("provider", "generic")
        normalized.setdefault("source_type", "manual")
        return normalized

    def remediation_overlay(self, control_id):
        return ""


class AWSProviderAdapter:
    provider = "aws"

    def can_handle(self, finding, metadata=None):
        metadata = metadata or {}
        if metadata.get("provider") == self.provider:
            return True
        return is_aws_finding(finding)

    def normalize(self, finding, metadata=None):
        normalized = dict(metadata or {})
        normalized["provider"] = self.provider
        normalized.setdefault("source_type", "manual")
        if not normalized.get("resource_type"):
            for marker, resource_type in AWS_SERVICE_MARKERS.items():
                if _contains_marker(finding, marker):
                    normalized["resource_type"] = resource_type
                    break
        return normalized

    def remediation_overlay(self, control_id):
        return AWS_REMEDIATION_OVERLAYS.get(control_id, "")


class AzureProviderAdapter:
    provider = "azure"

    AZURE_SERVICE_MARKERS = {
        "azure": "Azure",
        "entra id": "Entra ID",
        "azure ad": "Entra ID",
        "rbac": "Entra ID RBAC",
        "nsg": "Azure NSG",
        "network security group": "Azure NSG",
        "blob storage": "Azure Blob Storage",
        "key vault": "Azure Key Vault",
        "aks": "Azure AKS",
        "activity log": "Azure Activity Log",
    }

    AZURE_REMEDIATION_OVERLAYS = {
        "identity.least-privilege": "Use Entra ID Privileged Identity Management and scope app roles and group assignments to the minimum required.",
        "network.public-ingress": "Review the affected NSG and restrict inbound rules to approved ports and CIDRs.",
        "storage.public-access": "Enable Azure Storage Blob public access denial and remove unintended container or blob policy or ACL grants.",
        "secrets.exposure": "Rotate the affected value and move it to Azure Key Vault or another approved secret store.",
        "container.privileged-workload": "Use AKS Pod Security Policy and a non-root security context before redeployment.",
        "logging.audit-coverage": "Enable and validate Azure Activity Log coverage for the required subscriptions and resource groups.",
    }

    def can_handle(self, finding, metadata=None):
        metadata = metadata or {}
        if metadata.get("provider") == self.provider:
            return True
        normalized = finding.lower()
        return any(
            _contains_marker(normalized, marker) for marker in self.AZURE_SERVICE_MARKERS
        )

    def normalize(self, finding, metadata=None):
        normalized = dict(metadata or {})
        normalized["provider"] = self.provider
        normalized.setdefault("source_type", "manual")
        if not normalized.get("resource_type"):
            for marker, resource_type in self.AZURE_SERVICE_MARKERS.items():
                if _contains_marker(finding, marker):
                    normalized["resource_type"] = resource_type
                    break
        return normalized

    def remediation_overlay(self, control_id):
        return self.AZURE_REMEDIATION_OVERLAYS.get(control_id, "")


class GCPProviderAdapter:
    provider = "gcp"

    GCP_SERVICE_MARKERS = {
        "gcp": "GCP",
        "google cloud": "GCP",
        "cloud iam": "GCP IAM",
        "cloud identity": "GCP IAM",
        "vpc firewall": "GCP VPC Firewall",
        "firewall rule": "GCP VPC Firewall",
        "cloud storage": "GCP Cloud Storage",
        "secret manager": "GCP Secret Manager",
        "gke": "GKE",
        "google kubernetes engine": "GKE",
        "cloud audit log": "GCP Cloud Audit Log",
        "audit log": "GCP Cloud Audit Log",
    }

    GCP_REMEDIATION_OVERLAYS = {
        "identity.least-privilege": "Use GCP Cloud IAM with granular roles and scope service accounts to the minimum required.",
        "network.public-ingress": "Review the affected VPC firewall rule and restrict ingress to approved ports and CIDRs.",
        "storage.public-access": "Enable Cloud Storage uniform bucket-level access and remove unintended ACL or policy grants.",
        "secrets.exposure": "Rotate the affected value and move it to Secret Manager or another approved secret store.",
        "container.privileged-workload": "Use GKE Pod Security Standards and a non-root security context before redeployment.",
        "logging.audit-coverage": "Enable and validate Cloud Audit Log coverage for the required projects and log sinks.",
    }

    def can_handle(self, finding, metadata=None):
        metadata = metadata or {}
        if metadata.get("provider") == self.provider:
            return True
        normalized = finding.lower()
        return any(
            _contains_marker(normalized, marker) for marker in self.GCP_SERVICE_MARKERS
        )

    def normalize(self, finding, metadata=None):
        normalized = dict(metadata or {})
        normalized["provider"] = self.provider
        normalized.setdefault("source_type", "manual")
        if not normalized.get("resource_type"):
            for marker, resource_type in self.GCP_SERVICE_MARKERS.items():
                if _contains_marker(finding, marker):
                    normalized["resource_type"] = resource_type
                    break
        return normalized

    def remediation_overlay(self, control_id):
        return self.GCP_REMEDIATION_OVERLAYS.get(control_id, "")


class ProviderRouter:
    """Select the most specific available adapter; unsupported providers stay generic."""

    def __init__(self, enable_azure=False, enable_gcp=False):
        self.enable_azure = enable_azure
        self.enable_gcp = enable_gcp
        self.adapters = [
            AWSProviderAdapter(),
        ]
        if enable_azure:
            self.adapters.append(AzureProviderAdapter())
        if enable_gcp:
            self.adapters.append(GCPProviderAdapter())
        self.adapters.append(GenericProviderAdapter())

    def select(self, finding, metadata=None):
        best = None
        for adapter in self.adapters:
            if adapter.provider == "generic":
                continue
            if adapter.can_handle(finding, metadata):
                best = adapter
                break
        if best is not None:
            return best
        return next(adapter for adapter in self.adapters if adapter.provider == "generic")
