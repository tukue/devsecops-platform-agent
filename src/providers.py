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


class ProviderRouter:
    """Select the most specific available adapter; unsupported providers stay generic."""

    def __init__(self, adapters=None):
        self.adapters = adapters or (AWSProviderAdapter(), GenericProviderAdapter())

    def select(self, finding, metadata=None):
        for adapter in self.adapters:
            if adapter.provider != "generic" and adapter.can_handle(finding, metadata):
                return adapter
        return next(adapter for adapter in self.adapters if adapter.provider == "generic")
