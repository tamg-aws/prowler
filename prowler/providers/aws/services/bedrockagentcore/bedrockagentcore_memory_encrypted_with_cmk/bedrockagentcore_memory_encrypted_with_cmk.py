from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_memory_encrypted_with_cmk(Check):
    """Ensure Bedrock AgentCore memory resources are encrypted with a customer managed key.

    - PASS: The AgentCore memory resource has a customer managed KMS key configured.
    - FAIL: The AgentCore memory resource has no encryption key ARN configured.
    - MANUAL: GetMemory failed, so the encryption key could not be retrieved and
      an absent key ARN cannot be read as "no key"; or ListMemories failed for a
      Region, so that Region's memory resources are unknown rather than absent.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # A Region whose inventory could not be listed contributes no resources,
        # which would otherwise be indistinguishable from a Region that has none.
        for region, error in sorted(
            bedrockagentcore_client.memories_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "memory/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:memory/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore memory resources could not be listed in region {region} ({error}); verify manually that each one is encrypted with a customer managed KMS key."
            findings.append(report)

        for memory in bedrockagentcore_client.memories.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=memory)

            if not memory.detail_retrieved:
                # GetMemory failed (permissions, throttling, transient error).
                # Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore memory {memory.name or memory.id} encryption configuration could not be retrieved in region {memory.region}; verify manually that it uses a customer managed KMS key."
                findings.append(report)
                continue

            report.status = "PASS"
            report.status_extended = f"Bedrock AgentCore memory {memory.name or memory.id} is encrypted with a customer managed KMS key in region {memory.region}."
            if not memory.encryption_key_arn:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore memory {memory.name or memory.id} is not encrypted with a customer managed KMS key in region {memory.region}."
            findings.append(report)

        return findings
