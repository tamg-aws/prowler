from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_network_mode_not_public(Check):
    """Ensure Bedrock AgentCore agent runtimes do not use public network mode.

    - PASS: The AgentCore agent runtime network mode is not PUBLIC.
    - FAIL: The AgentCore agent runtime network mode is PUBLIC.
    - MANUAL: GetAgentRuntime failed, so the network mode could not be retrieved
      and an absent value cannot be read as "not PUBLIC".
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
            bedrockagentcore_client.agent_runtimes_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "runtime/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:runtime/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore agent runtimes could not be listed in region {region} ({error}); verify manually that each one does not use PUBLIC network mode."
            findings.append(report)
        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)

            if not runtime.detail_retrieved:
                # GetAgentRuntime failed (permissions, throttling, transient
                # error). Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} network configuration could not be retrieved in region {runtime.region}; verify manually that its network mode is not PUBLIC."
                findings.append(report)
                continue

            if runtime.network_mode == "PUBLIC":
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} uses PUBLIC network mode in region {runtime.region}."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} does not use PUBLIC network mode in region {runtime.region}."
            findings.append(report)

        return findings
