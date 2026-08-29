from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_runtime_inbound_authorizer_configured(Check):
    """Ensure Bedrock AgentCore agent runtimes require an inbound authorizer.

    - PASS: The AgentCore agent runtime has an authorizer configuration set.
    - FAIL: The AgentCore agent runtime has no authorizer configuration, so inbound calls fall
      back to IAM SigV4 and carry no validated end-user identity. This is NOT the same as
      unauthenticated: SigV4 authenticates the calling AWS principal, and AWS documents it as the
      default and as the recommended posture for service-to-service calls. The gap is that the
      agent cannot scope its actions or tool access to the person it is acting for.
    - MANUAL: GetAgentRuntime failed, so the authorizer configuration could not
      be retrieved and an absent value cannot be read as "no authorizer".
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
            report.status_extended = f"Bedrock AgentCore agent runtimes could not be listed in region {region} ({error}); verify manually that each one has an inbound authorizer configured."
            findings.append(report)
        for runtime in bedrockagentcore_client.agent_runtimes.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)

            if not runtime.detail_retrieved:
                # GetAgentRuntime failed (permissions, throttling, transient
                # error). Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} authorizer configuration could not be retrieved in region {runtime.region}; verify manually that an inbound authorizer is configured."
                findings.append(report)
                continue

            report.status = "PASS"
            report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} has an inbound authorizer configuration in region {runtime.region}."
            if not runtime.authorizer_configuration:
                # "has no inbound authorizer configured" read as unauthenticated, which is false:
                # with no authorizerConfiguration the runtime falls back to IAM SigV4, the AWS
                # default and the recommended posture for service-to-service calls. What is
                # missing is a validated end-user identity, so say that and nothing wider.
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} has no inbound authorizer configuration in region {runtime.region}, so inbound calls fall back to IAM SigV4 and carry no validated end-user identity."
            findings.append(report)

        return findings
