from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_jwt_authorizer_client_or_audience_restricted(Check):
    """Ensure Bedrock AgentCore custom JWT authorizers restrict clients or audience.

    - PASS: The resource's custom JWT authorizer has allowedClients or allowedAudience set.
    - FAIL: The resource uses a custom JWT authorizer with neither restriction populated.
    - MANUAL: GetGateway or GetAgentRuntime failed, so the restrictions could not
      be retrieved and an empty list cannot be read as "no restriction".

    The two loops gate at different points because in-scope is decided from
    different data. `authorizerType` is a required member of the ListGateways
    summary, so a gateway's scope is known even when GetGateway fails and only
    CUSTOM_JWT gateways reach the gate. ListAgentRuntimes carries no authorizer
    field at all, so a runtime whose GetAgentRuntime failed cannot be shown to be
    out of scope and is reported as MANUAL rather than dropped silently.
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
            report.status_extended = f"Bedrock AgentCore agent runtimes could not be listed in region {region} ({error}); verify manually that each one restricts its JWT authorizer by client or audience."
            findings.append(report)

        # A Region whose inventory could not be listed contributes no resources,
        # which would otherwise be indistinguishable from a Region that has none.
        for region, error in sorted(
            bedrockagentcore_client.gateways_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "gateway/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:gateway/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore gateways could not be listed in region {region} ({error}); verify manually that each one restricts its JWT authorizer by client or audience."
            findings.append(report)
        for gateway in bedrockagentcore_client.gateways.values():
            if gateway.authorizer_type != "CUSTOM_JWT":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=gateway)

            if not gateway.detail_retrieved:
                # GetGateway failed (permissions, throttling, transient error).
                # The gateway is known to use CUSTOM_JWT from the ListGateways
                # summary, but its restrictions are unreadable, so an empty
                # allowedClients/allowedAudience is not evidence of no
                # restriction.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} custom JWT authorizer configuration could not be retrieved in region {gateway.region}; verify manually that allowed clients or audience is restricted."
                findings.append(report)
                continue

            restricted = bool(gateway.custom_jwt_allowed_clients) or bool(
                gateway.custom_jwt_allowed_audience
            )
            if restricted:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} custom JWT authorizer restricts allowed clients or audience in region {gateway.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} custom JWT authorizer has no allowed clients or audience restriction in region {gateway.region}."
            findings.append(report)

        for runtime in bedrockagentcore_client.agent_runtimes.values():
            if not runtime.detail_retrieved:
                # GetAgentRuntime failed (permissions, throttling, transient
                # error). authorizerConfiguration is the only place a runtime's
                # authorizer appears, so the runtime cannot be shown to be out of
                # scope and must not be dropped from the finding set.
                report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} authorizer configuration could not be retrieved in region {runtime.region}; verify manually that any custom JWT authorizer restricts allowed clients or audience."
                findings.append(report)
                continue

            if "customJWTAuthorizer" not in (runtime.authorizer_configuration or {}):
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=runtime)
            restricted = bool(runtime.custom_jwt_allowed_clients) or bool(
                runtime.custom_jwt_allowed_audience
            )
            if restricted:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} custom JWT authorizer restricts allowed clients or audience in region {runtime.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore agent runtime {runtime.name} custom JWT authorizer has no allowed clients or audience restriction in region {runtime.region}."
            findings.append(report)

        return findings
