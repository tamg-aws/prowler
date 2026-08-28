from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client

# The log type an AgentCore Gateway emits for its request/response call trail.
# The CloudWatch Logs model types logType as a free-form string, so the value is
# matched literally rather than through an enum.
APPLICATION_LOGS = "APPLICATION_LOGS"


class bedrockagentcore_gateway_application_logs_enabled(Check):
    """Ensure Bedrock AgentCore gateways deliver their application logs.

    AgentCore does not configure a log destination for gateways automatically, so
    the gateway call trail exists only once a vended-log delivery is created for
    it. A gateway that never had one produces no log group at all, which is why
    this check reads the delivery inventory rather than looking for a log group.

    - PASS: A delivery exists for an APPLICATION_LOGS delivery source whose
      resourceArns include the gateway ARN.
    - FAIL: No such delivery source exists, or one exists with no delivery
      attached, so nothing is being delivered.
    - MANUAL: The gateway inventory or the delivery inventory could not be
      listed, so an absent delivery cannot be read as a disabled one.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # A Region whose gateway inventory could not be listed contributes no
        # resources, which would otherwise be indistinguishable from a Region
        # that genuinely has no gateways.
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
            report.status_extended = f"Bedrock AgentCore gateways could not be listed in region {region} ({error}); verify manually that each one delivers its application logs."
            findings.append(report)

        for gateway in bedrockagentcore_client.gateways.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=gateway)

            # A None inventory means the Region could not be read, not that it
            # holds nothing. Reporting FAIL here would accuse a gateway that is
            # correctly configured behind a permission the audit role lacks.
            sources = logs_client.delivery_sources.get(gateway.region)
            deliveries = logs_client.deliveries.get(gateway.region)
            if sources is None or deliveries is None:
                unreadable = "delivery sources" if sources is None else "deliveries"
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} log delivery could not be determined in region {gateway.region} because the CloudWatch Logs {unreadable} could not be listed; verify manually that its application logs are delivered."
                findings.append(report)
                continue

            # resourceArns is the only field tying a delivery source to a
            # specific gateway, so match on the gateway ARN rather than on the
            # source name or service, which callers choose freely.
            source_names = {
                source.name
                for source in sources
                if source.log_type == APPLICATION_LOGS
                and gateway.arn in source.resource_arns
            }
            if not source_names:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} has no {APPLICATION_LOGS} delivery source in region {gateway.region}, so its application logs are not delivered."
                findings.append(report)
                continue

            delivery = next(
                (
                    delivery
                    for delivery in deliveries
                    if delivery.delivery_source_name in source_names
                ),
                None,
            )
            if delivery is None:
                # A source without a delivery is a registration that emits
                # nothing, so it must not read as logging enabled.
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} has an {APPLICATION_LOGS} delivery source in region {gateway.region} but no delivery attached to it, so its application logs are not delivered."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore gateway {gateway.name} delivers its {APPLICATION_LOGS} to a {delivery.delivery_destination_type} destination in region {gateway.region}."
            findings.append(report)

        return findings
