from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client

# The log type an AgentCore Memory emits its extraction and consolidation job
# records under. The CloudWatch Logs model types logType as a free-form string,
# so the value is matched literally rather than through an enum.
APPLICATION_LOGS = "APPLICATION_LOGS"


class bedrockagentcore_memory_application_logs_enabled(Check):
    """Ensure Bedrock AgentCore memory resources deliver their application logs.

    AgentCore does not configure a log destination for memory automatically, so
    the extraction and consolidation records exist only once a vended-log
    delivery is created for the memory. A memory that never had one produces no
    log group at all, which is why this check reads the delivery inventory
    rather than looking for a log group.

    - PASS: A delivery exists for an APPLICATION_LOGS delivery source whose
      resourceArns include the memory ARN.
    - FAIL: No such delivery source exists, or one exists with no delivery
      attached, so nothing is being delivered.
    - MANUAL: The memory inventory or the delivery inventory could not be
      listed, so an absent delivery cannot be read as a disabled one.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # A Region whose memory inventory could not be listed contributes no
        # resources, which would otherwise be indistinguishable from a Region
        # that genuinely has no memory resources.
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
            report.status_extended = f"Bedrock AgentCore memory resources could not be listed in region {region} ({error}); verify manually that each one delivers its application logs."
            findings.append(report)

        for memory in bedrockagentcore_client.memories.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=memory)
            # GetMemory supplies the name, so a memory whose detail could not be
            # read still has an id to identify it by.
            memory_label = memory.name or memory.id

            # A None inventory means the Region could not be read, not that it
            # holds nothing. Reporting FAIL here would accuse a memory that is
            # correctly configured behind a permission the audit role lacks.
            sources = logs_client.delivery_sources.get(memory.region)
            deliveries = logs_client.deliveries.get(memory.region)
            if sources is None or deliveries is None:
                unreadable = "delivery sources" if sources is None else "deliveries"
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore memory {memory_label} log delivery could not be determined in region {memory.region} because the CloudWatch Logs {unreadable} could not be listed; verify manually that its application logs are delivered."
                findings.append(report)
                continue

            # resourceArns is the only field tying a delivery source to a
            # specific memory, so match on the memory ARN rather than on the
            # source name or service, which callers choose freely.
            source_names = {
                source.name
                for source in sources
                if source.log_type == APPLICATION_LOGS
                and memory.arn in source.resource_arns
            }
            if not source_names:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore memory {memory_label} has no {APPLICATION_LOGS} delivery source in region {memory.region}, so its application logs are not delivered."
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
                report.status_extended = f"Bedrock AgentCore memory {memory_label} has an {APPLICATION_LOGS} delivery source in region {memory.region} but no delivery attached to it, so its application logs are not delivered."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore memory {memory_label} delivers its {APPLICATION_LOGS} to a {delivery.delivery_destination_type} destination in region {memory.region}."
            findings.append(report)

        return findings
