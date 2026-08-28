from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_tool_network_mode_not_public(Check):
    """Ensure Bedrock AgentCore built-in tools do not use public network mode.

    - PASS: The AgentCore code interpreter or browser network mode is not PUBLIC.
    - FAIL: The AgentCore code interpreter or browser network mode is PUBLIC.
    - MANUAL: GetCodeInterpreter or GetBrowser failed, so the network mode could
      not be retrieved and an absent value cannot be read as "not PUBLIC".
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
            bedrockagentcore_client.browsers_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "browser/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:browser/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore browsers could not be listed in region {region} ({error}); verify manually that each one does not use PUBLIC network mode."
            findings.append(report)

        # A Region whose inventory could not be listed contributes no resources,
        # which would otherwise be indistinguishable from a Region that has none.
        for region, error in sorted(
            bedrockagentcore_client.code_interpreters_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "code-interpreter/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:code-interpreter/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore code interpreters could not be listed in region {region} ({error}); verify manually that each one does not use PUBLIC network mode."
            findings.append(report)
        for code_interpreter in bedrockagentcore_client.code_interpreters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=code_interpreter
            )

            if not code_interpreter.detail_retrieved:
                # GetCodeInterpreter failed (permissions, throttling, transient
                # error). Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore code interpreter {code_interpreter.name} network configuration could not be retrieved in region {code_interpreter.region}; verify manually that its network mode is not PUBLIC."
                findings.append(report)
                continue

            if code_interpreter.network_mode == "PUBLIC":
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore code interpreter {code_interpreter.name} uses PUBLIC network mode in region {code_interpreter.region}."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore code interpreter {code_interpreter.name} does not use PUBLIC network mode in region {code_interpreter.region}."
            findings.append(report)

        for browser in bedrockagentcore_client.browsers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=browser)

            if not browser.detail_retrieved:
                # GetBrowser failed (permissions, throttling, transient error).
                # Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} network configuration could not be retrieved in region {browser.region}; verify manually that its network mode is not PUBLIC."
                findings.append(report)
                continue

            if browser.network_mode == "PUBLIC":
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} uses PUBLIC network mode in region {browser.region}."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} does not use PUBLIC network mode in region {browser.region}."
            findings.append(report)

        return findings
