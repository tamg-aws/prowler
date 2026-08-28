from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_browser_session_recording_enabled(Check):
    """Ensure Bedrock AgentCore browser tools have session recording enabled.

    - PASS: The AgentCore browser has session recording enabled.
    - FAIL: The AgentCore browser does not have session recording enabled.
    - MANUAL: GetBrowser failed, so the recording configuration is unknown and
      cannot be reported as either enabled or disabled.
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
            report.status_extended = f"Bedrock AgentCore browsers could not be listed in region {region} ({error}); verify manually that each one records its sessions to Amazon S3."
            findings.append(report)
        for browser in bedrockagentcore_client.browsers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=browser)

            if not browser.detail_retrieved:
                # GetBrowser failed (permissions, throttling, transient error).
                # Do not assert compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} session recording configuration could not be retrieved in region {browser.region}; verify manually that session recording is enabled and directed to an S3 destination."
                findings.append(report)
                continue

            if browser.recording_enabled is True:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} has session recording enabled in region {browser.region}."
            elif browser.recording_enabled is None:
                # The browser reports a recording configuration but no explicit
                # enabled flag. It is an optional member with no documented
                # default, so reading it as false would FAIL a browser that may
                # in fact be recording.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} has a session recording configuration that does not report whether recording is enabled in region {browser.region}; verify manually that sessions are recorded to an S3 destination."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore browser {browser.name} does not have session recording enabled in region {browser.region}."
            findings.append(report)

        return findings
