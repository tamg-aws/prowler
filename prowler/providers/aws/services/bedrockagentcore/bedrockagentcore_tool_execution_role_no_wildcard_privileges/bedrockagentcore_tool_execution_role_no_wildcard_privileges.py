from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    check_admin_access,
    check_full_service_access,
)
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)

# Services an agent-directed sandbox most plausibly reaches for data or further
# credentials. A service-wide grant on any of these (for example s3:*) is not
# caught by check_admin_access, which only fires when an Allow reaches "*".
SENSITIVE_SERVICES = [
    "s3",
    "dynamodb",
    "secretsmanager",
    "ssm",
    "kms",
    "iam",
    "sts",
    "bedrock",
    "bedrock-agentcore",
    "lambda",
]


class bedrockagentcore_tool_execution_role_no_wildcard_privileges(Check):
    """Ensure Bedrock AgentCore built-in tool execution roles avoid wildcard privileges.

    Code interpreter and browser tools run agent-directed code, so any code in the
    sandbox can use the tool's execution role. The role is evaluated for:

    - No AWS-managed ``*FullAccess`` policy attached.
    - No attached or inline policy granting administrative access, service-wide
      access to a sensitive service, or a known privilege escalation combination.

    - PASS: No attached or inline policy of the tool's execution role individually
      grants any of the above, and every one of its documents could be read. The
      qualifier is load-bearing rather than cautious: a privilege escalation
      combination needs every one of its actions inside a single document to be
      detected, and 71 of the 101 known combinations take two or more actions, so a
      combination split across two of the role's policies is not seen here.
    - FAIL: At least one of the role's attached or inline policies grants one of the
      above. Each document is evaluated on its own and they are not aggregated, so
      this is a property of a policy on the role and not of the role's effective
      permissions, which are the union of the Allows minus the union of the Denies.
      A grant that was read is definite, so FAIL stands even if another document
      could not be retrieved.
    - MANUAL: GetCodeInterpreter or GetBrowser failed, so the tool's
      ``executionRoleArn`` is unknown and an absent value cannot be read as "no
      execution role attached"; or the tool names a role that is absent from the
      IAM inventory, which is unknown rather than a violation; or ``iam:ListRoles``
      was denied, so the inventory itself is unknown; or the policies that could
      be read hold no
      wildcard grant but at least one document could not be retrieved from the
      IAM inventory, which is precisely where such a grant would hide; or the
      Region's tool inventory could not be listed.
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
            report.status_extended = f"Bedrock AgentCore browsers could not be listed in region {region} ({error}); verify manually that each one has an execution role without wildcard privileges."
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
            report.status_extended = f"Bedrock AgentCore code interpreters could not be listed in region {region} ({error}); verify manually that each one has an execution role without wildcard privileges."
            findings.append(report)
        if iam_client.roles is None:
            # ListRoles was denied, so the IAM inventory is unknown rather than empty. Treating it
            # as empty would resolve every execution role to None below. This is the only check in
            # this PR that reads iam_client, so there is no sibling to be consistent with.
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.role_arn_template
            report.status = "MANUAL"
            report.status_extended = "IAM roles could not be listed, so no execution role could be evaluated for wildcard privileges; verify manually."
            findings.append(report)
            return findings

        roles_by_arn = {role.arn: role for role in iam_client.roles}

        tools = [
            ("code interpreter", tool)
            for tool in bedrockagentcore_client.code_interpreters.values()
        ] + [("browser", tool) for tool in bedrockagentcore_client.browsers.values()]

        for tool_kind, tool in tools:
            report = Check_Report_AWS(metadata=self.metadata(), resource=tool)

            if not tool.detail_retrieved:
                # GetCodeInterpreter/GetBrowser failed (permissions, throttling,
                # transient error). An absent execution role ARN is not evidence
                # that no role is attached.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} execution role could not be retrieved in region {tool.region}; verify manually that it grants no administrative, service-wide, or privilege escalation access."
                findings.append(report)
                continue

            if not tool.execution_role_arn:
                # A tool with no execution role cannot assume anything, so there
                # are no permissions to over-grant.
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} has no execution role attached in region {tool.region}."
                findings.append(report)
                continue

            role = roles_by_arn.get(tool.execution_role_arn)
            if role is None:
                # Present in the tool inventory but absent from the IAM inventory: unknown, not a
                # violation. The previous FAIL asserted a verdict the same sentence disclaimed.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} execution role could not be resolved in IAM and cannot be evaluated for wildcard privileges in region {tool.region}."
                findings.append(report)
                continue

            violations = []
            # A document that could not be read is exactly where an over-broad
            # grant would hide, so it is tracked rather than skipped: the role
            # cannot be called clean on the strength of the policies that did
            # resolve.
            unresolved = []

            for policy in role.attached_policies:
                policy_arn = policy.get("PolicyArn", "")
                policy_name = policy.get("PolicyName") or policy_arn
                # Match on the suffix, not an "arn:aws:" prefix: AWS-managed policy ARNs are
                # arn:aws-us-gov: and arn:aws-cn: in the other partitions, and the fall-through
                # below only tests SENSITIVE_SERVICES, so a *FullAccess policy for a service
                # outside that list would PASS there.
                if ":iam::aws:policy/" in policy_arn and policy_arn.endswith(
                    "FullAccess"
                ):
                    violations.append(
                        f"managed policy {policy_name} grants full access"
                    )
                    continue
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"managed policy {policy_name}")
                    continue
                violations.extend(
                    self._evaluate_document(
                        policy_obj.document, f"managed policy {policy_name}"
                    )
                )

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    unresolved.append(f"inline policy {inline_name}")
                    continue
                violations.extend(
                    self._evaluate_document(
                        policy_obj.document, f"inline policy {inline_name}"
                    )
                )

            if violations:
                # A wildcard grant that was read is a definite finding, so it
                # stands whatever else could not be read.
                violations.sort()
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} execution role has an attached or inline policy granting wildcard privileges in region {tool.region}: {'; '.join(violations)}."
            elif unresolved:
                unresolved.sort()
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} execution role {role.name} has no wildcard privileges in the policies that could be read in region {tool.region}, but {', '.join(unresolved)} could not be retrieved from the IAM inventory; verify manually that it grants no administrative, service-wide, or privilege escalation access."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore {tool_kind} {tool.name} execution role has no attached or inline policy individually granting wildcard privileges in region {tool.region}."

            findings.append(report)

        return findings

    def _evaluate_document(self, document: dict, label: str) -> list:
        """Evaluate a single policy document for over-broad grants.

        Args:
            document: The IAM policy document.
            label: How to refer to this policy in the finding text.

        Returns:
            A list of violation strings, empty when the document is acceptable.
        """
        if check_admin_access(document):
            return [f"{label} grants administrative access"]

        service_violations = [
            f"{label} grants full access to {service}"
            for service in SENSITIVE_SERVICES
            if check_full_service_access(service, document)
        ]
        if service_violations:
            return service_violations

        if check_privilege_escalation(document):
            return [f"{label} allows privilege escalation"]

        return []
