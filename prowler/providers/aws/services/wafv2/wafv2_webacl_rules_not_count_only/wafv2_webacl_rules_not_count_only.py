from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_rules_not_count_only(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            all_rules = web_acl.rules + web_acl.rule_groups
            # A web ACL with no rules at all is already reported by wafv2_webacl_with_rules.
            if not all_rules:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            if web_acl.default_action_block:
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} blocks requests by default, so its rules do not need a blocking action."
            elif any(rule.is_enforcing for rule in all_rules):
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} has at least one rule or rule group that can block matching requests."
            else:
                report.status = "FAIL"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} only counts matching requests, so no rule or rule group blocks them."

            findings.append(report)

        return findings
