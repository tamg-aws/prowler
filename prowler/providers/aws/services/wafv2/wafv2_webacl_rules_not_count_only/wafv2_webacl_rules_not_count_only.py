from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_rules_not_count_only(Check):
    def execute(self):
        """Report on whether anything in each Web ACL can block a matching request.

        One enforcing rule is enough, so the verdict does not depend on the order rules are
        evaluated in, and a Web ACL with no rules at all is skipped rather than reported.

        A Web ACL whose rule inventory could not be retrieved is reported MANUAL rather than skipped.
        The order matters: an unread inventory presents as an empty rule list, so the no-rules skip
        below would otherwise swallow it and the Web ACL would produce no finding at all.

        Returns:
            One report per Web ACL that has rules: PASS when it blocks by default or any one rule or
            rule group can block, FAIL when every one of them only counts, MANUAL when the rules
            could not be read.
        """
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            if web_acl.rules_retrieved is None:
                # GetWebACL never returned a rule inventory, so an empty rule list here means
                # unknown rather than absent. The sibling check on this PR,
                # wafv2_webacl_anti_ddos_rule_group_attached, reports the same state the same way.
                report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)
                report.status = "MANUAL"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} rules could not be retrieved, so whether any rule or rule group can block matching requests cannot be determined."
                findings.append(report)
                continue

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
