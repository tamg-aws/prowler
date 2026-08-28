from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

ANTI_DDOS_RULE_GROUP_VENDOR = "AWS"
ANTI_DDOS_RULE_GROUP_NAME = "AWSManagedRulesAntiDDoSRuleSet"


class wafv2_webacl_anti_ddos_rule_group_attached(Check):
    def execute(self):
        """Report on the AWSManagedRulesAntiDDoSRuleSet rule group for every Web ACL.

        A Web ACL whose rules could not be retrieved is reported MANUAL rather than FAIL, because an
        unread rule set is not evidence that the rule group is missing.

        Returns:
            One report per Web ACL: PASS when the rule group is attached and left enforcing, FAIL
            when it is absent or overridden to Count, MANUAL when the rules are unknown.
        """
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            if web_acl.rules_retrieved is None:
                report.status = "MANUAL"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} rules could not be retrieved, so whether the {ANTI_DDOS_RULE_GROUP_NAME} rule group is attached cannot be determined."
                findings.append(report)
                continue

            anti_ddos_rules = [
                rule
                for rule in web_acl.rules + web_acl.rule_groups
                if rule.managed_rule_group_vendor == ANTI_DDOS_RULE_GROUP_VENDOR
                and rule.managed_rule_group_name == ANTI_DDOS_RULE_GROUP_NAME
            ]

            if not anti_ddos_rules:
                report.status = "FAIL"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does not use the {ANTI_DDOS_RULE_GROUP_NAME} rule group, so it has no application-layer DDoS mitigation beyond the always-on baseline."
            elif any(rule.is_enforcing for rule in anti_ddos_rules):
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} uses the {ANTI_DDOS_RULE_GROUP_NAME} rule group and can challenge or block application-layer DDoS traffic."
            else:
                report.status = "FAIL"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} uses the {ANTI_DDOS_RULE_GROUP_NAME} rule group but overrides it to Count, so application-layer DDoS traffic is measured and then served."

            findings.append(report)

        return findings
