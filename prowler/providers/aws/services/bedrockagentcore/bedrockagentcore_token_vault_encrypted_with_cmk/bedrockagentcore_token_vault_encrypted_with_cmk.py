from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_token_vault_encrypted_with_cmk(Check):
    """Ensure the Bedrock AgentCore token vault is encrypted with a customer managed key.

    - PASS: The AgentCore token vault KMS key type is CustomerManagedKey.
    - FAIL: The AgentCore token vault KMS key type is not CustomerManagedKey.
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
            bedrockagentcore_client.token_vaults_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "token-vault/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:token-vault/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore token vaults could not be listed in region {region} ({error}); verify manually that each one is encrypted with a customer managed KMS key."
            findings.append(report)
        for vault in bedrockagentcore_client.token_vaults.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=vault)
            if not vault.detail_retrieved or not vault.kms_key_type:
                # keyType is a required member of the GetTokenVault response, so
                # an absent value means the response did not carry one rather
                # than that the vault uses a service-managed key.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} encryption configuration could not be retrieved in region {vault.region}; verify manually that it is encrypted with a customer managed KMS key."
                findings.append(report)
                continue

            if vault.kms_key_type == "CustomerManagedKey":
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} is encrypted with a customer managed KMS key in region {vault.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} is not encrypted with a customer managed KMS key in region {vault.region}."
            findings.append(report)

        return findings
