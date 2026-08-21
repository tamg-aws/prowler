from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client

SAGEMAKER_ENDPOINT_SERVICES = {
    "sagemaker.api": "SageMaker AI control plane",
    "sagemaker.runtime": "SageMaker AI runtime (InvokeEndpoint)",
}


class sagemaker_vpc_endpoints_configured(Check):
    """Ensure interface VPC endpoints are configured for the SageMaker AI APIs.

    Verifies that each VPC in a region holding SageMaker AI resources has
    available interface VPC endpoints for the control plane (`sagemaker.api`) and
    the inference runtime (`sagemaker.runtime`), so calls to those APIs stay on the
    AWS network instead of egressing via an internet or NAT gateway. The FIPS
    variant of either service name satisfies the same requirement.
    - PASS: the VPC has endpoints for both SageMaker AI services.
    - FAIL: the VPC is missing one or both.
    VPCs in regions holding no SageMaker AI resource are skipped.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report per in-scope VPC, with status PASS or FAIL.
        """
        findings = []
        sagemaker_regions = self._get_sagemaker_active_regions()

        for vpc_id, vpc in vpc_client.vpcs.items():
            if not (vpc_client.provider.scan_unused_services or vpc.in_use):
                continue

            if vpc.region not in sagemaker_regions:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
            report.status = "FAIL"

            found_services = set()

            for endpoint in vpc_client.vpc_endpoints:
                if (
                    endpoint.vpc_id != vpc_id
                    or endpoint.state != "available"
                    or endpoint.type != "Interface"
                ):
                    continue
                for svc_suffix in SAGEMAKER_ENDPOINT_SERVICES:
                    # `sagemaker.api-fips` and `sagemaker.runtime-fips` reach the same
                    # API over PrivateLink, so either spelling satisfies the service.
                    if endpoint.service_name.endswith(
                        f".{svc_suffix}"
                    ) or endpoint.service_name.endswith(f".{svc_suffix}-fips"):
                        found_services.add(svc_suffix)

            missing_services = set(SAGEMAKER_ENDPOINT_SERVICES) - found_services

            if not missing_services:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC {vpc.id} has VPC endpoints for all SageMaker AI services."
                )
            else:
                missing_labels = [
                    SAGEMAKER_ENDPOINT_SERVICES[svc] for svc in sorted(missing_services)
                ]
                report.status_extended = f"VPC {vpc.id} does not have VPC endpoints for the following SageMaker AI services: {', '.join(missing_labels)}."

            findings.append(report)

        return findings

    @staticmethod
    def _get_sagemaker_active_regions() -> set[str]:
        """Return regions holding at least one SageMaker AI resource.

        Deliberately reads only real inventory. `sagemaker_model_registries` and
        `sagemaker_monitoring_schedules` are excluded because their collectors
        append one synthetic record per scanned region whether or not anything
        exists, which would put every region in scope.
        """
        active_regions = set()

        for collection in (
            sagemaker_client.sagemaker_notebook_instances,
            sagemaker_client.sagemaker_models,
            sagemaker_client.sagemaker_training_jobs,
            sagemaker_client.sagemaker_processing_jobs,
            sagemaker_client.sagemaker_transform_jobs,
            sagemaker_client.sagemaker_domains,
        ):
            for resource in collection:
                active_regions.add(resource.region)

        for endpoint_config in sagemaker_client.endpoint_configs.values():
            active_regions.add(endpoint_config.region)

        return active_regions
