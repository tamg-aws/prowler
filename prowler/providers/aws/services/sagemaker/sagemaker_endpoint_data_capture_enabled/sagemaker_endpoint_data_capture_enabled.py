from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_endpoint_data_capture_enabled(Check):
    """Ensure SageMaker endpoint configurations capture inference data.

    Reads `DataCaptureConfig` from `DescribeEndpointConfig`. Data capture writes
    the inference requests and responses served by the endpoint to Amazon S3, and
    is the prerequisite for SageMaker Model Monitor: without it a monitoring
    schedule has nothing to baseline drift or anomalous behaviour against.
    - PASS: data capture is on for the endpoint configuration.
    - FAIL: no `DataCaptureConfig`, or capture is explicitly disabled.
    - MANUAL: the endpoint configuration could not be described.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report per SageMaker endpoint configuration, with status PASS, FAIL
            or MANUAL.
        """
        findings = []
        for endpoint_config in sagemaker_client.endpoint_configs.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=endpoint_config
            )
            if (
                endpoint_config.data_capture_scan_failed
                or endpoint_config.data_capture_enabled is None
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker endpoint configuration {endpoint_config.name} data "
                    f"capture configuration could not be read; manual review is "
                    f"required."
                )
            elif endpoint_config.data_capture_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker endpoint configuration {endpoint_config.name} has data "
                    f"capture enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker endpoint configuration {endpoint_config.name} does not "
                    f"have data capture enabled."
                )
            findings.append(report)

        return findings
