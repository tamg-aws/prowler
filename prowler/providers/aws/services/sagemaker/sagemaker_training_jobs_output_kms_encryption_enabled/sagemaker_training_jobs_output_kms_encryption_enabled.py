from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_training_jobs_output_kms_encryption_enabled(Check):
    """Ensure SageMaker training jobs encrypt their output artifacts with a KMS key.

    Reads `OutputDataConfig.KmsKeyId` from `DescribeTrainingJob`, the key that
    encrypts the model artifacts the job writes to Amazon S3. This is a different
    field from `ResourceConfig.VolumeKmsKeyId`, which covers only the ML storage
    volume attached to the training instance.
    - PASS: the job declares an output KMS key.
    - FAIL: the job declares no output KMS key, so artifacts fall back to the
      account's default Amazon S3 KMS key.
    - MANUAL: `OutputDataConfig` could not be read.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report per SageMaker training job, with status PASS, FAIL or MANUAL.
        """
        findings = []
        for training_job in sagemaker_client.sagemaker_training_jobs:
            report = Check_Report_AWS(metadata=self.metadata(), resource=training_job)
            if training_job.output_config_scan_failed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker training job {training_job.name} output data "
                    f"configuration could not be read; manual review is required."
                )
            elif training_job.output_kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker training job {training_job.name} encrypts its output "
                    f"artifacts with KMS key {training_job.output_kms_key_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker training job {training_job.name} does not encrypt its "
                    f"output artifacts with a KMS key."
                )
            findings.append(report)

        return findings
