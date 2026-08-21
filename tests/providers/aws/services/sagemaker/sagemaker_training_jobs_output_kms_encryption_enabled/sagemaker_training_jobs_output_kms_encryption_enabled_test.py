from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import TrainingJob
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_training_job = "test-training-job"
training_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:training-job/{test_training_job}"
output_kms_key_id = str(uuid4())

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_output_kms_encryption_enabled.sagemaker_training_jobs_output_kms_encryption_enabled"


class Test_sagemaker_training_jobs_output_kms_encryption_enabled:
    def _run(self, training_jobs):
        sagemaker_client = mock.MagicMock()
        sagemaker_client.sagemaker_training_jobs = training_jobs

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_training_jobs_output_kms_encryption_enabled.sagemaker_training_jobs_output_kms_encryption_enabled import (
                sagemaker_training_jobs_output_kms_encryption_enabled,
            )

            return sagemaker_training_jobs_output_kms_encryption_enabled().execute()

    def test_no_training_jobs(self):
        assert len(self._run([])) == 0

    def test_output_kms_key_configured(self):
        result = self._run(
            [
                TrainingJob(
                    name=test_training_job,
                    arn=training_job_arn,
                    region=AWS_REGION_EU_WEST_1,
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"SageMaker training job {test_training_job} encrypts its output artifacts with KMS key {output_kms_key_id}."
        )
        assert result[0].resource_id == test_training_job
        assert result[0].resource_arn == training_job_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_output_kms_key_missing(self):
        result = self._run(
            [
                TrainingJob(
                    name=test_training_job,
                    arn=training_job_arn,
                    region=AWS_REGION_EU_WEST_1,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker training job {test_training_job} does not encrypt its output artifacts with a KMS key."
        )
        assert result[0].resource_id == test_training_job
        assert result[0].resource_arn == training_job_arn

    def test_output_data_config_unreadable(self):
        result = self._run(
            [
                TrainingJob(
                    name=test_training_job,
                    arn=training_job_arn,
                    region=AWS_REGION_EU_WEST_1,
                    output_config_scan_failed=True,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"SageMaker training job {test_training_job} output data configuration could not be read; manual review is required."
        )
        assert result[0].resource_id == test_training_job
        assert result[0].resource_arn == training_job_arn

    def test_unreadable_takes_precedence_over_a_stale_key(self):
        """A scan failure must never report PASS, even if a key value is present."""
        result = self._run(
            [
                TrainingJob(
                    name=test_training_job,
                    arn=training_job_arn,
                    region=AWS_REGION_EU_WEST_1,
                    output_kms_key_id=output_kms_key_id,
                    output_config_scan_failed=True,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
