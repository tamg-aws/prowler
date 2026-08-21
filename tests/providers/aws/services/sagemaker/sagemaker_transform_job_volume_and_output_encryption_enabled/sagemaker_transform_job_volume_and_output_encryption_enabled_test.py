from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import TransformJob
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_transform_job = "test-transform-job"
transform_job_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:transform-job/{test_transform_job}"
volume_kms_key_id = str(uuid4())
output_kms_key_id = str(uuid4())

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_and_output_encryption_enabled.sagemaker_transform_job_volume_and_output_encryption_enabled"


class Test_sagemaker_transform_job_volume_and_output_encryption_enabled:
    def _run(self, transform_jobs):
        sagemaker_client = mock.MagicMock()
        sagemaker_client.sagemaker_transform_jobs = transform_jobs

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_transform_job_volume_and_output_encryption_enabled.sagemaker_transform_job_volume_and_output_encryption_enabled import (
                sagemaker_transform_job_volume_and_output_encryption_enabled,
            )

            return (
                sagemaker_transform_job_volume_and_output_encryption_enabled().execute()
            )

    @staticmethod
    def _transform_job(**kwargs):
        kwargs.setdefault("instance_type", "ml.m5.large")
        return TransformJob(
            name=test_transform_job,
            arn=transform_job_arn,
            region=AWS_REGION_EU_WEST_1,
            **kwargs,
        )

    def test_no_transform_jobs(self):
        assert len(self._run([])) == 0

    def test_both_keys_configured(self):
        result = self._run(
            [
                self._transform_job(
                    volume_kms_key_id=volume_kms_key_id,
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} uses a KMS key for both its compute volume and its output."
        )
        assert result[0].resource_id == test_transform_job
        assert result[0].resource_arn == transform_job_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_both_keys_missing(self):
        result = self._run([self._transform_job()])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} does not use a KMS key for its compute volume and output."
        )
        assert result[0].resource_id == test_transform_job
        assert result[0].resource_arn == transform_job_arn

    def test_volume_key_missing_only(self):
        result = self._run([self._transform_job(output_kms_key_id=output_kms_key_id)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} does not use a KMS key for its compute volume."
        )

    def test_output_key_missing_only(self):
        result = self._run([self._transform_job(volume_kms_key_id=volume_kms_key_id)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} does not use a KMS key for its output."
        )

    def test_encryption_config_unreadable(self):
        result = self._run([self._transform_job(encryption_config_scan_failed=True)])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} encryption configuration could not be read; manual review is required."
        )
        assert result[0].resource_id == test_transform_job
        assert result[0].resource_arn == transform_job_arn

    def test_unreadable_takes_precedence_over_stale_keys(self):
        """A scan failure must never report PASS, even if key values are present."""
        result = self._run(
            [
                self._transform_job(
                    volume_kms_key_id=volume_kms_key_id,
                    output_kms_key_id=output_kms_key_id,
                    encryption_config_scan_failed=True,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_multiple_jobs_report_independently(self):
        second_job = "test-transform-job-2"
        second_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:transform-job/{second_job}"
        result = self._run(
            [
                self._transform_job(
                    volume_kms_key_id=volume_kms_key_id,
                    output_kms_key_id=output_kms_key_id,
                ),
                TransformJob(
                    name=second_job,
                    arn=second_arn,
                    region=AWS_REGION_EU_WEST_1,
                    instance_type="ml.m5.large",
                    volume_kms_key_id=volume_kms_key_id,
                ),
            ]
        )
        assert len(result) == 2
        assert [r.status for r in result] == ["PASS", "FAIL"]
        assert [r.resource_arn for r in result] == [transform_job_arn, second_arn]

    def test_local_storage_instance_without_volume_key_passes(self):
        """SageMaker AI rejects a VolumeKmsKeyId here, so its absence is not a finding."""
        result = self._run(
            [
                self._transform_job(
                    instance_type="ml.g5.48xlarge",
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"SageMaker transform job {test_transform_job} uses a KMS key for its "
            f"output. Its compute volume runs on ml.g5.48xlarge, whose local instance "
            f"storage is encrypted by a hardware module on the instance and takes no "
            f"KMS key."
        )

    def test_non_local_storage_instance_without_volume_key_fails(self):
        """The same missing key on a family that accepts one is still a finding."""
        result = self._run(
            [
                self._transform_job(
                    instance_type="ml.m5.large",
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} does not use a KMS key for its compute volume."
        )

    def test_local_storage_instance_still_fails_on_the_output_key(self):
        """Exempting the volume must not exempt the output."""
        result = self._run([self._transform_job(instance_type="ml.g4dn.xlarge")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"SageMaker transform job {test_transform_job} does not use a KMS key for "
            f"its output. Its compute volume runs on ml.g4dn.xlarge, whose local "
            f"instance storage is encrypted by a hardware module on the instance and "
            f"takes no KMS key."
        )

    def test_every_local_storage_family_is_exempt(self):
        """One representative size per exempt family, so a dropped family fails here."""
        for instance_type in ("ml.g4dn.12xlarge", "ml.g5.xlarge", "ml.trn1.32xlarge"):
            result = self._run(
                [
                    self._transform_job(
                        instance_type=instance_type,
                        output_kms_key_id=output_kms_key_id,
                    )
                ]
            )
            assert result[0].status == "PASS", instance_type
            assert instance_type in result[0].status_extended

    def test_families_without_local_storage_are_not_exempt(self):
        """inf2 reports InstanceStorageSupported=false, so it must not be exempted."""
        for instance_type in ("ml.inf2.48xlarge", "ml.c5.xlarge", "ml.p3.2xlarge"):
            result = self._run(
                [
                    self._transform_job(
                        instance_type=instance_type,
                        output_kms_key_id=output_kms_key_id,
                    )
                ]
            )
            assert result[0].status == "FAIL", instance_type
            assert "compute volume" in result[0].status_extended

    def test_prefix_match_is_bounded_to_a_whole_family(self):
        """A family that merely starts with an exempt family's name is not exempt.

        `g5g` and `trn1` differ from `g5` and `trn1n`, and ec2:DescribeInstanceTypes
        reports g5g.* as InstanceStorageSupported=false, so it does take a volume key.
        Without the trailing dot in the family prefixes, `ml.g5` would match
        `ml.g5g.2xlarge` and wrongly exempt it.
        """
        result = self._run(
            [
                self._transform_job(
                    instance_type="ml.g5g.2xlarge",
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker transform job {test_transform_job} does not use a KMS key for its compute volume."
        )

    def test_unknown_instance_type_is_manual_not_fail(self):
        """The volume clause cannot be decided without the instance type."""
        result = self._run(
            [
                TransformJob(
                    name=test_transform_job,
                    arn=transform_job_arn,
                    region=AWS_REGION_EU_WEST_1,
                    output_kms_key_id=output_kms_key_id,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
