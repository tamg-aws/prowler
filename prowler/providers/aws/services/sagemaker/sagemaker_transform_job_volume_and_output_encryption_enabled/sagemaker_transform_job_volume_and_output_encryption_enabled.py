from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client

# TransformResources.VolumeKmsKeyId, botocore 1.40.61: "Certain Nitro-based instances
# include local storage, dependent on the instance type. Local storage volumes are
# encrypted using a hardware module on the instance. You can't request a
# VolumeKmsKeyId when using an instance type with local storage."
#
# So on these families the volume IS encrypted and no KMS key can be set -- asserting
# one would report an encrypted volume as unencrypted. Derived by taking every family
# in the pinned TransformInstanceType enum and reading InstanceStorageSupported from
# ec2:DescribeInstanceTypes: g4dn, g5 and trn1 report true; c4, c5, c6i, c7i, inf2,
# m4, m5, m6i, m7i, r6i and r7i report false; p2 and p3 are retired from EC2 and were
# EBS-only. Matched on the family prefix so every size is covered.
LOCAL_STORAGE_INSTANCE_FAMILIES = ("ml.g4dn.", "ml.g5.", "ml.trn1.")


class sagemaker_transform_job_volume_and_output_encryption_enabled(Check):
    """Ensure SageMaker batch transform jobs encrypt their volume and output with KMS.

    Reads both encryption keys `DescribeTransformJob` returns:
    `TransformResources.VolumeKmsKeyId` for the ML storage volume the job runs on,
    and `TransformOutput.KmsKeyId` for the inference results it writes to Amazon S3.
    Batch transform is a separate resource type from training jobs and real-time
    endpoints, so their encryption checks say nothing about it.

    On an instance type with local storage the volume clause is not asserted, because
    SageMaker AI rejects a `VolumeKmsKeyId` there and the volume is already encrypted
    by a hardware module on the instance; the report says so rather than staying silent.
    - PASS: every key that can be set is set.
    - FAIL: a settable key is missing; the report names which.
    - MANUAL: the job's encryption configuration could not be read.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            One report per SageMaker transform job, with status PASS, FAIL or MANUAL.
        """
        findings = []
        for transform_job in sagemaker_client.sagemaker_transform_jobs:
            report = Check_Report_AWS(metadata=self.metadata(), resource=transform_job)
            # Without the instance type the volume clause cannot be decided, so an
            # unresolved one is MANUAL rather than an assumed non-local-storage FAIL.
            if (
                transform_job.encryption_config_scan_failed
                or transform_job.instance_type is None
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} encryption "
                    f"configuration could not be read; manual review is required."
                )
                findings.append(report)
                continue

            unencrypted = []
            volume_note = ""
            if transform_job.instance_type.startswith(LOCAL_STORAGE_INSTANCE_FAMILIES):
                volume_note = (
                    f" Its compute volume runs on {transform_job.instance_type}, whose "
                    f"local instance storage is encrypted by a hardware module on the "
                    f"instance and takes no KMS key."
                )
            elif not transform_job.volume_kms_key_id:
                unencrypted.append("compute volume")
            if not transform_job.output_kms_key_id:
                unencrypted.append("output")

            if unencrypted:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} does not use a KMS "
                    f"key for its {' and '.join(unencrypted)}.{volume_note}"
                )
            else:
                encrypted = (
                    "its output"
                    if volume_note
                    else "both its compute volume and its output"
                )
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} uses a KMS key for "
                    f"{encrypted}.{volume_note}"
                )
            findings.append(report)

        return findings
