// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetAutonomousDatabasesClonesAutonomousDatabaseBackupConfigResult
    {
        /// <summary>
        /// Name of [Object Storage](https://docs.cloud.oracle.com/iaas/Content/Object/Concepts/objectstorageoverview.htm) bucket to use for storing manual backups.
        /// </summary>
        public readonly string ManualBackupBucketName;
        /// <summary>
        /// The manual backup destination type.
        /// </summary>
        public readonly string ManualBackupType;

        [OutputConstructor]
        private GetAutonomousDatabasesClonesAutonomousDatabaseBackupConfigResult(
            string manualBackupBucketName,

            string manualBackupType)
        {
            ManualBackupBucketName = manualBackupBucketName;
            ManualBackupType = manualBackupType;
        }
    }
}
