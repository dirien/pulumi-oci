// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class VolumeBackupSourceDetails
    {
        /// <summary>
        /// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
        /// </summary>
        public readonly string? KmsKeyId;
        /// <summary>
        /// The region of the volume backup source.
        /// </summary>
        public readonly string Region;
        /// <summary>
        /// The OCID of the source volume backup.
        /// </summary>
        public readonly string VolumeBackupId;

        [OutputConstructor]
        private VolumeBackupSourceDetails(
            string? kmsKeyId,

            string region,

            string volumeBackupId)
        {
            KmsKeyId = kmsKeyId;
            Region = region;
            VolumeBackupId = volumeBackupId;
        }
    }
}
