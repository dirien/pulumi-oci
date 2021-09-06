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
    public sealed class GetBootVolumeBackupSourceDetailsResult
    {
        /// <summary>
        /// The OCID of the boot volume backup.
        /// </summary>
        public readonly string BootVolumeBackupId;
        /// <summary>
        /// The OCID of the Key Management master encryption assigned to the boot volume backup. For more information about the Key Management service and encryption keys, see [Overview of Key Management](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
        /// </summary>
        public readonly string KmsKeyId;
        public readonly string Region;

        [OutputConstructor]
        private GetBootVolumeBackupSourceDetailsResult(
            string bootVolumeBackupId,

            string kmsKeyId,

            string region)
        {
            BootVolumeBackupId = bootVolumeBackupId;
            KmsKeyId = kmsKeyId;
            Region = region;
        }
    }
}
