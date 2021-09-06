// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class VolumeBackupSourceDetailsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the KMS key in the destination region which will be the master encryption key for the copied volume backup.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The region of the volume backup source.
        /// </summary>
        [Input("region", required: true)]
        public Input<string> Region { get; set; } = null!;

        /// <summary>
        /// The OCID of the source volume backup.
        /// </summary>
        [Input("volumeBackupId", required: true)]
        public Input<string> VolumeBackupId { get; set; } = null!;

        public VolumeBackupSourceDetailsGetArgs()
        {
        }
    }
}
