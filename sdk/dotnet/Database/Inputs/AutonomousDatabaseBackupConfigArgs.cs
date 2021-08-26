// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousDatabaseBackupConfigArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of [Object Storage](https://docs.cloud.oracle.com/iaas/Content/Object/Concepts/objectstorageoverview.htm) bucket to use for storing manual backups.
        /// </summary>
        [Input("manualBackupBucketName")]
        public Input<string>? ManualBackupBucketName { get; set; }

        /// <summary>
        /// The manual backup destination type.
        /// </summary>
        [Input("manualBackupType")]
        public Input<string>? ManualBackupType { get; set; }

        public AutonomousDatabaseBackupConfigArgs()
        {
        }
    }
}
