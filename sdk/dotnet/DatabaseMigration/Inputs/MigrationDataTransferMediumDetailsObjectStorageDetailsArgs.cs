// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationDataTransferMediumDetailsObjectStorageDetailsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Bucket name.
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// (Updatable) Namespace name of the object store bucket.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        public MigrationDataTransferMediumDetailsObjectStorageDetailsArgs()
        {
        }
    }
}
