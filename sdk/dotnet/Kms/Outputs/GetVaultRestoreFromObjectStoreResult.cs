// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class GetVaultRestoreFromObjectStoreResult
    {
        /// <summary>
        /// Name of the bucket where vault was backed up
        /// </summary>
        public readonly string Bucket;
        /// <summary>
        /// Type of backup to restore from. Values of "BUCKET", "PRE_AUTHENTICATED_REQUEST_URI" are supported
        /// </summary>
        public readonly string Destination;
        /// <summary>
        /// Namespace of the bucket where vault was backed up
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Object containing the backup
        /// </summary>
        public readonly string Object;
        /// <summary>
        /// Pre-authenticated-request-uri of the backup
        /// </summary>
        public readonly string Uri;

        [OutputConstructor]
        private GetVaultRestoreFromObjectStoreResult(
            string bucket,

            string destination,

            string @namespace,

            string @object,

            string uri)
        {
            Bucket = bucket;
            Destination = destination;
            Namespace = @namespace;
            Object = @object;
            Uri = uri;
        }
    }
}
