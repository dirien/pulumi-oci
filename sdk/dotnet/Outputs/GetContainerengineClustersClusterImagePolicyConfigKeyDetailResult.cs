// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetContainerengineClustersClusterImagePolicyConfigKeyDetailResult
    {
        /// <summary>
        /// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption.
        /// </summary>
        public readonly string KmsKeyId;

        [OutputConstructor]
        private GetContainerengineClustersClusterImagePolicyConfigKeyDetailResult(string kmsKeyId)
        {
            KmsKeyId = kmsKeyId;
        }
    }
}