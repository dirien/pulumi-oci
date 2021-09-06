// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterEndpointConfigResult
    {
        /// <summary>
        /// Whether the cluster should be assigned a public IP address. Defaults to false. If set to true on a private subnet, the cluster provisioning will fail.
        /// </summary>
        public readonly bool IsPublicIpEnabled;
        /// <summary>
        /// A list of the OCIDs of the network security groups (NSGs) to apply to the cluster endpoint. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The OCID of the regional subnet in which to place the Cluster endpoint.
        /// </summary>
        public readonly string SubnetId;

        [OutputConstructor]
        private GetClustersClusterEndpointConfigResult(
            bool isPublicIpEnabled,

            ImmutableArray<string> nsgIds,

            string subnetId)
        {
            IsPublicIpEnabled = isPublicIpEnabled;
            NsgIds = nsgIds;
            SubnetId = subnetId;
        }
    }
}
