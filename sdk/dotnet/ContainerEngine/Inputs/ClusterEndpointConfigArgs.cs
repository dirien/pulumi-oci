// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ClusterEndpointConfigArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether the cluster should be assigned a public IP address. Defaults to false. If set to true on a private subnet, the cluster provisioning will fail.
        /// </summary>
        [Input("isPublicIpEnabled")]
        public Input<bool>? IsPublicIpEnabled { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// A list of the OCIDs of the network security groups (NSGs) to apply to the cluster endpoint. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of the regional subnet in which to place the Cluster endpoint.
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        public ClusterEndpointConfigArgs()
        {
        }
    }
}
