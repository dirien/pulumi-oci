// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Inputs
{

    public sealed class ContainerengineNodePoolNodeArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain in which to place nodes. Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// An error that may be associated with the node.
        /// </summary>
        [Input("error")]
        public Input<Inputs.ContainerengineNodePoolNodeErrorArgs>? Error { get; set; }

        /// <summary>
        /// The fault domain of this node.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        /// <summary>
        /// The OCID of the compute instance backing this node.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// (Updatable) The version of Kubernetes to install on the nodes in the node pool.
        /// </summary>
        [Input("kubernetesVersion")]
        public Input<string>? KubernetesVersion { get; set; }

        /// <summary>
        /// Details about the state of the node.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) The name of the node pool. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The OCID of the node pool to which this node belongs.
        /// </summary>
        [Input("nodePoolId")]
        public Input<string>? NodePoolId { get; set; }

        /// <summary>
        /// The private IP address of this node.
        /// </summary>
        [Input("privateIp")]
        public Input<string>? PrivateIp { get; set; }

        /// <summary>
        /// The public IP address of this node.
        /// </summary>
        [Input("publicIp")]
        public Input<string>? PublicIp { get; set; }

        /// <summary>
        /// The state of the node.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the subnet in which to place nodes.
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        public ContainerengineNodePoolNodeArgs()
        {
        }
    }
}