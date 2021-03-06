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
    public sealed class GetNodePoolsNodePoolResult
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        public readonly string ClusterId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The OCID of the compute instance backing this node.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of key/value pairs to add to nodes after they join the Kubernetes cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolsNodePoolInitialNodeLabelResult> InitialNodeLabels;
        /// <summary>
        /// The version of Kubernetes this node is running.
        /// </summary>
        public readonly string KubernetesVersion;
        /// <summary>
        /// The name to filter on.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The configuration of nodes in the node pool.
        /// </summary>
        public readonly Outputs.GetNodePoolsNodePoolNodeConfigDetailsResult NodeConfigDetails;
        /// <summary>
        /// Deprecated. see `nodeSource`. The OCID of the image running on the nodes in the node pool.
        /// </summary>
        public readonly string NodeImageId;
        /// <summary>
        /// Deprecated. see `nodeSource`. The name of the image running on the nodes in the node pool.
        /// </summary>
        public readonly string NodeImageName;
        /// <summary>
        /// A list of key/value pairs to add to each underlying Oracle Cloud Infrastructure instance in the node pool on launch.
        /// </summary>
        public readonly ImmutableDictionary<string, object> NodeMetadata;
        /// <summary>
        /// The OCID of the node pool to which this node belongs.
        /// </summary>
        public readonly string NodePoolId;
        /// <summary>
        /// The name of the node shape of the nodes in the node pool.
        /// </summary>
        public readonly string NodeShape;
        /// <summary>
        /// The shape configuration of the nodes.
        /// </summary>
        public readonly Outputs.GetNodePoolsNodePoolNodeShapeConfigResult NodeShapeConfig;
        /// <summary>
        /// Deprecated. see `nodeSourceDetails`. Source running on the nodes in the node pool.
        /// </summary>
        public readonly Outputs.GetNodePoolsNodePoolNodeSourceResult NodeSource;
        /// <summary>
        /// Source running on the nodes in the node pool.
        /// </summary>
        public readonly Outputs.GetNodePoolsNodePoolNodeSourceDetailsResult NodeSourceDetails;
        /// <summary>
        /// The nodes in the node pool.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNodePoolsNodePoolNodeResult> Nodes;
        /// <summary>
        /// The number of nodes in each subnet.
        /// </summary>
        public readonly int QuantityPerSubnet;
        /// <summary>
        /// The SSH public key on each node in the node pool on launch.
        /// </summary>
        public readonly string SshPublicKey;
        /// <summary>
        /// The OCIDs of the subnets in which to place nodes for this node pool.
        /// </summary>
        public readonly ImmutableArray<string> SubnetIds;

        [OutputConstructor]
        private GetNodePoolsNodePoolResult(
            string clusterId,

            string compartmentId,

            string id,

            ImmutableArray<Outputs.GetNodePoolsNodePoolInitialNodeLabelResult> initialNodeLabels,

            string kubernetesVersion,

            string name,

            Outputs.GetNodePoolsNodePoolNodeConfigDetailsResult nodeConfigDetails,

            string nodeImageId,

            string nodeImageName,

            ImmutableDictionary<string, object> nodeMetadata,

            string nodePoolId,

            string nodeShape,

            Outputs.GetNodePoolsNodePoolNodeShapeConfigResult nodeShapeConfig,

            Outputs.GetNodePoolsNodePoolNodeSourceResult nodeSource,

            Outputs.GetNodePoolsNodePoolNodeSourceDetailsResult nodeSourceDetails,

            ImmutableArray<Outputs.GetNodePoolsNodePoolNodeResult> nodes,

            int quantityPerSubnet,

            string sshPublicKey,

            ImmutableArray<string> subnetIds)
        {
            ClusterId = clusterId;
            CompartmentId = compartmentId;
            Id = id;
            InitialNodeLabels = initialNodeLabels;
            KubernetesVersion = kubernetesVersion;
            Name = name;
            NodeConfigDetails = nodeConfigDetails;
            NodeImageId = nodeImageId;
            NodeImageName = nodeImageName;
            NodeMetadata = nodeMetadata;
            NodePoolId = nodePoolId;
            NodeShape = nodeShape;
            NodeShapeConfig = nodeShapeConfig;
            NodeSource = nodeSource;
            NodeSourceDetails = nodeSourceDetails;
            Nodes = nodes;
            QuantityPerSubnet = quantityPerSubnet;
            SshPublicKey = sshPublicKey;
            SubnetIds = subnetIds;
        }
    }
}
