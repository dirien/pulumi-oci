// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class NodePoolNodeConfigDetailsGetArgs : Pulumi.ResourceArgs
    {
        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// (Updatable) The OCIDs of the Network Security Group(s) to associate nodes for this node pool with. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        [Input("placementConfigs", required: true)]
        private InputList<Inputs.NodePoolNodeConfigDetailsPlacementConfigGetArgs>? _placementConfigs;

        /// <summary>
        /// (Updatable) The placement configurations for the node pool. Provide one placement configuration for each availability domain in which you intend to launch a node.
        /// </summary>
        public InputList<Inputs.NodePoolNodeConfigDetailsPlacementConfigGetArgs> PlacementConfigs
        {
            get => _placementConfigs ?? (_placementConfigs = new InputList<Inputs.NodePoolNodeConfigDetailsPlacementConfigGetArgs>());
            set => _placementConfigs = value;
        }

        /// <summary>
        /// (Updatable) The number of nodes that should be in the node pool.
        /// </summary>
        [Input("size", required: true)]
        public Input<int> Size { get; set; } = null!;

        public NodePoolNodeConfigDetailsGetArgs()
        {
        }
    }
}
