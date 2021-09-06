// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeployEnvironmentComputeInstanceGroupSelectorsItemArgs : Pulumi.ResourceArgs
    {
        [Input("computeInstanceIds")]
        private InputList<string>? _computeInstanceIds;

        /// <summary>
        /// (Updatable) Compute instance OCID identifiers that are members of this group.
        /// </summary>
        public InputList<string> ComputeInstanceIds
        {
            get => _computeInstanceIds ?? (_computeInstanceIds = new InputList<string>());
            set => _computeInstanceIds = value;
        }

        /// <summary>
        /// (Updatable) Query expression confirming to the Oracle Cloud Infrastructure Search Language syntax to select compute instances for the group. The language is documented at https://docs.oracle.com/en-us/iaas/Content/Search/Concepts/querysyntax.htm
        /// </summary>
        [Input("query")]
        public Input<string>? Query { get; set; }

        /// <summary>
        /// (Updatable) Region identifier referred by the deployment environment. Region identifiers are listed at https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
        /// </summary>
        [Input("region")]
        public Input<string>? Region { get; set; }

        /// <summary>
        /// (Updatable) Defines the type of the instance selector for the group.
        /// </summary>
        [Input("selectorType", required: true)]
        public Input<string> SelectorType { get; set; } = null!;

        public DeployEnvironmentComputeInstanceGroupSelectorsItemArgs()
        {
        }
    }
}
