// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeployEnvironmentComputeInstanceGroupSelectorsArgs : Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs>? _items;

        /// <summary>
        /// (Updatable) A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
        /// </summary>
        public InputList<Inputs.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs>());
            set => _items = value;
        }

        public DeployEnvironmentComputeInstanceGroupSelectorsArgs()
        {
        }
    }
}
