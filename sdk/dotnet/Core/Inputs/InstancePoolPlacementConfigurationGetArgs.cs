// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstancePoolPlacementConfigurationGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain to place instances.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        [Input("faultDomains")]
        private InputList<string>? _faultDomains;

        /// <summary>
        /// (Updatable) The fault domains to place instances.
        /// </summary>
        public InputList<string> FaultDomains
        {
            get => _faultDomains ?? (_faultDomains = new InputList<string>());
            set => _faultDomains = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the primary subnet to place instances.
        /// </summary>
        [Input("primarySubnetId", required: true)]
        public Input<string> PrimarySubnetId { get; set; } = null!;

        [Input("secondaryVnicSubnets")]
        private InputList<Inputs.InstancePoolPlacementConfigurationSecondaryVnicSubnetGetArgs>? _secondaryVnicSubnets;

        /// <summary>
        /// (Updatable) The set of secondary VNIC data for instances in the pool.
        /// </summary>
        public InputList<Inputs.InstancePoolPlacementConfigurationSecondaryVnicSubnetGetArgs> SecondaryVnicSubnets
        {
            get => _secondaryVnicSubnets ?? (_secondaryVnicSubnets = new InputList<Inputs.InstancePoolPlacementConfigurationSecondaryVnicSubnetGetArgs>());
            set => _secondaryVnicSubnets = value;
        }

        public InstancePoolPlacementConfigurationGetArgs()
        {
        }
    }
}
