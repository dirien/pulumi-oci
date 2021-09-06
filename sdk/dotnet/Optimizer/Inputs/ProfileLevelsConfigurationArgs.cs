// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Inputs
{

    public sealed class ProfileLevelsConfigurationArgs : Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.ProfileLevelsConfigurationItemArgs>? _items;

        /// <summary>
        /// (Updatable) The list of target tags attached to the current profile override.
        /// </summary>
        public InputList<Inputs.ProfileLevelsConfigurationItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.ProfileLevelsConfigurationItemArgs>());
            set => _items = value;
        }

        public ProfileLevelsConfigurationArgs()
        {
        }
    }
}
