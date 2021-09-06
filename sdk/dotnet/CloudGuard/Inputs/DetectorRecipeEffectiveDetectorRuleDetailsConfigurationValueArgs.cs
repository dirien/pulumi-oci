// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) configuration list item type, either CUSTOM or MANAGED
        /// </summary>
        [Input("listType")]
        public Input<string>? ListType { get; set; }

        /// <summary>
        /// (Updatable) type of the managed list
        /// </summary>
        [Input("managedListType")]
        public Input<string>? ManagedListType { get; set; }

        /// <summary>
        /// (Updatable) configuration value
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueArgs()
        {
        }
    }
}
