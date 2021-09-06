// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetResponderRecipeResponderRuleDetailsConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Unique name of the configuration
        /// </summary>
        [Input("configKey", required: true)]
        public Input<string> ConfigKey { get; set; } = null!;

        /// <summary>
        /// (Updatable) configuration name
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) configuration value
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public TargetTargetResponderRecipeResponderRuleDetailsConfigurationArgs()
        {
        }
    }
}
