// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Inputs
{

    public sealed class AutoScalingConfigurationPolicyResourceActionGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The action to take when autoscaling is triggered.
        /// </summary>
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        /// <summary>
        /// The type of resource action.
        /// </summary>
        [Input("actionType", required: true)]
        public Input<string> ActionType { get; set; } = null!;

        public AutoScalingConfigurationPolicyResourceActionGetArgs()
        {
        }
    }
}
