// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Outputs
{

    [OutputType]
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleResult
    {
        /// <summary>
        /// The action to take when autoscaling is triggered.
        /// </summary>
        public readonly Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleActionResult Action;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// ID of the condition that is assigned after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Metric and threshold details for triggering an autoscaling action.
        /// </summary>
        public readonly Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricResult Metric;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleResult(
            Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleActionResult action,

            string displayName,

            string id,

            Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricResult metric)
        {
            Action = action;
            DisplayName = displayName;
            Id = id;
            Metric = metric;
        }
    }
}
