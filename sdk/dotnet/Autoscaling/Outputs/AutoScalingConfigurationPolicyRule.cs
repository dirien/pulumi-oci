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
    public sealed class AutoScalingConfigurationPolicyRule
    {
        /// <summary>
        /// The action to take when autoscaling is triggered.
        /// </summary>
        public readonly Outputs.AutoScalingConfigurationPolicyRuleAction? Action;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource that is managed by the autoscaling configuration.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// Metric and threshold details for triggering an autoscaling action.
        /// </summary>
        public readonly Outputs.AutoScalingConfigurationPolicyRuleMetric? Metric;

        [OutputConstructor]
        private AutoScalingConfigurationPolicyRule(
            Outputs.AutoScalingConfigurationPolicyRuleAction? action,

            string displayName,

            string? id,

            Outputs.AutoScalingConfigurationPolicyRuleMetric? metric)
        {
            Action = action;
            DisplayName = displayName;
            Id = id;
            Metric = metric;
        }
    }
}
