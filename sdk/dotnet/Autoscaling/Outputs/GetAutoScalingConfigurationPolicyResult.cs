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
    public sealed class GetAutoScalingConfigurationPolicyResult
    {
        /// <summary>
        /// The capacity requirements of the autoscaling policy.
        /// </summary>
        public readonly Outputs.GetAutoScalingConfigurationPolicyCapacityResult Capacity;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The schedule for executing the autoscaling policy.
        /// </summary>
        public readonly Outputs.GetAutoScalingConfigurationPolicyExecutionScheduleResult ExecutionSchedule;
        /// <summary>
        /// ID of the condition that is assigned after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether the autoscaling policy is enabled.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// The type of autoscaling policy.
        /// </summary>
        public readonly string PolicyType;
        /// <summary>
        /// An action that can be executed against a resource.
        /// </summary>
        public readonly Outputs.GetAutoScalingConfigurationPolicyResourceActionResult ResourceAction;
        public readonly ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleResult> Rules;
        /// <summary>
        /// The date and time the autoscaling configuration was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetAutoScalingConfigurationPolicyResult(
            Outputs.GetAutoScalingConfigurationPolicyCapacityResult capacity,

            string displayName,

            Outputs.GetAutoScalingConfigurationPolicyExecutionScheduleResult executionSchedule,

            string id,

            bool isEnabled,

            string policyType,

            Outputs.GetAutoScalingConfigurationPolicyResourceActionResult resourceAction,

            ImmutableArray<Outputs.GetAutoScalingConfigurationPolicyRuleResult> rules,

            string timeCreated)
        {
            Capacity = capacity;
            DisplayName = displayName;
            ExecutionSchedule = executionSchedule;
            Id = id;
            IsEnabled = isEnabled;
            PolicyType = policyType;
            ResourceAction = resourceAction;
            Rules = rules;
            TimeCreated = timeCreated;
        }
    }
}
