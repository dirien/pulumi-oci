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
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricResult
    {
        public readonly string MetricType;
        public readonly Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThresholdResult Threshold;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricResult(
            string metricType,

            Outputs.GetAutoScalingConfigurationsAutoScalingConfigurationPolicyRuleMetricThresholdResult threshold)
        {
            MetricType = metricType;
            Threshold = threshold;
        }
    }
}
