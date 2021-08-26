// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetDetectorRecipeDetectorRuleDetailsResult
    {
        public readonly string Condition;
        /// <summary>
        /// Configuration details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectorRecipeDetectorRuleDetailsConfigurationResult> Configurations;
        /// <summary>
        /// configuration allowed or not
        /// </summary>
        public readonly bool IsConfigurationAllowed;
        /// <summary>
        /// Enables the control
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// user defined labels for a detector rule
        /// </summary>
        public readonly ImmutableArray<string> Labels;
        /// <summary>
        /// The Risk Level
        /// </summary>
        public readonly string RiskLevel;

        [OutputConstructor]
        private GetDetectorRecipeDetectorRuleDetailsResult(
            string condition,

            ImmutableArray<Outputs.GetDetectorRecipeDetectorRuleDetailsConfigurationResult> configurations,

            bool isConfigurationAllowed,

            bool isEnabled,

            ImmutableArray<string> labels,

            string riskLevel)
        {
            Condition = condition;
            Configurations = configurations;
            IsConfigurationAllowed = isConfigurationAllowed;
            IsEnabled = isEnabled;
            Labels = labels;
            RiskLevel = riskLevel;
        }
    }
}
