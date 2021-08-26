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
    public sealed class DetectorRecipeEffectiveDetectorRuleDetailsConfiguration
    {
        /// <summary>
        /// (Updatable) Unique name of the configuration
        /// </summary>
        public readonly string? ConfigKey;
        /// <summary>
        /// (Updatable) configuration data type
        /// </summary>
        public readonly string? DataType;
        /// <summary>
        /// (Updatable) configuration name
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) configuration value
        /// </summary>
        public readonly string? Value;
        /// <summary>
        /// (Updatable) List of configuration values
        /// </summary>
        public readonly ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValue> Values;

        [OutputConstructor]
        private DetectorRecipeEffectiveDetectorRuleDetailsConfiguration(
            string? configKey,

            string? dataType,

            string? name,

            string? value,

            ImmutableArray<Outputs.DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValue> values)
        {
            ConfigKey = configKey;
            DataType = dataType;
            Name = name;
            Value = value;
            Values = values;
        }
    }
}
