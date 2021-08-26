// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleDetailsConfigurationGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Unique name of the configuration
        /// </summary>
        [Input("configKey")]
        public Input<string>? ConfigKey { get; set; }

        /// <summary>
        /// (Updatable) configuration data type
        /// </summary>
        [Input("dataType")]
        public Input<string>? DataType { get; set; }

        /// <summary>
        /// (Updatable) configuration name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) configuration value
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        [Input("values")]
        private InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueGetArgs>? _values;

        /// <summary>
        /// (Updatable) List of configuration values
        /// </summary>
        public InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueGetArgs> Values
        {
            get => _values ?? (_values = new InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueGetArgs>());
            set => _values = value;
        }

        public DetectorRecipeEffectiveDetectorRuleDetailsConfigurationGetArgs()
        {
        }
    }
}
