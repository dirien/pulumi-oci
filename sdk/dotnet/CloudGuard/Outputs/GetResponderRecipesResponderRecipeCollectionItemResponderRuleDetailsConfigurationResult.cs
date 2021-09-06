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
    public sealed class GetResponderRecipesResponderRecipeCollectionItemResponderRuleDetailsConfigurationResult
    {
        /// <summary>
        /// Unique name of the configuration
        /// </summary>
        public readonly string ConfigKey;
        /// <summary>
        /// configuration name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// configuration value
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetResponderRecipesResponderRecipeCollectionItemResponderRuleDetailsConfigurationResult(
            string configKey,

            string name,

            string value)
        {
            ConfigKey = configKey;
            Name = name;
            Value = value;
        }
    }
}
