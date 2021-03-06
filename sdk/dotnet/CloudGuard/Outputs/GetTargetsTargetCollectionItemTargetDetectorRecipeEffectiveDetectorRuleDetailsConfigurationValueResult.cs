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
    public sealed class GetTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueResult
    {
        /// <summary>
        /// configuration list item type, either CUSTOM or MANAGED
        /// </summary>
        public readonly string ListType;
        /// <summary>
        /// type of the managed list
        /// </summary>
        public readonly string ManagedListType;
        /// <summary>
        /// configuration value
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRuleDetailsConfigurationValueResult(
            string listType,

            string managedListType,

            string value)
        {
            ListType = listType;
            ManagedListType = managedListType;
            Value = value;
        }
    }
}
