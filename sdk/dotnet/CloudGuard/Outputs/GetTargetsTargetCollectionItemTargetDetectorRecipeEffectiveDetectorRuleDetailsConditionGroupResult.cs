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
    public sealed class GetTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRuleDetailsConditionGroupResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string Condition;

        [OutputConstructor]
        private GetTargetsTargetCollectionItemTargetDetectorRecipeEffectiveDetectorRuleDetailsConditionGroupResult(
            string compartmentId,

            string condition)
        {
            CompartmentId = compartmentId;
            Condition = condition;
        }
    }
}
