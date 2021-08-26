// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) compartment associated with condition
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("condition", required: true)]
        public Input<string> Condition { get; set; } = null!;

        public TargetTargetDetectorRecipeDetectorRuleDetailsConditionGroupGetArgs()
        {
        }
    }
}
