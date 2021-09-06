// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleCandidateResponderRuleGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) DetectorRecipe Display Name
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Ocid for detector recipe
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// Preferred state
        /// </summary>
        [Input("isPreferred")]
        public Input<bool>? IsPreferred { get; set; }

        public DetectorRecipeEffectiveDetectorRuleCandidateResponderRuleGetArgs()
        {
        }
    }
}
