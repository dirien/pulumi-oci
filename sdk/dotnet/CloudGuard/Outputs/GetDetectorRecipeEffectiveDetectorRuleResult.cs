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
    public sealed class GetDetectorRecipeEffectiveDetectorRuleResult
    {
        /// <summary>
        /// List of CandidateResponderRule related to this rule
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectorRecipeEffectiveDetectorRuleCandidateResponderRuleResult> CandidateResponderRules;
        /// <summary>
        /// Description for DetectorRecipeDetectorRule
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Details of a Detector Rule
        /// </summary>
        public readonly Outputs.GetDetectorRecipeEffectiveDetectorRuleDetailsResult Details;
        /// <summary>
        /// detector for the rule
        /// </summary>
        public readonly string Detector;
        /// <summary>
        /// The unique identifier of the detector rule
        /// </summary>
        public readonly string DetectorRuleId;
        /// <summary>
        /// displayName
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// List of cloudguard managed list types related to this rule
        /// </summary>
        public readonly ImmutableArray<string> ManagedListTypes;
        /// <summary>
        /// Recommendation for DetectorRecipeDetectorRule
        /// </summary>
        public readonly string Recommendation;
        /// <summary>
        /// resource type of the configuration to which the rule is applied
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// service type of the configuration to which the rule is applied
        /// </summary>
        public readonly string ServiceType;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the detector recipe was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the detector recipe was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDetectorRecipeEffectiveDetectorRuleResult(
            ImmutableArray<Outputs.GetDetectorRecipeEffectiveDetectorRuleCandidateResponderRuleResult> candidateResponderRules,

            string description,

            Outputs.GetDetectorRecipeEffectiveDetectorRuleDetailsResult details,

            string detector,

            string detectorRuleId,

            string displayName,

            string lifecycleDetails,

            ImmutableArray<string> managedListTypes,

            string recommendation,

            string resourceType,

            string serviceType,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CandidateResponderRules = candidateResponderRules;
            Description = description;
            Details = details;
            Detector = detector;
            DetectorRuleId = detectorRuleId;
            DisplayName = displayName;
            LifecycleDetails = lifecycleDetails;
            ManagedListTypes = managedListTypes;
            Recommendation = recommendation;
            ResourceType = resourceType;
            ServiceType = serviceType;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
