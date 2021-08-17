// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetOptimizerCategoriesCategoryCollectionItemResult
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Text describing the category. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The estimated cost savings, in dollars, for the category.
        /// </summary>
        public readonly double EstimatedCostSaving;
        /// <summary>
        /// The unique OCID of the category.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// An array of `RecommendationCount` objects grouped by the level of importance assigned to the recommendation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOptimizerCategoriesCategoryCollectionItemRecommendationCountResult> RecommendationCounts;
        /// <summary>
        /// An array of `ResourceCount` objects grouped by the status of the recommendation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOptimizerCategoriesCategoryCollectionItemResourceCountResult> ResourceCounts;
        /// <summary>
        /// A filter that returns results that match the lifecycle state specified.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the category details were created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the category details were last updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOptimizerCategoriesCategoryCollectionItemResult(
            string compartmentId,

            string description,

            double estimatedCostSaving,

            string id,

            string name,

            ImmutableArray<Outputs.GetOptimizerCategoriesCategoryCollectionItemRecommendationCountResult> recommendationCounts,

            ImmutableArray<Outputs.GetOptimizerCategoriesCategoryCollectionItemResourceCountResult> resourceCounts,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            Description = description;
            EstimatedCostSaving = estimatedCostSaving;
            Id = id;
            Name = name;
            RecommendationCounts = recommendationCounts;
            ResourceCounts = resourceCounts;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}