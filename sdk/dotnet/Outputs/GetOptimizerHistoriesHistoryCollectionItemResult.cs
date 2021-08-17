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
    public sealed class GetOptimizerHistoriesHistoryCollectionItemResult
    {
        /// <summary>
        /// Details about the recommended action.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOptimizerHistoriesHistoryCollectionItemActionResult> Actions;
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        public readonly string CategoryId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name assigned to the compartment.
        /// </summary>
        public readonly string CompartmentName;
        /// <summary>
        /// The estimated cost savings, in dollars, for the resource action.
        /// </summary>
        public readonly double EstimatedCostSaving;
        /// <summary>
        /// Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
        /// </summary>
        public readonly ImmutableDictionary<string, object> ExtendedMetadata;
        /// <summary>
        /// The unique OCID associated with the recommendation history.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Custom metadata key/value pairs for the resource action.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Metadata;
        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        public readonly string RecommendationId;
        /// <summary>
        /// Optional. A filter that returns results that match the recommendation name specified.
        /// </summary>
        public readonly string RecommendationName;
        /// <summary>
        /// The unique OCID associated with the resource action.
        /// </summary>
        public readonly string ResourceActionId;
        /// <summary>
        /// The unique OCID associated with the resource.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// Optional. A filter that returns results that match the resource type specified.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// A filter that returns results that match the lifecycle state specified.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// A filter that returns recommendations that match the status specified.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The date and time the recommendation history was created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetOptimizerHistoriesHistoryCollectionItemResult(
            ImmutableArray<Outputs.GetOptimizerHistoriesHistoryCollectionItemActionResult> actions,

            string categoryId,

            string compartmentId,

            string compartmentName,

            double estimatedCostSaving,

            ImmutableDictionary<string, object> extendedMetadata,

            string id,

            ImmutableDictionary<string, object> metadata,

            string name,

            string recommendationId,

            string recommendationName,

            string resourceActionId,

            string resourceId,

            string resourceType,

            string state,

            string status,

            string timeCreated)
        {
            Actions = actions;
            CategoryId = categoryId;
            CompartmentId = compartmentId;
            CompartmentName = compartmentName;
            EstimatedCostSaving = estimatedCostSaving;
            ExtendedMetadata = extendedMetadata;
            Id = id;
            Metadata = metadata;
            Name = name;
            RecommendationId = recommendationId;
            RecommendationName = recommendationName;
            ResourceActionId = resourceActionId;
            ResourceId = resourceId;
            ResourceType = resourceType;
            State = state;
            Status = status;
            TimeCreated = timeCreated;
        }
    }
}