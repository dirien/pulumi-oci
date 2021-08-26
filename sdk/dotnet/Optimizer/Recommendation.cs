// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer
{
    /// <summary>
    /// This resource provides the Recommendation resource in Oracle Cloud Infrastructure Optimizer service.
    /// 
    /// Updates the recommendation that corresponds to the specified OCID.
    /// Use this operation to implement the following actions:
    /// 
    ///   * Postpone recommendation
    ///   * Dismiss recommendation
    ///   * Reactivate recommendation
    /// 
    /// ## Import
    /// 
    /// Recommendations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:optimizer/recommendation:Recommendation test_recommendation "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:optimizer/recommendation:Recommendation")]
    public partial class Recommendation : Pulumi.CustomResource
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Output("categoryId")]
        public Output<string> CategoryId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the tenancy. The tenancy is the root compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Text describing the recommendation.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The estimated cost savings, in dollars, for the recommendation.
        /// </summary>
        [Output("estimatedCostSaving")]
        public Output<double> EstimatedCostSaving { get; private set; } = null!;

        /// <summary>
        /// The level of importance assigned to the recommendation.
        /// </summary>
        [Output("importance")]
        public Output<string> Importance { get; private set; } = null!;

        /// <summary>
        /// The name of the profile level.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        [Output("recommendationId")]
        public Output<string> RecommendationId { get; private set; } = null!;

        /// <summary>
        /// An array of `ResourceCount` objects grouped by the status of the resource actions.
        /// </summary>
        [Output("resourceCounts")]
        public Output<ImmutableArray<Outputs.RecommendationResourceCount>> ResourceCounts { get; private set; } = null!;

        /// <summary>
        /// The recommendation's current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The status of the recommendation.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// Optional. The profile levels supported by a recommendation. For example, profile level values could be `Low`, `Medium`, and `High`. Not all recommendations support this field.
        /// </summary>
        [Output("supportedLevels")]
        public Output<Outputs.RecommendationSupportedLevels> SupportedLevels { get; private set; } = null!;

        /// <summary>
        /// The date and time the recommendation details were created, in the format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time that the recommendation entered its current status. The format is defined by RFC3339.
        /// </summary>
        [Output("timeStatusBegin")]
        public Output<string> TimeStatusBegin { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The date and time the current status will change. The format is defined by RFC3339.
        /// </summary>
        [Output("timeStatusEnd")]
        public Output<string> TimeStatusEnd { get; private set; } = null!;

        /// <summary>
        /// The date and time the recommendation details were last updated, in the format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a Recommendation resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Recommendation(string name, RecommendationArgs args, CustomResourceOptions? options = null)
            : base("oci:optimizer/recommendation:Recommendation", name, args ?? new RecommendationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Recommendation(string name, Input<string> id, RecommendationState? state = null, CustomResourceOptions? options = null)
            : base("oci:optimizer/recommendation:Recommendation", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Recommendation resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Recommendation Get(string name, Input<string> id, RecommendationState? state = null, CustomResourceOptions? options = null)
        {
            return new Recommendation(name, id, state, options);
        }
    }

    public sealed class RecommendationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        [Input("recommendationId", required: true)]
        public Input<string> RecommendationId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The status of the recommendation.
        /// </summary>
        [Input("status", required: true)]
        public Input<string> Status { get; set; } = null!;

        /// <summary>
        /// (Updatable) The date and time the current status will change. The format is defined by RFC3339.
        /// </summary>
        [Input("timeStatusEnd")]
        public Input<string>? TimeStatusEnd { get; set; }

        public RecommendationArgs()
        {
        }
    }

    public sealed class RecommendationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique OCID associated with the category.
        /// </summary>
        [Input("categoryId")]
        public Input<string>? CategoryId { get; set; }

        /// <summary>
        /// The OCID of the tenancy. The tenancy is the root compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Text describing the recommendation.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The estimated cost savings, in dollars, for the recommendation.
        /// </summary>
        [Input("estimatedCostSaving")]
        public Input<double>? EstimatedCostSaving { get; set; }

        /// <summary>
        /// The level of importance assigned to the recommendation.
        /// </summary>
        [Input("importance")]
        public Input<string>? Importance { get; set; }

        /// <summary>
        /// The name of the profile level.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The unique OCID associated with the recommendation.
        /// </summary>
        [Input("recommendationId")]
        public Input<string>? RecommendationId { get; set; }

        [Input("resourceCounts")]
        private InputList<Inputs.RecommendationResourceCountGetArgs>? _resourceCounts;

        /// <summary>
        /// An array of `ResourceCount` objects grouped by the status of the resource actions.
        /// </summary>
        public InputList<Inputs.RecommendationResourceCountGetArgs> ResourceCounts
        {
            get => _resourceCounts ?? (_resourceCounts = new InputList<Inputs.RecommendationResourceCountGetArgs>());
            set => _resourceCounts = value;
        }

        /// <summary>
        /// The recommendation's current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) The status of the recommendation.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// Optional. The profile levels supported by a recommendation. For example, profile level values could be `Low`, `Medium`, and `High`. Not all recommendations support this field.
        /// </summary>
        [Input("supportedLevels")]
        public Input<Inputs.RecommendationSupportedLevelsGetArgs>? SupportedLevels { get; set; }

        /// <summary>
        /// The date and time the recommendation details were created, in the format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time that the recommendation entered its current status. The format is defined by RFC3339.
        /// </summary>
        [Input("timeStatusBegin")]
        public Input<string>? TimeStatusBegin { get; set; }

        /// <summary>
        /// (Updatable) The date and time the current status will change. The format is defined by RFC3339.
        /// </summary>
        [Input("timeStatusEnd")]
        public Input<string>? TimeStatusEnd { get; set; }

        /// <summary>
        /// The date and time the recommendation details were last updated, in the format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public RecommendationState()
        {
        }
    }
}
