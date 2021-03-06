// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetResponderRecipe
    {
        /// <summary>
        /// This data source provides details about a specific Responder Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Get a ResponderRecipe by identifier
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testResponderRecipe = Output.Create(Oci.CloudGuard.GetResponderRecipe.InvokeAsync(new Oci.CloudGuard.GetResponderRecipeArgs
        ///         {
        ///             ResponderRecipeId = oci_cloud_guard_responder_recipe.Test_responder_recipe.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetResponderRecipeResult> InvokeAsync(GetResponderRecipeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetResponderRecipeResult>("oci:cloudguard/getResponderRecipe:getResponderRecipe", args ?? new GetResponderRecipeArgs(), options.WithVersion());
    }


    public sealed class GetResponderRecipeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of ResponderRecipe
        /// </summary>
        [Input("responderRecipeId", required: true)]
        public string ResponderRecipeId { get; set; } = null!;

        public GetResponderRecipeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetResponderRecipeResult
    {
        /// <summary>
        /// Compartment Identifier
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// ResponderRule Description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// ResponderRule Display Name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// List of responder rules associated with the recipe
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResponderRecipeEffectiveResponderRuleResult> EffectiveResponderRules;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Identifier for ResponderRecipe.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Owner of ResponderRecipe
        /// </summary>
        public readonly string Owner;
        public readonly string ResponderRecipeId;
        /// <summary>
        /// List of responder rules associated with the recipe
        /// </summary>
        public readonly ImmutableArray<Outputs.GetResponderRecipeResponderRuleResult> ResponderRules;
        /// <summary>
        /// The id of the source responder recipe.
        /// </summary>
        public readonly string SourceResponderRecipeId;
        /// <summary>
        /// The current state of the Example.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time the responder recipe was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the responder recipe was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetResponderRecipeResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableArray<Outputs.GetResponderRecipeEffectiveResponderRuleResult> effectiveResponderRules,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string owner,

            string responderRecipeId,

            ImmutableArray<Outputs.GetResponderRecipeResponderRuleResult> responderRules,

            string sourceResponderRecipeId,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            EffectiveResponderRules = effectiveResponderRules;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Owner = owner;
            ResponderRecipeId = responderRecipeId;
            ResponderRules = responderRules;
            SourceResponderRecipeId = sourceResponderRecipeId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
