// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetTagDefaults
    {
        /// <summary>
        /// This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists the tag defaults for tag definitions in the specified compartment.
        /// 
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
        ///         var testTagDefaults = Output.Create(Oci.Identity.GetTagDefaults.InvokeAsync(new Oci.Identity.GetTagDefaultsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Id = @var.Tag_default_id,
        ///             State = @var.Tag_default_state,
        ///             TagDefinitionId = oci_identity_tag_definition.Test_tag_definition.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetTagDefaultsResult> InvokeAsync(GetTagDefaultsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetTagDefaultsResult>("oci:identity/getTagDefaults:getTagDefaults", args ?? new GetTagDefaultsArgs(), options.WithVersion());
    }


    public sealed class GetTagDefaultsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetTagDefaultsFilterArgs>? _filters;
        public List<Inputs.GetTagDefaultsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetTagDefaultsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the specified OCID exactly.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The OCID of the tag definition.
        /// </summary>
        [Input("tagDefinitionId")]
        public string? TagDefinitionId { get; set; }

        public GetTagDefaultsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetTagDefaultsResult
    {
        /// <summary>
        /// The OCID of the compartment. The tag default applies to all new resources that get created in the compartment. Resources that existed before the tag default was created are not tagged.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetTagDefaultsFilterResult> Filters;
        /// <summary>
        /// The OCID of the tag default.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of tag_defaults.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTagDefaultsTagDefaultResult> TagDefaults;
        /// <summary>
        /// The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        /// </summary>
        public readonly string? TagDefinitionId;

        [OutputConstructor]
        private GetTagDefaultsResult(
            string? compartmentId,

            ImmutableArray<Outputs.GetTagDefaultsFilterResult> filters,

            string? id,

            string? state,

            ImmutableArray<Outputs.GetTagDefaultsTagDefaultResult> tagDefaults,

            string? tagDefinitionId)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            State = state;
            TagDefaults = tagDefaults;
            TagDefinitionId = tagDefinitionId;
        }
    }
}
