// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetViews
    {
        /// <summary>
        /// This data source provides the list of Views in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all views within a compartment. The collection can
        /// be filtered by display name, id, or lifecycle state. It can be sorted
        /// on creation time or displayName both in ASC or DESC order. Note that
        /// when no lifecycleState query parameter is provided, the collection
        /// does not include views in the DELETED lifecycleState to be consistent
        /// with other operations of the API. Requires a `PRIVATE` scope query parameter.
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
        ///         var testViews = Output.Create(Oci.Dns.GetViews.InvokeAsync(new Oci.Dns.GetViewsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Scope = "PRIVATE",
        ///             DisplayName = @var.View_display_name,
        ///             Id = @var.View_id,
        ///             State = @var.View_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetViewsResult> InvokeAsync(GetViewsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetViewsResult>("oci:dns/getViews:getViews", args ?? new GetViewsArgs(), options.WithVersion());
    }


    public sealed class GetViewsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The displayName of a resource.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetViewsFilterArgs>? _filters;
        public List<Inputs.GetViewsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetViewsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a resource.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// Value must be `PRIVATE` when listing private views.
        /// </summary>
        [Input("scope", required: true)]
        public string Scope { get; set; } = null!;

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetViewsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetViewsResult
    {
        /// <summary>
        /// The OCID of the owning compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The display name of the view.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetViewsFilterResult> Filters;
        /// <summary>
        /// The OCID of the view.
        /// </summary>
        public readonly string? Id;
        public readonly string Scope;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of views.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetViewsViewResult> Views;

        [OutputConstructor]
        private GetViewsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetViewsFilterResult> filters,

            string? id,

            string scope,

            string? state,

            ImmutableArray<Outputs.GetViewsViewResult> views)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Scope = scope;
            State = state;
            Views = views;
        }
    }
}
