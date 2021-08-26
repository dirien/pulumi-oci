// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDrgRouteDistributions
    {
        /// <summary>
        /// This data source provides the list of Drg Route Distributions in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the route distributions in the specified DRG.
        /// 
        /// To retrieve the statements in a distribution, use the
        /// ListDrgRouteDistributionStatements operation.
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
        ///         var testDrgRouteDistributions = Output.Create(Oci.Core.GetDrgRouteDistributions.InvokeAsync(new Oci.Core.GetDrgRouteDistributionsArgs
        ///         {
        ///             DrgId = oci_core_drg.Test_drg.Id,
        ///             DisplayName = @var.Drg_route_distribution_display_name,
        ///             State = @var.Drg_route_distribution_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDrgRouteDistributionsResult> InvokeAsync(GetDrgRouteDistributionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDrgRouteDistributionsResult>("oci:core/getDrgRouteDistributions:getDrgRouteDistributions", args ?? new GetDrgRouteDistributionsArgs(), options.WithVersion());
    }


    public sealed class GetDrgRouteDistributionsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
        /// </summary>
        [Input("drgId", required: true)]
        public string DrgId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetDrgRouteDistributionsFilterArgs>? _filters;
        public List<Inputs.GetDrgRouteDistributionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDrgRouteDistributionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter that only returns resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetDrgRouteDistributionsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDrgRouteDistributionsResult
    {
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG that contains this route distribution.
        /// </summary>
        public readonly string DrgId;
        /// <summary>
        /// The list of drg_route_distributions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrgRouteDistributionsDrgRouteDistributionResult> DrgRouteDistributions;
        public readonly ImmutableArray<Outputs.GetDrgRouteDistributionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The route distribution's current state.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetDrgRouteDistributionsResult(
            string? displayName,

            string drgId,

            ImmutableArray<Outputs.GetDrgRouteDistributionsDrgRouteDistributionResult> drgRouteDistributions,

            ImmutableArray<Outputs.GetDrgRouteDistributionsFilterResult> filters,

            string id,

            string? state)
        {
            DisplayName = displayName;
            DrgId = drgId;
            DrgRouteDistributions = drgRouteDistributions;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
