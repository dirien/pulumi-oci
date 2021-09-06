// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetRegions
    {
        /// <summary>
        /// This data source provides the list of Regions in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists all the regions offered by Oracle Cloud Infrastructure.
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
        ///         var testRegions = Output.Create(Oci.Identity.GetRegions.InvokeAsync());
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRegionsResult> InvokeAsync(GetRegionsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRegionsResult>("oci:identity/getRegions:getRegions", args ?? new GetRegionsArgs(), options.WithVersion());
    }


    public sealed class GetRegionsArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetRegionsFilterArgs>? _filters;
        public List<Inputs.GetRegionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRegionsFilterArgs>());
            set => _filters = value;
        }

        public GetRegionsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRegionsResult
    {
        public readonly ImmutableArray<Outputs.GetRegionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of regions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegionsRegionResult> Regions;

        [OutputConstructor]
        private GetRegionsResult(
            ImmutableArray<Outputs.GetRegionsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetRegionsRegionResult> regions)
        {
            Filters = filters;
            Id = id;
            Regions = regions;
        }
    }
}
