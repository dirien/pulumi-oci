// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics
{
    public static class GetPublicVantagePoints
    {
        /// <summary>
        /// This data source provides the list of Public Vantage Points in Oracle Cloud Infrastructure Apm Synthetics service.
        /// 
        /// Returns a list of public vantage points.
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
        ///         var testPublicVantagePoints = Output.Create(Oci.ApmSynthetics.GetPublicVantagePoints.InvokeAsync(new Oci.ApmSynthetics.GetPublicVantagePointsArgs
        ///         {
        ///             ApmDomainId = oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
        ///             DisplayName = @var.Public_vantage_point_display_name,
        ///             Name = @var.Public_vantage_point_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPublicVantagePointsResult> InvokeAsync(GetPublicVantagePointsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPublicVantagePointsResult>("oci:apmsynthetics/getPublicVantagePoints:getPublicVantagePoints", args ?? new GetPublicVantagePointsArgs(), options.WithVersion());
    }


    public sealed class GetPublicVantagePointsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetPublicVantagePointsFilterArgs>? _filters;
        public List<Inputs.GetPublicVantagePointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPublicVantagePointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetPublicVantagePointsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPublicVantagePointsResult
    {
        public readonly string ApmDomainId;
        /// <summary>
        /// Unique name that can be edited. The name should not contain any confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetPublicVantagePointsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Unique permanent name of the vantage point.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of public_vantage_point_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPublicVantagePointsPublicVantagePointCollectionResult> PublicVantagePointCollections;

        [OutputConstructor]
        private GetPublicVantagePointsResult(
            string apmDomainId,

            string? displayName,

            ImmutableArray<Outputs.GetPublicVantagePointsFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<Outputs.GetPublicVantagePointsPublicVantagePointCollectionResult> publicVantagePointCollections)
        {
            ApmDomainId = apmDomainId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Name = name;
            PublicVantagePointCollections = publicVantagePointCollections;
        }
    }
}
