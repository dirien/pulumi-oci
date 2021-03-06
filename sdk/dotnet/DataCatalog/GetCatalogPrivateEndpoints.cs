// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataCatalog
{
    public static class GetCatalogPrivateEndpoints
    {
        /// <summary>
        /// This data source provides the list of Catalog Private Endpoints in Oracle Cloud Infrastructure Data Catalog service.
        /// 
        /// Returns a list of all the catalog private endpoints in the specified compartment.
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
        ///         var testCatalogPrivateEndpoints = Output.Create(Oci.DataCatalog.GetCatalogPrivateEndpoints.InvokeAsync(new Oci.DataCatalog.GetCatalogPrivateEndpointsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Catalog_private_endpoint_display_name,
        ///             State = @var.Catalog_private_endpoint_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCatalogPrivateEndpointsResult> InvokeAsync(GetCatalogPrivateEndpointsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCatalogPrivateEndpointsResult>("oci:datacatalog/getCatalogPrivateEndpoints:getCatalogPrivateEndpoints", args ?? new GetCatalogPrivateEndpointsArgs(), options.WithVersion());
    }


    public sealed class GetCatalogPrivateEndpointsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment where you want to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetCatalogPrivateEndpointsFilterArgs>? _filters;
        public List<Inputs.GetCatalogPrivateEndpointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCatalogPrivateEndpointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetCatalogPrivateEndpointsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCatalogPrivateEndpointsResult
    {
        /// <summary>
        /// The list of catalog_private_endpoints.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCatalogPrivateEndpointsCatalogPrivateEndpointResult> CatalogPrivateEndpoints;
        /// <summary>
        /// Identifier of the compartment this private endpoint belongs to
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Mutable name of the Private Reverse Connection Endpoint
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetCatalogPrivateEndpointsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the private endpoint resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetCatalogPrivateEndpointsResult(
            ImmutableArray<Outputs.GetCatalogPrivateEndpointsCatalogPrivateEndpointResult> catalogPrivateEndpoints,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetCatalogPrivateEndpointsFilterResult> filters,

            string id,

            string? state)
        {
            CatalogPrivateEndpoints = catalogPrivateEndpoints;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
