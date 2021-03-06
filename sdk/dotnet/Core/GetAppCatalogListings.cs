// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetAppCatalogListings
    {
        /// <summary>
        /// This data source provides the list of App Catalog Listings in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the published listings.
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
        ///         var testAppCatalogListings = Output.Create(Oci.Core.GetAppCatalogListings.InvokeAsync(new Oci.Core.GetAppCatalogListingsArgs
        ///         {
        ///             DisplayName = @var.App_catalog_listing_display_name,
        ///             PublisherName = @var.App_catalog_listing_publisher_name,
        ///             PublisherType = @var.App_catalog_listing_publisher_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAppCatalogListingsResult> InvokeAsync(GetAppCatalogListingsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAppCatalogListingsResult>("oci:core/getAppCatalogListings:getAppCatalogListings", args ?? new GetAppCatalogListingsArgs(), options.WithVersion());
    }


    public sealed class GetAppCatalogListingsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAppCatalogListingsFilterArgs>? _filters;
        public List<Inputs.GetAppCatalogListingsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAppCatalogListingsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the publisher that matches the given publisher name exactly.
        /// </summary>
        [Input("publisherName")]
        public string? PublisherName { get; set; }

        /// <summary>
        /// A filter to return only publishers that match the given publisher type exactly. Valid types are OCI, ORACLE, TRUSTED, STANDARD.
        /// </summary>
        [Input("publisherType")]
        public string? PublisherType { get; set; }

        public GetAppCatalogListingsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAppCatalogListingsResult
    {
        /// <summary>
        /// The list of app_catalog_listings.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAppCatalogListingsAppCatalogListingResult> AppCatalogListings;
        /// <summary>
        /// The display name of the listing.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAppCatalogListingsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the publisher who published this listing.
        /// </summary>
        public readonly string? PublisherName;
        public readonly string? PublisherType;

        [OutputConstructor]
        private GetAppCatalogListingsResult(
            ImmutableArray<Outputs.GetAppCatalogListingsAppCatalogListingResult> appCatalogListings,

            string? displayName,

            ImmutableArray<Outputs.GetAppCatalogListingsFilterResult> filters,

            string id,

            string? publisherName,

            string? publisherType)
        {
            AppCatalogListings = appCatalogListings;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            PublisherName = publisherName;
            PublisherType = publisherType;
        }
    }
}
