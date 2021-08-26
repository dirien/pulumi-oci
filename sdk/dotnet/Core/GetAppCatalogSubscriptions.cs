// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetAppCatalogSubscriptions
    {
        /// <summary>
        /// This data source provides the list of App Catalog Subscriptions in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists subscriptions for a compartment.
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
        ///         var testAppCatalogSubscriptions = Output.Create(Oci.Core.GetAppCatalogSubscriptions.InvokeAsync(new Oci.Core.GetAppCatalogSubscriptionsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             ListingId = data.Oci_core_app_catalog_listing.Test_listing.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAppCatalogSubscriptionsResult> InvokeAsync(GetAppCatalogSubscriptionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAppCatalogSubscriptionsResult>("oci:core/getAppCatalogSubscriptions:getAppCatalogSubscriptions", args ?? new GetAppCatalogSubscriptionsArgs(), options.WithVersion());
    }


    public sealed class GetAppCatalogSubscriptionsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetAppCatalogSubscriptionsFilterArgs>? _filters;
        public List<Inputs.GetAppCatalogSubscriptionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAppCatalogSubscriptionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the listings that matches the given listing id.
        /// </summary>
        [Input("listingId")]
        public string? ListingId { get; set; }

        public GetAppCatalogSubscriptionsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAppCatalogSubscriptionsResult
    {
        /// <summary>
        /// The list of app_catalog_subscriptions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAppCatalogSubscriptionsAppCatalogSubscriptionResult> AppCatalogSubscriptions;
        /// <summary>
        /// The compartmentID of the subscription.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetAppCatalogSubscriptionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The ocid of the listing resource.
        /// </summary>
        public readonly string? ListingId;

        [OutputConstructor]
        private GetAppCatalogSubscriptionsResult(
            ImmutableArray<Outputs.GetAppCatalogSubscriptionsAppCatalogSubscriptionResult> appCatalogSubscriptions,

            string compartmentId,

            ImmutableArray<Outputs.GetAppCatalogSubscriptionsFilterResult> filters,

            string id,

            string? listingId)
        {
            AppCatalogSubscriptions = appCatalogSubscriptions;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ListingId = listingId;
        }
    }
}
