// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataCatalog
{
    public static class GetConnections
    {
        /// <summary>
        /// This data source provides the list of Connections in Oracle Cloud Infrastructure Data Catalog service.
        /// 
        /// Returns a list of all Connections for a data asset.
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
        ///         var testConnections = Output.Create(Oci.DataCatalog.GetConnections.InvokeAsync(new Oci.DataCatalog.GetConnectionsArgs
        ///         {
        ///             CatalogId = oci_datacatalog_catalog.Test_catalog.Id,
        ///             DataAssetKey = @var.Connection_data_asset_key,
        ///             CreatedById = oci_datacatalog_created_by.Test_created_by.Id,
        ///             DisplayName = @var.Connection_display_name,
        ///             DisplayNameContains = @var.Connection_display_name_contains,
        ///             ExternalKey = @var.Connection_external_key,
        ///             Fields = @var.Connection_fields,
        ///             IsDefault = @var.Connection_is_default,
        ///             State = @var.Connection_state,
        ///             TimeCreated = @var.Connection_time_created,
        ///             TimeStatusUpdated = @var.Connection_time_status_updated,
        ///             TimeUpdated = @var.Connection_time_updated,
        ///             UpdatedById = oci_datacatalog_updated_by.Test_updated_by.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetConnectionsResult> InvokeAsync(GetConnectionsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetConnectionsResult>("oci:datacatalog/getConnections:getConnections", args ?? new GetConnectionsArgs(), options.WithVersion());
    }


    public sealed class GetConnectionsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique catalog identifier.
        /// </summary>
        [Input("catalogId", required: true)]
        public string CatalogId { get; set; } = null!;

        /// <summary>
        /// OCID of the user who created the resource.
        /// </summary>
        [Input("createdById")]
        public string? CreatedById { get; set; }

        /// <summary>
        /// Unique data asset key.
        /// </summary>
        [Input("dataAssetKey", required: true)]
        public string DataAssetKey { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// A filter to return only resources that match display name pattern given. The match is not case sensitive. For Example : /folders?displayNameContains=Cu.* The above would match all folders with display name that starts with "Cu".
        /// </summary>
        [Input("displayNameContains")]
        public string? DisplayNameContains { get; set; }

        /// <summary>
        /// Unique external identifier of this resource in the external source system.
        /// </summary>
        [Input("externalKey")]
        public string? ExternalKey { get; set; }

        [Input("fields")]
        private List<string>? _fields;

        /// <summary>
        /// Specifies the fields to return in a connection summary response.
        /// </summary>
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private List<Inputs.GetConnectionsFilterArgs>? _filters;
        public List<Inputs.GetConnectionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetConnectionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Indicates whether this connection is the default connection.
        /// </summary>
        [Input("isDefault")]
        public bool? IsDefault { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public string? TimeCreated { get; set; }

        /// <summary>
        /// Time that the resource's status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeStatusUpdated")]
        public string? TimeStatusUpdated { get; set; }

        /// <summary>
        /// Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public string? TimeUpdated { get; set; }

        /// <summary>
        /// OCID of the user who updated the resource.
        /// </summary>
        [Input("updatedById")]
        public string? UpdatedById { get; set; }

        public GetConnectionsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetConnectionsResult
    {
        public readonly string CatalogId;
        /// <summary>
        /// The list of connection_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionsConnectionCollectionResult> ConnectionCollections;
        /// <summary>
        /// OCID of the user who created the connection.
        /// </summary>
        public readonly string? CreatedById;
        /// <summary>
        /// Unique key of the parent data asset.
        /// </summary>
        public readonly string DataAssetKey;
        /// <summary>
        /// A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string? DisplayNameContains;
        /// <summary>
        /// Unique external key of this object from the source system.
        /// </summary>
        public readonly string? ExternalKey;
        public readonly ImmutableArray<string> Fields;
        public readonly ImmutableArray<Outputs.GetConnectionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether this connection is the default connection.
        /// </summary>
        public readonly bool? IsDefault;
        /// <summary>
        /// The current state of the connection.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// Time that the connections status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string? TimeStatusUpdated;
        /// <summary>
        /// The last time that any change was made to the connection. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string? TimeUpdated;
        /// <summary>
        /// OCID of the user who modified the connection.
        /// </summary>
        public readonly string? UpdatedById;

        [OutputConstructor]
        private GetConnectionsResult(
            string catalogId,

            ImmutableArray<Outputs.GetConnectionsConnectionCollectionResult> connectionCollections,

            string? createdById,

            string dataAssetKey,

            string? displayName,

            string? displayNameContains,

            string? externalKey,

            ImmutableArray<string> fields,

            ImmutableArray<Outputs.GetConnectionsFilterResult> filters,

            string id,

            bool? isDefault,

            string? state,

            string? timeCreated,

            string? timeStatusUpdated,

            string? timeUpdated,

            string? updatedById)
        {
            CatalogId = catalogId;
            ConnectionCollections = connectionCollections;
            CreatedById = createdById;
            DataAssetKey = dataAssetKey;
            DisplayName = displayName;
            DisplayNameContains = displayNameContains;
            ExternalKey = externalKey;
            Fields = fields;
            Filters = filters;
            Id = id;
            IsDefault = isDefault;
            State = state;
            TimeCreated = timeCreated;
            TimeStatusUpdated = timeStatusUpdated;
            TimeUpdated = timeUpdated;
            UpdatedById = updatedById;
        }
    }
}
