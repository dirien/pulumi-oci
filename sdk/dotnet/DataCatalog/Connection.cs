// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataCatalog
{
    /// <summary>
    /// This resource provides the Connection resource in Oracle Cloud Infrastructure Data Catalog service.
    /// 
    /// Creates a new connection.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testConnection = new Oci.DataCatalog.Connection("testConnection", new Oci.DataCatalog.ConnectionArgs
    ///         {
    ///             CatalogId = oci_datacatalog_catalog.Test_catalog.Id,
    ///             DataAssetKey = @var.Connection_data_asset_key,
    ///             DisplayName = @var.Connection_display_name,
    ///             Properties = @var.Connection_properties,
    ///             TypeKey = @var.Connection_type_key,
    ///             Description = @var.Connection_description,
    ///             EncProperties = @var.Connection_enc_properties,
    ///             IsDefault = @var.Connection_is_default,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Connections can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:datacatalog/connection:Connection test_connection "catalogs/{catalogId}/dataAssets/{dataAssetKey}/connections/{connectionKey}"
    /// ```
    /// </summary>
    [OciResourceType("oci:datacatalog/connection:Connection")]
    public partial class Connection : Pulumi.CustomResource
    {
        /// <summary>
        /// Unique catalog identifier.
        /// </summary>
        [Output("catalogId")]
        public Output<string> CatalogId { get; private set; } = null!;

        /// <summary>
        /// OCID of the user who created the connection.
        /// </summary>
        [Output("createdById")]
        public Output<string> CreatedById { get; private set; } = null!;

        /// <summary>
        /// Unique data asset key.
        /// </summary>
        [Output("dataAssetKey")]
        public Output<string> DataAssetKey { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A description of the connection.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A map of maps that contains the encrypted values for sensitive properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. To determine the set of optional and required properties for a connection type, a query can be done on '/types?type=connection' that returns a collection of all connection types. The appropriate connection type, which will include definitions of all of it's properties, can be identified from this collection. Example: `{"encProperties": { "default": { "password": "example-password"}}}`
        /// </summary>
        [Output("encProperties")]
        public Output<ImmutableDictionary<string, object>?> EncProperties { get; private set; } = null!;

        /// <summary>
        /// Unique external key of this object from the source system.
        /// </summary>
        [Output("externalKey")]
        public Output<string> ExternalKey { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates whether this connection is the default connection. The first connection of a data asset defaults to being the default, subsequent connections default to not being the default. If a default connection already exists, then trying to create a connection as the default will fail. In this case the default connection would need to be updated not to be the default and then the new connection can then be created as the default.
        /// </summary>
        [Output("isDefault")]
        public Output<bool> IsDefault { get; private set; } = null!;

        /// <summary>
        /// Unique connection key that is immutable.
        /// </summary>
        [Output("key")]
        public Output<string> Key { get; private set; } = null!;

        /// <summary>
        /// A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        /// </summary>
        [Output("properties")]
        public Output<ImmutableDictionary<string, object>> Properties { get; private set; } = null!;

        /// <summary>
        /// The current state of the connection.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Time that the connections status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Output("timeStatusUpdated")]
        public Output<string> TimeStatusUpdated { get; private set; } = null!;

        /// <summary>
        /// The last time that any change was made to the connection. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The key of the object type. Type key's can be found via the '/types' endpoint.
        /// </summary>
        [Output("typeKey")]
        public Output<string> TypeKey { get; private set; } = null!;

        /// <summary>
        /// OCID of the user who modified the connection.
        /// </summary>
        [Output("updatedById")]
        public Output<string> UpdatedById { get; private set; } = null!;

        /// <summary>
        /// URI to the connection instance in the API.
        /// </summary>
        [Output("uri")]
        public Output<string> Uri { get; private set; } = null!;


        /// <summary>
        /// Create a Connection resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Connection(string name, ConnectionArgs args, CustomResourceOptions? options = null)
            : base("oci:datacatalog/connection:Connection", name, args ?? new ConnectionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Connection(string name, Input<string> id, ConnectionState? state = null, CustomResourceOptions? options = null)
            : base("oci:datacatalog/connection:Connection", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Connection resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Connection Get(string name, Input<string> id, ConnectionState? state = null, CustomResourceOptions? options = null)
        {
            return new Connection(name, id, state, options);
        }
    }

    public sealed class ConnectionArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique catalog identifier.
        /// </summary>
        [Input("catalogId", required: true)]
        public Input<string> CatalogId { get; set; } = null!;

        /// <summary>
        /// Unique data asset key.
        /// </summary>
        [Input("dataAssetKey", required: true)]
        public Input<string> DataAssetKey { get; set; } = null!;

        /// <summary>
        /// (Updatable) A description of the connection.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("encProperties")]
        private InputMap<object>? _encProperties;

        /// <summary>
        /// (Updatable) A map of maps that contains the encrypted values for sensitive properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. To determine the set of optional and required properties for a connection type, a query can be done on '/types?type=connection' that returns a collection of all connection types. The appropriate connection type, which will include definitions of all of it's properties, can be identified from this collection. Example: `{"encProperties": { "default": { "password": "example-password"}}}`
        /// </summary>
        public InputMap<object> EncProperties
        {
            get => _encProperties ?? (_encProperties = new InputMap<object>());
            set => _encProperties = value;
        }

        /// <summary>
        /// (Updatable) Indicates whether this connection is the default connection. The first connection of a data asset defaults to being the default, subsequent connections default to not being the default. If a default connection already exists, then trying to create a connection as the default will fail. In this case the default connection would need to be updated not to be the default and then the new connection can then be created as the default.
        /// </summary>
        [Input("isDefault")]
        public Input<bool>? IsDefault { get; set; }

        [Input("properties", required: true)]
        private InputMap<object>? _properties;

        /// <summary>
        /// A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        /// </summary>
        public InputMap<object> Properties
        {
            get => _properties ?? (_properties = new InputMap<object>());
            set => _properties = value;
        }

        /// <summary>
        /// The key of the object type. Type key's can be found via the '/types' endpoint.
        /// </summary>
        [Input("typeKey", required: true)]
        public Input<string> TypeKey { get; set; } = null!;

        public ConnectionArgs()
        {
        }
    }

    public sealed class ConnectionState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique catalog identifier.
        /// </summary>
        [Input("catalogId")]
        public Input<string>? CatalogId { get; set; }

        /// <summary>
        /// OCID of the user who created the connection.
        /// </summary>
        [Input("createdById")]
        public Input<string>? CreatedById { get; set; }

        /// <summary>
        /// Unique data asset key.
        /// </summary>
        [Input("dataAssetKey")]
        public Input<string>? DataAssetKey { get; set; }

        /// <summary>
        /// (Updatable) A description of the connection.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("encProperties")]
        private InputMap<object>? _encProperties;

        /// <summary>
        /// (Updatable) A map of maps that contains the encrypted values for sensitive properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. To determine the set of optional and required properties for a connection type, a query can be done on '/types?type=connection' that returns a collection of all connection types. The appropriate connection type, which will include definitions of all of it's properties, can be identified from this collection. Example: `{"encProperties": { "default": { "password": "example-password"}}}`
        /// </summary>
        public InputMap<object> EncProperties
        {
            get => _encProperties ?? (_encProperties = new InputMap<object>());
            set => _encProperties = value;
        }

        /// <summary>
        /// Unique external key of this object from the source system.
        /// </summary>
        [Input("externalKey")]
        public Input<string>? ExternalKey { get; set; }

        /// <summary>
        /// (Updatable) Indicates whether this connection is the default connection. The first connection of a data asset defaults to being the default, subsequent connections default to not being the default. If a default connection already exists, then trying to create a connection as the default will fail. In this case the default connection would need to be updated not to be the default and then the new connection can then be created as the default.
        /// </summary>
        [Input("isDefault")]
        public Input<bool>? IsDefault { get; set; }

        /// <summary>
        /// Unique connection key that is immutable.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        [Input("properties")]
        private InputMap<object>? _properties;

        /// <summary>
        /// A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        /// </summary>
        public InputMap<object> Properties
        {
            get => _properties ?? (_properties = new InputMap<object>());
            set => _properties = value;
        }

        /// <summary>
        /// The current state of the connection.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time that the connections status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeStatusUpdated")]
        public Input<string>? TimeStatusUpdated { get; set; }

        /// <summary>
        /// The last time that any change was made to the connection. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The key of the object type. Type key's can be found via the '/types' endpoint.
        /// </summary>
        [Input("typeKey")]
        public Input<string>? TypeKey { get; set; }

        /// <summary>
        /// OCID of the user who modified the connection.
        /// </summary>
        [Input("updatedById")]
        public Input<string>? UpdatedById { get; set; }

        /// <summary>
        /// URI to the connection instance in the API.
        /// </summary>
        [Input("uri")]
        public Input<string>? Uri { get; set; }

        public ConnectionState()
        {
        }
    }
}
