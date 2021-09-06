// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataCatalog.Outputs
{

    [OutputType]
    public sealed class GetConnectionsConnectionCollectionItemResult
    {
        /// <summary>
        /// Unique catalog identifier.
        /// </summary>
        public readonly string CatalogId;
        /// <summary>
        /// OCID of the user who created the resource.
        /// </summary>
        public readonly string CreatedById;
        /// <summary>
        /// Unique data asset key.
        /// </summary>
        public readonly string DataAssetKey;
        /// <summary>
        /// A description of the connection.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        public readonly ImmutableDictionary<string, object>? EncProperties;
        /// <summary>
        /// Unique external identifier of this resource in the external source system.
        /// </summary>
        public readonly string ExternalKey;
        /// <summary>
        /// Indicates whether this connection is the default connection.
        /// </summary>
        public readonly bool IsDefault;
        /// <summary>
        /// Unique connection key that is immutable.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> Properties;
        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time that the resource's status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeStatusUpdated;
        /// <summary>
        /// Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The key of the object type. Type key's can be found via the '/types' endpoint.
        /// </summary>
        public readonly string TypeKey;
        /// <summary>
        /// OCID of the user who updated the resource.
        /// </summary>
        public readonly string UpdatedById;
        /// <summary>
        /// URI to the connection instance in the API.
        /// </summary>
        public readonly string Uri;

        [OutputConstructor]
        private GetConnectionsConnectionCollectionItemResult(
            string catalogId,

            string createdById,

            string dataAssetKey,

            string description,

            string displayName,

            ImmutableDictionary<string, object>? encProperties,

            string externalKey,

            bool isDefault,

            string key,

            ImmutableDictionary<string, object> properties,

            string state,

            string timeCreated,

            string timeStatusUpdated,

            string timeUpdated,

            string typeKey,

            string updatedById,

            string uri)
        {
            CatalogId = catalogId;
            CreatedById = createdById;
            DataAssetKey = dataAssetKey;
            Description = description;
            DisplayName = displayName;
            EncProperties = encProperties;
            ExternalKey = externalKey;
            IsDefault = isDefault;
            Key = key;
            Properties = properties;
            State = state;
            TimeCreated = timeCreated;
            TimeStatusUpdated = timeStatusUpdated;
            TimeUpdated = timeUpdated;
            TypeKey = typeKey;
            UpdatedById = updatedById;
            Uri = uri;
        }
    }
}
