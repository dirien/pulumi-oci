# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetCatalogPrivateEndpointsCatalogPrivateEndpointResult',
    'GetCatalogPrivateEndpointsFilterResult',
    'GetCatalogTypesFilterResult',
    'GetCatalogTypesTypeCollectionResult',
    'GetCatalogTypesTypeCollectionItemResult',
    'GetCatalogsCatalogResult',
    'GetCatalogsFilterResult',
    'GetConnectionsConnectionCollectionResult',
    'GetConnectionsConnectionCollectionItemResult',
    'GetConnectionsFilterResult',
    'GetDataAssetsDataAssetCollectionResult',
    'GetDataAssetsDataAssetCollectionItemResult',
    'GetDataAssetsFilterResult',
]

@pulumi.output_type
class GetCatalogPrivateEndpointsCatalogPrivateEndpointResult(dict):
    def __init__(__self__, *,
                 attached_catalogs: Sequence[str],
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 display_name: str,
                 dns_zones: Sequence[str],
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 lifecycle_details: str,
                 state: str,
                 subnet_id: str,
                 time_created: str,
                 time_updated: str):
        """
        :param Sequence[str] attached_catalogs: The list of catalogs using the private reverse connection endpoint
        :param str compartment_id: The OCID of the compartment where you want to list resources.
        :param Mapping[str, Any] defined_tags: Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
        :param Sequence[str] dns_zones: List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: Unique identifier that is immutable
        :param str lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
        :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        :param str subnet_id: Subnet Identifier
        :param str time_created: The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str time_updated: The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        pulumi.set(__self__, "attached_catalogs", attached_catalogs)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "dns_zones", dns_zones)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "subnet_id", subnet_id)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="attachedCatalogs")
    def attached_catalogs(self) -> Sequence[str]:
        """
        The list of catalogs using the private reverse connection endpoint
        """
        return pulumi.get(self, "attached_catalogs")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment where you want to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given. The match is not case sensitive.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="dnsZones")
    def dns_zones(self) -> Sequence[str]:
        """
        List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
        """
        return pulumi.get(self, "dns_zones")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> str:
        """
        Subnet Identifier
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


@pulumi.output_type
class GetCatalogPrivateEndpointsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetCatalogTypesFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Immutable resource name.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Immutable resource name.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetCatalogTypesTypeCollectionResult(dict):
    def __init__(__self__, *,
                 count: int,
                 items: Sequence['outputs.GetCatalogTypesTypeCollectionItemResult']):
        pulumi.set(__self__, "count", count)
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def count(self) -> int:
        return pulumi.get(self, "count")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetCatalogTypesTypeCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetCatalogTypesTypeCollectionItemResult(dict):
    def __init__(__self__, *,
                 catalog_id: str,
                 description: str,
                 key: str,
                 name: str,
                 state: str,
                 type_category: str,
                 uri: str):
        """
        :param str catalog_id: Unique catalog identifier.
        :param str description: Detailed description of the type.
        :param str key: Unique type key that is immutable.
        :param str name: Immutable resource name.
        :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        :param str type_category: Indicates the category of this type . For example, data assets or connections.
        :param str uri: URI to the type instance in the API.
        """
        pulumi.set(__self__, "catalog_id", catalog_id)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "key", key)
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "type_category", type_category)
        pulumi.set(__self__, "uri", uri)

    @property
    @pulumi.getter(name="catalogId")
    def catalog_id(self) -> str:
        """
        Unique catalog identifier.
        """
        return pulumi.get(self, "catalog_id")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Detailed description of the type.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter
    def key(self) -> str:
        """
        Unique type key that is immutable.
        """
        return pulumi.get(self, "key")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Immutable resource name.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="typeCategory")
    def type_category(self) -> str:
        """
        Indicates the category of this type . For example, data assets or connections.
        """
        return pulumi.get(self, "type_category")

    @property
    @pulumi.getter
    def uri(self) -> str:
        """
        URI to the type instance in the API.
        """
        return pulumi.get(self, "uri")


@pulumi.output_type
class GetCatalogsCatalogResult(dict):
    def __init__(__self__, *,
                 attached_catalog_private_endpoints: Sequence[str],
                 compartment_id: str,
                 defined_tags: Mapping[str, Any],
                 display_name: str,
                 freeform_tags: Mapping[str, Any],
                 id: str,
                 lifecycle_details: str,
                 number_of_objects: int,
                 service_api_url: str,
                 service_console_url: str,
                 state: str,
                 time_created: str,
                 time_updated: str):
        """
        :param Sequence[str] attached_catalog_private_endpoints: The list of private reverse connection endpoints attached to the catalog
        :param str compartment_id: The OCID of the compartment where you want to list resources.
        :param Mapping[str, Any] defined_tags: Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        :param str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
        :param Mapping[str, Any] freeform_tags: Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param str id: Unique identifier that is immutable on creation.
        :param str lifecycle_details: An message describing the current state in more detail.  For example, it can be used to provide actionable information for a resource in 'Failed' state.
        :param int number_of_objects: The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
        :param str service_api_url: The REST front endpoint URL to the data catalog instance.
        :param str service_console_url: The console front endpoint URL to the data catalog instance.
        :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        :param str time_created: The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str time_updated: The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        pulumi.set(__self__, "attached_catalog_private_endpoints", attached_catalog_private_endpoints)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "defined_tags", defined_tags)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        pulumi.set(__self__, "number_of_objects", number_of_objects)
        pulumi.set(__self__, "service_api_url", service_api_url)
        pulumi.set(__self__, "service_console_url", service_console_url)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="attachedCatalogPrivateEndpoints")
    def attached_catalog_private_endpoints(self) -> Sequence[str]:
        """
        The list of private reverse connection endpoints attached to the catalog
        """
        return pulumi.get(self, "attached_catalog_private_endpoints")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment where you want to list resources.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given. The match is not case sensitive.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        An message describing the current state in more detail.  For example, it can be used to provide actionable information for a resource in 'Failed' state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="numberOfObjects")
    def number_of_objects(self) -> int:
        """
        The number of data objects added to the data catalog. Please see the data catalog documentation for further information on how this is calculated.
        """
        return pulumi.get(self, "number_of_objects")

    @property
    @pulumi.getter(name="serviceApiUrl")
    def service_api_url(self) -> str:
        """
        The REST front endpoint URL to the data catalog instance.
        """
        return pulumi.get(self, "service_api_url")

    @property
    @pulumi.getter(name="serviceConsoleUrl")
    def service_console_url(self) -> str:
        """
        The console front endpoint URL to the data catalog instance.
        """
        return pulumi.get(self, "service_console_url")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the data catalog was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the data catalog was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


@pulumi.output_type
class GetCatalogsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetConnectionsConnectionCollectionResult(dict):
    def __init__(__self__, *,
                 count: int,
                 items: Sequence['outputs.GetConnectionsConnectionCollectionItemResult']):
        pulumi.set(__self__, "count", count)
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def count(self) -> int:
        return pulumi.get(self, "count")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetConnectionsConnectionCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetConnectionsConnectionCollectionItemResult(dict):
    def __init__(__self__, *,
                 catalog_id: str,
                 created_by_id: str,
                 data_asset_key: str,
                 description: str,
                 display_name: str,
                 external_key: str,
                 is_default: bool,
                 key: str,
                 properties: Mapping[str, Any],
                 state: str,
                 time_created: str,
                 time_status_updated: str,
                 time_updated: str,
                 type_key: str,
                 updated_by_id: str,
                 uri: str,
                 enc_properties: Optional[Mapping[str, Any]] = None):
        """
        :param str catalog_id: Unique catalog identifier.
        :param str created_by_id: OCID of the user who created the resource.
        :param str data_asset_key: Unique data asset key.
        :param str description: A description of the connection.
        :param str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
        :param str external_key: Unique external identifier of this resource in the external source system.
        :param bool is_default: Indicates whether this connection is the default connection.
        :param str key: Unique connection key that is immutable.
        :param Mapping[str, Any] properties: A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        :param str time_created: Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str time_status_updated: Time that the resource's status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str time_updated: Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str type_key: The key of the object type. Type key's can be found via the '/types' endpoint.
        :param str updated_by_id: OCID of the user who updated the resource.
        :param str uri: URI to the connection instance in the API.
        """
        pulumi.set(__self__, "catalog_id", catalog_id)
        pulumi.set(__self__, "created_by_id", created_by_id)
        pulumi.set(__self__, "data_asset_key", data_asset_key)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "external_key", external_key)
        pulumi.set(__self__, "is_default", is_default)
        pulumi.set(__self__, "key", key)
        pulumi.set(__self__, "properties", properties)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_status_updated", time_status_updated)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "type_key", type_key)
        pulumi.set(__self__, "updated_by_id", updated_by_id)
        pulumi.set(__self__, "uri", uri)
        if enc_properties is not None:
            pulumi.set(__self__, "enc_properties", enc_properties)

    @property
    @pulumi.getter(name="catalogId")
    def catalog_id(self) -> str:
        """
        Unique catalog identifier.
        """
        return pulumi.get(self, "catalog_id")

    @property
    @pulumi.getter(name="createdById")
    def created_by_id(self) -> str:
        """
        OCID of the user who created the resource.
        """
        return pulumi.get(self, "created_by_id")

    @property
    @pulumi.getter(name="dataAssetKey")
    def data_asset_key(self) -> str:
        """
        Unique data asset key.
        """
        return pulumi.get(self, "data_asset_key")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        A description of the connection.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given. The match is not case sensitive.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="externalKey")
    def external_key(self) -> str:
        """
        Unique external identifier of this resource in the external source system.
        """
        return pulumi.get(self, "external_key")

    @property
    @pulumi.getter(name="isDefault")
    def is_default(self) -> bool:
        """
        Indicates whether this connection is the default connection.
        """
        return pulumi.get(self, "is_default")

    @property
    @pulumi.getter
    def key(self) -> str:
        """
        Unique connection key that is immutable.
        """
        return pulumi.get(self, "key")

    @property
    @pulumi.getter
    def properties(self) -> Mapping[str, Any]:
        """
        A map of maps that contains the properties which are specific to the connection type. Each connection type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most connections have required properties within the "default" category. Example: `{"properties": { "default": { "username": "user1"}}}`
        """
        return pulumi.get(self, "properties")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeStatusUpdated")
    def time_status_updated(self) -> str:
        """
        Time that the resource's status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_status_updated")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="typeKey")
    def type_key(self) -> str:
        """
        The key of the object type. Type key's can be found via the '/types' endpoint.
        """
        return pulumi.get(self, "type_key")

    @property
    @pulumi.getter(name="updatedById")
    def updated_by_id(self) -> str:
        """
        OCID of the user who updated the resource.
        """
        return pulumi.get(self, "updated_by_id")

    @property
    @pulumi.getter
    def uri(self) -> str:
        """
        URI to the connection instance in the API.
        """
        return pulumi.get(self, "uri")

    @property
    @pulumi.getter(name="encProperties")
    def enc_properties(self) -> Optional[Mapping[str, Any]]:
        return pulumi.get(self, "enc_properties")


@pulumi.output_type
class GetConnectionsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


@pulumi.output_type
class GetDataAssetsDataAssetCollectionResult(dict):
    def __init__(__self__, *,
                 count: int,
                 items: Sequence['outputs.GetDataAssetsDataAssetCollectionItemResult']):
        pulumi.set(__self__, "count", count)
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter
    def count(self) -> int:
        return pulumi.get(self, "count")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetDataAssetsDataAssetCollectionItemResult']:
        return pulumi.get(self, "items")


@pulumi.output_type
class GetDataAssetsDataAssetCollectionItemResult(dict):
    def __init__(__self__, *,
                 catalog_id: str,
                 created_by_id: str,
                 description: str,
                 display_name: str,
                 external_key: str,
                 key: str,
                 properties: Mapping[str, Any],
                 state: str,
                 time_created: str,
                 time_updated: str,
                 type_key: str,
                 updated_by_id: str,
                 uri: str):
        """
        :param str catalog_id: Unique catalog identifier.
        :param str created_by_id: OCID of the user who created the resource.
        :param str description: Detailed description of the data asset.
        :param str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
        :param str external_key: Unique external identifier of this resource in the external source system.
        :param str key: Unique data asset key that is immutable.
        :param Mapping[str, Any] properties: A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the "default" category. Example: `{"properties": { "default": { "host": "host1", "port": "1521", "database": "orcl"}}}`
        :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        :param str time_created: Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str time_updated: Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        :param str type_key: The key of the object type.
        :param str updated_by_id: OCID of the user who updated the resource.
        :param str uri: URI to the data asset instance in the API.
        """
        pulumi.set(__self__, "catalog_id", catalog_id)
        pulumi.set(__self__, "created_by_id", created_by_id)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "external_key", external_key)
        pulumi.set(__self__, "key", key)
        pulumi.set(__self__, "properties", properties)
        pulumi.set(__self__, "state", state)
        pulumi.set(__self__, "time_created", time_created)
        pulumi.set(__self__, "time_updated", time_updated)
        pulumi.set(__self__, "type_key", type_key)
        pulumi.set(__self__, "updated_by_id", updated_by_id)
        pulumi.set(__self__, "uri", uri)

    @property
    @pulumi.getter(name="catalogId")
    def catalog_id(self) -> str:
        """
        Unique catalog identifier.
        """
        return pulumi.get(self, "catalog_id")

    @property
    @pulumi.getter(name="createdById")
    def created_by_id(self) -> str:
        """
        OCID of the user who created the resource.
        """
        return pulumi.get(self, "created_by_id")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Detailed description of the data asset.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A filter to return only resources that match the entire display name given. The match is not case sensitive.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="externalKey")
    def external_key(self) -> str:
        """
        Unique external identifier of this resource in the external source system.
        """
        return pulumi.get(self, "external_key")

    @property
    @pulumi.getter
    def key(self) -> str:
        """
        Unique data asset key that is immutable.
        """
        return pulumi.get(self, "key")

    @property
    @pulumi.getter
    def properties(self) -> Mapping[str, Any]:
        """
        A map of maps that contains the properties which are specific to the asset type. Each data asset type definition defines it's set of required and optional properties. The map keys are category names and the values are maps of property name to property value. Every property is contained inside of a category. Most data assets have required properties within the "default" category. Example: `{"properties": { "default": { "host": "host1", "port": "1521", "database": "orcl"}}}`
        """
        return pulumi.get(self, "properties")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="typeKey")
    def type_key(self) -> str:
        """
        The key of the object type.
        """
        return pulumi.get(self, "type_key")

    @property
    @pulumi.getter(name="updatedById")
    def updated_by_id(self) -> str:
        """
        OCID of the user who updated the resource.
        """
        return pulumi.get(self, "updated_by_id")

    @property
    @pulumi.getter
    def uri(self) -> str:
        """
        URI to the data asset instance in the API.
        """
        return pulumi.get(self, "uri")


@pulumi.output_type
class GetDataAssetsFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")


