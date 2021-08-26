# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetConnectionsResult',
    'AwaitableGetConnectionsResult',
    'get_connections',
]

@pulumi.output_type
class GetConnectionsResult:
    """
    A collection of values returned by getConnections.
    """
    def __init__(__self__, catalog_id=None, connection_collections=None, created_by_id=None, data_asset_key=None, display_name=None, display_name_contains=None, external_key=None, fields=None, filters=None, id=None, is_default=None, state=None, time_created=None, time_status_updated=None, time_updated=None, updated_by_id=None):
        if catalog_id and not isinstance(catalog_id, str):
            raise TypeError("Expected argument 'catalog_id' to be a str")
        pulumi.set(__self__, "catalog_id", catalog_id)
        if connection_collections and not isinstance(connection_collections, list):
            raise TypeError("Expected argument 'connection_collections' to be a list")
        pulumi.set(__self__, "connection_collections", connection_collections)
        if created_by_id and not isinstance(created_by_id, str):
            raise TypeError("Expected argument 'created_by_id' to be a str")
        pulumi.set(__self__, "created_by_id", created_by_id)
        if data_asset_key and not isinstance(data_asset_key, str):
            raise TypeError("Expected argument 'data_asset_key' to be a str")
        pulumi.set(__self__, "data_asset_key", data_asset_key)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if display_name_contains and not isinstance(display_name_contains, str):
            raise TypeError("Expected argument 'display_name_contains' to be a str")
        pulumi.set(__self__, "display_name_contains", display_name_contains)
        if external_key and not isinstance(external_key, str):
            raise TypeError("Expected argument 'external_key' to be a str")
        pulumi.set(__self__, "external_key", external_key)
        if fields and not isinstance(fields, list):
            raise TypeError("Expected argument 'fields' to be a list")
        pulumi.set(__self__, "fields", fields)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_default and not isinstance(is_default, bool):
            raise TypeError("Expected argument 'is_default' to be a bool")
        pulumi.set(__self__, "is_default", is_default)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_status_updated and not isinstance(time_status_updated, str):
            raise TypeError("Expected argument 'time_status_updated' to be a str")
        pulumi.set(__self__, "time_status_updated", time_status_updated)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if updated_by_id and not isinstance(updated_by_id, str):
            raise TypeError("Expected argument 'updated_by_id' to be a str")
        pulumi.set(__self__, "updated_by_id", updated_by_id)

    @property
    @pulumi.getter(name="catalogId")
    def catalog_id(self) -> str:
        return pulumi.get(self, "catalog_id")

    @property
    @pulumi.getter(name="connectionCollections")
    def connection_collections(self) -> Sequence['outputs.GetConnectionsConnectionCollectionResult']:
        """
        The list of connection_collection.
        """
        return pulumi.get(self, "connection_collections")

    @property
    @pulumi.getter(name="createdById")
    def created_by_id(self) -> Optional[str]:
        """
        OCID of the user who created the connection.
        """
        return pulumi.get(self, "created_by_id")

    @property
    @pulumi.getter(name="dataAssetKey")
    def data_asset_key(self) -> str:
        """
        Unique key of the parent data asset.
        """
        return pulumi.get(self, "data_asset_key")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="displayNameContains")
    def display_name_contains(self) -> Optional[str]:
        return pulumi.get(self, "display_name_contains")

    @property
    @pulumi.getter(name="externalKey")
    def external_key(self) -> Optional[str]:
        """
        Unique external key of this object from the source system.
        """
        return pulumi.get(self, "external_key")

    @property
    @pulumi.getter
    def fields(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "fields")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetConnectionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isDefault")
    def is_default(self) -> Optional[bool]:
        """
        Indicates whether this connection is the default connection.
        """
        return pulumi.get(self, "is_default")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the connection.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[str]:
        """
        The date and time the connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeStatusUpdated")
    def time_status_updated(self) -> Optional[str]:
        """
        Time that the connections status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_status_updated")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[str]:
        """
        The last time that any change was made to the connection. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="updatedById")
    def updated_by_id(self) -> Optional[str]:
        """
        OCID of the user who modified the connection.
        """
        return pulumi.get(self, "updated_by_id")


class AwaitableGetConnectionsResult(GetConnectionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConnectionsResult(
            catalog_id=self.catalog_id,
            connection_collections=self.connection_collections,
            created_by_id=self.created_by_id,
            data_asset_key=self.data_asset_key,
            display_name=self.display_name,
            display_name_contains=self.display_name_contains,
            external_key=self.external_key,
            fields=self.fields,
            filters=self.filters,
            id=self.id,
            is_default=self.is_default,
            state=self.state,
            time_created=self.time_created,
            time_status_updated=self.time_status_updated,
            time_updated=self.time_updated,
            updated_by_id=self.updated_by_id)


def get_connections(catalog_id: Optional[str] = None,
                    created_by_id: Optional[str] = None,
                    data_asset_key: Optional[str] = None,
                    display_name: Optional[str] = None,
                    display_name_contains: Optional[str] = None,
                    external_key: Optional[str] = None,
                    fields: Optional[Sequence[str]] = None,
                    filters: Optional[Sequence[pulumi.InputType['GetConnectionsFilterArgs']]] = None,
                    is_default: Optional[bool] = None,
                    state: Optional[str] = None,
                    time_created: Optional[str] = None,
                    time_status_updated: Optional[str] = None,
                    time_updated: Optional[str] = None,
                    updated_by_id: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConnectionsResult:
    """
    This data source provides the list of Connections in Oracle Cloud Infrastructure Data Catalog service.

    Returns a list of all Connections for a data asset.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_connections = oci.datacatalog.get_connections(catalog_id=oci_datacatalog_catalog["test_catalog"]["id"],
        data_asset_key=var["connection_data_asset_key"],
        created_by_id=oci_datacatalog_created_by["test_created_by"]["id"],
        display_name=var["connection_display_name"],
        display_name_contains=var["connection_display_name_contains"],
        external_key=var["connection_external_key"],
        fields=var["connection_fields"],
        is_default=var["connection_is_default"],
        state=var["connection_state"],
        time_created=var["connection_time_created"],
        time_status_updated=var["connection_time_status_updated"],
        time_updated=var["connection_time_updated"],
        updated_by_id=oci_datacatalog_updated_by["test_updated_by"]["id"])
    ```


    :param str catalog_id: Unique catalog identifier.
    :param str created_by_id: OCID of the user who created the resource.
    :param str data_asset_key: Unique data asset key.
    :param str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param str display_name_contains: A filter to return only resources that match display name pattern given. The match is not case sensitive. For Example : /folders?displayNameContains=Cu.* The above would match all folders with display name that starts with "Cu".
    :param str external_key: Unique external identifier of this resource in the external source system.
    :param Sequence[str] fields: Specifies the fields to return in a connection summary response.
    :param bool is_default: Indicates whether this connection is the default connection.
    :param str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
    :param str time_created: Time that the resource was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
    :param str time_status_updated: Time that the resource's status was last updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
    :param str time_updated: Time that the resource was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
    :param str updated_by_id: OCID of the user who updated the resource.
    """
    __args__ = dict()
    __args__['catalogId'] = catalog_id
    __args__['createdById'] = created_by_id
    __args__['dataAssetKey'] = data_asset_key
    __args__['displayName'] = display_name
    __args__['displayNameContains'] = display_name_contains
    __args__['externalKey'] = external_key
    __args__['fields'] = fields
    __args__['filters'] = filters
    __args__['isDefault'] = is_default
    __args__['state'] = state
    __args__['timeCreated'] = time_created
    __args__['timeStatusUpdated'] = time_status_updated
    __args__['timeUpdated'] = time_updated
    __args__['updatedById'] = updated_by_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:datacatalog/getConnections:getConnections', __args__, opts=opts, typ=GetConnectionsResult).value

    return AwaitableGetConnectionsResult(
        catalog_id=__ret__.catalog_id,
        connection_collections=__ret__.connection_collections,
        created_by_id=__ret__.created_by_id,
        data_asset_key=__ret__.data_asset_key,
        display_name=__ret__.display_name,
        display_name_contains=__ret__.display_name_contains,
        external_key=__ret__.external_key,
        fields=__ret__.fields,
        filters=__ret__.filters,
        id=__ret__.id,
        is_default=__ret__.is_default,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_status_updated=__ret__.time_status_updated,
        time_updated=__ret__.time_updated,
        updated_by_id=__ret__.updated_by_id)
