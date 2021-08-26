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
    'GetIndexResult',
    'AwaitableGetIndexResult',
    'get_index',
]

@pulumi.output_type
class GetIndexResult:
    """
    A collection of values returned by getIndex.
    """
    def __init__(__self__, compartment_id=None, id=None, index_name=None, is_if_not_exists=None, keys=None, lifecycle_details=None, name=None, state=None, table_id=None, table_name=None, table_name_or_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if index_name and not isinstance(index_name, str):
            raise TypeError("Expected argument 'index_name' to be a str")
        pulumi.set(__self__, "index_name", index_name)
        if is_if_not_exists and not isinstance(is_if_not_exists, bool):
            raise TypeError("Expected argument 'is_if_not_exists' to be a bool")
        pulumi.set(__self__, "is_if_not_exists", is_if_not_exists)
        if keys and not isinstance(keys, list):
            raise TypeError("Expected argument 'keys' to be a list")
        pulumi.set(__self__, "keys", keys)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if table_id and not isinstance(table_id, str):
            raise TypeError("Expected argument 'table_id' to be a str")
        pulumi.set(__self__, "table_id", table_id)
        if table_name and not isinstance(table_name, str):
            raise TypeError("Expected argument 'table_name' to be a str")
        pulumi.set(__self__, "table_name", table_name)
        if table_name_or_id and not isinstance(table_name_or_id, str):
            raise TypeError("Expected argument 'table_name_or_id' to be a str")
        pulumi.set(__self__, "table_name_or_id", table_name_or_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="indexName")
    def index_name(self) -> str:
        return pulumi.get(self, "index_name")

    @property
    @pulumi.getter(name="isIfNotExists")
    def is_if_not_exists(self) -> bool:
        return pulumi.get(self, "is_if_not_exists")

    @property
    @pulumi.getter
    def keys(self) -> Sequence['outputs.GetIndexKeyResult']:
        """
        A set of keys for a secondary index.
        """
        return pulumi.get(self, "keys")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Index name.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The state of an index.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="tableId")
    def table_id(self) -> str:
        """
        the OCID of the table to which this index belongs.
        """
        return pulumi.get(self, "table_id")

    @property
    @pulumi.getter(name="tableName")
    def table_name(self) -> str:
        """
        The name of the table to which this index belongs.
        """
        return pulumi.get(self, "table_name")

    @property
    @pulumi.getter(name="tableNameOrId")
    def table_name_or_id(self) -> str:
        return pulumi.get(self, "table_name_or_id")


class AwaitableGetIndexResult(GetIndexResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIndexResult(
            compartment_id=self.compartment_id,
            id=self.id,
            index_name=self.index_name,
            is_if_not_exists=self.is_if_not_exists,
            keys=self.keys,
            lifecycle_details=self.lifecycle_details,
            name=self.name,
            state=self.state,
            table_id=self.table_id,
            table_name=self.table_name,
            table_name_or_id=self.table_name_or_id)


def get_index(compartment_id: Optional[str] = None,
              index_name: Optional[str] = None,
              table_name_or_id: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIndexResult:
    """
    This data source provides details about a specific Index resource in Oracle Cloud Infrastructure NoSQL Database service.

    Get information about a single index.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_index = oci.nosql.get_index(index_name=oci_nosql_index["test_index"]["name"],
        table_name_or_id=oci_nosql_table_name_or["test_table_name_or"]["id"],
        compartment_id=var["compartment_id"])
    ```


    :param str compartment_id: The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
    :param str index_name: The name of a table's index.
    :param str table_name_or_id: A table name within the compartment, or a table OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['indexName'] = index_name
    __args__['tableNameOrId'] = table_name_or_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:nosql/getIndex:getIndex', __args__, opts=opts, typ=GetIndexResult).value

    return AwaitableGetIndexResult(
        compartment_id=__ret__.compartment_id,
        id=__ret__.id,
        index_name=__ret__.index_name,
        is_if_not_exists=__ret__.is_if_not_exists,
        keys=__ret__.keys,
        lifecycle_details=__ret__.lifecycle_details,
        name=__ret__.name,
        state=__ret__.state,
        table_id=__ret__.table_id,
        table_name=__ret__.table_name,
        table_name_or_id=__ret__.table_name_or_id)
