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
    'GetManagedDatabaseResult',
    'AwaitableGetManagedDatabaseResult',
    'get_managed_database',
]

@pulumi.output_type
class GetManagedDatabaseResult:
    """
    A collection of values returned by getManagedDatabase.
    """
    def __init__(__self__, additional_details=None, compartment_id=None, database_status=None, database_sub_type=None, database_type=None, id=None, is_cluster=None, managed_database_groups=None, managed_database_id=None, name=None, parent_container_id=None, time_created=None):
        if additional_details and not isinstance(additional_details, dict):
            raise TypeError("Expected argument 'additional_details' to be a dict")
        pulumi.set(__self__, "additional_details", additional_details)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if database_status and not isinstance(database_status, str):
            raise TypeError("Expected argument 'database_status' to be a str")
        pulumi.set(__self__, "database_status", database_status)
        if database_sub_type and not isinstance(database_sub_type, str):
            raise TypeError("Expected argument 'database_sub_type' to be a str")
        pulumi.set(__self__, "database_sub_type", database_sub_type)
        if database_type and not isinstance(database_type, str):
            raise TypeError("Expected argument 'database_type' to be a str")
        pulumi.set(__self__, "database_type", database_type)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_cluster and not isinstance(is_cluster, bool):
            raise TypeError("Expected argument 'is_cluster' to be a bool")
        pulumi.set(__self__, "is_cluster", is_cluster)
        if managed_database_groups and not isinstance(managed_database_groups, list):
            raise TypeError("Expected argument 'managed_database_groups' to be a list")
        pulumi.set(__self__, "managed_database_groups", managed_database_groups)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if parent_container_id and not isinstance(parent_container_id, str):
            raise TypeError("Expected argument 'parent_container_id' to be a str")
        pulumi.set(__self__, "parent_container_id", parent_container_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="additionalDetails")
    def additional_details(self) -> Mapping[str, Any]:
        """
        The additional details specific to a type of database defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "additional_details")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="databaseStatus")
    def database_status(self) -> str:
        """
        The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
        """
        return pulumi.get(self, "database_status")

    @property
    @pulumi.getter(name="databaseSubType")
    def database_sub_type(self) -> str:
        """
        The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or a Non-container Database.
        """
        return pulumi.get(self, "database_sub_type")

    @property
    @pulumi.getter(name="databaseType")
    def database_type(self) -> str:
        """
        The type of Oracle Database installation.
        """
        return pulumi.get(self, "database_type")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isCluster")
    def is_cluster(self) -> bool:
        """
        Indicates whether the Oracle Database is part of a cluster.
        """
        return pulumi.get(self, "is_cluster")

    @property
    @pulumi.getter(name="managedDatabaseGroups")
    def managed_database_groups(self) -> Sequence['outputs.GetManagedDatabaseManagedDatabaseGroupResult']:
        """
        A list of Managed Database Groups that the Managed Database belongs to.
        """
        return pulumi.get(self, "managed_database_groups")

    @property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> str:
        return pulumi.get(self, "managed_database_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the Managed Database.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="parentContainerId")
    def parent_container_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
        """
        return pulumi.get(self, "parent_container_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the Managed Database was created.
        """
        return pulumi.get(self, "time_created")


class AwaitableGetManagedDatabaseResult(GetManagedDatabaseResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseResult(
            additional_details=self.additional_details,
            compartment_id=self.compartment_id,
            database_status=self.database_status,
            database_sub_type=self.database_sub_type,
            database_type=self.database_type,
            id=self.id,
            is_cluster=self.is_cluster,
            managed_database_groups=self.managed_database_groups,
            managed_database_id=self.managed_database_id,
            name=self.name,
            parent_container_id=self.parent_container_id,
            time_created=self.time_created)


def get_managed_database(managed_database_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseResult:
    """
    This data source provides details about a specific Managed Database resource in Oracle Cloud Infrastructure Database Management service.

    Gets the details for the Managed Database specified by managedDatabaseId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database = oci.databasemanagement.get_managed_database(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:databasemanagement/getManagedDatabase:getManagedDatabase', __args__, opts=opts, typ=GetManagedDatabaseResult).value

    return AwaitableGetManagedDatabaseResult(
        additional_details=__ret__.additional_details,
        compartment_id=__ret__.compartment_id,
        database_status=__ret__.database_status,
        database_sub_type=__ret__.database_sub_type,
        database_type=__ret__.database_type,
        id=__ret__.id,
        is_cluster=__ret__.is_cluster,
        managed_database_groups=__ret__.managed_database_groups,
        managed_database_id=__ret__.managed_database_id,
        name=__ret__.name,
        parent_container_id=__ret__.parent_container_id,
        time_created=__ret__.time_created)
