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
    'GetAutonomousContainerDatabaseDataguardAssociationsResult',
    'AwaitableGetAutonomousContainerDatabaseDataguardAssociationsResult',
    'get_autonomous_container_database_dataguard_associations',
]

@pulumi.output_type
class GetAutonomousContainerDatabaseDataguardAssociationsResult:
    """
    A collection of values returned by getAutonomousContainerDatabaseDataguardAssociations.
    """
    def __init__(__self__, autonomous_container_database_dataguard_associations=None, autonomous_container_database_id=None, filters=None, id=None):
        if autonomous_container_database_dataguard_associations and not isinstance(autonomous_container_database_dataguard_associations, list):
            raise TypeError("Expected argument 'autonomous_container_database_dataguard_associations' to be a list")
        pulumi.set(__self__, "autonomous_container_database_dataguard_associations", autonomous_container_database_dataguard_associations)
        if autonomous_container_database_id and not isinstance(autonomous_container_database_id, str):
            raise TypeError("Expected argument 'autonomous_container_database_id' to be a str")
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociations")
    def autonomous_container_database_dataguard_associations(self) -> Sequence['outputs.GetAutonomousContainerDatabaseDataguardAssociationsAutonomousContainerDatabaseDataguardAssociationResult']:
        """
        The list of autonomous_container_database_dataguard_associations.
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_associations")

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database.
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAutonomousContainerDatabaseDataguardAssociationsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetAutonomousContainerDatabaseDataguardAssociationsResult(GetAutonomousContainerDatabaseDataguardAssociationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAutonomousContainerDatabaseDataguardAssociationsResult(
            autonomous_container_database_dataguard_associations=self.autonomous_container_database_dataguard_associations,
            autonomous_container_database_id=self.autonomous_container_database_id,
            filters=self.filters,
            id=self.id)


def get_autonomous_container_database_dataguard_associations(autonomous_container_database_id: Optional[str] = None,
                                                             filters: Optional[Sequence[pulumi.InputType['GetAutonomousContainerDatabaseDataguardAssociationsFilterArgs']]] = None,
                                                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAutonomousContainerDatabaseDataguardAssociationsResult:
    """
    This data source provides the list of Autonomous Container Database Dataguard Associations in Oracle Cloud Infrastructure Database service.

    Gets a list of the Autonomous Container Databases with Autonomous Data Guard-enabled associated with the specified Autonomous Container Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_autonomous_container_database_dataguard_associations = oci.database.get_autonomous_container_database_dataguard_associations(autonomous_container_database_id=oci_database_autonomous_container_database["test_autonomous_container_database"]["id"])
    ```


    :param str autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['autonomousContainerDatabaseId'] = autonomous_container_database_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getAutonomousContainerDatabaseDataguardAssociations:getAutonomousContainerDatabaseDataguardAssociations', __args__, opts=opts, typ=GetAutonomousContainerDatabaseDataguardAssociationsResult).value

    return AwaitableGetAutonomousContainerDatabaseDataguardAssociationsResult(
        autonomous_container_database_dataguard_associations=__ret__.autonomous_container_database_dataguard_associations,
        autonomous_container_database_id=__ret__.autonomous_container_database_id,
        filters=__ret__.filters,
        id=__ret__.id)
