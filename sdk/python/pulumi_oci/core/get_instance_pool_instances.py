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
    'GetInstancePoolInstancesResult',
    'AwaitableGetInstancePoolInstancesResult',
    'get_instance_pool_instances',
]

@pulumi.output_type
class GetInstancePoolInstancesResult:
    """
    A collection of values returned by getInstancePoolInstances.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, instance_pool_id=None, instances=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_pool_id and not isinstance(instance_pool_id, str):
            raise TypeError("Expected argument 'instance_pool_id' to be a str")
        pulumi.set(__self__, "instance_pool_id", instance_pool_id)
        if instances and not isinstance(instances, list):
            raise TypeError("Expected argument 'instances' to be a list")
        pulumi.set(__self__, "instances", instances)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the instance.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The user-friendly name. Does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetInstancePoolInstancesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="instancePoolId")
    def instance_pool_id(self) -> str:
        return pulumi.get(self, "instance_pool_id")

    @property
    @pulumi.getter
    def instances(self) -> Sequence['outputs.GetInstancePoolInstancesInstanceResult']:
        """
        The list of instances.
        """
        return pulumi.get(self, "instances")


class AwaitableGetInstancePoolInstancesResult(GetInstancePoolInstancesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstancePoolInstancesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            instance_pool_id=self.instance_pool_id,
            instances=self.instances)


def get_instance_pool_instances(compartment_id: Optional[str] = None,
                                display_name: Optional[str] = None,
                                filters: Optional[Sequence[pulumi.InputType['GetInstancePoolInstancesFilterArgs']]] = None,
                                instance_pool_id: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstancePoolInstancesResult:
    """
    This data source provides the list of Instance Pool Instances in Oracle Cloud Infrastructure Core service.

    List the instances in the specified instance pool.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_pool_instances = oci.core.get_instance_pool_instances(compartment_id=var["compartment_id"],
        instance_pool_id=oci_core_instance_pool["test_instance_pool"]["id"],
        display_name=var["instance_pool_instance_display_name"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str instance_pool_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['instancePoolId'] = instance_pool_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getInstancePoolInstances:getInstancePoolInstances', __args__, opts=opts, typ=GetInstancePoolInstancesResult).value

    return AwaitableGetInstancePoolInstancesResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        instance_pool_id=__ret__.instance_pool_id,
        instances=__ret__.instances)
