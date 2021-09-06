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
    'GetInstancePoolResult',
    'AwaitableGetInstancePoolResult',
    'get_instance_pool',
]

@pulumi.output_type
class GetInstancePoolResult:
    """
    A collection of values returned by getInstancePool.
    """
    def __init__(__self__, actual_size=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, instance_configuration_id=None, instance_pool_id=None, load_balancers=None, placement_configurations=None, size=None, state=None, time_created=None):
        if actual_size and not isinstance(actual_size, int):
            raise TypeError("Expected argument 'actual_size' to be a int")
        pulumi.set(__self__, "actual_size", actual_size)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_configuration_id and not isinstance(instance_configuration_id, str):
            raise TypeError("Expected argument 'instance_configuration_id' to be a str")
        pulumi.set(__self__, "instance_configuration_id", instance_configuration_id)
        if instance_pool_id and not isinstance(instance_pool_id, str):
            raise TypeError("Expected argument 'instance_pool_id' to be a str")
        pulumi.set(__self__, "instance_pool_id", instance_pool_id)
        if load_balancers and not isinstance(load_balancers, list):
            raise TypeError("Expected argument 'load_balancers' to be a list")
        pulumi.set(__self__, "load_balancers", load_balancers)
        if placement_configurations and not isinstance(placement_configurations, list):
            raise TypeError("Expected argument 'placement_configurations' to be a list")
        pulumi.set(__self__, "placement_configurations", placement_configurations)
        if size and not isinstance(size, int):
            raise TypeError("Expected argument 'size' to be a int")
        pulumi.set(__self__, "size", size)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="actualSize")
    def actual_size(self) -> int:
        return pulumi.get(self, "actual_size")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the instance pool.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The display name of the VNIC. This is also use to match against the instance configuration defined secondary VNIC.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="instanceConfigurationId")
    def instance_configuration_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance configuration associated with the instance pool.
        """
        return pulumi.get(self, "instance_configuration_id")

    @property
    @pulumi.getter(name="instancePoolId")
    def instance_pool_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
        """
        return pulumi.get(self, "instance_pool_id")

    @property
    @pulumi.getter(name="loadBalancers")
    def load_balancers(self) -> Sequence['outputs.GetInstancePoolLoadBalancerResult']:
        """
        The load balancers attached to the instance pool.
        """
        return pulumi.get(self, "load_balancers")

    @property
    @pulumi.getter(name="placementConfigurations")
    def placement_configurations(self) -> Sequence['outputs.GetInstancePoolPlacementConfigurationResult']:
        """
        The placement configurations for the instance pool.
        """
        return pulumi.get(self, "placement_configurations")

    @property
    @pulumi.getter
    def size(self) -> int:
        """
        The number of actual instances in the instance pool on the cloud. This attribute will be different when instance pool is used along with autoScaling Configuration.
        """
        return pulumi.get(self, "size")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the instance pool.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the instance pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetInstancePoolResult(GetInstancePoolResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstancePoolResult(
            actual_size=self.actual_size,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            instance_configuration_id=self.instance_configuration_id,
            instance_pool_id=self.instance_pool_id,
            load_balancers=self.load_balancers,
            placement_configurations=self.placement_configurations,
            size=self.size,
            state=self.state,
            time_created=self.time_created)


def get_instance_pool(instance_pool_id: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstancePoolResult:
    """
    This data source provides details about a specific Instance Pool resource in Oracle Cloud Infrastructure Core service.

    Gets the specified instance pool

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_pool = oci.core.get_instance_pool(instance_pool_id=oci_core_instance_pool["test_instance_pool"]["id"])
    ```


    :param str instance_pool_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
    """
    __args__ = dict()
    __args__['instancePoolId'] = instance_pool_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getInstancePool:getInstancePool', __args__, opts=opts, typ=GetInstancePoolResult).value

    return AwaitableGetInstancePoolResult(
        actual_size=__ret__.actual_size,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        instance_configuration_id=__ret__.instance_configuration_id,
        instance_pool_id=__ret__.instance_pool_id,
        load_balancers=__ret__.load_balancers,
        placement_configurations=__ret__.placement_configurations,
        size=__ret__.size,
        state=__ret__.state,
        time_created=__ret__.time_created)
