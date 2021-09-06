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
    'GetDedicatedVmHostsResult',
    'AwaitableGetDedicatedVmHostsResult',
    'get_dedicated_vm_hosts',
]

@pulumi.output_type
class GetDedicatedVmHostsResult:
    """
    A collection of values returned by getDedicatedVmHosts.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, dedicated_vm_hosts=None, display_name=None, filters=None, id=None, instance_shape_name=None, remaining_memory_in_gbs_greater_than_or_equal_to=None, remaining_ocpus_greater_than_or_equal_to=None, state=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if dedicated_vm_hosts and not isinstance(dedicated_vm_hosts, list):
            raise TypeError("Expected argument 'dedicated_vm_hosts' to be a list")
        pulumi.set(__self__, "dedicated_vm_hosts", dedicated_vm_hosts)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_shape_name and not isinstance(instance_shape_name, str):
            raise TypeError("Expected argument 'instance_shape_name' to be a str")
        pulumi.set(__self__, "instance_shape_name", instance_shape_name)
        if remaining_memory_in_gbs_greater_than_or_equal_to and not isinstance(remaining_memory_in_gbs_greater_than_or_equal_to, float):
            raise TypeError("Expected argument 'remaining_memory_in_gbs_greater_than_or_equal_to' to be a float")
        pulumi.set(__self__, "remaining_memory_in_gbs_greater_than_or_equal_to", remaining_memory_in_gbs_greater_than_or_equal_to)
        if remaining_ocpus_greater_than_or_equal_to and not isinstance(remaining_ocpus_greater_than_or_equal_to, float):
            raise TypeError("Expected argument 'remaining_ocpus_greater_than_or_equal_to' to be a float")
        pulumi.set(__self__, "remaining_ocpus_greater_than_or_equal_to", remaining_ocpus_greater_than_or_equal_to)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[str]:
        """
        The availability domain the dedicated virtual machine host is running in.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the dedicated virtual machine host.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="dedicatedVmHosts")
    def dedicated_vm_hosts(self) -> Sequence['outputs.GetDedicatedVmHostsDedicatedVmHostResult']:
        """
        The list of dedicated_vm_hosts.
        """
        return pulumi.get(self, "dedicated_vm_hosts")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My Dedicated Vm Host`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDedicatedVmHostsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="instanceShapeName")
    def instance_shape_name(self) -> Optional[str]:
        return pulumi.get(self, "instance_shape_name")

    @property
    @pulumi.getter(name="remainingMemoryInGbsGreaterThanOrEqualTo")
    def remaining_memory_in_gbs_greater_than_or_equal_to(self) -> Optional[float]:
        return pulumi.get(self, "remaining_memory_in_gbs_greater_than_or_equal_to")

    @property
    @pulumi.getter(name="remainingOcpusGreaterThanOrEqualTo")
    def remaining_ocpus_greater_than_or_equal_to(self) -> Optional[float]:
        return pulumi.get(self, "remaining_ocpus_greater_than_or_equal_to")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the dedicated VM host.
        """
        return pulumi.get(self, "state")


class AwaitableGetDedicatedVmHostsResult(GetDedicatedVmHostsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDedicatedVmHostsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            dedicated_vm_hosts=self.dedicated_vm_hosts,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            instance_shape_name=self.instance_shape_name,
            remaining_memory_in_gbs_greater_than_or_equal_to=self.remaining_memory_in_gbs_greater_than_or_equal_to,
            remaining_ocpus_greater_than_or_equal_to=self.remaining_ocpus_greater_than_or_equal_to,
            state=self.state)


def get_dedicated_vm_hosts(availability_domain: Optional[str] = None,
                           compartment_id: Optional[str] = None,
                           display_name: Optional[str] = None,
                           filters: Optional[Sequence[pulumi.InputType['GetDedicatedVmHostsFilterArgs']]] = None,
                           instance_shape_name: Optional[str] = None,
                           remaining_memory_in_gbs_greater_than_or_equal_to: Optional[float] = None,
                           remaining_ocpus_greater_than_or_equal_to: Optional[float] = None,
                           state: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDedicatedVmHostsResult:
    """
    This data source provides the list of Dedicated Vm Hosts in Oracle Cloud Infrastructure Core service.

    Returns the list of dedicated virtual machine hosts that match the specified criteria in the specified compartment.

    You can limit the list by specifying a dedicated virtual machine host display name. The list will include all the identically-named
    dedicated virtual machine hosts in the compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vm_hosts = oci.core.get_dedicated_vm_hosts(compartment_id=var["compartment_id"],
        availability_domain=var["dedicated_vm_host_availability_domain"],
        display_name=var["dedicated_vm_host_display_name"],
        instance_shape_name=var["dedicated_vm_host_instance_shape_name"],
        remaining_memory_in_gbs_greater_than_or_equal_to=var["dedicated_vm_host_remaining_memory_in_gbs_greater_than_or_equal_to"],
        remaining_ocpus_greater_than_or_equal_to=var["dedicated_vm_host_remaining_ocpus_greater_than_or_equal_to"],
        state=var["dedicated_vm_host_state"])
    ```


    :param str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str instance_shape_name: The name for the instance's shape.
    :param float remaining_memory_in_gbs_greater_than_or_equal_to: The remaining memory of the dedicated VM host, in GBs.
    :param float remaining_ocpus_greater_than_or_equal_to: The available OCPUs of the dedicated VM host.
    :param str state: A filter to only return resources that match the given lifecycle state.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['instanceShapeName'] = instance_shape_name
    __args__['remainingMemoryInGbsGreaterThanOrEqualTo'] = remaining_memory_in_gbs_greater_than_or_equal_to
    __args__['remainingOcpusGreaterThanOrEqualTo'] = remaining_ocpus_greater_than_or_equal_to
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getDedicatedVmHosts:getDedicatedVmHosts', __args__, opts=opts, typ=GetDedicatedVmHostsResult).value

    return AwaitableGetDedicatedVmHostsResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        dedicated_vm_hosts=__ret__.dedicated_vm_hosts,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        instance_shape_name=__ret__.instance_shape_name,
        remaining_memory_in_gbs_greater_than_or_equal_to=__ret__.remaining_memory_in_gbs_greater_than_or_equal_to,
        remaining_ocpus_greater_than_or_equal_to=__ret__.remaining_ocpus_greater_than_or_equal_to,
        state=__ret__.state)
