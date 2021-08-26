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
    'GetInstancesResult',
    'AwaitableGetInstancesResult',
    'get_instances',
]

@pulumi.output_type
class GetInstancesResult:
    """
    A collection of values returned by getInstances.
    """
    def __init__(__self__, availability_domain=None, capacity_reservation_id=None, compartment_id=None, display_name=None, filters=None, id=None, instances=None, state=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if capacity_reservation_id and not isinstance(capacity_reservation_id, str):
            raise TypeError("Expected argument 'capacity_reservation_id' to be a str")
        pulumi.set(__self__, "capacity_reservation_id", capacity_reservation_id)
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
        if instances and not isinstance(instances, list):
            raise TypeError("Expected argument 'instances' to be a list")
        pulumi.set(__self__, "instances", instances)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[str]:
        """
        The availability domain the instance is running in.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="capacityReservationId")
    def capacity_reservation_id(self) -> Optional[str]:
        """
        The OCID of the compute capacity reservation this instance is launched under. When this field contains an empty string or is null, the instance is not currently in a capacity reservation. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
        """
        return pulumi.get(self, "capacity_reservation_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the instance.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My bare metal instance`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetInstancesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def instances(self) -> Sequence['outputs.GetInstancesInstanceResult']:
        """
        The list of instances.
        """
        return pulumi.get(self, "instances")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the instance.
        """
        return pulumi.get(self, "state")


class AwaitableGetInstancesResult(GetInstancesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstancesResult(
            availability_domain=self.availability_domain,
            capacity_reservation_id=self.capacity_reservation_id,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            instances=self.instances,
            state=self.state)


def get_instances(availability_domain: Optional[str] = None,
                  capacity_reservation_id: Optional[str] = None,
                  compartment_id: Optional[str] = None,
                  display_name: Optional[str] = None,
                  filters: Optional[Sequence[pulumi.InputType['GetInstancesFilterArgs']]] = None,
                  state: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstancesResult:
    """
    This data source provides the list of Instances in Oracle Cloud Infrastructure Core service.

    Lists the instances in the specified compartment and the specified availability domain.
    You can filter the results by specifying an instance name (the list will include all the identically-named
    instances in the compartment).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instances = oci.core.get_instances(compartment_id=var["compartment_id"],
        availability_domain=var["instance_availability_domain"],
        capacity_reservation_id=oci_core_capacity_reservation["test_capacity_reservation"]["id"],
        display_name=var["instance_display_name"],
        state=var["instance_state"])
    ```


    :param str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param str capacity_reservation_id: The OCID of the compute capacity reservation.
    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    :param str state: A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['capacityReservationId'] = capacity_reservation_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getInstances:getInstances', __args__, opts=opts, typ=GetInstancesResult).value

    return AwaitableGetInstancesResult(
        availability_domain=__ret__.availability_domain,
        capacity_reservation_id=__ret__.capacity_reservation_id,
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        instances=__ret__.instances,
        state=__ret__.state)