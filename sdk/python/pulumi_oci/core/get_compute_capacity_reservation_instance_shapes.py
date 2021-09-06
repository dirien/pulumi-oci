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
    'GetComputeCapacityReservationInstanceShapesResult',
    'AwaitableGetComputeCapacityReservationInstanceShapesResult',
    'get_compute_capacity_reservation_instance_shapes',
]

@pulumi.output_type
class GetComputeCapacityReservationInstanceShapesResult:
    """
    A collection of values returned by getComputeCapacityReservationInstanceShapes.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, compute_capacity_reservation_instance_shapes=None, display_name=None, filters=None, id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_capacity_reservation_instance_shapes and not isinstance(compute_capacity_reservation_instance_shapes, list):
            raise TypeError("Expected argument 'compute_capacity_reservation_instance_shapes' to be a list")
        pulumi.set(__self__, "compute_capacity_reservation_instance_shapes", compute_capacity_reservation_instance_shapes)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[str]:
        """
        The shape's availability domain.
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeCapacityReservationInstanceShapes")
    def compute_capacity_reservation_instance_shapes(self) -> Sequence['outputs.GetComputeCapacityReservationInstanceShapesComputeCapacityReservationInstanceShapeResult']:
        """
        The list of compute_capacity_reservation_instance_shapes.
        """
        return pulumi.get(self, "compute_capacity_reservation_instance_shapes")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeCapacityReservationInstanceShapesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetComputeCapacityReservationInstanceShapesResult(GetComputeCapacityReservationInstanceShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeCapacityReservationInstanceShapesResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            compute_capacity_reservation_instance_shapes=self.compute_capacity_reservation_instance_shapes,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_compute_capacity_reservation_instance_shapes(availability_domain: Optional[str] = None,
                                                     compartment_id: Optional[str] = None,
                                                     display_name: Optional[str] = None,
                                                     filters: Optional[Sequence[pulumi.InputType['GetComputeCapacityReservationInstanceShapesFilterArgs']]] = None,
                                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeCapacityReservationInstanceShapesResult:
    """
    This data source provides the list of Compute Capacity Reservation Instance Shapes in Oracle Cloud Infrastructure Core service.

    Lists the shapes that can be reserved within the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_capacity_reservation_instance_shapes = oci.core.get_compute_capacity_reservation_instance_shapes(compartment_id=var["compartment_id"],
        availability_domain=var["compute_capacity_reservation_instance_shape_availability_domain"],
        display_name=var["compute_capacity_reservation_instance_shape_display_name"])
    ```


    :param str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getComputeCapacityReservationInstanceShapes:getComputeCapacityReservationInstanceShapes', __args__, opts=opts, typ=GetComputeCapacityReservationInstanceShapesResult).value

    return AwaitableGetComputeCapacityReservationInstanceShapesResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        compute_capacity_reservation_instance_shapes=__ret__.compute_capacity_reservation_instance_shapes,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id)
