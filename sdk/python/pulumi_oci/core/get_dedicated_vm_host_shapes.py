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
    'GetDedicatedVmHostShapesResult',
    'AwaitableGetDedicatedVmHostShapesResult',
    'get_dedicated_vm_host_shapes',
]

@pulumi.output_type
class GetDedicatedVmHostShapesResult:
    """
    A collection of values returned by getDedicatedVmHostShapes.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, dedicated_vm_host_shapes=None, filters=None, id=None, instance_shape_name=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if dedicated_vm_host_shapes and not isinstance(dedicated_vm_host_shapes, list):
            raise TypeError("Expected argument 'dedicated_vm_host_shapes' to be a list")
        pulumi.set(__self__, "dedicated_vm_host_shapes", dedicated_vm_host_shapes)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_shape_name and not isinstance(instance_shape_name, str):
            raise TypeError("Expected argument 'instance_shape_name' to be a str")
        pulumi.set(__self__, "instance_shape_name", instance_shape_name)

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
    @pulumi.getter(name="dedicatedVmHostShapes")
    def dedicated_vm_host_shapes(self) -> Sequence['outputs.GetDedicatedVmHostShapesDedicatedVmHostShapeResult']:
        """
        The list of dedicated_vm_host_shapes.
        """
        return pulumi.get(self, "dedicated_vm_host_shapes")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDedicatedVmHostShapesFilterResult']]:
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


class AwaitableGetDedicatedVmHostShapesResult(GetDedicatedVmHostShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDedicatedVmHostShapesResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            dedicated_vm_host_shapes=self.dedicated_vm_host_shapes,
            filters=self.filters,
            id=self.id,
            instance_shape_name=self.instance_shape_name)


def get_dedicated_vm_host_shapes(availability_domain: Optional[str] = None,
                                 compartment_id: Optional[str] = None,
                                 filters: Optional[Sequence[pulumi.InputType['GetDedicatedVmHostShapesFilterArgs']]] = None,
                                 instance_shape_name: Optional[str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDedicatedVmHostShapesResult:
    """
    This data source provides the list of Dedicated Vm Host Shapes in Oracle Cloud Infrastructure Core service.

    Lists the shapes that can be used to launch a dedicated virtual machine host within the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vm_host_shapes = oci.core.get_dedicated_vm_host_shapes(compartment_id=var["compartment_id"],
        availability_domain=var["dedicated_vm_host_shape_availability_domain"],
        instance_shape_name=var["dedicated_vm_host_shape_instance_shape_name"])
    ```


    :param str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str instance_shape_name: The name for the instance's shape.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['instanceShapeName'] = instance_shape_name
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getDedicatedVmHostShapes:getDedicatedVmHostShapes', __args__, opts=opts, typ=GetDedicatedVmHostShapesResult).value

    return AwaitableGetDedicatedVmHostShapesResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        dedicated_vm_host_shapes=__ret__.dedicated_vm_host_shapes,
        filters=__ret__.filters,
        id=__ret__.id,
        instance_shape_name=__ret__.instance_shape_name)
