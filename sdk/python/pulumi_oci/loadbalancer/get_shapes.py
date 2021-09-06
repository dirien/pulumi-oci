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
    'GetShapesResult',
    'AwaitableGetShapesResult',
    'get_shapes',
]

@pulumi.output_type
class GetShapesResult:
    """
    A collection of values returned by getShapes.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, shapes=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if shapes and not isinstance(shapes, list):
            raise TypeError("Expected argument 'shapes' to be a list")
        pulumi.set(__self__, "shapes", shapes)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetShapesFilterResult']]:
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
    def shapes(self) -> Sequence['outputs.GetShapesShapeResult']:
        """
        The list of shapes.
        """
        return pulumi.get(self, "shapes")


class AwaitableGetShapesResult(GetShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetShapesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            shapes=self.shapes)


def get_shapes(compartment_id: Optional[str] = None,
               filters: Optional[Sequence[pulumi.InputType['GetShapesFilterArgs']]] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetShapesResult:
    """
    This data source provides the list of Load Balancer Shapes in Oracle Cloud Infrastructure Load Balancer service.

    Lists the valid load balancer shapes.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_load_balancer_shapes = oci.loadbalancer.get_shapes(compartment_id=var["compartment_id"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer shapes to list.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:loadbalancer/getShapes:getShapes', __args__, opts=opts, typ=GetShapesResult).value

    return AwaitableGetShapesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        shapes=__ret__.shapes)
