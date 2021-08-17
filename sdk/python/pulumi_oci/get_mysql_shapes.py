# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetMysqlShapesResult',
    'AwaitableGetMysqlShapesResult',
    'get_mysql_shapes',
]

@pulumi.output_type
class GetMysqlShapesResult:
    """
    A collection of values returned by GetMysqlShapes.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, filters=None, id=None, is_supported_fors=None, name=None, shapes=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_supported_fors and not isinstance(is_supported_fors, list):
            raise TypeError("Expected argument 'is_supported_fors' to be a list")
        pulumi.set(__self__, "is_supported_fors", is_supported_fors)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if shapes and not isinstance(shapes, list):
            raise TypeError("Expected argument 'shapes' to be a list")
        pulumi.set(__self__, "shapes", shapes)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[str]:
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMysqlShapesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isSupportedFors")
    def is_supported_fors(self) -> Optional[Sequence[str]]:
        """
        What service features the shape is supported for.
        """
        return pulumi.get(self, "is_supported_fors")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name of the shape used for the DB System.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def shapes(self) -> Sequence['outputs.GetMysqlShapesShapeResult']:
        """
        The list of shapes.
        """
        return pulumi.get(self, "shapes")


class AwaitableGetMysqlShapesResult(GetMysqlShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMysqlShapesResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            is_supported_fors=self.is_supported_fors,
            name=self.name,
            shapes=self.shapes)


def get_mysql_shapes(availability_domain: Optional[str] = None,
                     compartment_id: Optional[str] = None,
                     filters: Optional[Sequence[pulumi.InputType['GetMysqlShapesFilterArgs']]] = None,
                     is_supported_fors: Optional[Sequence[str]] = None,
                     name: Optional[str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMysqlShapesResult:
    """
    This data source provides the list of Shapes in Oracle Cloud Infrastructure MySQL Database service.

    Gets a list of the shapes you can use to create a new MySQL DB System.
    The shape determines the resources allocated to the DB System:
    CPU cores and memory for VM shapes; CPU cores, memory and
    storage for non-VM (or bare metal) shapes.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_shapes = oci.get_mysql_shapes(compartment_id=var["compartment_id"],
        availability_domain=var["shape_availability_domain"],
        is_supported_fors=var["shape_is_supported_for"],
        name=var["shape_name"])
    ```


    :param str availability_domain: The name of the Availability Domain.
    :param str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param Sequence[str] is_supported_fors: Return shapes that are supported by the service feature.
    :param str name: Name
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['isSupportedFors'] = is_supported_fors
    __args__['name'] = name
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getMysqlShapes:GetMysqlShapes', __args__, opts=opts, typ=GetMysqlShapesResult).value

    return AwaitableGetMysqlShapesResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        is_supported_fors=__ret__.is_supported_fors,
        name=__ret__.name,
        shapes=__ret__.shapes)