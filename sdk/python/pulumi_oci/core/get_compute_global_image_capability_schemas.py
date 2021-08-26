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
    'GetComputeGlobalImageCapabilitySchemasResult',
    'AwaitableGetComputeGlobalImageCapabilitySchemasResult',
    'get_compute_global_image_capability_schemas',
]

@pulumi.output_type
class GetComputeGlobalImageCapabilitySchemasResult:
    """
    A collection of values returned by getComputeGlobalImageCapabilitySchemas.
    """
    def __init__(__self__, compartment_id=None, compute_global_image_capability_schemas=None, display_name=None, filters=None, id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_global_image_capability_schemas and not isinstance(compute_global_image_capability_schemas, list):
            raise TypeError("Expected argument 'compute_global_image_capability_schemas' to be a list")
        pulumi.set(__self__, "compute_global_image_capability_schemas", compute_global_image_capability_schemas)
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
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The OCID of the compartment containing the compute global image capability schema
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeGlobalImageCapabilitySchemas")
    def compute_global_image_capability_schemas(self) -> Sequence['outputs.GetComputeGlobalImageCapabilitySchemasComputeGlobalImageCapabilitySchemaResult']:
        """
        The list of compute_global_image_capability_schemas.
        """
        return pulumi.get(self, "compute_global_image_capability_schemas")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly name for the compute global image capability schema.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeGlobalImageCapabilitySchemasFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetComputeGlobalImageCapabilitySchemasResult(GetComputeGlobalImageCapabilitySchemasResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeGlobalImageCapabilitySchemasResult(
            compartment_id=self.compartment_id,
            compute_global_image_capability_schemas=self.compute_global_image_capability_schemas,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_compute_global_image_capability_schemas(compartment_id: Optional[str] = None,
                                                display_name: Optional[str] = None,
                                                filters: Optional[Sequence[pulumi.InputType['GetComputeGlobalImageCapabilitySchemasFilterArgs']]] = None,
                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeGlobalImageCapabilitySchemasResult:
    """
    This data source provides the list of Compute Global Image Capability Schemas in Oracle Cloud Infrastructure Core service.

    Lists Compute Global Image Capability Schema in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_global_image_capability_schemas = oci.core.get_compute_global_image_capability_schemas(compartment_id=var["compartment_id"],
        display_name=var["compute_global_image_capability_schema_display_name"])
    ```


    :param str compartment_id: A filter to return only resources that match the given compartment OCID exactly.
    :param str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getComputeGlobalImageCapabilitySchemas:getComputeGlobalImageCapabilitySchemas', __args__, opts=opts, typ=GetComputeGlobalImageCapabilitySchemasResult).value

    return AwaitableGetComputeGlobalImageCapabilitySchemasResult(
        compartment_id=__ret__.compartment_id,
        compute_global_image_capability_schemas=__ret__.compute_global_image_capability_schemas,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id)
