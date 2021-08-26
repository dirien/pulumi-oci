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
    'GetServicesResult',
    'AwaitableGetServicesResult',
    'get_services',
]

@pulumi.output_type
class GetServicesResult:
    """
    A collection of values returned by getServices.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, services=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if services and not isinstance(services, list):
            raise TypeError("Expected argument 'services' to be a list")
        pulumi.set(__self__, "services", services)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetServicesFilterResult']]:
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
    def services(self) -> Sequence['outputs.GetServicesServiceResult']:
        """
        The list of services.
        """
        return pulumi.get(self, "services")


class AwaitableGetServicesResult(GetServicesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetServicesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            services=self.services)


def get_services(compartment_id: Optional[str] = None,
                 filters: Optional[Sequence[pulumi.InputType['GetServicesFilterArgs']]] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetServicesResult:
    """
    This data source provides the list of Services in Oracle Cloud Infrastructure Limits service.

    Returns the list of supported services.
    This includes the programmatic service name, along with the friendly service name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_services = oci.limits.get_services(compartment_id=var["tenancy_ocid"])
    ```


    :param str compartment_id: The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:limits/getServices:getServices', __args__, opts=opts, typ=GetServicesResult).value

    return AwaitableGetServicesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        services=__ret__.services)
