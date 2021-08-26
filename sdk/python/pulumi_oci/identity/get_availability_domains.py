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
    'GetAvailabilityDomainsResult',
    'AwaitableGetAvailabilityDomainsResult',
    'get_availability_domains',
]

@pulumi.output_type
class GetAvailabilityDomainsResult:
    """
    A collection of values returned by getAvailabilityDomains.
    """
    def __init__(__self__, availability_domains=None, compartment_id=None, filters=None, id=None):
        if availability_domains and not isinstance(availability_domains, list):
            raise TypeError("Expected argument 'availability_domains' to be a list")
        pulumi.set(__self__, "availability_domains", availability_domains)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="availabilityDomains")
    def availability_domains(self) -> Sequence['outputs.GetAvailabilityDomainsAvailabilityDomainResult']:
        """
        The list of availability_domains.
        """
        return pulumi.get(self, "availability_domains")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAvailabilityDomainsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetAvailabilityDomainsResult(GetAvailabilityDomainsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAvailabilityDomainsResult(
            availability_domains=self.availability_domains,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id)


def get_availability_domains(compartment_id: Optional[str] = None,
                             filters: Optional[Sequence[pulumi.InputType['GetAvailabilityDomainsFilterArgs']]] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAvailabilityDomainsResult:
    """
    This data source provides the list of Availability Domains in Oracle Cloud Infrastructure Identity service.

    Lists the availability domains in your tenancy. Specify the OCID of either the tenancy or another
    of your compartments as the value for the compartment ID (remember that the tenancy is simply the root compartment).
    See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).
    Note that the order of the results returned can change if availability domains are added or removed; therefore, do not
    create a dependency on the list order.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_availability_domains = oci.identity.get_availability_domains(compartment_id=var["tenancy_ocid"])
    ```


    :param str compartment_id: The OCID of the compartment (remember that the tenancy is simply the root compartment).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:identity/getAvailabilityDomains:getAvailabilityDomains', __args__, opts=opts, typ=GetAvailabilityDomainsResult).value

    return AwaitableGetAvailabilityDomainsResult(
        availability_domains=__ret__.availability_domains,
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id)
