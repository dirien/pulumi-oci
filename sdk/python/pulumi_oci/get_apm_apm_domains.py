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
    'GetApmApmDomainsResult',
    'AwaitableGetApmApmDomainsResult',
    'get_apm_apm_domains',
]

@pulumi.output_type
class GetApmApmDomainsResult:
    """
    A collection of values returned by GetApmApmDomains.
    """
    def __init__(__self__, apm_domains=None, compartment_id=None, display_name=None, filters=None, id=None, state=None):
        if apm_domains and not isinstance(apm_domains, list):
            raise TypeError("Expected argument 'apm_domains' to be a list")
        pulumi.set(__self__, "apm_domains", apm_domains)
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
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="apmDomains")
    def apm_domains(self) -> Sequence['outputs.GetApmApmDomainsApmDomainResult']:
        """
        The list of apm_domains.
        """
        return pulumi.get(self, "apm_domains")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment corresponding to the APM Domain.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        APM Domain display name, can be updated.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetApmApmDomainsFilterResult']]:
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
    def state(self) -> Optional[str]:
        """
        The current lifecycle state of the APM Domain.
        """
        return pulumi.get(self, "state")


class AwaitableGetApmApmDomainsResult(GetApmApmDomainsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetApmApmDomainsResult(
            apm_domains=self.apm_domains,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_apm_apm_domains(compartment_id: Optional[str] = None,
                        display_name: Optional[str] = None,
                        filters: Optional[Sequence[pulumi.InputType['GetApmApmDomainsFilterArgs']]] = None,
                        state: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetApmApmDomainsResult:
    """
    This data source provides the list of Apm Domains in Oracle Cloud Infrastructure Apm service.

    Lists all APM Domains for the specified tenant compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_apm_domains = oci.get_apm_apm_domains(compartment_id=var["compartment_id"],
        display_name=var["apm_domain_display_name"],
        state=var["apm_domain_state"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str state: A filter to return only resources that match the given life-cycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getApmApmDomains:GetApmApmDomains', __args__, opts=opts, typ=GetApmApmDomainsResult).value

    return AwaitableGetApmApmDomainsResult(
        apm_domains=__ret__.apm_domains,
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state)