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
    'GetResolverEndpointsResult',
    'AwaitableGetResolverEndpointsResult',
    'get_resolver_endpoints',
]

@pulumi.output_type
class GetResolverEndpointsResult:
    """
    A collection of values returned by getResolverEndpoints.
    """
    def __init__(__self__, filters=None, id=None, name=None, resolver_endpoints=None, resolver_id=None, scope=None, state=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if resolver_endpoints and not isinstance(resolver_endpoints, list):
            raise TypeError("Expected argument 'resolver_endpoints' to be a list")
        pulumi.set(__self__, "resolver_endpoints", resolver_endpoints)
        if resolver_id and not isinstance(resolver_id, str):
            raise TypeError("Expected argument 'resolver_id' to be a str")
        pulumi.set(__self__, "resolver_id", resolver_id)
        if scope and not isinstance(scope, str):
            raise TypeError("Expected argument 'scope' to be a str")
        pulumi.set(__self__, "scope", scope)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetResolverEndpointsFilterResult']]:
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
    def name(self) -> Optional[str]:
        """
        The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="resolverEndpoints")
    def resolver_endpoints(self) -> Sequence['outputs.GetResolverEndpointsResolverEndpointResult']:
        """
        The list of resolver_endpoints.
        """
        return pulumi.get(self, "resolver_endpoints")

    @property
    @pulumi.getter(name="resolverId")
    def resolver_id(self) -> str:
        return pulumi.get(self, "resolver_id")

    @property
    @pulumi.getter
    def scope(self) -> str:
        return pulumi.get(self, "scope")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the resource.
        """
        return pulumi.get(self, "state")


class AwaitableGetResolverEndpointsResult(GetResolverEndpointsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetResolverEndpointsResult(
            filters=self.filters,
            id=self.id,
            name=self.name,
            resolver_endpoints=self.resolver_endpoints,
            resolver_id=self.resolver_id,
            scope=self.scope,
            state=self.state)


def get_resolver_endpoints(filters: Optional[Sequence[pulumi.InputType['GetResolverEndpointsFilterArgs']]] = None,
                           name: Optional[str] = None,
                           resolver_id: Optional[str] = None,
                           scope: Optional[str] = None,
                           state: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetResolverEndpointsResult:
    """
    This data source provides the list of Resolver Endpoints in Oracle Cloud Infrastructure DNS service.

    Gets a list of all endpoints within a resolver. The collection can be filtered by name or lifecycle state.
    It can be sorted on creation time or name both in ASC or DESC order. Note that when no lifecycleState
    query parameter is provided, the collection does not include resolver endpoints in the DELETED
    lifecycle state to be consistent with other operations of the API. Requires a `PRIVATE` scope query parameter.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_resolver_endpoints = oci.dns.get_resolver_endpoints(resolver_id=oci_dns_resolver["test_resolver"]["id"],
        scope="PRIVATE",
        name=var["resolver_endpoint_name"],
        state=var["resolver_endpoint_state"])
    ```


    :param str name: The name of a resource.
    :param str resolver_id: The OCID of the target resolver.
    :param str scope: Value must be `PRIVATE` when listing private name resolver endpoints.
    :param str state: The state of a resource.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['resolverId'] = resolver_id
    __args__['scope'] = scope
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:dns/getResolverEndpoints:getResolverEndpoints', __args__, opts=opts, typ=GetResolverEndpointsResult).value

    return AwaitableGetResolverEndpointsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        resolver_endpoints=__ret__.resolver_endpoints,
        resolver_id=__ret__.resolver_id,
        scope=__ret__.scope,
        state=__ret__.state)
