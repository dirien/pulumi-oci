# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities

__all__ = [
    'GetCoreListingResourceVersionResult',
    'AwaitableGetCoreListingResourceVersionResult',
    'get_core_listing_resource_version',
]

@pulumi.output_type
class GetCoreListingResourceVersionResult:
    """
    A collection of values returned by GetCoreListingResourceVersion.
    """
    def __init__(__self__, accessible_ports=None, allowed_actions=None, available_regions=None, compatible_shapes=None, id=None, listing_id=None, listing_resource_id=None, listing_resource_version=None, resource_version=None, time_published=None):
        if accessible_ports and not isinstance(accessible_ports, list):
            raise TypeError("Expected argument 'accessible_ports' to be a list")
        pulumi.set(__self__, "accessible_ports", accessible_ports)
        if allowed_actions and not isinstance(allowed_actions, list):
            raise TypeError("Expected argument 'allowed_actions' to be a list")
        pulumi.set(__self__, "allowed_actions", allowed_actions)
        if available_regions and not isinstance(available_regions, list):
            raise TypeError("Expected argument 'available_regions' to be a list")
        pulumi.set(__self__, "available_regions", available_regions)
        if compatible_shapes and not isinstance(compatible_shapes, list):
            raise TypeError("Expected argument 'compatible_shapes' to be a list")
        pulumi.set(__self__, "compatible_shapes", compatible_shapes)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if listing_id and not isinstance(listing_id, str):
            raise TypeError("Expected argument 'listing_id' to be a str")
        pulumi.set(__self__, "listing_id", listing_id)
        if listing_resource_id and not isinstance(listing_resource_id, str):
            raise TypeError("Expected argument 'listing_resource_id' to be a str")
        pulumi.set(__self__, "listing_resource_id", listing_resource_id)
        if listing_resource_version and not isinstance(listing_resource_version, str):
            raise TypeError("Expected argument 'listing_resource_version' to be a str")
        pulumi.set(__self__, "listing_resource_version", listing_resource_version)
        if resource_version and not isinstance(resource_version, str):
            raise TypeError("Expected argument 'resource_version' to be a str")
        pulumi.set(__self__, "resource_version", resource_version)
        if time_published and not isinstance(time_published, str):
            raise TypeError("Expected argument 'time_published' to be a str")
        pulumi.set(__self__, "time_published", time_published)

    @property
    @pulumi.getter(name="accessiblePorts")
    def accessible_ports(self) -> Sequence[int]:
        return pulumi.get(self, "accessible_ports")

    @property
    @pulumi.getter(name="allowedActions")
    def allowed_actions(self) -> Sequence[str]:
        return pulumi.get(self, "allowed_actions")

    @property
    @pulumi.getter(name="availableRegions")
    def available_regions(self) -> Sequence[str]:
        return pulumi.get(self, "available_regions")

    @property
    @pulumi.getter(name="compatibleShapes")
    def compatible_shapes(self) -> Sequence[str]:
        return pulumi.get(self, "compatible_shapes")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="listingId")
    def listing_id(self) -> str:
        return pulumi.get(self, "listing_id")

    @property
    @pulumi.getter(name="listingResourceId")
    def listing_resource_id(self) -> str:
        return pulumi.get(self, "listing_resource_id")

    @property
    @pulumi.getter(name="listingResourceVersion")
    def listing_resource_version(self) -> str:
        return pulumi.get(self, "listing_resource_version")

    @property
    @pulumi.getter(name="resourceVersion")
    def resource_version(self) -> str:
        return pulumi.get(self, "resource_version")

    @property
    @pulumi.getter(name="timePublished")
    def time_published(self) -> str:
        return pulumi.get(self, "time_published")


class AwaitableGetCoreListingResourceVersionResult(GetCoreListingResourceVersionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCoreListingResourceVersionResult(
            accessible_ports=self.accessible_ports,
            allowed_actions=self.allowed_actions,
            available_regions=self.available_regions,
            compatible_shapes=self.compatible_shapes,
            id=self.id,
            listing_id=self.listing_id,
            listing_resource_id=self.listing_resource_id,
            listing_resource_version=self.listing_resource_version,
            resource_version=self.resource_version,
            time_published=self.time_published)


def get_core_listing_resource_version(listing_id: Optional[str] = None,
                                      resource_version: Optional[str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCoreListingResourceVersionResult:
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()
    __args__['listingId'] = listing_id
    __args__['resourceVersion'] = resource_version
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getCoreListingResourceVersion:GetCoreListingResourceVersion', __args__, opts=opts, typ=GetCoreListingResourceVersionResult).value

    return AwaitableGetCoreListingResourceVersionResult(
        accessible_ports=__ret__.accessible_ports,
        allowed_actions=__ret__.allowed_actions,
        available_regions=__ret__.available_regions,
        compatible_shapes=__ret__.compatible_shapes,
        id=__ret__.id,
        listing_id=__ret__.listing_id,
        listing_resource_id=__ret__.listing_resource_id,
        listing_resource_version=__ret__.listing_resource_version,
        resource_version=__ret__.resource_version,
        time_published=__ret__.time_published)