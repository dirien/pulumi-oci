# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities

__all__ = [
    'GetLimitsResourceAvailabilityResult',
    'AwaitableGetLimitsResourceAvailabilityResult',
    'get_limits_resource_availability',
]

@pulumi.output_type
class GetLimitsResourceAvailabilityResult:
    """
    A collection of values returned by GetLimitsResourceAvailability.
    """
    def __init__(__self__, availability_domain=None, available=None, compartment_id=None, effective_quota_value=None, fractional_availability=None, fractional_usage=None, id=None, limit_name=None, service_name=None, used=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if available and not isinstance(available, str):
            raise TypeError("Expected argument 'available' to be a str")
        pulumi.set(__self__, "available", available)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if effective_quota_value and not isinstance(effective_quota_value, float):
            raise TypeError("Expected argument 'effective_quota_value' to be a float")
        pulumi.set(__self__, "effective_quota_value", effective_quota_value)
        if fractional_availability and not isinstance(fractional_availability, float):
            raise TypeError("Expected argument 'fractional_availability' to be a float")
        pulumi.set(__self__, "fractional_availability", fractional_availability)
        if fractional_usage and not isinstance(fractional_usage, float):
            raise TypeError("Expected argument 'fractional_usage' to be a float")
        pulumi.set(__self__, "fractional_usage", fractional_usage)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if limit_name and not isinstance(limit_name, str):
            raise TypeError("Expected argument 'limit_name' to be a str")
        pulumi.set(__self__, "limit_name", limit_name)
        if service_name and not isinstance(service_name, str):
            raise TypeError("Expected argument 'service_name' to be a str")
        pulumi.set(__self__, "service_name", service_name)
        if used and not isinstance(used, str):
            raise TypeError("Expected argument 'used' to be a str")
        pulumi.set(__self__, "used", used)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[str]:
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter
    def available(self) -> str:
        """
        The count of available resources. To support resources with fractional counts, the field rounds down to the nearest integer.
        """
        return pulumi.get(self, "available")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="effectiveQuotaValue")
    def effective_quota_value(self) -> float:
        """
        The effective quota value for the given compartment. This field is only present if there is a current quota policy affecting the current resource in the target region or availability domain.
        """
        return pulumi.get(self, "effective_quota_value")

    @property
    @pulumi.getter(name="fractionalAvailability")
    def fractional_availability(self) -> float:
        """
        The most accurate count of available resources.
        """
        return pulumi.get(self, "fractional_availability")

    @property
    @pulumi.getter(name="fractionalUsage")
    def fractional_usage(self) -> float:
        """
        The current most accurate usage in the given compartment.
        """
        return pulumi.get(self, "fractional_usage")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="limitName")
    def limit_name(self) -> str:
        return pulumi.get(self, "limit_name")

    @property
    @pulumi.getter(name="serviceName")
    def service_name(self) -> str:
        return pulumi.get(self, "service_name")

    @property
    @pulumi.getter
    def used(self) -> str:
        """
        The current usage in the given compartment. To support resources with fractional counts, the field rounds up to the nearest integer.
        """
        return pulumi.get(self, "used")


class AwaitableGetLimitsResourceAvailabilityResult(GetLimitsResourceAvailabilityResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLimitsResourceAvailabilityResult(
            availability_domain=self.availability_domain,
            available=self.available,
            compartment_id=self.compartment_id,
            effective_quota_value=self.effective_quota_value,
            fractional_availability=self.fractional_availability,
            fractional_usage=self.fractional_usage,
            id=self.id,
            limit_name=self.limit_name,
            service_name=self.service_name,
            used=self.used)


def get_limits_resource_availability(availability_domain: Optional[str] = None,
                                     compartment_id: Optional[str] = None,
                                     limit_name: Optional[str] = None,
                                     service_name: Optional[str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLimitsResourceAvailabilityResult:
    """
    This data source provides details about a specific Resource Availability resource in Oracle Cloud Infrastructure Limits service.

    For a given compartmentId, resource limit name, and scope, returns the following:
      * The number of available resources associated with the given limit.
      * The usage in the selected compartment for the given limit.
          Note that not all resource limits support this API. If the value is not available, the API returns a 404 response.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_resource_availability = oci.get_limits_resource_availability(compartment_id=var["tenancy_ocid"],
        limit_name=var["resource_availability_limit_name"],
        service_name=oci_limits_service["test_service"]["name"],
        availability_domain=var["resource_availability_availability_domain"])
    ```


    :param str availability_domain: This field is mandatory if the scopeType of the target resource limit is AD. Otherwise, this field should be omitted. If the above requirements are not met, the API returns a 400 - InvalidParameter response.
    :param str compartment_id: The OCID of the compartment for which data is being fetched.
    :param str limit_name: The limit name for which to fetch the data.
    :param str service_name: The service name of the target quota.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['limitName'] = limit_name
    __args__['serviceName'] = service_name
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:index/getLimitsResourceAvailability:GetLimitsResourceAvailability', __args__, opts=opts, typ=GetLimitsResourceAvailabilityResult).value

    return AwaitableGetLimitsResourceAvailabilityResult(
        availability_domain=__ret__.availability_domain,
        available=__ret__.available,
        compartment_id=__ret__.compartment_id,
        effective_quota_value=__ret__.effective_quota_value,
        fractional_availability=__ret__.fractional_availability,
        fractional_usage=__ret__.fractional_usage,
        id=__ret__.id,
        limit_name=__ret__.limit_name,
        service_name=__ret__.service_name,
        used=__ret__.used)