# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetGatewayResult',
    'AwaitableGetGatewayResult',
    'get_gateway',
]

@pulumi.output_type
class GetGatewayResult:
    """
    A collection of values returned by getGateway.
    """
    def __init__(__self__, certificate_id=None, compartment_id=None, defined_tags=None, display_name=None, endpoint_type=None, freeform_tags=None, gateway_id=None, hostname=None, id=None, ip_addresses=None, lifecycle_details=None, response_cache_details=None, state=None, subnet_id=None, time_created=None, time_updated=None):
        if certificate_id and not isinstance(certificate_id, str):
            raise TypeError("Expected argument 'certificate_id' to be a str")
        pulumi.set(__self__, "certificate_id", certificate_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if endpoint_type and not isinstance(endpoint_type, str):
            raise TypeError("Expected argument 'endpoint_type' to be a str")
        pulumi.set(__self__, "endpoint_type", endpoint_type)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if gateway_id and not isinstance(gateway_id, str):
            raise TypeError("Expected argument 'gateway_id' to be a str")
        pulumi.set(__self__, "gateway_id", gateway_id)
        if hostname and not isinstance(hostname, str):
            raise TypeError("Expected argument 'hostname' to be a str")
        pulumi.set(__self__, "hostname", hostname)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ip_addresses and not isinstance(ip_addresses, list):
            raise TypeError("Expected argument 'ip_addresses' to be a list")
        pulumi.set(__self__, "ip_addresses", ip_addresses)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if response_cache_details and not isinstance(response_cache_details, dict):
            raise TypeError("Expected argument 'response_cache_details' to be a dict")
        pulumi.set(__self__, "response_cache_details", response_cache_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subnet_id and not isinstance(subnet_id, str):
            raise TypeError("Expected argument 'subnet_id' to be a str")
        pulumi.set(__self__, "subnet_id", subnet_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="certificateId")
    def certificate_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "certificate_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="endpointType")
    def endpoint_type(self) -> str:
        """
        Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
        """
        return pulumi.get(self, "endpoint_type")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="gatewayId")
    def gateway_id(self) -> str:
        return pulumi.get(self, "gateway_id")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        The hostname for APIs deployed on the gateway.
        """
        return pulumi.get(self, "hostname")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipAddresses")
    def ip_addresses(self) -> Sequence['outputs.GetGatewayIpAddressResult']:
        """
        An array of IP addresses associated with the gateway.
        """
        return pulumi.get(self, "ip_addresses")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="responseCacheDetails")
    def response_cache_details(self) -> 'outputs.GetGatewayResponseCacheDetailsResult':
        """
        Base Gateway response cache.
        """
        return pulumi.get(self, "response_cache_details")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the gateway.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetGatewayResult(GetGatewayResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetGatewayResult(
            certificate_id=self.certificate_id,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            endpoint_type=self.endpoint_type,
            freeform_tags=self.freeform_tags,
            gateway_id=self.gateway_id,
            hostname=self.hostname,
            id=self.id,
            ip_addresses=self.ip_addresses,
            lifecycle_details=self.lifecycle_details,
            response_cache_details=self.response_cache_details,
            state=self.state,
            subnet_id=self.subnet_id,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_gateway(gateway_id: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetGatewayResult:
    """
    This data source provides details about a specific Gateway resource in Oracle Cloud Infrastructure API Gateway service.

    Gets a gateway by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_gateway = oci.apigateway.get_gateway(gateway_id=oci_apigateway_gateway["test_gateway"]["id"])
    ```


    :param str gateway_id: The ocid of the gateway.
    """
    __args__ = dict()
    __args__['gatewayId'] = gateway_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:apigateway/getGateway:getGateway', __args__, opts=opts, typ=GetGatewayResult).value

    return AwaitableGetGatewayResult(
        certificate_id=__ret__.certificate_id,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        endpoint_type=__ret__.endpoint_type,
        freeform_tags=__ret__.freeform_tags,
        gateway_id=__ret__.gateway_id,
        hostname=__ret__.hostname,
        id=__ret__.id,
        ip_addresses=__ret__.ip_addresses,
        lifecycle_details=__ret__.lifecycle_details,
        response_cache_details=__ret__.response_cache_details,
        state=__ret__.state,
        subnet_id=__ret__.subnet_id,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
