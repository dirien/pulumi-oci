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
    'GetVirtualCircuitResult',
    'AwaitableGetVirtualCircuitResult',
    'get_virtual_circuit',
]

@pulumi.output_type
class GetVirtualCircuitResult:
    """
    A collection of values returned by getVirtualCircuit.
    """
    def __init__(__self__, bandwidth_shape_name=None, bgp_ipv6session_state=None, bgp_management=None, bgp_session_state=None, compartment_id=None, cross_connect_mappings=None, customer_asn=None, customer_bgp_asn=None, defined_tags=None, display_name=None, freeform_tags=None, gateway_id=None, id=None, oracle_bgp_asn=None, provider_service_id=None, provider_service_key_name=None, provider_state=None, public_prefixes=None, reference_comment=None, region=None, routing_policies=None, service_type=None, state=None, time_created=None, type=None, virtual_circuit_id=None):
        if bandwidth_shape_name and not isinstance(bandwidth_shape_name, str):
            raise TypeError("Expected argument 'bandwidth_shape_name' to be a str")
        pulumi.set(__self__, "bandwidth_shape_name", bandwidth_shape_name)
        if bgp_ipv6session_state and not isinstance(bgp_ipv6session_state, str):
            raise TypeError("Expected argument 'bgp_ipv6session_state' to be a str")
        pulumi.set(__self__, "bgp_ipv6session_state", bgp_ipv6session_state)
        if bgp_management and not isinstance(bgp_management, str):
            raise TypeError("Expected argument 'bgp_management' to be a str")
        if bgp_management is not None:
            warnings.warn("""The 'bgp_management' field has been deprecated. Please use the 'oci_core_fast_connect_provider_service' data source instead.""", DeprecationWarning)
            pulumi.log.warn("""bgp_management is deprecated: The 'bgp_management' field has been deprecated. Please use the 'oci_core_fast_connect_provider_service' data source instead.""")

        pulumi.set(__self__, "bgp_management", bgp_management)
        if bgp_session_state and not isinstance(bgp_session_state, str):
            raise TypeError("Expected argument 'bgp_session_state' to be a str")
        pulumi.set(__self__, "bgp_session_state", bgp_session_state)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if cross_connect_mappings and not isinstance(cross_connect_mappings, list):
            raise TypeError("Expected argument 'cross_connect_mappings' to be a list")
        pulumi.set(__self__, "cross_connect_mappings", cross_connect_mappings)
        if customer_asn and not isinstance(customer_asn, str):
            raise TypeError("Expected argument 'customer_asn' to be a str")
        pulumi.set(__self__, "customer_asn", customer_asn)
        if customer_bgp_asn and not isinstance(customer_bgp_asn, int):
            raise TypeError("Expected argument 'customer_bgp_asn' to be a int")
        if customer_bgp_asn is not None:
            warnings.warn("""The 'customer_bgp_asn' field has been deprecated. Please use 'customer_asn' instead.""", DeprecationWarning)
            pulumi.log.warn("""customer_bgp_asn is deprecated: The 'customer_bgp_asn' field has been deprecated. Please use 'customer_asn' instead.""")

        pulumi.set(__self__, "customer_bgp_asn", customer_bgp_asn)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if gateway_id and not isinstance(gateway_id, str):
            raise TypeError("Expected argument 'gateway_id' to be a str")
        pulumi.set(__self__, "gateway_id", gateway_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if oracle_bgp_asn and not isinstance(oracle_bgp_asn, int):
            raise TypeError("Expected argument 'oracle_bgp_asn' to be a int")
        pulumi.set(__self__, "oracle_bgp_asn", oracle_bgp_asn)
        if provider_service_id and not isinstance(provider_service_id, str):
            raise TypeError("Expected argument 'provider_service_id' to be a str")
        pulumi.set(__self__, "provider_service_id", provider_service_id)
        if provider_service_key_name and not isinstance(provider_service_key_name, str):
            raise TypeError("Expected argument 'provider_service_key_name' to be a str")
        pulumi.set(__self__, "provider_service_key_name", provider_service_key_name)
        if provider_state and not isinstance(provider_state, str):
            raise TypeError("Expected argument 'provider_state' to be a str")
        pulumi.set(__self__, "provider_state", provider_state)
        if public_prefixes and not isinstance(public_prefixes, list):
            raise TypeError("Expected argument 'public_prefixes' to be a list")
        pulumi.set(__self__, "public_prefixes", public_prefixes)
        if reference_comment and not isinstance(reference_comment, str):
            raise TypeError("Expected argument 'reference_comment' to be a str")
        pulumi.set(__self__, "reference_comment", reference_comment)
        if region and not isinstance(region, str):
            raise TypeError("Expected argument 'region' to be a str")
        pulumi.set(__self__, "region", region)
        if routing_policies and not isinstance(routing_policies, list):
            raise TypeError("Expected argument 'routing_policies' to be a list")
        pulumi.set(__self__, "routing_policies", routing_policies)
        if service_type and not isinstance(service_type, str):
            raise TypeError("Expected argument 'service_type' to be a str")
        pulumi.set(__self__, "service_type", service_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if virtual_circuit_id and not isinstance(virtual_circuit_id, str):
            raise TypeError("Expected argument 'virtual_circuit_id' to be a str")
        pulumi.set(__self__, "virtual_circuit_id", virtual_circuit_id)

    @property
    @pulumi.getter(name="bandwidthShapeName")
    def bandwidth_shape_name(self) -> str:
        """
        The provisioned data rate of the connection. To get a list of the available bandwidth levels (that is, shapes), see [ListFastConnectProviderServiceVirtualCircuitBandwidthShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/ListFastConnectProviderVirtualCircuitBandwidthShapes).  Example: `10 Gbps`
        """
        return pulumi.get(self, "bandwidth_shape_name")

    @property
    @pulumi.getter(name="bgpIpv6sessionState")
    def bgp_ipv6session_state(self) -> str:
        """
        The state of the Ipv6 BGP session associated with the virtual circuit.
        """
        return pulumi.get(self, "bgp_ipv6session_state")

    @property
    @pulumi.getter(name="bgpManagement")
    def bgp_management(self) -> str:
        """
        Deprecated. Instead use the information in [FastConnectProviderService](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/FastConnectProviderService/).
        """
        return pulumi.get(self, "bgp_management")

    @property
    @pulumi.getter(name="bgpSessionState")
    def bgp_session_state(self) -> str:
        """
        The state of the Ipv4 BGP session associated with the virtual circuit.
        """
        return pulumi.get(self, "bgp_session_state")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the virtual circuit.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="crossConnectMappings")
    def cross_connect_mappings(self) -> Sequence['outputs.GetVirtualCircuitCrossConnectMappingResult']:
        """
        An array of mappings, each containing properties for a cross-connect or cross-connect group that is associated with this virtual circuit.
        """
        return pulumi.get(self, "cross_connect_mappings")

    @property
    @pulumi.getter(name="customerAsn")
    def customer_asn(self) -> str:
        """
        The BGP ASN of the network at the other end of the BGP session from Oracle. If the session is between the customer's edge router and Oracle, the value is the customer's ASN. If the BGP session is between the provider's edge router and Oracle, the value is the provider's ASN. Can be a 2-byte or 4-byte ASN. Uses "asplain" format.
        """
        return pulumi.get(self, "customer_asn")

    @property
    @pulumi.getter(name="customerBgpAsn")
    def customer_bgp_asn(self) -> int:
        """
        Deprecated. Instead use `customerAsn`. If you specify values for both, the request will be rejected.
        """
        return pulumi.get(self, "customer_bgp_asn")

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
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

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
        """
        The OCID of the customer's [dynamic routing gateway (DRG)](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Drg) that this virtual circuit uses. Applicable only to private virtual circuits.
        """
        return pulumi.get(self, "gateway_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The virtual circuit's Oracle ID (OCID).
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="oracleBgpAsn")
    def oracle_bgp_asn(self) -> int:
        """
        The Oracle BGP ASN.
        """
        return pulumi.get(self, "oracle_bgp_asn")

    @property
    @pulumi.getter(name="providerServiceId")
    def provider_service_id(self) -> str:
        """
        The OCID of the service offered by the provider (if the customer is connecting via a provider).
        """
        return pulumi.get(self, "provider_service_id")

    @property
    @pulumi.getter(name="providerServiceKeyName")
    def provider_service_key_name(self) -> str:
        """
        The service key name offered by the provider (if the customer is connecting via a provider).
        """
        return pulumi.get(self, "provider_service_key_name")

    @property
    @pulumi.getter(name="providerState")
    def provider_state(self) -> str:
        """
        The provider's state in relation to this virtual circuit (if the customer is connecting via a provider). ACTIVE means the provider has provisioned the virtual circuit from their end. INACTIVE means the provider has not yet provisioned the virtual circuit, or has de-provisioned it.
        """
        return pulumi.get(self, "provider_state")

    @property
    @pulumi.getter(name="publicPrefixes")
    def public_prefixes(self) -> Sequence['outputs.GetVirtualCircuitPublicPrefixResult']:
        """
        For a public virtual circuit. The public IP prefixes (CIDRs) the customer wants to advertise across the connection. All prefix sizes are allowed.
        """
        return pulumi.get(self, "public_prefixes")

    @property
    @pulumi.getter(name="referenceComment")
    def reference_comment(self) -> str:
        """
        Provider-supplied reference information about this virtual circuit (if the customer is connecting via a provider).
        """
        return pulumi.get(self, "reference_comment")

    @property
    @pulumi.getter
    def region(self) -> str:
        """
        The Oracle Cloud Infrastructure region where this virtual circuit is located.
        """
        return pulumi.get(self, "region")

    @property
    @pulumi.getter(name="routingPolicies")
    def routing_policies(self) -> Sequence[str]:
        """
        The routing policy sets how routing information about the Oracle cloud is shared over a public virtual circuit. Policies available are: `ORACLE_SERVICE_NETWORK`, `REGIONAL`, `MARKET_LEVEL`, and `GLOBAL`. See [Route Filtering](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/routingonprem.htm#route_filtering) for details. By default, routing information is shared for all routes in the same market.
        """
        return pulumi.get(self, "routing_policies")

    @property
    @pulumi.getter(name="serviceType")
    def service_type(self) -> str:
        """
        Provider service type.
        """
        return pulumi.get(self, "service_type")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The virtual circuit's current state. For information about the different states, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the virtual circuit was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        Whether the virtual circuit supports private or public peering. For more information, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).
        """
        return pulumi.get(self, "type")

    @property
    @pulumi.getter(name="virtualCircuitId")
    def virtual_circuit_id(self) -> str:
        return pulumi.get(self, "virtual_circuit_id")


class AwaitableGetVirtualCircuitResult(GetVirtualCircuitResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVirtualCircuitResult(
            bandwidth_shape_name=self.bandwidth_shape_name,
            bgp_ipv6session_state=self.bgp_ipv6session_state,
            bgp_management=self.bgp_management,
            bgp_session_state=self.bgp_session_state,
            compartment_id=self.compartment_id,
            cross_connect_mappings=self.cross_connect_mappings,
            customer_asn=self.customer_asn,
            customer_bgp_asn=self.customer_bgp_asn,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            gateway_id=self.gateway_id,
            id=self.id,
            oracle_bgp_asn=self.oracle_bgp_asn,
            provider_service_id=self.provider_service_id,
            provider_service_key_name=self.provider_service_key_name,
            provider_state=self.provider_state,
            public_prefixes=self.public_prefixes,
            reference_comment=self.reference_comment,
            region=self.region,
            routing_policies=self.routing_policies,
            service_type=self.service_type,
            state=self.state,
            time_created=self.time_created,
            type=self.type,
            virtual_circuit_id=self.virtual_circuit_id)


def get_virtual_circuit(virtual_circuit_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVirtualCircuitResult:
    """
    This data source provides details about a specific Virtual Circuit resource in Oracle Cloud Infrastructure Core service.

    Gets the specified virtual circuit's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_virtual_circuit = oci.core.get_virtual_circuit(virtual_circuit_id=oci_core_virtual_circuit["test_virtual_circuit"]["id"])
    ```


    :param str virtual_circuit_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit.
    """
    __args__ = dict()
    __args__['virtualCircuitId'] = virtual_circuit_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getVirtualCircuit:getVirtualCircuit', __args__, opts=opts, typ=GetVirtualCircuitResult).value

    return AwaitableGetVirtualCircuitResult(
        bandwidth_shape_name=__ret__.bandwidth_shape_name,
        bgp_ipv6session_state=__ret__.bgp_ipv6session_state,
        bgp_management=__ret__.bgp_management,
        bgp_session_state=__ret__.bgp_session_state,
        compartment_id=__ret__.compartment_id,
        cross_connect_mappings=__ret__.cross_connect_mappings,
        customer_asn=__ret__.customer_asn,
        customer_bgp_asn=__ret__.customer_bgp_asn,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        gateway_id=__ret__.gateway_id,
        id=__ret__.id,
        oracle_bgp_asn=__ret__.oracle_bgp_asn,
        provider_service_id=__ret__.provider_service_id,
        provider_service_key_name=__ret__.provider_service_key_name,
        provider_state=__ret__.provider_state,
        public_prefixes=__ret__.public_prefixes,
        reference_comment=__ret__.reference_comment,
        region=__ret__.region,
        routing_policies=__ret__.routing_policies,
        service_type=__ret__.service_type,
        state=__ret__.state,
        time_created=__ret__.time_created,
        type=__ret__.type,
        virtual_circuit_id=__ret__.virtual_circuit_id)
