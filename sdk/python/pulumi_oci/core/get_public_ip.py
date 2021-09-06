# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetPublicIpResult',
    'AwaitableGetPublicIpResult',
    'get_public_ip',
]

@pulumi.output_type
class GetPublicIpResult:
    """
    A collection of values returned by getPublicIp.
    """
    def __init__(__self__, assigned_entity_id=None, assigned_entity_type=None, availability_domain=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, ip_address=None, lifetime=None, private_ip_id=None, public_ip_pool_id=None, scope=None, state=None, time_created=None):
        if assigned_entity_id and not isinstance(assigned_entity_id, str):
            raise TypeError("Expected argument 'assigned_entity_id' to be a str")
        pulumi.set(__self__, "assigned_entity_id", assigned_entity_id)
        if assigned_entity_type and not isinstance(assigned_entity_type, str):
            raise TypeError("Expected argument 'assigned_entity_type' to be a str")
        pulumi.set(__self__, "assigned_entity_type", assigned_entity_type)
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ip_address and not isinstance(ip_address, str):
            raise TypeError("Expected argument 'ip_address' to be a str")
        pulumi.set(__self__, "ip_address", ip_address)
        if lifetime and not isinstance(lifetime, str):
            raise TypeError("Expected argument 'lifetime' to be a str")
        pulumi.set(__self__, "lifetime", lifetime)
        if private_ip_id and not isinstance(private_ip_id, str):
            raise TypeError("Expected argument 'private_ip_id' to be a str")
        pulumi.set(__self__, "private_ip_id", private_ip_id)
        if public_ip_pool_id and not isinstance(public_ip_pool_id, str):
            raise TypeError("Expected argument 'public_ip_pool_id' to be a str")
        pulumi.set(__self__, "public_ip_pool_id", public_ip_pool_id)
        if scope and not isinstance(scope, str):
            raise TypeError("Expected argument 'scope' to be a str")
        pulumi.set(__self__, "scope", scope)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="assignedEntityId")
    def assigned_entity_id(self) -> str:
        """
        The OCID of the entity the public IP is assigned to, or in the process of being assigned to.
        """
        return pulumi.get(self, "assigned_entity_id")

    @property
    @pulumi.getter(name="assignedEntityType")
    def assigned_entity_type(self) -> str:
        """
        The type of entity the public IP is assigned to, or in the process of being assigned to.
        """
        return pulumi.get(self, "assigned_entity_type")

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> str:
        """
        The public IP's availability domain. This property is set only for ephemeral public IPs that are assigned to a private IP (that is, when the `scope` of the public IP is set to AVAILABILITY_DOMAIN). The value is the availability domain of the assigned private IP.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the public IP. For an ephemeral public IP, this is the compartment of its assigned entity (which can be a private IP or a regional entity such as a NAT gateway). For a reserved public IP that is currently assigned, its compartment can be different from the assigned private IP's.
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
    @pulumi.getter
    def id(self) -> str:
        """
        The public IP's Oracle ID (OCID).
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="ipAddress")
    def ip_address(self) -> str:
        """
        The public IP address of the `publicIp` object.  Example: `203.0.113.2`
        """
        return pulumi.get(self, "ip_address")

    @property
    @pulumi.getter
    def lifetime(self) -> str:
        """
        Defines when the public IP is deleted and released back to Oracle's public IP pool.
        * `EPHEMERAL`: The lifetime is tied to the lifetime of its assigned entity. An ephemeral public IP must always be assigned to an entity. If the assigned entity is a private IP, the ephemeral public IP is automatically deleted when the private IP is deleted, when the VNIC is terminated, or when the instance is terminated. If the assigned entity is a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/), the ephemeral public IP is automatically deleted when the NAT gateway is terminated.
        * `RESERVED`: You control the public IP's lifetime. You can delete a reserved public IP whenever you like. It does not need to be assigned to a private IP at all times.
        """
        return pulumi.get(self, "lifetime")

    @property
    @pulumi.getter(name="privateIpId")
    def private_ip_id(self) -> str:
        """
        Deprecated. Use `assignedEntityId` instead.
        """
        return pulumi.get(self, "private_ip_id")

    @property
    @pulumi.getter(name="publicIpPoolId")
    def public_ip_pool_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pool object created in the current tenancy.
        """
        return pulumi.get(self, "public_ip_pool_id")

    @property
    @pulumi.getter
    def scope(self) -> str:
        """
        Whether the public IP is regional or specific to a particular availability domain.
        * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs and ephemeral public IPs assigned to a regional entity have `scope` = `REGION`.
        * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it's assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
        """
        return pulumi.get(self, "scope")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The public IP's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the public IP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetPublicIpResult(GetPublicIpResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPublicIpResult(
            assigned_entity_id=self.assigned_entity_id,
            assigned_entity_type=self.assigned_entity_type,
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            ip_address=self.ip_address,
            lifetime=self.lifetime,
            private_ip_id=self.private_ip_id,
            public_ip_pool_id=self.public_ip_pool_id,
            scope=self.scope,
            state=self.state,
            time_created=self.time_created)


def get_public_ip(id: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  private_ip_id: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPublicIpResult:
    """
    This data source provides details about a specific Public Ip resource in Oracle Cloud Infrastructure Core service.

    Gets the specified public IP. You must specify the object's OCID.

    Alternatively, you can get the object by using [GetPublicIpByIpAddress](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PublicIp/GetPublicIpByIpAddress)
    with the public IP address (for example, 203.0.113.2).

    Or you can use [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PublicIp/GetPublicIpByPrivateIpId)
    with the OCID of the private IP that the public IP is assigned to.

    **Note:** If you're fetching a reserved public IP that is in the process of being
    moved to a different private IP, the service returns the public IP object with
    `lifecycleState` = ASSIGNING and `assignedEntityId` = OCID of the target private IP.

    ## Example Usage
    ### Get a public ip by public ip id
    ```python
    import pulumi
    import pulumi_oci as oci

    test_oci_core_public_ip_by_id = oci.core.get_public_ip(id=var["test_public_ip_id"])
    ```
    ### Get a public ip by private ip id
    ```python
    import pulumi
    import pulumi_oci as oci

    test_oci_core_public_ip_by_private_ip_id = oci.core.get_public_ip(private_ip_id=var["test_public_ip_private_ip_id"])
    ```
    ### Get a public ip by public ip address
    ```python
    import pulumi
    import pulumi_oci as oci

    test_oci_core_public_ip_by_ip = oci.core.get_public_ip(ip_address=var["test_public_ip_ip_address"])
    ```


    :param str id: The OCID of the public IP.
    :param str ip_address: Gets the public IP based on the public IP address (for example, 129.146.2.1).
    :param str private_ip_id: Gets the public IP assigned to the specified private IP. You must specify the OCID of the private IP. If no public IP is assigned, a 404 is returned.
    """
    __args__ = dict()
    __args__['id'] = id
    __args__['ipAddress'] = ip_address
    __args__['privateIpId'] = private_ip_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getPublicIp:getPublicIp', __args__, opts=opts, typ=GetPublicIpResult).value

    return AwaitableGetPublicIpResult(
        assigned_entity_id=__ret__.assigned_entity_id,
        assigned_entity_type=__ret__.assigned_entity_type,
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        ip_address=__ret__.ip_address,
        lifetime=__ret__.lifetime,
        private_ip_id=__ret__.private_ip_id,
        public_ip_pool_id=__ret__.public_ip_pool_id,
        scope=__ret__.scope,
        state=__ret__.state,
        time_created=__ret__.time_created)
