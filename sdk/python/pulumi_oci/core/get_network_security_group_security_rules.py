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
    'GetNetworkSecurityGroupSecurityRulesResult',
    'AwaitableGetNetworkSecurityGroupSecurityRulesResult',
    'get_network_security_group_security_rules',
]

@pulumi.output_type
class GetNetworkSecurityGroupSecurityRulesResult:
    """
    A collection of values returned by getNetworkSecurityGroupSecurityRules.
    """
    def __init__(__self__, direction=None, filters=None, id=None, network_security_group_id=None, security_rules=None):
        if direction and not isinstance(direction, str):
            raise TypeError("Expected argument 'direction' to be a str")
        pulumi.set(__self__, "direction", direction)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if network_security_group_id and not isinstance(network_security_group_id, str):
            raise TypeError("Expected argument 'network_security_group_id' to be a str")
        pulumi.set(__self__, "network_security_group_id", network_security_group_id)
        if security_rules and not isinstance(security_rules, list):
            raise TypeError("Expected argument 'security_rules' to be a list")
        pulumi.set(__self__, "security_rules", security_rules)

    @property
    @pulumi.getter
    def direction(self) -> Optional[str]:
        """
        Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
        """
        return pulumi.get(self, "direction")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNetworkSecurityGroupSecurityRulesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="networkSecurityGroupId")
    def network_security_group_id(self) -> str:
        return pulumi.get(self, "network_security_group_id")

    @property
    @pulumi.getter(name="securityRules")
    def security_rules(self) -> Sequence['outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleResult']:
        """
        The list of security_rules.
        """
        return pulumi.get(self, "security_rules")


class AwaitableGetNetworkSecurityGroupSecurityRulesResult(GetNetworkSecurityGroupSecurityRulesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkSecurityGroupSecurityRulesResult(
            direction=self.direction,
            filters=self.filters,
            id=self.id,
            network_security_group_id=self.network_security_group_id,
            security_rules=self.security_rules)


def get_network_security_group_security_rules(direction: Optional[str] = None,
                                              filters: Optional[Sequence[pulumi.InputType['GetNetworkSecurityGroupSecurityRulesFilterArgs']]] = None,
                                              network_security_group_id: Optional[str] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkSecurityGroupSecurityRulesResult:
    """
    This data source provides the list of Network Security Group Security Rules in Oracle Cloud Infrastructure Core service.

    Lists the security rules in the specified network security group.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_security_group_security_rules = oci.core.get_network_security_group_security_rules(network_security_group_id=oci_core_network_security_group["test_network_security_group"]["id"],
        direction=var["network_security_group_security_rule_direction"])
    ```


    :param str direction: Direction of the security rule. Set to `EGRESS` for rules that allow outbound IP packets, or `INGRESS` for rules that allow inbound IP packets.
    :param str network_security_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
    """
    __args__ = dict()
    __args__['direction'] = direction
    __args__['filters'] = filters
    __args__['networkSecurityGroupId'] = network_security_group_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:core/getNetworkSecurityGroupSecurityRules:getNetworkSecurityGroupSecurityRules', __args__, opts=opts, typ=GetNetworkSecurityGroupSecurityRulesResult).value

    return AwaitableGetNetworkSecurityGroupSecurityRulesResult(
        direction=__ret__.direction,
        filters=__ret__.filters,
        id=__ret__.id,
        network_security_group_id=__ret__.network_security_group_id,
        security_rules=__ret__.security_rules)
