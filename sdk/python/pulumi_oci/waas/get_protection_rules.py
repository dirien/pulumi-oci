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
    'GetProtectionRulesResult',
    'AwaitableGetProtectionRulesResult',
    'get_protection_rules',
]

@pulumi.output_type
class GetProtectionRulesResult:
    """
    A collection of values returned by getProtectionRules.
    """
    def __init__(__self__, actions=None, filters=None, id=None, mod_security_rule_ids=None, protection_rules=None, waas_policy_id=None):
        if actions and not isinstance(actions, list):
            raise TypeError("Expected argument 'actions' to be a list")
        pulumi.set(__self__, "actions", actions)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if mod_security_rule_ids and not isinstance(mod_security_rule_ids, list):
            raise TypeError("Expected argument 'mod_security_rule_ids' to be a list")
        pulumi.set(__self__, "mod_security_rule_ids", mod_security_rule_ids)
        if protection_rules and not isinstance(protection_rules, list):
            raise TypeError("Expected argument 'protection_rules' to be a list")
        pulumi.set(__self__, "protection_rules", protection_rules)
        if waas_policy_id and not isinstance(waas_policy_id, str):
            raise TypeError("Expected argument 'waas_policy_id' to be a str")
        pulumi.set(__self__, "waas_policy_id", waas_policy_id)

    @property
    @pulumi.getter
    def actions(self) -> Optional[Sequence[str]]:
        """
        The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
        """
        return pulumi.get(self, "actions")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProtectionRulesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="modSecurityRuleIds")
    def mod_security_rule_ids(self) -> Optional[Sequence[str]]:
        return pulumi.get(self, "mod_security_rule_ids")

    @property
    @pulumi.getter(name="protectionRules")
    def protection_rules(self) -> Sequence['outputs.GetProtectionRulesProtectionRuleResult']:
        """
        The list of protection_rules.
        """
        return pulumi.get(self, "protection_rules")

    @property
    @pulumi.getter(name="waasPolicyId")
    def waas_policy_id(self) -> str:
        return pulumi.get(self, "waas_policy_id")


class AwaitableGetProtectionRulesResult(GetProtectionRulesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProtectionRulesResult(
            actions=self.actions,
            filters=self.filters,
            id=self.id,
            mod_security_rule_ids=self.mod_security_rule_ids,
            protection_rules=self.protection_rules,
            waas_policy_id=self.waas_policy_id)


def get_protection_rules(actions: Optional[Sequence[str]] = None,
                         filters: Optional[Sequence[pulumi.InputType['GetProtectionRulesFilterArgs']]] = None,
                         mod_security_rule_ids: Optional[Sequence[str]] = None,
                         waas_policy_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProtectionRulesResult:
    """
    This data source provides the list of Protection Rules in Oracle Cloud Infrastructure Web Application Acceleration and Security service.

    Gets the list of available protection rules for a WAAS policy. Use the `GetWafConfig` operation to view a list of currently configured protection rules for the Web Application Firewall, or use the `ListRecommendations` operation to get a list of recommended protection rules for the Web Application Firewall.
    The list is sorted by `key`, in ascending order.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_rules = oci.waas.get_protection_rules(waas_policy_id=oci_waas_waas_policy["test_waas_policy"]["id"],
        actions=var["protection_rule_action"],
        mod_security_rule_ids=oci_events_rule["test_rule"]["id"])
    ```


    :param Sequence[str] actions: Filter rules using a list of actions.
    :param Sequence[str] mod_security_rule_ids: Filter rules using a list of ModSecurity rule IDs.
    :param str waas_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
    """
    __args__ = dict()
    __args__['actions'] = actions
    __args__['filters'] = filters
    __args__['modSecurityRuleIds'] = mod_security_rule_ids
    __args__['waasPolicyId'] = waas_policy_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:waas/getProtectionRules:getProtectionRules', __args__, opts=opts, typ=GetProtectionRulesResult).value

    return AwaitableGetProtectionRulesResult(
        actions=__ret__.actions,
        filters=__ret__.filters,
        id=__ret__.id,
        mod_security_rule_ids=__ret__.mod_security_rule_ids,
        protection_rules=__ret__.protection_rules,
        waas_policy_id=__ret__.waas_policy_id)
