# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetAlertRuleResult',
    'AwaitableGetAlertRuleResult',
    'get_alert_rule',
]

@pulumi.output_type
class GetAlertRuleResult:
    """
    A collection of values returned by getAlertRule.
    """
    def __init__(__self__, alert_rule_id=None, budget_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, message=None, recipients=None, state=None, threshold=None, threshold_type=None, time_created=None, time_updated=None, type=None, version=None):
        if alert_rule_id and not isinstance(alert_rule_id, str):
            raise TypeError("Expected argument 'alert_rule_id' to be a str")
        pulumi.set(__self__, "alert_rule_id", alert_rule_id)
        if budget_id and not isinstance(budget_id, str):
            raise TypeError("Expected argument 'budget_id' to be a str")
        pulumi.set(__self__, "budget_id", budget_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if message and not isinstance(message, str):
            raise TypeError("Expected argument 'message' to be a str")
        pulumi.set(__self__, "message", message)
        if recipients and not isinstance(recipients, str):
            raise TypeError("Expected argument 'recipients' to be a str")
        pulumi.set(__self__, "recipients", recipients)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if threshold and not isinstance(threshold, float):
            raise TypeError("Expected argument 'threshold' to be a float")
        pulumi.set(__self__, "threshold", threshold)
        if threshold_type and not isinstance(threshold_type, str):
            raise TypeError("Expected argument 'threshold_type' to be a str")
        pulumi.set(__self__, "threshold_type", threshold_type)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if version and not isinstance(version, int):
            raise TypeError("Expected argument 'version' to be a int")
        pulumi.set(__self__, "version", version)

    @property
    @pulumi.getter(name="alertRuleId")
    def alert_rule_id(self) -> str:
        return pulumi.get(self, "alert_rule_id")

    @property
    @pulumi.getter(name="budgetId")
    def budget_id(self) -> str:
        """
        The OCID of the budget
        """
        return pulumi.get(self, "budget_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        The description of the alert rule.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The name of the alert rule.
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
        The OCID of the alert rule
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def message(self) -> str:
        """
        Custom message that will be sent when alert is triggered
        """
        return pulumi.get(self, "message")

    @property
    @pulumi.getter
    def recipients(self) -> str:
        """
        Delimited list of email addresses to receive the alert when it triggers. Delimiter character can be comma, space, TAB, or semicolon.
        """
        return pulumi.get(self, "recipients")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the alert rule.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter
    def threshold(self) -> float:
        """
        The threshold for triggering the alert. If thresholdType is PERCENTAGE, the maximum value is 10000.
        """
        return pulumi.get(self, "threshold")

    @property
    @pulumi.getter(name="thresholdType")
    def threshold_type(self) -> str:
        """
        The type of threshold.
        """
        return pulumi.get(self, "threshold_type")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        Time when budget was created
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        Time when budget was updated
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        The type of alert. Valid values are ACTUAL (the alert will trigger based on actual usage) or FORECAST (the alert will trigger based on predicted usage).
        """
        return pulumi.get(self, "type")

    @property
    @pulumi.getter
    def version(self) -> int:
        """
        Version of the alert rule. Starts from 1 and increments by 1.
        """
        return pulumi.get(self, "version")


class AwaitableGetAlertRuleResult(GetAlertRuleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAlertRuleResult(
            alert_rule_id=self.alert_rule_id,
            budget_id=self.budget_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            message=self.message,
            recipients=self.recipients,
            state=self.state,
            threshold=self.threshold,
            threshold_type=self.threshold_type,
            time_created=self.time_created,
            time_updated=self.time_updated,
            type=self.type,
            version=self.version)


def get_alert_rule(alert_rule_id: Optional[str] = None,
                   budget_id: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAlertRuleResult:
    """
    This data source provides details about a specific Alert Rule resource in Oracle Cloud Infrastructure Budget service.

    Gets an Alert Rule for a specified Budget.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alert_rule = oci.budget.get_alert_rule(alert_rule_id=oci_budget_alert_rule["test_alert_rule"]["id"],
        budget_id=oci_budget_budget["test_budget"]["id"])
    ```


    :param str alert_rule_id: The unique Alert Rule OCID
    :param str budget_id: The unique Budget OCID
    """
    __args__ = dict()
    __args__['alertRuleId'] = alert_rule_id
    __args__['budgetId'] = budget_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:budget/getAlertRule:getAlertRule', __args__, opts=opts, typ=GetAlertRuleResult).value

    return AwaitableGetAlertRuleResult(
        alert_rule_id=__ret__.alert_rule_id,
        budget_id=__ret__.budget_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        message=__ret__.message,
        recipients=__ret__.recipients,
        state=__ret__.state,
        threshold=__ret__.threshold,
        threshold_type=__ret__.threshold_type,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        type=__ret__.type,
        version=__ret__.version)