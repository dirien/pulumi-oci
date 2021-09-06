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

__all__ = ['RuleArgs', 'Rule']

@pulumi.input_type
class RuleArgs:
    def __init__(__self__, *,
                 actions: pulumi.Input['RuleActionsArgs'],
                 compartment_id: pulumi.Input[str],
                 condition: pulumi.Input[str],
                 display_name: pulumi.Input[str],
                 is_enabled: pulumi.Input[bool],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a Rule resource.
        :param pulumi.Input['RuleActionsArgs'] actions: (Updatable) A list of one or more ActionDetails objects.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        :param pulumi.Input[str] condition: (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
               * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        :param pulumi.Input[str] display_name: (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[bool] is_enabled: (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        pulumi.set(__self__, "actions", actions)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "condition", condition)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "is_enabled", is_enabled)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @property
    @pulumi.getter
    def actions(self) -> pulumi.Input['RuleActionsArgs']:
        """
        (Updatable) A list of one or more ActionDetails objects.
        """
        return pulumi.get(self, "actions")

    @actions.setter
    def actions(self, value: pulumi.Input['RuleActionsArgs']):
        pulumi.set(self, "actions", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def condition(self) -> pulumi.Input[str]:
        """
        (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
        * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: pulumi.Input[str]):
        pulumi.set(self, "condition", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> pulumi.Input[bool]:
        """
        (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @is_enabled.setter
    def is_enabled(self, value: pulumi.Input[bool]):
        pulumi.set(self, "is_enabled", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _RuleState:
    def __init__(__self__, *,
                 actions: Optional[pulumi.Input['RuleActionsArgs']] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_enabled: Optional[pulumi.Input[bool]] = None,
                 lifecycle_message: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering Rule resources.
        :param pulumi.Input['RuleActionsArgs'] actions: (Updatable) A list of one or more ActionDetails objects.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        :param pulumi.Input[str] condition: (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
               * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[str] display_name: (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[bool] is_enabled: (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        :param pulumi.Input[str] lifecycle_message: A message generated by the Events service about the current state of this rule.
        :param pulumi.Input[str] state: The current state of the rule.
        :param pulumi.Input[str] time_created: The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        if actions is not None:
            pulumi.set(__self__, "actions", actions)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if condition is not None:
            pulumi.set(__self__, "condition", condition)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if is_enabled is not None:
            pulumi.set(__self__, "is_enabled", is_enabled)
        if lifecycle_message is not None:
            pulumi.set(__self__, "lifecycle_message", lifecycle_message)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter
    def actions(self) -> Optional[pulumi.Input['RuleActionsArgs']]:
        """
        (Updatable) A list of one or more ActionDetails objects.
        """
        return pulumi.get(self, "actions")

    @actions.setter
    def actions(self, value: Optional[pulumi.Input['RuleActionsArgs']]):
        pulumi.set(self, "actions", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def condition(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
        * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "condition", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @is_enabled.setter
    def is_enabled(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_enabled", value)

    @property
    @pulumi.getter(name="lifecycleMessage")
    def lifecycle_message(self) -> Optional[pulumi.Input[str]]:
        """
        A message generated by the Events service about the current state of this rule.
        """
        return pulumi.get(self, "lifecycle_message")

    @lifecycle_message.setter
    def lifecycle_message(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_message", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the rule.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)


class Rule(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 actions: Optional[pulumi.Input[pulumi.InputType['RuleActionsArgs']]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_enabled: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        """
        This resource provides the Rule resource in Oracle Cloud Infrastructure Events service.

        Creates a new rule.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_rule = oci.events.Rule("testRule",
            actions=oci.events.RuleActionsArgs(
                actions=[oci.events.RuleActionsActionArgs(
                    action_type=var["rule_actions_actions_action_type"],
                    is_enabled=var["rule_actions_actions_is_enabled"],
                    description=var["rule_actions_actions_description"],
                    function_id=oci_functions_function["test_function"]["id"],
                    stream_id=oci_streaming_stream["test_stream"]["id"],
                    topic_id=oci_ons_notification_topic["test_topic"]["id"],
                )],
            ),
            compartment_id=var["compartment_id"],
            condition=var["rule_condition"],
            display_name=var["rule_display_name"],
            is_enabled=var["rule_is_enabled"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            description=var["rule_description"],
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        Rules can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:events/rule:Rule test_rule "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[pulumi.InputType['RuleActionsArgs']] actions: (Updatable) A list of one or more ActionDetails objects.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        :param pulumi.Input[str] condition: (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
               * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[str] display_name: (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[bool] is_enabled: (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: RuleArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Rule resource in Oracle Cloud Infrastructure Events service.

        Creates a new rule.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_rule = oci.events.Rule("testRule",
            actions=oci.events.RuleActionsArgs(
                actions=[oci.events.RuleActionsActionArgs(
                    action_type=var["rule_actions_actions_action_type"],
                    is_enabled=var["rule_actions_actions_is_enabled"],
                    description=var["rule_actions_actions_description"],
                    function_id=oci_functions_function["test_function"]["id"],
                    stream_id=oci_streaming_stream["test_stream"]["id"],
                    topic_id=oci_ons_notification_topic["test_topic"]["id"],
                )],
            ),
            compartment_id=var["compartment_id"],
            condition=var["rule_condition"],
            display_name=var["rule_display_name"],
            is_enabled=var["rule_is_enabled"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            description=var["rule_description"],
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        Rules can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:events/rule:Rule test_rule "id"
        ```

        :param str resource_name: The name of the resource.
        :param RuleArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(RuleArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 actions: Optional[pulumi.Input[pulumi.InputType['RuleActionsArgs']]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_enabled: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = RuleArgs.__new__(RuleArgs)

            if actions is None and not opts.urn:
                raise TypeError("Missing required property 'actions'")
            __props__.__dict__["actions"] = actions
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if condition is None and not opts.urn:
                raise TypeError("Missing required property 'condition'")
            __props__.__dict__["condition"] = condition
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["description"] = description
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if is_enabled is None and not opts.urn:
                raise TypeError("Missing required property 'is_enabled'")
            __props__.__dict__["is_enabled"] = is_enabled
            __props__.__dict__["lifecycle_message"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(Rule, __self__).__init__(
            'oci:events/rule:Rule',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            actions: Optional[pulumi.Input[pulumi.InputType['RuleActionsArgs']]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            condition: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            description: Optional[pulumi.Input[str]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            is_enabled: Optional[pulumi.Input[bool]] = None,
            lifecycle_message: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None) -> 'Rule':
        """
        Get an existing Rule resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[pulumi.InputType['RuleActionsArgs']] actions: (Updatable) A list of one or more ActionDetails objects.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        :param pulumi.Input[str] condition: (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
               * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[str] display_name: (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[bool] is_enabled: (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        :param pulumi.Input[str] lifecycle_message: A message generated by the Events service about the current state of this rule.
        :param pulumi.Input[str] state: The current state of the rule.
        :param pulumi.Input[str] time_created: The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _RuleState.__new__(_RuleState)

        __props__.__dict__["actions"] = actions
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["condition"] = condition
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["is_enabled"] = is_enabled
        __props__.__dict__["lifecycle_message"] = lifecycle_message
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        return Rule(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def actions(self) -> pulumi.Output['outputs.RuleActions']:
        """
        (Updatable) A list of one or more ActionDetails objects.
        """
        return pulumi.get(self, "actions")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def condition(self) -> pulumi.Output[str]:
        """
        (Updatable) A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
        * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        """
        return pulumi.get(self, "condition")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[str]:
        """
        (Updatable) A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> pulumi.Output[bool]:
        """
        (Updatable) Whether or not this rule is currently enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @property
    @pulumi.getter(name="lifecycleMessage")
    def lifecycle_message(self) -> pulumi.Output[str]:
        """
        A message generated by the Events service about the current state of this rule.
        """
        return pulumi.get(self, "lifecycle_message")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the rule.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")

