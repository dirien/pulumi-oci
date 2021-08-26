# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['DynamicGroupArgs', 'DynamicGroup']

@pulumi.input_type
class DynamicGroupArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 description: pulumi.Input[str],
                 matching_rule: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a DynamicGroup resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy containing the group.
        :param pulumi.Input[str] description: (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[str] matching_rule: (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] name: The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "description", description)
        pulumi.set(__self__, "matching_rule", matching_rule)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The OCID of the tenancy containing the group.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def description(self) -> pulumi.Input[str]:
        """
        (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: pulumi.Input[str]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="matchingRule")
    def matching_rule(self) -> pulumi.Input[str]:
        """
        (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        """
        return pulumi.get(self, "matching_rule")

    @matching_rule.setter
    def matching_rule(self, value: pulumi.Input[str]):
        pulumi.set(self, "matching_rule", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _DynamicGroupState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 inactive_state: Optional[pulumi.Input[str]] = None,
                 matching_rule: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering DynamicGroup resources.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy containing the group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] inactive_state: The detailed status of INACTIVE lifecycleState.
        :param pulumi.Input[str] matching_rule: (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        :param pulumi.Input[str] name: The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[str] state: The group's current state.
        :param pulumi.Input[str] time_created: Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if inactive_state is not None:
            pulumi.set(__self__, "inactive_state", inactive_state)
        if matching_rule is not None:
            pulumi.set(__self__, "matching_rule", matching_rule)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the tenancy containing the group.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="inactiveState")
    def inactive_state(self) -> Optional[pulumi.Input[str]]:
        """
        The detailed status of INACTIVE lifecycleState.
        """
        return pulumi.get(self, "inactive_state")

    @inactive_state.setter
    def inactive_state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "inactive_state", value)

    @property
    @pulumi.getter(name="matchingRule")
    def matching_rule(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        """
        return pulumi.get(self, "matching_rule")

    @matching_rule.setter
    def matching_rule(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "matching_rule", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The group's current state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)


class DynamicGroup(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 matching_rule: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Dynamic Group resource in Oracle Cloud Infrastructure Identity service.

        Creates a new dynamic group in your tenancy.

        You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
        is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
        reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
        reside within compartments inside the tenancy. For information about OCIDs, see
        [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You must also specify a *name* for the dynamic group, which must be unique across all dynamic groups in your
        tenancy, and cannot be changed. Note that this name has to be also unique across all groups in your tenancy.
        You can use this name or the OCID when writing policies that apply to the dynamic group. For more information
        about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).

        You must also specify a *description* for the dynamic group (although it can be an empty string). It does not
        have to be unique, and you can change it anytime with [UpdateDynamicGroup](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/DynamicGroup/UpdateDynamicGroup).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_dynamic_group = oci.identity.DynamicGroup("testDynamicGroup",
            compartment_id=var["tenancy_ocid"],
            description=var["dynamic_group_description"],
            matching_rule=var["dynamic_group_matching_rule"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        DynamicGroups can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:identity/dynamicGroup:DynamicGroup test_dynamic_group "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy containing the group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] matching_rule: (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        :param pulumi.Input[str] name: The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: DynamicGroupArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Dynamic Group resource in Oracle Cloud Infrastructure Identity service.

        Creates a new dynamic group in your tenancy.

        You must specify your tenancy's OCID as the compartment ID in the request object (remember that the tenancy
        is simply the root compartment). Notice that IAM resources (users, groups, compartments, and some policies)
        reside within the tenancy itself, unlike cloud resources such as compute instances, which typically
        reside within compartments inside the tenancy. For information about OCIDs, see
        [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You must also specify a *name* for the dynamic group, which must be unique across all dynamic groups in your
        tenancy, and cannot be changed. Note that this name has to be also unique across all groups in your tenancy.
        You can use this name or the OCID when writing policies that apply to the dynamic group. For more information
        about policies, see [How Policies Work](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policies.htm).

        You must also specify a *description* for the dynamic group (although it can be an empty string). It does not
        have to be unique, and you can change it anytime with [UpdateDynamicGroup](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/DynamicGroup/UpdateDynamicGroup).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_dynamic_group = oci.identity.DynamicGroup("testDynamicGroup",
            compartment_id=var["tenancy_ocid"],
            description=var["dynamic_group_description"],
            matching_rule=var["dynamic_group_matching_rule"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        DynamicGroups can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:identity/dynamicGroup:DynamicGroup test_dynamic_group "id"
        ```

        :param str resource_name: The name of the resource.
        :param DynamicGroupArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(DynamicGroupArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 matching_rule: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
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
            __props__ = DynamicGroupArgs.__new__(DynamicGroupArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if description is None and not opts.urn:
                raise TypeError("Missing required property 'description'")
            __props__.__dict__["description"] = description
            __props__.__dict__["freeform_tags"] = freeform_tags
            if matching_rule is None and not opts.urn:
                raise TypeError("Missing required property 'matching_rule'")
            __props__.__dict__["matching_rule"] = matching_rule
            __props__.__dict__["name"] = name
            __props__.__dict__["inactive_state"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(DynamicGroup, __self__).__init__(
            'oci:identity/dynamicGroup:DynamicGroup',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            description: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            inactive_state: Optional[pulumi.Input[str]] = None,
            matching_rule: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None) -> 'DynamicGroup':
        """
        Get an existing DynamicGroup resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The OCID of the tenancy containing the group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] description: (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] inactive_state: The detailed status of INACTIVE lifecycleState.
        :param pulumi.Input[str] matching_rule: (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        :param pulumi.Input[str] name: The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        :param pulumi.Input[str] state: The group's current state.
        :param pulumi.Input[str] time_created: Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _DynamicGroupState.__new__(_DynamicGroupState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["description"] = description
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["inactive_state"] = inactive_state
        __props__.__dict__["matching_rule"] = matching_rule
        __props__.__dict__["name"] = name
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        return DynamicGroup(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the tenancy containing the group.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[str]:
        """
        (Updatable) The description you assign to the group during creation. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="inactiveState")
    def inactive_state(self) -> pulumi.Output[str]:
        """
        The detailed status of INACTIVE lifecycleState.
        """
        return pulumi.get(self, "inactive_state")

    @property
    @pulumi.getter(name="matchingRule")
    def matching_rule(self) -> pulumi.Output[str]:
        """
        (Updatable) The matching rule to dynamically match an instance certificate to this dynamic group. For rule syntax, see [Managing Dynamic Groups](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingdynamicgroups.htm).
        """
        return pulumi.get(self, "matching_rule")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        The name you assign to the group during creation. The name must be unique across all groups in the tenancy and cannot be changed.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The group's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

