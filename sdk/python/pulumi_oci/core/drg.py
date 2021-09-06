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

__all__ = ['DrgArgs', 'Drg']

@pulumi.input_type
class DrgArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a Drg resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

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
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _DrgState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 default_drg_route_tables: Optional[pulumi.Input['DrgDefaultDrgRouteTablesArgs']] = None,
                 default_export_drg_route_distribution_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 redundancy_status: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering Drg resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        :param pulumi.Input['DrgDefaultDrgRouteTablesArgs'] default_drg_route_tables: The default DRG route table for this DRG. Each network type has a default DRG route table.
        :param pulumi.Input[str] default_export_drg_route_distribution_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG's default export route distribution for the DRG attachments.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] redundancy_status: The redundancy status of the DRG specified.
        :param pulumi.Input[str] state: The DRG's current state.
        :param pulumi.Input[str] time_created: The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if default_drg_route_tables is not None:
            pulumi.set(__self__, "default_drg_route_tables", default_drg_route_tables)
        if default_export_drg_route_distribution_id is not None:
            pulumi.set(__self__, "default_export_drg_route_distribution_id", default_export_drg_route_distribution_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if redundancy_status is not None:
            pulumi.set(__self__, "redundancy_status", redundancy_status)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="defaultDrgRouteTables")
    def default_drg_route_tables(self) -> Optional[pulumi.Input['DrgDefaultDrgRouteTablesArgs']]:
        """
        The default DRG route table for this DRG. Each network type has a default DRG route table.
        """
        return pulumi.get(self, "default_drg_route_tables")

    @default_drg_route_tables.setter
    def default_drg_route_tables(self, value: Optional[pulumi.Input['DrgDefaultDrgRouteTablesArgs']]):
        pulumi.set(self, "default_drg_route_tables", value)

    @property
    @pulumi.getter(name="defaultExportDrgRouteDistributionId")
    def default_export_drg_route_distribution_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG's default export route distribution for the DRG attachments.
        """
        return pulumi.get(self, "default_export_drg_route_distribution_id")

    @default_export_drg_route_distribution_id.setter
    def default_export_drg_route_distribution_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "default_export_drg_route_distribution_id", value)

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
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="redundancyStatus")
    def redundancy_status(self) -> Optional[pulumi.Input[str]]:
        """
        The redundancy status of the DRG specified.
        """
        return pulumi.get(self, "redundancy_status")

    @redundancy_status.setter
    def redundancy_status(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "redundancy_status", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The DRG's current state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)


class Drg(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 __props__=None):
        """
        This resource provides the Drg resource in Oracle Cloud Infrastructure Core service.

        Creates a new dynamic routing gateway (DRG) in the specified compartment. For more information,
        see [Dynamic Routing Gateways (DRGs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingDRGs.htm).

        For the purposes of access control, you must provide the OCID of the compartment where you want
        the DRG to reside. Notice that the DRG doesn't have to be in the same compartment as the VCN,
        the DRG attachment, or other Networking Service components. If you're not sure which compartment
        to use, put the DRG in the same compartment as the VCN. For more information about compartments
        and access control, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
        For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You may optionally specify a *display name* for the DRG, otherwise a default is provided.
        It does not have to be unique, and you can change it. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_drg = oci.core.Drg("testDrg",
            compartment_id=var["compartment_id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["drg_display_name"],
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        Drgs can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/drg:Drg test_drg "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: DrgArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Drg resource in Oracle Cloud Infrastructure Core service.

        Creates a new dynamic routing gateway (DRG) in the specified compartment. For more information,
        see [Dynamic Routing Gateways (DRGs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingDRGs.htm).

        For the purposes of access control, you must provide the OCID of the compartment where you want
        the DRG to reside. Notice that the DRG doesn't have to be in the same compartment as the VCN,
        the DRG attachment, or other Networking Service components. If you're not sure which compartment
        to use, put the DRG in the same compartment as the VCN. For more information about compartments
        and access control, see [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
        For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You may optionally specify a *display name* for the DRG, otherwise a default is provided.
        It does not have to be unique, and you can change it. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_drg = oci.core.Drg("testDrg",
            compartment_id=var["compartment_id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["drg_display_name"],
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        Drgs can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/drg:Drg test_drg "id"
        ```

        :param str resource_name: The name of the resource.
        :param DrgArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(DrgArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
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
            __props__ = DrgArgs.__new__(DrgArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["default_drg_route_tables"] = None
            __props__.__dict__["default_export_drg_route_distribution_id"] = None
            __props__.__dict__["redundancy_status"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(Drg, __self__).__init__(
            'oci:core/drg:Drg',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            default_drg_route_tables: Optional[pulumi.Input[pulumi.InputType['DrgDefaultDrgRouteTablesArgs']]] = None,
            default_export_drg_route_distribution_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            redundancy_status: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None) -> 'Drg':
        """
        Get an existing Drg resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        :param pulumi.Input[pulumi.InputType['DrgDefaultDrgRouteTablesArgs']] default_drg_route_tables: The default DRG route table for this DRG. Each network type has a default DRG route table.
        :param pulumi.Input[str] default_export_drg_route_distribution_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG's default export route distribution for the DRG attachments.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] redundancy_status: The redundancy status of the DRG specified.
        :param pulumi.Input[str] state: The DRG's current state.
        :param pulumi.Input[str] time_created: The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _DrgState.__new__(_DrgState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["default_drg_route_tables"] = default_drg_route_tables
        __props__.__dict__["default_export_drg_route_distribution_id"] = default_export_drg_route_distribution_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["redundancy_status"] = redundancy_status
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        return Drg(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the DRG.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="defaultDrgRouteTables")
    def default_drg_route_tables(self) -> pulumi.Output['outputs.DrgDefaultDrgRouteTables']:
        """
        The default DRG route table for this DRG. Each network type has a default DRG route table.
        """
        return pulumi.get(self, "default_drg_route_tables")

    @property
    @pulumi.getter(name="defaultExportDrgRouteDistributionId")
    def default_export_drg_route_distribution_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this DRG's default export route distribution for the DRG attachments.
        """
        return pulumi.get(self, "default_export_drg_route_distribution_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="redundancyStatus")
    def redundancy_status(self) -> pulumi.Output[str]:
        """
        The redundancy status of the DRG specified.
        """
        return pulumi.get(self, "redundancy_status")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The DRG's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the DRG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

