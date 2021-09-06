# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['RemotePeeringConnectionArgs', 'RemotePeeringConnection']

@pulumi.input_type
class RemotePeeringConnectionArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 drg_id: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 peer_id: Optional[pulumi.Input[str]] = None,
                 peer_region_name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a RemotePeeringConnection resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment to contain the RPC.
        :param pulumi.Input[str] drg_id: The OCID of the DRG the RPC belongs to.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] peer_id: The OCID of the RPC you want to peer with.
        :param pulumi.Input[str] peer_region_name: The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "drg_id", drg_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if peer_id is not None:
            pulumi.set(__self__, "peer_id", peer_id)
        if peer_region_name is not None:
            pulumi.set(__self__, "peer_region_name", peer_region_name)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The OCID of the compartment to contain the RPC.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="drgId")
    def drg_id(self) -> pulumi.Input[str]:
        """
        The OCID of the DRG the RPC belongs to.
        """
        return pulumi.get(self, "drg_id")

    @drg_id.setter
    def drg_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "drg_id", value)

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
    @pulumi.getter(name="peerId")
    def peer_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the RPC you want to peer with.
        """
        return pulumi.get(self, "peer_id")

    @peer_id.setter
    def peer_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_id", value)

    @property
    @pulumi.getter(name="peerRegionName")
    def peer_region_name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        """
        return pulumi.get(self, "peer_region_name")

    @peer_region_name.setter
    def peer_region_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_region_name", value)


@pulumi.input_type
class _RemotePeeringConnectionState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 drg_id: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_cross_tenancy_peering: Optional[pulumi.Input[bool]] = None,
                 peer_id: Optional[pulumi.Input[str]] = None,
                 peer_region_name: Optional[pulumi.Input[str]] = None,
                 peer_tenancy_id: Optional[pulumi.Input[str]] = None,
                 peering_status: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering RemotePeeringConnection resources.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment to contain the RPC.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[str] drg_id: The OCID of the DRG the RPC belongs to.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[bool] is_cross_tenancy_peering: Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        :param pulumi.Input[str] peer_id: The OCID of the RPC you want to peer with.
        :param pulumi.Input[str] peer_region_name: The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        :param pulumi.Input[str] peer_tenancy_id: If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        :param pulumi.Input[str] peering_status: Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        :param pulumi.Input[str] state: The RPC's current lifecycle state.
        :param pulumi.Input[str] time_created: The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if drg_id is not None:
            pulumi.set(__self__, "drg_id", drg_id)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if is_cross_tenancy_peering is not None:
            pulumi.set(__self__, "is_cross_tenancy_peering", is_cross_tenancy_peering)
        if peer_id is not None:
            pulumi.set(__self__, "peer_id", peer_id)
        if peer_region_name is not None:
            pulumi.set(__self__, "peer_region_name", peer_region_name)
        if peer_tenancy_id is not None:
            pulumi.set(__self__, "peer_tenancy_id", peer_tenancy_id)
        if peering_status is not None:
            pulumi.set(__self__, "peering_status", peering_status)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the compartment to contain the RPC.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
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
    @pulumi.getter(name="drgId")
    def drg_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the DRG the RPC belongs to.
        """
        return pulumi.get(self, "drg_id")

    @drg_id.setter
    def drg_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "drg_id", value)

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
    @pulumi.getter(name="isCrossTenancyPeering")
    def is_cross_tenancy_peering(self) -> Optional[pulumi.Input[bool]]:
        """
        Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        """
        return pulumi.get(self, "is_cross_tenancy_peering")

    @is_cross_tenancy_peering.setter
    def is_cross_tenancy_peering(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_cross_tenancy_peering", value)

    @property
    @pulumi.getter(name="peerId")
    def peer_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the RPC you want to peer with.
        """
        return pulumi.get(self, "peer_id")

    @peer_id.setter
    def peer_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_id", value)

    @property
    @pulumi.getter(name="peerRegionName")
    def peer_region_name(self) -> Optional[pulumi.Input[str]]:
        """
        The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        """
        return pulumi.get(self, "peer_region_name")

    @peer_region_name.setter
    def peer_region_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_region_name", value)

    @property
    @pulumi.getter(name="peerTenancyId")
    def peer_tenancy_id(self) -> Optional[pulumi.Input[str]]:
        """
        If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        """
        return pulumi.get(self, "peer_tenancy_id")

    @peer_tenancy_id.setter
    def peer_tenancy_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_tenancy_id", value)

    @property
    @pulumi.getter(name="peeringStatus")
    def peering_status(self) -> Optional[pulumi.Input[str]]:
        """
        Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        """
        return pulumi.get(self, "peering_status")

    @peering_status.setter
    def peering_status(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peering_status", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The RPC's current lifecycle state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)


class RemotePeeringConnection(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 drg_id: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 peer_id: Optional[pulumi.Input[str]] = None,
                 peer_region_name: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Remote Peering Connection resource in Oracle Cloud Infrastructure Core service.

        Creates a new remote peering connection (RPC) for the specified DRG.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_remote_peering_connection = oci.core.RemotePeeringConnection("testRemotePeeringConnection",
            compartment_id=var["compartment_id"],
            drg_id=oci_core_drg["test_drg"]["id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["remote_peering_connection_display_name"],
            freeform_tags={
                "Department": "Finance",
            },
            peer_id=oci_core_remote_peering_connection["test_remote_peering_connection2"]["id"],
            peer_region_name=var["remote_peering_connection_peer_region_name"])
        ```

        ## Import

        RemotePeeringConnections can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/remotePeeringConnection:RemotePeeringConnection test_remote_peering_connection "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment to contain the RPC.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[str] drg_id: The OCID of the DRG the RPC belongs to.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] peer_id: The OCID of the RPC you want to peer with.
        :param pulumi.Input[str] peer_region_name: The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: RemotePeeringConnectionArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Remote Peering Connection resource in Oracle Cloud Infrastructure Core service.

        Creates a new remote peering connection (RPC) for the specified DRG.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_remote_peering_connection = oci.core.RemotePeeringConnection("testRemotePeeringConnection",
            compartment_id=var["compartment_id"],
            drg_id=oci_core_drg["test_drg"]["id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["remote_peering_connection_display_name"],
            freeform_tags={
                "Department": "Finance",
            },
            peer_id=oci_core_remote_peering_connection["test_remote_peering_connection2"]["id"],
            peer_region_name=var["remote_peering_connection_peer_region_name"])
        ```

        ## Import

        RemotePeeringConnections can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/remotePeeringConnection:RemotePeeringConnection test_remote_peering_connection "id"
        ```

        :param str resource_name: The name of the resource.
        :param RemotePeeringConnectionArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(RemotePeeringConnectionArgs, pulumi.ResourceOptions, *args, **kwargs)
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
                 drg_id: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 peer_id: Optional[pulumi.Input[str]] = None,
                 peer_region_name: Optional[pulumi.Input[str]] = None,
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
            __props__ = RemotePeeringConnectionArgs.__new__(RemotePeeringConnectionArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            if drg_id is None and not opts.urn:
                raise TypeError("Missing required property 'drg_id'")
            __props__.__dict__["drg_id"] = drg_id
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["peer_id"] = peer_id
            __props__.__dict__["peer_region_name"] = peer_region_name
            __props__.__dict__["is_cross_tenancy_peering"] = None
            __props__.__dict__["peer_tenancy_id"] = None
            __props__.__dict__["peering_status"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(RemotePeeringConnection, __self__).__init__(
            'oci:core/remotePeeringConnection:RemotePeeringConnection',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            drg_id: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            is_cross_tenancy_peering: Optional[pulumi.Input[bool]] = None,
            peer_id: Optional[pulumi.Input[str]] = None,
            peer_region_name: Optional[pulumi.Input[str]] = None,
            peer_tenancy_id: Optional[pulumi.Input[str]] = None,
            peering_status: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None) -> 'RemotePeeringConnection':
        """
        Get an existing RemotePeeringConnection resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The OCID of the compartment to contain the RPC.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[str] drg_id: The OCID of the DRG the RPC belongs to.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[bool] is_cross_tenancy_peering: Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        :param pulumi.Input[str] peer_id: The OCID of the RPC you want to peer with.
        :param pulumi.Input[str] peer_region_name: The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        :param pulumi.Input[str] peer_tenancy_id: If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        :param pulumi.Input[str] peering_status: Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        :param pulumi.Input[str] state: The RPC's current lifecycle state.
        :param pulumi.Input[str] time_created: The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _RemotePeeringConnectionState.__new__(_RemotePeeringConnectionState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["drg_id"] = drg_id
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["is_cross_tenancy_peering"] = is_cross_tenancy_peering
        __props__.__dict__["peer_id"] = peer_id
        __props__.__dict__["peer_region_name"] = peer_region_name
        __props__.__dict__["peer_tenancy_id"] = peer_tenancy_id
        __props__.__dict__["peering_status"] = peering_status
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        return RemotePeeringConnection(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the compartment to contain the RPC.
        """
        return pulumi.get(self, "compartment_id")

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
    @pulumi.getter(name="drgId")
    def drg_id(self) -> pulumi.Output[str]:
        """
        The OCID of the DRG the RPC belongs to.
        """
        return pulumi.get(self, "drg_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="isCrossTenancyPeering")
    def is_cross_tenancy_peering(self) -> pulumi.Output[bool]:
        """
        Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
        """
        return pulumi.get(self, "is_cross_tenancy_peering")

    @property
    @pulumi.getter(name="peerId")
    def peer_id(self) -> pulumi.Output[str]:
        """
        The OCID of the RPC you want to peer with.
        """
        return pulumi.get(self, "peer_id")

    @property
    @pulumi.getter(name="peerRegionName")
    def peer_region_name(self) -> pulumi.Output[str]:
        """
        The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
        """
        return pulumi.get(self, "peer_region_name")

    @property
    @pulumi.getter(name="peerTenancyId")
    def peer_tenancy_id(self) -> pulumi.Output[str]:
        """
        If this RPC is peered, this value is the OCID of the other RPC's tenancy.
        """
        return pulumi.get(self, "peer_tenancy_id")

    @property
    @pulumi.getter(name="peeringStatus")
    def peering_status(self) -> pulumi.Output[str]:
        """
        Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
        """
        return pulumi.get(self, "peering_status")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The RPC's current lifecycle state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

