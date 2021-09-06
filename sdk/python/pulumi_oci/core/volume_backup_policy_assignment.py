# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['VolumeBackupPolicyAssignmentArgs', 'VolumeBackupPolicyAssignment']

@pulumi.input_type
class VolumeBackupPolicyAssignmentArgs:
    def __init__(__self__, *,
                 asset_id: pulumi.Input[str],
                 policy_id: pulumi.Input[str]):
        """
        The set of arguments for constructing a VolumeBackupPolicyAssignment resource.
        :param pulumi.Input[str] asset_id: The OCID of the volume to assign the policy to.
        :param pulumi.Input[str] policy_id: The OCID of the volume backup policy to assign to the volume.
        """
        pulumi.set(__self__, "asset_id", asset_id)
        pulumi.set(__self__, "policy_id", policy_id)

    @property
    @pulumi.getter(name="assetId")
    def asset_id(self) -> pulumi.Input[str]:
        """
        The OCID of the volume to assign the policy to.
        """
        return pulumi.get(self, "asset_id")

    @asset_id.setter
    def asset_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "asset_id", value)

    @property
    @pulumi.getter(name="policyId")
    def policy_id(self) -> pulumi.Input[str]:
        """
        The OCID of the volume backup policy to assign to the volume.
        """
        return pulumi.get(self, "policy_id")

    @policy_id.setter
    def policy_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "policy_id", value)


@pulumi.input_type
class _VolumeBackupPolicyAssignmentState:
    def __init__(__self__, *,
                 asset_id: Optional[pulumi.Input[str]] = None,
                 policy_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering VolumeBackupPolicyAssignment resources.
        :param pulumi.Input[str] asset_id: The OCID of the volume to assign the policy to.
        :param pulumi.Input[str] policy_id: The OCID of the volume backup policy to assign to the volume.
        :param pulumi.Input[str] time_created: The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        if asset_id is not None:
            pulumi.set(__self__, "asset_id", asset_id)
        if policy_id is not None:
            pulumi.set(__self__, "policy_id", policy_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="assetId")
    def asset_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the volume to assign the policy to.
        """
        return pulumi.get(self, "asset_id")

    @asset_id.setter
    def asset_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "asset_id", value)

    @property
    @pulumi.getter(name="policyId")
    def policy_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the volume backup policy to assign to the volume.
        """
        return pulumi.get(self, "policy_id")

    @policy_id.setter
    def policy_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "policy_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)


class VolumeBackupPolicyAssignment(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 asset_id: Optional[pulumi.Input[str]] = None,
                 policy_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.

        Assigns a volume backup policy to the specified volume. Note that a given volume can
        only have one backup policy assigned to it. If this operation is used for a volume that already
        has a different backup policy assigned, the prior backup policy will be silently unassigned.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_volume_backup_policy_assignment = oci.core.VolumeBackupPolicyAssignment("testVolumeBackupPolicyAssignment",
            asset_id=oci_core_volume["test_volume"]["id"],
            policy_id=oci_core_volume_backup_policy["test_volume_backup_policy"]["id"])
        ```

        ## Import

        VolumeBackupPolicyAssignments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] asset_id: The OCID of the volume to assign the policy to.
        :param pulumi.Input[str] policy_id: The OCID of the volume backup policy to assign to the volume.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: VolumeBackupPolicyAssignmentArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Volume Backup Policy Assignment resource in Oracle Cloud Infrastructure Core service.

        Assigns a volume backup policy to the specified volume. Note that a given volume can
        only have one backup policy assigned to it. If this operation is used for a volume that already
        has a different backup policy assigned, the prior backup policy will be silently unassigned.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_volume_backup_policy_assignment = oci.core.VolumeBackupPolicyAssignment("testVolumeBackupPolicyAssignment",
            asset_id=oci_core_volume["test_volume"]["id"],
            policy_id=oci_core_volume_backup_policy["test_volume_backup_policy"]["id"])
        ```

        ## Import

        VolumeBackupPolicyAssignments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment test_volume_backup_policy_assignment "id"
        ```

        :param str resource_name: The name of the resource.
        :param VolumeBackupPolicyAssignmentArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(VolumeBackupPolicyAssignmentArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 asset_id: Optional[pulumi.Input[str]] = None,
                 policy_id: Optional[pulumi.Input[str]] = None,
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
            __props__ = VolumeBackupPolicyAssignmentArgs.__new__(VolumeBackupPolicyAssignmentArgs)

            if asset_id is None and not opts.urn:
                raise TypeError("Missing required property 'asset_id'")
            __props__.__dict__["asset_id"] = asset_id
            if policy_id is None and not opts.urn:
                raise TypeError("Missing required property 'policy_id'")
            __props__.__dict__["policy_id"] = policy_id
            __props__.__dict__["time_created"] = None
        super(VolumeBackupPolicyAssignment, __self__).__init__(
            'oci:core/volumeBackupPolicyAssignment:VolumeBackupPolicyAssignment',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            asset_id: Optional[pulumi.Input[str]] = None,
            policy_id: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None) -> 'VolumeBackupPolicyAssignment':
        """
        Get an existing VolumeBackupPolicyAssignment resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] asset_id: The OCID of the volume to assign the policy to.
        :param pulumi.Input[str] policy_id: The OCID of the volume backup policy to assign to the volume.
        :param pulumi.Input[str] time_created: The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _VolumeBackupPolicyAssignmentState.__new__(_VolumeBackupPolicyAssignmentState)

        __props__.__dict__["asset_id"] = asset_id
        __props__.__dict__["policy_id"] = policy_id
        __props__.__dict__["time_created"] = time_created
        return VolumeBackupPolicyAssignment(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="assetId")
    def asset_id(self) -> pulumi.Output[str]:
        """
        The OCID of the volume to assign the policy to.
        """
        return pulumi.get(self, "asset_id")

    @property
    @pulumi.getter(name="policyId")
    def policy_id(self) -> pulumi.Output[str]:
        """
        The OCID of the volume backup policy to assign to the volume.
        """
        return pulumi.get(self, "policy_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the volume backup policy was assigned to the volume. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

