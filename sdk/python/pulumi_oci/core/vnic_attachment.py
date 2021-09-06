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

__all__ = ['VnicAttachmentArgs', 'VnicAttachment']

@pulumi.input_type
class VnicAttachmentArgs:
    def __init__(__self__, *,
                 create_vnic_details: pulumi.Input['VnicAttachmentCreateVnicDetailsArgs'],
                 instance_id: pulumi.Input[str],
                 display_name: Optional[pulumi.Input[str]] = None,
                 nic_index: Optional[pulumi.Input[int]] = None):
        """
        The set of arguments for constructing a VnicAttachment resource.
        :param pulumi.Input['VnicAttachmentCreateVnicDetailsArgs'] create_vnic_details: (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] instance_id: The OCID of the instance.
        :param pulumi.Input[str] display_name: A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        :param pulumi.Input[int] nic_index: Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        pulumi.set(__self__, "create_vnic_details", create_vnic_details)
        pulumi.set(__self__, "instance_id", instance_id)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if nic_index is not None:
            pulumi.set(__self__, "nic_index", nic_index)

    @property
    @pulumi.getter(name="createVnicDetails")
    def create_vnic_details(self) -> pulumi.Input['VnicAttachmentCreateVnicDetailsArgs']:
        """
        (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "create_vnic_details")

    @create_vnic_details.setter
    def create_vnic_details(self, value: pulumi.Input['VnicAttachmentCreateVnicDetailsArgs']):
        pulumi.set(self, "create_vnic_details", value)

    @property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> pulumi.Input[str]:
        """
        The OCID of the instance.
        """
        return pulumi.get(self, "instance_id")

    @instance_id.setter
    def instance_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "instance_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="nicIndex")
    def nic_index(self) -> Optional[pulumi.Input[int]]:
        """
        Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "nic_index")

    @nic_index.setter
    def nic_index(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "nic_index", value)


@pulumi.input_type
class _VnicAttachmentState:
    def __init__(__self__, *,
                 availability_domain: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 create_vnic_details: Optional[pulumi.Input['VnicAttachmentCreateVnicDetailsArgs']] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 instance_id: Optional[pulumi.Input[str]] = None,
                 nic_index: Optional[pulumi.Input[int]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 subnet_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 vlan_id: Optional[pulumi.Input[str]] = None,
                 vlan_tag: Optional[pulumi.Input[int]] = None,
                 vnic_id: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering VnicAttachment resources.
        :param pulumi.Input[str] availability_domain: The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        :param pulumi.Input[str] compartment_id: The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
        :param pulumi.Input['VnicAttachmentCreateVnicDetailsArgs'] create_vnic_details: (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] display_name: A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        :param pulumi.Input[str] instance_id: The OCID of the instance.
        :param pulumi.Input[int] nic_index: Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] state: The current state of the VNIC attachment.
        :param pulumi.Input[str] subnet_id: The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
        :param pulumi.Input[str] time_created: The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] vlan_id: Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        :param pulumi.Input[int] vlan_tag: The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
        :param pulumi.Input[str] vnic_id: The OCID of the VNIC. Available after the attachment process is complete.
        """
        if availability_domain is not None:
            pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if create_vnic_details is not None:
            pulumi.set(__self__, "create_vnic_details", create_vnic_details)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if instance_id is not None:
            pulumi.set(__self__, "instance_id", instance_id)
        if nic_index is not None:
            pulumi.set(__self__, "nic_index", nic_index)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if subnet_id is not None:
            pulumi.set(__self__, "subnet_id", subnet_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if vlan_id is not None:
            pulumi.set(__self__, "vlan_id", vlan_id)
        if vlan_tag is not None:
            pulumi.set(__self__, "vlan_tag", vlan_tag)
        if vnic_id is not None:
            pulumi.set(__self__, "vnic_id", vnic_id)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[pulumi.Input[str]]:
        """
        The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @availability_domain.setter
    def availability_domain(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "availability_domain", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="createVnicDetails")
    def create_vnic_details(self) -> Optional[pulumi.Input['VnicAttachmentCreateVnicDetailsArgs']]:
        """
        (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "create_vnic_details")

    @create_vnic_details.setter
    def create_vnic_details(self, value: Optional[pulumi.Input['VnicAttachmentCreateVnicDetailsArgs']]):
        pulumi.set(self, "create_vnic_details", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the instance.
        """
        return pulumi.get(self, "instance_id")

    @instance_id.setter
    def instance_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "instance_id", value)

    @property
    @pulumi.getter(name="nicIndex")
    def nic_index(self) -> Optional[pulumi.Input[int]]:
        """
        Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "nic_index")

    @nic_index.setter
    def nic_index(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "nic_index", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the VNIC attachment.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
        """
        return pulumi.get(self, "subnet_id")

    @subnet_id.setter
    def subnet_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "subnet_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="vlanId")
    def vlan_id(self) -> Optional[pulumi.Input[str]]:
        """
        Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        """
        return pulumi.get(self, "vlan_id")

    @vlan_id.setter
    def vlan_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "vlan_id", value)

    @property
    @pulumi.getter(name="vlanTag")
    def vlan_tag(self) -> Optional[pulumi.Input[int]]:
        """
        The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
        """
        return pulumi.get(self, "vlan_tag")

    @vlan_tag.setter
    def vlan_tag(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "vlan_tag", value)

    @property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the VNIC. Available after the attachment process is complete.
        """
        return pulumi.get(self, "vnic_id")

    @vnic_id.setter
    def vnic_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "vnic_id", value)


class VnicAttachment(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 create_vnic_details: Optional[pulumi.Input[pulumi.InputType['VnicAttachmentCreateVnicDetailsArgs']]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 instance_id: Optional[pulumi.Input[str]] = None,
                 nic_index: Optional[pulumi.Input[int]] = None,
                 __props__=None):
        """
        This resource provides the Vnic Attachment resource in Oracle Cloud Infrastructure Core service.

        Creates a secondary VNIC and attaches it to the specified instance.
        For more information about secondary VNICs, see
        [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_vnic_attachment = oci.core.VnicAttachment("testVnicAttachment",
            create_vnic_details=oci.core.VnicAttachmentCreateVnicDetailsArgs(
                assign_private_dns_record=var["vnic_attachment_create_vnic_details_assign_private_dns_record"],
                assign_public_ip=var["vnic_attachment_create_vnic_details_assign_public_ip"],
                defined_tags=var["vnic_attachment_create_vnic_details_defined_tags"],
                display_name=var["vnic_attachment_create_vnic_details_display_name"],
                freeform_tags=var["vnic_attachment_create_vnic_details_freeform_tags"],
                hostname_label=var["vnic_attachment_create_vnic_details_hostname_label"],
                nsg_ids=var["vnic_attachment_create_vnic_details_nsg_ids"],
                private_ip=var["vnic_attachment_create_vnic_details_private_ip"],
                skip_source_dest_check=var["vnic_attachment_create_vnic_details_skip_source_dest_check"],
                subnet_id=oci_core_subnet["test_subnet"]["id"],
                vlan_id=oci_core_vlan["test_vlan"]["id"],
            ),
            instance_id=oci_core_instance["test_instance"]["id"],
            display_name=var["vnic_attachment_display_name"],
            nic_index=var["vnic_attachment_nic_index"])
        ```

        ## Import

        VnicAttachments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/vnicAttachment:VnicAttachment test_vnic_attachment "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[pulumi.InputType['VnicAttachmentCreateVnicDetailsArgs']] create_vnic_details: (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] display_name: A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        :param pulumi.Input[str] instance_id: The OCID of the instance.
        :param pulumi.Input[int] nic_index: Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: VnicAttachmentArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Vnic Attachment resource in Oracle Cloud Infrastructure Core service.

        Creates a secondary VNIC and attaches it to the specified instance.
        For more information about secondary VNICs, see
        [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_vnic_attachment = oci.core.VnicAttachment("testVnicAttachment",
            create_vnic_details=oci.core.VnicAttachmentCreateVnicDetailsArgs(
                assign_private_dns_record=var["vnic_attachment_create_vnic_details_assign_private_dns_record"],
                assign_public_ip=var["vnic_attachment_create_vnic_details_assign_public_ip"],
                defined_tags=var["vnic_attachment_create_vnic_details_defined_tags"],
                display_name=var["vnic_attachment_create_vnic_details_display_name"],
                freeform_tags=var["vnic_attachment_create_vnic_details_freeform_tags"],
                hostname_label=var["vnic_attachment_create_vnic_details_hostname_label"],
                nsg_ids=var["vnic_attachment_create_vnic_details_nsg_ids"],
                private_ip=var["vnic_attachment_create_vnic_details_private_ip"],
                skip_source_dest_check=var["vnic_attachment_create_vnic_details_skip_source_dest_check"],
                subnet_id=oci_core_subnet["test_subnet"]["id"],
                vlan_id=oci_core_vlan["test_vlan"]["id"],
            ),
            instance_id=oci_core_instance["test_instance"]["id"],
            display_name=var["vnic_attachment_display_name"],
            nic_index=var["vnic_attachment_nic_index"])
        ```

        ## Import

        VnicAttachments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/vnicAttachment:VnicAttachment test_vnic_attachment "id"
        ```

        :param str resource_name: The name of the resource.
        :param VnicAttachmentArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(VnicAttachmentArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 create_vnic_details: Optional[pulumi.Input[pulumi.InputType['VnicAttachmentCreateVnicDetailsArgs']]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 instance_id: Optional[pulumi.Input[str]] = None,
                 nic_index: Optional[pulumi.Input[int]] = None,
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
            __props__ = VnicAttachmentArgs.__new__(VnicAttachmentArgs)

            if create_vnic_details is None and not opts.urn:
                raise TypeError("Missing required property 'create_vnic_details'")
            __props__.__dict__["create_vnic_details"] = create_vnic_details
            __props__.__dict__["display_name"] = display_name
            if instance_id is None and not opts.urn:
                raise TypeError("Missing required property 'instance_id'")
            __props__.__dict__["instance_id"] = instance_id
            __props__.__dict__["nic_index"] = nic_index
            __props__.__dict__["availability_domain"] = None
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["subnet_id"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["vlan_id"] = None
            __props__.__dict__["vlan_tag"] = None
            __props__.__dict__["vnic_id"] = None
        super(VnicAttachment, __self__).__init__(
            'oci:core/vnicAttachment:VnicAttachment',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            availability_domain: Optional[pulumi.Input[str]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            create_vnic_details: Optional[pulumi.Input[pulumi.InputType['VnicAttachmentCreateVnicDetailsArgs']]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            instance_id: Optional[pulumi.Input[str]] = None,
            nic_index: Optional[pulumi.Input[int]] = None,
            state: Optional[pulumi.Input[str]] = None,
            subnet_id: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            vlan_id: Optional[pulumi.Input[str]] = None,
            vlan_tag: Optional[pulumi.Input[int]] = None,
            vnic_id: Optional[pulumi.Input[str]] = None) -> 'VnicAttachment':
        """
        Get an existing VnicAttachment resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] availability_domain: The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        :param pulumi.Input[str] compartment_id: The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
        :param pulumi.Input[pulumi.InputType['VnicAttachmentCreateVnicDetailsArgs']] create_vnic_details: (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] display_name: A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        :param pulumi.Input[str] instance_id: The OCID of the instance.
        :param pulumi.Input[int] nic_index: Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        :param pulumi.Input[str] state: The current state of the VNIC attachment.
        :param pulumi.Input[str] subnet_id: The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
        :param pulumi.Input[str] time_created: The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] vlan_id: Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        :param pulumi.Input[int] vlan_tag: The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
        :param pulumi.Input[str] vnic_id: The OCID of the VNIC. Available after the attachment process is complete.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _VnicAttachmentState.__new__(_VnicAttachmentState)

        __props__.__dict__["availability_domain"] = availability_domain
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["create_vnic_details"] = create_vnic_details
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["instance_id"] = instance_id
        __props__.__dict__["nic_index"] = nic_index
        __props__.__dict__["state"] = state
        __props__.__dict__["subnet_id"] = subnet_id
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["vlan_id"] = vlan_id
        __props__.__dict__["vlan_tag"] = vlan_tag
        __props__.__dict__["vnic_id"] = vnic_id
        return VnicAttachment(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> pulumi.Output[str]:
        """
        The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createVnicDetails")
    def create_vnic_details(self) -> pulumi.Output['outputs.VnicAttachmentCreateVnicDetails']:
        """
        (Updatable) Contains properties for a VNIC. You use this object when creating the primary VNIC during instance launch or when creating a secondary VNIC. For more information about VNICs, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "create_vnic_details")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> pulumi.Output[str]:
        """
        The OCID of the instance.
        """
        return pulumi.get(self, "instance_id")

    @property
    @pulumi.getter(name="nicIndex")
    def nic_index(self) -> pulumi.Output[int]:
        """
        Which physical network interface card (NIC) the VNIC will use. Defaults to 0. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        """
        return pulumi.get(self, "nic_index")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the VNIC attachment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> pulumi.Output[str]:
        """
        The OCID of the subnet to create the VNIC in. When launching an instance, use this `subnetId` instead of the deprecated `subnetId` in [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/LaunchInstanceDetails). At least one of them is required; if you provide both, the values must match.
        """
        return pulumi.get(self, "subnet_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="vlanId")
    def vlan_id(self) -> pulumi.Output[str]:
        """
        Provide this attribute only if you are an Oracle Cloud VMware Solution customer and creating a secondary VNIC in a VLAN. The value is the OCID of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        """
        return pulumi.get(self, "vlan_id")

    @property
    @pulumi.getter(name="vlanTag")
    def vlan_tag(self) -> pulumi.Output[int]:
        """
        The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
        """
        return pulumi.get(self, "vlan_tag")

    @property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> pulumi.Output[str]:
        """
        The OCID of the VNIC. Available after the attachment process is complete.
        """
        return pulumi.get(self, "vnic_id")

