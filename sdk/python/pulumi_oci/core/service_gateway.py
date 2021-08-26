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

__all__ = ['ServiceGatewayArgs', 'ServiceGateway']

@pulumi.input_type
class ServiceGatewayArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 services: pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]],
                 vcn_id: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 route_table_id: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a ServiceGateway resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
        :param pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]] services: (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        :param pulumi.Input[str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] route_table_id: (Updatable) The OCID of the route table the service gateway will use.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "services", services)
        pulumi.set(__self__, "vcn_id", vcn_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if route_table_id is not None:
            pulumi.set(__self__, "route_table_id", route_table_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def services(self) -> pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]]:
        """
        (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        """
        return pulumi.get(self, "services")

    @services.setter
    def services(self, value: pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]]):
        pulumi.set(self, "services", value)

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> pulumi.Input[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        return pulumi.get(self, "vcn_id")

    @vcn_id.setter
    def vcn_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "vcn_id", value)

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
    @pulumi.getter(name="routeTableId")
    def route_table_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the route table the service gateway will use.
        """
        return pulumi.get(self, "route_table_id")

    @route_table_id.setter
    def route_table_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "route_table_id", value)


@pulumi.input_type
class _ServiceGatewayState:
    def __init__(__self__, *,
                 block_traffic: Optional[pulumi.Input[bool]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 route_table_id: Optional[pulumi.Input[str]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 vcn_id: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering ServiceGateway resources.
        :param pulumi.Input[bool] block_traffic: Whether the service gateway blocks all traffic through it. The default is `false`. When this is `true`, traffic is not routed to any services, regardless of route rules.  Example: `true`
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] route_table_id: (Updatable) The OCID of the route table the service gateway will use.
        :param pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]] services: (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        :param pulumi.Input[str] state: The service gateway's current state.
        :param pulumi.Input[str] time_created: The date and time the service gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        if block_traffic is not None:
            pulumi.set(__self__, "block_traffic", block_traffic)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if route_table_id is not None:
            pulumi.set(__self__, "route_table_id", route_table_id)
        if services is not None:
            pulumi.set(__self__, "services", services)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if vcn_id is not None:
            pulumi.set(__self__, "vcn_id", vcn_id)

    @property
    @pulumi.getter(name="blockTraffic")
    def block_traffic(self) -> Optional[pulumi.Input[bool]]:
        """
        Whether the service gateway blocks all traffic through it. The default is `false`. When this is `true`, traffic is not routed to any services, regardless of route rules.  Example: `true`
        """
        return pulumi.get(self, "block_traffic")

    @block_traffic.setter
    def block_traffic(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "block_traffic", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
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
    @pulumi.getter(name="routeTableId")
    def route_table_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the route table the service gateway will use.
        """
        return pulumi.get(self, "route_table_id")

    @route_table_id.setter
    def route_table_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "route_table_id", value)

    @property
    @pulumi.getter
    def services(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]]]:
        """
        (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        """
        return pulumi.get(self, "services")

    @services.setter
    def services(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['ServiceGatewayServiceArgs']]]]):
        pulumi.set(self, "services", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The service gateway's current state.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the service gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        return pulumi.get(self, "vcn_id")

    @vcn_id.setter
    def vcn_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "vcn_id", value)


class ServiceGateway(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 route_table_id: Optional[pulumi.Input[str]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ServiceGatewayServiceArgs']]]]] = None,
                 vcn_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Service Gateway resource in Oracle Cloud Infrastructure Core service.

        Creates a new service gateway in the specified compartment.

        For the purposes of access control, you must provide the OCID of the compartment where you want
        the service gateway to reside. For more information about compartments and access control, see
        [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
        For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You may optionally specify a *display name* for the service gateway, otherwise a default is provided.
        It does not have to be unique, and you can change it. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_service_gateway = oci.core.ServiceGateway("testServiceGateway",
            compartment_id=var["compartment_id"],
            services=[oci.core.ServiceGatewayServiceArgs(
                service_id=data["oci_core_services"]["test_services"]["services"][0]["id"],
            )],
            vcn_id=oci_core_vcn["test_vcn"]["id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["service_gateway_display_name"],
            freeform_tags={
                "Department": "Finance",
            },
            route_table_id=oci_core_route_table["test_route_table"]["id"])
        ```

        ## Import

        ServiceGateways can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/serviceGateway:ServiceGateway test_service_gateway "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] route_table_id: (Updatable) The OCID of the route table the service gateway will use.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ServiceGatewayServiceArgs']]]] services: (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        :param pulumi.Input[str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ServiceGatewayArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Service Gateway resource in Oracle Cloud Infrastructure Core service.

        Creates a new service gateway in the specified compartment.

        For the purposes of access control, you must provide the OCID of the compartment where you want
        the service gateway to reside. For more information about compartments and access control, see
        [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
        For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

        You may optionally specify a *display name* for the service gateway, otherwise a default is provided.
        It does not have to be unique, and you can change it. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_service_gateway = oci.core.ServiceGateway("testServiceGateway",
            compartment_id=var["compartment_id"],
            services=[oci.core.ServiceGatewayServiceArgs(
                service_id=data["oci_core_services"]["test_services"]["services"][0]["id"],
            )],
            vcn_id=oci_core_vcn["test_vcn"]["id"],
            defined_tags={
                "Operations.CostCenter": "42",
            },
            display_name=var["service_gateway_display_name"],
            freeform_tags={
                "Department": "Finance",
            },
            route_table_id=oci_core_route_table["test_route_table"]["id"])
        ```

        ## Import

        ServiceGateways can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:core/serviceGateway:ServiceGateway test_service_gateway "id"
        ```

        :param str resource_name: The name of the resource.
        :param ServiceGatewayArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ServiceGatewayArgs, pulumi.ResourceOptions, *args, **kwargs)
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
                 route_table_id: Optional[pulumi.Input[str]] = None,
                 services: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ServiceGatewayServiceArgs']]]]] = None,
                 vcn_id: Optional[pulumi.Input[str]] = None,
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
            __props__ = ServiceGatewayArgs.__new__(ServiceGatewayArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["route_table_id"] = route_table_id
            if services is None and not opts.urn:
                raise TypeError("Missing required property 'services'")
            __props__.__dict__["services"] = services
            if vcn_id is None and not opts.urn:
                raise TypeError("Missing required property 'vcn_id'")
            __props__.__dict__["vcn_id"] = vcn_id
            __props__.__dict__["block_traffic"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
        super(ServiceGateway, __self__).__init__(
            'oci:core/serviceGateway:ServiceGateway',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            block_traffic: Optional[pulumi.Input[bool]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            route_table_id: Optional[pulumi.Input[str]] = None,
            services: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ServiceGatewayServiceArgs']]]]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            vcn_id: Optional[pulumi.Input[str]] = None) -> 'ServiceGateway':
        """
        Get an existing ServiceGateway resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] block_traffic: Whether the service gateway blocks all traffic through it. The default is `false`. When this is `true`, traffic is not routed to any services, regardless of route rules.  Example: `true`
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[str] display_name: (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[str] route_table_id: (Updatable) The OCID of the route table the service gateway will use.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['ServiceGatewayServiceArgs']]]] services: (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        :param pulumi.Input[str] state: The service gateway's current state.
        :param pulumi.Input[str] time_created: The date and time the service gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ServiceGatewayState.__new__(_ServiceGatewayState)

        __props__.__dict__["block_traffic"] = block_traffic
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["route_table_id"] = route_table_id
        __props__.__dict__["services"] = services
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["vcn_id"] = vcn_id
        return ServiceGateway(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="blockTraffic")
    def block_traffic(self) -> pulumi.Output[bool]:
        """
        Whether the service gateway blocks all traffic through it. The default is `false`. When this is `true`, traffic is not routed to any services, regardless of route rules.  Example: `true`
        """
        return pulumi.get(self, "block_traffic")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the service gateway.
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
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="routeTableId")
    def route_table_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the route table the service gateway will use.
        """
        return pulumi.get(self, "route_table_id")

    @property
    @pulumi.getter
    def services(self) -> pulumi.Output[Sequence['outputs.ServiceGatewayService']]:
        """
        (Updatable) List of the OCIDs of the [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) objects to enable for the service gateway. This list can be empty if you don't want to enable any `Service` objects when you create the gateway. You can enable a `Service` object later by using either [AttachServiceId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/AttachServiceId) or [UpdateServiceGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ServiceGateway/UpdateServiceGateway).
        """
        return pulumi.get(self, "services")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The service gateway's current state.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the service gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        """
        return pulumi.get(self, "vcn_id")

