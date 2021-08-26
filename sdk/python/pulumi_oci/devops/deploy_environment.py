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

__all__ = ['DeployEnvironmentArgs', 'DeployEnvironment']

@pulumi.input_type
class DeployEnvironmentArgs:
    def __init__(__self__, *,
                 deploy_environment_type: pulumi.Input[str],
                 project_id: pulumi.Input[str],
                 cluster_id: Optional[pulumi.Input[str]] = None,
                 compute_instance_group_selectors: Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 function_id: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a DeployEnvironment resource.
        :param pulumi.Input[str] deploy_environment_type: (Updatable) Deployment environment type.
        :param pulumi.Input[str] project_id: The OCID of a project.
        :param pulumi.Input[str] cluster_id: (Updatable) The OCID of the Kubernetes cluster.
        :param pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs'] compute_instance_group_selectors: (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] description: (Updatable) Optional description about the deployment environment.
        :param pulumi.Input[str] display_name: (Updatable) Deployment environment display name. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] function_id: (Updatable) The OCID of the Function.
        """
        pulumi.set(__self__, "deploy_environment_type", deploy_environment_type)
        pulumi.set(__self__, "project_id", project_id)
        if cluster_id is not None:
            pulumi.set(__self__, "cluster_id", cluster_id)
        if compute_instance_group_selectors is not None:
            pulumi.set(__self__, "compute_instance_group_selectors", compute_instance_group_selectors)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if function_id is not None:
            pulumi.set(__self__, "function_id", function_id)

    @property
    @pulumi.getter(name="deployEnvironmentType")
    def deploy_environment_type(self) -> pulumi.Input[str]:
        """
        (Updatable) Deployment environment type.
        """
        return pulumi.get(self, "deploy_environment_type")

    @deploy_environment_type.setter
    def deploy_environment_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "deploy_environment_type", value)

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> pulumi.Input[str]:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @project_id.setter
    def project_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "project_id", value)

    @property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the Kubernetes cluster.
        """
        return pulumi.get(self, "cluster_id")

    @cluster_id.setter
    def cluster_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "cluster_id", value)

    @property
    @pulumi.getter(name="computeInstanceGroupSelectors")
    def compute_instance_group_selectors(self) -> Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]:
        """
        (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        """
        return pulumi.get(self, "compute_instance_group_selectors")

    @compute_instance_group_selectors.setter
    def compute_instance_group_selectors(self, value: Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]):
        pulumi.set(self, "compute_instance_group_selectors", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional description about the deployment environment.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Deployment environment display name. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="functionId")
    def function_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the Function.
        """
        return pulumi.get(self, "function_id")

    @function_id.setter
    def function_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "function_id", value)


@pulumi.input_type
class _DeployEnvironmentState:
    def __init__(__self__, *,
                 cluster_id: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 compute_instance_group_selectors: Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 deploy_environment_type: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 function_id: Optional[pulumi.Input[str]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 project_id: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering DeployEnvironment resources.
        :param pulumi.Input[str] cluster_id: (Updatable) The OCID of the Kubernetes cluster.
        :param pulumi.Input[str] compartment_id: The OCID of a compartment.
        :param pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs'] compute_instance_group_selectors: (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] deploy_environment_type: (Updatable) Deployment environment type.
        :param pulumi.Input[str] description: (Updatable) Optional description about the deployment environment.
        :param pulumi.Input[str] display_name: (Updatable) Deployment environment display name. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] function_id: (Updatable) The OCID of the Function.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[str] project_id: The OCID of a project.
        :param pulumi.Input[str] state: The current state of the deployment environment.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        :param pulumi.Input[str] time_updated: Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        if cluster_id is not None:
            pulumi.set(__self__, "cluster_id", cluster_id)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_instance_group_selectors is not None:
            pulumi.set(__self__, "compute_instance_group_selectors", compute_instance_group_selectors)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if deploy_environment_type is not None:
            pulumi.set(__self__, "deploy_environment_type", deploy_environment_type)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if function_id is not None:
            pulumi.set(__self__, "function_id", function_id)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if project_id is not None:
            pulumi.set(__self__, "project_id", project_id)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the Kubernetes cluster.
        """
        return pulumi.get(self, "cluster_id")

    @cluster_id.setter
    def cluster_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "cluster_id", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="computeInstanceGroupSelectors")
    def compute_instance_group_selectors(self) -> Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]:
        """
        (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        """
        return pulumi.get(self, "compute_instance_group_selectors")

    @compute_instance_group_selectors.setter
    def compute_instance_group_selectors(self, value: Optional[pulumi.Input['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]):
        pulumi.set(self, "compute_instance_group_selectors", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="deployEnvironmentType")
    def deploy_environment_type(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Deployment environment type.
        """
        return pulumi.get(self, "deploy_environment_type")

    @deploy_environment_type.setter
    def deploy_environment_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "deploy_environment_type", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Optional description about the deployment environment.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Deployment environment display name. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="functionId")
    def function_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The OCID of the Function.
        """
        return pulumi.get(self, "function_id")

    @function_id.setter
    def function_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "function_id", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @project_id.setter
    def project_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "project_id", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the deployment environment.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "system_tags", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class DeployEnvironment(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cluster_id: Optional[pulumi.Input[str]] = None,
                 compute_instance_group_selectors: Optional[pulumi.Input[pulumi.InputType['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 deploy_environment_type: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 function_id: Optional[pulumi.Input[str]] = None,
                 project_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Deploy Environment resource in Oracle Cloud Infrastructure Devops service.

        Creates a new deployment environment.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_deploy_environment = oci.devops.DeployEnvironment("testDeployEnvironment",
            deploy_environment_type=var["deploy_environment_deploy_environment_type"],
            project_id=oci_devops_project["test_project"]["id"],
            cluster_id=oci_containerengine_cluster["test_cluster"]["id"],
            compute_instance_group_selectors=oci.devops.DeployEnvironmentComputeInstanceGroupSelectorsArgs(
                items=[oci.devops.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs(
                    selector_type=var["deploy_environment_compute_instance_group_selectors_items_selector_type"],
                    compute_instance_ids=var["deploy_environment_compute_instance_group_selectors_items_compute_instance_ids"],
                    query=var["deploy_environment_compute_instance_group_selectors_items_query"],
                    region=var["deploy_environment_compute_instance_group_selectors_items_region"],
                )],
            ),
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=var["deploy_environment_description"],
            display_name=var["deploy_environment_display_name"],
            freeform_tags={
                "bar-key": "value",
            },
            function_id=oci_functions_function["test_function"]["id"])
        ```

        ## Import

        DeployEnvironments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:devops/deployEnvironment:DeployEnvironment test_deploy_environment "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] cluster_id: (Updatable) The OCID of the Kubernetes cluster.
        :param pulumi.Input[pulumi.InputType['DeployEnvironmentComputeInstanceGroupSelectorsArgs']] compute_instance_group_selectors: (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] deploy_environment_type: (Updatable) Deployment environment type.
        :param pulumi.Input[str] description: (Updatable) Optional description about the deployment environment.
        :param pulumi.Input[str] display_name: (Updatable) Deployment environment display name. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] function_id: (Updatable) The OCID of the Function.
        :param pulumi.Input[str] project_id: The OCID of a project.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: DeployEnvironmentArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Deploy Environment resource in Oracle Cloud Infrastructure Devops service.

        Creates a new deployment environment.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_deploy_environment = oci.devops.DeployEnvironment("testDeployEnvironment",
            deploy_environment_type=var["deploy_environment_deploy_environment_type"],
            project_id=oci_devops_project["test_project"]["id"],
            cluster_id=oci_containerengine_cluster["test_cluster"]["id"],
            compute_instance_group_selectors=oci.devops.DeployEnvironmentComputeInstanceGroupSelectorsArgs(
                items=[oci.devops.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs(
                    selector_type=var["deploy_environment_compute_instance_group_selectors_items_selector_type"],
                    compute_instance_ids=var["deploy_environment_compute_instance_group_selectors_items_compute_instance_ids"],
                    query=var["deploy_environment_compute_instance_group_selectors_items_query"],
                    region=var["deploy_environment_compute_instance_group_selectors_items_region"],
                )],
            ),
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            description=var["deploy_environment_description"],
            display_name=var["deploy_environment_display_name"],
            freeform_tags={
                "bar-key": "value",
            },
            function_id=oci_functions_function["test_function"]["id"])
        ```

        ## Import

        DeployEnvironments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:devops/deployEnvironment:DeployEnvironment test_deploy_environment "id"
        ```

        :param str resource_name: The name of the resource.
        :param DeployEnvironmentArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(DeployEnvironmentArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cluster_id: Optional[pulumi.Input[str]] = None,
                 compute_instance_group_selectors: Optional[pulumi.Input[pulumi.InputType['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 deploy_environment_type: Optional[pulumi.Input[str]] = None,
                 description: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 function_id: Optional[pulumi.Input[str]] = None,
                 project_id: Optional[pulumi.Input[str]] = None,
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
            __props__ = DeployEnvironmentArgs.__new__(DeployEnvironmentArgs)

            __props__.__dict__["cluster_id"] = cluster_id
            __props__.__dict__["compute_instance_group_selectors"] = compute_instance_group_selectors
            __props__.__dict__["defined_tags"] = defined_tags
            if deploy_environment_type is None and not opts.urn:
                raise TypeError("Missing required property 'deploy_environment_type'")
            __props__.__dict__["deploy_environment_type"] = deploy_environment_type
            __props__.__dict__["description"] = description
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            __props__.__dict__["function_id"] = function_id
            if project_id is None and not opts.urn:
                raise TypeError("Missing required property 'project_id'")
            __props__.__dict__["project_id"] = project_id
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(DeployEnvironment, __self__).__init__(
            'oci:devops/deployEnvironment:DeployEnvironment',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            cluster_id: Optional[pulumi.Input[str]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            compute_instance_group_selectors: Optional[pulumi.Input[pulumi.InputType['DeployEnvironmentComputeInstanceGroupSelectorsArgs']]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            deploy_environment_type: Optional[pulumi.Input[str]] = None,
            description: Optional[pulumi.Input[str]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            function_id: Optional[pulumi.Input[str]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            project_id: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'DeployEnvironment':
        """
        Get an existing DeployEnvironment resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] cluster_id: (Updatable) The OCID of the Kubernetes cluster.
        :param pulumi.Input[str] compartment_id: The OCID of a compartment.
        :param pulumi.Input[pulumi.InputType['DeployEnvironmentComputeInstanceGroupSelectorsArgs']] compute_instance_group_selectors: (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] deploy_environment_type: (Updatable) Deployment environment type.
        :param pulumi.Input[str] description: (Updatable) Optional description about the deployment environment.
        :param pulumi.Input[str] display_name: (Updatable) Deployment environment display name. Avoid entering confidential information.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] function_id: (Updatable) The OCID of the Function.
        :param pulumi.Input[str] lifecycle_details: A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        :param pulumi.Input[str] project_id: The OCID of a project.
        :param pulumi.Input[str] state: The current state of the deployment environment.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        :param pulumi.Input[str] time_updated: Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _DeployEnvironmentState.__new__(_DeployEnvironmentState)

        __props__.__dict__["cluster_id"] = cluster_id
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["compute_instance_group_selectors"] = compute_instance_group_selectors
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["deploy_environment_type"] = deploy_environment_type
        __props__.__dict__["description"] = description
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["function_id"] = function_id
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["project_id"] = project_id
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return DeployEnvironment(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the Kubernetes cluster.
        """
        return pulumi.get(self, "cluster_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="computeInstanceGroupSelectors")
    def compute_instance_group_selectors(self) -> pulumi.Output['outputs.DeployEnvironmentComputeInstanceGroupSelectors']:
        """
        (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
        """
        return pulumi.get(self, "compute_instance_group_selectors")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deployEnvironmentType")
    def deploy_environment_type(self) -> pulumi.Output[str]:
        """
        (Updatable) Deployment environment type.
        """
        return pulumi.get(self, "deploy_environment_type")

    @property
    @pulumi.getter
    def description(self) -> pulumi.Output[str]:
        """
        (Updatable) Optional description about the deployment environment.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) Deployment environment display name. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="functionId")
    def function_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The OCID of the Function.
        """
        return pulumi.get(self, "function_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> pulumi.Output[str]:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the deployment environment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")

