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

__all__ = ['ContainerRepositoryArgs', 'ContainerRepository']

@pulumi.input_type
class ContainerRepositoryArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 display_name: pulumi.Input[str],
                 is_immutable: Optional[pulumi.Input[bool]] = None,
                 is_public: Optional[pulumi.Input[bool]] = None,
                 readme: Optional[pulumi.Input['ContainerRepositoryReadmeArgs']] = None):
        """
        The set of arguments for constructing a ContainerRepository resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        :param pulumi.Input[str] display_name: The container repository name.
        :param pulumi.Input[bool] is_immutable: (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        :param pulumi.Input[bool] is_public: (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        :param pulumi.Input['ContainerRepositoryReadmeArgs'] readme: (Updatable) Container repository readme.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        if is_immutable is not None:
            pulumi.set(__self__, "is_immutable", is_immutable)
        if is_public is not None:
            pulumi.set(__self__, "is_public", is_public)
        if readme is not None:
            pulumi.set(__self__, "readme", readme)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        The container repository name.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="isImmutable")
    def is_immutable(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        """
        return pulumi.get(self, "is_immutable")

    @is_immutable.setter
    def is_immutable(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_immutable", value)

    @property
    @pulumi.getter(name="isPublic")
    def is_public(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        """
        return pulumi.get(self, "is_public")

    @is_public.setter
    def is_public(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_public", value)

    @property
    @pulumi.getter
    def readme(self) -> Optional[pulumi.Input['ContainerRepositoryReadmeArgs']]:
        """
        (Updatable) Container repository readme.
        """
        return pulumi.get(self, "readme")

    @readme.setter
    def readme(self, value: Optional[pulumi.Input['ContainerRepositoryReadmeArgs']]):
        pulumi.set(self, "readme", value)


@pulumi.input_type
class _ContainerRepositoryState:
    def __init__(__self__, *,
                 billable_size_in_gbs: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 created_by: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 image_count: Optional[pulumi.Input[int]] = None,
                 is_immutable: Optional[pulumi.Input[bool]] = None,
                 is_public: Optional[pulumi.Input[bool]] = None,
                 layer_count: Optional[pulumi.Input[int]] = None,
                 layers_size_in_bytes: Optional[pulumi.Input[str]] = None,
                 readme: Optional[pulumi.Input['ContainerRepositoryReadmeArgs']] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_last_pushed: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering ContainerRepository resources.
        :param pulumi.Input[str] billable_size_in_gbs: Total storage size in GBs that will be charged.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        :param pulumi.Input[str] created_by: The id of the user or principal that created the resource.
        :param pulumi.Input[str] display_name: The container repository name.
        :param pulumi.Input[int] image_count: Total number of images.
        :param pulumi.Input[bool] is_immutable: (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        :param pulumi.Input[bool] is_public: (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        :param pulumi.Input[int] layer_count: Total number of layers.
        :param pulumi.Input[str] layers_size_in_bytes: Total storage in bytes consumed by layers.
        :param pulumi.Input['ContainerRepositoryReadmeArgs'] readme: (Updatable) Container repository readme.
        :param pulumi.Input[str] state: The current state of the container repository.
        :param pulumi.Input[str] time_created: An RFC 3339 timestamp indicating when the repository was created.
        :param pulumi.Input[str] time_last_pushed: An RFC 3339 timestamp indicating when an image was last pushed to the repository.
        """
        if billable_size_in_gbs is not None:
            pulumi.set(__self__, "billable_size_in_gbs", billable_size_in_gbs)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by is not None:
            pulumi.set(__self__, "created_by", created_by)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if image_count is not None:
            pulumi.set(__self__, "image_count", image_count)
        if is_immutable is not None:
            pulumi.set(__self__, "is_immutable", is_immutable)
        if is_public is not None:
            pulumi.set(__self__, "is_public", is_public)
        if layer_count is not None:
            pulumi.set(__self__, "layer_count", layer_count)
        if layers_size_in_bytes is not None:
            pulumi.set(__self__, "layers_size_in_bytes", layers_size_in_bytes)
        if readme is not None:
            pulumi.set(__self__, "readme", readme)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_last_pushed is not None:
            pulumi.set(__self__, "time_last_pushed", time_last_pushed)

    @property
    @pulumi.getter(name="billableSizeInGbs")
    def billable_size_in_gbs(self) -> Optional[pulumi.Input[str]]:
        """
        Total storage size in GBs that will be charged.
        """
        return pulumi.get(self, "billable_size_in_gbs")

    @billable_size_in_gbs.setter
    def billable_size_in_gbs(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "billable_size_in_gbs", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[pulumi.Input[str]]:
        """
        The id of the user or principal that created the resource.
        """
        return pulumi.get(self, "created_by")

    @created_by.setter
    def created_by(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "created_by", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        The container repository name.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="imageCount")
    def image_count(self) -> Optional[pulumi.Input[int]]:
        """
        Total number of images.
        """
        return pulumi.get(self, "image_count")

    @image_count.setter
    def image_count(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "image_count", value)

    @property
    @pulumi.getter(name="isImmutable")
    def is_immutable(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        """
        return pulumi.get(self, "is_immutable")

    @is_immutable.setter
    def is_immutable(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_immutable", value)

    @property
    @pulumi.getter(name="isPublic")
    def is_public(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        """
        return pulumi.get(self, "is_public")

    @is_public.setter
    def is_public(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_public", value)

    @property
    @pulumi.getter(name="layerCount")
    def layer_count(self) -> Optional[pulumi.Input[int]]:
        """
        Total number of layers.
        """
        return pulumi.get(self, "layer_count")

    @layer_count.setter
    def layer_count(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "layer_count", value)

    @property
    @pulumi.getter(name="layersSizeInBytes")
    def layers_size_in_bytes(self) -> Optional[pulumi.Input[str]]:
        """
        Total storage in bytes consumed by layers.
        """
        return pulumi.get(self, "layers_size_in_bytes")

    @layers_size_in_bytes.setter
    def layers_size_in_bytes(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "layers_size_in_bytes", value)

    @property
    @pulumi.getter
    def readme(self) -> Optional[pulumi.Input['ContainerRepositoryReadmeArgs']]:
        """
        (Updatable) Container repository readme.
        """
        return pulumi.get(self, "readme")

    @readme.setter
    def readme(self, value: Optional[pulumi.Input['ContainerRepositoryReadmeArgs']]):
        pulumi.set(self, "readme", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the container repository.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        An RFC 3339 timestamp indicating when the repository was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeLastPushed")
    def time_last_pushed(self) -> Optional[pulumi.Input[str]]:
        """
        An RFC 3339 timestamp indicating when an image was last pushed to the repository.
        """
        return pulumi.get(self, "time_last_pushed")

    @time_last_pushed.setter
    def time_last_pushed(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_last_pushed", value)


class ContainerRepository(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 is_immutable: Optional[pulumi.Input[bool]] = None,
                 is_public: Optional[pulumi.Input[bool]] = None,
                 readme: Optional[pulumi.Input[pulumi.InputType['ContainerRepositoryReadmeArgs']]] = None,
                 __props__=None):
        """
        This resource provides the Container Repository resource in Oracle Cloud Infrastructure Artifacts service.

        Create a new empty container repository. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_container_repository = oci.artifacts.ContainerRepository("testContainerRepository",
            compartment_id=var["compartment_id"],
            display_name=var["container_repository_display_name"],
            is_immutable=var["container_repository_is_immutable"],
            is_public=var["container_repository_is_public"],
            readme=oci.artifacts.ContainerRepositoryReadmeArgs(
                content=var["container_repository_readme_content"],
                format=var["container_repository_readme_format"],
            ))
        ```

        ## Import

        ContainerRepositories can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:artifacts/containerRepository:ContainerRepository test_container_repository "container/repositories/{repositoryId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        :param pulumi.Input[str] display_name: The container repository name.
        :param pulumi.Input[bool] is_immutable: (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        :param pulumi.Input[bool] is_public: (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        :param pulumi.Input[pulumi.InputType['ContainerRepositoryReadmeArgs']] readme: (Updatable) Container repository readme.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ContainerRepositoryArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Container Repository resource in Oracle Cloud Infrastructure Artifacts service.

        Create a new empty container repository. Avoid entering confidential information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_container_repository = oci.artifacts.ContainerRepository("testContainerRepository",
            compartment_id=var["compartment_id"],
            display_name=var["container_repository_display_name"],
            is_immutable=var["container_repository_is_immutable"],
            is_public=var["container_repository_is_public"],
            readme=oci.artifacts.ContainerRepositoryReadmeArgs(
                content=var["container_repository_readme_content"],
                format=var["container_repository_readme_format"],
            ))
        ```

        ## Import

        ContainerRepositories can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:artifacts/containerRepository:ContainerRepository test_container_repository "container/repositories/{repositoryId}"
        ```

        :param str resource_name: The name of the resource.
        :param ContainerRepositoryArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ContainerRepositoryArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 is_immutable: Optional[pulumi.Input[bool]] = None,
                 is_public: Optional[pulumi.Input[bool]] = None,
                 readme: Optional[pulumi.Input[pulumi.InputType['ContainerRepositoryReadmeArgs']]] = None,
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
            __props__ = ContainerRepositoryArgs.__new__(ContainerRepositoryArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["is_immutable"] = is_immutable
            __props__.__dict__["is_public"] = is_public
            __props__.__dict__["readme"] = readme
            __props__.__dict__["billable_size_in_gbs"] = None
            __props__.__dict__["created_by"] = None
            __props__.__dict__["image_count"] = None
            __props__.__dict__["layer_count"] = None
            __props__.__dict__["layers_size_in_bytes"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_last_pushed"] = None
        super(ContainerRepository, __self__).__init__(
            'oci:artifacts/containerRepository:ContainerRepository',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            billable_size_in_gbs: Optional[pulumi.Input[str]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            created_by: Optional[pulumi.Input[str]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            image_count: Optional[pulumi.Input[int]] = None,
            is_immutable: Optional[pulumi.Input[bool]] = None,
            is_public: Optional[pulumi.Input[bool]] = None,
            layer_count: Optional[pulumi.Input[int]] = None,
            layers_size_in_bytes: Optional[pulumi.Input[str]] = None,
            readme: Optional[pulumi.Input[pulumi.InputType['ContainerRepositoryReadmeArgs']]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_last_pushed: Optional[pulumi.Input[str]] = None) -> 'ContainerRepository':
        """
        Get an existing ContainerRepository resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] billable_size_in_gbs: Total storage size in GBs that will be charged.
        :param pulumi.Input[str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        :param pulumi.Input[str] created_by: The id of the user or principal that created the resource.
        :param pulumi.Input[str] display_name: The container repository name.
        :param pulumi.Input[int] image_count: Total number of images.
        :param pulumi.Input[bool] is_immutable: (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        :param pulumi.Input[bool] is_public: (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        :param pulumi.Input[int] layer_count: Total number of layers.
        :param pulumi.Input[str] layers_size_in_bytes: Total storage in bytes consumed by layers.
        :param pulumi.Input[pulumi.InputType['ContainerRepositoryReadmeArgs']] readme: (Updatable) Container repository readme.
        :param pulumi.Input[str] state: The current state of the container repository.
        :param pulumi.Input[str] time_created: An RFC 3339 timestamp indicating when the repository was created.
        :param pulumi.Input[str] time_last_pushed: An RFC 3339 timestamp indicating when an image was last pushed to the repository.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ContainerRepositoryState.__new__(_ContainerRepositoryState)

        __props__.__dict__["billable_size_in_gbs"] = billable_size_in_gbs
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["created_by"] = created_by
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["image_count"] = image_count
        __props__.__dict__["is_immutable"] = is_immutable
        __props__.__dict__["is_public"] = is_public
        __props__.__dict__["layer_count"] = layer_count
        __props__.__dict__["layers_size_in_bytes"] = layers_size_in_bytes
        __props__.__dict__["readme"] = readme
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_last_pushed"] = time_last_pushed
        return ContainerRepository(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="billableSizeInGbs")
    def billable_size_in_gbs(self) -> pulumi.Output[str]:
        """
        Total storage size in GBs that will be charged.
        """
        return pulumi.get(self, "billable_size_in_gbs")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the resource.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> pulumi.Output[str]:
        """
        The id of the user or principal that created the resource.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        The container repository name.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="imageCount")
    def image_count(self) -> pulumi.Output[int]:
        """
        Total number of images.
        """
        return pulumi.get(self, "image_count")

    @property
    @pulumi.getter(name="isImmutable")
    def is_immutable(self) -> pulumi.Output[bool]:
        """
        (Updatable) Whether the repository is immutable. Images cannot be overwritten in an immutable repository.
        """
        return pulumi.get(self, "is_immutable")

    @property
    @pulumi.getter(name="isPublic")
    def is_public(self) -> pulumi.Output[bool]:
        """
        (Updatable) Whether the repository is public. A public repository allows unauthenticated access.
        """
        return pulumi.get(self, "is_public")

    @property
    @pulumi.getter(name="layerCount")
    def layer_count(self) -> pulumi.Output[int]:
        """
        Total number of layers.
        """
        return pulumi.get(self, "layer_count")

    @property
    @pulumi.getter(name="layersSizeInBytes")
    def layers_size_in_bytes(self) -> pulumi.Output[str]:
        """
        Total storage in bytes consumed by layers.
        """
        return pulumi.get(self, "layers_size_in_bytes")

    @property
    @pulumi.getter
    def readme(self) -> pulumi.Output['outputs.ContainerRepositoryReadme']:
        """
        (Updatable) Container repository readme.
        """
        return pulumi.get(self, "readme")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the container repository.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        An RFC 3339 timestamp indicating when the repository was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastPushed")
    def time_last_pushed(self) -> pulumi.Output[str]:
        """
        An RFC 3339 timestamp indicating when an image was last pushed to the repository.
        """
        return pulumi.get(self, "time_last_pushed")

