# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetContainerImageResult',
    'AwaitableGetContainerImageResult',
    'get_container_image',
]

@pulumi.output_type
class GetContainerImageResult:
    """
    A collection of values returned by getContainerImage.
    """
    def __init__(__self__, compartment_id=None, created_by=None, digest=None, display_name=None, id=None, image_id=None, layers=None, layers_size_in_bytes=None, manifest_size_in_bytes=None, pull_count=None, repository_id=None, repository_name=None, state=None, time_created=None, time_last_pulled=None, version=None, versions=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if digest and not isinstance(digest, str):
            raise TypeError("Expected argument 'digest' to be a str")
        pulumi.set(__self__, "digest", digest)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if image_id and not isinstance(image_id, str):
            raise TypeError("Expected argument 'image_id' to be a str")
        pulumi.set(__self__, "image_id", image_id)
        if layers and not isinstance(layers, list):
            raise TypeError("Expected argument 'layers' to be a list")
        pulumi.set(__self__, "layers", layers)
        if layers_size_in_bytes and not isinstance(layers_size_in_bytes, str):
            raise TypeError("Expected argument 'layers_size_in_bytes' to be a str")
        pulumi.set(__self__, "layers_size_in_bytes", layers_size_in_bytes)
        if manifest_size_in_bytes and not isinstance(manifest_size_in_bytes, int):
            raise TypeError("Expected argument 'manifest_size_in_bytes' to be a int")
        pulumi.set(__self__, "manifest_size_in_bytes", manifest_size_in_bytes)
        if pull_count and not isinstance(pull_count, str):
            raise TypeError("Expected argument 'pull_count' to be a str")
        pulumi.set(__self__, "pull_count", pull_count)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if repository_name and not isinstance(repository_name, str):
            raise TypeError("Expected argument 'repository_name' to be a str")
        pulumi.set(__self__, "repository_name", repository_name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_pulled and not isinstance(time_last_pulled, str):
            raise TypeError("Expected argument 'time_last_pulled' to be a str")
        pulumi.set(__self__, "time_last_pulled", time_last_pulled)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)
        if versions and not isinstance(versions, list):
            raise TypeError("Expected argument 'versions' to be a list")
        pulumi.set(__self__, "versions", versions)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The compartment OCID to which the container image belongs. Inferred from the container repository.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> str:
        """
        The OCID of the user or principal that pushed the version.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter
    def digest(self) -> str:
        """
        The sha256 digest of the image layer.
        """
        return pulumi.get(self, "digest")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The repository name and the most recent version associated with the image. If there are no versions associated with the image, then last known version and digest are used instead. If the last known version is unavailable, then 'unknown' is used instead of the version.  Example: `ubuntu:latest` or `ubuntu:latest@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="imageId")
    def image_id(self) -> str:
        return pulumi.get(self, "image_id")

    @property
    @pulumi.getter
    def layers(self) -> Sequence['outputs.GetContainerImageLayerResult']:
        """
        Layers of which the image is composed, ordered by the layer digest.
        """
        return pulumi.get(self, "layers")

    @property
    @pulumi.getter(name="layersSizeInBytes")
    def layers_size_in_bytes(self) -> str:
        """
        The total size of the container image layers in bytes.
        """
        return pulumi.get(self, "layers_size_in_bytes")

    @property
    @pulumi.getter(name="manifestSizeInBytes")
    def manifest_size_in_bytes(self) -> int:
        """
        The size of the container image manifest in bytes.
        """
        return pulumi.get(self, "manifest_size_in_bytes")

    @property
    @pulumi.getter(name="pullCount")
    def pull_count(self) -> str:
        """
        Total number of pulls.
        """
        return pulumi.get(self, "pull_count")

    @property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container repository.
        """
        return pulumi.get(self, "repository_id")

    @property
    @pulumi.getter(name="repositoryName")
    def repository_name(self) -> str:
        """
        The container repository name.
        """
        return pulumi.get(self, "repository_name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the container image.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The creation time of the version.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastPulled")
    def time_last_pulled(self) -> str:
        """
        An RFC 3339 timestamp indicating when the image was last pulled.
        """
        return pulumi.get(self, "time_last_pulled")

    @property
    @pulumi.getter
    def version(self) -> str:
        """
        The version name.
        """
        return pulumi.get(self, "version")

    @property
    @pulumi.getter
    def versions(self) -> Sequence['outputs.GetContainerImageVersionResult']:
        """
        The versions associated with this image.
        """
        return pulumi.get(self, "versions")


class AwaitableGetContainerImageResult(GetContainerImageResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetContainerImageResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            digest=self.digest,
            display_name=self.display_name,
            id=self.id,
            image_id=self.image_id,
            layers=self.layers,
            layers_size_in_bytes=self.layers_size_in_bytes,
            manifest_size_in_bytes=self.manifest_size_in_bytes,
            pull_count=self.pull_count,
            repository_id=self.repository_id,
            repository_name=self.repository_name,
            state=self.state,
            time_created=self.time_created,
            time_last_pulled=self.time_last_pulled,
            version=self.version,
            versions=self.versions)


def get_container_image(image_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetContainerImageResult:
    """
    This data source provides details about a specific Container Image resource in Oracle Cloud Infrastructure Artifacts service.

    Get container image metadata.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_image = oci.artifacts.get_container_image(image_id=var["container_image_id"])
    ```


    :param str image_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
    """
    __args__ = dict()
    __args__['imageId'] = image_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:artifacts/getContainerImage:getContainerImage', __args__, opts=opts, typ=GetContainerImageResult).value

    return AwaitableGetContainerImageResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        digest=__ret__.digest,
        display_name=__ret__.display_name,
        id=__ret__.id,
        image_id=__ret__.image_id,
        layers=__ret__.layers,
        layers_size_in_bytes=__ret__.layers_size_in_bytes,
        manifest_size_in_bytes=__ret__.manifest_size_in_bytes,
        pull_count=__ret__.pull_count,
        repository_id=__ret__.repository_id,
        repository_name=__ret__.repository_name,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_last_pulled=__ret__.time_last_pulled,
        version=__ret__.version,
        versions=__ret__.versions)
