# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetGenericArtifactResult',
    'AwaitableGetGenericArtifactResult',
    'get_generic_artifact',
]

@pulumi.output_type
class GetGenericArtifactResult:
    """
    A collection of values returned by getGenericArtifact.
    """
    def __init__(__self__, artifact_id=None, artifact_path=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, repository_id=None, sha256=None, size_in_bytes=None, state=None, time_created=None, version=None):
        if artifact_id and not isinstance(artifact_id, str):
            raise TypeError("Expected argument 'artifact_id' to be a str")
        pulumi.set(__self__, "artifact_id", artifact_id)
        if artifact_path and not isinstance(artifact_path, str):
            raise TypeError("Expected argument 'artifact_path' to be a str")
        pulumi.set(__self__, "artifact_path", artifact_path)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)
        if sha256 and not isinstance(sha256, str):
            raise TypeError("Expected argument 'sha256' to be a str")
        pulumi.set(__self__, "sha256", sha256)
        if size_in_bytes and not isinstance(size_in_bytes, str):
            raise TypeError("Expected argument 'size_in_bytes' to be a str")
        pulumi.set(__self__, "size_in_bytes", size_in_bytes)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)

    @property
    @pulumi.getter(name="artifactId")
    def artifact_id(self) -> str:
        return pulumi.get(self, "artifact_id")

    @property
    @pulumi.getter(name="artifactPath")
    def artifact_path(self) -> str:
        """
        A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
        """
        return pulumi.get(self, "artifact_path")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
        """
        return pulumi.get(self, "repository_id")

    @property
    @pulumi.getter
    def sha256(self) -> str:
        """
        The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
        """
        return pulumi.get(self, "sha256")

    @property
    @pulumi.getter(name="sizeInBytes")
    def size_in_bytes(self) -> str:
        """
        The size of the artifact in bytes.
        """
        return pulumi.get(self, "size_in_bytes")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the artifact.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        An RFC 3339 timestamp indicating when the repository was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def version(self) -> str:
        """
        A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
        """
        return pulumi.get(self, "version")


class AwaitableGetGenericArtifactResult(GetGenericArtifactResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetGenericArtifactResult(
            artifact_id=self.artifact_id,
            artifact_path=self.artifact_path,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            repository_id=self.repository_id,
            sha256=self.sha256,
            size_in_bytes=self.size_in_bytes,
            state=self.state,
            time_created=self.time_created,
            version=self.version)


def get_generic_artifact(artifact_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetGenericArtifactResult:
    """
    This data source provides details about a specific Generic Artifact resource in Oracle Cloud Infrastructure Artifacts service.

    Gets information about an artifact with a specified [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_generic_artifact = oci.artifacts.get_generic_artifact(artifact_id=oci_artifacts_artifact["test_artifact"]["id"])
    ```


    :param str artifact_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
    """
    __args__ = dict()
    __args__['artifactId'] = artifact_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:artifacts/getGenericArtifact:getGenericArtifact', __args__, opts=opts, typ=GetGenericArtifactResult).value

    return AwaitableGetGenericArtifactResult(
        artifact_id=__ret__.artifact_id,
        artifact_path=__ret__.artifact_path,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        repository_id=__ret__.repository_id,
        sha256=__ret__.sha256,
        size_in_bytes=__ret__.size_in_bytes,
        state=__ret__.state,
        time_created=__ret__.time_created,
        version=__ret__.version)
