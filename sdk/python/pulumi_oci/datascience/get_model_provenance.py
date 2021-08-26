# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetModelProvenanceResult',
    'AwaitableGetModelProvenanceResult',
    'get_model_provenance',
]

@pulumi.output_type
class GetModelProvenanceResult:
    """
    A collection of values returned by getModelProvenance.
    """
    def __init__(__self__, git_branch=None, git_commit=None, id=None, model_id=None, repository_url=None, script_dir=None, training_id=None, training_script=None):
        if git_branch and not isinstance(git_branch, str):
            raise TypeError("Expected argument 'git_branch' to be a str")
        pulumi.set(__self__, "git_branch", git_branch)
        if git_commit and not isinstance(git_commit, str):
            raise TypeError("Expected argument 'git_commit' to be a str")
        pulumi.set(__self__, "git_commit", git_commit)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if model_id and not isinstance(model_id, str):
            raise TypeError("Expected argument 'model_id' to be a str")
        pulumi.set(__self__, "model_id", model_id)
        if repository_url and not isinstance(repository_url, str):
            raise TypeError("Expected argument 'repository_url' to be a str")
        pulumi.set(__self__, "repository_url", repository_url)
        if script_dir and not isinstance(script_dir, str):
            raise TypeError("Expected argument 'script_dir' to be a str")
        pulumi.set(__self__, "script_dir", script_dir)
        if training_id and not isinstance(training_id, str):
            raise TypeError("Expected argument 'training_id' to be a str")
        pulumi.set(__self__, "training_id", training_id)
        if training_script and not isinstance(training_script, str):
            raise TypeError("Expected argument 'training_script' to be a str")
        pulumi.set(__self__, "training_script", training_script)

    @property
    @pulumi.getter(name="gitBranch")
    def git_branch(self) -> str:
        """
        For model reproducibility purposes. Branch of the git repository associated with model training.
        """
        return pulumi.get(self, "git_branch")

    @property
    @pulumi.getter(name="gitCommit")
    def git_commit(self) -> str:
        """
        For model reproducibility purposes. Commit ID of the git repository associated with model training.
        """
        return pulumi.get(self, "git_commit")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="modelId")
    def model_id(self) -> str:
        return pulumi.get(self, "model_id")

    @property
    @pulumi.getter(name="repositoryUrl")
    def repository_url(self) -> str:
        """
        For model reproducibility purposes. URL of the git repository associated with model training.
        """
        return pulumi.get(self, "repository_url")

    @property
    @pulumi.getter(name="scriptDir")
    def script_dir(self) -> str:
        """
        For model reproducibility purposes. Path to model artifacts.
        """
        return pulumi.get(self, "script_dir")

    @property
    @pulumi.getter(name="trainingId")
    def training_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
        """
        return pulumi.get(self, "training_id")

    @property
    @pulumi.getter(name="trainingScript")
    def training_script(self) -> str:
        """
        For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
        """
        return pulumi.get(self, "training_script")


class AwaitableGetModelProvenanceResult(GetModelProvenanceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetModelProvenanceResult(
            git_branch=self.git_branch,
            git_commit=self.git_commit,
            id=self.id,
            model_id=self.model_id,
            repository_url=self.repository_url,
            script_dir=self.script_dir,
            training_id=self.training_id,
            training_script=self.training_script)


def get_model_provenance(model_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetModelProvenanceResult:
    """
    This data source provides details about a specific Model Provenance resource in Oracle Cloud Infrastructure Data Science service.

    Gets provenance information for specified model.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_provenance = oci.datascience.get_model_provenance(model_id=oci_datascience_model["test_model"]["id"])
    ```


    :param str model_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
    """
    __args__ = dict()
    __args__['modelId'] = model_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:datascience/getModelProvenance:getModelProvenance', __args__, opts=opts, typ=GetModelProvenanceResult).value

    return AwaitableGetModelProvenanceResult(
        git_branch=__ret__.git_branch,
        git_commit=__ret__.git_commit,
        id=__ret__.id,
        model_id=__ret__.model_id,
        repository_url=__ret__.repository_url,
        script_dir=__ret__.script_dir,
        training_id=__ret__.training_id,
        training_script=__ret__.training_script)
