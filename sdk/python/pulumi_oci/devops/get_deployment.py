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
    'GetDeploymentResult',
    'AwaitableGetDeploymentResult',
    'get_deployment',
]

@pulumi.output_type
class GetDeploymentResult:
    """
    A collection of values returned by getDeployment.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, deploy_artifact_override_arguments=None, deploy_pipeline_artifacts=None, deploy_pipeline_environments=None, deploy_pipeline_id=None, deploy_stage_id=None, deployment_arguments=None, deployment_execution_progress=None, deployment_id=None, deployment_type=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, previous_deployment_id=None, project_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deploy_artifact_override_arguments and not isinstance(deploy_artifact_override_arguments, dict):
            raise TypeError("Expected argument 'deploy_artifact_override_arguments' to be a dict")
        pulumi.set(__self__, "deploy_artifact_override_arguments", deploy_artifact_override_arguments)
        if deploy_pipeline_artifacts and not isinstance(deploy_pipeline_artifacts, dict):
            raise TypeError("Expected argument 'deploy_pipeline_artifacts' to be a dict")
        pulumi.set(__self__, "deploy_pipeline_artifacts", deploy_pipeline_artifacts)
        if deploy_pipeline_environments and not isinstance(deploy_pipeline_environments, dict):
            raise TypeError("Expected argument 'deploy_pipeline_environments' to be a dict")
        pulumi.set(__self__, "deploy_pipeline_environments", deploy_pipeline_environments)
        if deploy_pipeline_id and not isinstance(deploy_pipeline_id, str):
            raise TypeError("Expected argument 'deploy_pipeline_id' to be a str")
        pulumi.set(__self__, "deploy_pipeline_id", deploy_pipeline_id)
        if deploy_stage_id and not isinstance(deploy_stage_id, str):
            raise TypeError("Expected argument 'deploy_stage_id' to be a str")
        pulumi.set(__self__, "deploy_stage_id", deploy_stage_id)
        if deployment_arguments and not isinstance(deployment_arguments, dict):
            raise TypeError("Expected argument 'deployment_arguments' to be a dict")
        pulumi.set(__self__, "deployment_arguments", deployment_arguments)
        if deployment_execution_progress and not isinstance(deployment_execution_progress, dict):
            raise TypeError("Expected argument 'deployment_execution_progress' to be a dict")
        pulumi.set(__self__, "deployment_execution_progress", deployment_execution_progress)
        if deployment_id and not isinstance(deployment_id, str):
            raise TypeError("Expected argument 'deployment_id' to be a str")
        pulumi.set(__self__, "deployment_id", deployment_id)
        if deployment_type and not isinstance(deployment_type, str):
            raise TypeError("Expected argument 'deployment_type' to be a str")
        pulumi.set(__self__, "deployment_type", deployment_type)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if previous_deployment_id and not isinstance(previous_deployment_id, str):
            raise TypeError("Expected argument 'previous_deployment_id' to be a str")
        pulumi.set(__self__, "previous_deployment_id", previous_deployment_id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of a compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deployArtifactOverrideArguments")
    def deploy_artifact_override_arguments(self) -> 'outputs.GetDeploymentDeployArtifactOverrideArgumentsResult':
        """
        Specifies the list of artifact override arguments at the time of deployment.
        """
        return pulumi.get(self, "deploy_artifact_override_arguments")

    @property
    @pulumi.getter(name="deployPipelineArtifacts")
    def deploy_pipeline_artifacts(self) -> 'outputs.GetDeploymentDeployPipelineArtifactsResult':
        """
        List of all artifacts used in the pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_artifacts")

    @property
    @pulumi.getter(name="deployPipelineEnvironments")
    def deploy_pipeline_environments(self) -> 'outputs.GetDeploymentDeployPipelineEnvironmentsResult':
        """
        List of all environments used in the pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_environments")

    @property
    @pulumi.getter(name="deployPipelineId")
    def deploy_pipeline_id(self) -> str:
        """
        The OCID of a pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_id")

    @property
    @pulumi.getter(name="deployStageId")
    def deploy_stage_id(self) -> str:
        """
        The OCID of the stage.
        """
        return pulumi.get(self, "deploy_stage_id")

    @property
    @pulumi.getter(name="deploymentArguments")
    def deployment_arguments(self) -> 'outputs.GetDeploymentDeploymentArgumentsResult':
        """
        Specifies list of arguments passed along with the deployment.
        """
        return pulumi.get(self, "deployment_arguments")

    @property
    @pulumi.getter(name="deploymentExecutionProgress")
    def deployment_execution_progress(self) -> 'outputs.GetDeploymentDeploymentExecutionProgressResult':
        """
        The execution progress details of a deployment.
        """
        return pulumi.get(self, "deployment_execution_progress")

    @property
    @pulumi.getter(name="deploymentId")
    def deployment_id(self) -> str:
        return pulumi.get(self, "deployment_id")

    @property
    @pulumi.getter(name="deploymentType")
    def deployment_type(self) -> str:
        """
        Specifies type of Deployment
        """
        return pulumi.get(self, "deployment_type")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="previousDeploymentId")
    def previous_deployment_id(self) -> str:
        """
        Specifies the OCID of the previous deployment to be redeployed.
        """
        return pulumi.get(self, "previous_deployment_id")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the deployment.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeploymentResult(GetDeploymentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeploymentResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            deploy_artifact_override_arguments=self.deploy_artifact_override_arguments,
            deploy_pipeline_artifacts=self.deploy_pipeline_artifacts,
            deploy_pipeline_environments=self.deploy_pipeline_environments,
            deploy_pipeline_id=self.deploy_pipeline_id,
            deploy_stage_id=self.deploy_stage_id,
            deployment_arguments=self.deployment_arguments,
            deployment_execution_progress=self.deployment_execution_progress,
            deployment_id=self.deployment_id,
            deployment_type=self.deployment_type,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            previous_deployment_id=self.previous_deployment_id,
            project_id=self.project_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_deployment(deployment_id: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeploymentResult:
    """
    This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deployment = oci.devops.get_deployment(deployment_id=oci_devops_deployment["test_deployment"]["id"])
    ```


    :param str deployment_id: Unique deployment identifier.
    """
    __args__ = dict()
    __args__['deploymentId'] = deployment_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:devops/getDeployment:getDeployment', __args__, opts=opts, typ=GetDeploymentResult).value

    return AwaitableGetDeploymentResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        deploy_artifact_override_arguments=__ret__.deploy_artifact_override_arguments,
        deploy_pipeline_artifacts=__ret__.deploy_pipeline_artifacts,
        deploy_pipeline_environments=__ret__.deploy_pipeline_environments,
        deploy_pipeline_id=__ret__.deploy_pipeline_id,
        deploy_stage_id=__ret__.deploy_stage_id,
        deployment_arguments=__ret__.deployment_arguments,
        deployment_execution_progress=__ret__.deployment_execution_progress,
        deployment_id=__ret__.deployment_id,
        deployment_type=__ret__.deployment_type,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        previous_deployment_id=__ret__.previous_deployment_id,
        project_id=__ret__.project_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)
