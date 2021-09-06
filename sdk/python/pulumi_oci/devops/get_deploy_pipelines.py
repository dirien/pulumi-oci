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

__all__ = [
    'GetDeployPipelinesResult',
    'AwaitableGetDeployPipelinesResult',
    'get_deploy_pipelines',
]

@pulumi.output_type
class GetDeployPipelinesResult:
    """
    A collection of values returned by getDeployPipelines.
    """
    def __init__(__self__, compartment_id=None, deploy_pipeline_collections=None, display_name=None, filters=None, id=None, project_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if deploy_pipeline_collections and not isinstance(deploy_pipeline_collections, list):
            raise TypeError("Expected argument 'deploy_pipeline_collections' to be a list")
        pulumi.set(__self__, "deploy_pipeline_collections", deploy_pipeline_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The OCID of the compartment where the pipeline is created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="deployPipelineCollections")
    def deploy_pipeline_collections(self) -> Sequence['outputs.GetDeployPipelinesDeployPipelineCollectionResult']:
        """
        The list of deploy_pipeline_collection.
        """
        return pulumi.get(self, "deploy_pipeline_collections")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDeployPipelinesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[str]:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the deployment pipeline.
        """
        return pulumi.get(self, "state")


class AwaitableGetDeployPipelinesResult(GetDeployPipelinesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeployPipelinesResult(
            compartment_id=self.compartment_id,
            deploy_pipeline_collections=self.deploy_pipeline_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            project_id=self.project_id,
            state=self.state)


def get_deploy_pipelines(compartment_id: Optional[str] = None,
                         display_name: Optional[str] = None,
                         filters: Optional[Sequence[pulumi.InputType['GetDeployPipelinesFilterArgs']]] = None,
                         id: Optional[str] = None,
                         project_id: Optional[str] = None,
                         state: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeployPipelinesResult:
    """
    This data source provides the list of Deploy Pipelines in Oracle Cloud Infrastructure Devops service.

    Returns a list of deployment pipelines.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_pipelines = oci.devops.get_deploy_pipelines(compartment_id=var["compartment_id"],
        display_name=var["deploy_pipeline_display_name"],
        id=var["deploy_pipeline_id"],
        project_id=oci_devops_project["test_project"]["id"],
        state=var["deploy_pipeline_state"])
    ```


    :param str compartment_id: The OCID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    :param str id: Unique identifier or OCID for listing a single resource by ID.
    :param str project_id: unique project identifier
    :param str state: A filter to return only DeployPipelines that matches the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['projectId'] = project_id
    __args__['state'] = state
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:devops/getDeployPipelines:getDeployPipelines', __args__, opts=opts, typ=GetDeployPipelinesResult).value

    return AwaitableGetDeployPipelinesResult(
        compartment_id=__ret__.compartment_id,
        deploy_pipeline_collections=__ret__.deploy_pipeline_collections,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        project_id=__ret__.project_id,
        state=__ret__.state)
