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
    'GetMigrationResult',
    'AwaitableGetMigrationResult',
    'get_migration',
]

@pulumi.output_type
class GetMigrationResult:
    """
    A collection of values returned by getMigration.
    """
    def __init__(__self__, agent_id=None, compartment_id=None, credentials_secret_id=None, data_transfer_medium_details=None, datapump_settings=None, defined_tags=None, display_name=None, exclude_objects=None, executing_job_id=None, freeform_tags=None, golden_gate_details=None, id=None, lifecycle_details=None, migration_id=None, source_container_database_connection_id=None, source_database_connection_id=None, state=None, system_tags=None, target_database_connection_id=None, time_created=None, time_last_migration=None, time_updated=None, type=None, vault_details=None, wait_after=None):
        if agent_id and not isinstance(agent_id, str):
            raise TypeError("Expected argument 'agent_id' to be a str")
        pulumi.set(__self__, "agent_id", agent_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if credentials_secret_id and not isinstance(credentials_secret_id, str):
            raise TypeError("Expected argument 'credentials_secret_id' to be a str")
        pulumi.set(__self__, "credentials_secret_id", credentials_secret_id)
        if data_transfer_medium_details and not isinstance(data_transfer_medium_details, dict):
            raise TypeError("Expected argument 'data_transfer_medium_details' to be a dict")
        pulumi.set(__self__, "data_transfer_medium_details", data_transfer_medium_details)
        if datapump_settings and not isinstance(datapump_settings, dict):
            raise TypeError("Expected argument 'datapump_settings' to be a dict")
        pulumi.set(__self__, "datapump_settings", datapump_settings)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if exclude_objects and not isinstance(exclude_objects, list):
            raise TypeError("Expected argument 'exclude_objects' to be a list")
        pulumi.set(__self__, "exclude_objects", exclude_objects)
        if executing_job_id and not isinstance(executing_job_id, str):
            raise TypeError("Expected argument 'executing_job_id' to be a str")
        pulumi.set(__self__, "executing_job_id", executing_job_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if golden_gate_details and not isinstance(golden_gate_details, dict):
            raise TypeError("Expected argument 'golden_gate_details' to be a dict")
        pulumi.set(__self__, "golden_gate_details", golden_gate_details)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if migration_id and not isinstance(migration_id, str):
            raise TypeError("Expected argument 'migration_id' to be a str")
        pulumi.set(__self__, "migration_id", migration_id)
        if source_container_database_connection_id and not isinstance(source_container_database_connection_id, str):
            raise TypeError("Expected argument 'source_container_database_connection_id' to be a str")
        pulumi.set(__self__, "source_container_database_connection_id", source_container_database_connection_id)
        if source_database_connection_id and not isinstance(source_database_connection_id, str):
            raise TypeError("Expected argument 'source_database_connection_id' to be a str")
        pulumi.set(__self__, "source_database_connection_id", source_database_connection_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if target_database_connection_id and not isinstance(target_database_connection_id, str):
            raise TypeError("Expected argument 'target_database_connection_id' to be a str")
        pulumi.set(__self__, "target_database_connection_id", target_database_connection_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_migration and not isinstance(time_last_migration, str):
            raise TypeError("Expected argument 'time_last_migration' to be a str")
        pulumi.set(__self__, "time_last_migration", time_last_migration)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if vault_details and not isinstance(vault_details, dict):
            raise TypeError("Expected argument 'vault_details' to be a dict")
        pulumi.set(__self__, "vault_details", vault_details)
        if wait_after and not isinstance(wait_after, str):
            raise TypeError("Expected argument 'wait_after' to be a str")
        pulumi.set(__self__, "wait_after", wait_after)

    @property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> str:
        """
        The OCID of the registered On-Prem ODMS Agent. Required for Offline Migrations.
        """
        return pulumi.get(self, "agent_id")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        OCID of the compartment where the secret containing the credentials will be created.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="credentialsSecretId")
    def credentials_secret_id(self) -> str:
        """
        OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
        """
        return pulumi.get(self, "credentials_secret_id")

    @property
    @pulumi.getter(name="dataTransferMediumDetails")
    def data_transfer_medium_details(self) -> 'outputs.GetMigrationDataTransferMediumDetailsResult':
        """
        Data Transfer Medium details for the Migration.
        """
        return pulumi.get(self, "data_transfer_medium_details")

    @property
    @pulumi.getter(name="datapumpSettings")
    def datapump_settings(self) -> 'outputs.GetMigrationDatapumpSettingsResult':
        """
        Optional settings for Datapump Export and Import jobs
        """
        return pulumi.get(self, "datapump_settings")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Migration Display Name
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="excludeObjects")
    def exclude_objects(self) -> Sequence['outputs.GetMigrationExcludeObjectResult']:
        """
        Database objects to exclude from migration.
        """
        return pulumi.get(self, "exclude_objects")

    @property
    @pulumi.getter(name="executingJobId")
    def executing_job_id(self) -> str:
        """
        OCID of the current ODMS Job in execution for the Migration, if any.
        """
        return pulumi.get(self, "executing_job_id")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="goldenGateDetails")
    def golden_gate_details(self) -> 'outputs.GetMigrationGoldenGateDetailsResult':
        """
        Details about Oracle GoldenGate Microservices.
        """
        return pulumi.get(self, "golden_gate_details")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The OCID of the resource
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional status related to the execution and current state of the Migration.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="migrationId")
    def migration_id(self) -> str:
        return pulumi.get(self, "migration_id")

    @property
    @pulumi.getter(name="sourceContainerDatabaseConnectionId")
    def source_container_database_connection_id(self) -> str:
        """
        The OCID of the Source Container Database Connection.
        """
        return pulumi.get(self, "source_container_database_connection_id")

    @property
    @pulumi.getter(name="sourceDatabaseConnectionId")
    def source_database_connection_id(self) -> str:
        """
        The OCID of the Source Database Connection.
        """
        return pulumi.get(self, "source_database_connection_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the Migration Resource.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="targetDatabaseConnectionId")
    def target_database_connection_id(self) -> str:
        """
        The OCID of the Target Database Connection.
        """
        return pulumi.get(self, "target_database_connection_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the Migration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastMigration")
    def time_last_migration(self) -> str:
        """
        The time of last Migration. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_last_migration")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time of the last Migration details update. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        Migration type.
        """
        return pulumi.get(self, "type")

    @property
    @pulumi.getter(name="vaultDetails")
    def vault_details(self) -> 'outputs.GetMigrationVaultDetailsResult':
        """
        Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        """
        return pulumi.get(self, "vault_details")

    @property
    @pulumi.getter(name="waitAfter")
    def wait_after(self) -> str:
        """
        Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
        """
        return pulumi.get(self, "wait_after")


class AwaitableGetMigrationResult(GetMigrationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMigrationResult(
            agent_id=self.agent_id,
            compartment_id=self.compartment_id,
            credentials_secret_id=self.credentials_secret_id,
            data_transfer_medium_details=self.data_transfer_medium_details,
            datapump_settings=self.datapump_settings,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            exclude_objects=self.exclude_objects,
            executing_job_id=self.executing_job_id,
            freeform_tags=self.freeform_tags,
            golden_gate_details=self.golden_gate_details,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            migration_id=self.migration_id,
            source_container_database_connection_id=self.source_container_database_connection_id,
            source_database_connection_id=self.source_database_connection_id,
            state=self.state,
            system_tags=self.system_tags,
            target_database_connection_id=self.target_database_connection_id,
            time_created=self.time_created,
            time_last_migration=self.time_last_migration,
            time_updated=self.time_updated,
            type=self.type,
            vault_details=self.vault_details,
            wait_after=self.wait_after)


def get_migration(migration_id: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMigrationResult:
    """
    This data source provides details about a specific Migration resource in Oracle Cloud Infrastructure Database Migration service.

    Display Migration details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_migration = oci.databasemigration.get_migration(migration_id=oci_database_migration_migration["test_migration"]["id"])
    ```


    :param str migration_id: The OCID of the job
    """
    __args__ = dict()
    __args__['migrationId'] = migration_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:databasemigration/getMigration:getMigration', __args__, opts=opts, typ=GetMigrationResult).value

    return AwaitableGetMigrationResult(
        agent_id=__ret__.agent_id,
        compartment_id=__ret__.compartment_id,
        credentials_secret_id=__ret__.credentials_secret_id,
        data_transfer_medium_details=__ret__.data_transfer_medium_details,
        datapump_settings=__ret__.datapump_settings,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        exclude_objects=__ret__.exclude_objects,
        executing_job_id=__ret__.executing_job_id,
        freeform_tags=__ret__.freeform_tags,
        golden_gate_details=__ret__.golden_gate_details,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        migration_id=__ret__.migration_id,
        source_container_database_connection_id=__ret__.source_container_database_connection_id,
        source_database_connection_id=__ret__.source_database_connection_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        target_database_connection_id=__ret__.target_database_connection_id,
        time_created=__ret__.time_created,
        time_last_migration=__ret__.time_last_migration,
        time_updated=__ret__.time_updated,
        type=__ret__.type,
        vault_details=__ret__.vault_details,
        wait_after=__ret__.wait_after)