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
    'GetAutonomousContainerDatabaseResult',
    'AwaitableGetAutonomousContainerDatabaseResult',
    'get_autonomous_container_database',
]

@pulumi.output_type
class GetAutonomousContainerDatabaseResult:
    """
    A collection of values returned by getAutonomousContainerDatabase.
    """
    def __init__(__self__, autonomous_container_database_id=None, autonomous_exadata_infrastructure_id=None, autonomous_vm_cluster_id=None, availability_domain=None, backup_config=None, compartment_id=None, db_unique_name=None, db_version=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, infrastructure_type=None, key_store_id=None, key_store_wallet_name=None, kms_key_id=None, last_maintenance_run_id=None, lifecycle_details=None, maintenance_window=None, maintenance_window_details=None, next_maintenance_run_id=None, patch_id=None, patch_model=None, peer_autonomous_container_database_backup_config=None, peer_autonomous_container_database_compartment_id=None, peer_autonomous_container_database_display_name=None, peer_autonomous_exadata_infrastructure_id=None, peer_autonomous_vm_cluster_id=None, peer_db_unique_name=None, protection_mode=None, role=None, rotate_key_trigger=None, service_level_agreement_type=None, standby_maintenance_buffer_in_days=None, state=None, time_created=None, vault_id=None):
        if autonomous_container_database_id and not isinstance(autonomous_container_database_id, str):
            raise TypeError("Expected argument 'autonomous_container_database_id' to be a str")
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if autonomous_exadata_infrastructure_id and not isinstance(autonomous_exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'autonomous_exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "autonomous_exadata_infrastructure_id", autonomous_exadata_infrastructure_id)
        if autonomous_vm_cluster_id and not isinstance(autonomous_vm_cluster_id, str):
            raise TypeError("Expected argument 'autonomous_vm_cluster_id' to be a str")
        pulumi.set(__self__, "autonomous_vm_cluster_id", autonomous_vm_cluster_id)
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if backup_config and not isinstance(backup_config, dict):
            raise TypeError("Expected argument 'backup_config' to be a dict")
        pulumi.set(__self__, "backup_config", backup_config)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if db_unique_name and not isinstance(db_unique_name, str):
            raise TypeError("Expected argument 'db_unique_name' to be a str")
        pulumi.set(__self__, "db_unique_name", db_unique_name)
        if db_version and not isinstance(db_version, str):
            raise TypeError("Expected argument 'db_version' to be a str")
        pulumi.set(__self__, "db_version", db_version)
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
        if infrastructure_type and not isinstance(infrastructure_type, str):
            raise TypeError("Expected argument 'infrastructure_type' to be a str")
        pulumi.set(__self__, "infrastructure_type", infrastructure_type)
        if key_store_id and not isinstance(key_store_id, str):
            raise TypeError("Expected argument 'key_store_id' to be a str")
        pulumi.set(__self__, "key_store_id", key_store_id)
        if key_store_wallet_name and not isinstance(key_store_wallet_name, str):
            raise TypeError("Expected argument 'key_store_wallet_name' to be a str")
        pulumi.set(__self__, "key_store_wallet_name", key_store_wallet_name)
        if kms_key_id and not isinstance(kms_key_id, str):
            raise TypeError("Expected argument 'kms_key_id' to be a str")
        pulumi.set(__self__, "kms_key_id", kms_key_id)
        if last_maintenance_run_id and not isinstance(last_maintenance_run_id, str):
            raise TypeError("Expected argument 'last_maintenance_run_id' to be a str")
        pulumi.set(__self__, "last_maintenance_run_id", last_maintenance_run_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if maintenance_window and not isinstance(maintenance_window, dict):
            raise TypeError("Expected argument 'maintenance_window' to be a dict")
        pulumi.set(__self__, "maintenance_window", maintenance_window)
        if maintenance_window_details and not isinstance(maintenance_window_details, dict):
            raise TypeError("Expected argument 'maintenance_window_details' to be a dict")
        pulumi.set(__self__, "maintenance_window_details", maintenance_window_details)
        if next_maintenance_run_id and not isinstance(next_maintenance_run_id, str):
            raise TypeError("Expected argument 'next_maintenance_run_id' to be a str")
        pulumi.set(__self__, "next_maintenance_run_id", next_maintenance_run_id)
        if patch_id and not isinstance(patch_id, str):
            raise TypeError("Expected argument 'patch_id' to be a str")
        pulumi.set(__self__, "patch_id", patch_id)
        if patch_model and not isinstance(patch_model, str):
            raise TypeError("Expected argument 'patch_model' to be a str")
        pulumi.set(__self__, "patch_model", patch_model)
        if peer_autonomous_container_database_backup_config and not isinstance(peer_autonomous_container_database_backup_config, dict):
            raise TypeError("Expected argument 'peer_autonomous_container_database_backup_config' to be a dict")
        pulumi.set(__self__, "peer_autonomous_container_database_backup_config", peer_autonomous_container_database_backup_config)
        if peer_autonomous_container_database_compartment_id and not isinstance(peer_autonomous_container_database_compartment_id, str):
            raise TypeError("Expected argument 'peer_autonomous_container_database_compartment_id' to be a str")
        pulumi.set(__self__, "peer_autonomous_container_database_compartment_id", peer_autonomous_container_database_compartment_id)
        if peer_autonomous_container_database_display_name and not isinstance(peer_autonomous_container_database_display_name, str):
            raise TypeError("Expected argument 'peer_autonomous_container_database_display_name' to be a str")
        pulumi.set(__self__, "peer_autonomous_container_database_display_name", peer_autonomous_container_database_display_name)
        if peer_autonomous_exadata_infrastructure_id and not isinstance(peer_autonomous_exadata_infrastructure_id, str):
            raise TypeError("Expected argument 'peer_autonomous_exadata_infrastructure_id' to be a str")
        pulumi.set(__self__, "peer_autonomous_exadata_infrastructure_id", peer_autonomous_exadata_infrastructure_id)
        if peer_autonomous_vm_cluster_id and not isinstance(peer_autonomous_vm_cluster_id, str):
            raise TypeError("Expected argument 'peer_autonomous_vm_cluster_id' to be a str")
        pulumi.set(__self__, "peer_autonomous_vm_cluster_id", peer_autonomous_vm_cluster_id)
        if peer_db_unique_name and not isinstance(peer_db_unique_name, str):
            raise TypeError("Expected argument 'peer_db_unique_name' to be a str")
        pulumi.set(__self__, "peer_db_unique_name", peer_db_unique_name)
        if protection_mode and not isinstance(protection_mode, str):
            raise TypeError("Expected argument 'protection_mode' to be a str")
        pulumi.set(__self__, "protection_mode", protection_mode)
        if role and not isinstance(role, str):
            raise TypeError("Expected argument 'role' to be a str")
        pulumi.set(__self__, "role", role)
        if rotate_key_trigger and not isinstance(rotate_key_trigger, bool):
            raise TypeError("Expected argument 'rotate_key_trigger' to be a bool")
        pulumi.set(__self__, "rotate_key_trigger", rotate_key_trigger)
        if service_level_agreement_type and not isinstance(service_level_agreement_type, str):
            raise TypeError("Expected argument 'service_level_agreement_type' to be a str")
        pulumi.set(__self__, "service_level_agreement_type", service_level_agreement_type)
        if standby_maintenance_buffer_in_days and not isinstance(standby_maintenance_buffer_in_days, int):
            raise TypeError("Expected argument 'standby_maintenance_buffer_in_days' to be a int")
        pulumi.set(__self__, "standby_maintenance_buffer_in_days", standby_maintenance_buffer_in_days)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if vault_id and not isinstance(vault_id, str):
            raise TypeError("Expected argument 'vault_id' to be a str")
        pulumi.set(__self__, "vault_id", vault_id)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> str:
        return pulumi.get(self, "autonomous_container_database_id")

    @property
    @pulumi.getter(name="autonomousExadataInfrastructureId")
    def autonomous_exadata_infrastructure_id(self) -> str:
        """
        The OCID of the Autonomous Exadata Infrastructure.
        """
        return pulumi.get(self, "autonomous_exadata_infrastructure_id")

    @property
    @pulumi.getter(name="autonomousVmClusterId")
    def autonomous_vm_cluster_id(self) -> str:
        """
        The OCID of the Autonomous VM Cluster.
        """
        return pulumi.get(self, "autonomous_vm_cluster_id")

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> str:
        """
        The availability domain of the Autonomous Container Database.
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="backupConfig")
    def backup_config(self) -> 'outputs.GetAutonomousContainerDatabaseBackupConfigResult':
        """
        Backup options for the Autonomous Container Database.
        """
        return pulumi.get(self, "backup_config")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="dbUniqueName")
    def db_unique_name(self) -> str:
        """
        The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
        """
        return pulumi.get(self, "db_unique_name")

    @property
    @pulumi.getter(name="dbVersion")
    def db_version(self) -> str:
        """
        Oracle Database version of the Autonomous Container Database.
        """
        return pulumi.get(self, "db_version")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The user-provided name for the Autonomous Container Database.
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
        The OCID of the Autonomous Container Database.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="infrastructureType")
    def infrastructure_type(self) -> str:
        """
        The infrastructure type this resource belongs to.
        """
        return pulumi.get(self, "infrastructure_type")

    @property
    @pulumi.getter(name="keyStoreId")
    def key_store_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        """
        return pulumi.get(self, "key_store_id")

    @property
    @pulumi.getter(name="keyStoreWalletName")
    def key_store_wallet_name(self) -> str:
        """
        The wallet name for Oracle Key Vault.
        """
        return pulumi.get(self, "key_store_wallet_name")

    @property
    @pulumi.getter(name="kmsKeyId")
    def kms_key_id(self) -> str:
        """
        The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        """
        return pulumi.get(self, "kms_key_id")

    @property
    @pulumi.getter(name="lastMaintenanceRunId")
    def last_maintenance_run_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        """
        return pulumi.get(self, "last_maintenance_run_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="maintenanceWindow")
    def maintenance_window(self) -> 'outputs.GetAutonomousContainerDatabaseMaintenanceWindowResult':
        """
        The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        """
        return pulumi.get(self, "maintenance_window")

    @property
    @pulumi.getter(name="maintenanceWindowDetails")
    def maintenance_window_details(self) -> 'outputs.GetAutonomousContainerDatabaseMaintenanceWindowDetailsResult':
        return pulumi.get(self, "maintenance_window_details")

    @property
    @pulumi.getter(name="nextMaintenanceRunId")
    def next_maintenance_run_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        """
        return pulumi.get(self, "next_maintenance_run_id")

    @property
    @pulumi.getter(name="patchId")
    def patch_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
        """
        return pulumi.get(self, "patch_id")

    @property
    @pulumi.getter(name="patchModel")
    def patch_model(self) -> str:
        """
        Database patch model preference.
        """
        return pulumi.get(self, "patch_model")

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseBackupConfig")
    def peer_autonomous_container_database_backup_config(self) -> 'outputs.GetAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigResult':
        return pulumi.get(self, "peer_autonomous_container_database_backup_config")

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseCompartmentId")
    def peer_autonomous_container_database_compartment_id(self) -> str:
        return pulumi.get(self, "peer_autonomous_container_database_compartment_id")

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseDisplayName")
    def peer_autonomous_container_database_display_name(self) -> str:
        return pulumi.get(self, "peer_autonomous_container_database_display_name")

    @property
    @pulumi.getter(name="peerAutonomousExadataInfrastructureId")
    def peer_autonomous_exadata_infrastructure_id(self) -> str:
        return pulumi.get(self, "peer_autonomous_exadata_infrastructure_id")

    @property
    @pulumi.getter(name="peerAutonomousVmClusterId")
    def peer_autonomous_vm_cluster_id(self) -> str:
        return pulumi.get(self, "peer_autonomous_vm_cluster_id")

    @property
    @pulumi.getter(name="peerDbUniqueName")
    def peer_db_unique_name(self) -> str:
        return pulumi.get(self, "peer_db_unique_name")

    @property
    @pulumi.getter(name="protectionMode")
    def protection_mode(self) -> str:
        return pulumi.get(self, "protection_mode")

    @property
    @pulumi.getter
    def role(self) -> str:
        """
        The role of the dataguard enabled Autonomous Container Database.
        """
        return pulumi.get(self, "role")

    @property
    @pulumi.getter(name="rotateKeyTrigger")
    def rotate_key_trigger(self) -> bool:
        return pulumi.get(self, "rotate_key_trigger")

    @property
    @pulumi.getter(name="serviceLevelAgreementType")
    def service_level_agreement_type(self) -> str:
        """
        The service level agreement type of the container database. The default is STANDARD.
        """
        return pulumi.get(self, "service_level_agreement_type")

    @property
    @pulumi.getter(name="standbyMaintenanceBufferInDays")
    def standby_maintenance_buffer_in_days(self) -> int:
        """
        The scheduling detail for the quarterly maintenance window of the standby Autonomous Container Database. This value represents the number of days before scheduled maintenance of the primary database.
        """
        return pulumi.get(self, "standby_maintenance_buffer_in_days")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the Autonomous Container Database.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the Autonomous Container Database was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="vaultId")
    def vault_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        """
        return pulumi.get(self, "vault_id")


class AwaitableGetAutonomousContainerDatabaseResult(GetAutonomousContainerDatabaseResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAutonomousContainerDatabaseResult(
            autonomous_container_database_id=self.autonomous_container_database_id,
            autonomous_exadata_infrastructure_id=self.autonomous_exadata_infrastructure_id,
            autonomous_vm_cluster_id=self.autonomous_vm_cluster_id,
            availability_domain=self.availability_domain,
            backup_config=self.backup_config,
            compartment_id=self.compartment_id,
            db_unique_name=self.db_unique_name,
            db_version=self.db_version,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            infrastructure_type=self.infrastructure_type,
            key_store_id=self.key_store_id,
            key_store_wallet_name=self.key_store_wallet_name,
            kms_key_id=self.kms_key_id,
            last_maintenance_run_id=self.last_maintenance_run_id,
            lifecycle_details=self.lifecycle_details,
            maintenance_window=self.maintenance_window,
            maintenance_window_details=self.maintenance_window_details,
            next_maintenance_run_id=self.next_maintenance_run_id,
            patch_id=self.patch_id,
            patch_model=self.patch_model,
            peer_autonomous_container_database_backup_config=self.peer_autonomous_container_database_backup_config,
            peer_autonomous_container_database_compartment_id=self.peer_autonomous_container_database_compartment_id,
            peer_autonomous_container_database_display_name=self.peer_autonomous_container_database_display_name,
            peer_autonomous_exadata_infrastructure_id=self.peer_autonomous_exadata_infrastructure_id,
            peer_autonomous_vm_cluster_id=self.peer_autonomous_vm_cluster_id,
            peer_db_unique_name=self.peer_db_unique_name,
            protection_mode=self.protection_mode,
            role=self.role,
            rotate_key_trigger=self.rotate_key_trigger,
            service_level_agreement_type=self.service_level_agreement_type,
            standby_maintenance_buffer_in_days=self.standby_maintenance_buffer_in_days,
            state=self.state,
            time_created=self.time_created,
            vault_id=self.vault_id)


def get_autonomous_container_database(autonomous_container_database_id: Optional[str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAutonomousContainerDatabaseResult:
    """
    This data source provides details about a specific Autonomous Container Database resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified Autonomous Container Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_autonomous_container_database = oci.database.get_autonomous_container_database(autonomous_container_database_id=oci_database_autonomous_container_database["test_autonomous_container_database"]["id"])
    ```


    :param str autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['autonomousContainerDatabaseId'] = autonomous_container_database_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:database/getAutonomousContainerDatabase:getAutonomousContainerDatabase', __args__, opts=opts, typ=GetAutonomousContainerDatabaseResult).value

    return AwaitableGetAutonomousContainerDatabaseResult(
        autonomous_container_database_id=__ret__.autonomous_container_database_id,
        autonomous_exadata_infrastructure_id=__ret__.autonomous_exadata_infrastructure_id,
        autonomous_vm_cluster_id=__ret__.autonomous_vm_cluster_id,
        availability_domain=__ret__.availability_domain,
        backup_config=__ret__.backup_config,
        compartment_id=__ret__.compartment_id,
        db_unique_name=__ret__.db_unique_name,
        db_version=__ret__.db_version,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        infrastructure_type=__ret__.infrastructure_type,
        key_store_id=__ret__.key_store_id,
        key_store_wallet_name=__ret__.key_store_wallet_name,
        kms_key_id=__ret__.kms_key_id,
        last_maintenance_run_id=__ret__.last_maintenance_run_id,
        lifecycle_details=__ret__.lifecycle_details,
        maintenance_window=__ret__.maintenance_window,
        maintenance_window_details=__ret__.maintenance_window_details,
        next_maintenance_run_id=__ret__.next_maintenance_run_id,
        patch_id=__ret__.patch_id,
        patch_model=__ret__.patch_model,
        peer_autonomous_container_database_backup_config=__ret__.peer_autonomous_container_database_backup_config,
        peer_autonomous_container_database_compartment_id=__ret__.peer_autonomous_container_database_compartment_id,
        peer_autonomous_container_database_display_name=__ret__.peer_autonomous_container_database_display_name,
        peer_autonomous_exadata_infrastructure_id=__ret__.peer_autonomous_exadata_infrastructure_id,
        peer_autonomous_vm_cluster_id=__ret__.peer_autonomous_vm_cluster_id,
        peer_db_unique_name=__ret__.peer_db_unique_name,
        protection_mode=__ret__.protection_mode,
        role=__ret__.role,
        rotate_key_trigger=__ret__.rotate_key_trigger,
        service_level_agreement_type=__ret__.service_level_agreement_type,
        standby_maintenance_buffer_in_days=__ret__.standby_maintenance_buffer_in_days,
        state=__ret__.state,
        time_created=__ret__.time_created,
        vault_id=__ret__.vault_id)
