// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Migration resource in Oracle Cloud Infrastructure Database Migration service.
//
// Create a Migration resource that contains all the details to perform the
// database migration operation like source and destination database
// details, credentials, etc.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := oci.NewDatabaseMigrationMigration(ctx, "testMigration", &oci.DatabaseMigrationMigrationArgs{
// 			CompartmentId:              pulumi.Any(_var.Compartment_id),
// 			SourceDatabaseConnectionId: pulumi.Any(oci_database_migration_connection.Test_connection.Id),
// 			TargetDatabaseConnectionId: pulumi.Any(oci_database_migration_connection.Test_connection.Id),
// 			Type:                       pulumi.Any(_var.Migration_type),
// 			AgentId:                    pulumi.Any(oci_database_migration_agent.Test_agent.Id),
// 			DataTransferMediumDetails: &DatabaseMigrationMigrationDataTransferMediumDetailsArgs{
// 				DatabaseLinkDetails: &DatabaseMigrationMigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs{
// 					Name: pulumi.Any(_var.Migration_data_transfer_medium_details_database_link_details_name),
// 				},
// 				ObjectStorageDetails: &DatabaseMigrationMigrationDataTransferMediumDetailsObjectStorageDetailsArgs{
// 					Bucket:    pulumi.Any(_var.Migration_data_transfer_medium_details_object_storage_details_bucket),
// 					Namespace: pulumi.Any(_var.Migration_data_transfer_medium_details_object_storage_details_namespace),
// 				},
// 			},
// 			DatapumpSettings: &DatabaseMigrationMigrationDatapumpSettingsArgs{
// 				DataPumpParameters: &DatabaseMigrationMigrationDatapumpSettingsDataPumpParametersArgs{
// 					Estimate:                pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_estimate),
// 					ExcludeParameters:       pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_exclude_parameters),
// 					ExportParallelismDegree: pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_export_parallelism_degree),
// 					ImportParallelismDegree: pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_import_parallelism_degree),
// 					IsCluster:               pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_is_cluster),
// 					TableExistsAction:       pulumi.Any(_var.Migration_datapump_settings_data_pump_parameters_table_exists_action),
// 				},
// 				ExportDirectoryObject: &DatabaseMigrationMigrationDatapumpSettingsExportDirectoryObjectArgs{
// 					Name: pulumi.Any(_var.Migration_datapump_settings_export_directory_object_name),
// 					Path: pulumi.Any(_var.Migration_datapump_settings_export_directory_object_path),
// 				},
// 				ImportDirectoryObject: &DatabaseMigrationMigrationDatapumpSettingsImportDirectoryObjectArgs{
// 					Name: pulumi.Any(_var.Migration_datapump_settings_import_directory_object_name),
// 					Path: pulumi.Any(_var.Migration_datapump_settings_import_directory_object_path),
// 				},
// 				JobMode: pulumi.Any(_var.Migration_datapump_settings_job_mode),
// 				MetadataRemaps: DatabaseMigrationMigrationDatapumpSettingsMetadataRemapArray{
// 					&DatabaseMigrationMigrationDatapumpSettingsMetadataRemapArgs{
// 						NewValue: pulumi.Any(_var.Migration_datapump_settings_metadata_remaps_new_value),
// 						OldValue: pulumi.Any(_var.Migration_datapump_settings_metadata_remaps_old_value),
// 						Type:     pulumi.Any(_var.Migration_datapump_settings_metadata_remaps_type),
// 					},
// 				},
// 			},
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			DisplayName: pulumi.Any(_var.Migration_display_name),
// 			ExcludeObjects: DatabaseMigrationMigrationExcludeObjectArray{
// 				&DatabaseMigrationMigrationExcludeObjectArgs{
// 					Object: pulumi.Any(_var.Migration_exclude_objects_object),
// 					Owner:  pulumi.Any(_var.Migration_exclude_objects_owner),
// 				},
// 			},
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
// 			},
// 			GoldenGateDetails: &DatabaseMigrationMigrationGoldenGateDetailsArgs{
// 				Hub: &DatabaseMigrationMigrationGoldenGateDetailsHubArgs{
// 					RestAdminCredentials: &DatabaseMigrationMigrationGoldenGateDetailsHubRestAdminCredentialsArgs{
// 						Password: pulumi.Any(_var.Migration_golden_gate_details_hub_rest_admin_credentials_password),
// 						Username: pulumi.Any(_var.Migration_golden_gate_details_hub_rest_admin_credentials_username),
// 					},
// 					SourceDbAdminCredentials: &DatabaseMigrationMigrationGoldenGateDetailsHubSourceDbAdminCredentialsArgs{
// 						Password: pulumi.Any(_var.Migration_golden_gate_details_hub_source_db_admin_credentials_password),
// 						Username: pulumi.Any(_var.Migration_golden_gate_details_hub_source_db_admin_credentials_username),
// 					},
// 					SourceMicroservicesDeploymentName: pulumi.Any(oci_apigateway_deployment.Test_deployment.Name),
// 					TargetDbAdminCredentials: &DatabaseMigrationMigrationGoldenGateDetailsHubTargetDbAdminCredentialsArgs{
// 						Password: pulumi.Any(_var.Migration_golden_gate_details_hub_target_db_admin_credentials_password),
// 						Username: pulumi.Any(_var.Migration_golden_gate_details_hub_target_db_admin_credentials_username),
// 					},
// 					TargetMicroservicesDeploymentName: pulumi.Any(oci_apigateway_deployment.Test_deployment.Name),
// 					Url:                               pulumi.Any(_var.Migration_golden_gate_details_hub_url),
// 					ComputeId:                         pulumi.Any(oci_database_migration_compute.Test_compute.Id),
// 					SourceContainerDbAdminCredentials: &DatabaseMigrationMigrationGoldenGateDetailsHubSourceContainerDbAdminCredentialsArgs{
// 						Password: pulumi.Any(_var.Migration_golden_gate_details_hub_source_container_db_admin_credentials_password),
// 						Username: pulumi.Any(_var.Migration_golden_gate_details_hub_source_container_db_admin_credentials_username),
// 					},
// 				},
// 				Settings: &DatabaseMigrationMigrationGoldenGateDetailsSettingsArgs{
// 					AcceptableLag: pulumi.Any(_var.Migration_golden_gate_details_settings_acceptable_lag),
// 					Extract: &DatabaseMigrationMigrationGoldenGateDetailsSettingsExtractArgs{
// 						LongTransDuration:  pulumi.Any(_var.Migration_golden_gate_details_settings_extract_long_trans_duration),
// 						PerformanceProfile: pulumi.Any(_var.Migration_golden_gate_details_settings_extract_performance_profile),
// 					},
// 					Replicat: &DatabaseMigrationMigrationGoldenGateDetailsSettingsReplicatArgs{
// 						MapParallelism:      pulumi.Any(_var.Migration_golden_gate_details_settings_replicat_map_parallelism),
// 						MaxApplyParallelism: pulumi.Any(_var.Migration_golden_gate_details_settings_replicat_max_apply_parallelism),
// 						MinApplyParallelism: pulumi.Any(_var.Migration_golden_gate_details_settings_replicat_min_apply_parallelism),
// 					},
// 				},
// 			},
// 			SourceContainerDatabaseConnectionId: pulumi.Any(oci_database_migration_connection.Test_connection.Id),
// 			VaultDetails: &DatabaseMigrationMigrationVaultDetailsArgs{
// 				CompartmentId: pulumi.Any(_var.Compartment_id),
// 				KeyId:         pulumi.Any(oci_kms_key.Test_key.Id),
// 				VaultId:       pulumi.Any(oci_kms_vault.Test_vault.Id),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Migrations can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:index/databaseMigrationMigration:DatabaseMigrationMigration test_migration "id"
// ```
type DatabaseMigrationMigration struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
	AgentId pulumi.StringOutput `pulumi:"agentId"`
	// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
	CredentialsSecretId pulumi.StringOutput `pulumi:"credentialsSecretId"`
	// (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
	DataTransferMediumDetails DatabaseMigrationMigrationDataTransferMediumDetailsOutput `pulumi:"dataTransferMediumDetails"`
	// (Updatable) Optional settings for Datapump Export and Import jobs
	DatapumpSettings DatabaseMigrationMigrationDatapumpSettingsOutput `pulumi:"datapumpSettings"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Migration Display Name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Database objects to exclude from migration.
	ExcludeObjects DatabaseMigrationMigrationExcludeObjectArrayOutput `pulumi:"excludeObjects"`
	// OCID of the current ODMS Job in execution for the Migration, if any.
	ExecutingJobId pulumi.StringOutput `pulumi:"executingJobId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
	GoldenGateDetails DatabaseMigrationMigrationGoldenGateDetailsOutput `pulumi:"goldenGateDetails"`
	// Additional status related to the execution and current state of the Migration.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
	SourceContainerDatabaseConnectionId pulumi.StringOutput `pulumi:"sourceContainerDatabaseConnectionId"`
	// (Updatable) The OCID of the Source Database Connection.
	SourceDatabaseConnectionId pulumi.StringOutput `pulumi:"sourceDatabaseConnectionId"`
	// The current state of the Migration Resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// (Updatable) The OCID of the Target Database Connection.
	TargetDatabaseConnectionId pulumi.StringOutput `pulumi:"targetDatabaseConnectionId"`
	// The time the Migration was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time of last Migration. An RFC3339 formatted datetime string.
	TimeLastMigration pulumi.StringOutput `pulumi:"timeLastMigration"`
	// The time of the last Migration details update. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) Migration type.
	Type pulumi.StringOutput `pulumi:"type"`
	// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
	VaultDetails DatabaseMigrationMigrationVaultDetailsOutput `pulumi:"vaultDetails"`
	// Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
	WaitAfter pulumi.StringOutput `pulumi:"waitAfter"`
}

// NewDatabaseMigrationMigration registers a new resource with the given unique name, arguments, and options.
func NewDatabaseMigrationMigration(ctx *pulumi.Context,
	name string, args *DatabaseMigrationMigrationArgs, opts ...pulumi.ResourceOption) (*DatabaseMigrationMigration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SourceDatabaseConnectionId == nil {
		return nil, errors.New("invalid value for required argument 'SourceDatabaseConnectionId'")
	}
	if args.TargetDatabaseConnectionId == nil {
		return nil, errors.New("invalid value for required argument 'TargetDatabaseConnectionId'")
	}
	if args.Type == nil {
		return nil, errors.New("invalid value for required argument 'Type'")
	}
	var resource DatabaseMigrationMigration
	err := ctx.RegisterResource("oci:index/databaseMigrationMigration:DatabaseMigrationMigration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatabaseMigrationMigration gets an existing DatabaseMigrationMigration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatabaseMigrationMigration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatabaseMigrationMigrationState, opts ...pulumi.ResourceOption) (*DatabaseMigrationMigration, error) {
	var resource DatabaseMigrationMigration
	err := ctx.ReadResource("oci:index/databaseMigrationMigration:DatabaseMigrationMigration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatabaseMigrationMigration resources.
type databaseMigrationMigrationState struct {
	// (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
	AgentId *string `pulumi:"agentId"`
	// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
	CompartmentId *string `pulumi:"compartmentId"`
	// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
	CredentialsSecretId *string `pulumi:"credentialsSecretId"`
	// (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
	DataTransferMediumDetails *DatabaseMigrationMigrationDataTransferMediumDetails `pulumi:"dataTransferMediumDetails"`
	// (Updatable) Optional settings for Datapump Export and Import jobs
	DatapumpSettings *DatabaseMigrationMigrationDatapumpSettings `pulumi:"datapumpSettings"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Migration Display Name
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Database objects to exclude from migration.
	ExcludeObjects []DatabaseMigrationMigrationExcludeObject `pulumi:"excludeObjects"`
	// OCID of the current ODMS Job in execution for the Migration, if any.
	ExecutingJobId *string `pulumi:"executingJobId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
	GoldenGateDetails *DatabaseMigrationMigrationGoldenGateDetails `pulumi:"goldenGateDetails"`
	// Additional status related to the execution and current state of the Migration.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
	SourceContainerDatabaseConnectionId *string `pulumi:"sourceContainerDatabaseConnectionId"`
	// (Updatable) The OCID of the Source Database Connection.
	SourceDatabaseConnectionId *string `pulumi:"sourceDatabaseConnectionId"`
	// The current state of the Migration Resource.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// (Updatable) The OCID of the Target Database Connection.
	TargetDatabaseConnectionId *string `pulumi:"targetDatabaseConnectionId"`
	// The time the Migration was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time of last Migration. An RFC3339 formatted datetime string.
	TimeLastMigration *string `pulumi:"timeLastMigration"`
	// The time of the last Migration details update. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) Migration type.
	Type *string `pulumi:"type"`
	// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
	VaultDetails *DatabaseMigrationMigrationVaultDetails `pulumi:"vaultDetails"`
	// Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
	WaitAfter *string `pulumi:"waitAfter"`
}

type DatabaseMigrationMigrationState struct {
	// (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
	AgentId pulumi.StringPtrInput
	// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
	CompartmentId pulumi.StringPtrInput
	// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
	CredentialsSecretId pulumi.StringPtrInput
	// (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
	DataTransferMediumDetails DatabaseMigrationMigrationDataTransferMediumDetailsPtrInput
	// (Updatable) Optional settings for Datapump Export and Import jobs
	DatapumpSettings DatabaseMigrationMigrationDatapumpSettingsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Migration Display Name
	DisplayName pulumi.StringPtrInput
	// (Updatable) Database objects to exclude from migration.
	ExcludeObjects DatabaseMigrationMigrationExcludeObjectArrayInput
	// OCID of the current ODMS Job in execution for the Migration, if any.
	ExecutingJobId pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
	GoldenGateDetails DatabaseMigrationMigrationGoldenGateDetailsPtrInput
	// Additional status related to the execution and current state of the Migration.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
	SourceContainerDatabaseConnectionId pulumi.StringPtrInput
	// (Updatable) The OCID of the Source Database Connection.
	SourceDatabaseConnectionId pulumi.StringPtrInput
	// The current state of the Migration Resource.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// (Updatable) The OCID of the Target Database Connection.
	TargetDatabaseConnectionId pulumi.StringPtrInput
	// The time the Migration was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time of last Migration. An RFC3339 formatted datetime string.
	TimeLastMigration pulumi.StringPtrInput
	// The time of the last Migration details update. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) Migration type.
	Type pulumi.StringPtrInput
	// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
	VaultDetails DatabaseMigrationMigrationVaultDetailsPtrInput
	// Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
	WaitAfter pulumi.StringPtrInput
}

func (DatabaseMigrationMigrationState) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseMigrationMigrationState)(nil)).Elem()
}

type databaseMigrationMigrationArgs struct {
	// (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
	AgentId *string `pulumi:"agentId"`
	// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
	DataTransferMediumDetails *DatabaseMigrationMigrationDataTransferMediumDetails `pulumi:"dataTransferMediumDetails"`
	// (Updatable) Optional settings for Datapump Export and Import jobs
	DatapumpSettings *DatabaseMigrationMigrationDatapumpSettings `pulumi:"datapumpSettings"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Migration Display Name
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Database objects to exclude from migration.
	ExcludeObjects []DatabaseMigrationMigrationExcludeObject `pulumi:"excludeObjects"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
	GoldenGateDetails *DatabaseMigrationMigrationGoldenGateDetails `pulumi:"goldenGateDetails"`
	// (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
	SourceContainerDatabaseConnectionId *string `pulumi:"sourceContainerDatabaseConnectionId"`
	// (Updatable) The OCID of the Source Database Connection.
	SourceDatabaseConnectionId string `pulumi:"sourceDatabaseConnectionId"`
	// (Updatable) The OCID of the Target Database Connection.
	TargetDatabaseConnectionId string `pulumi:"targetDatabaseConnectionId"`
	// (Updatable) Migration type.
	Type string `pulumi:"type"`
	// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
	VaultDetails *DatabaseMigrationMigrationVaultDetails `pulumi:"vaultDetails"`
}

// The set of arguments for constructing a DatabaseMigrationMigration resource.
type DatabaseMigrationMigrationArgs struct {
	// (Updatable) The OCID of the registered ODMS Agent. Required for OFFLINE Migrations.
	AgentId pulumi.StringPtrInput
	// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
	CompartmentId pulumi.StringInput
	// (Updatable) Data Transfer Medium details for the Migration. If not specified, it will default to Database Link. Only one type of medium details can be specified.
	DataTransferMediumDetails DatabaseMigrationMigrationDataTransferMediumDetailsPtrInput
	// (Updatable) Optional settings for Datapump Export and Import jobs
	DatapumpSettings DatabaseMigrationMigrationDatapumpSettingsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Migration Display Name
	DisplayName pulumi.StringPtrInput
	// (Updatable) Database objects to exclude from migration.
	ExcludeObjects DatabaseMigrationMigrationExcludeObjectArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
	GoldenGateDetails DatabaseMigrationMigrationGoldenGateDetailsPtrInput
	// (Updatable) The OCID of the Source Container Database Connection. Only used for ONLINE migrations. Only Connections of type Non-Autonomous can be used as source container databases.
	SourceContainerDatabaseConnectionId pulumi.StringPtrInput
	// (Updatable) The OCID of the Source Database Connection.
	SourceDatabaseConnectionId pulumi.StringInput
	// (Updatable) The OCID of the Target Database Connection.
	TargetDatabaseConnectionId pulumi.StringInput
	// (Updatable) Migration type.
	Type pulumi.StringInput
	// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
	VaultDetails DatabaseMigrationMigrationVaultDetailsPtrInput
}

func (DatabaseMigrationMigrationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseMigrationMigrationArgs)(nil)).Elem()
}

type DatabaseMigrationMigrationInput interface {
	pulumi.Input

	ToDatabaseMigrationMigrationOutput() DatabaseMigrationMigrationOutput
	ToDatabaseMigrationMigrationOutputWithContext(ctx context.Context) DatabaseMigrationMigrationOutput
}

func (*DatabaseMigrationMigration) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseMigrationMigration)(nil))
}

func (i *DatabaseMigrationMigration) ToDatabaseMigrationMigrationOutput() DatabaseMigrationMigrationOutput {
	return i.ToDatabaseMigrationMigrationOutputWithContext(context.Background())
}

func (i *DatabaseMigrationMigration) ToDatabaseMigrationMigrationOutputWithContext(ctx context.Context) DatabaseMigrationMigrationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationMigrationOutput)
}

func (i *DatabaseMigrationMigration) ToDatabaseMigrationMigrationPtrOutput() DatabaseMigrationMigrationPtrOutput {
	return i.ToDatabaseMigrationMigrationPtrOutputWithContext(context.Background())
}

func (i *DatabaseMigrationMigration) ToDatabaseMigrationMigrationPtrOutputWithContext(ctx context.Context) DatabaseMigrationMigrationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationMigrationPtrOutput)
}

type DatabaseMigrationMigrationPtrInput interface {
	pulumi.Input

	ToDatabaseMigrationMigrationPtrOutput() DatabaseMigrationMigrationPtrOutput
	ToDatabaseMigrationMigrationPtrOutputWithContext(ctx context.Context) DatabaseMigrationMigrationPtrOutput
}

type databaseMigrationMigrationPtrType DatabaseMigrationMigrationArgs

func (*databaseMigrationMigrationPtrType) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseMigrationMigration)(nil))
}

func (i *databaseMigrationMigrationPtrType) ToDatabaseMigrationMigrationPtrOutput() DatabaseMigrationMigrationPtrOutput {
	return i.ToDatabaseMigrationMigrationPtrOutputWithContext(context.Background())
}

func (i *databaseMigrationMigrationPtrType) ToDatabaseMigrationMigrationPtrOutputWithContext(ctx context.Context) DatabaseMigrationMigrationPtrOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationMigrationPtrOutput)
}

// DatabaseMigrationMigrationArrayInput is an input type that accepts DatabaseMigrationMigrationArray and DatabaseMigrationMigrationArrayOutput values.
// You can construct a concrete instance of `DatabaseMigrationMigrationArrayInput` via:
//
//          DatabaseMigrationMigrationArray{ DatabaseMigrationMigrationArgs{...} }
type DatabaseMigrationMigrationArrayInput interface {
	pulumi.Input

	ToDatabaseMigrationMigrationArrayOutput() DatabaseMigrationMigrationArrayOutput
	ToDatabaseMigrationMigrationArrayOutputWithContext(context.Context) DatabaseMigrationMigrationArrayOutput
}

type DatabaseMigrationMigrationArray []DatabaseMigrationMigrationInput

func (DatabaseMigrationMigrationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabaseMigrationMigration)(nil)).Elem()
}

func (i DatabaseMigrationMigrationArray) ToDatabaseMigrationMigrationArrayOutput() DatabaseMigrationMigrationArrayOutput {
	return i.ToDatabaseMigrationMigrationArrayOutputWithContext(context.Background())
}

func (i DatabaseMigrationMigrationArray) ToDatabaseMigrationMigrationArrayOutputWithContext(ctx context.Context) DatabaseMigrationMigrationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationMigrationArrayOutput)
}

// DatabaseMigrationMigrationMapInput is an input type that accepts DatabaseMigrationMigrationMap and DatabaseMigrationMigrationMapOutput values.
// You can construct a concrete instance of `DatabaseMigrationMigrationMapInput` via:
//
//          DatabaseMigrationMigrationMap{ "key": DatabaseMigrationMigrationArgs{...} }
type DatabaseMigrationMigrationMapInput interface {
	pulumi.Input

	ToDatabaseMigrationMigrationMapOutput() DatabaseMigrationMigrationMapOutput
	ToDatabaseMigrationMigrationMapOutputWithContext(context.Context) DatabaseMigrationMigrationMapOutput
}

type DatabaseMigrationMigrationMap map[string]DatabaseMigrationMigrationInput

func (DatabaseMigrationMigrationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabaseMigrationMigration)(nil)).Elem()
}

func (i DatabaseMigrationMigrationMap) ToDatabaseMigrationMigrationMapOutput() DatabaseMigrationMigrationMapOutput {
	return i.ToDatabaseMigrationMigrationMapOutputWithContext(context.Background())
}

func (i DatabaseMigrationMigrationMap) ToDatabaseMigrationMigrationMapOutputWithContext(ctx context.Context) DatabaseMigrationMigrationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseMigrationMigrationMapOutput)
}

type DatabaseMigrationMigrationOutput struct {
	*pulumi.OutputState
}

func (DatabaseMigrationMigrationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*DatabaseMigrationMigration)(nil))
}

func (o DatabaseMigrationMigrationOutput) ToDatabaseMigrationMigrationOutput() DatabaseMigrationMigrationOutput {
	return o
}

func (o DatabaseMigrationMigrationOutput) ToDatabaseMigrationMigrationOutputWithContext(ctx context.Context) DatabaseMigrationMigrationOutput {
	return o
}

func (o DatabaseMigrationMigrationOutput) ToDatabaseMigrationMigrationPtrOutput() DatabaseMigrationMigrationPtrOutput {
	return o.ToDatabaseMigrationMigrationPtrOutputWithContext(context.Background())
}

func (o DatabaseMigrationMigrationOutput) ToDatabaseMigrationMigrationPtrOutputWithContext(ctx context.Context) DatabaseMigrationMigrationPtrOutput {
	return o.ApplyT(func(v DatabaseMigrationMigration) *DatabaseMigrationMigration {
		return &v
	}).(DatabaseMigrationMigrationPtrOutput)
}

type DatabaseMigrationMigrationPtrOutput struct {
	*pulumi.OutputState
}

func (DatabaseMigrationMigrationPtrOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseMigrationMigration)(nil))
}

func (o DatabaseMigrationMigrationPtrOutput) ToDatabaseMigrationMigrationPtrOutput() DatabaseMigrationMigrationPtrOutput {
	return o
}

func (o DatabaseMigrationMigrationPtrOutput) ToDatabaseMigrationMigrationPtrOutputWithContext(ctx context.Context) DatabaseMigrationMigrationPtrOutput {
	return o
}

type DatabaseMigrationMigrationArrayOutput struct{ *pulumi.OutputState }

func (DatabaseMigrationMigrationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]DatabaseMigrationMigration)(nil))
}

func (o DatabaseMigrationMigrationArrayOutput) ToDatabaseMigrationMigrationArrayOutput() DatabaseMigrationMigrationArrayOutput {
	return o
}

func (o DatabaseMigrationMigrationArrayOutput) ToDatabaseMigrationMigrationArrayOutputWithContext(ctx context.Context) DatabaseMigrationMigrationArrayOutput {
	return o
}

func (o DatabaseMigrationMigrationArrayOutput) Index(i pulumi.IntInput) DatabaseMigrationMigrationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) DatabaseMigrationMigration {
		return vs[0].([]DatabaseMigrationMigration)[vs[1].(int)]
	}).(DatabaseMigrationMigrationOutput)
}

type DatabaseMigrationMigrationMapOutput struct{ *pulumi.OutputState }

func (DatabaseMigrationMigrationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]DatabaseMigrationMigration)(nil))
}

func (o DatabaseMigrationMigrationMapOutput) ToDatabaseMigrationMigrationMapOutput() DatabaseMigrationMigrationMapOutput {
	return o
}

func (o DatabaseMigrationMigrationMapOutput) ToDatabaseMigrationMigrationMapOutputWithContext(ctx context.Context) DatabaseMigrationMigrationMapOutput {
	return o
}

func (o DatabaseMigrationMigrationMapOutput) MapIndex(k pulumi.StringInput) DatabaseMigrationMigrationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) DatabaseMigrationMigration {
		return vs[0].(map[string]DatabaseMigrationMigration)[vs[1].(string)]
	}).(DatabaseMigrationMigrationOutput)
}

func init() {
	pulumi.RegisterOutputType(DatabaseMigrationMigrationOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationMigrationPtrOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationMigrationArrayOutput{})
	pulumi.RegisterOutputType(DatabaseMigrationMigrationMapOutput{})
}