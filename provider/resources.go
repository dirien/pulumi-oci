// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"fmt"
	"path/filepath"
	"unicode"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/pulumi/pulumi-oci/provider/pkg/version"
	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge"
	shim "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim"
	shimv1 "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim/sdk-v1"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
	oci "github.com/terraform-providers/terraform-provider-oci/oci"
)

// all of the OCI token components used below.
const (
	// packages:
	ociPkg = "oci"
	// modules:
	ociMod                     = "index"                   // the root module
	aiAnomalyDetectionMod      = "AiAnomalyDetection"      // Ai Anomaly Detection
	analyticsMod               = "Analytics"               // Analytics
	apiGatewayMod              = "ApiGateway"              // API Gateway
	apmSyntheticsMod           = "ApmSynthetics"           // Apm Synthetics
	apmMod                     = "Apm"                     // Application Performance Monitoring
	artifactsMod               = "Artifacts"               // Artifacts
	auditMod                   = "Audit"                   // Audit
	autoscalingMod             = "Autoscaling"             // Auto Scaling
	bastionMod                 = "Bastion"                 // Bastion
	bdsMod                     = "Bds"                     // Big Data Service
	blockchainMod              = "Blockchain"              // Blockchain
	budgetMod                  = "Budget"                  // Budget
	cloudGuardMod              = "CloudGuard"              // Cloud Guard
	computeInstanceAgentMod    = "ComputeInstanceAgent"    // Compute Instance Agent
	containerEngineMod         = "ContainerEngine"         // Container Engine
	oceMod                     = "Oce"                     // Content and Experience
	coreMod                    = "Core"                    // Core
	dataCatalogMod             = "DataCatalog"             // Data Catalog
	dataFlowMod                = "DataFlow"                // Data Flow
	dataIntegrationMod         = "DataIntegration"         // Data Integration
	dataSafeMod                = "DataSafe"                // Data Safe
	dataScienceMod             = "DataScience"             // Data Science
	databaseMod                = "Database"                // Database
	databaseManagementMod      = "DatabaseManagement"      // Database Management
	databaseMigrationMod       = "DatabaseMigration"       // Database Migration
	devopsMod                  = "Devops"                  // Devops
	odaMod                     = "Oda"                     // Digital Assistant
	dnsMod                     = "Dns"                     // DNS
	emailMod                   = "Email"                   // Email
	eventsMod                  = "Events"                  // Events
	fileStorageMod             = "FileStorage"             // File Storage
	functionsMod               = "Functions"               // Functions
	genericArtifactsContentMod = "GenericArtifactsContent" // Generic Artifacts Content
	goldenGateMod              = "GoldenGate"              // Golden Gate
	healthChecksMod            = "HealthChecks"            // Health Checks
	identityMod                = "Identity"                // Identity
	integrationMod             = "Integration"             // Integration
	jmsMod                     = "Jms"                     // Jms
	kmsMod                     = "Kms"                     // Kms
	limitsMod                  = "Limits"                  // Limits
	loadBalancerMod            = "LoadBalancer"            // Load Balancer
	logAnalyticsMod            = "LogAnalytics"            // Log Analytics
	loggingMod                 = "Logging"                 // Logging
	managementAgentMod         = "ManagementAgent"         // Management Agent
	managementDashboardMod     = "ManagementDashboard"     // Management Dashboard
	marketplaceMod             = "Marketplace"             // Marketplace
	meteringComputationMod     = "MeteringComputation"     // Metering Computation
	monitoringMod              = "Monitoring"              // Monitoring
	mysqlMod                   = "Mysql"                   // MySQL Database
	networkLoadBalancerMod     = "NetworkLoadBalancer"     // Network Load Balancer
	nosqlMod                   = "Nosql"                   // NoSQL Database
	onsMod                     = "Ons"                     // Notifications
	objectStorageMod           = "ObjectStorage"           // Object Storage
	opsiMod                    = "Opsi"                    // Opsi
	optimizerMod               = "Optimizer"               // Optimizer
	ocvpMod                    = "Ocvp"                    // Oracle Cloud VMware Solution
	osManagementMod            = "OsManagement"            // OS Management
	resourceManagerMod         = "ResourceManager"         // Resource Manager
	serviceCatalogMod          = "ServiceCatalog"          // Service Catalog
	schMod                     = "Sch"                     // Service Connector Hub
	streamingMod               = "Streaming"               // Streaming
	vaultMod                   = "Vault"                   // Vault
	vulnerabilityScanningMod   = "VulnerabilityScanning"   // Vulnerability Scanning
	waasMod                    = "Waas"                    // Web Application Acceleration and Security
)

var namespaceMap = map[string]string{
	"oci": "Oci",
}

// makeMember manufactures a type token for the package and the given module and type.
func makeMember(mod string, mem string) tokens.ModuleMember {
	return tokens.ModuleMember(ociPkg + ":" + mod + ":" + mem)
}

// makeType manufactures a type token for the package and the given module and type.
func makeType(mod string, typ string) tokens.Type {
	return tokens.Type(makeMember(mod, typ))
}

// makeDataSource manufactures a standard resource token given a module and resource name.  It
// automatically uses the main package and names the file by simply lower casing the data source's
// first character.
func makeDataSource(mod string, res string) tokens.ModuleMember {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return makeMember(mod+"/"+fn, res)
}

// makeResource manufactures a standard resource token given a module and resource name.  It
// automatically uses the main package and names the file by simply lower casing the resource's
// first character.
func makeResource(mod string, res string) tokens.Type {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return makeType(mod+"/"+fn, res)
}

// boolRef returns a reference to the bool argument.
func boolRef(b bool) *bool {
	return &b
}

// stringValue gets a string value from a property map if present, else ""
func stringValue(vars resource.PropertyMap, prop resource.PropertyKey) string {
	val, ok := vars[prop]
	if ok && val.IsString() {
		return val.StringValue()
	}
	return ""
}

// preConfigureCallback is called before the providerConfigure function of the underlying provider.
// It should validate that the provider can be configured, and provide actionable errors in the case
// it cannot be. Configuration variables can be read from `vars` using the `stringValue` function -
// for example `stringValue(vars, "accessKey")`.
func preConfigureCallback(vars resource.PropertyMap, c shim.ResourceConfig) error {
	return nil
}

// managedByPulumi is a default used for some managed resources, in the absence of something more meaningful.
var managedByPulumi = &tfbridge.DefaultInfo{Value: "Managed by Pulumi"}

// Provider returns additional overlaid schema and metadata associated with the provider..
func Provider() tfbridge.ProviderInfo {
	// Instantiate the Terraform provider
	p := shimv1.NewProvider(oci.Provider().(*schema.Provider))

	// Create a Pulumi provider mapping
	prov := tfbridge.ProviderInfo{
		P:                    p,
		Name:                 "oci",
		Description:          "A Pulumi package for creating and managing Oracle Cloud Infrastructure (OCI) cloud resources.",
		Keywords:             []string{"pulumi", "oci"},
		License:              "Apache-2.0",
		Homepage:             "https://pulumi.io",
		Repository:           "https://github.com/pulumi/pulumi-oci",
		Config:               map[string]*tfbridge.SchemaInfo{},
		PreConfigureCallback: preConfigureCallback,
		Resources: map[string]*tfbridge.ResourceInfo{
			// Ai Anomaly Detection
			"oci_ai_anomaly_detection_ai_private_endpoint": {Tok: makeResource(aiAnomalyDetectionMod, "AiPrivateEndpoint")},
			"oci_ai_anomaly_detection_data_asset":          {Tok: makeResource(aiAnomalyDetectionMod, "DataAsset")},
			"oci_ai_anomaly_detection_model":               {Tok: makeResource(aiAnomalyDetectionMod, "Model")},
			"oci_ai_anomaly_detection_project":             {Tok: makeResource(aiAnomalyDetectionMod, "Project")},
			// Analytics
			"oci_analytics_analytics_instance":                        {Tok: makeResource(analyticsMod, "AnalyticsInstance")},
			"oci_analytics_analytics_instance_private_access_channel": {Tok: makeResource(analyticsMod, "AnalyticsInstancePrivateAccessChannel")},
			"oci_analytics_analytics_instance_vanity_url":             {Tok: makeResource(analyticsMod, "AnalyticsInstanceVanityUrl")},
			// API Gateway
			"oci_apigateway_api":         {Tok: makeResource(apiGatewayMod, "Api")},
			"oci_apigateway_certificate": {Tok: makeResource(apiGatewayMod, "Certificate")},
			"oci_apigateway_deployment":  {Tok: makeResource(apiGatewayMod, "Deployment")},
			"oci_apigateway_gateway":     {Tok: makeResource(apiGatewayMod, "Gateway")},
			// Apm Synthetics
			"oci_apm_synthetics_monitor": {Tok: makeResource(apmSyntheticsMod, "Monitor")},
			"oci_apm_synthetics_script":  {Tok: makeResource(apmSyntheticsMod, "Script")},
			// APM
			"oci_apm_apm_domain": {Tok: makeResource(apmMod, "ApmDomain")},
			// Artifacts
			"oci_artifacts_container_configuration":   {Tok: makeResource(artifactsMod, "ContainerConfiguration")},
			"oci_artifacts_container_image_signature": {Tok: makeResource(artifactsMod, "ContainerImageSignature")},
			"oci_artifacts_container_repository":      {Tok: makeResource(artifactsMod, "ContainerRepository")},
			"oci_artifacts_generic_artifact":          {Tok: makeResource(artifactsMod, "GenericArtifact")},
			"oci_artifacts_repository":                {Tok: makeResource(artifactsMod, "Repository")},
			// Audit
			"oci_audit_configuration": {Tok: makeResource(auditMod, "Configuration")},
			// AutoScaling
			"oci_autoscaling_auto_scaling_configuration": {Tok: makeResource(autoscalingMod, "AutoScalingConfiguration")},
			// Bastion
			"oci_bastion_bastion": {Tok: makeResource(bastionMod, "Bastion")},
			"oci_bastion_session": {Tok: makeResource(bastionMod, "Session")},
			// BDS
			"oci_bds_auto_scaling_configuration": {Tok: makeResource(bdsMod, "AutoScalingConfiguration")},
			"oci_bds_bds_instance":               {Tok: makeResource(bdsMod, "BdsInstance")},
			// Blockchain
			"oci_blockchain_blockchain_platform": {Tok: makeResource(blockchainMod, "BlockchainPlatform")},
			"oci_blockchain_osn":                 {Tok: makeResource(blockchainMod, "Osn")},
			"oci_blockchain_peer":                {Tok: makeResource(blockchainMod, "Peer")},
			// Budget
			"oci_budget_alert_rule": {Tok: makeResource(budgetMod, "AlertRule")},
			"oci_budget_budget":     {Tok: makeResource(budgetMod, "Budget")},
			// Cloud Guard
			"oci_cloud_guard_cloud_guard_configuration": {Tok: makeResource(cloudGuardMod, "CloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":            {Tok: makeResource(cloudGuardMod, "DataMaskRule")},
			"oci_cloud_guard_detector_recipe":           {Tok: makeResource(cloudGuardMod, "DetectorRecipe")},
			"oci_cloud_guard_managed_list":              {Tok: makeResource(cloudGuardMod, "ManagedList")},
			"oci_cloud_guard_responder_recipe":          {Tok: makeResource(cloudGuardMod, "ResponderRecipe")},
			"oci_cloud_guard_target":                    {Tok: makeResource(cloudGuardMod, "Target")},
			// Compute Instance Agent
			// Container Engine
			"oci_containerengine_cluster":   {Tok: makeResource(containerEngineMod, "Cluster")},
			"oci_containerengine_node_pool": {Tok: makeResource(containerEngineMod, "NodePool")},
			// OCE
			"oci_oce_oce_instance": {Tok: makeResource(oceMod, "OceInstance")},
			// Core
			"oci_core_app_catalog_listing_resource_version_agreement": {Tok: makeResource(coreMod, "AppCatalogListingResourceVersionAgreement")},
			"oci_core_app_catalog_subscription":                       {Tok: makeResource(coreMod, "AppCatalogSubscription")},
			"oci_core_boot_volume":                                    {Tok: makeResource(coreMod, "BootVolume")},
			"oci_core_boot_volume_backup":                             {Tok: makeResource(coreMod, "BootVolumeBackup")},
			"oci_core_cluster_network":                                {Tok: makeResource(coreMod, "ClusterNetwork")},
			"oci_core_compute_capacity_reservation":                   {Tok: makeResource(coreMod, "ComputeCapacityReservation")},
			"oci_core_compute_image_capability_schema":                {Tok: makeResource(coreMod, "ComputeImageCapabilitySchema")},
			"oci_core_console_history":                                {Tok: makeResource(coreMod, "ConsoleHistory")},
			"oci_core_cpe":                                            {Tok: makeResource(coreMod, "Cpe")},
			"oci_core_cross_connect":                                  {Tok: makeResource(coreMod, "CrossConnect")},
			"oci_core_cross_connect_group":                            {Tok: makeResource(coreMod, "CrossConnectGroup")},
			"oci_core_dedicated_vm_host":                              {Tok: makeResource(coreMod, "DedicatedVmHost")},
			"oci_core_dhcp_options":                                   {Tok: makeResource(coreMod, "DhcpOptions")},
			"oci_core_drg":                                            {Tok: makeResource(coreMod, "Drg")},
			"oci_core_drg_attachment":                                 {Tok: makeResource(coreMod, "DrgAttachment")},
			"oci_core_drg_attachment_management":                      {Tok: makeResource(coreMod, "DrgAttachmentManagement")},
			"oci_core_drg_attachments_list":                           {Tok: makeResource(coreMod, "DrgAttachmentsList")},
			"oci_core_drg_route_distribution":                         {Tok: makeResource(coreMod, "DrgRouteDistribution")},
			"oci_core_drg_route_distribution_statement":               {Tok: makeResource(coreMod, "DrgRouteDistributionStatement")},
			"oci_core_drg_route_table":                                {Tok: makeResource(coreMod, "DrgRouteTable")},
			"oci_core_drg_route_table_route_rule":                     {Tok: makeResource(coreMod, "DrgRouteTableRouteRule")},
			"oci_core_image":                                          {Tok: makeResource(coreMod, "Image")},
			"oci_core_instance":                                       {Tok: makeResource(coreMod, "Instance")},
			"oci_core_instance_configuration":                         {Tok: makeResource(coreMod, "InstanceConfiguration")},
			"oci_core_instance_console_connection":                    {Tok: makeResource(coreMod, "InstanceConsoleConnection")},
			"oci_core_instance_pool":                                  {Tok: makeResource(coreMod, "InstancePool")},
			"oci_core_instance_pool_instance":                         {Tok: makeResource(coreMod, "InstancePoolInstance")},
			"oci_core_internet_gateway":                               {Tok: makeResource(coreMod, "InternetGateway")},
			"oci_core_ipsec":                                          {Tok: makeResource(coreMod, "Ipsec")},
			"oci_core_ipsec_connection_tunnel_management":             {Tok: makeResource(coreMod, "IpsecConnectionTunnelManagement")},
			"oci_core_ipv6":                                           {Tok: makeResource(coreMod, "Ipv6")},
			"oci_core_local_peering_gateway":                          {Tok: makeResource(coreMod, "LocalPeeringGateway")},
			"oci_core_nat_gateway":                                    {Tok: makeResource(coreMod, "NatGateway")},
			"oci_core_network_security_group":                         {Tok: makeResource(coreMod, "NetworkSecurityGroup")},
			"oci_core_network_security_group_security_rule":           {Tok: makeResource(coreMod, "NetworkSecurityGroupSecurityRule")},
			"oci_core_private_ip":                                     {Tok: makeResource(coreMod, "PrivateIp")},
			"oci_core_public_ip":                                      {Tok: makeResource(coreMod, "PublicIp")},
			"oci_core_public_ip_pool":                                 {Tok: makeResource(coreMod, "PublicIpPool")},
			"oci_core_public_ip_pool_capacity":                        {Tok: makeResource(coreMod, "PublicIpPoolCapacity")},
			"oci_core_remote_peering_connection":                      {Tok: makeResource(coreMod, "RemotePeeringConnection")},
			"oci_core_route_table":                                    {Tok: makeResource(coreMod, "RouteTable")},
			"oci_core_route_table_attachment":                         {Tok: makeResource(coreMod, "RouteTableAttachment")},
			"oci_core_security_list":                                  {Tok: makeResource(coreMod, "SecurityList")},
			"oci_core_service_gateway":                                {Tok: makeResource(coreMod, "ServiceGateway")},
			"oci_core_subnet":                                         {Tok: makeResource(coreMod, "Subnet")},
			"oci_core_vcn":                                            {Tok: makeResource(coreMod, "Vcn")},
			"oci_core_virtual_circuit":                                {Tok: makeResource(coreMod, "VirtualCircuit")},
			"oci_core_vlan":                                           {Tok: makeResource(coreMod, "Vlan")},
			"oci_core_vnic_attachment":                                {Tok: makeResource(coreMod, "VnicAttachment")},
			"oci_core_volume":                                         {Tok: makeResource(coreMod, "Volume")},
			"oci_core_volume_attachment":                              {Tok: makeResource(coreMod, "VolumeAttachment")},
			"oci_core_volume_backup":                                  {Tok: makeResource(coreMod, "VolumeBackup")},
			"oci_core_volume_backup_policy":                           {Tok: makeResource(coreMod, "VolumeBackupPolicy")},
			"oci_core_volume_backup_policy_assignment":                {Tok: makeResource(coreMod, "VolumeBackupPolicyAssignment")},
			"oci_core_volume_group":                                   {Tok: makeResource(coreMod, "VolumeGroup")},
			"oci_core_volume_group_backup":                            {Tok: makeResource(coreMod, "VolumeGroupBackup")},
			// Data Catalog
			"oci_datacatalog_catalog":                  {Tok: makeResource(dataCatalogMod, "Catalog")},
			"oci_datacatalog_catalog_private_endpoint": {Tok: makeResource(dataCatalogMod, "CatalogPrivateEndpoint")},
			"oci_datacatalog_connection":               {Tok: makeResource(dataCatalogMod, "Connection")},
			"oci_datacatalog_data_asset":               {Tok: makeResource(dataCatalogMod, "DataAsset")},
			// Data Flow
			"oci_dataflow_application":      {Tok: makeResource(dataFlowMod, "Application")},
			"oci_dataflow_invoke_run":       {Tok: makeResource(dataFlowMod, "InvokeRun")},
			"oci_dataflow_private_endpoint": {Tok: makeResource(dataFlowMod, "PrivateEndpoint")},
			// Data Integration
			"oci_dataintegration_workspace": {Tok: makeResource(dataIntegrationMod, "Workspace")},
			// Data Safe
			"oci_data_safe_data_safe_configuration":    {Tok: makeResource(dataSafeMod, "DataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint": {Tok: makeResource(dataSafeMod, "DataSafePrivateEndpoint")},
			"oci_data_safe_on_prem_connector":          {Tok: makeResource(dataSafeMod, "OnPremConnector")},
			"oci_data_safe_target_database":            {Tok: makeResource(dataSafeMod, "TargetDatabase")},
			// Data Science
			"oci_datascience_model":            {Tok: makeResource(dataScienceMod, "Model")},
			"oci_datascience_model_deployment": {Tok: makeResource(dataScienceMod, "ModelDeployment")},
			"oci_datascience_model_provenance": {Tok: makeResource(dataScienceMod, "ModelProvenance")},
			"oci_datascience_notebook_session": {Tok: makeResource(dataScienceMod, "NotebookSession")},
			"oci_datascience_project":          {Tok: makeResource(dataScienceMod, "Project")},
			// Database
			"oci_database_autonomous_container_database":                                  {Tok: makeResource(databaseMod, "AutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association_operation":  {Tok: makeResource(databaseMod, "AutonomousContainerDatabaseDataguardAssociationOperation")},
			"oci_database_autonomous_database":                                            {Tok: makeResource(databaseMod, "AutonomousDatabase")},
			"oci_database_autonomous_database_backup":                                     {Tok: makeResource(databaseMod, "AutonomousDatabaseBackup")},
			"oci_database_autonomous_database_instance_wallet_management":                 {Tok: makeResource(databaseMod, "AutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_regional_wallet_management":                 {Tok: makeResource(databaseMod, "AutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                                     {Tok: makeResource(databaseMod, "AutonomousDatabaseWallet")},
			"oci_database_autonomous_exadata_infrastructure":                              {Tok: makeResource(databaseMod, "AutonomousExadataInfrastructure")},
			"oci_database_autonomous_vm_cluster":                                          {Tok: makeResource(databaseMod, "AutonomousVmCluster")},
			"oci_database_backup":                                                         {Tok: makeResource(databaseMod, "Backup")},
			"oci_database_backup_destination":                                             {Tok: makeResource(databaseMod, "BackupDestination")},
			"oci_database_cloud_exadata_infrastructure":                                   {Tok: makeResource(databaseMod, "CloudExadataInfrastructure")},
			"oci_database_cloud_vm_cluster":                                               {Tok: makeResource(databaseMod, "CloudVmCluster")},
			"oci_database_data_guard_association":                                         {Tok: makeResource(databaseMod, "DataGuardAssociation")},
			"oci_database_database":                                                       {Tok: makeResource(databaseMod, "Database")},
			"oci_database_database_software_image":                                        {Tok: makeResource(databaseMod, "DatabaseSoftwareImage")},
			"oci_database_database_upgrade":                                               {Tok: makeResource(databaseMod, "DatabaseUpgrade")},
			"oci_database_db_home":                                                        {Tok: makeResource(databaseMod, "DbHome")},
			"oci_database_db_node_console_connection":                                     {Tok: makeResource(databaseMod, "DbNodeConsoleConnection")},
			"oci_database_db_system":                                                      {Tok: makeResource(databaseMod, "DbSystem")},
			"oci_database_exadata_infrastructure":                                         {Tok: makeResource(databaseMod, "ExadataInfrastructure")},
			"oci_database_exadata_iorm_config":                                            {Tok: makeResource(databaseMod, "ExadataIormConfig")},
			"oci_database_external_container_database":                                    {Tok: makeResource(databaseMod, "ExternalContainerDatabase")},
			"oci_database_external_container_database_management":                         {Tok: makeResource(databaseMod, "ExternalContainerDatabaseManagement")},
			"oci_database_external_database_connector":                                    {Tok: makeResource(databaseMod, "ExternalDatabaseConnector")},
			"oci_database_external_non_container_database":                                {Tok: makeResource(databaseMod, "ExternalNonContainerDatabase")},
			"oci_database_external_non_container_database_management":                     {Tok: makeResource(databaseMod, "ExternalNonContainerDatabaseManagement")},
			"oci_database_external_non_container_database_operations_insights_management": {Tok: makeResource(databaseMod, "ExternalNonContainerDatabaseOperationsInsightsManagement")},
			"oci_database_external_pluggable_database":                                    {Tok: makeResource(databaseMod, "ExternalPluggableDatabase")},
			"oci_database_external_pluggable_database_management":                         {Tok: makeResource(databaseMod, "ExternalPluggableDatabaseManagement")},
			"oci_database_external_pluggable_database_operations_insights_management":     {Tok: makeResource(databaseMod, "ExternalPluggableDatabaseOperationsInsightsManagement")},
			"oci_database_key_store":                                                      {Tok: makeResource(databaseMod, "KeyStore")},
			"oci_database_maintenance_run":                                                {Tok: makeResource(databaseMod, "MaintenanceRun")},
			"oci_database_migration":                                                      {Tok: makeResource(databaseMod, "Migration")},
			"oci_database_pluggable_database":                                             {Tok: makeResource(databaseMod, "PluggableDatabase")},
			"oci_database_pluggable_databases_local_clone":                                {Tok: makeResource(databaseMod, "PluggableDatabasesLocalClone")},
			"oci_database_pluggable_databases_remote_clone":                               {Tok: makeResource(databaseMod, "PluggableDatabasesRemoteClone")},
			"oci_database_vm_cluster":                                                     {Tok: makeResource(databaseMod, "VmCluster")},
			"oci_database_vm_cluster_network":                                             {Tok: makeResource(databaseMod, "VmClusterNetwork")},
			// Database Management
			"oci_database_management_managed_database_group":                      {Tok: makeResource(databaseManagementMod, "ManagedDatabaseGroup")},
			"oci_database_management_managed_databases_change_database_parameter": {Tok: makeResource(databaseManagementMod, "ManagedDatabasesChangeDatabaseParameter")},
			"oci_database_management_managed_databases_reset_database_parameter":  {Tok: makeResource(databaseManagementMod, "ManagedDatabasesResetDatabaseParameter")},
			// Database Migration
			"oci_database_migration_agent":      {Tok: makeResource(databaseMigrationMod, "Agent")},
			"oci_database_migration_connection": {Tok: makeResource(databaseMigrationMod, "Connection")},
			"oci_database_migration_job":        {Tok: makeResource(databaseMigrationMod, "Job")},
			"oci_database_migration_migration":  {Tok: makeResource(databaseMigrationMod, "Migration")},
			// Devops
			"oci_devops_deploy_artifact":    {Tok: makeResource(devopsMod, "DeployArtifact")},
			"oci_devops_deploy_environment": {Tok: makeResource(devopsMod, "DeployEnvironment")},
			"oci_devops_deploy_pipeline":    {Tok: makeResource(devopsMod, "DeployPipeline")},
			"oci_devops_deploy_stage":       {Tok: makeResource(devopsMod, "DeployStage")},
			"oci_devops_deployment":         {Tok: makeResource(devopsMod, "Deployment")},
			"oci_devops_project":            {Tok: makeResource(devopsMod, "Project")},
			// ODA
			"oci_oda_oda_instance": {Tok: makeResource(odaMod, "OdaInstance")},
			// DNS
			"oci_dns_record":                     {Tok: makeResource(dnsMod, "Record")},
			"oci_dns_resolver":                   {Tok: makeResource(dnsMod, "Resolver")},
			"oci_dns_resolver_endpoint":          {Tok: makeResource(dnsMod, "ResolverEndpoint")},
			"oci_dns_rrset":                      {Tok: makeResource(dnsMod, "Rrset")},
			"oci_dns_steering_policy":            {Tok: makeResource(dnsMod, "SteeringPolicy")},
			"oci_dns_steering_policy_attachment": {Tok: makeResource(dnsMod, "SteeringPolicyAttachment")},
			"oci_dns_tsig_key":                   {Tok: makeResource(dnsMod, "TsigKey")},
			"oci_dns_view":                       {Tok: makeResource(dnsMod, "View")},
			"oci_dns_zone":                       {Tok: makeResource(dnsMod, "Zone")},
			// Email
			"oci_email_dkim":         {Tok: makeResource(emailMod, "Dkim")},
			"oci_email_email_domain": {Tok: makeResource(emailMod, "EmailDomain")},
			"oci_email_sender":       {Tok: makeResource(emailMod, "Sender")},
			"oci_email_suppression":  {Tok: makeResource(emailMod, "Suppression")},
			// Events
			"oci_events_rule": {Tok: makeResource(eventsMod, "Rule")},
			// File Storage
			"oci_file_storage_export":       {Tok: makeResource(fileStorageMod, "Export")},
			"oci_file_storage_export_set":   {Tok: makeResource(fileStorageMod, "ExportSet")},
			"oci_file_storage_file_system":  {Tok: makeResource(fileStorageMod, "FileSystem")},
			"oci_file_storage_mount_target": {Tok: makeResource(fileStorageMod, "MountTarget")},
			"oci_file_storage_snapshot":     {Tok: makeResource(fileStorageMod, "Snapshot")},
			// Functions
			"oci_functions_application":     {Tok: makeResource(functionsMod, "Application")},
			"oci_functions_function":        {Tok: makeResource(functionsMod, "Function")},
			"oci_functions_invoke_function": {Tok: makeResource(functionsMod, "InvokeFunction")},
			// Generic Artifacts Content
			// Golden Gate
			"oci_golden_gate_database_registration": {Tok: makeResource(goldenGateMod, "DatabaseRegistration")},
			"oci_golden_gate_deployment":            {Tok: makeResource(goldenGateMod, "Deployment")},
			"oci_golden_gate_deployment_backup":     {Tok: makeResource(goldenGateMod, "DeploymentBackup")},
			// Health Checks
			"oci_health_checks_http_monitor": {Tok: makeResource(healthChecksMod, "HttpMonitor")},
			"oci_health_checks_http_probe":   {Tok: makeResource(healthChecksMod, "HttpProbe")},
			"oci_health_checks_ping_monitor": {Tok: makeResource(healthChecksMod, "PingMonitor")},
			"oci_health_checks_ping_probe":   {Tok: makeResource(healthChecksMod, "PingProbe")},
			// Identity
			"oci_identity_api_key":                      {Tok: makeResource(identityMod, "ApiKey")},
			"oci_identity_auth_token":                   {Tok: makeResource(identityMod, "AuthToken")},
			"oci_identity_authentication_policy":        {Tok: makeResource(identityMod, "AuthenticationPolicy")},
			"oci_identity_compartment":                  {Tok: makeResource(identityMod, "Compartment")},
			"oci_identity_customer_secret_key":          {Tok: makeResource(identityMod, "CustomerSecretKey")},
			"oci_identity_dynamic_group":                {Tok: makeResource(identityMod, "DynamicGroup")},
			"oci_identity_group":                        {Tok: makeResource(identityMod, "Group")},
			"oci_identity_identity_provider":            {Tok: makeResource(identityMod, "IdentityProvider")},
			"oci_identity_idp_group_mapping":            {Tok: makeResource(identityMod, "IdpGroupMapping")},
			"oci_identity_network_source":               {Tok: makeResource(identityMod, "NetworkSource")},
			"oci_identity_policy":                       {Tok: makeResource(identityMod, "Policy")},
			"oci_identity_smtp_credential":              {Tok: makeResource(identityMod, "SmtpCredential")},
			"oci_identity_swift_password":               {Tok: makeResource(identityMod, "SwiftPassword")},
			"oci_identity_tag":                          {Tok: makeResource(identityMod, "Tag")},
			"oci_identity_tag_default":                  {Tok: makeResource(identityMod, "TagDefault")},
			"oci_identity_tag_namespace":                {Tok: makeResource(identityMod, "TagNamespace")},
			"oci_identity_ui_password":                  {Tok: makeResource(identityMod, "UiPassword")},
			"oci_identity_user":                         {Tok: makeResource(identityMod, "User")},
			"oci_identity_user_capabilities_management": {Tok: makeResource(identityMod, "UserCapabilitiesManagement")},
			"oci_identity_user_group_membership":        {Tok: makeResource(identityMod, "UserGroupMembership")},
			// Integration
			"oci_integration_integration_instance": {Tok: makeResource(integrationMod, "IntegrationInstance")},
			// Jms
			"oci_jms_fleet": {Tok: makeResource(jmsMod, "Fleet")},
			// Kms
			"oci_kms_encrypted_data": {Tok: makeResource(kmsMod, "EncryptedData")},
			"oci_kms_generated_key":  {Tok: makeResource(kmsMod, "GeneratedKey")},
			"oci_kms_key":            {Tok: makeResource(kmsMod, "Key")},
			"oci_kms_key_version":    {Tok: makeResource(kmsMod, "KeyVersion")},
			"oci_kms_sign":           {Tok: makeResource(kmsMod, "Sign")},
			"oci_kms_vault":          {Tok: makeResource(kmsMod, "Vault")},
			"oci_kms_verify":         {Tok: makeResource(kmsMod, "Verify")},
			// Limits
			"oci_limits_quota": {Tok: makeResource(limitsMod, "Quota")},
			// Load Balancer
			"oci_load_balancer_backend":                      {Tok: makeResource(loadBalancerMod, "Backend")},
			"oci_load_balancer_backend_set":                  {Tok: makeResource(loadBalancerMod, "BackendSet")},
			"oci_load_balancer_certificate":                  {Tok: makeResource(loadBalancerMod, "Certificate")},
			"oci_load_balancer_hostname":                     {Tok: makeResource(loadBalancerMod, "Hostname")},
			"oci_load_balancer_listener":                     {Tok: makeResource(loadBalancerMod, "Listener")},
			"oci_load_balancer_load_balancer":                {Tok: makeResource(loadBalancerMod, "LoadBalancer")},
			"oci_load_balancer_load_balancer_routing_policy": {Tok: makeResource(loadBalancerMod, "LoadBalancerRoutingPolicy")},
			"oci_load_balancer_path_route_set":               {Tok: makeResource(loadBalancerMod, "PathRouteSet")},
			"oci_load_balancer_rule_set":                     {Tok: makeResource(loadBalancerMod, "RuleSet")},
			"oci_load_balancer_ssl_cipher_suite":             {Tok: makeResource(loadBalancerMod, "SslCipherSuite")},
			// Log Analytics
			"oci_log_analytics_log_analytics_entity":                 {Tok: makeResource(logAnalyticsMod, "LogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_log_group":              {Tok: makeResource(logAnalyticsMod, "LogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_object_collection_rule": {Tok: makeResource(logAnalyticsMod, "LogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_namespace":                            {Tok: makeResource(logAnalyticsMod, "Namespace")},
			// Logging
			"oci_logging_log":                         {Tok: makeResource(loggingMod, "Log")},
			"oci_logging_log_group":                   {Tok: makeResource(loggingMod, "LogGroup")},
			"oci_logging_log_saved_search":            {Tok: makeResource(loggingMod, "LogSavedSearch")},
			"oci_logging_unified_agent_configuration": {Tok: makeResource(loggingMod, "UnifiedAgentConfiguration")},
			// Management Agent
			"oci_management_agent_management_agent":             {Tok: makeResource(managementAgentMod, "ManagementAgent")},
			"oci_management_agent_management_agent_install_key": {Tok: makeResource(managementAgentMod, "ManagementAgentInstallKey")},
			// Management Dashboard
			"oci_management_dashboard_management_dashboards_import": {Tok: makeResource(managementDashboardMod, "ManagementDashboardsImport")},
			// Marketplace
			"oci_marketplace_accepted_agreement": {Tok: makeResource(marketplaceMod, "AcceptedAgreement")},
			"oci_marketplace_publication":        {Tok: makeResource(marketplaceMod, "Publication")},
			// Metering Computation
			"oci_metering_computation_custom_table": {Tok: makeResource(meteringComputationMod, "CustomTable")},
			"oci_metering_computation_query":        {Tok: makeResource(meteringComputationMod, "Query")},
			"oci_metering_computation_usage":        {Tok: makeResource(meteringComputationMod, "Usage")},
			// Monitoring
			"oci_monitoring_alarm": {Tok: makeResource(monitoringMod, "Alarm")},
			// MYSQL
			"oci_mysql_analytics_cluster": {Tok: makeResource(mysqlMod, "AnalyticsCluster")},
			"oci_mysql_channel":           {Tok: makeResource(mysqlMod, "Channel")},
			"oci_mysql_heat_wave_cluster": {Tok: makeResource(mysqlMod, "HeatWaveCluster")},
			"oci_mysql_mysql_backup":      {Tok: makeResource(mysqlMod, "MysqlBackup")},
			"oci_mysql_mysql_db_system":   {Tok: makeResource(mysqlMod, "MysqlDbSystem")},
			// Network Load Balancer
			"oci_network_load_balancer_backend":               {Tok: makeResource(networkLoadBalancerMod, "Backend")},
			"oci_network_load_balancer_backend_set":           {Tok: makeResource(networkLoadBalancerMod, "BackendSet")},
			"oci_network_load_balancer_listener":              {Tok: makeResource(networkLoadBalancerMod, "Listener")},
			"oci_network_load_balancer_network_load_balancer": {Tok: makeResource(networkLoadBalancerMod, "NetworkLoadBalancer")},
			// NOSQL
			"oci_nosql_index": {Tok: makeResource(nosqlMod, "Index")},
			"oci_nosql_table": {Tok: makeResource(nosqlMod, "Table")},
			// ONS
			"oci_ons_notification_topic": {Tok: makeResource(onsMod, "NotificationTopic")},
			"oci_ons_subscription":       {Tok: makeResource(onsMod, "Subscription")},
			// Object Storage
			"oci_objectstorage_bucket":                  {Tok: makeResource(objectStorageMod, "ObjectstorageBucket")},
			"oci_objectstorage_object":                  {Tok: makeResource(objectStorageMod, "ObjectstorageObject")},
			"oci_objectstorage_object_lifecycle_policy": {Tok: makeResource(objectStorageMod, "ObjectstorageObjectLifecyclePolicy")},
			"oci_objectstorage_preauthrequest":          {Tok: makeResource(objectStorageMod, "ObjectstoragePreauthrequest")},
			"oci_objectstorage_replication_policy":      {Tok: makeResource(objectStorageMod, "ObjectstorageReplicationPolicy")},
			// Opsi
			"oci_opsi_database_insight":          {Tok: makeResource(opsiMod, "DatabaseInsight")},
			"oci_opsi_enterprise_manager_bridge": {Tok: makeResource(opsiMod, "EnterpriseManagerBridge")},
			"oci_opsi_host_insight":              {Tok: makeResource(opsiMod, "HostInsight")},
			// Optimizer
			"oci_optimizer_enrollment_status": {Tok: makeResource(optimizerMod, "EnrollmentStatus")},
			"oci_optimizer_profile":           {Tok: makeResource(optimizerMod, "Profile")},
			"oci_optimizer_recommendation":    {Tok: makeResource(optimizerMod, "Recommendation")},
			"oci_optimizer_resource_action":   {Tok: makeResource(optimizerMod, "ResourceAction")},
			// OCVP
			"oci_ocvp_esxi_host": {Tok: makeResource(ocvpMod, "EsxiHost")},
			"oci_ocvp_sddc":      {Tok: makeResource(ocvpMod, "Sddc")},
			// OS Management
			"oci_osmanagement_managed_instance_group":      {Tok: makeResource(osManagementMod, "ManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_management": {Tok: makeResource(osManagementMod, "ManagedInstanceManagement")},
			"oci_osmanagement_software_source":             {Tok: makeResource(osManagementMod, "SoftwareSource")},
			// Resource Manager
			// Service Catalog
			"oci_service_catalog_private_application":         {Tok: makeResource(serviceCatalogMod, "PrivateApplication")},
			"oci_service_catalog_service_catalog":             {Tok: makeResource(serviceCatalogMod, "ServiceCatalog")},
			"oci_service_catalog_service_catalog_association": {Tok: makeResource(serviceCatalogMod, "ServiceCatalogAssociation")},
			// SCH
			"oci_sch_service_connector": {Tok: makeResource(schMod, "ServiceConnector")},
			// Streaming
			"oci_streaming_connect_harness": {Tok: makeResource(streamingMod, "ConnectHarness")},
			"oci_streaming_stream":          {Tok: makeResource(streamingMod, "Stream")},
			"oci_streaming_stream_pool":     {Tok: makeResource(streamingMod, "StreamPool")},
			// Vault
			// Vulnerability Scanning
			"oci_vulnerability_scanning_container_scan_recipe": {Tok: makeResource(vulnerabilityScanningMod, "ContainerScanRecipe")},
			"oci_vulnerability_scanning_container_scan_target": {Tok: makeResource(vulnerabilityScanningMod, "ContainerScanTarget")},
			"oci_vulnerability_scanning_host_scan_recipe":      {Tok: makeResource(vulnerabilityScanningMod, "HostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_target":      {Tok: makeResource(vulnerabilityScanningMod, "HostScanTarget")},
			// WAAS
			"oci_waas_address_list":           {Tok: makeResource(waasMod, "AddressList")},
			"oci_waas_certificate":            {Tok: makeResource(waasMod, "Certificate")},
			"oci_waas_custom_protection_rule": {Tok: makeResource(waasMod, "CustomProtectionRule")},
			"oci_waas_http_redirect":          {Tok: makeResource(waasMod, "HttpRedirect")},
			"oci_waas_protection_rule":        {Tok: makeResource(waasMod, "ProtectionRule")},
			"oci_waas_purge_cache":            {Tok: makeResource(waasMod, "PurgeCache")},
			"oci_waas_waas_policy":            {Tok: makeResource(waasMod, "WaasPolicy")},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			"oci_analytics_analytics_instance":                                  {Tok: makeDataSource(ociMod, "GetAnalyticsAnalyticsInstance")},
			"oci_analytics_analytics_instance_private_access_channel":           {Tok: makeDataSource(ociMod, "GetAnalyticsAnalyticsInstancePrivateAccessChannel")},
			"oci_analytics_analytics_instances":                                 {Tok: makeDataSource(ociMod, "GetAnalyticsAnalyticsInstances")},
			"oci_apigateway_api":                                                {Tok: makeDataSource(ociMod, "GetApigatewayApi")},
			"oci_apigateway_api_content":                                        {Tok: makeDataSource(ociMod, "GetApigatewayApiContent")},
			"oci_apigateway_api_deployment_specification":                       {Tok: makeDataSource(ociMod, "GetApigatewayApiDeploymentSpecification")},
			"oci_apigateway_api_validation":                                     {Tok: makeDataSource(ociMod, "GetApigatewayApiValidation")},
			"oci_apigateway_apis":                                               {Tok: makeDataSource(ociMod, "GetApigatewayApis")},
			"oci_apigateway_certificate":                                        {Tok: makeDataSource(ociMod, "GetApigatewayCertificate")},
			"oci_apigateway_certificates":                                       {Tok: makeDataSource(ociMod, "GetApigatewayCertificates")},
			"oci_apigateway_deployment":                                         {Tok: makeDataSource(ociMod, "GetApigatewayDeployment")},
			"oci_apigateway_deployments":                                        {Tok: makeDataSource(ociMod, "GetApigatewayDeployments")},
			"oci_apigateway_gateway":                                            {Tok: makeDataSource(ociMod, "GetApigatewayGateway")},
			"oci_apigateway_gateways":                                           {Tok: makeDataSource(ociMod, "GetApigatewayGateways")},
			"oci_apm_apm_domain":                                                {Tok: makeDataSource(ociMod, "GetApmApmDomain")},
			"oci_apm_apm_domains":                                               {Tok: makeDataSource(ociMod, "GetApmApmDomains")},
			"oci_apm_data_keys":                                                 {Tok: makeDataSource(ociMod, "GetApmDataKeys")},
			"oci_apm_synthetics_monitor":                                        {Tok: makeDataSource(ociMod, "GetApmSyntheticsMonitor")},
			"oci_apm_synthetics_monitors":                                       {Tok: makeDataSource(ociMod, "GetApmSyntheticsMonitors")},
			"oci_apm_synthetics_public_vantage_point":                           {Tok: makeDataSource(ociMod, "GetApmSyntheticsPublicVantagePoint")},
			"oci_apm_synthetics_public_vantage_points":                          {Tok: makeDataSource(ociMod, "GetApmSyntheticsPublicVantagePoints")},
			"oci_apm_synthetics_result":                                         {Tok: makeDataSource(ociMod, "GetApmSyntheticsResult")},
			"oci_apm_synthetics_script":                                         {Tok: makeDataSource(ociMod, "GetApmSyntheticsScript")},
			"oci_apm_synthetics_scripts":                                        {Tok: makeDataSource(ociMod, "GetApmSyntheticsScripts")},
			"oci_artifacts_container_configuration":                             {Tok: makeDataSource(ociMod, "GetArtifactsContainerConfiguration")},
			"oci_artifacts_container_image":                                     {Tok: makeDataSource(ociMod, "GetArtifactsContainerImage")},
			"oci_artifacts_container_image_signature":                           {Tok: makeDataSource(ociMod, "GetArtifactsContainerImageSignature")},
			"oci_artifacts_container_image_signatures":                          {Tok: makeDataSource(ociMod, "GetArtifactsContainerImageSignatures")},
			"oci_artifacts_container_images":                                    {Tok: makeDataSource(ociMod, "GetArtifactsContainerImages")},
			"oci_artifacts_container_repositories":                              {Tok: makeDataSource(ociMod, "GetArtifactsContainerRepositories")},
			"oci_artifacts_container_repository":                                {Tok: makeDataSource(ociMod, "GetArtifactsContainerRepository")},
			"oci_artifacts_generic_artifact":                                    {Tok: makeDataSource(ociMod, "GetArtifactsGenericArtifact")},
			"oci_artifacts_generic_artifacts":                                   {Tok: makeDataSource(ociMod, "GetArtifactsGenericArtifacts")},
			"oci_artifacts_repositories":                                        {Tok: makeDataSource(ociMod, "GetArtifactsRepositories")},
			"oci_artifacts_repository":                                          {Tok: makeDataSource(ociMod, "GetArtifactsRepository")},
			"oci_audit_configuration":                                           {Tok: makeDataSource(ociMod, "GetAuditConfiguration")},
			"oci_audit_events":                                                  {Tok: makeDataSource(ociMod, "GetAuditEvents")},
			"oci_autoscaling_auto_scaling_configuration":                        {Tok: makeDataSource(ociMod, "GetAutoscalingAutoScalingConfiguration")},
			"oci_autoscaling_auto_scaling_configurations":                       {Tok: makeDataSource(ociMod, "GetAutoscalingAutoScalingConfigurations")},
			"oci_bastion_bastion":                                               {Tok: makeDataSource(ociMod, "GetBastionBastion")},
			"oci_bastion_bastions":                                              {Tok: makeDataSource(ociMod, "GetBastionBastions")},
			"oci_bastion_session":                                               {Tok: makeDataSource(ociMod, "GetBastionSession")},
			"oci_bastion_sessions":                                              {Tok: makeDataSource(ociMod, "GetBastionSessions")},
			"oci_bds_auto_scaling_configuration":                                {Tok: makeDataSource(ociMod, "GetBdsAutoScalingConfiguration")},
			"oci_bds_auto_scaling_configurations":                               {Tok: makeDataSource(ociMod, "GetBdsAutoScalingConfigurations")},
			"oci_bds_bds_instance":                                              {Tok: makeDataSource(ociMod, "GetBdsBdsInstance")},
			"oci_bds_bds_instances":                                             {Tok: makeDataSource(ociMod, "GetBdsBdsInstances")},
			"oci_blockchain_blockchain_platform":                                {Tok: makeDataSource(ociMod, "GetBlockchainBlockchainPlatform")},
			"oci_blockchain_blockchain_platforms":                               {Tok: makeDataSource(ociMod, "GetBlockchainBlockchainPlatforms")},
			"oci_blockchain_osn":                                                {Tok: makeDataSource(ociMod, "GetBlockchainOsn")},
			"oci_blockchain_osns":                                               {Tok: makeDataSource(ociMod, "GetBlockchainOsns")},
			"oci_blockchain_peer":                                               {Tok: makeDataSource(ociMod, "GetBlockchainPeer")},
			"oci_blockchain_peers":                                              {Tok: makeDataSource(ociMod, "GetBlockchainPeers")},
			"oci_budget_alert_rule":                                             {Tok: makeDataSource(ociMod, "GetBudgetAlertRule")},
			"oci_budget_alert_rules":                                            {Tok: makeDataSource(ociMod, "GetBudgetAlertRules")},
			"oci_budget_budget":                                                 {Tok: makeDataSource(ociMod, "GetBudgetBudget")},
			"oci_budget_budgets":                                                {Tok: makeDataSource(ociMod, "GetBudgetBudgets")},
			"oci_cloud_guard_cloud_guard_configuration":                         {Tok: makeDataSource(ociMod, "GetCloudGuardCloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":                                    {Tok: makeDataSource(ociMod, "GetCloudGuardDataMaskRule")},
			"oci_cloud_guard_data_mask_rules":                                   {Tok: makeDataSource(ociMod, "GetCloudGuardDataMaskRules")},
			"oci_cloud_guard_detector_recipe":                                   {Tok: makeDataSource(ociMod, "GetCloudGuardDetectorRecipe")},
			"oci_cloud_guard_detector_recipes":                                  {Tok: makeDataSource(ociMod, "GetCloudGuardDetectorRecipes")},
			"oci_cloud_guard_managed_list":                                      {Tok: makeDataSource(ociMod, "GetCloudGuardManagedList")},
			"oci_cloud_guard_managed_lists":                                     {Tok: makeDataSource(ociMod, "GetCloudGuardManagedLists")},
			"oci_cloud_guard_responder_recipe":                                  {Tok: makeDataSource(ociMod, "GetCloudGuardResponderRecipe")},
			"oci_cloud_guard_responder_recipes":                                 {Tok: makeDataSource(ociMod, "GetCloudGuardResponderRecipes")},
			"oci_cloud_guard_target":                                            {Tok: makeDataSource(ociMod, "GetCloudGuardTarget")},
			"oci_cloud_guard_targets":                                           {Tok: makeDataSource(ociMod, "GetCloudGuardTargets")},
			"oci_computeinstanceagent_instance_agent_plugin":                    {Tok: makeDataSource(ociMod, "GetComputeinstanceagentInstanceAgentPlugin")},
			"oci_computeinstanceagent_instance_agent_plugins":                   {Tok: makeDataSource(ociMod, "GetComputeinstanceagentInstanceAgentPlugins")},
			"oci_computeinstanceagent_instance_available_plugins":               {Tok: makeDataSource(ociMod, "GetComputeinstanceagentInstanceAvailablePlugins")},
			"oci_containerengine_cluster_kube_config":                           {Tok: makeDataSource(ociMod, "GetContainerengineClusterKubeConfig")},
			"oci_containerengine_cluster_option":                                {Tok: makeDataSource(ociMod, "GetContainerengineClusterOption")},
			"oci_containerengine_clusters":                                      {Tok: makeDataSource(ociMod, "GetContainerengineClusters")},
			"oci_containerengine_migrate_to_native_vcn_status":                  {Tok: makeDataSource(ociMod, "GetContainerengineMigrateToNativeVcnStatus")},
			"oci_containerengine_node_pool":                                     {Tok: makeDataSource(ociMod, "GetContainerengineNodePool")},
			"oci_containerengine_node_pool_option":                              {Tok: makeDataSource(ociMod, "GetContainerengineNodePoolOption")},
			"oci_containerengine_node_pools":                                    {Tok: makeDataSource(ociMod, "GetContainerengineNodePools")},
			"oci_containerengine_work_request_errors":                           {Tok: makeDataSource(ociMod, "GetContainerengineWorkRequestErrors")},
			"oci_containerengine_work_request_log_entries":                      {Tok: makeDataSource(ociMod, "GetContainerengineWorkRequestLogEntries")},
			"oci_containerengine_work_requests":                                 {Tok: makeDataSource(ociMod, "GetContainerengineWorkRequests")},
			"oci_core_app_catalog_listing":                                      {Tok: makeDataSource(ociMod, "GetCoreAppCatalogListing")},
			"oci_core_app_catalog_listing_resource_version":                     {Tok: makeDataSource(ociMod, "GetCoreAppCatalogListingResourceVersion")},
			"oci_core_app_catalog_listing_resource_versions":                    {Tok: makeDataSource(ociMod, "GetCoreAppCatalogListingResourceVersions")},
			"oci_core_app_catalog_listings":                                     {Tok: makeDataSource(ociMod, "GetCoreAppCatalogListings")},
			"oci_core_app_catalog_subscriptions":                                {Tok: makeDataSource(ociMod, "GetCoreAppCatalogSubscriptions")},
			"oci_core_block_volume_replica":                                     {Tok: makeDataSource(ociMod, "GetCoreBlockVolumeReplica")},
			"oci_core_block_volume_replicas":                                    {Tok: makeDataSource(ociMod, "GetCoreBlockVolumeReplicas")},
			"oci_core_boot_volume":                                              {Tok: makeDataSource(ociMod, "GetCoreBootVolume")},
			"oci_core_boot_volume_attachments":                                  {Tok: makeDataSource(ociMod, "GetCoreBootVolumeAttachments")},
			"oci_core_boot_volume_backup":                                       {Tok: makeDataSource(ociMod, "GetCoreBootVolumeBackup")},
			"oci_core_boot_volume_backups":                                      {Tok: makeDataSource(ociMod, "GetCoreBootVolumeBackups")},
			"oci_core_boot_volume_replica":                                      {Tok: makeDataSource(ociMod, "GetCoreBootVolumeReplica")},
			"oci_core_boot_volume_replicas":                                     {Tok: makeDataSource(ociMod, "GetCoreBootVolumeReplicas")},
			"oci_core_boot_volumes":                                             {Tok: makeDataSource(ociMod, "GetCoreBootVolumes")},
			"oci_core_byoip_allocated_ranges":                                   {Tok: makeDataSource(ociMod, "GetCoreByoipAllocatedRanges")},
			"oci_core_byoip_range":                                              {Tok: makeDataSource(ociMod, "GetCoreByoipRange")},
			"oci_core_byoip_ranges":                                             {Tok: makeDataSource(ociMod, "GetCoreByoipRanges")},
			"oci_core_cluster_network":                                          {Tok: makeDataSource(ociMod, "GetCoreClusterNetwork")},
			"oci_core_cluster_network_instances":                                {Tok: makeDataSource(ociMod, "GetCoreClusterNetworkInstances")},
			"oci_core_cluster_networks":                                         {Tok: makeDataSource(ociMod, "GetCoreClusterNetworks")},
			"oci_core_compute_capacity_reservation":                             {Tok: makeDataSource(ociMod, "GetCoreComputeCapacityReservation")},
			"oci_core_compute_capacity_reservation_instance_shapes":             {Tok: makeDataSource(ociMod, "GetCoreComputeCapacityReservationInstanceShapes")},
			"oci_core_compute_capacity_reservation_instances":                   {Tok: makeDataSource(ociMod, "GetCoreComputeCapacityReservationInstances")},
			"oci_core_compute_capacity_reservations":                            {Tok: makeDataSource(ociMod, "GetCoreComputeCapacityReservations")},
			"oci_core_compute_global_image_capability_schema":                   {Tok: makeDataSource(ociMod, "GetCoreComputeGlobalImageCapabilitySchema")},
			"oci_core_compute_global_image_capability_schemas":                  {Tok: makeDataSource(ociMod, "GetCoreComputeGlobalImageCapabilitySchemas")},
			"oci_core_compute_global_image_capability_schemas_version":          {Tok: makeDataSource(ociMod, "GetCoreComputeGlobalImageCapabilitySchemasVersion")},
			"oci_core_compute_global_image_capability_schemas_versions":         {Tok: makeDataSource(ociMod, "GetCoreComputeGlobalImageCapabilitySchemasVersions")},
			"oci_core_compute_image_capability_schema":                          {Tok: makeDataSource(ociMod, "GetCoreComputeImageCapabilitySchema")},
			"oci_core_compute_image_capability_schemas":                         {Tok: makeDataSource(ociMod, "GetCoreComputeImageCapabilitySchemas")},
			"oci_core_console_histories":                                        {Tok: makeDataSource(ociMod, "GetCoreConsoleHistories")},
			"oci_core_console_history_data":                                     {Tok: makeDataSource(ociMod, "GetCoreConsoleHistoryData")},
			"oci_core_cpe_device_shape":                                         {Tok: makeDataSource(ociMod, "GetCoreCpeDeviceShape")},
			"oci_core_cpe_device_shapes":                                        {Tok: makeDataSource(ociMod, "GetCoreCpeDeviceShapes")},
			"oci_core_cpes":                                                     {Tok: makeDataSource(ociMod, "GetCoreCpes")},
			"oci_core_cross_connect":                                            {Tok: makeDataSource(ociMod, "GetCoreCrossConnect")},
			"oci_core_cross_connect_group":                                      {Tok: makeDataSource(ociMod, "GetCoreCrossConnectGroup")},
			"oci_core_cross_connect_groups":                                     {Tok: makeDataSource(ociMod, "GetCoreCrossConnectGroups")},
			"oci_core_cross_connect_locations":                                  {Tok: makeDataSource(ociMod, "GetCoreCrossConnectLocations")},
			"oci_core_cross_connect_port_speed_shapes":                          {Tok: makeDataSource(ociMod, "GetCoreCrossConnectPortSpeedShapes")},
			"oci_core_cross_connect_status":                                     {Tok: makeDataSource(ociMod, "GetCoreCrossConnectStatus")},
			"oci_core_cross_connects":                                           {Tok: makeDataSource(ociMod, "GetCoreCrossConnects")},
			"oci_core_dedicated_vm_host":                                        {Tok: makeDataSource(ociMod, "GetCoreDedicatedVmHost")},
			"oci_core_dedicated_vm_host_instance_shapes":                        {Tok: makeDataSource(ociMod, "GetCoreDedicatedVmHostInstanceShapes")},
			"oci_core_dedicated_vm_host_shapes":                                 {Tok: makeDataSource(ociMod, "GetCoreDedicatedVmHostShapes")},
			"oci_core_dedicated_vm_hosts":                                       {Tok: makeDataSource(ociMod, "GetCoreDedicatedVmHosts")},
			"oci_core_dedicated_vm_hosts_instances":                             {Tok: makeDataSource(ociMod, "GetCoreDedicatedVmHostsInstances")},
			"oci_core_dhcp_options":                                             {Tok: makeDataSource(ociMod, "GetCoreDhcpOptions")},
			"oci_core_drg_attachments":                                          {Tok: makeDataSource(ociMod, "GetCoreDrgAttachments")},
			"oci_core_drg_route_distribution":                                   {Tok: makeDataSource(ociMod, "GetCoreDrgRouteDistribution")},
			"oci_core_drg_route_distribution_statements":                        {Tok: makeDataSource(ociMod, "GetCoreDrgRouteDistributionStatements")},
			"oci_core_drg_route_distributions":                                  {Tok: makeDataSource(ociMod, "GetCoreDrgRouteDistributions")},
			"oci_core_drg_route_table":                                          {Tok: makeDataSource(ociMod, "GetCoreDrgRouteTable")},
			"oci_core_drg_route_table_route_rules":                              {Tok: makeDataSource(ociMod, "GetCoreDrgRouteTableRouteRules")},
			"oci_core_drg_route_tables":                                         {Tok: makeDataSource(ociMod, "GetCoreDrgRouteTables")},
			"oci_core_drgs":                                                     {Tok: makeDataSource(ociMod, "GetCoreDrgs")},
			"oci_core_fast_connect_provider_service":                            {Tok: makeDataSource(ociMod, "GetCoreFastConnectProviderService")},
			"oci_core_fast_connect_provider_service_key":                        {Tok: makeDataSource(ociMod, "GetCoreFastConnectProviderServiceKey")},
			"oci_core_fast_connect_provider_services":                           {Tok: makeDataSource(ociMod, "GetCoreFastConnectProviderServices")},
			"oci_core_image":                                                    {Tok: makeDataSource(ociMod, "GetCoreImage")},
			"oci_core_image_shape":                                              {Tok: makeDataSource(ociMod, "GetCoreImageShape")},
			"oci_core_image_shapes":                                             {Tok: makeDataSource(ociMod, "GetCoreImageShapes")},
			"oci_core_images":                                                   {Tok: makeDataSource(ociMod, "GetCoreImages")},
			"oci_core_instance":                                                 {Tok: makeDataSource(ociMod, "GetCoreInstance")},
			"oci_core_instance_configuration":                                   {Tok: makeDataSource(ociMod, "GetCoreInstanceConfiguration")},
			"oci_core_instance_configurations":                                  {Tok: makeDataSource(ociMod, "GetCoreInstanceConfigurations")},
			"oci_core_instance_console_connections":                             {Tok: makeDataSource(ociMod, "GetCoreInstanceConsoleConnections")},
			"oci_core_instance_credentials":                                     {Tok: makeDataSource(ociMod, "GetCoreInstanceCredentials")},
			"oci_core_instance_devices":                                         {Tok: makeDataSource(ociMod, "GetCoreInstanceDevices")},
			"oci_core_instance_pool":                                            {Tok: makeDataSource(ociMod, "GetCoreInstancePool")},
			"oci_core_instance_pool_instances":                                  {Tok: makeDataSource(ociMod, "GetCoreInstancePoolInstances")},
			"oci_core_instance_pool_load_balancer_attachment":                   {Tok: makeDataSource(ociMod, "GetCoreInstancePoolLoadBalancerAttachment")},
			"oci_core_instance_pools":                                           {Tok: makeDataSource(ociMod, "GetCoreInstancePools")},
			"oci_core_instances":                                                {Tok: makeDataSource(ociMod, "GetCoreInstances")},
			"oci_core_internet_gateways":                                        {Tok: makeDataSource(ociMod, "GetCoreInternetGateways")},
			"oci_core_ipsec_config":                                             {Tok: makeDataSource(ociMod, "GetCoreIpsecConfig")},
			"oci_core_ipsec_connection_tunnel":                                  {Tok: makeDataSource(ociMod, "GetCoreIpsecConnectionTunnel")},
			"oci_core_ipsec_connection_tunnels":                                 {Tok: makeDataSource(ociMod, "GetCoreIpsecConnectionTunnels")},
			"oci_core_ipsec_connections":                                        {Tok: makeDataSource(ociMod, "GetCoreIpsecConnections")},
			"oci_core_ipsec_status":                                             {Tok: makeDataSource(ociMod, "GetCoreIpsecStatus")},
			"oci_core_ipv6":                                                     {Tok: makeDataSource(ociMod, "GetCoreIpv6")},
			"oci_core_ipv6s":                                                    {Tok: makeDataSource(ociMod, "GetCoreIpv6s")},
			"oci_core_letter_of_authority":                                      {Tok: makeDataSource(ociMod, "GetCoreLetterOfAuthority")},
			"oci_core_listing_resource_version":                                 {Tok: makeDataSource(ociMod, "GetCoreListingResourceVersion")},
			"oci_core_listing_resource_versions":                                {Tok: makeDataSource(ociMod, "GetCoreListingResourceVersions")},
			"oci_core_local_peering_gateways":                                   {Tok: makeDataSource(ociMod, "GetCoreLocalPeeringGateways")},
			"oci_core_nat_gateway":                                              {Tok: makeDataSource(ociMod, "GetCoreNatGateway")},
			"oci_core_nat_gateways":                                             {Tok: makeDataSource(ociMod, "GetCoreNatGateways")},
			"oci_core_network_security_group":                                   {Tok: makeDataSource(ociMod, "GetCoreNetworkSecurityGroup")},
			"oci_core_network_security_group_security_rules":                    {Tok: makeDataSource(ociMod, "GetCoreNetworkSecurityGroupSecurityRules")},
			"oci_core_network_security_group_vnics":                             {Tok: makeDataSource(ociMod, "GetCoreNetworkSecurityGroupVnics")},
			"oci_core_network_security_groups":                                  {Tok: makeDataSource(ociMod, "GetCoreNetworkSecurityGroups")},
			"oci_core_peer_region_for_remote_peerings":                          {Tok: makeDataSource(ociMod, "GetCorePeerRegionForRemotePeerings")},
			"oci_core_private_ip":                                               {Tok: makeDataSource(ociMod, "GetCorePrivateIp")},
			"oci_core_private_ips":                                              {Tok: makeDataSource(ociMod, "GetCorePrivateIps")},
			"oci_core_public_ip":                                                {Tok: makeDataSource(ociMod, "GetCorePublicIp")},
			"oci_core_public_ip_pool":                                           {Tok: makeDataSource(ociMod, "GetCorePublicIpPool")},
			"oci_core_public_ip_pools":                                          {Tok: makeDataSource(ociMod, "GetCorePublicIpPools")},
			"oci_core_public_ips":                                               {Tok: makeDataSource(ociMod, "GetCorePublicIps")},
			"oci_core_remote_peering_connections":                               {Tok: makeDataSource(ociMod, "GetCoreRemotePeeringConnections")},
			"oci_core_route_tables":                                             {Tok: makeDataSource(ociMod, "GetCoreRouteTables")},
			"oci_core_security_lists":                                           {Tok: makeDataSource(ociMod, "GetCoreSecurityLists")},
			"oci_core_service_gateways":                                         {Tok: makeDataSource(ociMod, "GetCoreServiceGateways")},
			"oci_core_services":                                                 {Tok: makeDataSource(ociMod, "GetCoreServices")},
			"oci_core_shape":                                                    {Tok: makeDataSource(ociMod, "GetCoreShape")},
			"oci_core_shapes":                                                   {Tok: makeDataSource(ociMod, "GetCoreShapes")},
			"oci_core_subnet":                                                   {Tok: makeDataSource(ociMod, "GetCoreSubnet")},
			"oci_core_subnets":                                                  {Tok: makeDataSource(ociMod, "GetCoreSubnets")},
			"oci_core_vcn":                                                      {Tok: makeDataSource(ociMod, "GetCoreVcn")},
			"oci_core_vcn_dns_resolver_association":                             {Tok: makeDataSource(ociMod, "GetCoreVcnDnsResolverAssociation")},
			"oci_core_vcns":                                                     {Tok: makeDataSource(ociMod, "GetCoreVcns")},
			"oci_core_virtual_circuit":                                          {Tok: makeDataSource(ociMod, "GetCoreVirtualCircuit")},
			"oci_core_virtual_circuit_bandwidth_shapes":                         {Tok: makeDataSource(ociMod, "GetCoreVirtualCircuitBandwidthShapes")},
			"oci_core_virtual_circuit_public_prefixes":                          {Tok: makeDataSource(ociMod, "GetCoreVirtualCircuitPublicPrefixes")},
			"oci_core_virtual_circuits":                                         {Tok: makeDataSource(ociMod, "GetCoreVirtualCircuits")},
			"oci_core_virtual_networks":                                         {Tok: makeDataSource(ociMod, "GetCoreVirtualNetworks")},
			"oci_core_vlan":                                                     {Tok: makeDataSource(ociMod, "GetCoreVlan")},
			"oci_core_vlans":                                                    {Tok: makeDataSource(ociMod, "GetCoreVlans")},
			"oci_core_vnic":                                                     {Tok: makeDataSource(ociMod, "GetCoreVnic")},
			"oci_core_vnic_attachments":                                         {Tok: makeDataSource(ociMod, "GetCoreVnicAttachments")},
			"oci_core_volume":                                                   {Tok: makeDataSource(ociMod, "GetCoreVolume")},
			"oci_core_volume_attachments":                                       {Tok: makeDataSource(ociMod, "GetCoreVolumeAttachments")},
			"oci_core_volume_backup_policies":                                   {Tok: makeDataSource(ociMod, "GetCoreVolumeBackupPolicies")},
			"oci_core_volume_backup_policy_assignments":                         {Tok: makeDataSource(ociMod, "GetCoreVolumeBackupPolicyAssignments")},
			"oci_core_volume_backups":                                           {Tok: makeDataSource(ociMod, "GetCoreVolumeBackups")},
			"oci_core_volume_group_backups":                                     {Tok: makeDataSource(ociMod, "GetCoreVolumeGroupBackups")},
			"oci_core_volume_groups":                                            {Tok: makeDataSource(ociMod, "GetCoreVolumeGroups")},
			"oci_core_volumes":                                                  {Tok: makeDataSource(ociMod, "GetCoreVolumes")},
			"oci_data_safe_data_safe_configuration":                             {Tok: makeDataSource(ociMod, "GetDataSafeDataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint":                          {Tok: makeDataSource(ociMod, "GetDataSafeDataSafePrivateEndpoint")},
			"oci_data_safe_data_safe_private_endpoints":                         {Tok: makeDataSource(ociMod, "GetDataSafeDataSafePrivateEndpoints")},
			"oci_data_safe_on_prem_connector":                                   {Tok: makeDataSource(ociMod, "GetDataSafeOnPremConnector")},
			"oci_data_safe_on_prem_connectors":                                  {Tok: makeDataSource(ociMod, "GetDataSafeOnPremConnectors")},
			"oci_data_safe_target_database":                                     {Tok: makeDataSource(ociMod, "GetDataSafeTargetDatabase")},
			"oci_data_safe_target_databases":                                    {Tok: makeDataSource(ociMod, "GetDataSafeTargetDatabases")},
			"oci_database_autonomous_container_database":                        {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association":  {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousContainerDatabaseDataguardAssociation")},
			"oci_database_autonomous_container_database_dataguard_associations": {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousContainerDatabaseDataguardAssociations")},
			"oci_database_autonomous_container_databases":                       {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousContainerDatabases")},
			"oci_database_autonomous_container_patches":                         {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousContainerPatches")},
			"oci_database_autonomous_database":                                  {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabase")},
			"oci_database_autonomous_database_backup":                           {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseBackup")},
			"oci_database_autonomous_database_backups":                          {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseBackups")},
			"oci_database_autonomous_database_dataguard_association":            {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseDataguardAssociation")},
			"oci_database_autonomous_database_dataguard_associations":           {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseDataguardAssociations")},
			"oci_database_autonomous_database_instance_wallet_management":       {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_regional_wallet_management":       {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                           {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabaseWallet")},
			"oci_database_autonomous_databases":                                 {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabases")},
			"oci_database_autonomous_databases_clones":                          {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDatabasesClones")},
			"oci_database_autonomous_db_preview_versions":                       {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDbPreviewVersions")},
			"oci_database_autonomous_db_versions":                               {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousDbVersions")},
			"oci_database_autonomous_exadata_infrastructure":                    {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousExadataInfrastructure")},
			"oci_database_autonomous_exadata_infrastructure_ocpu":               {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousExadataInfrastructureOcpu")},
			"oci_database_autonomous_exadata_infrastructure_shapes":             {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousExadataInfrastructureShapes")},
			"oci_database_autonomous_exadata_infrastructures":                   {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousExadataInfrastructures")},
			"oci_database_autonomous_patch":                                     {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousPatch")},
			"oci_database_autonomous_vm_cluster":                                {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousVmCluster")},
			"oci_database_autonomous_vm_clusters":                               {Tok: makeDataSource(ociMod, "GetDatabaseAutonomousVmClusters")},
			"oci_database_backup_destination":                                   {Tok: makeDataSource(ociMod, "GetDatabaseBackupDestination")},
			"oci_database_backup_destinations":                                  {Tok: makeDataSource(ociMod, "GetDatabaseBackupDestinations")},
			"oci_database_backups":                                              {Tok: makeDataSource(ociMod, "GetDatabaseBackups")},
			"oci_database_cloud_exadata_infrastructure":                         {Tok: makeDataSource(ociMod, "GetDatabaseCloudExadataInfrastructure")},
			"oci_database_cloud_exadata_infrastructures":                        {Tok: makeDataSource(ociMod, "GetDatabaseCloudExadataInfrastructures")},
			"oci_database_cloud_vm_cluster":                                     {Tok: makeDataSource(ociMod, "GetDatabaseCloudVmCluster")},
			"oci_database_cloud_vm_clusters":                                    {Tok: makeDataSource(ociMod, "GetDatabaseCloudVmClusters")},
			"oci_database_data_guard_association":                               {Tok: makeDataSource(ociMod, "GetDatabaseDataGuardAssociation")},
			"oci_database_data_guard_associations":                              {Tok: makeDataSource(ociMod, "GetDatabaseDataGuardAssociations")},
			"oci_database_database":                                             {Tok: makeDataSource(ociMod, "GetDatabaseDatabase")},
			"oci_database_database_software_image":                              {Tok: makeDataSource(ociMod, "GetDatabaseDatabaseSoftwareImage")},
			"oci_database_database_software_images":                             {Tok: makeDataSource(ociMod, "GetDatabaseDatabaseSoftwareImages")},
			"oci_database_database_upgrade_history_entries":                     {Tok: makeDataSource(ociMod, "GetDatabaseDatabaseUpgradeHistoryEntries")},
			"oci_database_database_upgrade_history_entry":                       {Tok: makeDataSource(ociMod, "GetDatabaseDatabaseUpgradeHistoryEntry")},
			"oci_database_databases":                                            {Tok: makeDataSource(ociMod, "GetDatabaseDatabases")},
			"oci_database_db_home":                                              {Tok: makeDataSource(ociMod, "GetDatabaseDbHome")},
			"oci_database_db_home_patch_history_entries":                        {Tok: makeDataSource(ociMod, "GetDatabaseDbHomePatchHistoryEntries")},
			"oci_database_db_home_patches":                                      {Tok: makeDataSource(ociMod, "GetDatabaseDbHomePatches")},
			"oci_database_db_homes":                                             {Tok: makeDataSource(ociMod, "GetDatabaseDbHomes")},
			"oci_database_db_node":                                              {Tok: makeDataSource(ociMod, "GetDatabaseDbNode")},
			"oci_database_db_node_console_connection":                           {Tok: makeDataSource(ociMod, "GetDatabaseDbNodeConsoleConnection")},
			"oci_database_db_node_console_connections":                          {Tok: makeDataSource(ociMod, "GetDatabaseDbNodeConsoleConnections")},
			"oci_database_db_nodes":                                             {Tok: makeDataSource(ociMod, "GetDatabaseDbNodes")},
			"oci_database_db_system_patch_history_entries":                      {Tok: makeDataSource(ociMod, "GetDatabaseDbSystemPatchHistoryEntries")},
			"oci_database_db_system_patches":                                    {Tok: makeDataSource(ociMod, "GetDatabaseDbSystemPatches")},
			"oci_database_db_system_shapes":                                     {Tok: makeDataSource(ociMod, "GetDatabaseDbSystemShapes")},
			"oci_database_db_systems":                                           {Tok: makeDataSource(ociMod, "GetDatabaseDbSystems")},
			"oci_database_db_versions":                                          {Tok: makeDataSource(ociMod, "GetDatabaseDbVersions")},
			"oci_database_exadata_infrastructure":                               {Tok: makeDataSource(ociMod, "GetDatabaseExadataInfrastructure")},
			"oci_database_exadata_infrastructure_download_config_file":          {Tok: makeDataSource(ociMod, "GetDatabaseExadataInfrastructureDownloadConfigFile")},
			"oci_database_exadata_infrastructures":                              {Tok: makeDataSource(ociMod, "GetDatabaseExadataInfrastructures")},
			"oci_database_exadata_iorm_config":                                  {Tok: makeDataSource(ociMod, "GetDatabaseExadataIormConfig")},
			"oci_database_external_container_database":                          {Tok: makeDataSource(ociMod, "GetDatabaseExternalContainerDatabase")},
			"oci_database_external_container_databases":                         {Tok: makeDataSource(ociMod, "GetDatabaseExternalContainerDatabases")},
			"oci_database_external_database_connector":                          {Tok: makeDataSource(ociMod, "GetDatabaseExternalDatabaseConnector")},
			"oci_database_external_database_connectors":                         {Tok: makeDataSource(ociMod, "GetDatabaseExternalDatabaseConnectors")},
			"oci_database_external_non_container_database":                      {Tok: makeDataSource(ociMod, "GetDatabaseExternalNonContainerDatabase")},
			"oci_database_external_non_container_databases":                     {Tok: makeDataSource(ociMod, "GetDatabaseExternalNonContainerDatabases")},
			"oci_database_external_pluggable_database":                          {Tok: makeDataSource(ociMod, "GetDatabaseExternalPluggableDatabase")},
			"oci_database_external_pluggable_databases":                         {Tok: makeDataSource(ociMod, "GetDatabaseExternalPluggableDatabases")},
			"oci_database_flex_components":                                      {Tok: makeDataSource(ociMod, "GetDatabaseFlexComponents")},
			"oci_database_gi_versions":                                          {Tok: makeDataSource(ociMod, "GetDatabaseGiVersions")},
			"oci_database_key_store":                                            {Tok: makeDataSource(ociMod, "GetDatabaseKeyStore")},
			"oci_database_key_stores":                                           {Tok: makeDataSource(ociMod, "GetDatabaseKeyStores")},
			"oci_database_maintenance_run":                                      {Tok: makeDataSource(ociMod, "GetDatabaseMaintenanceRun")},
			"oci_database_maintenance_runs":                                     {Tok: makeDataSource(ociMod, "GetDatabaseMaintenanceRuns")},
			"oci_database_management_managed_database":                          {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabase")},
			"oci_database_management_managed_database_group":                    {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabaseGroup")},
			"oci_database_management_managed_database_groups":                   {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabaseGroups")},
			"oci_database_management_managed_databases":                         {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabases")},
			"oci_database_management_managed_databases_database_parameter":      {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabasesDatabaseParameter")},
			"oci_database_management_managed_databases_database_parameters":     {Tok: makeDataSource(ociMod, "GetDatabaseManagementManagedDatabasesDatabaseParameters")},
			"oci_database_migration_agent":                                      {Tok: makeDataSource(ociMod, "GetDatabaseMigrationAgent")},
			"oci_database_migration_agent_images":                               {Tok: makeDataSource(ociMod, "GetDatabaseMigrationAgentImages")},
			"oci_database_migration_agents":                                     {Tok: makeDataSource(ociMod, "GetDatabaseMigrationAgents")},
			"oci_database_migration_connection":                                 {Tok: makeDataSource(ociMod, "GetDatabaseMigrationConnection")},
			"oci_database_migration_connections":                                {Tok: makeDataSource(ociMod, "GetDatabaseMigrationConnections")},
			"oci_database_migration_job":                                        {Tok: makeDataSource(ociMod, "GetDatabaseMigrationJob")},
			"oci_database_migration_jobs":                                       {Tok: makeDataSource(ociMod, "GetDatabaseMigrationJobs")},
			"oci_database_migration_migration":                                  {Tok: makeDataSource(ociMod, "GetDatabaseMigrationMigration")},
			"oci_database_migration_migrations":                                 {Tok: makeDataSource(ociMod, "GetDatabaseMigrationMigrations")},
			"oci_database_pluggable_database":                                   {Tok: makeDataSource(ociMod, "GetDatabasePluggableDatabase")},
			"oci_database_pluggable_databases":                                  {Tok: makeDataSource(ociMod, "GetDatabasePluggableDatabases")},
			"oci_database_vm_cluster":                                           {Tok: makeDataSource(ociMod, "GetDatabaseVmCluster")},
			"oci_database_vm_cluster_network":                                   {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterNetwork")},
			"oci_database_vm_cluster_network_download_config_file":              {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterNetworkDownloadConfigFile")},
			"oci_database_vm_cluster_networks":                                  {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterNetworks")},
			"oci_database_vm_cluster_patch":                                     {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterPatch")},
			"oci_database_vm_cluster_patch_history_entries":                     {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterPatchHistoryEntries")},
			"oci_database_vm_cluster_patch_history_entry":                       {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterPatchHistoryEntry")},
			"oci_database_vm_cluster_patches":                                   {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterPatches")},
			"oci_database_vm_cluster_recommended_network":                       {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterRecommendedNetwork")},
			"oci_database_vm_cluster_update":                                    {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterUpdate")},
			"oci_database_vm_cluster_update_history_entries":                    {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterUpdateHistoryEntries")},
			"oci_database_vm_cluster_update_history_entry":                      {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterUpdateHistoryEntry")},
			"oci_database_vm_cluster_updates":                                   {Tok: makeDataSource(ociMod, "GetDatabaseVmClusterUpdates")},
			"oci_database_vm_clusters":                                          {Tok: makeDataSource(ociMod, "GetDatabaseVmClusters")},
			"oci_datacatalog_catalog":                                           {Tok: makeDataSource(ociMod, "GetDatacatalogCatalog")},
			"oci_datacatalog_catalog_private_endpoint":                          {Tok: makeDataSource(ociMod, "GetDatacatalogCatalogPrivateEndpoint")},
			"oci_datacatalog_catalog_private_endpoints":                         {Tok: makeDataSource(ociMod, "GetDatacatalogCatalogPrivateEndpoints")},
			"oci_datacatalog_catalog_type":                                      {Tok: makeDataSource(ociMod, "GetDatacatalogCatalogType")},
			"oci_datacatalog_catalog_types":                                     {Tok: makeDataSource(ociMod, "GetDatacatalogCatalogTypes")},
			"oci_datacatalog_catalogs":                                          {Tok: makeDataSource(ociMod, "GetDatacatalogCatalogs")},
			"oci_datacatalog_connection":                                        {Tok: makeDataSource(ociMod, "GetDatacatalogConnection")},
			"oci_datacatalog_connections":                                       {Tok: makeDataSource(ociMod, "GetDatacatalogConnections")},
			"oci_datacatalog_data_asset":                                        {Tok: makeDataSource(ociMod, "GetDatacatalogDataAsset")},
			"oci_datacatalog_data_assets":                                       {Tok: makeDataSource(ociMod, "GetDatacatalogDataAssets")},
			"oci_datacatalog_metastore":                                         {Tok: makeDataSource(ociMod, "GetDatacatalogMetastore")},
			"oci_datacatalog_metastores":                                        {Tok: makeDataSource(ociMod, "GetDatacatalogMetastores")},
			"oci_dataflow_application":                                          {Tok: makeDataSource(ociMod, "GetDataflowApplication")},
			"oci_dataflow_applications":                                         {Tok: makeDataSource(ociMod, "GetDataflowApplications")},
			"oci_dataflow_invoke_run":                                           {Tok: makeDataSource(ociMod, "GetDataflowInvokeRun")},
			"oci_dataflow_invoke_runs":                                          {Tok: makeDataSource(ociMod, "GetDataflowInvokeRuns")},
			"oci_dataflow_private_endpoint":                                     {Tok: makeDataSource(ociMod, "GetDataflowPrivateEndpoint")},
			"oci_dataflow_private_endpoints":                                    {Tok: makeDataSource(ociMod, "GetDataflowPrivateEndpoints")},
			"oci_dataflow_run_log":                                              {Tok: makeDataSource(ociMod, "GetDataflowRunLog")},
			"oci_dataflow_run_logs":                                             {Tok: makeDataSource(ociMod, "GetDataflowRunLogs")},
			"oci_dataintegration_workspace":                                     {Tok: makeDataSource(ociMod, "GetDataintegrationWorkspace")},
			"oci_dataintegration_workspaces":                                    {Tok: makeDataSource(ociMod, "GetDataintegrationWorkspaces")},
			"oci_datascience_model":                                             {Tok: makeDataSource(ociMod, "GetDatascienceModel")},
			"oci_datascience_model_deployment":                                  {Tok: makeDataSource(ociMod, "GetDatascienceModelDeployment")},
			"oci_datascience_model_deployment_shapes":                           {Tok: makeDataSource(ociMod, "GetDatascienceModelDeploymentShapes")},
			"oci_datascience_model_deployments":                                 {Tok: makeDataSource(ociMod, "GetDatascienceModelDeployments")},
			"oci_datascience_model_provenance":                                  {Tok: makeDataSource(ociMod, "GetDatascienceModelProvenance")},
			"oci_datascience_models":                                            {Tok: makeDataSource(ociMod, "GetDatascienceModels")},
			"oci_datascience_notebook_session":                                  {Tok: makeDataSource(ociMod, "GetDatascienceNotebookSession")},
			"oci_datascience_notebook_session_shapes":                           {Tok: makeDataSource(ociMod, "GetDatascienceNotebookSessionShapes")},
			"oci_datascience_notebook_sessions":                                 {Tok: makeDataSource(ociMod, "GetDatascienceNotebookSessions")},
			"oci_datascience_project":                                           {Tok: makeDataSource(ociMod, "GetDatascienceProject")},
			"oci_datascience_projects":                                          {Tok: makeDataSource(ociMod, "GetDatascienceProjects")},
			"oci_devops_deploy_artifact":                                        {Tok: makeDataSource(ociMod, "GetDevopsDeployArtifact")},
			"oci_devops_deploy_artifacts":                                       {Tok: makeDataSource(ociMod, "GetDevopsDeployArtifacts")},
			"oci_devops_deploy_environment":                                     {Tok: makeDataSource(ociMod, "GetDevopsDeployEnvironment")},
			"oci_devops_deploy_environments":                                    {Tok: makeDataSource(ociMod, "GetDevopsDeployEnvironments")},
			"oci_devops_deploy_pipeline":                                        {Tok: makeDataSource(ociMod, "GetDevopsDeployPipeline")},
			"oci_devops_deploy_pipelines":                                       {Tok: makeDataSource(ociMod, "GetDevopsDeployPipelines")},
			"oci_devops_deploy_stage":                                           {Tok: makeDataSource(ociMod, "GetDevopsDeployStage")},
			"oci_devops_deploy_stages":                                          {Tok: makeDataSource(ociMod, "GetDevopsDeployStages")},
			"oci_devops_deployment":                                             {Tok: makeDataSource(ociMod, "GetDevopsDeployment")},
			"oci_devops_deployments":                                            {Tok: makeDataSource(ociMod, "GetDevopsDeployments")},
			"oci_devops_project":                                                {Tok: makeDataSource(ociMod, "GetDevopsProject")},
			"oci_devops_projects":                                               {Tok: makeDataSource(ociMod, "GetDevopsProjects")},
			"oci_dns_records":                                                   {Tok: makeDataSource(ociMod, "GetDnsRecords")},
			"oci_dns_resolver":                                                  {Tok: makeDataSource(ociMod, "GetDnsResolver")},
			"oci_dns_resolver_endpoint":                                         {Tok: makeDataSource(ociMod, "GetDnsResolverEndpoint")},
			"oci_dns_resolver_endpoints":                                        {Tok: makeDataSource(ociMod, "GetDnsResolverEndpoints")},
			"oci_dns_resolvers":                                                 {Tok: makeDataSource(ociMod, "GetDnsResolvers")},
			"oci_dns_rrset":                                                     {Tok: makeDataSource(ociMod, "GetDnsRrset")},
			"oci_dns_steering_policies":                                         {Tok: makeDataSource(ociMod, "GetDnsSteeringPolicies")},
			"oci_dns_steering_policy":                                           {Tok: makeDataSource(ociMod, "GetDnsSteeringPolicy")},
			"oci_dns_steering_policy_attachment":                                {Tok: makeDataSource(ociMod, "GetDnsSteeringPolicyAttachment")},
			"oci_dns_steering_policy_attachments":                               {Tok: makeDataSource(ociMod, "GetDnsSteeringPolicyAttachments")},
			"oci_dns_tsig_key":                                                  {Tok: makeDataSource(ociMod, "GetDnsTsigKey")},
			"oci_dns_tsig_keys":                                                 {Tok: makeDataSource(ociMod, "GetDnsTsigKeys")},
			"oci_dns_view":                                                      {Tok: makeDataSource(ociMod, "GetDnsView")},
			"oci_dns_views":                                                     {Tok: makeDataSource(ociMod, "GetDnsViews")},
			"oci_dns_zones":                                                     {Tok: makeDataSource(ociMod, "GetDnsZones")},
			"oci_email_dkim":                                                    {Tok: makeDataSource(ociMod, "GetEmailDkim")},
			"oci_email_dkims":                                                   {Tok: makeDataSource(ociMod, "GetEmailDkims")},
			"oci_email_email_domain":                                            {Tok: makeDataSource(ociMod, "GetEmailEmailDomain")},
			"oci_email_email_domains":                                           {Tok: makeDataSource(ociMod, "GetEmailEmailDomains")},
			"oci_email_sender":                                                  {Tok: makeDataSource(ociMod, "GetEmailSender")},
			"oci_email_senders":                                                 {Tok: makeDataSource(ociMod, "GetEmailSenders")},
			"oci_email_suppression":                                             {Tok: makeDataSource(ociMod, "GetEmailSuppression")},
			"oci_email_suppressions":                                            {Tok: makeDataSource(ociMod, "GetEmailSuppressions")},
			"oci_events_rule":                                                   {Tok: makeDataSource(ociMod, "GetEventsRule")},
			"oci_events_rules":                                                  {Tok: makeDataSource(ociMod, "GetEventsRules")},
			"oci_file_storage_export_sets":                                      {Tok: makeDataSource(ociMod, "GetFileStorageExportSets")},
			"oci_file_storage_exports":                                          {Tok: makeDataSource(ociMod, "GetFileStorageExports")},
			"oci_file_storage_file_systems":                                     {Tok: makeDataSource(ociMod, "GetFileStorageFileSystems")},
			"oci_file_storage_mount_targets":                                    {Tok: makeDataSource(ociMod, "GetFileStorageMountTargets")},
			"oci_file_storage_snapshot":                                         {Tok: makeDataSource(ociMod, "GetFileStorageSnapshot")},
			"oci_file_storage_snapshots":                                        {Tok: makeDataSource(ociMod, "GetFileStorageSnapshots")},
			"oci_functions_application":                                         {Tok: makeDataSource(ociMod, "GetFunctionsApplication")},
			"oci_functions_applications":                                        {Tok: makeDataSource(ociMod, "GetFunctionsApplications")},
			"oci_functions_function":                                            {Tok: makeDataSource(ociMod, "GetFunctionsFunction")},
			"oci_functions_functions":                                           {Tok: makeDataSource(ociMod, "GetFunctionsFunctions")},
			"oci_generic_artifacts_content_artifact_by_path":                    {Tok: makeDataSource(ociMod, "GetGenericArtifactsContentArtifactByPath")},
			"oci_generic_artifacts_content_generic_artifacts_content":           {Tok: makeDataSource(ociMod, "GetGenericArtifactsContentGenericArtifactsContent")},
			"oci_golden_gate_database_registration":                             {Tok: makeDataSource(ociMod, "GetGoldenGateDatabaseRegistration")},
			"oci_golden_gate_database_registrations":                            {Tok: makeDataSource(ociMod, "GetGoldenGateDatabaseRegistrations")},
			"oci_golden_gate_deployment":                                        {Tok: makeDataSource(ociMod, "GetGoldenGateDeployment")},
			"oci_golden_gate_deployment_backup":                                 {Tok: makeDataSource(ociMod, "GetGoldenGateDeploymentBackup")},
			"oci_golden_gate_deployment_backups":                                {Tok: makeDataSource(ociMod, "GetGoldenGateDeploymentBackups")},
			"oci_golden_gate_deployments":                                       {Tok: makeDataSource(ociMod, "GetGoldenGateDeployments")},
			"oci_health_checks_http_monitor":                                    {Tok: makeDataSource(ociMod, "GetHealthChecksHttpMonitor")},
			"oci_health_checks_http_monitors":                                   {Tok: makeDataSource(ociMod, "GetHealthChecksHttpMonitors")},
			"oci_health_checks_http_probe_results":                              {Tok: makeDataSource(ociMod, "GetHealthChecksHttpProbeResults")},
			"oci_health_checks_ping_monitor":                                    {Tok: makeDataSource(ociMod, "GetHealthChecksPingMonitor")},
			"oci_health_checks_ping_monitors":                                   {Tok: makeDataSource(ociMod, "GetHealthChecksPingMonitors")},
			"oci_health_checks_ping_probe_results":                              {Tok: makeDataSource(ociMod, "GetHealthChecksPingProbeResults")},
			"oci_health_checks_vantage_points":                                  {Tok: makeDataSource(ociMod, "GetHealthChecksVantagePoints")},
			"oci_identity_api_keys":                                             {Tok: makeDataSource(ociMod, "GetIdentityApiKeys")},
			"oci_identity_auth_tokens":                                          {Tok: makeDataSource(ociMod, "GetIdentityAuthTokens")},
			"oci_identity_authentication_policy":                                {Tok: makeDataSource(ociMod, "GetIdentityAuthenticationPolicy")},
			"oci_identity_availability_domain":                                  {Tok: makeDataSource(ociMod, "GetIdentityAvailabilityDomain")},
			"oci_identity_availability_domains":                                 {Tok: makeDataSource(ociMod, "GetIdentityAvailabilityDomains")},
			"oci_identity_compartment":                                          {Tok: makeDataSource(ociMod, "GetIdentityCompartment")},
			"oci_identity_compartments":                                         {Tok: makeDataSource(ociMod, "GetIdentityCompartments")},
			"oci_identity_cost_tracking_tags":                                   {Tok: makeDataSource(ociMod, "GetIdentityCostTrackingTags")},
			"oci_identity_customer_secret_keys":                                 {Tok: makeDataSource(ociMod, "GetIdentityCustomerSecretKeys")},
			"oci_identity_dynamic_groups":                                       {Tok: makeDataSource(ociMod, "GetIdentityDynamicGroups")},
			"oci_identity_fault_domains":                                        {Tok: makeDataSource(ociMod, "GetIdentityFaultDomains")},
			"oci_identity_group":                                                {Tok: makeDataSource(ociMod, "GetIdentityGroup")},
			"oci_identity_groups":                                               {Tok: makeDataSource(ociMod, "GetIdentityGroups")},
			"oci_identity_identity_provider_groups":                             {Tok: makeDataSource(ociMod, "GetIdentityIdentityProviderGroups")},
			"oci_identity_identity_providers":                                   {Tok: makeDataSource(ociMod, "GetIdentityIdentityProviders")},
			"oci_identity_idp_group_mappings":                                   {Tok: makeDataSource(ociMod, "GetIdentityIdpGroupMappings")},
			"oci_identity_network_source":                                       {Tok: makeDataSource(ociMod, "GetIdentityNetworkSource")},
			"oci_identity_network_sources":                                      {Tok: makeDataSource(ociMod, "GetIdentityNetworkSources")},
			"oci_identity_policies":                                             {Tok: makeDataSource(ociMod, "GetIdentityPolicies")},
			"oci_identity_region_subscriptions":                                 {Tok: makeDataSource(ociMod, "GetIdentityRegionSubscriptions")},
			"oci_identity_regions":                                              {Tok: makeDataSource(ociMod, "GetIdentityRegions")},
			"oci_identity_smtp_credentials":                                     {Tok: makeDataSource(ociMod, "GetIdentitySmtpCredentials")},
			"oci_identity_swift_passwords":                                      {Tok: makeDataSource(ociMod, "GetIdentitySwiftPasswords")},
			"oci_identity_tag":                                                  {Tok: makeDataSource(ociMod, "GetIdentityTag")},
			"oci_identity_tag_default":                                          {Tok: makeDataSource(ociMod, "GetIdentityTagDefault")},
			"oci_identity_tag_defaults":                                         {Tok: makeDataSource(ociMod, "GetIdentityTagDefaults")},
			"oci_identity_tag_namespaces":                                       {Tok: makeDataSource(ociMod, "GetIdentityTagNamespaces")},
			"oci_identity_tags":                                                 {Tok: makeDataSource(ociMod, "GetIdentityTags")},
			"oci_identity_tenancy":                                              {Tok: makeDataSource(ociMod, "GetIdentityTenancy")},
			"oci_identity_ui_password":                                          {Tok: makeDataSource(ociMod, "GetIdentityUiPassword")},
			"oci_identity_user":                                                 {Tok: makeDataSource(ociMod, "GetIdentityUser")},
			"oci_identity_user_group_memberships":                               {Tok: makeDataSource(ociMod, "GetIdentityUserGroupMemberships")},
			"oci_identity_users":                                                {Tok: makeDataSource(ociMod, "GetIdentityUsers")},
			"oci_integration_integration_instance":                              {Tok: makeDataSource(ociMod, "GetIntegrationIntegrationInstance")},
			"oci_integration_integration_instances":                             {Tok: makeDataSource(ociMod, "GetIntegrationIntegrationInstances")},
			"oci_jms_fleet":                                                     {Tok: makeDataSource(ociMod, "GetJmsFleet")},
			"oci_jms_fleets":                                                    {Tok: makeDataSource(ociMod, "GetJmsFleets")},
			"oci_kms_decrypted_data":                                            {Tok: makeDataSource(ociMod, "GetKmsDecryptedData")},
			"oci_kms_encrypted_data":                                            {Tok: makeDataSource(ociMod, "GetKmsEncryptedData")},
			"oci_kms_key":                                                       {Tok: makeDataSource(ociMod, "GetKmsKey")},
			"oci_kms_key_version":                                               {Tok: makeDataSource(ociMod, "GetKmsKeyVersion")},
			"oci_kms_key_versions":                                              {Tok: makeDataSource(ociMod, "GetKmsKeyVersions")},
			"oci_kms_keys":                                                      {Tok: makeDataSource(ociMod, "GetKmsKeys")},
			"oci_kms_replication_status":                                        {Tok: makeDataSource(ociMod, "GetKmsReplicationStatus")},
			"oci_kms_vault":                                                     {Tok: makeDataSource(ociMod, "GetKmsVault")},
			"oci_kms_vault_replicas":                                            {Tok: makeDataSource(ociMod, "GetKmsVaultReplicas")},
			"oci_kms_vault_usage":                                               {Tok: makeDataSource(ociMod, "GetKmsVaultUsage")},
			"oci_kms_vaults":                                                    {Tok: makeDataSource(ociMod, "GetKmsVaults")},
			"oci_limits_limit_definitions":                                      {Tok: makeDataSource(ociMod, "GetLimitsLimitDefinitions")},
			"oci_limits_limit_values":                                           {Tok: makeDataSource(ociMod, "GetLimitsLimitValues")},
			"oci_limits_quota":                                                  {Tok: makeDataSource(ociMod, "GetLimitsQuota")},
			"oci_limits_quotas":                                                 {Tok: makeDataSource(ociMod, "GetLimitsQuotas")},
			"oci_limits_resource_availability":                                  {Tok: makeDataSource(ociMod, "GetLimitsResourceAvailability")},
			"oci_limits_services":                                               {Tok: makeDataSource(ociMod, "GetLimitsServices")},
			"oci_load_balancer_backend_health":                                  {Tok: makeDataSource(ociMod, "GetLoadBalancerBackendHealth")},
			"oci_load_balancer_backend_set_health":                              {Tok: makeDataSource(ociMod, "GetLoadBalancerBackendSetHealth")},
			"oci_load_balancer_backend_sets":                                    {Tok: makeDataSource(ociMod, "GetLoadBalancerBackendSets")},
			"oci_load_balancer_backends":                                        {Tok: makeDataSource(ociMod, "GetLoadBalancerBackends")},
			//"oci_load_balancer_backendsets":                                     {Tok: makeDataSource(ociMod, "GetLoadBalancerBackendsets")},
			"oci_load_balancer_certificates":                             {Tok: makeDataSource(ociMod, "GetLoadBalancerCertificates")},
			"oci_load_balancer_health":                                   {Tok: makeDataSource(ociMod, "GetLoadBalancerHealth")},
			"oci_load_balancer_hostnames":                                {Tok: makeDataSource(ociMod, "GetLoadBalancerHostnames")},
			"oci_load_balancer_listener_rules":                           {Tok: makeDataSource(ociMod, "GetLoadBalancerListenerRules")},
			"oci_load_balancer_load_balancer_routing_policies":           {Tok: makeDataSource(ociMod, "GetLoadBalancerLoadBalancerRoutingPolicies")},
			"oci_load_balancer_load_balancer_routing_policy":             {Tok: makeDataSource(ociMod, "GetLoadBalancerLoadBalancerRoutingPolicy")},
			"oci_load_balancer_load_balancers":                           {Tok: makeDataSource(ociMod, "GetLoadBalancerLoadBalancers")},
			"oci_load_balancer_path_route_sets":                          {Tok: makeDataSource(ociMod, "GetLoadBalancerPathRouteSets")},
			"oci_load_balancer_policies":                                 {Tok: makeDataSource(ociMod, "GetLoadBalancerPolicies")},
			"oci_load_balancer_protocols":                                {Tok: makeDataSource(ociMod, "GetLoadBalancerProtocols")},
			"oci_load_balancer_rule_set":                                 {Tok: makeDataSource(ociMod, "GetLoadBalancerRuleSet")},
			"oci_load_balancer_rule_sets":                                {Tok: makeDataSource(ociMod, "GetLoadBalancerRuleSets")},
			"oci_load_balancer_shapes":                                   {Tok: makeDataSource(ociMod, "GetLoadBalancerShapes")},
			"oci_load_balancer_ssl_cipher_suite":                         {Tok: makeDataSource(ociMod, "GetLoadBalancerSslCipherSuite")},
			"oci_load_balancer_ssl_cipher_suites":                        {Tok: makeDataSource(ociMod, "GetLoadBalancerSslCipherSuites")},
			"oci_load_balancers":                                         {Tok: makeDataSource(ociMod, "GetLoadBalancers")},
			"oci_log_analytics_log_analytics_entities":                   {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsEntities")},
			"oci_log_analytics_log_analytics_entities_summary":           {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsEntitiesSummary")},
			"oci_log_analytics_log_analytics_entity":                     {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_log_group":                  {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_log_groups":                 {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsLogGroups")},
			"oci_log_analytics_log_analytics_log_groups_summary":         {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsLogGroupsSummary")},
			"oci_log_analytics_log_analytics_object_collection_rule":     {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_log_analytics_object_collection_rules":    {Tok: makeDataSource(ociMod, "GetLogAnalyticsLogAnalyticsObjectCollectionRules")},
			"oci_log_analytics_namespace":                                {Tok: makeDataSource(ociMod, "GetLogAnalyticsNamespace")},
			"oci_log_analytics_namespaces":                               {Tok: makeDataSource(ociMod, "GetLogAnalyticsNamespaces")},
			"oci_logging_log":                                            {Tok: makeDataSource(ociMod, "GetLoggingLog")},
			"oci_logging_log_group":                                      {Tok: makeDataSource(ociMod, "GetLoggingLogGroup")},
			"oci_logging_log_groups":                                     {Tok: makeDataSource(ociMod, "GetLoggingLogGroups")},
			"oci_logging_log_saved_search":                               {Tok: makeDataSource(ociMod, "GetLoggingLogSavedSearch")},
			"oci_logging_log_saved_searches":                             {Tok: makeDataSource(ociMod, "GetLoggingLogSavedSearches")},
			"oci_logging_logs":                                           {Tok: makeDataSource(ociMod, "GetLoggingLogs")},
			"oci_logging_unified_agent_configuration":                    {Tok: makeDataSource(ociMod, "GetLoggingUnifiedAgentConfiguration")},
			"oci_logging_unified_agent_configurations":                   {Tok: makeDataSource(ociMod, "GetLoggingUnifiedAgentConfigurations")},
			"oci_management_agent_management_agent":                      {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgent")},
			"oci_management_agent_management_agent_available_histories":  {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgentAvailableHistories")},
			"oci_management_agent_management_agent_images":               {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgentImages")},
			"oci_management_agent_management_agent_install_key":          {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgentInstallKey")},
			"oci_management_agent_management_agent_install_keys":         {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgentInstallKeys")},
			"oci_management_agent_management_agent_plugins":              {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgentPlugins")},
			"oci_management_agent_management_agents":                     {Tok: makeDataSource(ociMod, "GetManagementAgentManagementAgents")},
			"oci_management_dashboard_management_dashboards_export":      {Tok: makeDataSource(ociMod, "GetManagementDashboardManagementDashboardsExport")},
			"oci_marketplace_accepted_agreement":                         {Tok: makeDataSource(ociMod, "GetMarketplaceAcceptedAgreement")},
			"oci_marketplace_accepted_agreements":                        {Tok: makeDataSource(ociMod, "GetMarketplaceAcceptedAgreements")},
			"oci_marketplace_categories":                                 {Tok: makeDataSource(ociMod, "GetMarketplaceCategories")},
			"oci_marketplace_listing":                                    {Tok: makeDataSource(ociMod, "GetMarketplaceListing")},
			"oci_marketplace_listing_package":                            {Tok: makeDataSource(ociMod, "GetMarketplaceListingPackage")},
			"oci_marketplace_listing_package_agreements":                 {Tok: makeDataSource(ociMod, "GetMarketplaceListingPackageAgreements")},
			"oci_marketplace_listing_packages":                           {Tok: makeDataSource(ociMod, "GetMarketplaceListingPackages")},
			"oci_marketplace_listing_taxes":                              {Tok: makeDataSource(ociMod, "GetMarketplaceListingTaxes")},
			"oci_marketplace_listings":                                   {Tok: makeDataSource(ociMod, "GetMarketplaceListings")},
			"oci_marketplace_publication":                                {Tok: makeDataSource(ociMod, "GetMarketplacePublication")},
			"oci_marketplace_publication_package":                        {Tok: makeDataSource(ociMod, "GetMarketplacePublicationPackage")},
			"oci_marketplace_publication_packages":                       {Tok: makeDataSource(ociMod, "GetMarketplacePublicationPackages")},
			"oci_marketplace_publications":                               {Tok: makeDataSource(ociMod, "GetMarketplacePublications")},
			"oci_marketplace_publishers":                                 {Tok: makeDataSource(ociMod, "GetMarketplacePublishers")},
			"oci_metering_computation_configuration":                     {Tok: makeDataSource(ociMod, "GetMeteringComputationConfiguration")},
			"oci_metering_computation_custom_table":                      {Tok: makeDataSource(ociMod, "GetMeteringComputationCustomTable")},
			"oci_metering_computation_custom_tables":                     {Tok: makeDataSource(ociMod, "GetMeteringComputationCustomTables")},
			"oci_metering_computation_queries":                           {Tok: makeDataSource(ociMod, "GetMeteringComputationQueries")},
			"oci_metering_computation_query":                             {Tok: makeDataSource(ociMod, "GetMeteringComputationQuery")},
			"oci_monitoring_alarm":                                       {Tok: makeDataSource(ociMod, "GetMonitoringAlarm")},
			"oci_monitoring_alarm_history_collection":                    {Tok: makeDataSource(ociMod, "GetMonitoringAlarmHistoryCollection")},
			"oci_monitoring_alarm_statuses":                              {Tok: makeDataSource(ociMod, "GetMonitoringAlarmStatuses")},
			"oci_monitoring_alarms":                                      {Tok: makeDataSource(ociMod, "GetMonitoringAlarms")},
			"oci_monitoring_metric_data":                                 {Tok: makeDataSource(ociMod, "GetMonitoringMetricData")},
			"oci_monitoring_metrics":                                     {Tok: makeDataSource(ociMod, "GetMonitoringMetrics")},
			"oci_mysql_analytics_cluster":                                {Tok: makeDataSource(ociMod, "GetMysqlAnalyticsCluster")},
			"oci_mysql_channel":                                          {Tok: makeDataSource(ociMod, "GetMysqlChannel")},
			"oci_mysql_channels":                                         {Tok: makeDataSource(ociMod, "GetMysqlChannels")},
			"oci_mysql_heat_wave_cluster":                                {Tok: makeDataSource(ociMod, "GetMysqlHeatWaveCluster")},
			"oci_mysql_mysql_backup":                                     {Tok: makeDataSource(ociMod, "GetMysqlMysqlBackup")},
			"oci_mysql_mysql_backups":                                    {Tok: makeDataSource(ociMod, "GetMysqlMysqlBackups")},
			"oci_mysql_mysql_configuration":                              {Tok: makeDataSource(ociMod, "GetMysqlMysqlConfiguration")},
			"oci_mysql_mysql_configurations":                             {Tok: makeDataSource(ociMod, "GetMysqlMysqlConfigurations")},
			"oci_mysql_mysql_db_system":                                  {Tok: makeDataSource(ociMod, "GetMysqlMysqlDbSystem")},
			"oci_mysql_mysql_db_systems":                                 {Tok: makeDataSource(ociMod, "GetMysqlMysqlDbSystems")},
			"oci_mysql_mysql_versions":                                   {Tok: makeDataSource(ociMod, "GetMysqlMysqlVersions")},
			"oci_mysql_shapes":                                           {Tok: makeDataSource(ociMod, "GetMysqlShapes")},
			"oci_network_load_balancer_backend_health":                   {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerBackendHealth")},
			"oci_network_load_balancer_backend_set":                      {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerBackendSet")},
			"oci_network_load_balancer_backend_set_health":               {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerBackendSetHealth")},
			"oci_network_load_balancer_backend_sets":                     {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerBackendSets")},
			"oci_network_load_balancer_backends":                         {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerBackends")},
			"oci_network_load_balancer_listener":                         {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerListener")},
			"oci_network_load_balancer_listeners":                        {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerListeners")},
			"oci_network_load_balancer_network_load_balancer":            {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerNetworkLoadBalancer")},
			"oci_network_load_balancer_network_load_balancer_health":     {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerNetworkLoadBalancerHealth")},
			"oci_network_load_balancer_network_load_balancers":           {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerNetworkLoadBalancers")},
			"oci_network_load_balancer_network_load_balancers_policies":  {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerNetworkLoadBalancersPolicies")},
			"oci_network_load_balancer_network_load_balancers_protocols": {Tok: makeDataSource(ociMod, "GetNetworkLoadBalancerNetworkLoadBalancersProtocols")},
			"oci_nosql_index":                                            {Tok: makeDataSource(ociMod, "GetNosqlIndex")},
			"oci_nosql_indexes":                                          {Tok: makeDataSource(ociMod, "GetNosqlIndexes")},
			"oci_nosql_table":                                            {Tok: makeDataSource(ociMod, "GetNosqlTable")},
			"oci_nosql_tables":                                           {Tok: makeDataSource(ociMod, "GetNosqlTables")},
			"oci_objectstorage_bucket":                                   {Tok: makeDataSource(ociMod, "GetObjectstorageBucket")},
			"oci_objectstorage_bucket_summaries":                         {Tok: makeDataSource(ociMod, "GetObjectstorageBucketSummaries")},
			"oci_objectstorage_namespace":                                {Tok: makeDataSource(ociMod, "GetObjectstorageNamespace")},
			"oci_objectstorage_namespace_metadata":                       {Tok: makeDataSource(ociMod, "GetObjectstorageNamespaceMetadata")},
			"oci_objectstorage_object":                                   {Tok: makeDataSource(ociMod, "GetObjectstorageObject")},
			"oci_objectstorage_object_head":                              {Tok: makeDataSource(ociMod, "GetObjectstorageObjectHead")},
			"oci_objectstorage_object_lifecycle_policy":                  {Tok: makeDataSource(ociMod, "GetObjectstorageObjectLifecyclePolicy")},
			"oci_objectstorage_object_versions":                          {Tok: makeDataSource(ociMod, "GetObjectstorageObjectVersions")},
			"oci_objectstorage_objects":                                  {Tok: makeDataSource(ociMod, "GetObjectstorageObjects")},
			"oci_objectstorage_preauthrequest":                           {Tok: makeDataSource(ociMod, "GetObjectstoragePreauthrequest")},
			"oci_objectstorage_preauthrequests":                          {Tok: makeDataSource(ociMod, "GetObjectstoragePreauthrequests")},
			"oci_objectstorage_replication_policies":                     {Tok: makeDataSource(ociMod, "GetObjectstorageReplicationPolicies")},
			"oci_objectstorage_replication_policy":                       {Tok: makeDataSource(ociMod, "GetObjectstorageReplicationPolicy")},
			"oci_objectstorage_replication_sources":                      {Tok: makeDataSource(ociMod, "GetObjectstorageReplicationSources")},
			"oci_oce_oce_instance":                                       {Tok: makeDataSource(ociMod, "GetOceOceInstance")},
			"oci_oce_oce_instances":                                      {Tok: makeDataSource(ociMod, "GetOceOceInstances")},
			"oci_ocvp_esxi_host":                                         {Tok: makeDataSource(ociMod, "GetOcvpEsxiHost")},
			"oci_ocvp_esxi_hosts":                                        {Tok: makeDataSource(ociMod, "GetOcvpEsxiHosts")},
			"oci_ocvp_sddc":                                              {Tok: makeDataSource(ociMod, "GetOcvpSddc")},
			"oci_ocvp_sddcs":                                             {Tok: makeDataSource(ociMod, "GetOcvpSddcs")},
			"oci_ocvp_supported_skus":                                    {Tok: makeDataSource(ociMod, "GetOcvpSupportedSkus")},
			"oci_ocvp_supported_vmware_software_versions":                {Tok: makeDataSource(ociMod, "GetOcvpSupportedVmwareSoftwareVersions")},
			"oci_oda_oda_instance":                                       {Tok: makeDataSource(ociMod, "GetOdaOdaInstance")},
			"oci_oda_oda_instances":                                      {Tok: makeDataSource(ociMod, "GetOdaOdaInstances")},
			"oci_ons_notification_topic":                                 {Tok: makeDataSource(ociMod, "GetOnsNotificationTopic")},
			"oci_ons_notification_topics":                                {Tok: makeDataSource(ociMod, "GetOnsNotificationTopics")},
			"oci_ons_subscription":                                       {Tok: makeDataSource(ociMod, "GetOnsSubscription")},
			"oci_ons_subscriptions":                                      {Tok: makeDataSource(ociMod, "GetOnsSubscriptions")},
			"oci_opsi_database_insight":                                  {Tok: makeDataSource(ociMod, "GetOpsiDatabaseInsight")},
			"oci_opsi_database_insights":                                 {Tok: makeDataSource(ociMod, "GetOpsiDatabaseInsights")},
			"oci_opsi_enterprise_manager_bridge":                         {Tok: makeDataSource(ociMod, "GetOpsiEnterpriseManagerBridge")},
			"oci_opsi_enterprise_manager_bridges":                        {Tok: makeDataSource(ociMod, "GetOpsiEnterpriseManagerBridges")},
			"oci_opsi_host_insight":                                      {Tok: makeDataSource(ociMod, "GetOpsiHostInsight")},
			"oci_opsi_host_insights":                                     {Tok: makeDataSource(ociMod, "GetOpsiHostInsights")},
			"oci_optimizer_categories":                                   {Tok: makeDataSource(ociMod, "GetOptimizerCategories")},
			"oci_optimizer_category":                                     {Tok: makeDataSource(ociMod, "GetOptimizerCategory")},
			"oci_optimizer_enrollment_status":                            {Tok: makeDataSource(ociMod, "GetOptimizerEnrollmentStatus")},
			"oci_optimizer_enrollment_statuses":                          {Tok: makeDataSource(ociMod, "GetOptimizerEnrollmentStatuses")},
			"oci_optimizer_histories":                                    {Tok: makeDataSource(ociMod, "GetOptimizerHistories")},
			"oci_optimizer_profile":                                      {Tok: makeDataSource(ociMod, "GetOptimizerProfile")},
			"oci_optimizer_profiles":                                     {Tok: makeDataSource(ociMod, "GetOptimizerProfiles")},
			"oci_optimizer_recommendation":                               {Tok: makeDataSource(ociMod, "GetOptimizerRecommendation")},
			//"oci_optimizer_recommendation_strategies":                           {Tok: makeDataSource(ociMod, "GetOptimizerRecommendationStrategies")},
			//"oci_optimizer_recommendation_strategy":                             {Tok: makeDataSource(ociMod, "GetOptimizerRecommendationStrategy")},
			"oci_optimizer_recommendations":                    {Tok: makeDataSource(ociMod, "GetOptimizerRecommendations")},
			"oci_optimizer_resource_action":                    {Tok: makeDataSource(ociMod, "GetOptimizerResourceAction")},
			"oci_optimizer_resource_actions":                   {Tok: makeDataSource(ociMod, "GetOptimizerResourceActions")},
			"oci_osmanagement_managed_instance":                {Tok: makeDataSource(ociMod, "GetOsmanagementManagedInstance")},
			"oci_osmanagement_managed_instance_group":          {Tok: makeDataSource(ociMod, "GetOsmanagementManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_groups":         {Tok: makeDataSource(ociMod, "GetOsmanagementManagedInstanceGroups")},
			"oci_osmanagement_managed_instances":               {Tok: makeDataSource(ociMod, "GetOsmanagementManagedInstances")},
			"oci_osmanagement_software_source":                 {Tok: makeDataSource(ociMod, "GetOsmanagementSoftwareSource")},
			"oci_osmanagement_software_sources":                {Tok: makeDataSource(ociMod, "GetOsmanagementSoftwareSources")},
			"oci_resourcemanager_stack":                        {Tok: makeDataSource(ociMod, "GetResourcemanagerStack")},
			"oci_resourcemanager_stack_tf_state":               {Tok: makeDataSource(ociMod, "GetResourcemanagerStackTfState")},
			"oci_resourcemanager_stacks":                       {Tok: makeDataSource(ociMod, "GetResourcemanagerStacks")},
			"oci_sch_service_connector":                        {Tok: makeDataSource(ociMod, "GetSchServiceConnector")},
			"oci_sch_service_connectors":                       {Tok: makeDataSource(ociMod, "GetSchServiceConnectors")},
			"oci_service_catalog_private_application":          {Tok: makeDataSource(ociMod, "GetServiceCatalogPrivateApplication")},
			"oci_service_catalog_private_application_package":  {Tok: makeDataSource(ociMod, "GetServiceCatalogPrivateApplicationPackage")},
			"oci_service_catalog_private_application_packages": {Tok: makeDataSource(ociMod, "GetServiceCatalogPrivateApplicationPackages")},
			"oci_service_catalog_private_applications":         {Tok: makeDataSource(ociMod, "GetServiceCatalogPrivateApplications")},
			"oci_service_catalog_service_catalog":              {Tok: makeDataSource(ociMod, "GetServiceCatalogServiceCatalog")},
			"oci_service_catalog_service_catalog_association":  {Tok: makeDataSource(ociMod, "GetServiceCatalogServiceCatalogAssociation")},
			"oci_service_catalog_service_catalog_associations": {Tok: makeDataSource(ociMod, "GetServiceCatalogServiceCatalogAssociations")},
			"oci_service_catalog_service_catalogs":             {Tok: makeDataSource(ociMod, "GetServiceCatalogServiceCatalogs")},
			"oci_streaming_connect_harness":                    {Tok: makeDataSource(ociMod, "GetStreamingConnectHarness")},
			"oci_streaming_connect_harnesses":                  {Tok: makeDataSource(ociMod, "GetStreamingConnectHarnesses")},
			"oci_streaming_stream":                             {Tok: makeDataSource(ociMod, "GetStreamingStream")},
			"oci_streaming_stream_pool":                        {Tok: makeDataSource(ociMod, "GetStreamingStreamPool")},
			"oci_streaming_stream_pools":                       {Tok: makeDataSource(ociMod, "GetStreamingStreamPools")},
			"oci_streaming_streams":                            {Tok: makeDataSource(ociMod, "GetStreamingStreams")},
			"oci_vault_secret":                                 {Tok: makeDataSource(ociMod, "GetVaultSecret")},
			"oci_vault_secret_version":                         {Tok: makeDataSource(ociMod, "GetVaultSecretVersion")},
			"oci_vault_secrets":                                {Tok: makeDataSource(ociMod, "GetVaultSecrets")},
			"oci_vulnerability_scanning_host_scan_recipe":      {Tok: makeDataSource(ociMod, "GetVulnerabilityScanningHostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_recipes":     {Tok: makeDataSource(ociMod, "GetVulnerabilityScanningHostScanRecipes")},
			"oci_vulnerability_scanning_host_scan_target":      {Tok: makeDataSource(ociMod, "GetVulnerabilityScanningHostScanTarget")},
			"oci_vulnerability_scanning_host_scan_targets":     {Tok: makeDataSource(ociMod, "GetVulnerabilityScanningHostScanTargets")},
			"oci_waas_address_list":                            {Tok: makeDataSource(ociMod, "GetWaasAddressList")},
			"oci_waas_address_lists":                           {Tok: makeDataSource(ociMod, "GetWaasAddressLists")},
			"oci_waas_certificate":                             {Tok: makeDataSource(ociMod, "GetWaasCertificate")},
			"oci_waas_certificates":                            {Tok: makeDataSource(ociMod, "GetWaasCertificates")},
			"oci_waas_custom_protection_rule":                  {Tok: makeDataSource(ociMod, "GetWaasCustomProtectionRule")},
			"oci_waas_custom_protection_rules":                 {Tok: makeDataSource(ociMod, "GetWaasCustomProtectionRules")},
			"oci_waas_edge_subnets":                            {Tok: makeDataSource(ociMod, "GetWaasEdgeSubnets")},
			"oci_waas_http_redirect":                           {Tok: makeDataSource(ociMod, "GetWaasHttpRedirect")},
			"oci_waas_http_redirects":                          {Tok: makeDataSource(ociMod, "GetWaasHttpRedirects")},
			"oci_waas_protection_rule":                         {Tok: makeDataSource(ociMod, "GetWaasProtectionRule")},
			"oci_waas_protection_rules":                        {Tok: makeDataSource(ociMod, "GetWaasProtectionRules")},
			"oci_waas_waas_policies":                           {Tok: makeDataSource(ociMod, "GetWaasWaasPolicies")},
			"oci_waas_waas_policy":                             {Tok: makeDataSource(ociMod, "GetWaasWaasPolicy")},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			// List any npm dependencies and their versions
			Dependencies: map[string]string{
				"@pulumi/pulumi": "^3.0.0",
			},
			DevDependencies: map[string]string{
				"@types/node": "^10.0.0", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			// See the documentation for tfbridge.OverlayInfo for how to lay out this
			// section, or refer to the AWS provider. Delete this section if there are
			// no overlay files.
			//Overlay: &tfbridge.OverlayInfo{},
		},
		Python: &tfbridge.PythonInfo{
			// List any Python dependencies and their version ranges
			Requires: map[string]string{
				"pulumi": ">=3.0.0,<4.0.0",
			},
		},
		Golang: &tfbridge.GolangInfo{
			ImportBasePath: filepath.Join(
				fmt.Sprintf("github.com/pulumi/pulumi-%[1]s/sdk/", ociPkg),
				tfbridge.GetModuleMajorVersion(version.Version),
				"go",
				ociPkg,
			),
			GenerateResourceContainerTypes: true,
		},
		CSharp: &tfbridge.CSharpInfo{
			PackageReferences: map[string]string{
				"Pulumi":                       "3.*",
				"System.Collections.Immutable": "1.6.0",
			},
			Namespaces: namespaceMap,
		},
	}

	prov.SetAutonaming(255, "-")

	return prov
}
