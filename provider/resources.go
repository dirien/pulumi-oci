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
			// Ai Anomaly Detection
			"oci_ai_anomaly_detection_ai_private_endpoint":  {Tok: makeDataSource(aiAnomalyDetectionMod, "getAiPrivateEndpoint")},
			"oci_ai_anomaly_detection_ai_private_endpoints": {Tok: makeDataSource(aiAnomalyDetectionMod, "getAiPrivateEndpoints")},
			"oci_ai_anomaly_detection_data_asset":           {Tok: makeDataSource(aiAnomalyDetectionMod, "getDataAsset")},
			"oci_ai_anomaly_detection_data_assets":          {Tok: makeDataSource(aiAnomalyDetectionMod, "getDataAssets")},
			"oci_ai_anomaly_detection_model":                {Tok: makeDataSource(aiAnomalyDetectionMod, "getModel")},
			"oci_ai_anomaly_detection_models":               {Tok: makeDataSource(aiAnomalyDetectionMod, "getModels")},
			"oci_ai_anomaly_detection_project":              {Tok: makeDataSource(aiAnomalyDetectionMod, "getProject")},
			"oci_ai_anomaly_detection_projects":             {Tok: makeDataSource(aiAnomalyDetectionMod, "getProjects")},
			// Analytics
			"oci_analytics_analytics_instance":                        {Tok: makeDataSource(analyticsMod, "getAnalyticsInstance")},
			"oci_analytics_analytics_instance_private_access_channel": {Tok: makeDataSource(analyticsMod, "getAnalyticsInstancePrivateAccessChannel")},
			"oci_analytics_analytics_instances":                       {Tok: makeDataSource(analyticsMod, "getAnalyticsInstances")},
			// API Gateway
			"oci_apigateway_api":                          {Tok: makeDataSource(apiGatewayMod, "getApi")},
			"oci_apigateway_api_content":                  {Tok: makeDataSource(apiGatewayMod, "getApiContent")},
			"oci_apigateway_api_deployment_specification": {Tok: makeDataSource(apiGatewayMod, "getApiDeploymentSpecification")},
			"oci_apigateway_api_validation":               {Tok: makeDataSource(apiGatewayMod, "getApiValidation")},
			"oci_apigateway_apis":                         {Tok: makeDataSource(apiGatewayMod, "getApis")},
			"oci_apigateway_certificate":                  {Tok: makeDataSource(apiGatewayMod, "getCertificate")},
			"oci_apigateway_certificates":                 {Tok: makeDataSource(apiGatewayMod, "getCertificates")},
			"oci_apigateway_deployment":                   {Tok: makeDataSource(apiGatewayMod, "getDeployment")},
			"oci_apigateway_deployments":                  {Tok: makeDataSource(apiGatewayMod, "getDeployments")},
			"oci_apigateway_gateway":                      {Tok: makeDataSource(apiGatewayMod, "getGateway")},
			"oci_apigateway_gateways":                     {Tok: makeDataSource(apiGatewayMod, "getGateways")},
			// Apm Synthetics
			"oci_apm_synthetics_monitor":               {Tok: makeDataSource(apmSyntheticsMod, "getMonitor")},
			"oci_apm_synthetics_monitors":              {Tok: makeDataSource(apmSyntheticsMod, "getMonitors")},
			"oci_apm_synthetics_public_vantage_point":  {Tok: makeDataSource(apmSyntheticsMod, "getPublicVantagePoint")},
			"oci_apm_synthetics_public_vantage_points": {Tok: makeDataSource(apmSyntheticsMod, "getPublicVantagePoints")},
			"oci_apm_synthetics_result":                {Tok: makeDataSource(apmSyntheticsMod, "getResult")},
			"oci_apm_synthetics_script":                {Tok: makeDataSource(apmSyntheticsMod, "getScript")},
			"oci_apm_synthetics_scripts":               {Tok: makeDataSource(apmSyntheticsMod, "getScripts")},
			// APM
			"oci_apm_apm_domain":  {Tok: makeDataSource(apmMod, "getApmDomain")},
			"oci_apm_apm_domains": {Tok: makeDataSource(apmMod, "getApmDomains")},
			"oci_apm_data_keys":   {Tok: makeDataSource(apmMod, "getDataKeys")},
			// Artifacts
			"oci_artifacts_container_configuration":    {Tok: makeDataSource(artifactsMod, "getContainerConfiguration")},
			"oci_artifacts_container_image":            {Tok: makeDataSource(artifactsMod, "getContainerImage")},
			"oci_artifacts_container_image_signature":  {Tok: makeDataSource(artifactsMod, "getContainerImageSignature")},
			"oci_artifacts_container_image_signatures": {Tok: makeDataSource(artifactsMod, "getContainerImageSignatures")},
			"oci_artifacts_container_images":           {Tok: makeDataSource(artifactsMod, "getContainerImages")},
			"oci_artifacts_container_repositories":     {Tok: makeDataSource(artifactsMod, "getContainerRepositories")},
			"oci_artifacts_container_repository":       {Tok: makeDataSource(artifactsMod, "getContainerRepository")},
			"oci_artifacts_generic_artifact":           {Tok: makeDataSource(artifactsMod, "getGenericArtifact")},
			"oci_artifacts_generic_artifacts":          {Tok: makeDataSource(artifactsMod, "getGenericArtifacts")},
			"oci_artifacts_repositories":               {Tok: makeDataSource(artifactsMod, "getRepositories")},
			"oci_artifacts_repository":                 {Tok: makeDataSource(artifactsMod, "getRepository")},
			// Audit
			"oci_audit_configuration": {Tok: makeDataSource(auditMod, "getConfiguration")},
			"oci_audit_events":        {Tok: makeDataSource(auditMod, "getEvents")},
			// AutoScaling
			"oci_autoscaling_auto_scaling_configuration":  {Tok: makeDataSource(autoscalingMod, "getAutoScalingConfiguration")},
			"oci_autoscaling_auto_scaling_configurations": {Tok: makeDataSource(autoscalingMod, "getAutoScalingConfigurations")},
			// Bastion
			"oci_bastion_bastion":  {Tok: makeDataSource(bastionMod, "getBastion")},
			"oci_bastion_bastions": {Tok: makeDataSource(bastionMod, "getBastions")},
			"oci_bastion_session":  {Tok: makeDataSource(bastionMod, "getSession")},
			"oci_bastion_sessions": {Tok: makeDataSource(bastionMod, "getSessions")},
			// BDS
			"oci_bds_auto_scaling_configuration": {Tok: makeDataSource(bdsMod, "getAutoScalingConfiguration")},
			"oci_bds_bds_instance":               {Tok: makeDataSource(bdsMod, "getBdsInstance")},
			"oci_bds_bds_instances":              {Tok: makeDataSource(bdsMod, "getBdsInstances")},
			// Blockchain
			"oci_blockchain_blockchain_platform":  {Tok: makeDataSource(blockchainMod, "getBlockchainPlatform")},
			"oci_blockchain_blockchain_platforms": {Tok: makeDataSource(blockchainMod, "getBlockchainPlatforms")},
			"oci_blockchain_osn":                  {Tok: makeDataSource(blockchainMod, "getOsn")},
			"oci_blockchain_osns":                 {Tok: makeDataSource(blockchainMod, "getOsns")},
			"oci_blockchain_peer":                 {Tok: makeDataSource(blockchainMod, "getPeer")},
			"oci_blockchain_peers":                {Tok: makeDataSource(blockchainMod, "getPeers")},
			// Budget
			"oci_budget_alert_rule":  {Tok: makeDataSource(budgetMod, "getAlertRule")},
			"oci_budget_alert_rules": {Tok: makeDataSource(budgetMod, "getAlertRules")},
			"oci_budget_budget":      {Tok: makeDataSource(budgetMod, "getBudget")},
			"oci_budget_budgets":     {Tok: makeDataSource(budgetMod, "getBudgets")},
			// Cloud Guard
			"oci_cloud_guard_cloud_guard_configuration": {Tok: makeDataSource(cloudGuardMod, "getCloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":            {Tok: makeDataSource(cloudGuardMod, "getDataMaskRule")},
			"oci_cloud_guard_data_mask_rules":           {Tok: makeDataSource(cloudGuardMod, "getDataMaskRules")},
			"oci_cloud_guard_detector_recipe":           {Tok: makeDataSource(cloudGuardMod, "getDetectorRecipe")},
			"oci_cloud_guard_detector_recipes":          {Tok: makeDataSource(cloudGuardMod, "getDetectorRecipes")},
			"oci_cloud_guard_managed_list":              {Tok: makeDataSource(cloudGuardMod, "getManagedList")},
			"oci_cloud_guard_managed_lists":             {Tok: makeDataSource(cloudGuardMod, "getManagedLists")},
			"oci_cloud_guard_responder_recipe":          {Tok: makeDataSource(cloudGuardMod, "getResponderRecipe")},
			"oci_cloud_guard_responder_recipes":         {Tok: makeDataSource(cloudGuardMod, "getResponderRecipes")},
			"oci_cloud_guard_target":                    {Tok: makeDataSource(cloudGuardMod, "getTarget")},
			"oci_cloud_guard_targets":                   {Tok: makeDataSource(cloudGuardMod, "getTargets")},
			// Compute Instance Agent
			"oci_computeinstanceagent_instance_available_plugins": {Tok: makeDataSource(computeInstanceAgentMod, "getInstanceAvailablePlugins")},
			"oci_computeinstanceagent_instance_agent_plugins":     {Tok: makeDataSource(computeInstanceAgentMod, "getInstanceAgentPlugins")},
			"oci_computeinstanceagent_instance_agent_plugin":      {Tok: makeDataSource(computeInstanceAgentMod, "getInstanceAgentPlugin")},
			// Container Engine
			"oci_containerengine_cluster_kube_config":      {Tok: makeDataSource(containerEngineMod, "getClusterKubeConfig")},
			"oci_containerengine_cluster_option":           {Tok: makeDataSource(containerEngineMod, "getClusterOption")},
			"oci_containerengine_clusters":                 {Tok: makeDataSource(containerEngineMod, "getClusters")},
			"oci_containerengine_node_pool":                {Tok: makeDataSource(containerEngineMod, "getNodePool")},
			"oci_containerengine_node_pool_option":         {Tok: makeDataSource(containerEngineMod, "getNodePoolOption")},
			"oci_containerengine_node_pools":               {Tok: makeDataSource(containerEngineMod, "getNodePools")},
			"oci_containerengine_work_request_errors":      {Tok: makeDataSource(containerEngineMod, "getWorkRequestErrors")},
			"oci_containerengine_work_request_log_entries": {Tok: makeDataSource(containerEngineMod, "getWorkRequestLogEntries")},
			"oci_containerengine_work_requests":            {Tok: makeDataSource(containerEngineMod, "getWorkRequests")},
			// OCE
			"oci_oce_oce_instance":  {Tok: makeDataSource(oceMod, "getOceInstance")},
			"oci_oce_oce_instances": {Tok: makeDataSource(oceMod, "getOceInstances")},
			// Core
			"oci_core_app_catalog_listing":                              {Tok: makeDataSource(coreMod, "getAppCatalogListing")},
			"oci_core_app_catalog_listing_resource_version":             {Tok: makeDataSource(coreMod, "getAppCatalogListingResourceVersion")},
			"oci_core_app_catalog_listing_resource_versions":            {Tok: makeDataSource(coreMod, "getAppCatalogListingResourceVersions")},
			"oci_core_app_catalog_listings":                             {Tok: makeDataSource(coreMod, "getAppCatalogListings")},
			"oci_core_app_catalog_subscriptions":                        {Tok: makeDataSource(coreMod, "getAppCatalogSubscriptions")},
			"oci_core_block_volume_replica":                             {Tok: makeDataSource(coreMod, "getBlockVolumeReplica")},
			"oci_core_block_volume_replicas":                            {Tok: makeDataSource(coreMod, "getBlockVolumeReplicas")},
			"oci_core_boot_volume":                                      {Tok: makeDataSource(coreMod, "getBootVolume")},
			"oci_core_boot_volume_attachments":                          {Tok: makeDataSource(coreMod, "getBootVolumeAttachments")},
			"oci_core_boot_volume_backup":                               {Tok: makeDataSource(coreMod, "getBootVolumeBackup")},
			"oci_core_boot_volume_backups":                              {Tok: makeDataSource(coreMod, "getBootVolumeBackups")},
			"oci_core_boot_volume_replica":                              {Tok: makeDataSource(coreMod, "getBootVolumeReplica")},
			"oci_core_boot_volume_replicas":                             {Tok: makeDataSource(coreMod, "getBootVolumeReplicas")},
			"oci_core_boot_volumes":                                     {Tok: makeDataSource(coreMod, "getBootVolumes")},
			"oci_core_byoip_allocated_ranges":                           {Tok: makeDataSource(coreMod, "getByoipAllocatedRanges")},
			"oci_core_byoip_range":                                      {Tok: makeDataSource(coreMod, "getByoipRange")},
			"oci_core_byoip_ranges":                                     {Tok: makeDataSource(coreMod, "getByoipRanges")},
			"oci_core_cluster_network":                                  {Tok: makeDataSource(coreMod, "getClusterNetwork")},
			"oci_core_cluster_network_instances":                        {Tok: makeDataSource(coreMod, "getClusterNetworkInstances")},
			"oci_core_cluster_networks":                                 {Tok: makeDataSource(coreMod, "getClusterNetworks")},
			"oci_core_compute_capacity_reservation":                     {Tok: makeDataSource(coreMod, "getComputeCapacityReservation")},
			"oci_core_compute_capacity_reservation_instance_shapes":     {Tok: makeDataSource(coreMod, "getComputeCapacityReservationInstanceShapes")},
			"oci_core_compute_capacity_reservation_instances":           {Tok: makeDataSource(coreMod, "getComputeCapacityReservationInstances")},
			"oci_core_compute_capacity_reservations":                    {Tok: makeDataSource(coreMod, "getComputeCapacityReservations")},
			"oci_core_compute_global_image_capability_schema":           {Tok: makeDataSource(coreMod, "getComputeGlobalImageCapabilitySchema")},
			"oci_core_compute_global_image_capability_schemas":          {Tok: makeDataSource(coreMod, "getComputeGlobalImageCapabilitySchemas")},
			"oci_core_compute_global_image_capability_schemas_version":  {Tok: makeDataSource(coreMod, "getComputeGlobalImageCapabilitySchemasVersion")},
			"oci_core_compute_global_image_capability_schemas_versions": {Tok: makeDataSource(coreMod, "getComputeGlobalImageCapabilitySchemasVersions")},
			"oci_core_compute_image_capability_schema":                  {Tok: makeDataSource(coreMod, "getComputeImageCapabilitySchema")},
			"oci_core_compute_image_capability_schemas":                 {Tok: makeDataSource(coreMod, "getComputeImageCapabilitySchemas")},
			"oci_core_console_histories":                                {Tok: makeDataSource(coreMod, "getConsoleHistories")},
			"oci_core_console_history_data":                             {Tok: makeDataSource(coreMod, "getConsoleHistoryData")},
			"oci_core_cpe_device_shape":                                 {Tok: makeDataSource(coreMod, "getCpeDeviceShape")},
			"oci_core_cpe_device_shapes":                                {Tok: makeDataSource(coreMod, "getCpeDeviceShapes")},
			"oci_core_cpes":                                             {Tok: makeDataSource(coreMod, "getCpes")},
			"oci_core_cross_connect":                                    {Tok: makeDataSource(coreMod, "getCrossConnect")},
			"oci_core_cross_connect_group":                              {Tok: makeDataSource(coreMod, "getCrossConnectGroup")},
			"oci_core_cross_connect_groups":                             {Tok: makeDataSource(coreMod, "getCrossConnectGroups")},
			"oci_core_cross_connect_locations":                          {Tok: makeDataSource(coreMod, "getCrossConnectLocations")},
			"oci_core_cross_connect_port_speed_shapes":                  {Tok: makeDataSource(coreMod, "getCrossConnectPortSpeedShapes")},
			"oci_core_cross_connect_status":                             {Tok: makeDataSource(coreMod, "getCrossConnectStatus")},
			"oci_core_cross_connects":                                   {Tok: makeDataSource(coreMod, "getCrossConnects")},
			"oci_core_dedicated_vm_host":                                {Tok: makeDataSource(coreMod, "getDedicatedVmHost")},
			"oci_core_dedicated_vm_host_instance_shapes":                {Tok: makeDataSource(coreMod, "getDedicatedVmHostInstanceShapes")},
			"oci_core_dedicated_vm_host_shapes":                         {Tok: makeDataSource(coreMod, "getDedicatedVmHostShapes")},
			"oci_core_dedicated_vm_hosts":                               {Tok: makeDataSource(coreMod, "getDedicatedVmHosts")},
			"oci_core_dedicated_vm_hosts_instances":                     {Tok: makeDataSource(coreMod, "getDedicatedVmHostsInstances")},
			"oci_core_dhcp_options":                                     {Tok: makeDataSource(coreMod, "getDhcpOptions")},
			"oci_core_drg_attachments":                                  {Tok: makeDataSource(coreMod, "getDrgAttachments")},
			"oci_core_drg_route_distribution":                           {Tok: makeDataSource(coreMod, "getDrgRouteDistribution")},
			"oci_core_drg_route_distribution_statements":                {Tok: makeDataSource(coreMod, "getDrgRouteDistributionStatements")},
			"oci_core_drg_route_distributions":                          {Tok: makeDataSource(coreMod, "getDrgRouteDistributions")},
			"oci_core_drg_route_table":                                  {Tok: makeDataSource(coreMod, "getDrgRouteTable")},
			"oci_core_drg_route_table_route_rules":                      {Tok: makeDataSource(coreMod, "getDrgRouteTableRouteRules")},
			"oci_core_drg_route_tables":                                 {Tok: makeDataSource(coreMod, "getDrgRouteTables")},
			"oci_core_drgs":                                             {Tok: makeDataSource(coreMod, "getDrgs")},
			"oci_core_fast_connect_provider_service":                    {Tok: makeDataSource(coreMod, "getFastConnectProviderService")},
			"oci_core_fast_connect_provider_service_key":                {Tok: makeDataSource(coreMod, "getFastConnectProviderServiceKey")},
			"oci_core_fast_connect_provider_services":                   {Tok: makeDataSource(coreMod, "getFastConnectProviderServices")},
			"oci_core_image":                                            {Tok: makeDataSource(coreMod, "getImage")},
			"oci_core_image_shape":                                      {Tok: makeDataSource(coreMod, "getImageShape")},
			"oci_core_image_shapes":                                     {Tok: makeDataSource(coreMod, "getImageShapes")},
			"oci_core_images":                                           {Tok: makeDataSource(coreMod, "getImages")},
			"oci_core_instance":                                         {Tok: makeDataSource(coreMod, "getInstance")},
			"oci_core_instance_configuration":                           {Tok: makeDataSource(coreMod, "getInstanceConfiguration")},
			"oci_core_instance_configurations":                          {Tok: makeDataSource(coreMod, "getInstanceConfigurations")},
			"oci_core_instance_console_connections":                     {Tok: makeDataSource(coreMod, "getInstanceConsoleConnections")},
			"oci_core_instance_credentials":                             {Tok: makeDataSource(coreMod, "getInstanceCredentials")},
			"oci_core_instance_devices":                                 {Tok: makeDataSource(coreMod, "getInstanceDevices")},
			"oci_core_instance_pool":                                    {Tok: makeDataSource(coreMod, "getInstancePool")},
			"oci_core_instance_pool_instances":                          {Tok: makeDataSource(coreMod, "getInstancePoolInstances")},
			"oci_core_instance_pool_load_balancer_attachment":           {Tok: makeDataSource(coreMod, "getInstancePoolLoadBalancerAttachment")},
			"oci_core_instance_pools":                                   {Tok: makeDataSource(coreMod, "getInstancePools")},
			"oci_core_instances":                                        {Tok: makeDataSource(coreMod, "getInstances")},
			"oci_core_internet_gateways":                                {Tok: makeDataSource(coreMod, "getInternetGateways")},
			"oci_core_ipsec_config":                                     {Tok: makeDataSource(coreMod, "getIpsecConfig")},
			"oci_core_ipsec_connection_tunnel":                          {Tok: makeDataSource(coreMod, "getIpsecConnectionTunnel")},
			"oci_core_ipsec_connection_tunnels":                         {Tok: makeDataSource(coreMod, "getIpsecConnectionTunnels")},
			"oci_core_ipsec_connections":                                {Tok: makeDataSource(coreMod, "getIpsecConnections")},
			"oci_core_ipsec_status":                                     {Tok: makeDataSource(coreMod, "getIpsecStatus")},
			"oci_core_ipv6":                                             {Tok: makeDataSource(coreMod, "getIpv6")},
			"oci_core_ipv6s":                                            {Tok: makeDataSource(coreMod, "getIpv6s")},
			"oci_core_letter_of_authority":                              {Tok: makeDataSource(coreMod, "getLetterOfAuthority")},
			"oci_core_local_peering_gateways":                           {Tok: makeDataSource(coreMod, "getLocalPeeringGateways")},
			"oci_core_nat_gateway":                                      {Tok: makeDataSource(coreMod, "getNatGateway")},
			"oci_core_nat_gateways":                                     {Tok: makeDataSource(coreMod, "getNatGateways")},
			"oci_core_network_security_group":                           {Tok: makeDataSource(coreMod, "getNetworkSecurityGroup")},
			"oci_core_network_security_group_security_rules":            {Tok: makeDataSource(coreMod, "getNetworkSecurityGroupSecurityRules")},
			"oci_core_network_security_group_vnics":                     {Tok: makeDataSource(coreMod, "getNetworkSecurityGroupVnics")},
			"oci_core_network_security_groups":                          {Tok: makeDataSource(coreMod, "getNetworkSecurityGroups")},
			"oci_core_peer_region_for_remote_peerings":                  {Tok: makeDataSource(coreMod, "getPeerRegionForRemotePeerings")},
			"oci_core_private_ip":                                       {Tok: makeDataSource(coreMod, "getPrivateIp")},
			"oci_core_private_ips":                                      {Tok: makeDataSource(coreMod, "getPrivateIps")},
			"oci_core_public_ip":                                        {Tok: makeDataSource(coreMod, "getPublicIp")},
			"oci_core_public_ip_pool":                                   {Tok: makeDataSource(coreMod, "getPublicIpPool")},
			"oci_core_public_ip_pools":                                  {Tok: makeDataSource(coreMod, "getPublicIpPools")},
			"oci_core_public_ips":                                       {Tok: makeDataSource(coreMod, "getPublicIps")},
			"oci_core_remote_peering_connections":                       {Tok: makeDataSource(coreMod, "getRemotePeeringConnections")},
			"oci_core_route_tables":                                     {Tok: makeDataSource(coreMod, "getRouteTables")},
			"oci_core_security_lists":                                   {Tok: makeDataSource(coreMod, "getSecurityLists")},
			"oci_core_service_gateways":                                 {Tok: makeDataSource(coreMod, "getServiceGateways")},
			"oci_core_services":                                         {Tok: makeDataSource(coreMod, "getServices")},
			"oci_core_shapes":                                           {Tok: makeDataSource(coreMod, "getShapes")},
			"oci_core_subnet":                                           {Tok: makeDataSource(coreMod, "getSubnet")},
			"oci_core_subnets":                                          {Tok: makeDataSource(coreMod, "getSubnets")},
			"oci_core_vcn":                                              {Tok: makeDataSource(coreMod, "getVcn")},
			"oci_core_vcn_dns_resolver_association":                     {Tok: makeDataSource(coreMod, "getVcnDnsResolverAssociation")},
			"oci_core_vcns":                                             {Tok: makeDataSource(coreMod, "getVcns")},
			"oci_core_virtual_circuit":                                  {Tok: makeDataSource(coreMod, "getVirtualCircuit")},
			"oci_core_virtual_circuit_bandwidth_shapes":                 {Tok: makeDataSource(coreMod, "getVirtualCircuitBandwidthShapes")},
			"oci_core_virtual_circuit_public_prefixes":                  {Tok: makeDataSource(coreMod, "getVirtualCircuitPublicPrefixes")},
			"oci_core_virtual_circuits":                                 {Tok: makeDataSource(coreMod, "getVirtualCircuits")},
			"oci_core_vlan":                                             {Tok: makeDataSource(coreMod, "getVlan")},
			"oci_core_vlans":                                            {Tok: makeDataSource(coreMod, "getVlans")},
			"oci_core_vnic":                                             {Tok: makeDataSource(coreMod, "getVnic")},
			"oci_core_vnic_attachments":                                 {Tok: makeDataSource(coreMod, "getVnicAttachments")},
			"oci_core_volume":                                           {Tok: makeDataSource(coreMod, "getVolume")},
			"oci_core_volume_attachments":                               {Tok: makeDataSource(coreMod, "getVolumeAttachments")},
			"oci_core_volume_backup_policies":                           {Tok: makeDataSource(coreMod, "getVolumeBackupPolicies")},
			"oci_core_volume_backup_policy_assignments":                 {Tok: makeDataSource(coreMod, "getVolumeBackupPolicyAssignments")},
			"oci_core_volume_backups":                                   {Tok: makeDataSource(coreMod, "getVolumeBackups")},
			"oci_core_volume_group_backups":                             {Tok: makeDataSource(coreMod, "getVolumeGroupBackups")},
			"oci_core_volume_groups":                                    {Tok: makeDataSource(coreMod, "getVolumeGroups")},
			"oci_core_volumes":                                          {Tok: makeDataSource(coreMod, "getVolumes")},
			// Data Catalog
			"oci_datacatalog_catalog":                   {Tok: makeDataSource(dataCatalogMod, "getCatalog")},
			"oci_datacatalog_catalog_private_endpoint":  {Tok: makeDataSource(dataCatalogMod, "getCatalogPrivateEndpoint")},
			"oci_datacatalog_catalog_private_endpoints": {Tok: makeDataSource(dataCatalogMod, "getCatalogPrivateEndpoints")},
			"oci_datacatalog_catalog_type":              {Tok: makeDataSource(dataCatalogMod, "getCatalogType")},
			"oci_datacatalog_catalog_types":             {Tok: makeDataSource(dataCatalogMod, "getCatalogTypes")},
			"oci_datacatalog_catalogs":                  {Tok: makeDataSource(dataCatalogMod, "getCatalogs")},
			"oci_datacatalog_connection":                {Tok: makeDataSource(dataCatalogMod, "getConnection")},
			"oci_datacatalog_connections":               {Tok: makeDataSource(dataCatalogMod, "getConnections")},
			"oci_datacatalog_data_asset":                {Tok: makeDataSource(dataCatalogMod, "getDataAsset")},
			"oci_datacatalog_data_assets":               {Tok: makeDataSource(dataCatalogMod, "getDataAssets")},
			// Data Flow
			"oci_dataflow_application":       {Tok: makeDataSource(dataFlowMod, "getApplication")},
			"oci_dataflow_applications":      {Tok: makeDataSource(dataFlowMod, "getApplications")},
			"oci_dataflow_invoke_run":        {Tok: makeDataSource(dataFlowMod, "getInvokeRun")},
			"oci_dataflow_invoke_runs":       {Tok: makeDataSource(dataFlowMod, "getInvokeRuns")},
			"oci_dataflow_private_endpoint":  {Tok: makeDataSource(dataFlowMod, "getPrivateEndpoint")},
			"oci_dataflow_private_endpoints": {Tok: makeDataSource(dataFlowMod, "getPrivateEndpoints")},
			"oci_dataflow_run_log":           {Tok: makeDataSource(dataFlowMod, "getRunLog")},
			"oci_dataflow_run_logs":          {Tok: makeDataSource(dataFlowMod, "getRunLogs")},
			// Data Integration
			"oci_dataintegration_workspace":  {Tok: makeDataSource(dataIntegrationMod, "getWorkspace")},
			"oci_dataintegration_workspaces": {Tok: makeDataSource(dataIntegrationMod, "getWorkspaces")},
			// Data Safe
			"oci_data_safe_data_safe_configuration":     {Tok: makeDataSource(dataSafeMod, "getDataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint":  {Tok: makeDataSource(dataSafeMod, "getDataSafePrivateEndpoint")},
			"oci_data_safe_data_safe_private_endpoints": {Tok: makeDataSource(dataSafeMod, "getDataSafePrivateEndpoints")},
			"oci_data_safe_on_prem_connector":           {Tok: makeDataSource(dataSafeMod, "getOnPremConnector")},
			"oci_data_safe_on_prem_connectors":          {Tok: makeDataSource(dataSafeMod, "getOnPremConnectors")},
			"oci_data_safe_target_database":             {Tok: makeDataSource(dataSafeMod, "getTargetDatabase")},
			"oci_data_safe_target_databases":            {Tok: makeDataSource(dataSafeMod, "getTargetDatabases")},
			// Data Science
			"oci_datascience_model":                   {Tok: makeDataSource(dataScienceMod, "getModel")},
			"oci_datascience_model_deployment":        {Tok: makeDataSource(dataScienceMod, "getModelDeployment")},
			"oci_datascience_model_deployment_shapes": {Tok: makeDataSource(dataScienceMod, "getModelDeploymentShapes")},
			"oci_datascience_model_deployments":       {Tok: makeDataSource(dataScienceMod, "getModelDeployments")},
			"oci_datascience_model_provenance":        {Tok: makeDataSource(dataScienceMod, "getModelProvenance")},
			"oci_datascience_models":                  {Tok: makeDataSource(dataScienceMod, "getModels")},
			"oci_datascience_notebook_session":        {Tok: makeDataSource(dataScienceMod, "getNotebookSession")},
			"oci_datascience_notebook_session_shapes": {Tok: makeDataSource(dataScienceMod, "getNotebookSessionShapes")},
			"oci_datascience_notebook_sessions":       {Tok: makeDataSource(dataScienceMod, "getNotebookSessions")},
			"oci_datascience_project":                 {Tok: makeDataSource(dataScienceMod, "getProject")},
			"oci_datascience_projects":                {Tok: makeDataSource(dataScienceMod, "getProjects")},
			// Database
			"oci_database_autonomous_container_database":                        {Tok: makeDataSource(databaseMod, "getAutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association":  {Tok: makeDataSource(databaseMod, "getAutonomousContainerDatabaseDataguardAssociation")},
			"oci_database_autonomous_container_database_dataguard_associations": {Tok: makeDataSource(databaseMod, "getAutonomousContainerDatabaseDataguardAssociations")},
			"oci_database_autonomous_container_databases":                       {Tok: makeDataSource(databaseMod, "getAutonomousContainerDatabases")},
			"oci_database_autonomous_container_patches":                         {Tok: makeDataSource(databaseMod, "getAutonomousContainerPatches")},
			"oci_database_autonomous_database":                                  {Tok: makeDataSource(databaseMod, "getAutonomousDatabase")},
			"oci_database_autonomous_database_backup":                           {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseBackup")},
			"oci_database_autonomous_database_backups":                          {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseBackups")},
			"oci_database_autonomous_database_dataguard_association":            {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseDataguardAssociation")},
			"oci_database_autonomous_database_dataguard_associations":           {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseDataguardAssociations")},
			"oci_database_autonomous_database_instance_wallet_management":       {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_regional_wallet_management":       {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                           {Tok: makeDataSource(databaseMod, "getAutonomousDatabaseWallet")},
			"oci_database_autonomous_databases":                                 {Tok: makeDataSource(databaseMod, "getAutonomousDatabases")},
			"oci_database_autonomous_databases_clones":                          {Tok: makeDataSource(databaseMod, "getAutonomousDatabasesClones")},
			"oci_database_autonomous_db_preview_versions":                       {Tok: makeDataSource(databaseMod, "getAutonomousDbPreviewVersions")},
			"oci_database_autonomous_db_versions":                               {Tok: makeDataSource(databaseMod, "getAutonomousDbVersions")},
			"oci_database_autonomous_exadata_infrastructure":                    {Tok: makeDataSource(databaseMod, "getAutonomousExadataInfrastructure")},
			"oci_database_autonomous_exadata_infrastructure_ocpu":               {Tok: makeDataSource(databaseMod, "getAutonomousExadataInfrastructureOcpu")},
			"oci_database_autonomous_exadata_infrastructure_shapes":             {Tok: makeDataSource(databaseMod, "getAutonomousExadataInfrastructureShapes")},
			"oci_database_autonomous_exadata_infrastructures":                   {Tok: makeDataSource(databaseMod, "getAutonomousExadataInfrastructures")},
			"oci_database_autonomous_patch":                                     {Tok: makeDataSource(databaseMod, "getAutonomousPatch")},
			"oci_database_autonomous_vm_cluster":                                {Tok: makeDataSource(databaseMod, "getAutonomousVmCluster")},
			"oci_database_autonomous_vm_clusters":                               {Tok: makeDataSource(databaseMod, "getAutonomousVmClusters")},
			"oci_database_backup_destination":                                   {Tok: makeDataSource(databaseMod, "getBackupDestination")},
			"oci_database_backup_destinations":                                  {Tok: makeDataSource(databaseMod, "getBackupDestinations")},
			"oci_database_backups":                                              {Tok: makeDataSource(databaseMod, "getBackups")},
			"oci_database_cloud_exadata_infrastructure":                         {Tok: makeDataSource(databaseMod, "getCloudExadataInfrastructure")},
			"oci_database_cloud_exadata_infrastructures":                        {Tok: makeDataSource(databaseMod, "getCloudExadataInfrastructures")},
			"oci_database_cloud_vm_cluster":                                     {Tok: makeDataSource(databaseMod, "getCloudVmCluster")},
			"oci_database_cloud_vm_clusters":                                    {Tok: makeDataSource(databaseMod, "getCloudVmClusters")},
			"oci_database_data_guard_association":                               {Tok: makeDataSource(databaseMod, "getDataGuardAssociation")},
			"oci_database_data_guard_associations":                              {Tok: makeDataSource(databaseMod, "getDataGuardAssociations")},
			"oci_database_database":                                             {Tok: makeDataSource(databaseMod, "getDatabase")},
			"oci_database_database_software_image":                              {Tok: makeDataSource(databaseMod, "getDatabaseSoftwareImage")},
			"oci_database_database_software_images":                             {Tok: makeDataSource(databaseMod, "getDatabaseSoftwareImages")},
			"oci_database_database_upgrade_history_entries":                     {Tok: makeDataSource(databaseMod, "getDatabaseUpgradeHistoryEntries")},
			"oci_database_database_upgrade_history_entry":                       {Tok: makeDataSource(databaseMod, "getDatabaseUpgradeHistoryEntry")},
			"oci_database_databases":                                            {Tok: makeDataSource(databaseMod, "getDatabases")},
			"oci_database_db_home":                                              {Tok: makeDataSource(databaseMod, "getDbHome")},
			"oci_database_db_home_patch_history_entries":                        {Tok: makeDataSource(databaseMod, "getDbHomePatchHistoryEntries")},
			"oci_database_db_home_patches":                                      {Tok: makeDataSource(databaseMod, "getDbHomePatches")},
			"oci_database_db_homes":                                             {Tok: makeDataSource(databaseMod, "getDbHomes")},
			"oci_database_db_node":                                              {Tok: makeDataSource(databaseMod, "getDbNode")},
			"oci_database_db_node_console_connection":                           {Tok: makeDataSource(databaseMod, "getDbNodeConsoleConnection")},
			"oci_database_db_node_console_connections":                          {Tok: makeDataSource(databaseMod, "getDbNodeConsoleConnections")},
			"oci_database_db_nodes":                                             {Tok: makeDataSource(databaseMod, "getDbNodes")},
			"oci_database_db_system_patch_history_entries":                      {Tok: makeDataSource(databaseMod, "getDbSystemPatchHistoryEntries")},
			"oci_database_db_system_patches":                                    {Tok: makeDataSource(databaseMod, "getDbSystemPatches")},
			"oci_database_db_system_shapes":                                     {Tok: makeDataSource(databaseMod, "getDbSystemShapes")},
			"oci_database_db_systems":                                           {Tok: makeDataSource(databaseMod, "getDbSystems")},
			"oci_database_db_versions":                                          {Tok: makeDataSource(databaseMod, "getDbVersions")},
			"oci_database_exadata_infrastructure":                               {Tok: makeDataSource(databaseMod, "getExadataInfrastructure")},
			"oci_database_exadata_infrastructure_download_config_file":          {Tok: makeDataSource(databaseMod, "getExadataInfrastructureDownloadConfigFile")},
			"oci_database_exadata_infrastructures":                              {Tok: makeDataSource(databaseMod, "getExadataInfrastructures")},
			"oci_database_exadata_iorm_config":                                  {Tok: makeDataSource(databaseMod, "getExadataIormConfig")},
			"oci_database_external_container_database":                          {Tok: makeDataSource(databaseMod, "getExternalContainerDatabase")},
			"oci_database_external_container_databases":                         {Tok: makeDataSource(databaseMod, "getExternalContainerDatabases")},
			"oci_database_external_database_connector":                          {Tok: makeDataSource(databaseMod, "getExternalDatabaseConnector")},
			"oci_database_external_database_connectors":                         {Tok: makeDataSource(databaseMod, "getExternalDatabaseConnectors")},
			"oci_database_external_non_container_database":                      {Tok: makeDataSource(databaseMod, "getExternalNonContainerDatabase")},
			"oci_database_external_non_container_databases":                     {Tok: makeDataSource(databaseMod, "getExternalNonContainerDatabases")},
			"oci_database_external_pluggable_database":                          {Tok: makeDataSource(databaseMod, "getExternalPluggableDatabase")},
			"oci_database_external_pluggable_databases":                         {Tok: makeDataSource(databaseMod, "getExternalPluggableDatabases")},
			"oci_database_flex_components":                                      {Tok: makeDataSource(databaseMod, "getFlexComponents")},
			"oci_database_gi_versions":                                          {Tok: makeDataSource(databaseMod, "getGiVersions")},
			"oci_database_key_store":                                            {Tok: makeDataSource(databaseMod, "getKeyStore")},
			"oci_database_key_stores":                                           {Tok: makeDataSource(databaseMod, "getKeyStores")},
			"oci_database_maintenance_run":                                      {Tok: makeDataSource(databaseMod, "getMaintenanceRun")},
			"oci_database_maintenance_runs":                                     {Tok: makeDataSource(databaseMod, "getMaintenanceRuns")},
			"oci_database_pluggable_database":                                   {Tok: makeDataSource(databaseMod, "getPluggableDatabase")},
			"oci_database_pluggable_databases":                                  {Tok: makeDataSource(databaseMod, "getPluggableDatabases")},
			"oci_database_vm_cluster":                                           {Tok: makeDataSource(databaseMod, "getVmCluster")},
			"oci_database_vm_cluster_network":                                   {Tok: makeDataSource(databaseMod, "getVmClusterNetwork")},
			"oci_database_vm_cluster_network_download_config_file":              {Tok: makeDataSource(databaseMod, "getVmClusterNetworkDownloadConfigFile")},
			"oci_database_vm_cluster_networks":                                  {Tok: makeDataSource(databaseMod, "getVmClusterNetworks")},
			"oci_database_vm_cluster_patch":                                     {Tok: makeDataSource(databaseMod, "getVmClusterPatch")},
			"oci_database_vm_cluster_patch_history_entries":                     {Tok: makeDataSource(databaseMod, "getVmClusterPatchHistoryEntries")},
			"oci_database_vm_cluster_patch_history_entry":                       {Tok: makeDataSource(databaseMod, "getVmClusterPatchHistoryEntry")},
			"oci_database_vm_cluster_patches":                                   {Tok: makeDataSource(databaseMod, "getVmClusterPatches")},
			"oci_database_vm_cluster_recommended_network":                       {Tok: makeDataSource(databaseMod, "getVmClusterRecommendedNetwork")},
			"oci_database_vm_cluster_update":                                    {Tok: makeDataSource(databaseMod, "getVmClusterUpdate")},
			"oci_database_vm_cluster_update_history_entries":                    {Tok: makeDataSource(databaseMod, "getVmClusterUpdateHistoryEntries")},
			"oci_database_vm_cluster_update_history_entry":                      {Tok: makeDataSource(databaseMod, "getVmClusterUpdateHistoryEntry")},
			"oci_database_vm_cluster_updates":                                   {Tok: makeDataSource(databaseMod, "getVmClusterUpdates")},
			"oci_database_vm_clusters":                                          {Tok: makeDataSource(databaseMod, "getVmClusters")},
			// Database Management
			"oci_database_management_managed_database":                      {Tok: makeDataSource(databaseManagementMod, "getManagedDatabase")},
			"oci_database_management_managed_database_group":                {Tok: makeDataSource(databaseManagementMod, "getManagedDatabaseGroup")},
			"oci_database_management_managed_database_groups":               {Tok: makeDataSource(databaseManagementMod, "getManagedDatabaseGroups")},
			"oci_database_management_managed_databases":                     {Tok: makeDataSource(databaseManagementMod, "getManagedDatabases")},
			"oci_database_management_managed_databases_database_parameter":  {Tok: makeDataSource(databaseManagementMod, "getManagedDatabasesDatabaseParameter")},
			"oci_database_management_managed_databases_database_parameters": {Tok: makeDataSource(databaseManagementMod, "getManagedDatabasesDatabaseParameters")},
			// Database Migration
			"oci_database_migration_agent":        {Tok: makeDataSource(databaseMigrationMod, "getAgent")},
			"oci_database_migration_agent_images": {Tok: makeDataSource(databaseMigrationMod, "getAgentImages")},
			"oci_database_migration_agents":       {Tok: makeDataSource(databaseMigrationMod, "getAgents")},
			"oci_database_migration_connection":   {Tok: makeDataSource(databaseMigrationMod, "getConnection")},
			"oci_database_migration_connections":  {Tok: makeDataSource(databaseMigrationMod, "getConnections")},
			"oci_database_migration_job":          {Tok: makeDataSource(databaseMigrationMod, "getJob")},
			"oci_database_migration_jobs":         {Tok: makeDataSource(databaseMigrationMod, "getJobs")},
			"oci_database_migration_migration":    {Tok: makeDataSource(databaseMigrationMod, "getMigration")},
			"oci_database_migration_migrations":   {Tok: makeDataSource(databaseMigrationMod, "getMigrations")},
			// Devops
			"oci_devops_deploy_artifact":     {Tok: makeDataSource(devopsMod, "getDeployArtifact")},
			"oci_devops_deploy_artifacts":    {Tok: makeDataSource(devopsMod, "getDeployArtifacts")},
			"oci_devops_deploy_environment":  {Tok: makeDataSource(devopsMod, "getDeployEnvironment")},
			"oci_devops_deploy_environments": {Tok: makeDataSource(devopsMod, "getDeployEnvironments")},
			"oci_devops_deploy_pipeline":     {Tok: makeDataSource(devopsMod, "getDeployPipeline")},
			"oci_devops_deploy_pipelines":    {Tok: makeDataSource(devopsMod, "getDeployPipelines")},
			"oci_devops_deploy_stage":        {Tok: makeDataSource(devopsMod, "getDeployStage")},
			"oci_devops_deploy_stages":       {Tok: makeDataSource(devopsMod, "getDeployStages")},
			"oci_devops_deployment":          {Tok: makeDataSource(devopsMod, "getDeployment")},
			"oci_devops_deployments":         {Tok: makeDataSource(devopsMod, "getDeployments")},
			"oci_devops_project":             {Tok: makeDataSource(devopsMod, "getProject")},
			"oci_devops_projects":            {Tok: makeDataSource(devopsMod, "getProjects")},
			// ODA
			"oci_oda_oda_instance":  {Tok: makeDataSource(odaMod, "getOdaInstance")},
			"oci_oda_oda_instances": {Tok: makeDataSource(odaMod, "getOdaInstances")},
			// DNS
			"oci_dns_records":                     {Tok: makeDataSource(dnsMod, "getRecords")},
			"oci_dns_resolver":                    {Tok: makeDataSource(dnsMod, "getResolver")},
			"oci_dns_resolver_endpoint":           {Tok: makeDataSource(dnsMod, "getResolverEndpoint")},
			"oci_dns_resolver_endpoints":          {Tok: makeDataSource(dnsMod, "getResolverEndpoints")},
			"oci_dns_resolvers":                   {Tok: makeDataSource(dnsMod, "getResolvers")},
			"oci_dns_rrset":                       {Tok: makeDataSource(dnsMod, "getRrset")},
			"oci_dns_steering_policies":           {Tok: makeDataSource(dnsMod, "getSteeringPolicies")},
			"oci_dns_steering_policy":             {Tok: makeDataSource(dnsMod, "getSteeringPolicy")},
			"oci_dns_steering_policy_attachment":  {Tok: makeDataSource(dnsMod, "getSteeringPolicyAttachment")},
			"oci_dns_steering_policy_attachments": {Tok: makeDataSource(dnsMod, "getSteeringPolicyAttachments")},
			"oci_dns_tsig_key":                    {Tok: makeDataSource(dnsMod, "getTsigKey")},
			"oci_dns_tsig_keys":                   {Tok: makeDataSource(dnsMod, "getTsigKeys")},
			"oci_dns_view":                        {Tok: makeDataSource(dnsMod, "getView")},
			"oci_dns_views":                       {Tok: makeDataSource(dnsMod, "getViews")},
			"oci_dns_zones":                       {Tok: makeDataSource(dnsMod, "getZones")},
			// Email
			"oci_email_dkim":          {Tok: makeDataSource(emailMod, "getDkim")},
			"oci_email_dkims":         {Tok: makeDataSource(emailMod, "getDkims")},
			"oci_email_email_domain":  {Tok: makeDataSource(emailMod, "getEmailDomain")},
			"oci_email_email_domains": {Tok: makeDataSource(emailMod, "getEmailDomains")},
			"oci_email_sender":        {Tok: makeDataSource(emailMod, "getSender")},
			"oci_email_senders":       {Tok: makeDataSource(emailMod, "getSenders")},
			"oci_email_suppression":   {Tok: makeDataSource(emailMod, "getSuppression")},
			"oci_email_suppressions":  {Tok: makeDataSource(emailMod, "getSuppressions")},
			// Events
			"oci_events_rule":  {Tok: makeDataSource(eventsMod, "getRule")},
			"oci_events_rules": {Tok: makeDataSource(eventsMod, "getRules")},
			// File Storage
			"oci_file_storage_export_sets":   {Tok: makeDataSource(fileStorageMod, "getExportSets")},
			"oci_file_storage_exports":       {Tok: makeDataSource(fileStorageMod, "getExports")},
			"oci_file_storage_file_systems":  {Tok: makeDataSource(fileStorageMod, "getFileSystems")},
			"oci_file_storage_mount_targets": {Tok: makeDataSource(fileStorageMod, "getMountTargets")},
			"oci_file_storage_snapshot":      {Tok: makeDataSource(fileStorageMod, "getSnapshot")},
			"oci_file_storage_snapshots":     {Tok: makeDataSource(fileStorageMod, "getSnapshots")},
			// Functions
			"oci_functions_application":  {Tok: makeDataSource(functionsMod, "getApplication")},
			"oci_functions_applications": {Tok: makeDataSource(functionsMod, "getApplications")},
			"oci_functions_function":     {Tok: makeDataSource(functionsMod, "getFunction")},
			"oci_functions_functions":    {Tok: makeDataSource(functionsMod, "getFunctions")},
			// Generic Artifacts Content
			"oci_generic_artifacts_content_generic_artifacts_content": {Tok: makeDataSource(genericArtifactsContentMod, "getGenericArtifactsContent")},
			// Golden Gate
			"oci_golden_gate_database_registration":  {Tok: makeDataSource(goldenGateMod, "getDatabaseRegistration")},
			"oci_golden_gate_database_registrations": {Tok: makeDataSource(goldenGateMod, "getDatabaseRegistrations")},
			"oci_golden_gate_deployment":             {Tok: makeDataSource(goldenGateMod, "getDeployment")},
			"oci_golden_gate_deployment_backup":      {Tok: makeDataSource(goldenGateMod, "getDeploymentBackup")},
			"oci_golden_gate_deployment_backups":     {Tok: makeDataSource(goldenGateMod, "getDeploymentBackups")},
			"oci_golden_gate_deployments":            {Tok: makeDataSource(goldenGateMod, "getDeployments")},
			// Health Checks
			"oci_health_checks_http_monitor":       {Tok: makeDataSource(healthChecksMod, "getHttpMonitor")},
			"oci_health_checks_http_monitors":      {Tok: makeDataSource(healthChecksMod, "getHttpMonitors")},
			"oci_health_checks_http_probe_results": {Tok: makeDataSource(healthChecksMod, "getHttpProbeResults")},
			"oci_health_checks_ping_monitor":       {Tok: makeDataSource(healthChecksMod, "getPingMonitor")},
			"oci_health_checks_ping_monitors":      {Tok: makeDataSource(healthChecksMod, "getPingMonitors")},
			"oci_health_checks_ping_probe_results": {Tok: makeDataSource(healthChecksMod, "getPingProbeResults")},
			"oci_health_checks_vantage_points":     {Tok: makeDataSource(healthChecksMod, "getVantagePoints")},
			// Identity
			"oci_identity_api_keys":                 {Tok: makeDataSource(identityMod, "getApiKeys")},
			"oci_identity_auth_tokens":              {Tok: makeDataSource(identityMod, "getAuthTokens")},
			"oci_identity_authentication_policy":    {Tok: makeDataSource(identityMod, "getAuthenticationPolicy")},
			"oci_identity_availability_domain":      {Tok: makeDataSource(identityMod, "getAvailabilityDomain")},
			"oci_identity_availability_domains":     {Tok: makeDataSource(identityMod, "getAvailabilityDomains")},
			"oci_identity_compartment":              {Tok: makeDataSource(identityMod, "getCompartment")},
			"oci_identity_compartments":             {Tok: makeDataSource(identityMod, "getCompartments")},
			"oci_identity_cost_tracking_tags":       {Tok: makeDataSource(identityMod, "getCostTrackingTags")},
			"oci_identity_customer_secret_keys":     {Tok: makeDataSource(identityMod, "getCustomerSecretKeys")},
			"oci_identity_dynamic_groups":           {Tok: makeDataSource(identityMod, "getDynamicGroups")},
			"oci_identity_fault_domains":            {Tok: makeDataSource(identityMod, "getFaultDomains")},
			"oci_identity_group":                    {Tok: makeDataSource(identityMod, "getGroup")},
			"oci_identity_groups":                   {Tok: makeDataSource(identityMod, "getGroups")},
			"oci_identity_identity_provider_groups": {Tok: makeDataSource(identityMod, "getIdentityProviderGroups")},
			"oci_identity_identity_providers":       {Tok: makeDataSource(identityMod, "getIdentityProviders")},
			"oci_identity_idp_group_mappings":       {Tok: makeDataSource(identityMod, "getIdpGroupMappings")},
			"oci_identity_network_source":           {Tok: makeDataSource(identityMod, "getNetworkSource")},
			"oci_identity_network_sources":          {Tok: makeDataSource(identityMod, "getNetworkSources")},
			"oci_identity_policies":                 {Tok: makeDataSource(identityMod, "getPolicies")},
			"oci_identity_region_subscriptions":     {Tok: makeDataSource(identityMod, "getRegionSubscriptions")},
			"oci_identity_regions":                  {Tok: makeDataSource(identityMod, "getRegions")},
			"oci_identity_smtp_credentials":         {Tok: makeDataSource(identityMod, "getSmtpCredentials")},
			"oci_identity_swift_passwords":          {Tok: makeDataSource(identityMod, "getSwiftPasswords")},
			"oci_identity_tag":                      {Tok: makeDataSource(identityMod, "getTag")},
			"oci_identity_tag_default":              {Tok: makeDataSource(identityMod, "getTagDefault")},
			"oci_identity_tag_defaults":             {Tok: makeDataSource(identityMod, "getTagDefaults")},
			"oci_identity_tag_namespaces":           {Tok: makeDataSource(identityMod, "getTagNamespaces")},
			"oci_identity_tags":                     {Tok: makeDataSource(identityMod, "getTags")},
			"oci_identity_tenancy":                  {Tok: makeDataSource(identityMod, "getTenancy")},
			"oci_identity_ui_password":              {Tok: makeDataSource(identityMod, "getUiPassword")},
			"oci_identity_user":                     {Tok: makeDataSource(identityMod, "getUser")},
			"oci_identity_user_group_memberships":   {Tok: makeDataSource(identityMod, "getUserGroupMemberships")},
			"oci_identity_users":                    {Tok: makeDataSource(identityMod, "getUsers")},
			// Integration
			"oci_integration_integration_instance":  {Tok: makeDataSource(integrationMod, "getIntegrationInstance")},
			"oci_integration_integration_instances": {Tok: makeDataSource(integrationMod, "getIntegrationInstances")},
			// Jms
			"oci_jms_fleet":  {Tok: makeDataSource(jmsMod, "getFleet")},
			"oci_jms_fleets": {Tok: makeDataSource(jmsMod, "getFleets")},
			// Kms
			"oci_kms_decrypted_data":     {Tok: makeDataSource(kmsMod, "getDecryptedData")},
			"oci_kms_encrypted_data":     {Tok: makeDataSource(kmsMod, "getEncryptedData")},
			"oci_kms_key":                {Tok: makeDataSource(kmsMod, "getKey")},
			"oci_kms_key_version":        {Tok: makeDataSource(kmsMod, "getKeyVersion")},
			"oci_kms_key_versions":       {Tok: makeDataSource(kmsMod, "getKeyVersions")},
			"oci_kms_keys":               {Tok: makeDataSource(kmsMod, "getKeys")},
			"oci_kms_replication_status": {Tok: makeDataSource(kmsMod, "getReplicationStatus")},
			"oci_kms_vault":              {Tok: makeDataSource(kmsMod, "getVault")},
			"oci_kms_vault_replicas":     {Tok: makeDataSource(kmsMod, "getVaultReplicas")},
			"oci_kms_vault_usage":        {Tok: makeDataSource(kmsMod, "getVaultUsage")},
			"oci_kms_vaults":             {Tok: makeDataSource(kmsMod, "getVaults")},
			// Limits
			"oci_limits_limit_definitions":     {Tok: makeDataSource(limitsMod, "getLimitDefinitions")},
			"oci_limits_limit_values":          {Tok: makeDataSource(limitsMod, "getLimitValues")},
			"oci_limits_quota":                 {Tok: makeDataSource(limitsMod, "getQuota")},
			"oci_limits_quotas":                {Tok: makeDataSource(limitsMod, "getQuotas")},
			"oci_limits_resource_availability": {Tok: makeDataSource(limitsMod, "getResourceAvailability")},
			"oci_limits_services":              {Tok: makeDataSource(limitsMod, "getServices")},
			// Load Balancer
			"oci_load_balancer_backend_health":                 {Tok: makeDataSource(loadBalancerMod, "getBackendHealth")},
			"oci_load_balancer_backend_set_health":             {Tok: makeDataSource(loadBalancerMod, "getBackendSetHealth")},
			"oci_load_balancer_backend_sets":                   {Tok: makeDataSource(loadBalancerMod, "getBackendSets")},
			"oci_load_balancer_backends":                       {Tok: makeDataSource(loadBalancerMod, "getBackends")},
			"oci_load_balancer_certificates":                   {Tok: makeDataSource(loadBalancerMod, "getCertificates")},
			"oci_load_balancer_health":                         {Tok: makeDataSource(loadBalancerMod, "getHealth")},
			"oci_load_balancer_hostnames":                      {Tok: makeDataSource(loadBalancerMod, "getHostnames")},
			"oci_load_balancer_listener_rules":                 {Tok: makeDataSource(loadBalancerMod, "getListenerRules")},
			"oci_load_balancer_load_balancer_routing_policies": {Tok: makeDataSource(loadBalancerMod, "getLoadBalancerRoutingPolicies")},
			"oci_load_balancer_load_balancer_routing_policy":   {Tok: makeDataSource(loadBalancerMod, "getLoadBalancerRoutingPolicy")},
			"oci_load_balancer_load_balancers":                 {Tok: makeDataSource(loadBalancerMod, "getLoadBalancers")},
			"oci_load_balancer_path_route_sets":                {Tok: makeDataSource(loadBalancerMod, "getPathRouteSets")},
			"oci_load_balancer_policies":                       {Tok: makeDataSource(loadBalancerMod, "getPolicies")},
			"oci_load_balancer_protocols":                      {Tok: makeDataSource(loadBalancerMod, "getProtocols")},
			"oci_load_balancer_rule_set":                       {Tok: makeDataSource(loadBalancerMod, "getRuleSet")},
			"oci_load_balancer_rule_sets":                      {Tok: makeDataSource(loadBalancerMod, "getRuleSets")},
			"oci_load_balancer_shapes":                         {Tok: makeDataSource(loadBalancerMod, "getShapes")},
			"oci_load_balancer_ssl_cipher_suite":               {Tok: makeDataSource(loadBalancerMod, "getSslCipherSuite")},
			"oci_load_balancer_ssl_cipher_suites":              {Tok: makeDataSource(loadBalancerMod, "getSslCipherSuites")},
			// Log Analytics
			"oci_log_analytics_log_analytics_entities":                {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsEntities")},
			"oci_log_analytics_log_analytics_entities_summary":        {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsEntitiesSummary")},
			"oci_log_analytics_log_analytics_entity":                  {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_log_group":               {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_log_groups":              {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsLogGroups")},
			"oci_log_analytics_log_analytics_log_groups_summary":      {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsLogGroupsSummary")},
			"oci_log_analytics_log_analytics_object_collection_rule":  {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_log_analytics_object_collection_rules": {Tok: makeDataSource(logAnalyticsMod, "getLogAnalyticsObjectCollectionRules")},
			"oci_log_analytics_namespace":                             {Tok: makeDataSource(logAnalyticsMod, "getNamespace")},
			"oci_log_analytics_namespaces":                            {Tok: makeDataSource(logAnalyticsMod, "getNamespaces")},
			// Logging
			"oci_logging_log":                          {Tok: makeDataSource(loggingMod, "getLog")},
			"oci_logging_log_group":                    {Tok: makeDataSource(loggingMod, "getLogGroup")},
			"oci_logging_log_groups":                   {Tok: makeDataSource(loggingMod, "getLogGroups")},
			"oci_logging_log_saved_search":             {Tok: makeDataSource(loggingMod, "getLogSavedSearch")},
			"oci_logging_log_saved_searches":           {Tok: makeDataSource(loggingMod, "getLogSavedSearches")},
			"oci_logging_logs":                         {Tok: makeDataSource(loggingMod, "getLogs")},
			"oci_logging_unified_agent_configuration":  {Tok: makeDataSource(loggingMod, "getUnifiedAgentConfiguration")},
			"oci_logging_unified_agent_configurations": {Tok: makeDataSource(loggingMod, "getUnifiedAgentConfigurations")},
			// Management Agent
			"oci_management_agent_management_agent":                     {Tok: makeDataSource(managementAgentMod, "getManagementAgent")},
			"oci_management_agent_management_agent_available_histories": {Tok: makeDataSource(managementAgentMod, "getManagementAgentAvailableHistories")},
			"oci_management_agent_management_agent_images":              {Tok: makeDataSource(managementAgentMod, "getManagementAgentImages")},
			"oci_management_agent_management_agent_install_key":         {Tok: makeDataSource(managementAgentMod, "getManagementAgentInstallKey")},
			"oci_management_agent_management_agent_install_keys":        {Tok: makeDataSource(managementAgentMod, "getManagementAgentInstallKeys")},
			"oci_management_agent_management_agent_plugins":             {Tok: makeDataSource(managementAgentMod, "getManagementAgentPlugins")},
			"oci_management_agent_management_agents":                    {Tok: makeDataSource(managementAgentMod, "getManagementAgents")},
			// Management Dashboard
			"oci_management_dashboard_management_dashboards_export": {Tok: makeDataSource(managementDashboardMod, "getManagementDashboardsExport")},
			// Marketplace
			"oci_marketplace_accepted_agreement":         {Tok: makeDataSource(marketplaceMod, "getAcceptedAgreement")},
			"oci_marketplace_accepted_agreements":        {Tok: makeDataSource(marketplaceMod, "getAcceptedAgreements")},
			"oci_marketplace_categories":                 {Tok: makeDataSource(marketplaceMod, "getCategories")},
			"oci_marketplace_listing":                    {Tok: makeDataSource(marketplaceMod, "getListing")},
			"oci_marketplace_listing_package":            {Tok: makeDataSource(marketplaceMod, "getListingPackage")},
			"oci_marketplace_listing_package_agreements": {Tok: makeDataSource(marketplaceMod, "getListingPackageAgreements")},
			"oci_marketplace_listing_packages":           {Tok: makeDataSource(marketplaceMod, "getListingPackages")},
			"oci_marketplace_listing_taxes":              {Tok: makeDataSource(marketplaceMod, "getListingTaxes")},
			"oci_marketplace_listings":                   {Tok: makeDataSource(marketplaceMod, "getListings")},
			"oci_marketplace_publication":                {Tok: makeDataSource(marketplaceMod, "getPublication")},
			"oci_marketplace_publication_package":        {Tok: makeDataSource(marketplaceMod, "getPublicationPackage")},
			"oci_marketplace_publication_packages":       {Tok: makeDataSource(marketplaceMod, "getPublicationPackages")},
			"oci_marketplace_publications":               {Tok: makeDataSource(marketplaceMod, "getPublications")},
			"oci_marketplace_publishers":                 {Tok: makeDataSource(marketplaceMod, "getPublishers")},
			// Metering Computation
			"oci_metering_computation_configuration": {Tok: makeDataSource(meteringComputationMod, "getConfiguration")},
			"oci_metering_computation_custom_table":  {Tok: makeDataSource(meteringComputationMod, "getCustomTable")},
			"oci_metering_computation_custom_tables": {Tok: makeDataSource(meteringComputationMod, "getCustomTables")},
			"oci_metering_computation_queries":       {Tok: makeDataSource(meteringComputationMod, "getQueries")},
			"oci_metering_computation_query":         {Tok: makeDataSource(meteringComputationMod, "getQuery")},
			// Monitoring
			"oci_monitoring_alarm":                    {Tok: makeDataSource(monitoringMod, "getAlarm")},
			"oci_monitoring_alarm_history_collection": {Tok: makeDataSource(monitoringMod, "getAlarmHistoryCollection")},
			"oci_monitoring_alarm_statuses":           {Tok: makeDataSource(monitoringMod, "getAlarmStatuses")},
			"oci_monitoring_alarms":                   {Tok: makeDataSource(monitoringMod, "getAlarms")},
			"oci_monitoring_metric_data":              {Tok: makeDataSource(monitoringMod, "getMetricData")},
			"oci_monitoring_metrics":                  {Tok: makeDataSource(monitoringMod, "getMetrics")},
			// MYSQL
			"oci_mysql_analytics_cluster":    {Tok: makeDataSource(mysqlMod, "getAnalyticsCluster")},
			"oci_mysql_channel":              {Tok: makeDataSource(mysqlMod, "getChannel")},
			"oci_mysql_channels":             {Tok: makeDataSource(mysqlMod, "getChannels")},
			"oci_mysql_heat_wave_cluster":    {Tok: makeDataSource(mysqlMod, "getHeatWaveCluster")},
			"oci_mysql_mysql_backup":         {Tok: makeDataSource(mysqlMod, "getMysqlBackup")},
			"oci_mysql_mysql_backups":        {Tok: makeDataSource(mysqlMod, "getMysqlBackups")},
			"oci_mysql_mysql_configuration":  {Tok: makeDataSource(mysqlMod, "getMysqlConfiguration")},
			"oci_mysql_mysql_configurations": {Tok: makeDataSource(mysqlMod, "getMysqlConfigurations")},
			"oci_mysql_mysql_db_system":      {Tok: makeDataSource(mysqlMod, "getMysqlDbSystem")},
			"oci_mysql_mysql_db_systems":     {Tok: makeDataSource(mysqlMod, "getMysqlDbSystems")},
			"oci_mysql_mysql_versions":       {Tok: makeDataSource(mysqlMod, "getMysqlVersions")},
			"oci_mysql_shapes":               {Tok: makeDataSource(mysqlMod, "getShapes")},
			// Network Load Balancer
			"oci_network_load_balancer_backend_health":                   {Tok: makeDataSource(networkLoadBalancerMod, "getBackendHealth")},
			"oci_network_load_balancer_backend_set":                      {Tok: makeDataSource(networkLoadBalancerMod, "getBackendSet")},
			"oci_network_load_balancer_backend_sets":                     {Tok: makeDataSource(networkLoadBalancerMod, "getBackendSets")},
			"oci_network_load_balancer_backends":                         {Tok: makeDataSource(networkLoadBalancerMod, "getBackends")},
			"oci_network_load_balancer_listener":                         {Tok: makeDataSource(networkLoadBalancerMod, "getListener")},
			"oci_network_load_balancer_listeners":                        {Tok: makeDataSource(networkLoadBalancerMod, "getListeners")},
			"oci_network_load_balancer_network_load_balancer":            {Tok: makeDataSource(networkLoadBalancerMod, "getNetworkLoadBalancer")},
			"oci_network_load_balancer_network_load_balancer_health":     {Tok: makeDataSource(networkLoadBalancerMod, "getNetworkLoadBalancerHealth")},
			"oci_network_load_balancer_network_load_balancers":           {Tok: makeDataSource(networkLoadBalancerMod, "getNetworkLoadBalancers")},
			"oci_network_load_balancer_network_load_balancers_policies":  {Tok: makeDataSource(networkLoadBalancerMod, "getNetworkLoadBalancersPolicies")},
			"oci_network_load_balancer_network_load_balancers_protocols": {Tok: makeDataSource(networkLoadBalancerMod, "getNetworkLoadBalancersProtocols")},
			// NOSQL
			"oci_nosql_index":   {Tok: makeDataSource(nosqlMod, "getIndex")},
			"oci_nosql_indexes": {Tok: makeDataSource(nosqlMod, "getIndexes")},
			"oci_nosql_table":   {Tok: makeDataSource(nosqlMod, "getTable")},
			"oci_nosql_tables":  {Tok: makeDataSource(nosqlMod, "getTables")},
			// ONS
			"oci_ons_notification_topic":  {Tok: makeDataSource(onsMod, "getNotificationTopic")},
			"oci_ons_notification_topics": {Tok: makeDataSource(onsMod, "getNotificationTopics")},
			"oci_ons_subscription":        {Tok: makeDataSource(onsMod, "getSubscription")},
			"oci_ons_subscriptions":       {Tok: makeDataSource(onsMod, "getSubscriptions")},
			// Object Storage
			"oci_objectstorage_bucket":                  {Tok: makeDataSource(objectStorageMod, "getBucket")},
			"oci_objectstorage_bucket_summaries":        {Tok: makeDataSource(objectStorageMod, "getBucketSummaries")},
			"oci_objectstorage_namespace":               {Tok: makeDataSource(objectStorageMod, "getNamespace")},
			"oci_objectstorage_object":                  {Tok: makeDataSource(objectStorageMod, "getObject")},
			"oci_objectstorage_object_head":             {Tok: makeDataSource(objectStorageMod, "getObjectHead")},
			"oci_objectstorage_object_lifecycle_policy": {Tok: makeDataSource(objectStorageMod, "getObjectLifecyclePolicy")},
			"oci_objectstorage_object_versions":         {Tok: makeDataSource(objectStorageMod, "getObjectVersions")},
			"oci_objectstorage_objects":                 {Tok: makeDataSource(objectStorageMod, "getObjects")},
			"oci_objectstorage_preauthrequest":          {Tok: makeDataSource(objectStorageMod, "getPreauthrequest")},
			"oci_objectstorage_preauthrequests":         {Tok: makeDataSource(objectStorageMod, "getPreauthrequests")},
			"oci_objectstorage_replication_policies":    {Tok: makeDataSource(objectStorageMod, "getReplicationPolicies")},
			"oci_objectstorage_replication_policy":      {Tok: makeDataSource(objectStorageMod, "getReplicationPolicy")},
			"oci_objectstorage_replication_sources":     {Tok: makeDataSource(objectStorageMod, "getReplicationSources")},
			// Opsi
			"oci_opsi_database_insight":           {Tok: makeDataSource(opsiMod, "getDatabaseInsight")},
			"oci_opsi_database_insights":          {Tok: makeDataSource(opsiMod, "getDatabaseInsights")},
			"oci_opsi_enterprise_manager_bridge":  {Tok: makeDataSource(opsiMod, "getEnterpriseManagerBridge")},
			"oci_opsi_enterprise_manager_bridges": {Tok: makeDataSource(opsiMod, "getEnterpriseManagerBridges")},
			"oci_opsi_host_insight":               {Tok: makeDataSource(opsiMod, "getHostInsight")},
			"oci_opsi_host_insights":              {Tok: makeDataSource(opsiMod, "getHostInsights")},
			// Optimizer
			"oci_optimizer_categories":          {Tok: makeDataSource(optimizerMod, "getCategories")},
			"oci_optimizer_category":            {Tok: makeDataSource(optimizerMod, "getCategory")},
			"oci_optimizer_enrollment_status":   {Tok: makeDataSource(optimizerMod, "getEnrollmentStatus")},
			"oci_optimizer_enrollment_statuses": {Tok: makeDataSource(optimizerMod, "getEnrollmentStatuses")},
			"oci_optimizer_histories":           {Tok: makeDataSource(optimizerMod, "getHistories")},
			"oci_optimizer_profile":             {Tok: makeDataSource(optimizerMod, "getProfile")},
			"oci_optimizer_profiles":            {Tok: makeDataSource(optimizerMod, "getProfiles")},
			"oci_optimizer_recommendation":      {Tok: makeDataSource(optimizerMod, "getRecommendation")},
			// "oci_optimizer_recommendation_strategies": {Tok: makeDataSource(optimizerMod, "getRecommendationStrategies")},
			// "oci_optimizer_recommendation_strategy": {Tok: makeDataSource(optimizerMod, "getRecommendationStrategy")},
			"oci_optimizer_recommendations":  {Tok: makeDataSource(optimizerMod, "getRecommendations")},
			"oci_optimizer_resource_action":  {Tok: makeDataSource(optimizerMod, "getResourceAction")},
			"oci_optimizer_resource_actions": {Tok: makeDataSource(optimizerMod, "getResourceActions")},
			// OCVP
			"oci_ocvp_esxi_host":                          {Tok: makeDataSource(ocvpMod, "getEsxiHost")},
			"oci_ocvp_esxi_hosts":                         {Tok: makeDataSource(ocvpMod, "getEsxiHosts")},
			"oci_ocvp_sddc":                               {Tok: makeDataSource(ocvpMod, "getSddc")},
			"oci_ocvp_sddcs":                              {Tok: makeDataSource(ocvpMod, "getSddcs")},
			"oci_ocvp_supported_skus":                     {Tok: makeDataSource(ocvpMod, "getSupportedSkus")},
			"oci_ocvp_supported_vmware_software_versions": {Tok: makeDataSource(ocvpMod, "getSupportedVmwareSoftwareVersions")},
			// OS Management
			"oci_osmanagement_managed_instance":        {Tok: makeDataSource(osManagementMod, "getManagedInstance")},
			"oci_osmanagement_managed_instance_group":  {Tok: makeDataSource(osManagementMod, "getManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_groups": {Tok: makeDataSource(osManagementMod, "getManagedInstanceGroups")},
			"oci_osmanagement_managed_instances":       {Tok: makeDataSource(osManagementMod, "getManagedInstances")},
			"oci_osmanagement_software_source":         {Tok: makeDataSource(osManagementMod, "getSoftwareSource")},
			"oci_osmanagement_software_sources":        {Tok: makeDataSource(osManagementMod, "getSoftwareSources")},
			// Resource Manager
			"oci_resourcemanager_stacks":         {Tok: makeDataSource(resourceManagerMod, "getStacks")},
			"oci_resourcemanager_stack":          {Tok: makeDataSource(resourceManagerMod, "getStack")},
			"oci_resourcemanager_stack_tf_state": {Tok: makeDataSource(resourceManagerMod, "getStackTfState")},
			// Service Catalog
			"oci_service_catalog_private_application":          {Tok: makeDataSource(serviceCatalogMod, "getPrivateApplication")},
			"oci_service_catalog_private_application_package":  {Tok: makeDataSource(serviceCatalogMod, "getPrivateApplicationPackage")},
			"oci_service_catalog_private_application_packages": {Tok: makeDataSource(serviceCatalogMod, "getPrivateApplicationPackages")},
			"oci_service_catalog_private_applications":         {Tok: makeDataSource(serviceCatalogMod, "getPrivateApplications")},
			"oci_service_catalog_service_catalog":              {Tok: makeDataSource(serviceCatalogMod, "getServiceCatalog")},
			"oci_service_catalog_service_catalog_association":  {Tok: makeDataSource(serviceCatalogMod, "getServiceCatalogAssociation")},
			"oci_service_catalog_service_catalog_associations": {Tok: makeDataSource(serviceCatalogMod, "getServiceCatalogAssociations")},
			"oci_service_catalog_service_catalogs":             {Tok: makeDataSource(serviceCatalogMod, "getServiceCatalogs")},
			// SCH
			"oci_sch_service_connector":  {Tok: makeDataSource(schMod, "getServiceConnector")},
			"oci_sch_service_connectors": {Tok: makeDataSource(schMod, "getServiceConnectors")},
			// Streaming
			"oci_streaming_connect_harness":   {Tok: makeDataSource(streamingMod, "getConnectHarness")},
			"oci_streaming_connect_harnesses": {Tok: makeDataSource(streamingMod, "getConnectHarnesses")},
			"oci_streaming_stream":            {Tok: makeDataSource(streamingMod, "getStream")},
			"oci_streaming_stream_pool":       {Tok: makeDataSource(streamingMod, "getStreamPool")},
			"oci_streaming_stream_pools":      {Tok: makeDataSource(streamingMod, "getStreamPools")},
			"oci_streaming_streams":           {Tok: makeDataSource(streamingMod, "getStreams")},
			// Vault
			"oci_vault_secrets":        {Tok: makeDataSource(vaultMod, "getSecrets")},
			"oci_vault_secret":         {Tok: makeDataSource(vaultMod, "getSecret")},
			"oci_vault_secret_version": {Tok: makeDataSource(vaultMod, "getSecretVersion")},
			// Vulnerability Scanning
			"oci_vulnerability_scanning_container_scan_recipe":  {Tok: makeDataSource(vulnerabilityScanningMod, "getContainerScanRecipe")},
			"oci_vulnerability_scanning_container_scan_recipes": {Tok: makeDataSource(vulnerabilityScanningMod, "getContainerScanRecipes")},
			"oci_vulnerability_scanning_container_scan_target":  {Tok: makeDataSource(vulnerabilityScanningMod, "getContainerScanTarget")},
			"oci_vulnerability_scanning_container_scan_targets": {Tok: makeDataSource(vulnerabilityScanningMod, "getContainerScanTargets")},
			"oci_vulnerability_scanning_host_scan_recipe":       {Tok: makeDataSource(vulnerabilityScanningMod, "getHostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_recipes":      {Tok: makeDataSource(vulnerabilityScanningMod, "getHostScanRecipes")},
			"oci_vulnerability_scanning_host_scan_target":       {Tok: makeDataSource(vulnerabilityScanningMod, "getHostScanTarget")},
			"oci_vulnerability_scanning_host_scan_targets":      {Tok: makeDataSource(vulnerabilityScanningMod, "getHostScanTargets")},
			// WAAS
			"oci_waas_address_list":            {Tok: makeDataSource(waasMod, "getAddressList")},
			"oci_waas_address_lists":           {Tok: makeDataSource(waasMod, "getAddressLists")},
			"oci_waas_certificate":             {Tok: makeDataSource(waasMod, "getCertificate")},
			"oci_waas_certificates":            {Tok: makeDataSource(waasMod, "getCertificates")},
			"oci_waas_custom_protection_rule":  {Tok: makeDataSource(waasMod, "getCustomProtectionRule")},
			"oci_waas_custom_protection_rules": {Tok: makeDataSource(waasMod, "getCustomProtectionRules")},
			"oci_waas_edge_subnets":            {Tok: makeDataSource(waasMod, "getEdgeSubnets")},
			"oci_waas_http_redirect":           {Tok: makeDataSource(waasMod, "getHttpRedirect")},
			"oci_waas_http_redirects":          {Tok: makeDataSource(waasMod, "getHttpRedirects")},
			"oci_waas_protection_rule":         {Tok: makeDataSource(waasMod, "getProtectionRule")},
			"oci_waas_protection_rules":        {Tok: makeDataSource(waasMod, "getProtectionRules")},
			"oci_waas_waas_policies":           {Tok: makeDataSource(waasMod, "getWaasPolicies")},
			"oci_waas_waas_policy":             {Tok: makeDataSource(waasMod, "getWaasPolicy")},
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
