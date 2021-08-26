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
	"strings"
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

// ociMember manufactures a type token for the OCI package and the given module, file name, and type.
func ociMember(moduleTitle string, fn string, mem string) tokens.ModuleMember {
	moduleName := strings.ToLower(moduleTitle)
	namespaceMap[moduleName] = moduleTitle
	if fn != "" {
		moduleName += "/" + fn
	}
	return tokens.ModuleMember(ociPkg + ":" + moduleName + ":" + mem)
}

// ociType manufactures a type token for the OCI package and the given module, file name, and type.
func ociType(mod string, fn string, typ string) tokens.Type {
	return tokens.Type(ociMember(mod, fn, typ))
}

// ociTypeDefaultFile manufactures a standard resource token given a module and resource name.  It automatically uses the OCI
// package and names the file by simply lower casing the type's first character.
func ociTypeDefaultFile(mod string, typ string) tokens.Type {
	fn := string(unicode.ToLower(rune(typ[0]))) + typ[1:]
	return ociType(mod, fn, typ)
}

// ociDataSource manufactures a standard resource token given a module and resource name. It automatically uses the OCI
// package and names the file by simply lower casing the data source's first character.
func ociDataSource(mod string, res string) tokens.ModuleMember {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return ociMember(mod, fn, res)
}

// ociResource manufactures a standard resource token given a module and resource name.
func ociResource(mod string, res string) tokens.Type {
	return ociTypeDefaultFile(mod, res)
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
			"oci_ai_anomaly_detection_ai_private_endpoint": {Tok: ociResource(aiAnomalyDetectionMod, "AiPrivateEndpoint")},
			"oci_ai_anomaly_detection_data_asset":          {Tok: ociResource(aiAnomalyDetectionMod, "DataAsset")},
			"oci_ai_anomaly_detection_model":               {Tok: ociResource(aiAnomalyDetectionMod, "Model")},
			"oci_ai_anomaly_detection_project":             {Tok: ociResource(aiAnomalyDetectionMod, "Project")},
			// Analytics
			"oci_analytics_analytics_instance":                        {Tok: ociResource(analyticsMod, "AnalyticsInstance")},
			"oci_analytics_analytics_instance_private_access_channel": {Tok: ociResource(analyticsMod, "AnalyticsInstancePrivateAccessChannel")},
			"oci_analytics_analytics_instance_vanity_url":             {Tok: ociResource(analyticsMod, "AnalyticsInstanceVanityUrl")},
			// API Gateway
			"oci_apigateway_api":         {Tok: ociResource(apiGatewayMod, "Api")},
			"oci_apigateway_certificate": {Tok: ociResource(apiGatewayMod, "Certificate")},
			"oci_apigateway_deployment":  {Tok: ociResource(apiGatewayMod, "Deployment")},
			"oci_apigateway_gateway":     {Tok: ociResource(apiGatewayMod, "Gateway")},
			// Apm Synthetics
			"oci_apm_synthetics_monitor": {Tok: ociResource(apmSyntheticsMod, "Monitor")},
			"oci_apm_synthetics_script":  {Tok: ociResource(apmSyntheticsMod, "Script")},
			// APM
			"oci_apm_apm_domain": {Tok: ociResource(apmMod, "ApmDomain")},
			// Artifacts
			"oci_artifacts_container_configuration":   {Tok: ociResource(artifactsMod, "ContainerConfiguration")},
			"oci_artifacts_container_image_signature": {Tok: ociResource(artifactsMod, "ContainerImageSignature")},
			"oci_artifacts_container_repository":      {Tok: ociResource(artifactsMod, "ContainerRepository")},
			"oci_artifacts_generic_artifact":          {Tok: ociResource(artifactsMod, "GenericArtifact")},
			"oci_artifacts_repository":                {Tok: ociResource(artifactsMod, "Repository")},
			// Audit
			"oci_audit_configuration": {Tok: ociResource(auditMod, "Configuration")},
			// AutoScaling
			"oci_autoscaling_auto_scaling_configuration": {Tok: ociResource(autoscalingMod, "AutoScalingConfiguration")},
			// Bastion
			"oci_bastion_bastion": {Tok: ociResource(bastionMod, "Bastion")},
			"oci_bastion_session": {Tok: ociResource(bastionMod, "Session")},
			// BDS
			"oci_bds_auto_scaling_configuration": {Tok: ociResource(bdsMod, "AutoScalingConfiguration")},
			"oci_bds_bds_instance":               {Tok: ociResource(bdsMod, "BdsInstance")},
			// Blockchain
			"oci_blockchain_blockchain_platform": {Tok: ociResource(blockchainMod, "BlockchainPlatform")},
			"oci_blockchain_osn":                 {Tok: ociResource(blockchainMod, "Osn")},
			"oci_blockchain_peer":                {Tok: ociResource(blockchainMod, "Peer")},
			// Budget
			"oci_budget_alert_rule": {Tok: ociResource(budgetMod, "AlertRule")},
			"oci_budget_budget":     {Tok: ociResource(budgetMod, "Budget")},
			// Cloud Guard
			"oci_cloud_guard_cloud_guard_configuration": {Tok: ociResource(cloudGuardMod, "CloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":            {Tok: ociResource(cloudGuardMod, "DataMaskRule")},
			"oci_cloud_guard_detector_recipe":           {Tok: ociResource(cloudGuardMod, "DetectorRecipe")},
			"oci_cloud_guard_managed_list":              {Tok: ociResource(cloudGuardMod, "ManagedList")},
			"oci_cloud_guard_responder_recipe":          {Tok: ociResource(cloudGuardMod, "ResponderRecipe")},
			"oci_cloud_guard_target":                    {Tok: ociResource(cloudGuardMod, "Target")},
			// Compute Instance Agent
			// Container Engine
			"oci_containerengine_cluster":   {Tok: ociResource(containerEngineMod, "Cluster")},
			"oci_containerengine_node_pool": {Tok: ociResource(containerEngineMod, "NodePool")},
			// OCE
			"oci_oce_oce_instance": {Tok: ociResource(oceMod, "OceInstance")},
			// Core
			"oci_core_app_catalog_listing_resource_version_agreement": {Tok: ociResource(coreMod, "AppCatalogListingResourceVersionAgreement")},
			"oci_core_app_catalog_subscription":                       {Tok: ociResource(coreMod, "AppCatalogSubscription")},
			"oci_core_boot_volume":                                    {Tok: ociResource(coreMod, "BootVolume")},
			"oci_core_boot_volume_backup":                             {Tok: ociResource(coreMod, "BootVolumeBackup")},
			"oci_core_cluster_network":                                {Tok: ociResource(coreMod, "ClusterNetwork")},
			"oci_core_compute_capacity_reservation":                   {Tok: ociResource(coreMod, "ComputeCapacityReservation")},
			"oci_core_compute_image_capability_schema":                {Tok: ociResource(coreMod, "ComputeImageCapabilitySchema")},
			"oci_core_console_history":                                {Tok: ociResource(coreMod, "ConsoleHistory")},
			"oci_core_cpe":                                            {Tok: ociResource(coreMod, "Cpe")},
			"oci_core_cross_connect":                                  {Tok: ociResource(coreMod, "CrossConnect")},
			"oci_core_cross_connect_group":                            {Tok: ociResource(coreMod, "CrossConnectGroup")},
			"oci_core_dedicated_vm_host":                              {Tok: ociResource(coreMod, "DedicatedVmHost")},
			"oci_core_dhcp_options":                                   {Tok: ociResource(coreMod, "DhcpOptions")},
			"oci_core_drg":                                            {Tok: ociResource(coreMod, "Drg")},
			"oci_core_drg_attachment":                                 {Tok: ociResource(coreMod, "DrgAttachment")},
			"oci_core_drg_attachment_management":                      {Tok: ociResource(coreMod, "DrgAttachmentManagement")},
			"oci_core_drg_attachments_list":                           {Tok: ociResource(coreMod, "DrgAttachmentsList")},
			"oci_core_drg_route_distribution":                         {Tok: ociResource(coreMod, "DrgRouteDistribution")},
			"oci_core_drg_route_distribution_statement":               {Tok: ociResource(coreMod, "DrgRouteDistributionStatement")},
			"oci_core_drg_route_table":                                {Tok: ociResource(coreMod, "DrgRouteTable")},
			"oci_core_drg_route_table_route_rule":                     {Tok: ociResource(coreMod, "DrgRouteTableRouteRule")},
			"oci_core_image":                                          {Tok: ociResource(coreMod, "Image")},
			"oci_core_instance":                                       {Tok: ociResource(coreMod, "Instance")},
			"oci_core_instance_configuration":                         {Tok: ociResource(coreMod, "InstanceConfiguration")},
			"oci_core_instance_console_connection":                    {Tok: ociResource(coreMod, "InstanceConsoleConnection")},
			"oci_core_instance_pool":                                  {Tok: ociResource(coreMod, "InstancePool")},
			"oci_core_instance_pool_instance":                         {Tok: ociResource(coreMod, "InstancePoolInstance")},
			"oci_core_internet_gateway":                               {Tok: ociResource(coreMod, "InternetGateway")},
			"oci_core_ipsec":                                          {Tok: ociResource(coreMod, "Ipsec")},
			"oci_core_ipsec_connection_tunnel_management":             {Tok: ociResource(coreMod, "IpsecConnectionTunnelManagement")},
			"oci_core_ipv6":                                           {Tok: ociResource(coreMod, "Ipv6")},
			"oci_core_local_peering_gateway":                          {Tok: ociResource(coreMod, "LocalPeeringGateway")},
			"oci_core_nat_gateway":                                    {Tok: ociResource(coreMod, "NatGateway")},
			"oci_core_network_security_group":                         {Tok: ociResource(coreMod, "NetworkSecurityGroup")},
			"oci_core_network_security_group_security_rule":           {Tok: ociResource(coreMod, "NetworkSecurityGroupSecurityRule")},
			"oci_core_private_ip":                                     {Tok: ociResource(coreMod, "PrivateIp")},
			"oci_core_public_ip":                                      {Tok: ociResource(coreMod, "PublicIp")},
			"oci_core_public_ip_pool":                                 {Tok: ociResource(coreMod, "PublicIpPool")},
			"oci_core_public_ip_pool_capacity":                        {Tok: ociResource(coreMod, "PublicIpPoolCapacity")},
			"oci_core_remote_peering_connection":                      {Tok: ociResource(coreMod, "RemotePeeringConnection")},
			"oci_core_route_table":                                    {Tok: ociResource(coreMod, "RouteTable")},
			"oci_core_route_table_attachment":                         {Tok: ociResource(coreMod, "RouteTableAttachment")},
			"oci_core_security_list":                                  {Tok: ociResource(coreMod, "SecurityList")},
			"oci_core_service_gateway":                                {Tok: ociResource(coreMod, "ServiceGateway")},
			"oci_core_subnet":                                         {Tok: ociResource(coreMod, "Subnet")},
			"oci_core_vcn":                                            {Tok: ociResource(coreMod, "Vcn")},
			"oci_core_virtual_circuit":                                {Tok: ociResource(coreMod, "VirtualCircuit")},
			"oci_core_vlan":                                           {Tok: ociResource(coreMod, "Vlan")},
			"oci_core_vnic_attachment":                                {Tok: ociResource(coreMod, "VnicAttachment")},
			"oci_core_volume":                                         {Tok: ociResource(coreMod, "Volume")},
			"oci_core_volume_attachment":                              {Tok: ociResource(coreMod, "VolumeAttachment")},
			"oci_core_volume_backup":                                  {Tok: ociResource(coreMod, "VolumeBackup")},
			"oci_core_volume_backup_policy":                           {Tok: ociResource(coreMod, "VolumeBackupPolicy")},
			"oci_core_volume_backup_policy_assignment":                {Tok: ociResource(coreMod, "VolumeBackupPolicyAssignment")},
			"oci_core_volume_group":                                   {Tok: ociResource(coreMod, "VolumeGroup")},
			"oci_core_volume_group_backup":                            {Tok: ociResource(coreMod, "VolumeGroupBackup")},
			// Data Catalog
			"oci_datacatalog_catalog":                  {Tok: ociResource(dataCatalogMod, "Catalog")},
			"oci_datacatalog_catalog_private_endpoint": {Tok: ociResource(dataCatalogMod, "CatalogPrivateEndpoint")},
			"oci_datacatalog_connection":               {Tok: ociResource(dataCatalogMod, "Connection")},
			"oci_datacatalog_data_asset":               {Tok: ociResource(dataCatalogMod, "DataAsset")},
			// Data Flow
			"oci_dataflow_application":      {Tok: ociResource(dataFlowMod, "Application")},
			"oci_dataflow_invoke_run":       {Tok: ociResource(dataFlowMod, "InvokeRun")},
			"oci_dataflow_private_endpoint": {Tok: ociResource(dataFlowMod, "PrivateEndpoint")},
			// Data Integration
			"oci_dataintegration_workspace": {Tok: ociResource(dataIntegrationMod, "Workspace")},
			// Data Safe
			"oci_data_safe_data_safe_configuration":    {Tok: ociResource(dataSafeMod, "DataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint": {Tok: ociResource(dataSafeMod, "DataSafePrivateEndpoint")},
			"oci_data_safe_on_prem_connector":          {Tok: ociResource(dataSafeMod, "OnPremConnector")},
			"oci_data_safe_target_database":            {Tok: ociResource(dataSafeMod, "TargetDatabase")},
			// Data Science
			"oci_datascience_model":            {Tok: ociResource(dataScienceMod, "Model")},
			"oci_datascience_model_deployment": {Tok: ociResource(dataScienceMod, "ModelDeployment")},
			"oci_datascience_model_provenance": {Tok: ociResource(dataScienceMod, "ModelProvenance")},
			"oci_datascience_notebook_session": {Tok: ociResource(dataScienceMod, "NotebookSession")},
			"oci_datascience_project":          {Tok: ociResource(dataScienceMod, "Project")},
			// Database
			"oci_database_autonomous_container_database":                                  {Tok: ociResource(databaseMod, "AutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association_operation":  {Tok: ociResource(databaseMod, "AutonomousContainerDatabaseDataguardAssociationOperation")},
			"oci_database_autonomous_database":                                            {Tok: ociResource(databaseMod, "AutonomousDatabase")},
			"oci_database_autonomous_database_backup":                                     {Tok: ociResource(databaseMod, "AutonomousDatabaseBackup")},
			"oci_database_autonomous_database_instance_wallet_management":                 {Tok: ociResource(databaseMod, "AutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_regional_wallet_management":                 {Tok: ociResource(databaseMod, "AutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                                     {Tok: ociResource(databaseMod, "AutonomousDatabaseWallet")},
			"oci_database_autonomous_exadata_infrastructure":                              {Tok: ociResource(databaseMod, "AutonomousExadataInfrastructure")},
			"oci_database_autonomous_vm_cluster":                                          {Tok: ociResource(databaseMod, "AutonomousVmCluster")},
			"oci_database_backup":                                                         {Tok: ociResource(databaseMod, "Backup")},
			"oci_database_backup_destination":                                             {Tok: ociResource(databaseMod, "BackupDestination")},
			"oci_database_cloud_exadata_infrastructure":                                   {Tok: ociResource(databaseMod, "CloudExadataInfrastructure")},
			"oci_database_cloud_vm_cluster":                                               {Tok: ociResource(databaseMod, "CloudVmCluster")},
			"oci_database_data_guard_association":                                         {Tok: ociResource(databaseMod, "DataGuardAssociation")},
			"oci_database_database":                                                       {Tok: ociResource(databaseMod, "Database")},
			"oci_database_database_software_image":                                        {Tok: ociResource(databaseMod, "DatabaseSoftwareImage")},
			"oci_database_database_upgrade":                                               {Tok: ociResource(databaseMod, "DatabaseUpgrade")},
			"oci_database_db_home":                                                        {Tok: ociResource(databaseMod, "DbHome")},
			"oci_database_db_node_console_connection":                                     {Tok: ociResource(databaseMod, "DbNodeConsoleConnection")},
			"oci_database_db_system":                                                      {Tok: ociResource(databaseMod, "DbSystem")},
			"oci_database_exadata_infrastructure":                                         {Tok: ociResource(databaseMod, "ExadataInfrastructure")},
			"oci_database_exadata_iorm_config":                                            {Tok: ociResource(databaseMod, "ExadataIormConfig")},
			"oci_database_external_container_database":                                    {Tok: ociResource(databaseMod, "ExternalContainerDatabase")},
			"oci_database_external_container_database_management":                         {Tok: ociResource(databaseMod, "ExternalContainerDatabaseManagement")},
			"oci_database_external_database_connector":                                    {Tok: ociResource(databaseMod, "ExternalDatabaseConnector")},
			"oci_database_external_non_container_database":                                {Tok: ociResource(databaseMod, "ExternalNonContainerDatabase")},
			"oci_database_external_non_container_database_management":                     {Tok: ociResource(databaseMod, "ExternalNonContainerDatabaseManagement")},
			"oci_database_external_non_container_database_operations_insights_management": {Tok: ociResource(databaseMod, "ExternalNonContainerDatabaseOperationsInsightsManagement")},
			"oci_database_external_pluggable_database":                                    {Tok: ociResource(databaseMod, "ExternalPluggableDatabase")},
			"oci_database_external_pluggable_database_management":                         {Tok: ociResource(databaseMod, "ExternalPluggableDatabaseManagement")},
			"oci_database_external_pluggable_database_operations_insights_management":     {Tok: ociResource(databaseMod, "ExternalPluggableDatabaseOperationsInsightsManagement")},
			"oci_database_key_store":                                                      {Tok: ociResource(databaseMod, "KeyStore")},
			"oci_database_maintenance_run":                                                {Tok: ociResource(databaseMod, "MaintenanceRun")},
			"oci_database_migration":                                                      {Tok: ociResource(databaseMod, "Migration")},
			"oci_database_pluggable_database":                                             {Tok: ociResource(databaseMod, "PluggableDatabase")},
			"oci_database_pluggable_databases_local_clone":                                {Tok: ociResource(databaseMod, "PluggableDatabasesLocalClone")},
			"oci_database_pluggable_databases_remote_clone":                               {Tok: ociResource(databaseMod, "PluggableDatabasesRemoteClone")},
			"oci_database_vm_cluster":                                                     {Tok: ociResource(databaseMod, "VmCluster")},
			"oci_database_vm_cluster_network":                                             {Tok: ociResource(databaseMod, "VmClusterNetwork")},
			// Database Management
			"oci_database_management_managed_database_group":                      {Tok: ociResource(databaseManagementMod, "ManagedDatabaseGroup")},
			"oci_database_management_managed_databases_change_database_parameter": {Tok: ociResource(databaseManagementMod, "ManagedDatabasesChangeDatabaseParameter")},
			"oci_database_management_managed_databases_reset_database_parameter":  {Tok: ociResource(databaseManagementMod, "ManagedDatabasesResetDatabaseParameter")},
			// Database Migration
			"oci_database_migration_agent":      {Tok: ociResource(databaseMigrationMod, "Agent")},
			"oci_database_migration_connection": {Tok: ociResource(databaseMigrationMod, "Connection")},
			"oci_database_migration_job":        {Tok: ociResource(databaseMigrationMod, "Job")},
			"oci_database_migration_migration":  {Tok: ociResource(databaseMigrationMod, "Migration")},
			// Devops
			"oci_devops_deploy_artifact":    {Tok: ociResource(devopsMod, "DeployArtifact")},
			"oci_devops_deploy_environment": {Tok: ociResource(devopsMod, "DeployEnvironment")},
			"oci_devops_deploy_pipeline":    {Tok: ociResource(devopsMod, "DeployPipeline")},
			"oci_devops_deploy_stage":       {Tok: ociResource(devopsMod, "DeployStage")},
			"oci_devops_deployment":         {Tok: ociResource(devopsMod, "Deployment")},
			"oci_devops_project":            {Tok: ociResource(devopsMod, "Project")},
			// ODA
			"oci_oda_oda_instance": {Tok: ociResource(odaMod, "OdaInstance")},
			// DNS
			"oci_dns_record":                     {Tok: ociResource(dnsMod, "Record")},
			"oci_dns_resolver":                   {Tok: ociResource(dnsMod, "Resolver")},
			"oci_dns_resolver_endpoint":          {Tok: ociResource(dnsMod, "ResolverEndpoint")},
			"oci_dns_rrset":                      {Tok: ociResource(dnsMod, "Rrset")},
			"oci_dns_steering_policy":            {Tok: ociResource(dnsMod, "SteeringPolicy")},
			"oci_dns_steering_policy_attachment": {Tok: ociResource(dnsMod, "SteeringPolicyAttachment")},
			"oci_dns_tsig_key":                   {Tok: ociResource(dnsMod, "TsigKey")},
			"oci_dns_view":                       {Tok: ociResource(dnsMod, "View")},
			"oci_dns_zone":                       {Tok: ociResource(dnsMod, "Zone")},
			// Email
			"oci_email_dkim":         {Tok: ociResource(emailMod, "Dkim")},
			"oci_email_email_domain": {Tok: ociResource(emailMod, "EmailDomain")},
			"oci_email_sender":       {Tok: ociResource(emailMod, "Sender")},
			"oci_email_suppression":  {Tok: ociResource(emailMod, "Suppression")},
			// Events
			"oci_events_rule": {Tok: ociResource(eventsMod, "Rule")},
			// File Storage
			"oci_file_storage_export":       {Tok: ociResource(fileStorageMod, "Export")},
			"oci_file_storage_export_set":   {Tok: ociResource(fileStorageMod, "ExportSet")},
			"oci_file_storage_file_system":  {Tok: ociResource(fileStorageMod, "FileSystem")},
			"oci_file_storage_mount_target": {Tok: ociResource(fileStorageMod, "MountTarget")},
			"oci_file_storage_snapshot":     {Tok: ociResource(fileStorageMod, "Snapshot")},
			// Functions
			"oci_functions_application":     {Tok: ociResource(functionsMod, "Application")},
			"oci_functions_function":        {Tok: ociResource(functionsMod, "Function")},
			"oci_functions_invoke_function": {Tok: ociResource(functionsMod, "InvokeFunction")},
			// Generic Artifacts Content
			// Golden Gate
			"oci_golden_gate_database_registration": {Tok: ociResource(goldenGateMod, "DatabaseRegistration")},
			"oci_golden_gate_deployment":            {Tok: ociResource(goldenGateMod, "Deployment")},
			"oci_golden_gate_deployment_backup":     {Tok: ociResource(goldenGateMod, "DeploymentBackup")},
			// Health Checks
			"oci_health_checks_http_monitor": {Tok: ociResource(healthChecksMod, "HttpMonitor")},
			"oci_health_checks_http_probe":   {Tok: ociResource(healthChecksMod, "HttpProbe")},
			"oci_health_checks_ping_monitor": {Tok: ociResource(healthChecksMod, "PingMonitor")},
			"oci_health_checks_ping_probe":   {Tok: ociResource(healthChecksMod, "PingProbe")},
			// Identity
			"oci_identity_api_key":                      {Tok: ociResource(identityMod, "ApiKey")},
			"oci_identity_auth_token":                   {Tok: ociResource(identityMod, "AuthToken")},
			"oci_identity_authentication_policy":        {Tok: ociResource(identityMod, "AuthenticationPolicy")},
			"oci_identity_compartment":                  {Tok: ociResource(identityMod, "Compartment")},
			"oci_identity_customer_secret_key":          {Tok: ociResource(identityMod, "CustomerSecretKey")},
			"oci_identity_dynamic_group":                {Tok: ociResource(identityMod, "DynamicGroup")},
			"oci_identity_group":                        {Tok: ociResource(identityMod, "Group")},
			"oci_identity_identity_provider":            {Tok: ociResource(identityMod, "IdentityProvider")},
			"oci_identity_idp_group_mapping":            {Tok: ociResource(identityMod, "IdpGroupMapping")},
			"oci_identity_network_source":               {Tok: ociResource(identityMod, "NetworkSource")},
			"oci_identity_policy":                       {Tok: ociResource(identityMod, "Policy")},
			"oci_identity_smtp_credential":              {Tok: ociResource(identityMod, "SmtpCredential")},
			"oci_identity_swift_password":               {Tok: ociResource(identityMod, "SwiftPassword")},
			"oci_identity_tag":                          {Tok: ociResource(identityMod, "Tag")},
			"oci_identity_tag_default":                  {Tok: ociResource(identityMod, "TagDefault")},
			"oci_identity_tag_namespace":                {Tok: ociResource(identityMod, "TagNamespace")},
			"oci_identity_ui_password":                  {Tok: ociResource(identityMod, "UiPassword")},
			"oci_identity_user":                         {Tok: ociResource(identityMod, "User")},
			"oci_identity_user_capabilities_management": {Tok: ociResource(identityMod, "UserCapabilitiesManagement")},
			"oci_identity_user_group_membership":        {Tok: ociResource(identityMod, "UserGroupMembership")},
			// Integration
			"oci_integration_integration_instance": {Tok: ociResource(integrationMod, "IntegrationInstance")},
			// Jms
			"oci_jms_fleet": {Tok: ociResource(jmsMod, "Fleet")},
			// Kms
			"oci_kms_encrypted_data": {Tok: ociResource(kmsMod, "EncryptedData")},
			"oci_kms_generated_key":  {Tok: ociResource(kmsMod, "GeneratedKey")},
			"oci_kms_key":            {Tok: ociResource(kmsMod, "Key")},
			"oci_kms_key_version":    {Tok: ociResource(kmsMod, "KeyVersion")},
			"oci_kms_sign":           {Tok: ociResource(kmsMod, "Sign")},
			"oci_kms_vault":          {Tok: ociResource(kmsMod, "Vault")},
			"oci_kms_verify":         {Tok: ociResource(kmsMod, "Verify")},
			// Limits
			"oci_limits_quota": {Tok: ociResource(limitsMod, "Quota")},
			// Load Balancer
			"oci_load_balancer_backend":                      {Tok: ociResource(loadBalancerMod, "Backend")},
			"oci_load_balancer_backend_set":                  {Tok: ociResource(loadBalancerMod, "BackendSet")},
			"oci_load_balancer_certificate":                  {Tok: ociResource(loadBalancerMod, "Certificate")},
			"oci_load_balancer_hostname":                     {Tok: ociResource(loadBalancerMod, "Hostname")},
			"oci_load_balancer_listener":                     {Tok: ociResource(loadBalancerMod, "Listener")},
			"oci_load_balancer_load_balancer":                {Tok: ociResource(loadBalancerMod, "LoadBalancer")},
			"oci_load_balancer_load_balancer_routing_policy": {Tok: ociResource(loadBalancerMod, "LoadBalancerRoutingPolicy")},
			"oci_load_balancer_path_route_set":               {Tok: ociResource(loadBalancerMod, "PathRouteSet")},
			"oci_load_balancer_rule_set":                     {Tok: ociResource(loadBalancerMod, "RuleSet")},
			"oci_load_balancer_ssl_cipher_suite":             {Tok: ociResource(loadBalancerMod, "SslCipherSuite")},
			// Log Analytics
			"oci_log_analytics_log_analytics_entity":                 {Tok: ociResource(logAnalyticsMod, "LogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_log_group":              {Tok: ociResource(logAnalyticsMod, "LogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_object_collection_rule": {Tok: ociResource(logAnalyticsMod, "LogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_namespace":                            {Tok: ociResource(logAnalyticsMod, "Namespace")},
			// Logging
			"oci_logging_log":                         {Tok: ociResource(loggingMod, "Log")},
			"oci_logging_log_group":                   {Tok: ociResource(loggingMod, "LogGroup")},
			"oci_logging_log_saved_search":            {Tok: ociResource(loggingMod, "LogSavedSearch")},
			"oci_logging_unified_agent_configuration": {Tok: ociResource(loggingMod, "UnifiedAgentConfiguration")},
			// Management Agent
			"oci_management_agent_management_agent":             {Tok: ociResource(managementAgentMod, "ManagementAgent")},
			"oci_management_agent_management_agent_install_key": {Tok: ociResource(managementAgentMod, "ManagementAgentInstallKey")},
			// Management Dashboard
			"oci_management_dashboard_management_dashboards_import": {Tok: ociResource(managementDashboardMod, "ManagementDashboardsImport")},
			// Marketplace
			"oci_marketplace_accepted_agreement": {Tok: ociResource(marketplaceMod, "AcceptedAgreement")},
			"oci_marketplace_publication":        {Tok: ociResource(marketplaceMod, "Publication")},
			// Metering Computation
			"oci_metering_computation_custom_table": {Tok: ociResource(meteringComputationMod, "CustomTable")},
			"oci_metering_computation_query":        {Tok: ociResource(meteringComputationMod, "Query")},
			"oci_metering_computation_usage":        {Tok: ociResource(meteringComputationMod, "Usage")},
			// Monitoring
			"oci_monitoring_alarm": {Tok: ociResource(monitoringMod, "Alarm")},
			// MYSQL
			"oci_mysql_analytics_cluster": {Tok: ociResource(mysqlMod, "AnalyticsCluster")},
			"oci_mysql_channel":           {Tok: ociResource(mysqlMod, "Channel")},
			"oci_mysql_heat_wave_cluster": {Tok: ociResource(mysqlMod, "HeatWaveCluster")},
			"oci_mysql_mysql_backup":      {Tok: ociResource(mysqlMod, "MysqlBackup")},
			"oci_mysql_mysql_db_system":   {Tok: ociResource(mysqlMod, "MysqlDbSystem")},
			// Network Load Balancer
			"oci_network_load_balancer_backend":               {Tok: ociResource(networkLoadBalancerMod, "Backend")},
			"oci_network_load_balancer_backend_set":           {Tok: ociResource(networkLoadBalancerMod, "BackendSet")},
			"oci_network_load_balancer_listener":              {Tok: ociResource(networkLoadBalancerMod, "Listener")},
			"oci_network_load_balancer_network_load_balancer": {Tok: ociResource(networkLoadBalancerMod, "NetworkLoadBalancer")},
			// NOSQL
			"oci_nosql_index": {Tok: ociResource(nosqlMod, "Index")},
			"oci_nosql_table": {Tok: ociResource(nosqlMod, "Table")},
			// ONS
			"oci_ons_notification_topic": {Tok: ociResource(onsMod, "NotificationTopic")},
			"oci_ons_subscription":       {Tok: ociResource(onsMod, "Subscription")},
			// Object Storage
			"oci_objectstorage_bucket":                  {Tok: ociResource(objectStorageMod, "ObjectstorageBucket")},
			"oci_objectstorage_object":                  {Tok: ociResource(objectStorageMod, "ObjectstorageObject")},
			"oci_objectstorage_object_lifecycle_policy": {Tok: ociResource(objectStorageMod, "ObjectstorageObjectLifecyclePolicy")},
			"oci_objectstorage_preauthrequest":          {Tok: ociResource(objectStorageMod, "ObjectstoragePreauthrequest")},
			"oci_objectstorage_replication_policy":      {Tok: ociResource(objectStorageMod, "ObjectstorageReplicationPolicy")},
			// Opsi
			"oci_opsi_database_insight":          {Tok: ociResource(opsiMod, "DatabaseInsight")},
			"oci_opsi_enterprise_manager_bridge": {Tok: ociResource(opsiMod, "EnterpriseManagerBridge")},
			"oci_opsi_host_insight":              {Tok: ociResource(opsiMod, "HostInsight")},
			// Optimizer
			"oci_optimizer_enrollment_status": {Tok: ociResource(optimizerMod, "EnrollmentStatus")},
			"oci_optimizer_profile":           {Tok: ociResource(optimizerMod, "Profile")},
			"oci_optimizer_recommendation":    {Tok: ociResource(optimizerMod, "Recommendation")},
			"oci_optimizer_resource_action":   {Tok: ociResource(optimizerMod, "ResourceAction")},
			// OCVP
			"oci_ocvp_esxi_host": {Tok: ociResource(ocvpMod, "EsxiHost")},
			"oci_ocvp_sddc":      {Tok: ociResource(ocvpMod, "Sddc")},
			// OS Management
			"oci_osmanagement_managed_instance_group":      {Tok: ociResource(osManagementMod, "ManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_management": {Tok: ociResource(osManagementMod, "ManagedInstanceManagement")},
			"oci_osmanagement_software_source":             {Tok: ociResource(osManagementMod, "SoftwareSource")},
			// Resource Manager
			// Service Catalog
			"oci_service_catalog_private_application":         {Tok: ociResource(serviceCatalogMod, "PrivateApplication")},
			"oci_service_catalog_service_catalog":             {Tok: ociResource(serviceCatalogMod, "ServiceCatalog")},
			"oci_service_catalog_service_catalog_association": {Tok: ociResource(serviceCatalogMod, "ServiceCatalogAssociation")},
			// SCH
			"oci_sch_service_connector": {Tok: ociResource(schMod, "ServiceConnector")},
			// Streaming
			"oci_streaming_connect_harness": {Tok: ociResource(streamingMod, "ConnectHarness")},
			"oci_streaming_stream":          {Tok: ociResource(streamingMod, "Stream")},
			"oci_streaming_stream_pool":     {Tok: ociResource(streamingMod, "StreamPool")},
			// Vault
			// Vulnerability Scanning
			"oci_vulnerability_scanning_container_scan_recipe": {Tok: ociResource(vulnerabilityScanningMod, "ContainerScanRecipe")},
			"oci_vulnerability_scanning_container_scan_target": {Tok: ociResource(vulnerabilityScanningMod, "ContainerScanTarget")},
			"oci_vulnerability_scanning_host_scan_recipe":      {Tok: ociResource(vulnerabilityScanningMod, "HostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_target":      {Tok: ociResource(vulnerabilityScanningMod, "HostScanTarget")},
			// WAAS
			"oci_waas_address_list":           {Tok: ociResource(waasMod, "AddressList")},
			"oci_waas_certificate":            {Tok: ociResource(waasMod, "Certificate")},
			"oci_waas_custom_protection_rule": {Tok: ociResource(waasMod, "CustomProtectionRule")},
			"oci_waas_http_redirect":          {Tok: ociResource(waasMod, "HttpRedirect")},
			"oci_waas_protection_rule":        {Tok: ociResource(waasMod, "ProtectionRule")},
			"oci_waas_purge_cache":            {Tok: ociResource(waasMod, "PurgeCache")},
			"oci_waas_waas_policy":            {Tok: ociResource(waasMod, "WaasPolicy")},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			// Ai Anomaly Detection
			"oci_ai_anomaly_detection_ai_private_endpoint":  {Tok: ociDataSource(aiAnomalyDetectionMod, "getAiPrivateEndpoint")},
			"oci_ai_anomaly_detection_ai_private_endpoints": {Tok: ociDataSource(aiAnomalyDetectionMod, "getAiPrivateEndpoints")},
			"oci_ai_anomaly_detection_data_asset":           {Tok: ociDataSource(aiAnomalyDetectionMod, "getDataAsset")},
			"oci_ai_anomaly_detection_data_assets":          {Tok: ociDataSource(aiAnomalyDetectionMod, "getDataAssets")},
			"oci_ai_anomaly_detection_model":                {Tok: ociDataSource(aiAnomalyDetectionMod, "getModel")},
			"oci_ai_anomaly_detection_models":               {Tok: ociDataSource(aiAnomalyDetectionMod, "getModels")},
			"oci_ai_anomaly_detection_project":              {Tok: ociDataSource(aiAnomalyDetectionMod, "getProject")},
			"oci_ai_anomaly_detection_projects":             {Tok: ociDataSource(aiAnomalyDetectionMod, "getProjects")},
			// Analytics
			"oci_analytics_analytics_instance":                        {Tok: ociDataSource(analyticsMod, "getAnalyticsInstance")},
			"oci_analytics_analytics_instance_private_access_channel": {Tok: ociDataSource(analyticsMod, "getAnalyticsInstancePrivateAccessChannel")},
			"oci_analytics_analytics_instances":                       {Tok: ociDataSource(analyticsMod, "getAnalyticsInstances")},
			// API Gateway
			"oci_apigateway_api":                          {Tok: ociDataSource(apiGatewayMod, "getApi")},
			"oci_apigateway_api_content":                  {Tok: ociDataSource(apiGatewayMod, "getApiContent")},
			"oci_apigateway_api_deployment_specification": {Tok: ociDataSource(apiGatewayMod, "getApiDeploymentSpecification")},
			"oci_apigateway_api_validation":               {Tok: ociDataSource(apiGatewayMod, "getApiValidation")},
			"oci_apigateway_apis":                         {Tok: ociDataSource(apiGatewayMod, "getApis")},
			"oci_apigateway_certificate":                  {Tok: ociDataSource(apiGatewayMod, "getCertificate")},
			"oci_apigateway_certificates":                 {Tok: ociDataSource(apiGatewayMod, "getCertificates")},
			"oci_apigateway_deployment":                   {Tok: ociDataSource(apiGatewayMod, "getDeployment")},
			"oci_apigateway_deployments":                  {Tok: ociDataSource(apiGatewayMod, "getDeployments")},
			"oci_apigateway_gateway":                      {Tok: ociDataSource(apiGatewayMod, "getGateway")},
			"oci_apigateway_gateways":                     {Tok: ociDataSource(apiGatewayMod, "getGateways")},
			// Apm Synthetics
			"oci_apm_synthetics_monitor":               {Tok: ociDataSource(apmSyntheticsMod, "getMonitor")},
			"oci_apm_synthetics_monitors":              {Tok: ociDataSource(apmSyntheticsMod, "getMonitors")},
			"oci_apm_synthetics_public_vantage_point":  {Tok: ociDataSource(apmSyntheticsMod, "getPublicVantagePoint")},
			"oci_apm_synthetics_public_vantage_points": {Tok: ociDataSource(apmSyntheticsMod, "getPublicVantagePoints")},
			"oci_apm_synthetics_result":                {Tok: ociDataSource(apmSyntheticsMod, "getResult")},
			"oci_apm_synthetics_script":                {Tok: ociDataSource(apmSyntheticsMod, "getScript")},
			"oci_apm_synthetics_scripts":               {Tok: ociDataSource(apmSyntheticsMod, "getScripts")},
			// APM
			"oci_apm_apm_domain":  {Tok: ociDataSource(apmMod, "getApmDomain")},
			"oci_apm_apm_domains": {Tok: ociDataSource(apmMod, "getApmDomains")},
			"oci_apm_data_keys":   {Tok: ociDataSource(apmMod, "getDataKeys")},
			// Artifacts
			"oci_artifacts_container_configuration":    {Tok: ociDataSource(artifactsMod, "getContainerConfiguration")},
			"oci_artifacts_container_image":            {Tok: ociDataSource(artifactsMod, "getContainerImage")},
			"oci_artifacts_container_image_signature":  {Tok: ociDataSource(artifactsMod, "getContainerImageSignature")},
			"oci_artifacts_container_image_signatures": {Tok: ociDataSource(artifactsMod, "getContainerImageSignatures")},
			"oci_artifacts_container_images":           {Tok: ociDataSource(artifactsMod, "getContainerImages")},
			"oci_artifacts_container_repositories":     {Tok: ociDataSource(artifactsMod, "getContainerRepositories")},
			"oci_artifacts_container_repository":       {Tok: ociDataSource(artifactsMod, "getContainerRepository")},
			"oci_artifacts_generic_artifact":           {Tok: ociDataSource(artifactsMod, "getGenericArtifact")},
			"oci_artifacts_generic_artifacts":          {Tok: ociDataSource(artifactsMod, "getGenericArtifacts")},
			"oci_artifacts_repositories":               {Tok: ociDataSource(artifactsMod, "getRepositories")},
			"oci_artifacts_repository":                 {Tok: ociDataSource(artifactsMod, "getRepository")},
			// Audit
			"oci_audit_configuration": {Tok: ociDataSource(auditMod, "getConfiguration")},
			"oci_audit_events":        {Tok: ociDataSource(auditMod, "getEvents")},
			// AutoScaling
			"oci_autoscaling_auto_scaling_configuration":  {Tok: ociDataSource(autoscalingMod, "getAutoScalingConfiguration")},
			"oci_autoscaling_auto_scaling_configurations": {Tok: ociDataSource(autoscalingMod, "getAutoScalingConfigurations")},
			// Bastion
			"oci_bastion_bastion":  {Tok: ociDataSource(bastionMod, "getBastion")},
			"oci_bastion_bastions": {Tok: ociDataSource(bastionMod, "getBastions")},
			"oci_bastion_session":  {Tok: ociDataSource(bastionMod, "getSession")},
			"oci_bastion_sessions": {Tok: ociDataSource(bastionMod, "getSessions")},
			// BDS
			"oci_bds_auto_scaling_configuration": {Tok: ociDataSource(bdsMod, "getAutoScalingConfiguration")},
			"oci_bds_bds_instance":               {Tok: ociDataSource(bdsMod, "getBdsInstance")},
			"oci_bds_bds_instances":              {Tok: ociDataSource(bdsMod, "getBdsInstances")},
			// Blockchain
			"oci_blockchain_blockchain_platform":  {Tok: ociDataSource(blockchainMod, "getBlockchainPlatform")},
			"oci_blockchain_blockchain_platforms": {Tok: ociDataSource(blockchainMod, "getBlockchainPlatforms")},
			"oci_blockchain_osn":                  {Tok: ociDataSource(blockchainMod, "getOsn")},
			"oci_blockchain_osns":                 {Tok: ociDataSource(blockchainMod, "getOsns")},
			"oci_blockchain_peer":                 {Tok: ociDataSource(blockchainMod, "getPeer")},
			"oci_blockchain_peers":                {Tok: ociDataSource(blockchainMod, "getPeers")},
			// Budget
			"oci_budget_alert_rule":  {Tok: ociDataSource(budgetMod, "getAlertRule")},
			"oci_budget_alert_rules": {Tok: ociDataSource(budgetMod, "getAlertRules")},
			"oci_budget_budget":      {Tok: ociDataSource(budgetMod, "getBudget")},
			"oci_budget_budgets":     {Tok: ociDataSource(budgetMod, "getBudgets")},
			// Cloud Guard
			"oci_cloud_guard_cloud_guard_configuration": {Tok: ociDataSource(cloudGuardMod, "getCloudGuardConfiguration")},
			"oci_cloud_guard_data_mask_rule":            {Tok: ociDataSource(cloudGuardMod, "getDataMaskRule")},
			"oci_cloud_guard_data_mask_rules":           {Tok: ociDataSource(cloudGuardMod, "getDataMaskRules")},
			"oci_cloud_guard_detector_recipe":           {Tok: ociDataSource(cloudGuardMod, "getDetectorRecipe")},
			"oci_cloud_guard_detector_recipes":          {Tok: ociDataSource(cloudGuardMod, "getDetectorRecipes")},
			"oci_cloud_guard_managed_list":              {Tok: ociDataSource(cloudGuardMod, "getManagedList")},
			"oci_cloud_guard_managed_lists":             {Tok: ociDataSource(cloudGuardMod, "getManagedLists")},
			"oci_cloud_guard_responder_recipe":          {Tok: ociDataSource(cloudGuardMod, "getResponderRecipe")},
			"oci_cloud_guard_responder_recipes":         {Tok: ociDataSource(cloudGuardMod, "getResponderRecipes")},
			"oci_cloud_guard_target":                    {Tok: ociDataSource(cloudGuardMod, "getTarget")},
			"oci_cloud_guard_targets":                   {Tok: ociDataSource(cloudGuardMod, "getTargets")},
			// Compute Instance Agent
			"oci_computeinstanceagent_instance_available_plugins": {Tok: ociDataSource(computeInstanceAgentMod, "getInstanceAvailablePlugins")},
			"oci_computeinstanceagent_instance_agent_plugins":     {Tok: ociDataSource(computeInstanceAgentMod, "getInstanceAgentPlugins")},
			"oci_computeinstanceagent_instance_agent_plugin":      {Tok: ociDataSource(computeInstanceAgentMod, "getInstanceAgentPlugin")},
			// Container Engine
			"oci_containerengine_cluster_kube_config":      {Tok: ociDataSource(containerEngineMod, "getClusterKubeConfig")},
			"oci_containerengine_cluster_option":           {Tok: ociDataSource(containerEngineMod, "getClusterOption")},
			"oci_containerengine_clusters":                 {Tok: ociDataSource(containerEngineMod, "getClusters")},
			"oci_containerengine_node_pool":                {Tok: ociDataSource(containerEngineMod, "getNodePool")},
			"oci_containerengine_node_pool_option":         {Tok: ociDataSource(containerEngineMod, "getNodePoolOption")},
			"oci_containerengine_node_pools":               {Tok: ociDataSource(containerEngineMod, "getNodePools")},
			"oci_containerengine_work_request_errors":      {Tok: ociDataSource(containerEngineMod, "getWorkRequestErrors")},
			"oci_containerengine_work_request_log_entries": {Tok: ociDataSource(containerEngineMod, "getWorkRequestLogEntries")},
			"oci_containerengine_work_requests":            {Tok: ociDataSource(containerEngineMod, "getWorkRequests")},
			// OCE
			"oci_oce_oce_instance":  {Tok: ociDataSource(oceMod, "getOceInstance")},
			"oci_oce_oce_instances": {Tok: ociDataSource(oceMod, "getOceInstances")},
			// Core
			"oci_core_app_catalog_listing":                              {Tok: ociDataSource(coreMod, "getAppCatalogListing")},
			"oci_core_app_catalog_listing_resource_version":             {Tok: ociDataSource(coreMod, "getAppCatalogListingResourceVersion")},
			"oci_core_app_catalog_listing_resource_versions":            {Tok: ociDataSource(coreMod, "getAppCatalogListingResourceVersions")},
			"oci_core_app_catalog_listings":                             {Tok: ociDataSource(coreMod, "getAppCatalogListings")},
			"oci_core_app_catalog_subscriptions":                        {Tok: ociDataSource(coreMod, "getAppCatalogSubscriptions")},
			"oci_core_block_volume_replica":                             {Tok: ociDataSource(coreMod, "getBlockVolumeReplica")},
			"oci_core_block_volume_replicas":                            {Tok: ociDataSource(coreMod, "getBlockVolumeReplicas")},
			"oci_core_boot_volume":                                      {Tok: ociDataSource(coreMod, "getBootVolume")},
			"oci_core_boot_volume_attachments":                          {Tok: ociDataSource(coreMod, "getBootVolumeAttachments")},
			"oci_core_boot_volume_backup":                               {Tok: ociDataSource(coreMod, "getBootVolumeBackup")},
			"oci_core_boot_volume_backups":                              {Tok: ociDataSource(coreMod, "getBootVolumeBackups")},
			"oci_core_boot_volume_replica":                              {Tok: ociDataSource(coreMod, "getBootVolumeReplica")},
			"oci_core_boot_volume_replicas":                             {Tok: ociDataSource(coreMod, "getBootVolumeReplicas")},
			"oci_core_boot_volumes":                                     {Tok: ociDataSource(coreMod, "getBootVolumes")},
			"oci_core_byoip_allocated_ranges":                           {Tok: ociDataSource(coreMod, "getByoipAllocatedRanges")},
			"oci_core_byoip_range":                                      {Tok: ociDataSource(coreMod, "getByoipRange")},
			"oci_core_byoip_ranges":                                     {Tok: ociDataSource(coreMod, "getByoipRanges")},
			"oci_core_cluster_network":                                  {Tok: ociDataSource(coreMod, "getClusterNetwork")},
			"oci_core_cluster_network_instances":                        {Tok: ociDataSource(coreMod, "getClusterNetworkInstances")},
			"oci_core_cluster_networks":                                 {Tok: ociDataSource(coreMod, "getClusterNetworks")},
			"oci_core_compute_capacity_reservation":                     {Tok: ociDataSource(coreMod, "getComputeCapacityReservation")},
			"oci_core_compute_capacity_reservation_instance_shapes":     {Tok: ociDataSource(coreMod, "getComputeCapacityReservationInstanceShapes")},
			"oci_core_compute_capacity_reservation_instances":           {Tok: ociDataSource(coreMod, "getComputeCapacityReservationInstances")},
			"oci_core_compute_capacity_reservations":                    {Tok: ociDataSource(coreMod, "getComputeCapacityReservations")},
			"oci_core_compute_global_image_capability_schema":           {Tok: ociDataSource(coreMod, "getComputeGlobalImageCapabilitySchema")},
			"oci_core_compute_global_image_capability_schemas":          {Tok: ociDataSource(coreMod, "getComputeGlobalImageCapabilitySchemas")},
			"oci_core_compute_global_image_capability_schemas_version":  {Tok: ociDataSource(coreMod, "getComputeGlobalImageCapabilitySchemasVersion")},
			"oci_core_compute_global_image_capability_schemas_versions": {Tok: ociDataSource(coreMod, "getComputeGlobalImageCapabilitySchemasVersions")},
			"oci_core_compute_image_capability_schema":                  {Tok: ociDataSource(coreMod, "getComputeImageCapabilitySchema")},
			"oci_core_compute_image_capability_schemas":                 {Tok: ociDataSource(coreMod, "getComputeImageCapabilitySchemas")},
			"oci_core_console_histories":                                {Tok: ociDataSource(coreMod, "getConsoleHistories")},
			"oci_core_console_history_data":                             {Tok: ociDataSource(coreMod, "getConsoleHistoryData")},
			"oci_core_cpe_device_shape":                                 {Tok: ociDataSource(coreMod, "getCpeDeviceShape")},
			"oci_core_cpe_device_shapes":                                {Tok: ociDataSource(coreMod, "getCpeDeviceShapes")},
			"oci_core_cpes":                                             {Tok: ociDataSource(coreMod, "getCpes")},
			"oci_core_cross_connect":                                    {Tok: ociDataSource(coreMod, "getCrossConnect")},
			"oci_core_cross_connect_group":                              {Tok: ociDataSource(coreMod, "getCrossConnectGroup")},
			"oci_core_cross_connect_groups":                             {Tok: ociDataSource(coreMod, "getCrossConnectGroups")},
			"oci_core_cross_connect_locations":                          {Tok: ociDataSource(coreMod, "getCrossConnectLocations")},
			"oci_core_cross_connect_port_speed_shapes":                  {Tok: ociDataSource(coreMod, "getCrossConnectPortSpeedShapes")},
			"oci_core_cross_connect_status":                             {Tok: ociDataSource(coreMod, "getCrossConnectStatus")},
			"oci_core_cross_connects":                                   {Tok: ociDataSource(coreMod, "getCrossConnects")},
			"oci_core_dedicated_vm_host":                                {Tok: ociDataSource(coreMod, "getDedicatedVmHost")},
			"oci_core_dedicated_vm_host_instance_shapes":                {Tok: ociDataSource(coreMod, "getDedicatedVmHostInstanceShapes")},
			"oci_core_dedicated_vm_host_shapes":                         {Tok: ociDataSource(coreMod, "getDedicatedVmHostShapes")},
			"oci_core_dedicated_vm_hosts":                               {Tok: ociDataSource(coreMod, "getDedicatedVmHosts")},
			"oci_core_dedicated_vm_hosts_instances":                     {Tok: ociDataSource(coreMod, "getDedicatedVmHostsInstances")},
			"oci_core_dhcp_options":                                     {Tok: ociDataSource(coreMod, "getDhcpOptions")},
			"oci_core_drg_attachments":                                  {Tok: ociDataSource(coreMod, "getDrgAttachments")},
			"oci_core_drg_route_distribution":                           {Tok: ociDataSource(coreMod, "getDrgRouteDistribution")},
			"oci_core_drg_route_distribution_statements":                {Tok: ociDataSource(coreMod, "getDrgRouteDistributionStatements")},
			"oci_core_drg_route_distributions":                          {Tok: ociDataSource(coreMod, "getDrgRouteDistributions")},
			"oci_core_drg_route_table":                                  {Tok: ociDataSource(coreMod, "getDrgRouteTable")},
			"oci_core_drg_route_table_route_rules":                      {Tok: ociDataSource(coreMod, "getDrgRouteTableRouteRules")},
			"oci_core_drg_route_tables":                                 {Tok: ociDataSource(coreMod, "getDrgRouteTables")},
			"oci_core_drgs":                                             {Tok: ociDataSource(coreMod, "getDrgs")},
			"oci_core_fast_connect_provider_service":                    {Tok: ociDataSource(coreMod, "getFastConnectProviderService")},
			"oci_core_fast_connect_provider_service_key":                {Tok: ociDataSource(coreMod, "getFastConnectProviderServiceKey")},
			"oci_core_fast_connect_provider_services":                   {Tok: ociDataSource(coreMod, "getFastConnectProviderServices")},
			"oci_core_image":                                            {Tok: ociDataSource(coreMod, "getImage")},
			"oci_core_image_shape":                                      {Tok: ociDataSource(coreMod, "getImageShape")},
			"oci_core_image_shapes":                                     {Tok: ociDataSource(coreMod, "getImageShapes")},
			"oci_core_images":                                           {Tok: ociDataSource(coreMod, "getImages")},
			"oci_core_instance":                                         {Tok: ociDataSource(coreMod, "getInstance")},
			"oci_core_instance_configuration":                           {Tok: ociDataSource(coreMod, "getInstanceConfiguration")},
			"oci_core_instance_configurations":                          {Tok: ociDataSource(coreMod, "getInstanceConfigurations")},
			"oci_core_instance_console_connections":                     {Tok: ociDataSource(coreMod, "getInstanceConsoleConnections")},
			"oci_core_instance_credentials":                             {Tok: ociDataSource(coreMod, "getInstanceCredentials")},
			"oci_core_instance_devices":                                 {Tok: ociDataSource(coreMod, "getInstanceDevices")},
			"oci_core_instance_pool":                                    {Tok: ociDataSource(coreMod, "getInstancePool")},
			"oci_core_instance_pool_instances":                          {Tok: ociDataSource(coreMod, "getInstancePoolInstances")},
			"oci_core_instance_pool_load_balancer_attachment":           {Tok: ociDataSource(coreMod, "getInstancePoolLoadBalancerAttachment")},
			"oci_core_instance_pools":                                   {Tok: ociDataSource(coreMod, "getInstancePools")},
			"oci_core_instances":                                        {Tok: ociDataSource(coreMod, "getInstances")},
			"oci_core_internet_gateways":                                {Tok: ociDataSource(coreMod, "getInternetGateways")},
			"oci_core_ipsec_config":                                     {Tok: ociDataSource(coreMod, "getIpsecConfig")},
			"oci_core_ipsec_connection_tunnel":                          {Tok: ociDataSource(coreMod, "getIpsecConnectionTunnel")},
			"oci_core_ipsec_connection_tunnels":                         {Tok: ociDataSource(coreMod, "getIpsecConnectionTunnels")},
			"oci_core_ipsec_connections":                                {Tok: ociDataSource(coreMod, "getIpsecConnections")},
			"oci_core_ipsec_status":                                     {Tok: ociDataSource(coreMod, "getIpsecStatus")},
			"oci_core_ipv6":                                             {Tok: ociDataSource(coreMod, "getIpv6")},
			"oci_core_ipv6s":                                            {Tok: ociDataSource(coreMod, "getIpv6s")},
			"oci_core_letter_of_authority":                              {Tok: ociDataSource(coreMod, "getLetterOfAuthority")},
			"oci_core_local_peering_gateways":                           {Tok: ociDataSource(coreMod, "getLocalPeeringGateways")},
			"oci_core_nat_gateway":                                      {Tok: ociDataSource(coreMod, "getNatGateway")},
			"oci_core_nat_gateways":                                     {Tok: ociDataSource(coreMod, "getNatGateways")},
			"oci_core_network_security_group":                           {Tok: ociDataSource(coreMod, "getNetworkSecurityGroup")},
			"oci_core_network_security_group_security_rules":            {Tok: ociDataSource(coreMod, "getNetworkSecurityGroupSecurityRules")},
			"oci_core_network_security_group_vnics":                     {Tok: ociDataSource(coreMod, "getNetworkSecurityGroupVnics")},
			"oci_core_network_security_groups":                          {Tok: ociDataSource(coreMod, "getNetworkSecurityGroups")},
			"oci_core_peer_region_for_remote_peerings":                  {Tok: ociDataSource(coreMod, "getPeerRegionForRemotePeerings")},
			"oci_core_private_ip":                                       {Tok: ociDataSource(coreMod, "getPrivateIp")},
			"oci_core_private_ips":                                      {Tok: ociDataSource(coreMod, "getPrivateIps")},
			"oci_core_public_ip":                                        {Tok: ociDataSource(coreMod, "getPublicIp")},
			"oci_core_public_ip_pool":                                   {Tok: ociDataSource(coreMod, "getPublicIpPool")},
			"oci_core_public_ip_pools":                                  {Tok: ociDataSource(coreMod, "getPublicIpPools")},
			"oci_core_public_ips":                                       {Tok: ociDataSource(coreMod, "getPublicIps")},
			"oci_core_remote_peering_connections":                       {Tok: ociDataSource(coreMod, "getRemotePeeringConnections")},
			"oci_core_route_tables":                                     {Tok: ociDataSource(coreMod, "getRouteTables")},
			"oci_core_security_lists":                                   {Tok: ociDataSource(coreMod, "getSecurityLists")},
			"oci_core_service_gateways":                                 {Tok: ociDataSource(coreMod, "getServiceGateways")},
			"oci_core_services":                                         {Tok: ociDataSource(coreMod, "getServices")},
			"oci_core_shapes":                                           {Tok: ociDataSource(coreMod, "getShapes")},
			"oci_core_subnet":                                           {Tok: ociDataSource(coreMod, "getSubnet")},
			"oci_core_subnets":                                          {Tok: ociDataSource(coreMod, "getSubnets")},
			"oci_core_vcn":                                              {Tok: ociDataSource(coreMod, "getVcn")},
			"oci_core_vcn_dns_resolver_association":                     {Tok: ociDataSource(coreMod, "getVcnDnsResolverAssociation")},
			"oci_core_vcns":                                             {Tok: ociDataSource(coreMod, "getVcns")},
			"oci_core_virtual_circuit":                                  {Tok: ociDataSource(coreMod, "getVirtualCircuit")},
			"oci_core_virtual_circuit_bandwidth_shapes":                 {Tok: ociDataSource(coreMod, "getVirtualCircuitBandwidthShapes")},
			"oci_core_virtual_circuit_public_prefixes":                  {Tok: ociDataSource(coreMod, "getVirtualCircuitPublicPrefixes")},
			"oci_core_virtual_circuits":                                 {Tok: ociDataSource(coreMod, "getVirtualCircuits")},
			"oci_core_vlan":                                             {Tok: ociDataSource(coreMod, "getVlan")},
			"oci_core_vlans":                                            {Tok: ociDataSource(coreMod, "getVlans")},
			"oci_core_vnic":                                             {Tok: ociDataSource(coreMod, "getVnic")},
			"oci_core_vnic_attachments":                                 {Tok: ociDataSource(coreMod, "getVnicAttachments")},
			"oci_core_volume":                                           {Tok: ociDataSource(coreMod, "getVolume")},
			"oci_core_volume_attachments":                               {Tok: ociDataSource(coreMod, "getVolumeAttachments")},
			"oci_core_volume_backup_policies":                           {Tok: ociDataSource(coreMod, "getVolumeBackupPolicies")},
			"oci_core_volume_backup_policy_assignments":                 {Tok: ociDataSource(coreMod, "getVolumeBackupPolicyAssignments")},
			"oci_core_volume_backups":                                   {Tok: ociDataSource(coreMod, "getVolumeBackups")},
			"oci_core_volume_group_backups":                             {Tok: ociDataSource(coreMod, "getVolumeGroupBackups")},
			"oci_core_volume_groups":                                    {Tok: ociDataSource(coreMod, "getVolumeGroups")},
			"oci_core_volumes":                                          {Tok: ociDataSource(coreMod, "getVolumes")},
			// Data Catalog
			"oci_datacatalog_catalog":                   {Tok: ociDataSource(dataCatalogMod, "getCatalog")},
			"oci_datacatalog_catalog_private_endpoint":  {Tok: ociDataSource(dataCatalogMod, "getCatalogPrivateEndpoint")},
			"oci_datacatalog_catalog_private_endpoints": {Tok: ociDataSource(dataCatalogMod, "getCatalogPrivateEndpoints")},
			"oci_datacatalog_catalog_type":              {Tok: ociDataSource(dataCatalogMod, "getCatalogType")},
			"oci_datacatalog_catalog_types":             {Tok: ociDataSource(dataCatalogMod, "getCatalogTypes")},
			"oci_datacatalog_catalogs":                  {Tok: ociDataSource(dataCatalogMod, "getCatalogs")},
			"oci_datacatalog_connection":                {Tok: ociDataSource(dataCatalogMod, "getConnection")},
			"oci_datacatalog_connections":               {Tok: ociDataSource(dataCatalogMod, "getConnections")},
			"oci_datacatalog_data_asset":                {Tok: ociDataSource(dataCatalogMod, "getDataAsset")},
			"oci_datacatalog_data_assets":               {Tok: ociDataSource(dataCatalogMod, "getDataAssets")},
			// Data Flow
			"oci_dataflow_application":       {Tok: ociDataSource(dataFlowMod, "getApplication")},
			"oci_dataflow_applications":      {Tok: ociDataSource(dataFlowMod, "getApplications")},
			"oci_dataflow_invoke_run":        {Tok: ociDataSource(dataFlowMod, "getInvokeRun")},
			"oci_dataflow_invoke_runs":       {Tok: ociDataSource(dataFlowMod, "getInvokeRuns")},
			"oci_dataflow_private_endpoint":  {Tok: ociDataSource(dataFlowMod, "getPrivateEndpoint")},
			"oci_dataflow_private_endpoints": {Tok: ociDataSource(dataFlowMod, "getPrivateEndpoints")},
			"oci_dataflow_run_log":           {Tok: ociDataSource(dataFlowMod, "getRunLog")},
			"oci_dataflow_run_logs":          {Tok: ociDataSource(dataFlowMod, "getRunLogs")},
			// Data Integration
			"oci_dataintegration_workspace":  {Tok: ociDataSource(dataIntegrationMod, "getWorkspace")},
			"oci_dataintegration_workspaces": {Tok: ociDataSource(dataIntegrationMod, "getWorkspaces")},
			// Data Safe
			"oci_data_safe_data_safe_configuration":     {Tok: ociDataSource(dataSafeMod, "getDataSafeConfiguration")},
			"oci_data_safe_data_safe_private_endpoint":  {Tok: ociDataSource(dataSafeMod, "getDataSafePrivateEndpoint")},
			"oci_data_safe_data_safe_private_endpoints": {Tok: ociDataSource(dataSafeMod, "getDataSafePrivateEndpoints")},
			"oci_data_safe_on_prem_connector":           {Tok: ociDataSource(dataSafeMod, "getOnPremConnector")},
			"oci_data_safe_on_prem_connectors":          {Tok: ociDataSource(dataSafeMod, "getOnPremConnectors")},
			"oci_data_safe_target_database":             {Tok: ociDataSource(dataSafeMod, "getTargetDatabase")},
			"oci_data_safe_target_databases":            {Tok: ociDataSource(dataSafeMod, "getTargetDatabases")},
			// Data Science
			"oci_datascience_model":                   {Tok: ociDataSource(dataScienceMod, "getModel")},
			"oci_datascience_model_deployment":        {Tok: ociDataSource(dataScienceMod, "getModelDeployment")},
			"oci_datascience_model_deployment_shapes": {Tok: ociDataSource(dataScienceMod, "getModelDeploymentShapes")},
			"oci_datascience_model_deployments":       {Tok: ociDataSource(dataScienceMod, "getModelDeployments")},
			"oci_datascience_model_provenance":        {Tok: ociDataSource(dataScienceMod, "getModelProvenance")},
			"oci_datascience_models":                  {Tok: ociDataSource(dataScienceMod, "getModels")},
			"oci_datascience_notebook_session":        {Tok: ociDataSource(dataScienceMod, "getNotebookSession")},
			"oci_datascience_notebook_session_shapes": {Tok: ociDataSource(dataScienceMod, "getNotebookSessionShapes")},
			"oci_datascience_notebook_sessions":       {Tok: ociDataSource(dataScienceMod, "getNotebookSessions")},
			"oci_datascience_project":                 {Tok: ociDataSource(dataScienceMod, "getProject")},
			"oci_datascience_projects":                {Tok: ociDataSource(dataScienceMod, "getProjects")},
			// Database
			"oci_database_autonomous_container_database":                        {Tok: ociDataSource(databaseMod, "getAutonomousContainerDatabase")},
			"oci_database_autonomous_container_database_dataguard_association":  {Tok: ociDataSource(databaseMod, "getAutonomousContainerDatabaseDataguardAssociation")},
			"oci_database_autonomous_container_database_dataguard_associations": {Tok: ociDataSource(databaseMod, "getAutonomousContainerDatabaseDataguardAssociations")},
			"oci_database_autonomous_container_databases":                       {Tok: ociDataSource(databaseMod, "getAutonomousContainerDatabases")},
			"oci_database_autonomous_container_patches":                         {Tok: ociDataSource(databaseMod, "getAutonomousContainerPatches")},
			"oci_database_autonomous_database":                                  {Tok: ociDataSource(databaseMod, "getAutonomousDatabase")},
			"oci_database_autonomous_database_backup":                           {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseBackup")},
			"oci_database_autonomous_database_backups":                          {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseBackups")},
			"oci_database_autonomous_database_dataguard_association":            {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseDataguardAssociation")},
			"oci_database_autonomous_database_dataguard_associations":           {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseDataguardAssociations")},
			"oci_database_autonomous_database_instance_wallet_management":       {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseInstanceWalletManagement")},
			"oci_database_autonomous_database_regional_wallet_management":       {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseRegionalWalletManagement")},
			"oci_database_autonomous_database_wallet":                           {Tok: ociDataSource(databaseMod, "getAutonomousDatabaseWallet")},
			"oci_database_autonomous_databases":                                 {Tok: ociDataSource(databaseMod, "getAutonomousDatabases")},
			"oci_database_autonomous_databases_clones":                          {Tok: ociDataSource(databaseMod, "getAutonomousDatabasesClones")},
			"oci_database_autonomous_db_preview_versions":                       {Tok: ociDataSource(databaseMod, "getAutonomousDbPreviewVersions")},
			"oci_database_autonomous_db_versions":                               {Tok: ociDataSource(databaseMod, "getAutonomousDbVersions")},
			"oci_database_autonomous_exadata_infrastructure":                    {Tok: ociDataSource(databaseMod, "getAutonomousExadataInfrastructure")},
			"oci_database_autonomous_exadata_infrastructure_ocpu":               {Tok: ociDataSource(databaseMod, "getAutonomousExadataInfrastructureOcpu")},
			"oci_database_autonomous_exadata_infrastructure_shapes":             {Tok: ociDataSource(databaseMod, "getAutonomousExadataInfrastructureShapes")},
			"oci_database_autonomous_exadata_infrastructures":                   {Tok: ociDataSource(databaseMod, "getAutonomousExadataInfrastructures")},
			"oci_database_autonomous_patch":                                     {Tok: ociDataSource(databaseMod, "getAutonomousPatch")},
			"oci_database_autonomous_vm_cluster":                                {Tok: ociDataSource(databaseMod, "getAutonomousVmCluster")},
			"oci_database_autonomous_vm_clusters":                               {Tok: ociDataSource(databaseMod, "getAutonomousVmClusters")},
			"oci_database_backup_destination":                                   {Tok: ociDataSource(databaseMod, "getBackupDestination")},
			"oci_database_backup_destinations":                                  {Tok: ociDataSource(databaseMod, "getBackupDestinations")},
			"oci_database_backups":                                              {Tok: ociDataSource(databaseMod, "getBackups")},
			"oci_database_cloud_exadata_infrastructure":                         {Tok: ociDataSource(databaseMod, "getCloudExadataInfrastructure")},
			"oci_database_cloud_exadata_infrastructures":                        {Tok: ociDataSource(databaseMod, "getCloudExadataInfrastructures")},
			"oci_database_cloud_vm_cluster":                                     {Tok: ociDataSource(databaseMod, "getCloudVmCluster")},
			"oci_database_cloud_vm_clusters":                                    {Tok: ociDataSource(databaseMod, "getCloudVmClusters")},
			"oci_database_data_guard_association":                               {Tok: ociDataSource(databaseMod, "getDataGuardAssociation")},
			"oci_database_data_guard_associations":                              {Tok: ociDataSource(databaseMod, "getDataGuardAssociations")},
			"oci_database_database":                                             {Tok: ociDataSource(databaseMod, "getDatabase")},
			"oci_database_database_software_image":                              {Tok: ociDataSource(databaseMod, "getDatabaseSoftwareImage")},
			"oci_database_database_software_images":                             {Tok: ociDataSource(databaseMod, "getDatabaseSoftwareImages")},
			"oci_database_database_upgrade_history_entries":                     {Tok: ociDataSource(databaseMod, "getDatabaseUpgradeHistoryEntries")},
			"oci_database_database_upgrade_history_entry":                       {Tok: ociDataSource(databaseMod, "getDatabaseUpgradeHistoryEntry")},
			"oci_database_databases":                                            {Tok: ociDataSource(databaseMod, "getDatabases")},
			"oci_database_db_home":                                              {Tok: ociDataSource(databaseMod, "getDbHome")},
			"oci_database_db_home_patch_history_entries":                        {Tok: ociDataSource(databaseMod, "getDbHomePatchHistoryEntries")},
			"oci_database_db_home_patches":                                      {Tok: ociDataSource(databaseMod, "getDbHomePatches")},
			"oci_database_db_homes":                                             {Tok: ociDataSource(databaseMod, "getDbHomes")},
			"oci_database_db_node":                                              {Tok: ociDataSource(databaseMod, "getDbNode")},
			"oci_database_db_node_console_connection":                           {Tok: ociDataSource(databaseMod, "getDbNodeConsoleConnection")},
			"oci_database_db_node_console_connections":                          {Tok: ociDataSource(databaseMod, "getDbNodeConsoleConnections")},
			"oci_database_db_nodes":                                             {Tok: ociDataSource(databaseMod, "getDbNodes")},
			"oci_database_db_system_patch_history_entries":                      {Tok: ociDataSource(databaseMod, "getDbSystemPatchHistoryEntries")},
			"oci_database_db_system_patches":                                    {Tok: ociDataSource(databaseMod, "getDbSystemPatches")},
			"oci_database_db_system_shapes":                                     {Tok: ociDataSource(databaseMod, "getDbSystemShapes")},
			"oci_database_db_systems":                                           {Tok: ociDataSource(databaseMod, "getDbSystems")},
			"oci_database_db_versions":                                          {Tok: ociDataSource(databaseMod, "getDbVersions")},
			"oci_database_exadata_infrastructure":                               {Tok: ociDataSource(databaseMod, "getExadataInfrastructure")},
			"oci_database_exadata_infrastructure_download_config_file":          {Tok: ociDataSource(databaseMod, "getExadataInfrastructureDownloadConfigFile")},
			"oci_database_exadata_infrastructures":                              {Tok: ociDataSource(databaseMod, "getExadataInfrastructures")},
			"oci_database_exadata_iorm_config":                                  {Tok: ociDataSource(databaseMod, "getExadataIormConfig")},
			"oci_database_external_container_database":                          {Tok: ociDataSource(databaseMod, "getExternalContainerDatabase")},
			"oci_database_external_container_databases":                         {Tok: ociDataSource(databaseMod, "getExternalContainerDatabases")},
			"oci_database_external_database_connector":                          {Tok: ociDataSource(databaseMod, "getExternalDatabaseConnector")},
			"oci_database_external_database_connectors":                         {Tok: ociDataSource(databaseMod, "getExternalDatabaseConnectors")},
			"oci_database_external_non_container_database":                      {Tok: ociDataSource(databaseMod, "getExternalNonContainerDatabase")},
			"oci_database_external_non_container_databases":                     {Tok: ociDataSource(databaseMod, "getExternalNonContainerDatabases")},
			"oci_database_external_pluggable_database":                          {Tok: ociDataSource(databaseMod, "getExternalPluggableDatabase")},
			"oci_database_external_pluggable_databases":                         {Tok: ociDataSource(databaseMod, "getExternalPluggableDatabases")},
			"oci_database_flex_components":                                      {Tok: ociDataSource(databaseMod, "getFlexComponents")},
			"oci_database_gi_versions":                                          {Tok: ociDataSource(databaseMod, "getGiVersions")},
			"oci_database_key_store":                                            {Tok: ociDataSource(databaseMod, "getKeyStore")},
			"oci_database_key_stores":                                           {Tok: ociDataSource(databaseMod, "getKeyStores")},
			"oci_database_maintenance_run":                                      {Tok: ociDataSource(databaseMod, "getMaintenanceRun")},
			"oci_database_maintenance_runs":                                     {Tok: ociDataSource(databaseMod, "getMaintenanceRuns")},
			"oci_database_pluggable_database":                                   {Tok: ociDataSource(databaseMod, "getPluggableDatabase")},
			"oci_database_pluggable_databases":                                  {Tok: ociDataSource(databaseMod, "getPluggableDatabases")},
			"oci_database_vm_cluster":                                           {Tok: ociDataSource(databaseMod, "getVmCluster")},
			"oci_database_vm_cluster_network":                                   {Tok: ociDataSource(databaseMod, "getVmClusterNetwork")},
			"oci_database_vm_cluster_network_download_config_file":              {Tok: ociDataSource(databaseMod, "getVmClusterNetworkDownloadConfigFile")},
			"oci_database_vm_cluster_networks":                                  {Tok: ociDataSource(databaseMod, "getVmClusterNetworks")},
			"oci_database_vm_cluster_patch":                                     {Tok: ociDataSource(databaseMod, "getVmClusterPatch")},
			"oci_database_vm_cluster_patch_history_entries":                     {Tok: ociDataSource(databaseMod, "getVmClusterPatchHistoryEntries")},
			"oci_database_vm_cluster_patch_history_entry":                       {Tok: ociDataSource(databaseMod, "getVmClusterPatchHistoryEntry")},
			"oci_database_vm_cluster_patches":                                   {Tok: ociDataSource(databaseMod, "getVmClusterPatches")},
			"oci_database_vm_cluster_recommended_network":                       {Tok: ociDataSource(databaseMod, "getVmClusterRecommendedNetwork")},
			"oci_database_vm_cluster_update":                                    {Tok: ociDataSource(databaseMod, "getVmClusterUpdate")},
			"oci_database_vm_cluster_update_history_entries":                    {Tok: ociDataSource(databaseMod, "getVmClusterUpdateHistoryEntries")},
			"oci_database_vm_cluster_update_history_entry":                      {Tok: ociDataSource(databaseMod, "getVmClusterUpdateHistoryEntry")},
			"oci_database_vm_cluster_updates":                                   {Tok: ociDataSource(databaseMod, "getVmClusterUpdates")},
			"oci_database_vm_clusters":                                          {Tok: ociDataSource(databaseMod, "getVmClusters")},
			// Database Management
			"oci_database_management_managed_database":                      {Tok: ociDataSource(databaseManagementMod, "getManagedDatabase")},
			"oci_database_management_managed_database_group":                {Tok: ociDataSource(databaseManagementMod, "getManagedDatabaseGroup")},
			"oci_database_management_managed_database_groups":               {Tok: ociDataSource(databaseManagementMod, "getManagedDatabaseGroups")},
			"oci_database_management_managed_databases":                     {Tok: ociDataSource(databaseManagementMod, "getManagedDatabases")},
			"oci_database_management_managed_databases_database_parameter":  {Tok: ociDataSource(databaseManagementMod, "getManagedDatabasesDatabaseParameter")},
			"oci_database_management_managed_databases_database_parameters": {Tok: ociDataSource(databaseManagementMod, "getManagedDatabasesDatabaseParameters")},
			// Database Migration
			"oci_database_migration_agent":        {Tok: ociDataSource(databaseMigrationMod, "getAgent")},
			"oci_database_migration_agent_images": {Tok: ociDataSource(databaseMigrationMod, "getAgentImages")},
			"oci_database_migration_agents":       {Tok: ociDataSource(databaseMigrationMod, "getAgents")},
			"oci_database_migration_connection":   {Tok: ociDataSource(databaseMigrationMod, "getConnection")},
			"oci_database_migration_connections":  {Tok: ociDataSource(databaseMigrationMod, "getConnections")},
			"oci_database_migration_job":          {Tok: ociDataSource(databaseMigrationMod, "getJob")},
			"oci_database_migration_jobs":         {Tok: ociDataSource(databaseMigrationMod, "getJobs")},
			"oci_database_migration_migration":    {Tok: ociDataSource(databaseMigrationMod, "getMigration")},
			"oci_database_migration_migrations":   {Tok: ociDataSource(databaseMigrationMod, "getMigrations")},
			// Devops
			"oci_devops_deploy_artifact":     {Tok: ociDataSource(devopsMod, "getDeployArtifact")},
			"oci_devops_deploy_artifacts":    {Tok: ociDataSource(devopsMod, "getDeployArtifacts")},
			"oci_devops_deploy_environment":  {Tok: ociDataSource(devopsMod, "getDeployEnvironment")},
			"oci_devops_deploy_environments": {Tok: ociDataSource(devopsMod, "getDeployEnvironments")},
			"oci_devops_deploy_pipeline":     {Tok: ociDataSource(devopsMod, "getDeployPipeline")},
			"oci_devops_deploy_pipelines":    {Tok: ociDataSource(devopsMod, "getDeployPipelines")},
			"oci_devops_deploy_stage":        {Tok: ociDataSource(devopsMod, "getDeployStage")},
			"oci_devops_deploy_stages":       {Tok: ociDataSource(devopsMod, "getDeployStages")},
			"oci_devops_deployment":          {Tok: ociDataSource(devopsMod, "getDeployment")},
			"oci_devops_deployments":         {Tok: ociDataSource(devopsMod, "getDeployments")},
			"oci_devops_project":             {Tok: ociDataSource(devopsMod, "getProject")},
			"oci_devops_projects":            {Tok: ociDataSource(devopsMod, "getProjects")},
			// ODA
			"oci_oda_oda_instance":  {Tok: ociDataSource(odaMod, "getOdaInstance")},
			"oci_oda_oda_instances": {Tok: ociDataSource(odaMod, "getOdaInstances")},
			// DNS
			"oci_dns_records":                     {Tok: ociDataSource(dnsMod, "getRecords")},
			"oci_dns_resolver":                    {Tok: ociDataSource(dnsMod, "getResolver")},
			"oci_dns_resolver_endpoint":           {Tok: ociDataSource(dnsMod, "getResolverEndpoint")},
			"oci_dns_resolver_endpoints":          {Tok: ociDataSource(dnsMod, "getResolverEndpoints")},
			"oci_dns_resolvers":                   {Tok: ociDataSource(dnsMod, "getResolvers")},
			"oci_dns_rrset":                       {Tok: ociDataSource(dnsMod, "getRrset")},
			"oci_dns_steering_policies":           {Tok: ociDataSource(dnsMod, "getSteeringPolicies")},
			"oci_dns_steering_policy":             {Tok: ociDataSource(dnsMod, "getSteeringPolicy")},
			"oci_dns_steering_policy_attachment":  {Tok: ociDataSource(dnsMod, "getSteeringPolicyAttachment")},
			"oci_dns_steering_policy_attachments": {Tok: ociDataSource(dnsMod, "getSteeringPolicyAttachments")},
			"oci_dns_tsig_key":                    {Tok: ociDataSource(dnsMod, "getTsigKey")},
			"oci_dns_tsig_keys":                   {Tok: ociDataSource(dnsMod, "getTsigKeys")},
			"oci_dns_view":                        {Tok: ociDataSource(dnsMod, "getView")},
			"oci_dns_views":                       {Tok: ociDataSource(dnsMod, "getViews")},
			"oci_dns_zones":                       {Tok: ociDataSource(dnsMod, "getZones")},
			// Email
			"oci_email_dkim":          {Tok: ociDataSource(emailMod, "getDkim")},
			"oci_email_dkims":         {Tok: ociDataSource(emailMod, "getDkims")},
			"oci_email_email_domain":  {Tok: ociDataSource(emailMod, "getEmailDomain")},
			"oci_email_email_domains": {Tok: ociDataSource(emailMod, "getEmailDomains")},
			"oci_email_sender":        {Tok: ociDataSource(emailMod, "getSender")},
			"oci_email_senders":       {Tok: ociDataSource(emailMod, "getSenders")},
			"oci_email_suppression":   {Tok: ociDataSource(emailMod, "getSuppression")},
			"oci_email_suppressions":  {Tok: ociDataSource(emailMod, "getSuppressions")},
			// Events
			"oci_events_rule":  {Tok: ociDataSource(eventsMod, "getRule")},
			"oci_events_rules": {Tok: ociDataSource(eventsMod, "getRules")},
			// File Storage
			"oci_file_storage_export_sets":   {Tok: ociDataSource(fileStorageMod, "getExportSets")},
			"oci_file_storage_exports":       {Tok: ociDataSource(fileStorageMod, "getExports")},
			"oci_file_storage_file_systems":  {Tok: ociDataSource(fileStorageMod, "getFileSystems")},
			"oci_file_storage_mount_targets": {Tok: ociDataSource(fileStorageMod, "getMountTargets")},
			"oci_file_storage_snapshot":      {Tok: ociDataSource(fileStorageMod, "getSnapshot")},
			"oci_file_storage_snapshots":     {Tok: ociDataSource(fileStorageMod, "getSnapshots")},
			// Functions
			"oci_functions_application":  {Tok: ociDataSource(functionsMod, "getApplication")},
			"oci_functions_applications": {Tok: ociDataSource(functionsMod, "getApplications")},
			"oci_functions_function":     {Tok: ociDataSource(functionsMod, "getFunction")},
			"oci_functions_functions":    {Tok: ociDataSource(functionsMod, "getFunctions")},
			// Generic Artifacts Content
			"oci_generic_artifacts_content_generic_artifacts_content": {Tok: ociDataSource(genericArtifactsContentMod, "getGenericArtifactsContent")},
			// Golden Gate
			"oci_golden_gate_database_registration":  {Tok: ociDataSource(goldenGateMod, "getDatabaseRegistration")},
			"oci_golden_gate_database_registrations": {Tok: ociDataSource(goldenGateMod, "getDatabaseRegistrations")},
			"oci_golden_gate_deployment":             {Tok: ociDataSource(goldenGateMod, "getDeployment")},
			"oci_golden_gate_deployment_backup":      {Tok: ociDataSource(goldenGateMod, "getDeploymentBackup")},
			"oci_golden_gate_deployment_backups":     {Tok: ociDataSource(goldenGateMod, "getDeploymentBackups")},
			"oci_golden_gate_deployments":            {Tok: ociDataSource(goldenGateMod, "getDeployments")},
			// Health Checks
			"oci_health_checks_http_monitor":       {Tok: ociDataSource(healthChecksMod, "getHttpMonitor")},
			"oci_health_checks_http_monitors":      {Tok: ociDataSource(healthChecksMod, "getHttpMonitors")},
			"oci_health_checks_http_probe_results": {Tok: ociDataSource(healthChecksMod, "getHttpProbeResults")},
			"oci_health_checks_ping_monitor":       {Tok: ociDataSource(healthChecksMod, "getPingMonitor")},
			"oci_health_checks_ping_monitors":      {Tok: ociDataSource(healthChecksMod, "getPingMonitors")},
			"oci_health_checks_ping_probe_results": {Tok: ociDataSource(healthChecksMod, "getPingProbeResults")},
			"oci_health_checks_vantage_points":     {Tok: ociDataSource(healthChecksMod, "getVantagePoints")},
			// Identity
			"oci_identity_api_keys":                 {Tok: ociDataSource(identityMod, "getApiKeys")},
			"oci_identity_auth_tokens":              {Tok: ociDataSource(identityMod, "getAuthTokens")},
			"oci_identity_authentication_policy":    {Tok: ociDataSource(identityMod, "getAuthenticationPolicy")},
			"oci_identity_availability_domain":      {Tok: ociDataSource(identityMod, "getAvailabilityDomain")},
			"oci_identity_availability_domains":     {Tok: ociDataSource(identityMod, "getAvailabilityDomains")},
			"oci_identity_compartment":              {Tok: ociDataSource(identityMod, "getCompartment")},
			"oci_identity_compartments":             {Tok: ociDataSource(identityMod, "getCompartments")},
			"oci_identity_cost_tracking_tags":       {Tok: ociDataSource(identityMod, "getCostTrackingTags")},
			"oci_identity_customer_secret_keys":     {Tok: ociDataSource(identityMod, "getCustomerSecretKeys")},
			"oci_identity_dynamic_groups":           {Tok: ociDataSource(identityMod, "getDynamicGroups")},
			"oci_identity_fault_domains":            {Tok: ociDataSource(identityMod, "getFaultDomains")},
			"oci_identity_group":                    {Tok: ociDataSource(identityMod, "getGroup")},
			"oci_identity_groups":                   {Tok: ociDataSource(identityMod, "getGroups")},
			"oci_identity_identity_provider_groups": {Tok: ociDataSource(identityMod, "getIdentityProviderGroups")},
			"oci_identity_identity_providers":       {Tok: ociDataSource(identityMod, "getIdentityProviders")},
			"oci_identity_idp_group_mappings":       {Tok: ociDataSource(identityMod, "getIdpGroupMappings")},
			"oci_identity_network_source":           {Tok: ociDataSource(identityMod, "getNetworkSource")},
			"oci_identity_network_sources":          {Tok: ociDataSource(identityMod, "getNetworkSources")},
			"oci_identity_policies":                 {Tok: ociDataSource(identityMod, "getPolicies")},
			"oci_identity_region_subscriptions":     {Tok: ociDataSource(identityMod, "getRegionSubscriptions")},
			"oci_identity_regions":                  {Tok: ociDataSource(identityMod, "getRegions")},
			"oci_identity_smtp_credentials":         {Tok: ociDataSource(identityMod, "getSmtpCredentials")},
			"oci_identity_swift_passwords":          {Tok: ociDataSource(identityMod, "getSwiftPasswords")},
			"oci_identity_tag":                      {Tok: ociDataSource(identityMod, "getTag")},
			"oci_identity_tag_default":              {Tok: ociDataSource(identityMod, "getTagDefault")},
			"oci_identity_tag_defaults":             {Tok: ociDataSource(identityMod, "getTagDefaults")},
			"oci_identity_tag_namespaces":           {Tok: ociDataSource(identityMod, "getTagNamespaces")},
			"oci_identity_tags":                     {Tok: ociDataSource(identityMod, "getTags")},
			"oci_identity_tenancy":                  {Tok: ociDataSource(identityMod, "getTenancy")},
			"oci_identity_ui_password":              {Tok: ociDataSource(identityMod, "getUiPassword")},
			"oci_identity_user":                     {Tok: ociDataSource(identityMod, "getUser")},
			"oci_identity_user_group_memberships":   {Tok: ociDataSource(identityMod, "getUserGroupMemberships")},
			"oci_identity_users":                    {Tok: ociDataSource(identityMod, "getUsers")},
			// Integration
			"oci_integration_integration_instance":  {Tok: ociDataSource(integrationMod, "getIntegrationInstance")},
			"oci_integration_integration_instances": {Tok: ociDataSource(integrationMod, "getIntegrationInstances")},
			// Jms
			"oci_jms_fleet":  {Tok: ociDataSource(jmsMod, "getFleet")},
			"oci_jms_fleets": {Tok: ociDataSource(jmsMod, "getFleets")},
			// Kms
			"oci_kms_decrypted_data":     {Tok: ociDataSource(kmsMod, "getDecryptedData")},
			"oci_kms_encrypted_data":     {Tok: ociDataSource(kmsMod, "getEncryptedData")},
			"oci_kms_key":                {Tok: ociDataSource(kmsMod, "getKey")},
			"oci_kms_key_version":        {Tok: ociDataSource(kmsMod, "getKeyVersion")},
			"oci_kms_key_versions":       {Tok: ociDataSource(kmsMod, "getKeyVersions")},
			"oci_kms_keys":               {Tok: ociDataSource(kmsMod, "getKeys")},
			"oci_kms_replication_status": {Tok: ociDataSource(kmsMod, "getReplicationStatus")},
			"oci_kms_vault":              {Tok: ociDataSource(kmsMod, "getVault")},
			"oci_kms_vault_replicas":     {Tok: ociDataSource(kmsMod, "getVaultReplicas")},
			"oci_kms_vault_usage":        {Tok: ociDataSource(kmsMod, "getVaultUsage")},
			"oci_kms_vaults":             {Tok: ociDataSource(kmsMod, "getVaults")},
			// Limits
			"oci_limits_limit_definitions":     {Tok: ociDataSource(limitsMod, "getLimitDefinitions")},
			"oci_limits_limit_values":          {Tok: ociDataSource(limitsMod, "getLimitValues")},
			"oci_limits_quota":                 {Tok: ociDataSource(limitsMod, "getQuota")},
			"oci_limits_quotas":                {Tok: ociDataSource(limitsMod, "getQuotas")},
			"oci_limits_resource_availability": {Tok: ociDataSource(limitsMod, "getResourceAvailability")},
			"oci_limits_services":              {Tok: ociDataSource(limitsMod, "getServices")},
			// Load Balancer
			"oci_load_balancer_backend_health":                 {Tok: ociDataSource(loadBalancerMod, "getBackendHealth")},
			"oci_load_balancer_backend_set_health":             {Tok: ociDataSource(loadBalancerMod, "getBackendSetHealth")},
			"oci_load_balancer_backend_sets":                   {Tok: ociDataSource(loadBalancerMod, "getBackendSets")},
			"oci_load_balancer_backends":                       {Tok: ociDataSource(loadBalancerMod, "getBackends")},
			"oci_load_balancer_certificates":                   {Tok: ociDataSource(loadBalancerMod, "getCertificates")},
			"oci_load_balancer_health":                         {Tok: ociDataSource(loadBalancerMod, "getHealth")},
			"oci_load_balancer_hostnames":                      {Tok: ociDataSource(loadBalancerMod, "getHostnames")},
			"oci_load_balancer_listener_rules":                 {Tok: ociDataSource(loadBalancerMod, "getListenerRules")},
			"oci_load_balancer_load_balancer_routing_policies": {Tok: ociDataSource(loadBalancerMod, "getLoadBalancerRoutingPolicies")},
			"oci_load_balancer_load_balancer_routing_policy":   {Tok: ociDataSource(loadBalancerMod, "getLoadBalancerRoutingPolicy")},
			"oci_load_balancer_load_balancers":                 {Tok: ociDataSource(loadBalancerMod, "getLoadBalancers")},
			"oci_load_balancer_path_route_sets":                {Tok: ociDataSource(loadBalancerMod, "getPathRouteSets")},
			"oci_load_balancer_policies":                       {Tok: ociDataSource(loadBalancerMod, "getPolicies")},
			"oci_load_balancer_protocols":                      {Tok: ociDataSource(loadBalancerMod, "getProtocols")},
			"oci_load_balancer_rule_set":                       {Tok: ociDataSource(loadBalancerMod, "getRuleSet")},
			"oci_load_balancer_rule_sets":                      {Tok: ociDataSource(loadBalancerMod, "getRuleSets")},
			"oci_load_balancer_shapes":                         {Tok: ociDataSource(loadBalancerMod, "getShapes")},
			"oci_load_balancer_ssl_cipher_suite":               {Tok: ociDataSource(loadBalancerMod, "getSslCipherSuite")},
			"oci_load_balancer_ssl_cipher_suites":              {Tok: ociDataSource(loadBalancerMod, "getSslCipherSuites")},
			// Log Analytics
			"oci_log_analytics_log_analytics_entities":                {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsEntities")},
			"oci_log_analytics_log_analytics_entities_summary":        {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsEntitiesSummary")},
			"oci_log_analytics_log_analytics_entity":                  {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsEntity")},
			"oci_log_analytics_log_analytics_log_group":               {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsLogGroup")},
			"oci_log_analytics_log_analytics_log_groups":              {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsLogGroups")},
			"oci_log_analytics_log_analytics_log_groups_summary":      {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsLogGroupsSummary")},
			"oci_log_analytics_log_analytics_object_collection_rule":  {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsObjectCollectionRule")},
			"oci_log_analytics_log_analytics_object_collection_rules": {Tok: ociDataSource(logAnalyticsMod, "getLogAnalyticsObjectCollectionRules")},
			"oci_log_analytics_namespace":                             {Tok: ociDataSource(logAnalyticsMod, "getNamespace")},
			"oci_log_analytics_namespaces":                            {Tok: ociDataSource(logAnalyticsMod, "getNamespaces")},
			// Logging
			"oci_logging_log":                          {Tok: ociDataSource(loggingMod, "getLog")},
			"oci_logging_log_group":                    {Tok: ociDataSource(loggingMod, "getLogGroup")},
			"oci_logging_log_groups":                   {Tok: ociDataSource(loggingMod, "getLogGroups")},
			"oci_logging_log_saved_search":             {Tok: ociDataSource(loggingMod, "getLogSavedSearch")},
			"oci_logging_log_saved_searches":           {Tok: ociDataSource(loggingMod, "getLogSavedSearches")},
			"oci_logging_logs":                         {Tok: ociDataSource(loggingMod, "getLogs")},
			"oci_logging_unified_agent_configuration":  {Tok: ociDataSource(loggingMod, "getUnifiedAgentConfiguration")},
			"oci_logging_unified_agent_configurations": {Tok: ociDataSource(loggingMod, "getUnifiedAgentConfigurations")},
			// Management Agent
			"oci_management_agent_management_agent":                     {Tok: ociDataSource(managementAgentMod, "getManagementAgent")},
			"oci_management_agent_management_agent_available_histories": {Tok: ociDataSource(managementAgentMod, "getManagementAgentAvailableHistories")},
			"oci_management_agent_management_agent_images":              {Tok: ociDataSource(managementAgentMod, "getManagementAgentImages")},
			"oci_management_agent_management_agent_install_key":         {Tok: ociDataSource(managementAgentMod, "getManagementAgentInstallKey")},
			"oci_management_agent_management_agent_install_keys":        {Tok: ociDataSource(managementAgentMod, "getManagementAgentInstallKeys")},
			"oci_management_agent_management_agent_plugins":             {Tok: ociDataSource(managementAgentMod, "getManagementAgentPlugins")},
			"oci_management_agent_management_agents":                    {Tok: ociDataSource(managementAgentMod, "getManagementAgents")},
			// Management Dashboard
			"oci_management_dashboard_management_dashboards_export": {Tok: ociDataSource(managementDashboardMod, "getManagementDashboardsExport")},
			// Marketplace
			"oci_marketplace_accepted_agreement":         {Tok: ociDataSource(marketplaceMod, "getAcceptedAgreement")},
			"oci_marketplace_accepted_agreements":        {Tok: ociDataSource(marketplaceMod, "getAcceptedAgreements")},
			"oci_marketplace_categories":                 {Tok: ociDataSource(marketplaceMod, "getCategories")},
			"oci_marketplace_listing":                    {Tok: ociDataSource(marketplaceMod, "getListing")},
			"oci_marketplace_listing_package":            {Tok: ociDataSource(marketplaceMod, "getListingPackage")},
			"oci_marketplace_listing_package_agreements": {Tok: ociDataSource(marketplaceMod, "getListingPackageAgreements")},
			"oci_marketplace_listing_packages":           {Tok: ociDataSource(marketplaceMod, "getListingPackages")},
			"oci_marketplace_listing_taxes":              {Tok: ociDataSource(marketplaceMod, "getListingTaxes")},
			"oci_marketplace_listings":                   {Tok: ociDataSource(marketplaceMod, "getListings")},
			"oci_marketplace_publication":                {Tok: ociDataSource(marketplaceMod, "getPublication")},
			"oci_marketplace_publication_package":        {Tok: ociDataSource(marketplaceMod, "getPublicationPackage")},
			"oci_marketplace_publication_packages":       {Tok: ociDataSource(marketplaceMod, "getPublicationPackages")},
			"oci_marketplace_publications":               {Tok: ociDataSource(marketplaceMod, "getPublications")},
			"oci_marketplace_publishers":                 {Tok: ociDataSource(marketplaceMod, "getPublishers")},
			// Metering Computation
			"oci_metering_computation_configuration": {Tok: ociDataSource(meteringComputationMod, "getConfiguration")},
			"oci_metering_computation_custom_table":  {Tok: ociDataSource(meteringComputationMod, "getCustomTable")},
			"oci_metering_computation_custom_tables": {Tok: ociDataSource(meteringComputationMod, "getCustomTables")},
			"oci_metering_computation_queries":       {Tok: ociDataSource(meteringComputationMod, "getQueries")},
			"oci_metering_computation_query":         {Tok: ociDataSource(meteringComputationMod, "getQuery")},
			// Monitoring
			"oci_monitoring_alarm":                    {Tok: ociDataSource(monitoringMod, "getAlarm")},
			"oci_monitoring_alarm_history_collection": {Tok: ociDataSource(monitoringMod, "getAlarmHistoryCollection")},
			"oci_monitoring_alarm_statuses":           {Tok: ociDataSource(monitoringMod, "getAlarmStatuses")},
			"oci_monitoring_alarms":                   {Tok: ociDataSource(monitoringMod, "getAlarms")},
			"oci_monitoring_metric_data":              {Tok: ociDataSource(monitoringMod, "getMetricData")},
			"oci_monitoring_metrics":                  {Tok: ociDataSource(monitoringMod, "getMetrics")},
			// MYSQL
			"oci_mysql_analytics_cluster":    {Tok: ociDataSource(mysqlMod, "getAnalyticsCluster")},
			"oci_mysql_channel":              {Tok: ociDataSource(mysqlMod, "getChannel")},
			"oci_mysql_channels":             {Tok: ociDataSource(mysqlMod, "getChannels")},
			"oci_mysql_heat_wave_cluster":    {Tok: ociDataSource(mysqlMod, "getHeatWaveCluster")},
			"oci_mysql_mysql_backup":         {Tok: ociDataSource(mysqlMod, "getMysqlBackup")},
			"oci_mysql_mysql_backups":        {Tok: ociDataSource(mysqlMod, "getMysqlBackups")},
			"oci_mysql_mysql_configuration":  {Tok: ociDataSource(mysqlMod, "getMysqlConfiguration")},
			"oci_mysql_mysql_configurations": {Tok: ociDataSource(mysqlMod, "getMysqlConfigurations")},
			"oci_mysql_mysql_db_system":      {Tok: ociDataSource(mysqlMod, "getMysqlDbSystem")},
			"oci_mysql_mysql_db_systems":     {Tok: ociDataSource(mysqlMod, "getMysqlDbSystems")},
			"oci_mysql_mysql_versions":       {Tok: ociDataSource(mysqlMod, "getMysqlVersions")},
			"oci_mysql_shapes":               {Tok: ociDataSource(mysqlMod, "getShapes")},
			// Network Load Balancer
			"oci_network_load_balancer_backend_health":                   {Tok: ociDataSource(networkLoadBalancerMod, "getBackendHealth")},
			"oci_network_load_balancer_backend_set":                      {Tok: ociDataSource(networkLoadBalancerMod, "getBackendSet")},
			"oci_network_load_balancer_backend_sets":                     {Tok: ociDataSource(networkLoadBalancerMod, "getBackendSets")},
			"oci_network_load_balancer_backends":                         {Tok: ociDataSource(networkLoadBalancerMod, "getBackends")},
			"oci_network_load_balancer_listener":                         {Tok: ociDataSource(networkLoadBalancerMod, "getListener")},
			"oci_network_load_balancer_listeners":                        {Tok: ociDataSource(networkLoadBalancerMod, "getListeners")},
			"oci_network_load_balancer_network_load_balancer":            {Tok: ociDataSource(networkLoadBalancerMod, "getNetworkLoadBalancer")},
			"oci_network_load_balancer_network_load_balancer_health":     {Tok: ociDataSource(networkLoadBalancerMod, "getNetworkLoadBalancerHealth")},
			"oci_network_load_balancer_network_load_balancers":           {Tok: ociDataSource(networkLoadBalancerMod, "getNetworkLoadBalancers")},
			"oci_network_load_balancer_network_load_balancers_policies":  {Tok: ociDataSource(networkLoadBalancerMod, "getNetworkLoadBalancersPolicies")},
			"oci_network_load_balancer_network_load_balancers_protocols": {Tok: ociDataSource(networkLoadBalancerMod, "getNetworkLoadBalancersProtocols")},
			// NOSQL
			"oci_nosql_index":   {Tok: ociDataSource(nosqlMod, "getIndex")},
			"oci_nosql_indexes": {Tok: ociDataSource(nosqlMod, "getIndexes")},
			"oci_nosql_table":   {Tok: ociDataSource(nosqlMod, "getTable")},
			"oci_nosql_tables":  {Tok: ociDataSource(nosqlMod, "getTables")},
			// ONS
			"oci_ons_notification_topic":  {Tok: ociDataSource(onsMod, "getNotificationTopic")},
			"oci_ons_notification_topics": {Tok: ociDataSource(onsMod, "getNotificationTopics")},
			"oci_ons_subscription":        {Tok: ociDataSource(onsMod, "getSubscription")},
			"oci_ons_subscriptions":       {Tok: ociDataSource(onsMod, "getSubscriptions")},
			// Object Storage
			"oci_objectstorage_bucket":                  {Tok: ociDataSource(objectStorageMod, "getBucket")},
			"oci_objectstorage_bucket_summaries":        {Tok: ociDataSource(objectStorageMod, "getBucketSummaries")},
			"oci_objectstorage_namespace":               {Tok: ociDataSource(objectStorageMod, "getNamespace")},
			"oci_objectstorage_object":                  {Tok: ociDataSource(objectStorageMod, "getObject")},
			"oci_objectstorage_object_head":             {Tok: ociDataSource(objectStorageMod, "getObjectHead")},
			"oci_objectstorage_object_lifecycle_policy": {Tok: ociDataSource(objectStorageMod, "getObjectLifecyclePolicy")},
			"oci_objectstorage_object_versions":         {Tok: ociDataSource(objectStorageMod, "getObjectVersions")},
			"oci_objectstorage_objects":                 {Tok: ociDataSource(objectStorageMod, "getObjects")},
			"oci_objectstorage_preauthrequest":          {Tok: ociDataSource(objectStorageMod, "getPreauthrequest")},
			"oci_objectstorage_preauthrequests":         {Tok: ociDataSource(objectStorageMod, "getPreauthrequests")},
			"oci_objectstorage_replication_policies":    {Tok: ociDataSource(objectStorageMod, "getReplicationPolicies")},
			"oci_objectstorage_replication_policy":      {Tok: ociDataSource(objectStorageMod, "getReplicationPolicy")},
			"oci_objectstorage_replication_sources":     {Tok: ociDataSource(objectStorageMod, "getReplicationSources")},
			// Opsi
			"oci_opsi_database_insight":           {Tok: ociDataSource(opsiMod, "getDatabaseInsight")},
			"oci_opsi_database_insights":          {Tok: ociDataSource(opsiMod, "getDatabaseInsights")},
			"oci_opsi_enterprise_manager_bridge":  {Tok: ociDataSource(opsiMod, "getEnterpriseManagerBridge")},
			"oci_opsi_enterprise_manager_bridges": {Tok: ociDataSource(opsiMod, "getEnterpriseManagerBridges")},
			"oci_opsi_host_insight":               {Tok: ociDataSource(opsiMod, "getHostInsight")},
			"oci_opsi_host_insights":              {Tok: ociDataSource(opsiMod, "getHostInsights")},
			// Optimizer
			"oci_optimizer_categories":          {Tok: ociDataSource(optimizerMod, "getCategories")},
			"oci_optimizer_category":            {Tok: ociDataSource(optimizerMod, "getCategory")},
			"oci_optimizer_enrollment_status":   {Tok: ociDataSource(optimizerMod, "getEnrollmentStatus")},
			"oci_optimizer_enrollment_statuses": {Tok: ociDataSource(optimizerMod, "getEnrollmentStatuses")},
			"oci_optimizer_histories":           {Tok: ociDataSource(optimizerMod, "getHistories")},
			"oci_optimizer_profile":             {Tok: ociDataSource(optimizerMod, "getProfile")},
			"oci_optimizer_profiles":            {Tok: ociDataSource(optimizerMod, "getProfiles")},
			"oci_optimizer_recommendation":      {Tok: ociDataSource(optimizerMod, "getRecommendation")},
			// "oci_optimizer_recommendation_strategies": {Tok: ociDataSource(optimizerMod, "getRecommendationStrategies")},
			// "oci_optimizer_recommendation_strategy": {Tok: ociDataSource(optimizerMod, "getRecommendationStrategy")},
			"oci_optimizer_recommendations":  {Tok: ociDataSource(optimizerMod, "getRecommendations")},
			"oci_optimizer_resource_action":  {Tok: ociDataSource(optimizerMod, "getResourceAction")},
			"oci_optimizer_resource_actions": {Tok: ociDataSource(optimizerMod, "getResourceActions")},
			// OCVP
			"oci_ocvp_esxi_host":                          {Tok: ociDataSource(ocvpMod, "getEsxiHost")},
			"oci_ocvp_esxi_hosts":                         {Tok: ociDataSource(ocvpMod, "getEsxiHosts")},
			"oci_ocvp_sddc":                               {Tok: ociDataSource(ocvpMod, "getSddc")},
			"oci_ocvp_sddcs":                              {Tok: ociDataSource(ocvpMod, "getSddcs")},
			"oci_ocvp_supported_skus":                     {Tok: ociDataSource(ocvpMod, "getSupportedSkus")},
			"oci_ocvp_supported_vmware_software_versions": {Tok: ociDataSource(ocvpMod, "getSupportedVmwareSoftwareVersions")},
			// OS Management
			"oci_osmanagement_managed_instance":        {Tok: ociDataSource(osManagementMod, "getManagedInstance")},
			"oci_osmanagement_managed_instance_group":  {Tok: ociDataSource(osManagementMod, "getManagedInstanceGroup")},
			"oci_osmanagement_managed_instance_groups": {Tok: ociDataSource(osManagementMod, "getManagedInstanceGroups")},
			"oci_osmanagement_managed_instances":       {Tok: ociDataSource(osManagementMod, "getManagedInstances")},
			"oci_osmanagement_software_source":         {Tok: ociDataSource(osManagementMod, "getSoftwareSource")},
			"oci_osmanagement_software_sources":        {Tok: ociDataSource(osManagementMod, "getSoftwareSources")},
			// Resource Manager
			"oci_resourcemanager_stacks":         {Tok: ociDataSource(resourceManagerMod, "getStacks")},
			"oci_resourcemanager_stack":          {Tok: ociDataSource(resourceManagerMod, "getStack")},
			"oci_resourcemanager_stack_tf_state": {Tok: ociDataSource(resourceManagerMod, "getStackTfState")},
			// Service Catalog
			"oci_service_catalog_private_application":          {Tok: ociDataSource(serviceCatalogMod, "getPrivateApplication")},
			"oci_service_catalog_private_application_package":  {Tok: ociDataSource(serviceCatalogMod, "getPrivateApplicationPackage")},
			"oci_service_catalog_private_application_packages": {Tok: ociDataSource(serviceCatalogMod, "getPrivateApplicationPackages")},
			"oci_service_catalog_private_applications":         {Tok: ociDataSource(serviceCatalogMod, "getPrivateApplications")},
			"oci_service_catalog_service_catalog":              {Tok: ociDataSource(serviceCatalogMod, "getServiceCatalog")},
			"oci_service_catalog_service_catalog_association":  {Tok: ociDataSource(serviceCatalogMod, "getServiceCatalogAssociation")},
			"oci_service_catalog_service_catalog_associations": {Tok: ociDataSource(serviceCatalogMod, "getServiceCatalogAssociations")},
			"oci_service_catalog_service_catalogs":             {Tok: ociDataSource(serviceCatalogMod, "getServiceCatalogs")},
			// SCH
			"oci_sch_service_connector":  {Tok: ociDataSource(schMod, "getServiceConnector")},
			"oci_sch_service_connectors": {Tok: ociDataSource(schMod, "getServiceConnectors")},
			// Streaming
			"oci_streaming_connect_harness":   {Tok: ociDataSource(streamingMod, "getConnectHarness")},
			"oci_streaming_connect_harnesses": {Tok: ociDataSource(streamingMod, "getConnectHarnesses")},
			"oci_streaming_stream":            {Tok: ociDataSource(streamingMod, "getStream")},
			"oci_streaming_stream_pool":       {Tok: ociDataSource(streamingMod, "getStreamPool")},
			"oci_streaming_stream_pools":      {Tok: ociDataSource(streamingMod, "getStreamPools")},
			"oci_streaming_streams":           {Tok: ociDataSource(streamingMod, "getStreams")},
			// Vault
			"oci_vault_secrets":        {Tok: ociDataSource(vaultMod, "getSecrets")},
			"oci_vault_secret":         {Tok: ociDataSource(vaultMod, "getSecret")},
			"oci_vault_secret_version": {Tok: ociDataSource(vaultMod, "getSecretVersion")},
			// Vulnerability Scanning
			"oci_vulnerability_scanning_container_scan_recipe":  {Tok: ociDataSource(vulnerabilityScanningMod, "getContainerScanRecipe")},
			"oci_vulnerability_scanning_container_scan_recipes": {Tok: ociDataSource(vulnerabilityScanningMod, "getContainerScanRecipes")},
			"oci_vulnerability_scanning_container_scan_target":  {Tok: ociDataSource(vulnerabilityScanningMod, "getContainerScanTarget")},
			"oci_vulnerability_scanning_container_scan_targets": {Tok: ociDataSource(vulnerabilityScanningMod, "getContainerScanTargets")},
			"oci_vulnerability_scanning_host_scan_recipe":       {Tok: ociDataSource(vulnerabilityScanningMod, "getHostScanRecipe")},
			"oci_vulnerability_scanning_host_scan_recipes":      {Tok: ociDataSource(vulnerabilityScanningMod, "getHostScanRecipes")},
			"oci_vulnerability_scanning_host_scan_target":       {Tok: ociDataSource(vulnerabilityScanningMod, "getHostScanTarget")},
			"oci_vulnerability_scanning_host_scan_targets":      {Tok: ociDataSource(vulnerabilityScanningMod, "getHostScanTargets")},
			// WAAS
			"oci_waas_address_list":            {Tok: ociDataSource(waasMod, "getAddressList")},
			"oci_waas_address_lists":           {Tok: ociDataSource(waasMod, "getAddressLists")},
			"oci_waas_certificate":             {Tok: ociDataSource(waasMod, "getCertificate")},
			"oci_waas_certificates":            {Tok: ociDataSource(waasMod, "getCertificates")},
			"oci_waas_custom_protection_rule":  {Tok: ociDataSource(waasMod, "getCustomProtectionRule")},
			"oci_waas_custom_protection_rules": {Tok: ociDataSource(waasMod, "getCustomProtectionRules")},
			"oci_waas_edge_subnets":            {Tok: ociDataSource(waasMod, "getEdgeSubnets")},
			"oci_waas_http_redirect":           {Tok: ociDataSource(waasMod, "getHttpRedirect")},
			"oci_waas_http_redirects":          {Tok: ociDataSource(waasMod, "getHttpRedirects")},
			"oci_waas_protection_rule":         {Tok: ociDataSource(waasMod, "getProtectionRule")},
			"oci_waas_protection_rules":        {Tok: ociDataSource(waasMod, "getProtectionRules")},
			"oci_waas_waas_policies":           {Tok: ociDataSource(waasMod, "getWaasPolicies")},
			"oci_waas_waas_policy":             {Tok: ociDataSource(waasMod, "getWaasPolicy")},
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
