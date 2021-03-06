// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Cloud Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 *
 * Creates a cloud VM cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCloudVmCluster = new oci.database.CloudVmCluster("testCloudVmCluster", {
 *     backupSubnetId: oci_core_subnet.test_subnet.id,
 *     cloudExadataInfrastructureId: oci_database_cloud_exadata_infrastructure.test_cloud_exadata_infrastructure.id,
 *     compartmentId: _var.compartment_id,
 *     cpuCoreCount: _var.cloud_vm_cluster_cpu_core_count,
 *     displayName: _var.cloud_vm_cluster_display_name,
 *     giVersion: _var.cloud_vm_cluster_gi_version,
 *     hostname: _var.cloud_vm_cluster_hostname,
 *     sshPublicKeys: _var.cloud_vm_cluster_ssh_public_keys,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     backupNetworkNsgIds: _var.cloud_vm_cluster_backup_network_nsg_ids,
 *     clusterName: _var.cloud_vm_cluster_cluster_name,
 *     dataStoragePercentage: _var.cloud_vm_cluster_data_storage_percentage,
 *     definedTags: _var.cloud_vm_cluster_defined_tags,
 *     domain: _var.cloud_vm_cluster_domain,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isLocalBackupEnabled: _var.cloud_vm_cluster_is_local_backup_enabled,
 *     isSparseDiskgroupEnabled: _var.cloud_vm_cluster_is_sparse_diskgroup_enabled,
 *     licenseModel: _var.cloud_vm_cluster_license_model,
 *     nsgIds: _var.cloud_vm_cluster_nsg_ids,
 *     timeZone: _var.cloud_vm_cluster_time_zone,
 * });
 * ```
 *
 * ## Import
 *
 * CloudVmClusters can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:database/cloudVmCluster:CloudVmCluster test_cloud_vm_cluster "id"
 * ```
 */
export class CloudVmCluster extends pulumi.CustomResource {
    /**
     * Get an existing CloudVmCluster resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CloudVmClusterState, opts?: pulumi.CustomResourceOptions): CloudVmCluster {
        return new CloudVmCluster(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:database/cloudVmCluster:CloudVmCluster';

    /**
     * Returns true if the given object is an instance of CloudVmCluster.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CloudVmCluster {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CloudVmCluster.__pulumiType;
    }

    /**
     * The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     */
    public /*out*/ readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
     */
    public readonly backupNetworkNsgIds!: pulumi.Output<string[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet associated with the cloud VM cluster.
     */
    public readonly backupSubnetId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     */
    public readonly cloudExadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The cluster name for cloud VM cluster. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
     */
    public readonly clusterName!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) The number of CPU cores to enable for a cloud VM cluster. Valid values depend on the specified shape:
     * * Exadata.Base.48 - Specify a multiple of 2, from 0 to 48.
     * * Exadata.Quarter1.84 - Specify a multiple of 2, from 22 to 84.
     * * Exadata.Half1.168 - Specify a multiple of 4, from 44 to 168.
     * * Exadata.Full1.336 - Specify a multiple of 8, from 88 to 336.
     * * Exadata.Quarter2.92 - Specify a multiple of 2, from 0 to 92.
     * * Exadata.Half2.184 - Specify a multiple of 4, from 0 to 184.
     * * Exadata.Full2.368 - Specify a multiple of 8, from 0 to 368.
     */
    public readonly cpuCoreCount!: pulumi.Output<number>;
    public readonly createAsync!: pulumi.Output<boolean | undefined>;
    /**
     * The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 35, 40, 60 and 80. The default is 80 percent assigned to DATA storage. See [Storage Configuration](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaoverview.htm#Exadata) in the Exadata documentation for details on the impact of the configuration settings on storage.
     */
    public readonly dataStoragePercentage!: pulumi.Output<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The type of redundancy configured for the cloud Vm cluster. NORMAL is 2-way redundancy. HIGH is 3-way redundancy.
     */
    public /*out*/ readonly diskRedundancy!: pulumi.Output<string>;
    /**
     * (Updatable) The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * A domain name used for the cloud VM cluster. If the Oracle-provided internet and VCN resolver is enabled for the specified subnet, the domain name for the subnet is used (do not provide one). Otherwise, provide a valid DNS domain name. Hyphens (-) are not permitted. Applies to Exadata Cloud Service instances only.
     */
    public readonly domain!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A valid Oracle Grid Infrastructure (GI) software version.
     */
    public readonly giVersion!: pulumi.Output<string>;
    /**
     * The hostname for the cloud VM cluster. The hostname must begin with an alphabetic character, and can contain alphanumeric characters and hyphens (-). The maximum length of the hostname is 16 characters for bare metal and virtual machine DB systems, and 12 characters for Exadata systems.
     */
    public readonly hostname!: pulumi.Output<string>;
    /**
     * The IORM settings of the Exadata DB system.
     */
    public /*out*/ readonly iormConfigCache!: pulumi.Output<outputs.database.CloudVmClusterIormConfigCache>;
    /**
     * If true, database backup on local Exadata storage is configured for the cloud VM cluster. If false, database backup on local Exadata storage is not available in the cloud VM cluster.
     */
    public readonly isLocalBackupEnabled!: pulumi.Output<boolean>;
    /**
     * If true, the sparse disk group is configured for the cloud VM cluster. If false, the sparse disk group is not created.
     */
    public readonly isSparseDiskgroupEnabled!: pulumi.Output<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history entry. This value is updated when a maintenance update starts.
     */
    public /*out*/ readonly lastUpdateHistoryEntryId!: pulumi.Output<string>;
    /**
     * (Updatable) The Oracle license model that applies to the cloud VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     */
    public readonly licenseModel!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The port number configured for the listener on the cloud VM cluster.
     */
    public /*out*/ readonly listenerPort!: pulumi.Output<string>;
    /**
     * The number of nodes in the cloud VM cluster.
     */
    public /*out*/ readonly nodeCount!: pulumi.Output<number>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The FQDN of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     */
    public /*out*/ readonly scanDnsName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     */
    public /*out*/ readonly scanDnsRecordId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IP addresses associated with the cloud VM cluster. SCAN IP addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
     */
    public /*out*/ readonly scanIpIds!: pulumi.Output<string[]>;
    /**
     * The model name of the Exadata hardware running the cloud VM cluster.
     */
    public /*out*/ readonly shape!: pulumi.Output<string>;
    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the cloud VM cluster.
     */
    public readonly sshPublicKeys!: pulumi.Output<string[]>;
    /**
     * The current state of the cloud VM cluster.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The storage allocation for the disk group, in gigabytes (GB).
     */
    public /*out*/ readonly storageSizeInGbs!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the cloud VM cluster.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * Operating system version of the image.
     */
    public /*out*/ readonly systemVersion!: pulumi.Output<string>;
    /**
     * The date and time that the cloud VM cluster was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time zone to use for the cloud VM cluster. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    public readonly timeZone!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IP (VIP) addresses associated with the cloud VM cluster. The Cluster Ready Services (CRS) creates and maintains one VIP address for each node in the Exadata Cloud Service instance to enable failover. If one node fails, the VIP is reassigned to another active node in the cluster.
     */
    public /*out*/ readonly vipIds!: pulumi.Output<string[]>;
    /**
     * The OCID of the zone the cloud VM cluster is associated with.
     */
    public /*out*/ readonly zoneId!: pulumi.Output<string>;

    /**
     * Create a CloudVmCluster resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CloudVmClusterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CloudVmClusterArgs | CloudVmClusterState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CloudVmClusterState | undefined;
            inputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            inputs["backupNetworkNsgIds"] = state ? state.backupNetworkNsgIds : undefined;
            inputs["backupSubnetId"] = state ? state.backupSubnetId : undefined;
            inputs["cloudExadataInfrastructureId"] = state ? state.cloudExadataInfrastructureId : undefined;
            inputs["clusterName"] = state ? state.clusterName : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["cpuCoreCount"] = state ? state.cpuCoreCount : undefined;
            inputs["createAsync"] = state ? state.createAsync : undefined;
            inputs["dataStoragePercentage"] = state ? state.dataStoragePercentage : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["diskRedundancy"] = state ? state.diskRedundancy : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domain"] = state ? state.domain : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["giVersion"] = state ? state.giVersion : undefined;
            inputs["hostname"] = state ? state.hostname : undefined;
            inputs["iormConfigCache"] = state ? state.iormConfigCache : undefined;
            inputs["isLocalBackupEnabled"] = state ? state.isLocalBackupEnabled : undefined;
            inputs["isSparseDiskgroupEnabled"] = state ? state.isSparseDiskgroupEnabled : undefined;
            inputs["lastUpdateHistoryEntryId"] = state ? state.lastUpdateHistoryEntryId : undefined;
            inputs["licenseModel"] = state ? state.licenseModel : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["listenerPort"] = state ? state.listenerPort : undefined;
            inputs["nodeCount"] = state ? state.nodeCount : undefined;
            inputs["nsgIds"] = state ? state.nsgIds : undefined;
            inputs["scanDnsName"] = state ? state.scanDnsName : undefined;
            inputs["scanDnsRecordId"] = state ? state.scanDnsRecordId : undefined;
            inputs["scanIpIds"] = state ? state.scanIpIds : undefined;
            inputs["shape"] = state ? state.shape : undefined;
            inputs["sshPublicKeys"] = state ? state.sshPublicKeys : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["storageSizeInGbs"] = state ? state.storageSizeInGbs : undefined;
            inputs["subnetId"] = state ? state.subnetId : undefined;
            inputs["systemVersion"] = state ? state.systemVersion : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeZone"] = state ? state.timeZone : undefined;
            inputs["vipIds"] = state ? state.vipIds : undefined;
            inputs["zoneId"] = state ? state.zoneId : undefined;
        } else {
            const args = argsOrState as CloudVmClusterArgs | undefined;
            if ((!args || args.backupSubnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'backupSubnetId'");
            }
            if ((!args || args.cloudExadataInfrastructureId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cloudExadataInfrastructureId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.cpuCoreCount === undefined) && !opts.urn) {
                throw new Error("Missing required property 'cpuCoreCount'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.giVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'giVersion'");
            }
            if ((!args || args.hostname === undefined) && !opts.urn) {
                throw new Error("Missing required property 'hostname'");
            }
            if ((!args || args.sshPublicKeys === undefined) && !opts.urn) {
                throw new Error("Missing required property 'sshPublicKeys'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            inputs["backupNetworkNsgIds"] = args ? args.backupNetworkNsgIds : undefined;
            inputs["backupSubnetId"] = args ? args.backupSubnetId : undefined;
            inputs["cloudExadataInfrastructureId"] = args ? args.cloudExadataInfrastructureId : undefined;
            inputs["clusterName"] = args ? args.clusterName : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["cpuCoreCount"] = args ? args.cpuCoreCount : undefined;
            inputs["createAsync"] = args ? args.createAsync : undefined;
            inputs["dataStoragePercentage"] = args ? args.dataStoragePercentage : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domain"] = args ? args.domain : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["giVersion"] = args ? args.giVersion : undefined;
            inputs["hostname"] = args ? args.hostname : undefined;
            inputs["isLocalBackupEnabled"] = args ? args.isLocalBackupEnabled : undefined;
            inputs["isSparseDiskgroupEnabled"] = args ? args.isSparseDiskgroupEnabled : undefined;
            inputs["licenseModel"] = args ? args.licenseModel : undefined;
            inputs["nsgIds"] = args ? args.nsgIds : undefined;
            inputs["sshPublicKeys"] = args ? args.sshPublicKeys : undefined;
            inputs["subnetId"] = args ? args.subnetId : undefined;
            inputs["timeZone"] = args ? args.timeZone : undefined;
            inputs["availabilityDomain"] = undefined /*out*/;
            inputs["diskRedundancy"] = undefined /*out*/;
            inputs["iormConfigCache"] = undefined /*out*/;
            inputs["lastUpdateHistoryEntryId"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["listenerPort"] = undefined /*out*/;
            inputs["nodeCount"] = undefined /*out*/;
            inputs["scanDnsName"] = undefined /*out*/;
            inputs["scanDnsRecordId"] = undefined /*out*/;
            inputs["scanIpIds"] = undefined /*out*/;
            inputs["shape"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["storageSizeInGbs"] = undefined /*out*/;
            inputs["systemVersion"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["vipIds"] = undefined /*out*/;
            inputs["zoneId"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(CloudVmCluster.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering CloudVmCluster resources.
 */
export interface CloudVmClusterState {
    /**
     * The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
     */
    backupNetworkNsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet associated with the cloud VM cluster.
     */
    backupSubnetId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     */
    cloudExadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The cluster name for cloud VM cluster. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
     */
    clusterName?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) The number of CPU cores to enable for a cloud VM cluster. Valid values depend on the specified shape:
     * * Exadata.Base.48 - Specify a multiple of 2, from 0 to 48.
     * * Exadata.Quarter1.84 - Specify a multiple of 2, from 22 to 84.
     * * Exadata.Half1.168 - Specify a multiple of 4, from 44 to 168.
     * * Exadata.Full1.336 - Specify a multiple of 8, from 88 to 336.
     * * Exadata.Quarter2.92 - Specify a multiple of 2, from 0 to 92.
     * * Exadata.Half2.184 - Specify a multiple of 4, from 0 to 184.
     * * Exadata.Full2.368 - Specify a multiple of 8, from 0 to 368.
     */
    cpuCoreCount?: pulumi.Input<number>;
    createAsync?: pulumi.Input<boolean>;
    /**
     * The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 35, 40, 60 and 80. The default is 80 percent assigned to DATA storage. See [Storage Configuration](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaoverview.htm#Exadata) in the Exadata documentation for details on the impact of the configuration settings on storage.
     */
    dataStoragePercentage?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The type of redundancy configured for the cloud Vm cluster. NORMAL is 2-way redundancy. HIGH is 3-way redundancy.
     */
    diskRedundancy?: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A domain name used for the cloud VM cluster. If the Oracle-provided internet and VCN resolver is enabled for the specified subnet, the domain name for the subnet is used (do not provide one). Otherwise, provide a valid DNS domain name. Hyphens (-) are not permitted. Applies to Exadata Cloud Service instances only.
     */
    domain?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A valid Oracle Grid Infrastructure (GI) software version.
     */
    giVersion?: pulumi.Input<string>;
    /**
     * The hostname for the cloud VM cluster. The hostname must begin with an alphabetic character, and can contain alphanumeric characters and hyphens (-). The maximum length of the hostname is 16 characters for bare metal and virtual machine DB systems, and 12 characters for Exadata systems.
     */
    hostname?: pulumi.Input<string>;
    /**
     * The IORM settings of the Exadata DB system.
     */
    iormConfigCache?: pulumi.Input<inputs.database.CloudVmClusterIormConfigCache>;
    /**
     * If true, database backup on local Exadata storage is configured for the cloud VM cluster. If false, database backup on local Exadata storage is not available in the cloud VM cluster.
     */
    isLocalBackupEnabled?: pulumi.Input<boolean>;
    /**
     * If true, the sparse disk group is configured for the cloud VM cluster. If false, the sparse disk group is not created.
     */
    isSparseDiskgroupEnabled?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history entry. This value is updated when a maintenance update starts.
     */
    lastUpdateHistoryEntryId?: pulumi.Input<string>;
    /**
     * (Updatable) The Oracle license model that applies to the cloud VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     */
    licenseModel?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The port number configured for the listener on the cloud VM cluster.
     */
    listenerPort?: pulumi.Input<string>;
    /**
     * The number of nodes in the cloud VM cluster.
     */
    nodeCount?: pulumi.Input<number>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The FQDN of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     */
    scanDnsName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     */
    scanDnsRecordId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IP addresses associated with the cloud VM cluster. SCAN IP addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
     */
    scanIpIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The model name of the Exadata hardware running the cloud VM cluster.
     */
    shape?: pulumi.Input<string>;
    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the cloud VM cluster.
     */
    sshPublicKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The current state of the cloud VM cluster.
     */
    state?: pulumi.Input<string>;
    /**
     * The storage allocation for the disk group, in gigabytes (GB).
     */
    storageSizeInGbs?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the cloud VM cluster.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * Operating system version of the image.
     */
    systemVersion?: pulumi.Input<string>;
    /**
     * The date and time that the cloud VM cluster was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time zone to use for the cloud VM cluster. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    timeZone?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IP (VIP) addresses associated with the cloud VM cluster. The Cluster Ready Services (CRS) creates and maintains one VIP address for each node in the Exadata Cloud Service instance to enable failover. If one node fails, the VIP is reassigned to another active node in the cluster.
     */
    vipIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the zone the cloud VM cluster is associated with.
     */
    zoneId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a CloudVmCluster resource.
 */
export interface CloudVmClusterArgs {
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
     */
    backupNetworkNsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet associated with the cloud VM cluster.
     */
    backupSubnetId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     */
    cloudExadataInfrastructureId: pulumi.Input<string>;
    /**
     * The cluster name for cloud VM cluster. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
     */
    clusterName?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The number of CPU cores to enable for a cloud VM cluster. Valid values depend on the specified shape:
     * * Exadata.Base.48 - Specify a multiple of 2, from 0 to 48.
     * * Exadata.Quarter1.84 - Specify a multiple of 2, from 22 to 84.
     * * Exadata.Half1.168 - Specify a multiple of 4, from 44 to 168.
     * * Exadata.Full1.336 - Specify a multiple of 8, from 88 to 336.
     * * Exadata.Quarter2.92 - Specify a multiple of 2, from 0 to 92.
     * * Exadata.Half2.184 - Specify a multiple of 4, from 0 to 184.
     * * Exadata.Full2.368 - Specify a multiple of 8, from 0 to 368.
     */
    cpuCoreCount: pulumi.Input<number>;
    createAsync?: pulumi.Input<boolean>;
    /**
     * The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 35, 40, 60 and 80. The default is 80 percent assigned to DATA storage. See [Storage Configuration](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaoverview.htm#Exadata) in the Exadata documentation for details on the impact of the configuration settings on storage.
     */
    dataStoragePercentage?: pulumi.Input<number>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     */
    displayName: pulumi.Input<string>;
    /**
     * A domain name used for the cloud VM cluster. If the Oracle-provided internet and VCN resolver is enabled for the specified subnet, the domain name for the subnet is used (do not provide one). Otherwise, provide a valid DNS domain name. Hyphens (-) are not permitted. Applies to Exadata Cloud Service instances only.
     */
    domain?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A valid Oracle Grid Infrastructure (GI) software version.
     */
    giVersion: pulumi.Input<string>;
    /**
     * The hostname for the cloud VM cluster. The hostname must begin with an alphabetic character, and can contain alphanumeric characters and hyphens (-). The maximum length of the hostname is 16 characters for bare metal and virtual machine DB systems, and 12 characters for Exadata systems.
     */
    hostname: pulumi.Input<string>;
    /**
     * If true, database backup on local Exadata storage is configured for the cloud VM cluster. If false, database backup on local Exadata storage is not available in the cloud VM cluster.
     */
    isLocalBackupEnabled?: pulumi.Input<boolean>;
    /**
     * If true, the sparse disk group is configured for the cloud VM cluster. If false, the sparse disk group is not created.
     */
    isSparseDiskgroupEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) The Oracle license model that applies to the cloud VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     */
    licenseModel?: pulumi.Input<string>;
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the cloud VM cluster.
     */
    sshPublicKeys: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the cloud VM cluster.
     */
    subnetId: pulumi.Input<string>;
    /**
     * The time zone to use for the cloud VM cluster. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    timeZone?: pulumi.Input<string>;
}
