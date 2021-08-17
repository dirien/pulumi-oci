// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "./types";
import * as utilities from "./utilities";

/**
 * This data source provides the list of Vm Cluster Networks in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the VM cluster networks in the specified compartment. Applies to Exadata Cloud@Customer instances only.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterNetworks = oci.GetDatabaseVmClusterNetworks({
 *     compartmentId: _var.compartment_id,
 *     exadataInfrastructureId: oci_database_exadata_infrastructure.test_exadata_infrastructure.id,
 *     displayName: _var.vm_cluster_network_display_name,
 *     state: _var.vm_cluster_network_state,
 * });
 * ```
 */
export function getDatabaseVmClusterNetworks(args: GetDatabaseVmClusterNetworksArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseVmClusterNetworksResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:index/getDatabaseVmClusterNetworks:GetDatabaseVmClusterNetworks", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "exadataInfrastructureId": args.exadataInfrastructureId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking GetDatabaseVmClusterNetworks.
 */
export interface GetDatabaseVmClusterNetworksArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    /**
     * The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    exadataInfrastructureId: string;
    filters?: inputs.GetDatabaseVmClusterNetworksFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by GetDatabaseVmClusterNetworks.
 */
export interface GetDatabaseVmClusterNetworksResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the VM cluster network. The name does not need to be unique.
     */
    readonly displayName?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId: string;
    readonly filters?: outputs.GetDatabaseVmClusterNetworksFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the VM cluster network.
     */
    readonly state?: string;
    /**
     * The list of vm_cluster_networks.
     */
    readonly vmClusterNetworks: outputs.GetDatabaseVmClusterNetworksVmClusterNetwork[];
}