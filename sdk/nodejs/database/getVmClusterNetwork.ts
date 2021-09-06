// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vm Cluster Network resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified VM cluster network. Applies to Exadata Cloud@Customer instances only.
 * To get information about a cloud VM cluster in an Exadata Cloud Service instance, use the [GetCloudVmCluster ](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/GetCloudVmCluster) operation.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterNetwork = oci.database.getVmClusterNetwork({
 *     exadataInfrastructureId: oci_database_exadata_infrastructure.test_exadata_infrastructure.id,
 *     vmClusterNetworkId: oci_database_vm_cluster_network.test_vm_cluster_network.id,
 * });
 * ```
 */
export function getVmClusterNetwork(args: GetVmClusterNetworkArgs, opts?: pulumi.InvokeOptions): Promise<GetVmClusterNetworkResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getVmClusterNetwork:getVmClusterNetwork", {
        "exadataInfrastructureId": args.exadataInfrastructureId,
        "vmClusterNetworkId": args.vmClusterNetworkId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVmClusterNetwork.
 */
export interface GetVmClusterNetworkArgs {
    /**
     * The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    exadataInfrastructureId: string;
    /**
     * The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterNetworkId: string;
}

/**
 * A collection of values returned by getVmClusterNetwork.
 */
export interface GetVmClusterNetworkResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The user-friendly name for the VM cluster network. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * The list of DNS server IP addresses. Maximum of 3 allowed.
     */
    readonly dns: string[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    readonly id: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The list of NTP server IP addresses. Maximum of 3 allowed.
     */
    readonly ntps: string[];
    /**
     * The SCAN details.
     */
    readonly scans: outputs.database.GetVmClusterNetworkScan[];
    /**
     * The current state of the VM cluster network.
     */
    readonly state: string;
    /**
     * The date and time when the VM cluster network was created.
     */
    readonly timeCreated: string;
    readonly validateVmClusterNetwork: boolean;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated VM Cluster.
     */
    readonly vmClusterId: string;
    readonly vmClusterNetworkId: string;
    /**
     * Details of the client and backup networks.
     */
    readonly vmNetworks: outputs.database.GetVmClusterNetworkVmNetwork[];
}
