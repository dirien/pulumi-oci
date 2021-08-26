// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vault resource in Oracle Cloud Infrastructure Kms service.
 *
 * Gets the specified vault's configuration information.
 *
 * As a provisioning operation, this call is subject to a Key Management limit that applies to
 * the total number of requests across all provisioning read operations. Key Management might
 * throttle this call to reject an otherwise valid request when the total rate of provisioning
 * read operations exceeds 10 requests per second for a given tenancy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVault = oci.kms.getVault({
 *     vaultId: oci_kms_vault.test_vault.id,
 * });
 * ```
 */
export function getVault(args: GetVaultArgs, opts?: pulumi.InvokeOptions): Promise<GetVaultResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:kms/getVault:getVault", {
        "vaultId": args.vaultId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVault.
 */
export interface GetVaultArgs {
    /**
     * The OCID of the vault.
     */
    vaultId: string;
}

/**
 * A collection of values returned by getVault.
 */
export interface GetVaultResult {
    /**
     * The OCID of the compartment that contains a particular vault.
     */
    readonly compartmentId: string;
    /**
     * The service endpoint to perform cryptographic operations against. Cryptographic operations include [Encrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/EncryptedData/Encrypt), [Decrypt](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/DecryptedData/Decrypt), and [GenerateDataEncryptionKey](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/GeneratedKey/GenerateDataEncryptionKey) operations.
     */
    readonly cryptoEndpoint: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly name for the vault. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the vault.
     */
    readonly id: string;
    /**
     * A boolean that will be true when vault is primary, and will be false when vault is a replica from a primary vault.
     */
    readonly isPrimary: boolean;
    /**
     * The service endpoint to perform management operations against. Management operations include "Create," "Update," "List," "Get," and "Delete" operations.
     */
    readonly managementEndpoint: string;
    /**
     * Vault replica details
     */
    readonly replicaDetails: outputs.kms.GetVaultReplicaDetails;
    /**
     * Details where vault was backed up.
     */
    readonly restoreFromFile: outputs.kms.GetVaultRestoreFromFile;
    /**
     * Details where vault was backed up
     */
    readonly restoreFromObjectStore: outputs.kms.GetVaultRestoreFromObjectStore;
    /**
     * When flipped, triggers restore if restore options are provided. Values of 0 or 1 are supported
     */
    readonly restoreTrigger: boolean;
    /**
     * The OCID of the vault from which this vault was restored, if it was restored from a backup file.  If you restore a vault to the same region, the vault retains the same OCID that it had when you  backed up the vault.
     */
    readonly restoredFromVaultId: string;
    /**
     * The vault's current lifecycle state.  Example: `DELETED`
     */
    readonly state: string;
    /**
     * The date and time this vault was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-04-03T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * An optional property to indicate when to delete the vault, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    readonly timeOfDeletion: string;
    readonly vaultId: string;
    /**
     * The type of vault. Each type of vault stores the key with different degrees of isolation and has different options and pricing.
     */
    readonly vaultType: string;
}
