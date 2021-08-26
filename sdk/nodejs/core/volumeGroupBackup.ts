// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Volume Group Backup resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new backup volume group of the specified volume group.
 * For more information, see [Volume Groups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumeGroupBackup = new oci.core.VolumeGroupBackup("testVolumeGroupBackup", {
 *     volumeGroupId: oci_core_volume_group.test_volume_group.id,
 *     compartmentId: _var.compartment_id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.volume_group_backup_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     type: _var.volume_group_backup_type,
 * });
 * ```
 *
 * ## Import
 *
 * VolumeGroupBackups can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:core/volumeGroupBackup:VolumeGroupBackup test_volume_group_backup "id"
 * ```
 */
export class VolumeGroupBackup extends pulumi.CustomResource {
    /**
     * Get an existing VolumeGroupBackup resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VolumeGroupBackupState, opts?: pulumi.CustomResourceOptions): VolumeGroupBackup {
        return new VolumeGroupBackup(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:core/volumeGroupBackup:VolumeGroupBackup';

    /**
     * Returns true if the given object is an instance of VolumeGroupBackup.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VolumeGroupBackup {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VolumeGroupBackup.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     */
    public /*out*/ readonly expirationTime!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The aggregate size of the volume group backup, in GBs.
     */
    public /*out*/ readonly sizeInGbs!: pulumi.Output<string>;
    /**
     * The aggregate size of the volume group backup, in MBs.
     */
    public /*out*/ readonly sizeInMbs!: pulumi.Output<string>;
    /**
     * Details of the volume group backup source in the cloud.
     */
    public readonly sourceDetails!: pulumi.Output<outputs.core.VolumeGroupBackupSourceDetails | undefined>;
    /**
     * Specifies whether the volume group backup was created manually, or via scheduled backup policy.
     */
    public /*out*/ readonly sourceType!: pulumi.Output<string>;
    /**
     * The OCID of the source volume group backup.
     */
    public /*out*/ readonly sourceVolumeGroupBackupId!: pulumi.Output<string>;
    /**
     * The current state of a volume group backup.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeRequestReceived!: pulumi.Output<string>;
    /**
     * The type of backup to create. If omitted, defaults to incremental.
     * * Allowed values are :
     * * FULL
     * * INCREMENTAL
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `sizeInGbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     */
    public /*out*/ readonly uniqueSizeInGbs!: pulumi.Output<string>;
    /**
     * The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `sizeInMbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     */
    public /*out*/ readonly uniqueSizeInMbs!: pulumi.Output<string>;
    /**
     * OCIDs for the volume backups in this volume group backup.
     */
    public /*out*/ readonly volumeBackupIds!: pulumi.Output<string[]>;
    /**
     * The OCID of the volume group that needs to be backed up.
     */
    public readonly volumeGroupId!: pulumi.Output<string>;

    /**
     * Create a VolumeGroupBackup resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: VolumeGroupBackupArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VolumeGroupBackupArgs | VolumeGroupBackupState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VolumeGroupBackupState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["expirationTime"] = state ? state.expirationTime : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["sizeInGbs"] = state ? state.sizeInGbs : undefined;
            inputs["sizeInMbs"] = state ? state.sizeInMbs : undefined;
            inputs["sourceDetails"] = state ? state.sourceDetails : undefined;
            inputs["sourceType"] = state ? state.sourceType : undefined;
            inputs["sourceVolumeGroupBackupId"] = state ? state.sourceVolumeGroupBackupId : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeRequestReceived"] = state ? state.timeRequestReceived : undefined;
            inputs["type"] = state ? state.type : undefined;
            inputs["uniqueSizeInGbs"] = state ? state.uniqueSizeInGbs : undefined;
            inputs["uniqueSizeInMbs"] = state ? state.uniqueSizeInMbs : undefined;
            inputs["volumeBackupIds"] = state ? state.volumeBackupIds : undefined;
            inputs["volumeGroupId"] = state ? state.volumeGroupId : undefined;
        } else {
            const args = argsOrState as VolumeGroupBackupArgs | undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["sourceDetails"] = args ? args.sourceDetails : undefined;
            inputs["type"] = args ? args.type : undefined;
            inputs["volumeGroupId"] = args ? args.volumeGroupId : undefined;
            inputs["expirationTime"] = undefined /*out*/;
            inputs["sizeInGbs"] = undefined /*out*/;
            inputs["sizeInMbs"] = undefined /*out*/;
            inputs["sourceType"] = undefined /*out*/;
            inputs["sourceVolumeGroupBackupId"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeRequestReceived"] = undefined /*out*/;
            inputs["uniqueSizeInGbs"] = undefined /*out*/;
            inputs["uniqueSizeInMbs"] = undefined /*out*/;
            inputs["volumeBackupIds"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(VolumeGroupBackup.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VolumeGroupBackup resources.
 */
export interface VolumeGroupBackupState {
    /**
     * (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The date and time the volume group backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for volume group backups that were created automatically by a scheduled-backup policy. For manually created volume group backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     */
    expirationTime?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The aggregate size of the volume group backup, in GBs.
     */
    sizeInGbs?: pulumi.Input<string>;
    /**
     * The aggregate size of the volume group backup, in MBs.
     */
    sizeInMbs?: pulumi.Input<string>;
    /**
     * Details of the volume group backup source in the cloud.
     */
    sourceDetails?: pulumi.Input<inputs.core.VolumeGroupBackupSourceDetails>;
    /**
     * Specifies whether the volume group backup was created manually, or via scheduled backup policy.
     */
    sourceType?: pulumi.Input<string>;
    /**
     * The OCID of the source volume group backup.
     */
    sourceVolumeGroupBackupId?: pulumi.Input<string>;
    /**
     * The current state of a volume group backup.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the volume group backup was created. This is the time the actual point-in-time image of the volume group data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the request to create the volume group backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeRequestReceived?: pulumi.Input<string>;
    /**
     * The type of backup to create. If omitted, defaults to incremental.
     * * Allowed values are :
     * * FULL
     * * INCREMENTAL
     */
    type?: pulumi.Input<string>;
    /**
     * The aggregate size used by the volume group backup, in GBs.  It is typically smaller than `sizeInGbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     */
    uniqueSizeInGbs?: pulumi.Input<string>;
    /**
     * The aggregate size used by the volume group backup, in MBs.  It is typically smaller than `sizeInMbs`, depending on the space consumed on the volume group and whether the volume backup is full or incremental.
     */
    uniqueSizeInMbs?: pulumi.Input<string>;
    /**
     * OCIDs for the volume backups in this volume group backup.
     */
    volumeBackupIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the volume group that needs to be backed up.
     */
    volumeGroupId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a VolumeGroupBackup resource.
 */
export interface VolumeGroupBackupArgs {
    /**
     * (Updatable) The OCID of the compartment that will contain the volume group backup. This parameter is optional, by default backup will be created in the same compartment and source volume group.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name for the volume group backup. Does not have to be unique and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Details of the volume group backup source in the cloud.
     */
    sourceDetails?: pulumi.Input<inputs.core.VolumeGroupBackupSourceDetails>;
    /**
     * The type of backup to create. If omitted, defaults to incremental.
     * * Allowed values are :
     * * FULL
     * * INCREMENTAL
     */
    type?: pulumi.Input<string>;
    /**
     * The OCID of the volume group that needs to be backed up.
     */
    volumeGroupId?: pulumi.Input<string>;
}
