// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Export resource in Oracle Cloud Infrastructure File Storage service.
 *
 * Creates a new export in the specified export set, path, and
 * file system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExport = new oci.filestorage.Export("testExport", {
 *     exportSetId: oci_file_storage_export_set.test_export_set.id,
 *     fileSystemId: oci_file_storage_file_system.test_file_system.id,
 *     path: _var.export_path,
 *     exportOptions: [{
 *         source: _var.export_export_options_source,
 *         access: _var.export_export_options_access,
 *         anonymousGid: _var.export_export_options_anonymous_gid,
 *         anonymousUid: _var.export_export_options_anonymous_uid,
 *         identitySquash: _var.export_export_options_identity_squash,
 *         requirePrivilegedSourcePort: _var.export_export_options_require_privileged_source_port,
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * Exports can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:filestorage/export:Export test_export "id"
 * ```
 */
export class Export extends pulumi.CustomResource {
    /**
     * Get an existing Export resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExportState, opts?: pulumi.CustomResourceOptions): Export {
        return new Export(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:filestorage/export:Export';

    /**
     * Returns true if the given object is an instance of Export.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Export {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Export.__pulumiType;
    }

    /**
     * (Updatable) Export options for the new export. If left unspecified, defaults to:
     */
    public readonly exportOptions!: pulumi.Output<outputs.filestorage.ExportExportOption[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    public readonly exportSetId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    public readonly fileSystemId!: pulumi.Output<string>;
    /**
     * Path used to access the associated file system.
     */
    public readonly path!: pulumi.Output<string>;
    /**
     * The current state of this export.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Export resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExportArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExportArgs | ExportState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExportState | undefined;
            inputs["exportOptions"] = state ? state.exportOptions : undefined;
            inputs["exportSetId"] = state ? state.exportSetId : undefined;
            inputs["fileSystemId"] = state ? state.fileSystemId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as ExportArgs | undefined;
            if ((!args || args.exportSetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'exportSetId'");
            }
            if ((!args || args.fileSystemId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fileSystemId'");
            }
            if ((!args || args.path === undefined) && !opts.urn) {
                throw new Error("Missing required property 'path'");
            }
            inputs["exportOptions"] = args ? args.exportOptions : undefined;
            inputs["exportSetId"] = args ? args.exportSetId : undefined;
            inputs["fileSystemId"] = args ? args.fileSystemId : undefined;
            inputs["path"] = args ? args.path : undefined;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Export.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Export resources.
 */
export interface ExportState {
    /**
     * (Updatable) Export options for the new export. If left unspecified, defaults to:
     */
    exportOptions?: pulumi.Input<pulumi.Input<inputs.filestorage.ExportExportOption>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    exportSetId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    fileSystemId?: pulumi.Input<string>;
    /**
     * Path used to access the associated file system.
     */
    path?: pulumi.Input<string>;
    /**
     * The current state of this export.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Export resource.
 */
export interface ExportArgs {
    /**
     * (Updatable) Export options for the new export. If left unspecified, defaults to:
     */
    exportOptions?: pulumi.Input<pulumi.Input<inputs.filestorage.ExportExportOption>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
     */
    exportSetId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
     */
    fileSystemId: pulumi.Input<string>;
    /**
     * Path used to access the associated file system.
     */
    path: pulumi.Input<string>;
}
