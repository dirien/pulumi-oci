// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Mount Target resource in Oracle Cloud Infrastructure File Storage service.
 *
 * Creates a new mount target in the specified compartment and
 * subnet. You can associate a file system with a mount
 * target only when they exist in the same availability domain. Instances
 * can connect to mount targets in another availablity domain, but
 * you might see higher latency than with instances in the same
 * availability domain as the mount target.
 *
 * Mount targets have one or more private IP addresses that you can
 * provide as the host portion of remote target parameters in
 * client mount commands. These private IP addresses are listed
 * in the privateIpIds property of the mount target and are highly available. Mount
 * targets also consume additional IP addresses in their subnet.
 * Do not use /30 or smaller subnets for mount target creation because they
 * do not have sufficient available IP addresses.
 * Allow at least three IP addresses for each mount target.
 *
 * For information about access control and compartments, see
 * [Overview of the IAM
 * Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
 *
 * For information about availability domains, see [Regions and
 * Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
 * To get a list of availability domains, use the
 * `ListAvailabilityDomains` operation in the Identity and Access
 * Management Service API.
 *
 * All Oracle Cloud Infrastructure Services resources, including
 * mount targets, get an Oracle-assigned, unique ID called an
 * Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).\
 * When you create a resource, you can find its OCID in the response.
 * You can also retrieve a resource's OCID by using a List API operation on that resource
 * type, or by viewing the resource in the Console.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMountTarget = new oci.filestorage.MountTarget("testMountTarget", {
 *     availabilityDomain: _var.mount_target_availability_domain,
 *     compartmentId: _var.compartment_id,
 *     subnetId: oci_core_subnet.test_subnet.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.mount_target_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     hostnameLabel: _var.mount_target_hostname_label,
 *     ipAddress: _var.mount_target_ip_address,
 *     nsgIds: _var.mount_target_nsg_ids,
 * });
 * ```
 *
 * ## Import
 *
 * MountTargets can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:filestorage/mountTarget:MountTarget test_mount_target "id"
 * ```
 */
export class MountTarget extends pulumi.CustomResource {
    /**
     * Get an existing MountTarget resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MountTargetState, opts?: pulumi.CustomResourceOptions): MountTarget {
        return new MountTarget(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:filestorage/mountTarget:MountTarget';

    /**
     * Returns true if the given object is an instance of MountTarget.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MountTarget {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MountTarget.__pulumiType;
    }

    /**
     * The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
     */
    public /*out*/ readonly exportSetId!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
     */
    public readonly hostnameLabel!: pulumi.Output<string>;
    /**
     * A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
     */
    public readonly ipAddress!: pulumi.Output<string>;
    /**
     * Additional information about the current 'lifecycleState'.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The OCIDs of the private IP addresses associated with this mount target.
     */
    public /*out*/ readonly privateIpIds!: pulumi.Output<string[]>;
    /**
     * The current state of the mount target.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * The date and time the mount target was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a MountTarget resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MountTargetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MountTargetArgs | MountTargetState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MountTargetState | undefined;
            inputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["exportSetId"] = state ? state.exportSetId : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["hostnameLabel"] = state ? state.hostnameLabel : undefined;
            inputs["ipAddress"] = state ? state.ipAddress : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["nsgIds"] = state ? state.nsgIds : undefined;
            inputs["privateIpIds"] = state ? state.privateIpIds : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["subnetId"] = state ? state.subnetId : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as MountTargetArgs | undefined;
            if ((!args || args.availabilityDomain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityDomain'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            inputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["hostnameLabel"] = args ? args.hostnameLabel : undefined;
            inputs["ipAddress"] = args ? args.ipAddress : undefined;
            inputs["nsgIds"] = args ? args.nsgIds : undefined;
            inputs["subnetId"] = args ? args.subnetId : undefined;
            inputs["exportSetId"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["privateIpIds"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(MountTarget.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MountTarget resources.
 */
export interface MountTargetState {
    /**
     * The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated export set. Controls what file systems will be exported through Network File System (NFS) protocol on this mount target.
     */
    exportSetId?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
     */
    hostnameLabel?: pulumi.Input<string>;
    /**
     * A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * Additional information about the current 'lifecycleState'.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCIDs of the private IP addresses associated with this mount target.
     */
    privateIpIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The current state of the mount target.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
     */
    subnetId?: pulumi.Input<string>;
    /**
     * The date and time the mount target was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MountTarget resource.
 */
export interface MountTargetArgs {
    /**
     * The availability domain in which to create the mount target.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the mount target.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My mount target`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The hostname for the mount target's IP address, used for DNS resolution. The value is the hostname portion of the private IP address's fully qualified domain name (FQDN). For example, `files-1` in the FQDN `files-1.subnet123.vcn1.oraclevcn.com`. Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
     */
    hostnameLabel?: pulumi.Input<string>;
    /**
     * A private IP address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns a private IP address from the subnet.  Example: `10.0.3.3`
     */
    ipAddress?: pulumi.Input<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this mount target. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the mount target from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which to create the mount target.
     */
    subnetId: pulumi.Input<string>;
}
