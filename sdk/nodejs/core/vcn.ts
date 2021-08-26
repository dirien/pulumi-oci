// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Vcn resource in Oracle Cloud Infrastructure Core service.
 *
 * The VCN automatically comes with a default route table, default security list, and default set of DHCP options.
 * For managing these resources, see [Managing Default VCN Resources](https://www.terraform.io/docs/providers/oci/guides/managing_default_resources.html)
 *
 * Creates a new Virtual Cloud Network (VCN). For more information, see
 * [VCNs and Subnets](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm).
 *
 * For the VCN, you specify a list of one or more IPv4 CIDR blocks that meet the following criteria:
 *
 * - The CIDR blocks must be valid.
 * - They must not overlap with each other or with the on-premises network CIDR block.
 * - The number of CIDR blocks does not exceed the limit of CIDR blocks allowed per VCN.
 *
 * For a CIDR block, Oracle recommends that you use one of the private IP address ranges specified in [RFC 1918](https://tools.ietf.org/html/rfc1918) (10.0.0.0/8, 172.16/12, and 192.168/16). Example:
 * 172.16.0.0/16. The CIDR blocks can range from /16 to /30.
 *
 * For the purposes of access control, you must provide the OCID of the compartment where you want the VCN to
 * reside. Consult an Oracle Cloud Infrastructure administrator in your organization if you're not sure which
 * compartment to use. Notice that the VCN doesn't have to be in the same compartment as the subnets or other
 * Networking Service components. For more information about compartments and access control, see
 * [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about OCIDs, see
 * [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
 *
 * You may optionally specify a *display name* for the VCN, otherwise a default is provided. It does not have to
 * be unique, and you can change it. Avoid entering confidential information.
 *
 * You can also add a DNS label for the VCN, which is required if you want the instances to use the
 * Interent and VCN Resolver option for DNS in the VCN. For more information, see
 * [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
 *
 * The VCN automatically comes with a default route table, default security list, and default set of DHCP options.
 * The OCID for each is returned in the response. You can't delete these default objects, but you can change their
 * contents (that is, change the route rules, security list rules, and so on).
 *
 * The VCN and subnets you create are not accessible until you attach an internet gateway or set up an IPSec VPN
 * or FastConnect. For more information, see
 * [Overview of the Networking Service](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/overview.htm).
 *
 * ## Supported Aliases
 *
 * * `ociCoreVirtualNetwork`
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVcn = new oci.core.Vcn("testVcn", {
 *     compartmentId: _var.compartment_id,
 *     cidrBlock: _var.vcn_cidr_block,
 *     cidrBlocks: _var.vcn_cidr_blocks,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: _var.vcn_display_name,
 *     dnsLabel: _var.vcn_dns_label,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     isIpv6enabled: _var.vcn_is_ipv6enabled,
 * });
 * ```
 *
 * ## Import
 *
 * Vcns can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:core/vcn:Vcn test_vcn "id"
 * ```
 */
export class Vcn extends pulumi.CustomResource {
    /**
     * Get an existing Vcn resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VcnState, opts?: pulumi.CustomResourceOptions): Vcn {
        return new Vcn(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:core/vcn:Vcn';

    /**
     * Returns true if the given object is an instance of Vcn.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Vcn {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Vcn.__pulumiType;
    }

    /**
     * **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
     */
    public readonly cidrBlock!: pulumi.Output<string>;
    /**
     * (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
     * * The CIDR blocks must be valid.
     * * They must not overlap with each other or with the on-premises network CIDR block.
     * * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidrBlocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidrBlock to be added must be placed at the end of the list. Once you migrate to using `cidrBlocks` from `cidrBlock`, you will not be able to switch back.
     * **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
     */
    public readonly cidrBlocks!: pulumi.Output<string[]>;
    /**
     * (Updatable) The OCID of the compartment to contain the VCN.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The OCID for the VCN's default set of DHCP options.
     */
    public /*out*/ readonly defaultDhcpOptionsId!: pulumi.Output<string>;
    /**
     * The OCID for the VCN's default route table.
     */
    public /*out*/ readonly defaultRouteTableId!: pulumi.Output<string>;
    /**
     * The OCID for the VCN's default security list.
     */
    public /*out*/ readonly defaultSecurityListId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
     */
    public readonly dnsLabel!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * For an IPv6-enabled VCN, this is the list of IPv6 CIDR blocks for the VCN's IP address space. The CIDRs are provided by Oracle and the sizes are always /56.
     */
    public /*out*/ readonly ipv6cidrBlocks!: pulumi.Output<string[]>;
    /**
     * Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
     */
    public readonly isIpv6enabled!: pulumi.Output<boolean>;
    /**
     * The VCN's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the VCN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The VCN's domain name, which consists of the VCN's DNS label, and the `oraclevcn.com` domain.
     */
    public /*out*/ readonly vcnDomainName!: pulumi.Output<string>;

    /**
     * Create a Vcn resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VcnArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VcnArgs | VcnState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VcnState | undefined;
            inputs["cidrBlock"] = state ? state.cidrBlock : undefined;
            inputs["cidrBlocks"] = state ? state.cidrBlocks : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["defaultDhcpOptionsId"] = state ? state.defaultDhcpOptionsId : undefined;
            inputs["defaultRouteTableId"] = state ? state.defaultRouteTableId : undefined;
            inputs["defaultSecurityListId"] = state ? state.defaultSecurityListId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["dnsLabel"] = state ? state.dnsLabel : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["ipv6cidrBlocks"] = state ? state.ipv6cidrBlocks : undefined;
            inputs["isIpv6enabled"] = state ? state.isIpv6enabled : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["vcnDomainName"] = state ? state.vcnDomainName : undefined;
        } else {
            const args = argsOrState as VcnArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            inputs["cidrBlock"] = args ? args.cidrBlock : undefined;
            inputs["cidrBlocks"] = args ? args.cidrBlocks : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["dnsLabel"] = args ? args.dnsLabel : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["isIpv6enabled"] = args ? args.isIpv6enabled : undefined;
            inputs["defaultDhcpOptionsId"] = undefined /*out*/;
            inputs["defaultRouteTableId"] = undefined /*out*/;
            inputs["defaultSecurityListId"] = undefined /*out*/;
            inputs["ipv6cidrBlocks"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["vcnDomainName"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Vcn.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Vcn resources.
 */
export interface VcnState {
    /**
     * **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
     */
    cidrBlock?: pulumi.Input<string>;
    /**
     * (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
     * * The CIDR blocks must be valid.
     * * They must not overlap with each other or with the on-premises network CIDR block.
     * * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidrBlocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidrBlock to be added must be placed at the end of the list. Once you migrate to using `cidrBlocks` from `cidrBlock`, you will not be able to switch back.
     * **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
     */
    cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The OCID of the compartment to contain the VCN.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The OCID for the VCN's default set of DHCP options.
     */
    defaultDhcpOptionsId?: pulumi.Input<string>;
    /**
     * The OCID for the VCN's default route table.
     */
    defaultRouteTableId?: pulumi.Input<string>;
    /**
     * The OCID for the VCN's default security list.
     */
    defaultSecurityListId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
     */
    dnsLabel?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * For an IPv6-enabled VCN, this is the list of IPv6 CIDR blocks for the VCN's IP address space. The CIDRs are provided by Oracle and the sizes are always /56.
     */
    ipv6cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
     */
    isIpv6enabled?: pulumi.Input<boolean>;
    /**
     * The VCN's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the VCN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The VCN's domain name, which consists of the VCN's DNS label, and the `oraclevcn.com` domain.
     */
    vcnDomainName?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Vcn resource.
 */
export interface VcnArgs {
    /**
     * **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
     */
    cidrBlock?: pulumi.Input<string>;
    /**
     * (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
     * * The CIDR blocks must be valid.
     * * They must not overlap with each other or with the on-premises network CIDR block.
     * * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidrBlocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidrBlock to be added must be placed at the end of the list. Once you migrate to using `cidrBlocks` from `cidrBlock`, you will not be able to switch back.
     * **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
     */
    cidrBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * (Updatable) The OCID of the compartment to contain the VCN.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
     */
    dnsLabel?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
     */
    isIpv6enabled?: pulumi.Input<boolean>;
}
