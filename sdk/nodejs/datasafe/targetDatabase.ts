// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Target Database resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Registers the specified database with Data Safe and creates a Data Safe target database in the Data Safe Console.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTargetDatabase = new oci.datasafe.TargetDatabase("testTargetDatabase", {
 *     compartmentId: _var.compartment_id,
 *     databaseDetails: {
 *         databaseType: _var.target_database_database_details_database_type,
 *         infrastructureType: _var.target_database_database_details_infrastructure_type,
 *         autonomousDatabaseId: oci_database_autonomous_database.test_autonomous_database.id,
 *         dbSystemId: oci_database_db_system.test_db_system.id,
 *         instanceId: oci_core_instance.test_instance.id,
 *         ipAddresses: _var.target_database_database_details_ip_addresses,
 *         listenerPort: _var.target_database_database_details_listener_port,
 *         serviceName: oci_core_service.test_service.name,
 *         vmClusterId: oci_database_vm_cluster.test_vm_cluster.id,
 *     },
 *     connectionOption: {
 *         connectionType: _var.target_database_connection_option_connection_type,
 *         datasafePrivateEndpointId: oci_dataflow_private_endpoint.test_private_endpoint.id,
 *         onPremConnectorId: oci_data_safe_on_prem_connector.test_on_prem_connector.id,
 *     },
 *     credentials: {
 *         password: _var.target_database_credentials_password,
 *         userName: oci_identity_user.test_user.name,
 *     },
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.target_database_description,
 *     displayName: _var.target_database_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     tlsConfig: {
 *         status: _var.target_database_tls_config_status,
 *         certificateStoreType: _var.target_database_tls_config_certificate_store_type,
 *         keyStoreContent: _var.target_database_tls_config_key_store_content,
 *         storePassword: _var.target_database_tls_config_store_password,
 *         trustStoreContent: _var.target_database_tls_config_trust_store_content,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * TargetDatabases can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:datasafe/targetDatabase:TargetDatabase test_target_database "id"
 * ```
 */
export class TargetDatabase extends pulumi.CustomResource {
    /**
     * Get an existing TargetDatabase resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: TargetDatabaseState, opts?: pulumi.CustomResourceOptions): TargetDatabase {
        return new TargetDatabase(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:datasafe/targetDatabase:TargetDatabase';

    /**
     * Returns true if the given object is an instance of TargetDatabase.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is TargetDatabase {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === TargetDatabase.__pulumiType;
    }

    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    public readonly connectionOption!: pulumi.Output<outputs.datasafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    public readonly credentials!: pulumi.Output<outputs.datasafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe. To choose applicable database type and infrastructure type refer to  https://confluence.oci.oraclecorp.com/display/DATASAFE/Target+V2+Design
     */
    public readonly databaseDetails!: pulumi.Output<outputs.datasafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Details about the current state of the target database in Data Safe.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The current state of the target database in Data Safe.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time of the target database update in Data Safe.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    public readonly tlsConfig!: pulumi.Output<outputs.datasafe.TargetDatabaseTlsConfig>;

    /**
     * Create a TargetDatabase resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: TargetDatabaseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: TargetDatabaseArgs | TargetDatabaseState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as TargetDatabaseState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["connectionOption"] = state ? state.connectionOption : undefined;
            inputs["credentials"] = state ? state.credentials : undefined;
            inputs["databaseDetails"] = state ? state.databaseDetails : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["systemTags"] = state ? state.systemTags : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            inputs["tlsConfig"] = state ? state.tlsConfig : undefined;
        } else {
            const args = argsOrState as TargetDatabaseArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.databaseDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'databaseDetails'");
            }
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["connectionOption"] = args ? args.connectionOption : undefined;
            inputs["credentials"] = args ? args.credentials : undefined;
            inputs["databaseDetails"] = args ? args.databaseDetails : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["tlsConfig"] = args ? args.tlsConfig : undefined;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["systemTags"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(TargetDatabase.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering TargetDatabase resources.
 */
export interface TargetDatabaseState {
    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    connectionOption?: pulumi.Input<inputs.datasafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    credentials?: pulumi.Input<inputs.datasafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe. To choose applicable database type and infrastructure type refer to  https://confluence.oci.oraclecorp.com/display/DATASAFE/Target+V2+Design
     */
    databaseDetails?: pulumi.Input<inputs.datasafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Details about the current state of the target database in Data Safe.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The current state of the target database in Data Safe.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The date and time the database was registered in Data Safe and created as a target database in Data Safe.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time of the target database update in Data Safe.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    tlsConfig?: pulumi.Input<inputs.datasafe.TargetDatabaseTlsConfig>;
}

/**
 * The set of arguments for constructing a TargetDatabase resource.
 */
export interface TargetDatabaseArgs {
    /**
     * (Updatable) The OCID of the compartment in which to create the Data Safe target database.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Types of connection supported by Data Safe.
     */
    connectionOption?: pulumi.Input<inputs.datasafe.TargetDatabaseConnectionOption>;
    /**
     * (Updatable) The database credentials required for Data Safe to connect to the database.
     */
    credentials?: pulumi.Input<inputs.datasafe.TargetDatabaseCredentials>;
    /**
     * (Updatable) Details of the database for the registration in Data Safe. To choose applicable database type and infrastructure type refer to  https://confluence.oci.oraclecorp.com/display/DATASAFE/Target+V2+Design
     */
    databaseDetails: pulumi.Input<inputs.datasafe.TargetDatabaseDatabaseDetails>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the target database in Data Safe.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The display name of the target database in Data Safe. The name is modifiable and does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The details required to establish a TLS enabled connection.
     */
    tlsConfig?: pulumi.Input<inputs.datasafe.TargetDatabaseTlsConfig>;
}
