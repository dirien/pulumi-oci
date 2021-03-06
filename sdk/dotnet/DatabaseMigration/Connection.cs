// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration
{
    /// <summary>
    /// This resource provides the Connection resource in Oracle Cloud Infrastructure Database Migration service.
    /// 
    /// Create a Database Connection resource that contains the details to connect to either a Source or Target Database
    /// in the migration.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testConnection = new Oci.DatabaseMigration.Connection("testConnection", new Oci.DatabaseMigration.ConnectionArgs
    ///         {
    ///             AdminCredentials = new Oci.DatabaseMigration.Inputs.ConnectionAdminCredentialsArgs
    ///             {
    ///                 Password = @var.Connection_admin_credentials_password,
    ///                 Username = @var.Connection_admin_credentials_username,
    ///             },
    ///             CompartmentId = @var.Compartment_id,
    ///             DatabaseType = @var.Connection_database_type,
    ///             VaultDetails = new Oci.DatabaseMigration.Inputs.ConnectionVaultDetailsArgs
    ///             {
    ///                 CompartmentId = @var.Compartment_id,
    ///                 KeyId = oci_kms_key.Test_key.Id,
    ///                 VaultId = oci_kms_vault.Test_vault.Id,
    ///             },
    ///             CertificateTdn = @var.Connection_certificate_tdn,
    ///             ConnectDescriptor = new Oci.DatabaseMigration.Inputs.ConnectionConnectDescriptorArgs
    ///             {
    ///                 ConnectString = @var.Connection_connect_descriptor_connect_string,
    ///                 DatabaseServiceName = oci_core_service.Test_service.Name,
    ///                 Host = @var.Connection_connect_descriptor_host,
    ///                 Port = @var.Connection_connect_descriptor_port,
    ///             },
    ///             DatabaseId = oci_database_database.Test_database.Id,
    ///             DefinedTags = 
    ///             {
    ///                 { "foo-namespace.bar-key", "value" },
    ///             },
    ///             DisplayName = @var.Connection_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "bar-key", "value" },
    ///             },
    ///             PrivateEndpoint = new Oci.DatabaseMigration.Inputs.ConnectionPrivateEndpointArgs
    ///             {
    ///                 CompartmentId = @var.Compartment_id,
    ///                 SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                 VcnId = oci_core_vcn.Test_vcn.Id,
    ///             },
    ///             SshDetails = new Oci.DatabaseMigration.Inputs.ConnectionSshDetailsArgs
    ///             {
    ///                 Host = @var.Connection_ssh_details_host,
    ///                 Sshkey = @var.Connection_ssh_details_sshkey,
    ///                 User = @var.Connection_ssh_details_user,
    ///                 SudoLocation = @var.Connection_ssh_details_sudo_location,
    ///             },
    ///             TlsKeystore = @var.Connection_tls_keystore,
    ///             TlsWallet = @var.Connection_tls_wallet,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Connections can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:databasemigration/connection:Connection test_connection "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:databasemigration/connection:Connection")]
    public partial class Connection : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Database Admin Credentials details.
        /// </summary>
        [Output("adminCredentials")]
        public Output<Outputs.ConnectionAdminCredentials> AdminCredentials { get; private set; } = null!;

        /// <summary>
        /// (Updatable) This name is the distinguished name used while creating the certificate on target database. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Output("certificateTdn")]
        public Output<string> CertificateTdn { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Connect Descriptor details. Required for Manual and UserManagerOci connection types. If a Private Endpoint was specified for the Connection, the host should contain a valid IP address.
        /// </summary>
        [Output("connectDescriptor")]
        public Output<Outputs.ConnectionConnectDescriptor> ConnectDescriptor { get; private set; } = null!;

        /// <summary>
        /// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Database Connection credentials.
        /// </summary>
        [Output("credentialsSecretId")]
        public Output<string> CredentialsSecretId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the cloud database. Required if the database connection type is Autonomous.
        /// </summary>
        [Output("databaseId")]
        public Output<string> DatabaseId { get; private set; } = null!;

        /// <summary>
        /// Database connection type.
        /// </summary>
        [Output("databaseType")]
        public Output<string> DatabaseType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Database Connection display name identifier.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Private Endpoint configuration details. Not required for source container database connections, it will default to the specified Source Database Connection Private Endpoint.
        /// </summary>
        [Output("privateEndpoint")]
        public Output<Outputs.ConnectionPrivateEndpoint> PrivateEndpoint { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details of the ssh key that will be used. Required for source database Manual and UserManagerOci connection types. Not required for source container database connections.
        /// </summary>
        [Output("sshDetails")]
        public Output<Outputs.ConnectionSshDetails> SshDetails { get; private set; } = null!;

        /// <summary>
        /// The current state of the Connection resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the Connection resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time of the last Connection resource details update. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) keystore.jks file contents; base64 encoded String. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Output("tlsKeystore")]
        public Output<string> TlsKeystore { get; private set; } = null!;

        /// <summary>
        /// (Updatable) cwallet.sso containing containing the TCPS/SSL certificate; base64 encoded String. Not required for source container database connections.
        /// </summary>
        [Output("tlsWallet")]
        public Output<string> TlsWallet { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        /// </summary>
        [Output("vaultDetails")]
        public Output<Outputs.ConnectionVaultDetails> VaultDetails { get; private set; } = null!;


        /// <summary>
        /// Create a Connection resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Connection(string name, ConnectionArgs args, CustomResourceOptions? options = null)
            : base("oci:databasemigration/connection:Connection", name, args ?? new ConnectionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Connection(string name, Input<string> id, ConnectionState? state = null, CustomResourceOptions? options = null)
            : base("oci:databasemigration/connection:Connection", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Connection resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Connection Get(string name, Input<string> id, ConnectionState? state = null, CustomResourceOptions? options = null)
        {
            return new Connection(name, id, state, options);
        }
    }

    public sealed class ConnectionArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Database Admin Credentials details.
        /// </summary>
        [Input("adminCredentials", required: true)]
        public Input<Inputs.ConnectionAdminCredentialsArgs> AdminCredentials { get; set; } = null!;

        /// <summary>
        /// (Updatable) This name is the distinguished name used while creating the certificate on target database. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Input("certificateTdn")]
        public Input<string>? CertificateTdn { get; set; }

        /// <summary>
        /// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Connect Descriptor details. Required for Manual and UserManagerOci connection types. If a Private Endpoint was specified for the Connection, the host should contain a valid IP address.
        /// </summary>
        [Input("connectDescriptor")]
        public Input<Inputs.ConnectionConnectDescriptorArgs>? ConnectDescriptor { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the cloud database. Required if the database connection type is Autonomous.
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        /// <summary>
        /// Database connection type.
        /// </summary>
        [Input("databaseType", required: true)]
        public Input<string> DatabaseType { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Database Connection display name identifier.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Private Endpoint configuration details. Not required for source container database connections, it will default to the specified Source Database Connection Private Endpoint.
        /// </summary>
        [Input("privateEndpoint")]
        public Input<Inputs.ConnectionPrivateEndpointArgs>? PrivateEndpoint { get; set; }

        /// <summary>
        /// (Updatable) Details of the ssh key that will be used. Required for source database Manual and UserManagerOci connection types. Not required for source container database connections.
        /// </summary>
        [Input("sshDetails")]
        public Input<Inputs.ConnectionSshDetailsArgs>? SshDetails { get; set; }

        /// <summary>
        /// (Updatable) keystore.jks file contents; base64 encoded String. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Input("tlsKeystore")]
        public Input<string>? TlsKeystore { get; set; }

        /// <summary>
        /// (Updatable) cwallet.sso containing containing the TCPS/SSL certificate; base64 encoded String. Not required for source container database connections.
        /// </summary>
        [Input("tlsWallet")]
        public Input<string>? TlsWallet { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        /// </summary>
        [Input("vaultDetails", required: true)]
        public Input<Inputs.ConnectionVaultDetailsArgs> VaultDetails { get; set; } = null!;

        public ConnectionArgs()
        {
        }
    }

    public sealed class ConnectionState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Database Admin Credentials details.
        /// </summary>
        [Input("adminCredentials")]
        public Input<Inputs.ConnectionAdminCredentialsGetArgs>? AdminCredentials { get; set; }

        /// <summary>
        /// (Updatable) This name is the distinguished name used while creating the certificate on target database. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Input("certificateTdn")]
        public Input<string>? CertificateTdn { get; set; }

        /// <summary>
        /// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Connect Descriptor details. Required for Manual and UserManagerOci connection types. If a Private Endpoint was specified for the Connection, the host should contain a valid IP address.
        /// </summary>
        [Input("connectDescriptor")]
        public Input<Inputs.ConnectionConnectDescriptorGetArgs>? ConnectDescriptor { get; set; }

        /// <summary>
        /// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Database Connection credentials.
        /// </summary>
        [Input("credentialsSecretId")]
        public Input<string>? CredentialsSecretId { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the cloud database. Required if the database connection type is Autonomous.
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        /// <summary>
        /// Database connection type.
        /// </summary>
        [Input("databaseType")]
        public Input<string>? DatabaseType { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Database Connection display name identifier.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Private Endpoint configuration details. Not required for source container database connections, it will default to the specified Source Database Connection Private Endpoint.
        /// </summary>
        [Input("privateEndpoint")]
        public Input<Inputs.ConnectionPrivateEndpointGetArgs>? PrivateEndpoint { get; set; }

        /// <summary>
        /// (Updatable) Details of the ssh key that will be used. Required for source database Manual and UserManagerOci connection types. Not required for source container database connections.
        /// </summary>
        [Input("sshDetails")]
        public Input<Inputs.ConnectionSshDetailsGetArgs>? SshDetails { get; set; }

        /// <summary>
        /// The current state of the Connection resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the Connection resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time of the last Connection resource details update. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// (Updatable) keystore.jks file contents; base64 encoded String. Requires a TLS wallet to be specified. Not required for source container database connections.
        /// </summary>
        [Input("tlsKeystore")]
        public Input<string>? TlsKeystore { get; set; }

        /// <summary>
        /// (Updatable) cwallet.sso containing containing the TCPS/SSL certificate; base64 encoded String. Not required for source container database connections.
        /// </summary>
        [Input("tlsWallet")]
        public Input<string>? TlsWallet { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        /// </summary>
        [Input("vaultDetails")]
        public Input<Inputs.ConnectionVaultDetailsGetArgs>? VaultDetails { get; set; }

        public ConnectionState()
        {
        }
    }
}
