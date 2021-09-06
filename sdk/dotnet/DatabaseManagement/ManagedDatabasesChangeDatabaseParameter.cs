// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the Managed Databases Change Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Changes database parameter values. There are two kinds of database
    /// parameters:
    /// 
    /// - Dynamic parameters: They can be changed for the current Oracle
    ///   Database instance. The changes take effect immediately.
    /// - Static parameters: They cannot be changed for the current instance.
    ///   You must change these parameters and then restart the database before
    ///   changes take effect.
    /// 
    /// **Note:** If the instance is started using a text initialization
    /// parameter file, the parameter changes are applicable only for the
    /// current instance. You must update them manually to be passed to
    /// a future instance.
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
    ///         var testManagedDatabasesChangeDatabaseParameter = new Oci.DatabaseManagement.ManagedDatabasesChangeDatabaseParameter("testManagedDatabasesChangeDatabaseParameter", new Oci.DatabaseManagement.ManagedDatabasesChangeDatabaseParameterArgs
    ///         {
    ///             Credentials = new Oci.DatabaseManagement.Inputs.ManagedDatabasesChangeDatabaseParameterCredentialsArgs
    ///             {
    ///                 Password = @var.Managed_databases_change_database_parameter_credentials_password,
    ///                 Role = @var.Managed_databases_change_database_parameter_credentials_role,
    ///                 UserName = oci_identity_user.Test_user.Name,
    ///             },
    ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
    ///             Parameters = 
    ///             {
    ///                 new Oci.DatabaseManagement.Inputs.ManagedDatabasesChangeDatabaseParameterParameterArgs
    ///                 {
    ///                     Name = @var.Managed_databases_change_database_parameter_parameters_name,
    ///                     Value = @var.Managed_databases_change_database_parameter_parameters_value,
    ///                     UpdateComment = @var.Managed_databases_change_database_parameter_parameters_update_comment,
    ///                 },
    ///             },
    ///             Scope = @var.Managed_databases_change_database_parameter_scope,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:databasemanagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter")]
    public partial class ManagedDatabasesChangeDatabaseParameter : Pulumi.CustomResource
    {
        /// <summary>
        /// The database credentials used to perform management activity.
        /// </summary>
        [Output("credentials")]
        public Output<Outputs.ManagedDatabasesChangeDatabaseParameterCredentials> Credentials { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Output("managedDatabaseId")]
        public Output<string> ManagedDatabaseId { get; private set; } = null!;

        /// <summary>
        /// A list of database parameters and their values.
        /// </summary>
        [Output("parameters")]
        public Output<ImmutableArray<Outputs.ManagedDatabasesChangeDatabaseParameterParameter>> Parameters { get; private set; } = null!;

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// </summary>
        [Output("scope")]
        public Output<string> Scope { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedDatabasesChangeDatabaseParameter resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedDatabasesChangeDatabaseParameter(string name, ManagedDatabasesChangeDatabaseParameterArgs args, CustomResourceOptions? options = null)
            : base("oci:databasemanagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, args ?? new ManagedDatabasesChangeDatabaseParameterArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedDatabasesChangeDatabaseParameter(string name, Input<string> id, ManagedDatabasesChangeDatabaseParameterState? state = null, CustomResourceOptions? options = null)
            : base("oci:databasemanagement/managedDatabasesChangeDatabaseParameter:ManagedDatabasesChangeDatabaseParameter", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedDatabasesChangeDatabaseParameter resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedDatabasesChangeDatabaseParameter Get(string name, Input<string> id, ManagedDatabasesChangeDatabaseParameterState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedDatabasesChangeDatabaseParameter(name, id, state, options);
        }
    }

    public sealed class ManagedDatabasesChangeDatabaseParameterArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database credentials used to perform management activity.
        /// </summary>
        [Input("credentials", required: true)]
        public Input<Inputs.ManagedDatabasesChangeDatabaseParameterCredentialsArgs> Credentials { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        [Input("parameters", required: true)]
        private InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterArgs>? _parameters;

        /// <summary>
        /// A list of database parameters and their values.
        /// </summary>
        public InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterArgs> Parameters
        {
            get => _parameters ?? (_parameters = new InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterArgs>());
            set => _parameters = value;
        }

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// </summary>
        [Input("scope", required: true)]
        public Input<string> Scope { get; set; } = null!;

        public ManagedDatabasesChangeDatabaseParameterArgs()
        {
        }
    }

    public sealed class ManagedDatabasesChangeDatabaseParameterState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database credentials used to perform management activity.
        /// </summary>
        [Input("credentials")]
        public Input<Inputs.ManagedDatabasesChangeDatabaseParameterCredentialsGetArgs>? Credentials { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId")]
        public Input<string>? ManagedDatabaseId { get; set; }

        [Input("parameters")]
        private InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterGetArgs>? _parameters;

        /// <summary>
        /// A list of database parameters and their values.
        /// </summary>
        public InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterGetArgs> Parameters
        {
            get => _parameters ?? (_parameters = new InputList<Inputs.ManagedDatabasesChangeDatabaseParameterParameterGetArgs>());
            set => _parameters = value;
        }

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        public ManagedDatabasesChangeDatabaseParameterState()
        {
        }
    }
}
