// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetExternalPluggableDatabase
    {
        /// <summary>
        /// This data source provides details about a specific External Pluggable Database resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about a specific
        /// [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testExternalPluggableDatabase = Output.Create(Oci.Database.GetExternalPluggableDatabase.InvokeAsync(new Oci.Database.GetExternalPluggableDatabaseArgs
        ///         {
        ///             ExternalPluggableDatabaseId = oci_database_external_pluggable_database.Test_external_pluggable_database.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetExternalPluggableDatabaseResult> InvokeAsync(GetExternalPluggableDatabaseArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetExternalPluggableDatabaseResult>("oci:database/getExternalPluggableDatabase:getExternalPluggableDatabase", args ?? new GetExternalPluggableDatabaseArgs(), options.WithVersion());
    }


    public sealed class GetExternalPluggableDatabaseArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("externalPluggableDatabaseId", required: true)]
        public string ExternalPluggableDatabaseId { get; set; } = null!;

        public GetExternalPluggableDatabaseArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetExternalPluggableDatabaseResult
    {
        /// <summary>
        /// The character set of the external database.
        /// </summary>
        public readonly string CharacterSet;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The Oracle Database configuration
        /// </summary>
        public readonly string DatabaseConfiguration;
        /// <summary>
        /// The Oracle Database edition.
        /// </summary>
        public readonly string DatabaseEdition;
        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        public readonly Outputs.GetExternalPluggableDatabaseDatabaseManagementConfigResult DatabaseManagementConfig;
        /// <summary>
        /// The Oracle Database version.
        /// </summary>
        public readonly string DatabaseVersion;
        /// <summary>
        /// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
        /// </summary>
        public readonly string DbId;
        /// <summary>
        /// The database packs licensed for the external Oracle Database.
        /// </summary>
        public readonly string DbPacks;
        /// <summary>
        /// The `DB_UNIQUE_NAME` of the external database.
        /// </summary>
        public readonly string DbUniqueName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name for the external database. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
        /// </summary>
        public readonly string ExternalContainerDatabaseId;
        public readonly string ExternalPluggableDatabaseId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure external database resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The national character of the external database.
        /// </summary>
        public readonly string NcharacterSet;
        /// <summary>
        /// The configuration of Operations Insights for the external database
        /// </summary>
        public readonly Outputs.GetExternalPluggableDatabaseOperationsInsightsConfigResult OperationsInsightsConfig;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
        /// </summary>
        public readonly string SourceId;
        /// <summary>
        /// The current state of the Oracle Cloud Infrastructure external database resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
        /// </summary>
        public readonly string TimeZone;

        [OutputConstructor]
        private GetExternalPluggableDatabaseResult(
            string characterSet,

            string compartmentId,

            string databaseConfiguration,

            string databaseEdition,

            Outputs.GetExternalPluggableDatabaseDatabaseManagementConfigResult databaseManagementConfig,

            string databaseVersion,

            string dbId,

            string dbPacks,

            string dbUniqueName,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string externalContainerDatabaseId,

            string externalPluggableDatabaseId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string ncharacterSet,

            Outputs.GetExternalPluggableDatabaseOperationsInsightsConfigResult operationsInsightsConfig,

            string sourceId,

            string state,

            string timeCreated,

            string timeZone)
        {
            CharacterSet = characterSet;
            CompartmentId = compartmentId;
            DatabaseConfiguration = databaseConfiguration;
            DatabaseEdition = databaseEdition;
            DatabaseManagementConfig = databaseManagementConfig;
            DatabaseVersion = databaseVersion;
            DbId = dbId;
            DbPacks = dbPacks;
            DbUniqueName = dbUniqueName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalContainerDatabaseId = externalContainerDatabaseId;
            ExternalPluggableDatabaseId = externalPluggableDatabaseId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NcharacterSet = ncharacterSet;
            OperationsInsightsConfig = operationsInsightsConfig;
            SourceId = sourceId;
            State = state;
            TimeCreated = timeCreated;
            TimeZone = timeZone;
        }
    }
}
