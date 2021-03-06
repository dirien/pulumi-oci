// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDatabaseUpgradeHistoryEntry
    {
        /// <summary>
        /// This data source provides details about a specific Database Upgrade History Entry resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// gets the upgrade history for a specified database.
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
        ///         var testDatabaseUpgradeHistoryEntry = Output.Create(Oci.Database.GetDatabaseUpgradeHistoryEntry.InvokeAsync(new Oci.Database.GetDatabaseUpgradeHistoryEntryArgs
        ///         {
        ///             DatabaseId = oci_database_database.Test_database.Id,
        ///             UpgradeHistoryEntryId = oci_database_upgrade_history_entry.Test_upgrade_history_entry.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDatabaseUpgradeHistoryEntryResult> InvokeAsync(GetDatabaseUpgradeHistoryEntryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDatabaseUpgradeHistoryEntryResult>("oci:database/getDatabaseUpgradeHistoryEntry:getDatabaseUpgradeHistoryEntry", args ?? new GetDatabaseUpgradeHistoryEntryArgs(), options.WithVersion());
    }


    public sealed class GetDatabaseUpgradeHistoryEntryArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public string DatabaseId { get; set; } = null!;

        /// <summary>
        /// The database upgrade History [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("upgradeHistoryEntryId", required: true)]
        public string UpgradeHistoryEntryId { get; set; } = null!;

        public GetDatabaseUpgradeHistoryEntryArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDatabaseUpgradeHistoryEntryResult
    {
        /// <summary>
        /// The database upgrade action.
        /// </summary>
        public readonly string Action;
        public readonly string DatabaseId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: "-upgradeTimezone false -keepEvents"
        /// </summary>
        public readonly string Options;
        /// <summary>
        /// The source of the Oracle Database software to be used for the upgrade.
        /// * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
        /// * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
        /// </summary>
        public readonly string Source;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        public readonly string SourceDbHomeId;
        /// <summary>
        /// Status of database upgrade history SUCCEEDED|IN_PROGRESS|FAILED.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// the database software image used for upgrading database.
        /// </summary>
        public readonly string TargetDatabaseSoftwareImageId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        public readonly string TargetDbHomeId;
        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        public readonly string TargetDbVersion;
        /// <summary>
        /// The date and time when the database upgrade ended.
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// The date and time when the database upgrade started.
        /// </summary>
        public readonly string TimeStarted;
        public readonly string UpgradeHistoryEntryId;

        [OutputConstructor]
        private GetDatabaseUpgradeHistoryEntryResult(
            string action,

            string databaseId,

            string id,

            string lifecycleDetails,

            string options,

            string source,

            string sourceDbHomeId,

            string state,

            string targetDatabaseSoftwareImageId,

            string targetDbHomeId,

            string targetDbVersion,

            string timeEnded,

            string timeStarted,

            string upgradeHistoryEntryId)
        {
            Action = action;
            DatabaseId = databaseId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Options = options;
            Source = source;
            SourceDbHomeId = sourceDbHomeId;
            State = state;
            TargetDatabaseSoftwareImageId = targetDatabaseSoftwareImageId;
            TargetDbHomeId = targetDbHomeId;
            TargetDbVersion = targetDbVersion;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            UpgradeHistoryEntryId = upgradeHistoryEntryId;
        }
    }
}
