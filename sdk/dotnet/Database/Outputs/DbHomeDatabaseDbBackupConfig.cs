// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class DbHomeDatabaseDbBackupConfig
    {
        /// <summary>
        /// (Updatable) If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
        /// </summary>
        public readonly bool? AutoBackupEnabled;
        /// <summary>
        /// (Updatable) Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
        /// </summary>
        public readonly string? AutoBackupWindow;
        /// <summary>
        /// Backup destination details.
        /// </summary>
        public readonly ImmutableArray<Outputs.DbHomeDatabaseDbBackupConfigBackupDestinationDetail> BackupDestinationDetails;
        /// <summary>
        /// (Updatable) Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
        /// </summary>
        public readonly int? RecoveryWindowInDays;

        [OutputConstructor]
        private DbHomeDatabaseDbBackupConfig(
            bool? autoBackupEnabled,

            string? autoBackupWindow,

            ImmutableArray<Outputs.DbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails,

            int? recoveryWindowInDays)
        {
            AutoBackupEnabled = autoBackupEnabled;
            AutoBackupWindow = autoBackupWindow;
            BackupDestinationDetails = backupDestinationDetails;
            RecoveryWindowInDays = recoveryWindowInDays;
        }
    }
}
