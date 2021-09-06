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
    public sealed class GetDbHomeDatabaseDbBackupConfigResult
    {
        public readonly bool AutoBackupEnabled;
        public readonly string AutoBackupWindow;
        public readonly ImmutableArray<Outputs.GetDbHomeDatabaseDbBackupConfigBackupDestinationDetailResult> BackupDestinationDetails;
        public readonly int RecoveryWindowInDays;

        [OutputConstructor]
        private GetDbHomeDatabaseDbBackupConfigResult(
            bool autoBackupEnabled,

            string autoBackupWindow,

            ImmutableArray<Outputs.GetDbHomeDatabaseDbBackupConfigBackupDestinationDetailResult> backupDestinationDetails,

            int recoveryWindowInDays)
        {
            AutoBackupEnabled = autoBackupEnabled;
            AutoBackupWindow = autoBackupWindow;
            BackupDestinationDetails = backupDestinationDetails;
            RecoveryWindowInDays = recoveryWindowInDays;
        }
    }
}
