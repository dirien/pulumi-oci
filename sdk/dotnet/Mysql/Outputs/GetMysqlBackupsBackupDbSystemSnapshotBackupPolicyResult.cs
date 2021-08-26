// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyResult
    {
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// If automated backups are enabled or disabled.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// Number of days to retain this backup.
        /// </summary>
        public readonly int RetentionInDays;
        /// <summary>
        /// The start time of the maintenance window.
        /// </summary>
        public readonly string WindowStartTime;

        [OutputConstructor]
        private GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyResult(
            ImmutableDictionary<string, object> definedTags,

            ImmutableDictionary<string, object> freeformTags,

            bool isEnabled,

            int retentionInDays,

            string windowStartTime)
        {
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            IsEnabled = isEnabled;
            RetentionInDays = retentionInDays;
            WindowStartTime = windowStartTime;
        }
    }
}
