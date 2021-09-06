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
    public sealed class DbSystemIormConfigCacheDbPlan
    {
        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        public readonly string? DbName;
        /// <summary>
        /// The flash cache limit for this database. This value is internally configured based on the share value assigned to the database.
        /// </summary>
        public readonly string? FlashCacheLimit;
        /// <summary>
        /// The relative priority of this database.
        /// </summary>
        public readonly int? Share;

        [OutputConstructor]
        private DbSystemIormConfigCacheDbPlan(
            string? dbName,

            string? flashCacheLimit,

            int? share)
        {
            DbName = dbName;
            FlashCacheLimit = flashCacheLimit;
            Share = share;
        }
    }
}
