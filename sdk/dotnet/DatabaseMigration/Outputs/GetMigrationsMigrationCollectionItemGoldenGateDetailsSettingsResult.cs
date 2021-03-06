// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsResult
    {
        /// <summary>
        /// ODMS will monitor GoldenGate end-to-end latency until the lag time is lower than the specified value in seconds.
        /// </summary>
        public readonly int AcceptableLag;
        /// <summary>
        /// Parameters for Extract processes.
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsExtractResult Extract;
        /// <summary>
        /// Parameters for Replicat processes.
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsReplicatResult Replicat;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsResult(
            int acceptableLag,

            Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsExtractResult extract,

            Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsReplicatResult replicat)
        {
            AcceptableLag = acceptableLag;
            Extract = extract;
            Replicat = replicat;
        }
    }
}
