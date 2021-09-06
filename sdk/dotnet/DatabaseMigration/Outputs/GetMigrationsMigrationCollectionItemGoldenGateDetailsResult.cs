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
    public sealed class GetMigrationsMigrationCollectionItemGoldenGateDetailsResult
    {
        /// <summary>
        /// Details about Oracle GoldenGate Microservices.
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsHubResult Hub;
        /// <summary>
        /// Optional settings for Oracle GoldenGate processes
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsResult Settings;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemGoldenGateDetailsResult(
            Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsHubResult hub,

            Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsSettingsResult settings)
        {
            Hub = hub;
            Settings = settings;
        }
    }
}
