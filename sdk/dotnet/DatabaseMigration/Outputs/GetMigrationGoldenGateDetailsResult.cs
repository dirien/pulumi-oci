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
    public sealed class GetMigrationGoldenGateDetailsResult
    {
        /// <summary>
        /// Details about Oracle GoldenGate Microservices.
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsHubResult Hub;
        /// <summary>
        /// Optional settings for Oracle GoldenGate processes
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsSettingsResult Settings;

        [OutputConstructor]
        private GetMigrationGoldenGateDetailsResult(
            Outputs.GetMigrationGoldenGateDetailsHubResult hub,

            Outputs.GetMigrationGoldenGateDetailsSettingsResult settings)
        {
            Hub = hub;
            Settings = settings;
        }
    }
}