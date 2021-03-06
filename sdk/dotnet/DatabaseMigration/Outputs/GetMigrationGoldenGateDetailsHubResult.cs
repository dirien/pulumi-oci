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
    public sealed class GetMigrationGoldenGateDetailsHubResult
    {
        /// <summary>
        /// OCID of Golden Gate compute instance.
        /// </summary>
        public readonly string ComputeId;
        /// <summary>
        /// Database Admin Credentials details.
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsHubRestAdminCredentialsResult RestAdminCredentials;
        /// <summary>
        /// Database Admin Credentials details.
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsHubSourceContainerDbAdminCredentialsResult SourceContainerDbAdminCredentials;
        /// <summary>
        /// Database Admin Credentials details.
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsHubSourceDbAdminCredentialsResult SourceDbAdminCredentials;
        /// <summary>
        /// Name of Microservices deployment to operate on source DB
        /// </summary>
        public readonly string SourceMicroservicesDeploymentName;
        /// <summary>
        /// Database Admin Credentials details.
        /// </summary>
        public readonly Outputs.GetMigrationGoldenGateDetailsHubTargetDbAdminCredentialsResult TargetDbAdminCredentials;
        /// <summary>
        /// Name of Microservices deployment to operate on target DB
        /// </summary>
        public readonly string TargetMicroservicesDeploymentName;
        /// <summary>
        /// Oracle GoldenGate hub's REST endpoint. Refer to https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/network.html#GUID-A709DA55-111D-455E-8942-C9BDD1E38CAA
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetMigrationGoldenGateDetailsHubResult(
            string computeId,

            Outputs.GetMigrationGoldenGateDetailsHubRestAdminCredentialsResult restAdminCredentials,

            Outputs.GetMigrationGoldenGateDetailsHubSourceContainerDbAdminCredentialsResult sourceContainerDbAdminCredentials,

            Outputs.GetMigrationGoldenGateDetailsHubSourceDbAdminCredentialsResult sourceDbAdminCredentials,

            string sourceMicroservicesDeploymentName,

            Outputs.GetMigrationGoldenGateDetailsHubTargetDbAdminCredentialsResult targetDbAdminCredentials,

            string targetMicroservicesDeploymentName,

            string url)
        {
            ComputeId = computeId;
            RestAdminCredentials = restAdminCredentials;
            SourceContainerDbAdminCredentials = sourceContainerDbAdminCredentials;
            SourceDbAdminCredentials = sourceDbAdminCredentials;
            SourceMicroservicesDeploymentName = sourceMicroservicesDeploymentName;
            TargetDbAdminCredentials = targetDbAdminCredentials;
            TargetMicroservicesDeploymentName = targetMicroservicesDeploymentName;
            Url = url;
        }
    }
}
