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
    public sealed class GetExternalNonContainerDatabaseDatabaseManagementConfigResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        public readonly string DatabaseManagementConnectionId;
        /// <summary>
        /// The status of the Database Management service.
        /// </summary>
        public readonly string DatabaseManagementStatus;
        /// <summary>
        /// The Oracle license model that applies to the external database.
        /// </summary>
        public readonly string LicenseModel;

        [OutputConstructor]
        private GetExternalNonContainerDatabaseDatabaseManagementConfigResult(
            string databaseManagementConnectionId,

            string databaseManagementStatus,

            string licenseModel)
        {
            DatabaseManagementConnectionId = databaseManagementConnectionId;
            DatabaseManagementStatus = databaseManagementStatus;
            LicenseModel = licenseModel;
        }
    }
}
