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
    public sealed class GetMigrationsMigrationCollectionItemDatapumpSettingsImportDirectoryObjectResult
    {
        /// <summary>
        /// Name of directory object in database
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Absolute path of directory on database server
        /// </summary>
        public readonly string Path;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemDatapumpSettingsImportDirectoryObjectResult(
            string name,

            string path)
        {
            Name = name;
            Path = path;
        }
    }
}
