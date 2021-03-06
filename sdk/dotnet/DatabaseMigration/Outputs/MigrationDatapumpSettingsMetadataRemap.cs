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
    public sealed class MigrationDatapumpSettingsMetadataRemap
    {
        /// <summary>
        /// (Updatable) Specifies the new value that oldValue should be translated into.
        /// </summary>
        public readonly string NewValue;
        /// <summary>
        /// (Updatable) Specifies the value which needs to be reset.
        /// </summary>
        public readonly string OldValue;
        /// <summary>
        /// (Updatable) Migration type.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private MigrationDatapumpSettingsMetadataRemap(
            string newValue,

            string oldValue,

            string type)
        {
            NewValue = newValue;
            OldValue = oldValue;
            Type = type;
        }
    }
}
