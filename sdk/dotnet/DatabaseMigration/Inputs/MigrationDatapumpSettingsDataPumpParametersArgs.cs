// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationDatapumpSettingsDataPumpParametersArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Estimate size of dumps that will be generated.
        /// </summary>
        [Input("estimate")]
        public Input<string>? Estimate { get; set; }

        [Input("excludeParameters")]
        private InputList<string>? _excludeParameters;

        /// <summary>
        /// (Updatable) Exclude paratemers for export and import.
        /// </summary>
        public InputList<string> ExcludeParameters
        {
            get => _excludeParameters ?? (_excludeParameters = new InputList<string>());
            set => _excludeParameters = value;
        }

        /// <summary>
        /// (Updatable) Maximum number of worker processes that can be used for a Datapump Export job.
        /// </summary>
        [Input("exportParallelismDegree")]
        public Input<int>? ExportParallelismDegree { get; set; }

        /// <summary>
        /// (Updatable) Maximum number of worker processes that can be used for a Datapump Import job. For an Autonomous Database, ODMS will automatically query its CPU core count and set this property.
        /// </summary>
        [Input("importParallelismDegree")]
        public Input<int>? ImportParallelismDegree { get; set; }

        /// <summary>
        /// (Updatable) False to force datapump worker process to run on one instance.
        /// </summary>
        [Input("isCluster")]
        public Input<bool>? IsCluster { get; set; }

        /// <summary>
        /// (Updatable) IMPORT: Specifies the action to be performed when data is loaded into a preexisting table.
        /// </summary>
        [Input("tableExistsAction")]
        public Input<string>? TableExistsAction { get; set; }

        public MigrationDatapumpSettingsDataPumpParametersArgs()
        {
        }
    }
}
