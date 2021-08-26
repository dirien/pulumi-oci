// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Inputs
{

    public sealed class ServiceConnectorSourceGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of [cursor](https://docs.cloud.oracle.com/iaas/Content/Streaming/Tasks/using_a_single_consumer.htm#usingcursors), which determines the starting point from which the stream will be consumed.
        /// </summary>
        [Input("cursor")]
        public Input<Inputs.ServiceConnectorSourceCursorGetArgs>? Cursor { get; set; }

        /// <summary>
        /// (Updatable) The type descriminator.
        /// </summary>
        [Input("kind", required: true)]
        public Input<string> Kind { get; set; } = null!;

        [Input("logSources")]
        private InputList<Inputs.ServiceConnectorSourceLogSourceGetArgs>? _logSources;

        /// <summary>
        /// (Updatable) The resources affected by this work request.
        /// </summary>
        public InputList<Inputs.ServiceConnectorSourceLogSourceGetArgs> LogSources
        {
            get => _logSources ?? (_logSources = new InputList<Inputs.ServiceConnectorSourceLogSourceGetArgs>());
            set => _logSources = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
        /// </summary>
        [Input("streamId")]
        public Input<string>? StreamId { get; set; }

        public ServiceConnectorSourceGetArgs()
        {
        }
    }
}
