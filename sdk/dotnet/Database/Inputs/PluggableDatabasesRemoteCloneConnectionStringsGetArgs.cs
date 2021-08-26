// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class PluggableDatabasesRemoteCloneConnectionStringsGetArgs : Pulumi.ResourceArgs
    {
        [Input("allConnectionStrings")]
        private InputMap<object>? _allConnectionStrings;

        /// <summary>
        /// All connection strings to use to connect to the pluggable database.
        /// </summary>
        public InputMap<object> AllConnectionStrings
        {
            get => _allConnectionStrings ?? (_allConnectionStrings = new InputMap<object>());
            set => _allConnectionStrings = value;
        }

        /// <summary>
        /// A host name-based PDB connection string.
        /// </summary>
        [Input("pdbDefault")]
        public Input<string>? PdbDefault { get; set; }

        /// <summary>
        /// An IP-based PDB connection string.
        /// </summary>
        [Input("pdbIpDefault")]
        public Input<string>? PdbIpDefault { get; set; }

        public PluggableDatabasesRemoteCloneConnectionStringsGetArgs()
        {
        }
    }
}
