// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow
{
    public static class GetApplication
    {
        /// <summary>
        /// This data source provides details about a specific Application resource in Oracle Cloud Infrastructure Data Flow service.
        /// 
        /// Retrieves an application using an `applicationId`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testApplication = Output.Create(Oci.DataFlow.GetApplication.InvokeAsync(new Oci.DataFlow.GetApplicationArgs
        ///         {
        ///             ApplicationId = oci_dataflow_application.Test_application.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetApplicationResult> InvokeAsync(GetApplicationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetApplicationResult>("oci:dataflow/getApplication:getApplication", args ?? new GetApplicationArgs(), options.WithVersion());
    }


    public sealed class GetApplicationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique ID for an application.
        /// </summary>
        [Input("applicationId", required: true)]
        public string ApplicationId { get; set; } = null!;

        public GetApplicationArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetApplicationResult
    {
        public readonly string ApplicationId;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of an archive.zip file containing custom dependencies that may be used to support the execution a Python, Java, or Scala application. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string ArchiveUri;
        /// <summary>
        /// The arguments passed to the running application as command line arguments.  An argument is either a plain text or a placeholder. Placeholders are replaced using values from the parameters map.  Each placeholder specified must be represented in the parameters map else the request (POST or PUT) will fail with a HTTP 400 status code.  Placeholders are specified as `Service Api Spec`, where `name` is the name of the parameter. Example:  `[ "--input", "${input_file}", "--name", "John Doe" ]` If "input_file" has a value of "mydata.xml", then the value above will be translated to `--input mydata.xml --name "John Doe"`
        /// </summary>
        public readonly ImmutableArray<string> Arguments;
        /// <summary>
        /// The class for the application.
        /// </summary>
        public readonly string ClassName;
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { "spark.app.name" : "My App Name", "spark.shuffle.io.maxRetries" : "4" } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Configuration;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. This name is not necessarily unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The VM shape for the driver. Sets the driver cores and memory.
        /// </summary>
        public readonly string DriverShape;
        /// <summary>
        /// The input used for spark-submit command. For more details see https://spark.apache.org/docs/latest/submitting-applications.html#launching-applications-with-spark-submit. Supported options include ``--class``, ``--file``, ``--jars``, ``--conf``, ``--py-files``, and main application file with arguments. Example: ``--jars oci://path/to/a.jar,oci://path/to/b.jar --files oci://path/to/a.json,oci://path/to/b.csv --py-files oci://path/to/a.py,oci://path/to/b.py --conf spark.sql.crossJoin.enabled=true --class org.apache.spark.examples.SparkPi oci://path/to/main.jar 10`` Note: If execute is specified together with applicationId, className, configuration, fileUri, language, arguments, parameters during application create/update, or run create/submit, Data Flow service will use derived information from execute input only.
        /// </summary>
        public readonly string Execute;
        /// <summary>
        /// The VM shape for the executors. Sets the executor cores and memory.
        /// </summary>
        public readonly string ExecutorShape;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the file containing the application to execute. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string FileUri;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The application ID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The Spark language.
        /// </summary>
        public readonly string Language;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the bucket where the Spark job logs are to be uploaded. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string LogsBucketUri;
        /// <summary>
        /// The OCID of Oracle Cloud Infrastructure Hive Metastore.
        /// </summary>
        public readonly string MetastoreId;
        /// <summary>
        /// The number of executor VMs requested.
        /// </summary>
        public readonly int NumExecutors;
        /// <summary>
        /// The OCID of the user who created the resource.
        /// </summary>
        public readonly string OwnerPrincipalId;
        /// <summary>
        /// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
        /// </summary>
        public readonly string OwnerUserName;
        /// <summary>
        /// An array of name/value pairs used to fill placeholders found in properties like `Application.arguments`.  The name must be a string of one or more word characters (a-z, A-Z, 0-9, _).  The value can be a string of 0 or more characters of any kind. Example:  [ { name: "iterations", value: "10"}, { name: "input_file", value: "mydata.xml" }, { name: "variable_x", value: "${x}"} ]
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApplicationParameterResult> Parameters;
        /// <summary>
        /// The OCID of a private endpoint.
        /// </summary>
        public readonly string PrivateEndpointId;
        /// <summary>
        /// The Spark version utilized to run the application.
        /// </summary>
        public readonly string SparkVersion;
        /// <summary>
        /// The current state of this application.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// An Oracle Cloud Infrastructure URI of the bucket to be used as default warehouse directory for BATCH SQL runs. See https://docs.cloud.oracle.com/iaas/Content/API/SDKDocs/hdfsconnector.htm#uriformat.
        /// </summary>
        public readonly string WarehouseBucketUri;

        [OutputConstructor]
        private GetApplicationResult(
            string applicationId,

            string archiveUri,

            ImmutableArray<string> arguments,

            string className,

            string compartmentId,

            ImmutableDictionary<string, object> configuration,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string driverShape,

            string execute,

            string executorShape,

            string fileUri,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string language,

            string logsBucketUri,

            string metastoreId,

            int numExecutors,

            string ownerPrincipalId,

            string ownerUserName,

            ImmutableArray<Outputs.GetApplicationParameterResult> parameters,

            string privateEndpointId,

            string sparkVersion,

            string state,

            string timeCreated,

            string timeUpdated,

            string warehouseBucketUri)
        {
            ApplicationId = applicationId;
            ArchiveUri = archiveUri;
            Arguments = arguments;
            ClassName = className;
            CompartmentId = compartmentId;
            Configuration = configuration;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            DriverShape = driverShape;
            Execute = execute;
            ExecutorShape = executorShape;
            FileUri = fileUri;
            FreeformTags = freeformTags;
            Id = id;
            Language = language;
            LogsBucketUri = logsBucketUri;
            MetastoreId = metastoreId;
            NumExecutors = numExecutors;
            OwnerPrincipalId = ownerPrincipalId;
            OwnerUserName = ownerUserName;
            Parameters = parameters;
            PrivateEndpointId = privateEndpointId;
            SparkVersion = sparkVersion;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WarehouseBucketUri = warehouseBucketUri;
        }
    }
}
