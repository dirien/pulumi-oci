// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlConfigurationsConfigurationVariablesResult
    {
        /// <summary>
        /// ("autocommit")
        /// </summary>
        public readonly bool Autocommit;
        /// <summary>
        /// ("binlog_expire_logs_seconds") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int BinlogExpireLogsSeconds;
        /// <summary>
        /// ("completion_type")
        /// </summary>
        public readonly string CompletionType;
        /// <summary>
        /// ("connect_timeout")
        /// </summary>
        public readonly int ConnectTimeout;
        /// <summary>
        /// ("cte_max_recursion_depth")
        /// </summary>
        public readonly int CteMaxRecursionDepth;
        /// <summary>
        /// ("default_authentication_plugin")
        /// </summary>
        public readonly string DefaultAuthenticationPlugin;
        /// <summary>
        /// ("foreign_key_checks")
        /// </summary>
        public readonly bool ForeignKeyChecks;
        /// <summary>
        /// ("generated_random_password_length") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int GeneratedRandomPasswordLength;
        /// <summary>
        /// * EVENTUAL: Both RO and RW transactions do not wait for preceding transactions to be applied before executing. A RW transaction does not wait for other members to apply a transaction. This means that a transaction could be externalized on one member before the others. This also means that in the event of a primary failover, the new primary can accept new RO and RW transactions before the previous primary transactions are all applied. RO transactions could result in outdated values, RW transactions could result in a rollback due to conflicts.
        /// * BEFORE_ON_PRIMARY_FAILOVER: New RO or RW transactions with a newly elected primary that is applying backlog from the old primary are held (not applied) until any backlog has been applied. This ensures that when a primary failover happens, intentionally or not, clients always see the latest value on the primary. This guarantees consistency, but means that clients must be able to handle the delay in the event that a backlog is being applied. Usually this delay should be minimal, but does depend on the size of the backlog.
        /// * BEFORE: A RW transaction waits for all preceding transactions to complete before being applied. A RO transaction waits for all preceding transactions to complete before being executed. This ensures that this transaction reads the latest value by only affecting the latency of the transaction. This reduces the overhead of synchronization on every RW transaction, by ensuring synchronization is used only on RO transactions. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// * AFTER: A RW transaction waits until its changes have been applied to all of the other members. This value has no effect on RO transactions. This mode ensures that when a transaction is committed on the local member, any subsequent transaction reads the written value or a more recent value on any group member. Use this mode with a group that is used for predominantly RO operations to ensure that applied RW transactions are applied everywhere once they commit. This could be used by your application to ensure that subsequent reads fetch the latest data which includes the latest writes. This reduces the overhead of synchronization on every RO transaction, by ensuring synchronization is used only on RW transactions. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// * BEFORE_AND_AFTER: A RW transaction waits for 1) all preceding transactions to complete before being applied and 2) until its changes have been applied on other members. A RO transaction waits for all preceding transactions to complete before execution takes place. This consistency level also includes the consistency guarantees provided by BEFORE_ON_PRIMARY_FAILOVER.
        /// </summary>
        public readonly string GroupReplicationConsistency;
        /// <summary>
        /// ("information_schema_stats_expiry")
        /// </summary>
        public readonly int InformationSchemaStatsExpiry;
        /// <summary>
        /// ("innodb_buffer_pool_instances")
        /// </summary>
        public readonly int InnodbBufferPoolInstances;
        /// <summary>
        /// ("innodb_buffer_pool_size")
        /// </summary>
        public readonly string InnodbBufferPoolSize;
        /// <summary>
        /// ("innodb_ft_enable_stopword")
        /// </summary>
        public readonly bool InnodbFtEnableStopword;
        /// <summary>
        /// ("innodb_ft_max_token_size")
        /// </summary>
        public readonly int InnodbFtMaxTokenSize;
        /// <summary>
        /// ("innodb_ft_min_token_size")
        /// </summary>
        public readonly int InnodbFtMinTokenSize;
        /// <summary>
        /// ("innodb_ft_num_word_optimize")
        /// </summary>
        public readonly int InnodbFtNumWordOptimize;
        /// <summary>
        /// ("innodb_ft_result_cache_limit")
        /// </summary>
        public readonly int InnodbFtResultCacheLimit;
        /// <summary>
        /// ("innodb_ft_server_stopword_table")
        /// </summary>
        public readonly string InnodbFtServerStopwordTable;
        /// <summary>
        /// ("innodb_lock_wait_timeout")
        /// </summary>
        public readonly int InnodbLockWaitTimeout;
        /// <summary>
        /// ("innodb_max_purge_lag")
        /// </summary>
        public readonly int InnodbMaxPurgeLag;
        /// <summary>
        /// ("innodb_max_purge_lag_delay")
        /// </summary>
        public readonly int InnodbMaxPurgeLagDelay;
        /// <summary>
        /// ("local_infile")
        /// </summary>
        public readonly bool LocalInfile;
        /// <summary>
        /// ("mandatory_roles")
        /// </summary>
        public readonly string MandatoryRoles;
        /// <summary>
        /// ("max_connections")
        /// </summary>
        public readonly int MaxConnections;
        /// <summary>
        /// ("max_execution_time")
        /// </summary>
        public readonly int MaxExecutionTime;
        /// <summary>
        /// ("max_prepared_stmt_count")
        /// </summary>
        public readonly int MaxPreparedStmtCount;
        /// <summary>
        /// ("mysql_firewall_mode")
        /// </summary>
        public readonly bool MysqlFirewallMode;
        /// <summary>
        /// DEPRECATED -- typo of mysqlx_zstd_default_compression_level. variable will be ignored.
        /// </summary>
        public readonly int MysqlZstdDefaultCompressionLevel;
        /// <summary>
        /// ("mysqlx_connect_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxConnectTimeout;
        /// <summary>
        /// Set the default compression level for the deflate algorithm. ("mysqlx_deflate_default_compression_level")
        /// </summary>
        public readonly int MysqlxDeflateDefaultCompressionLevel;
        /// <summary>
        /// Limit the upper bound of accepted compression levels for the deflate algorithm. ("mysqlx_deflate_max_client_compression_level")
        /// </summary>
        public readonly int MysqlxDeflateMaxClientCompressionLevel;
        /// <summary>
        /// ("mysqlx_document_id_unique_prefix") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxDocumentIdUniquePrefix;
        /// <summary>
        /// ("mysqlx_enable_hello_notice") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly bool MysqlxEnableHelloNotice;
        /// <summary>
        /// ("mysqlx_idle_worker_thread_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxIdleWorkerThreadTimeout;
        /// <summary>
        /// ("mysqlx_interactive_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxInteractiveTimeout;
        /// <summary>
        /// Set the default compression level for the lz4 algorithm. ("mysqlx_lz4_default_compression_level")
        /// </summary>
        public readonly int MysqlxLz4defaultCompressionLevel;
        /// <summary>
        /// Limit the upper bound of accepted compression levels for the lz4 algorithm. ("mysqlx_lz4_max_client_compression_level")
        /// </summary>
        public readonly int MysqlxLz4maxClientCompressionLevel;
        /// <summary>
        /// ("mysqlx_max_allowed_packet") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxMaxAllowedPacket;
        /// <summary>
        /// ("mysqlx_min_worker_threads") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxMinWorkerThreads;
        /// <summary>
        /// ("mysqlx_read_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxReadTimeout;
        /// <summary>
        /// ("mysqlx_wait_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxWaitTimeout;
        /// <summary>
        /// ("mysqlx_write_timeout") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int MysqlxWriteTimeout;
        /// <summary>
        /// Set the default compression level for the zstd algorithm. ("mysqlx_zstd_default_compression_level")
        /// </summary>
        public readonly int MysqlxZstdDefaultCompressionLevel;
        /// <summary>
        /// Limit the upper bound of accepted compression levels for the zstd algorithm. ("mysqlx_zstd_max_client_compression_level")
        /// </summary>
        public readonly int MysqlxZstdMaxClientCompressionLevel;
        /// <summary>
        /// ("parser_max_mem_size")
        /// </summary>
        public readonly int ParserMaxMemSize;
        /// <summary>
        /// ("query_alloc_block_size") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int QueryAllocBlockSize;
        /// <summary>
        /// ("query_prealloc_size") DEPRECATED -- variable should not be settable and will be ignored
        /// </summary>
        public readonly int QueryPreallocSize;
        /// <summary>
        /// ("sql_mode")
        /// </summary>
        public readonly string SqlMode;
        /// <summary>
        /// ("sql_require_primary_key")
        /// </summary>
        public readonly bool SqlRequirePrimaryKey;
        /// <summary>
        /// ("sql_warnings")
        /// </summary>
        public readonly bool SqlWarnings;
        /// <summary>
        /// ("transaction_isolation")
        /// </summary>
        public readonly string TransactionIsolation;

        [OutputConstructor]
        private GetMysqlConfigurationsConfigurationVariablesResult(
            bool autocommit,

            int binlogExpireLogsSeconds,

            string completionType,

            int connectTimeout,

            int cteMaxRecursionDepth,

            string defaultAuthenticationPlugin,

            bool foreignKeyChecks,

            int generatedRandomPasswordLength,

            string groupReplicationConsistency,

            int informationSchemaStatsExpiry,

            int innodbBufferPoolInstances,

            string innodbBufferPoolSize,

            bool innodbFtEnableStopword,

            int innodbFtMaxTokenSize,

            int innodbFtMinTokenSize,

            int innodbFtNumWordOptimize,

            int innodbFtResultCacheLimit,

            string innodbFtServerStopwordTable,

            int innodbLockWaitTimeout,

            int innodbMaxPurgeLag,

            int innodbMaxPurgeLagDelay,

            bool localInfile,

            string mandatoryRoles,

            int maxConnections,

            int maxExecutionTime,

            int maxPreparedStmtCount,

            bool mysqlFirewallMode,

            int mysqlZstdDefaultCompressionLevel,

            int mysqlxConnectTimeout,

            int mysqlxDeflateDefaultCompressionLevel,

            int mysqlxDeflateMaxClientCompressionLevel,

            int mysqlxDocumentIdUniquePrefix,

            bool mysqlxEnableHelloNotice,

            int mysqlxIdleWorkerThreadTimeout,

            int mysqlxInteractiveTimeout,

            int mysqlxLz4defaultCompressionLevel,

            int mysqlxLz4maxClientCompressionLevel,

            int mysqlxMaxAllowedPacket,

            int mysqlxMinWorkerThreads,

            int mysqlxReadTimeout,

            int mysqlxWaitTimeout,

            int mysqlxWriteTimeout,

            int mysqlxZstdDefaultCompressionLevel,

            int mysqlxZstdMaxClientCompressionLevel,

            int parserMaxMemSize,

            int queryAllocBlockSize,

            int queryPreallocSize,

            string sqlMode,

            bool sqlRequirePrimaryKey,

            bool sqlWarnings,

            string transactionIsolation)
        {
            Autocommit = autocommit;
            BinlogExpireLogsSeconds = binlogExpireLogsSeconds;
            CompletionType = completionType;
            ConnectTimeout = connectTimeout;
            CteMaxRecursionDepth = cteMaxRecursionDepth;
            DefaultAuthenticationPlugin = defaultAuthenticationPlugin;
            ForeignKeyChecks = foreignKeyChecks;
            GeneratedRandomPasswordLength = generatedRandomPasswordLength;
            GroupReplicationConsistency = groupReplicationConsistency;
            InformationSchemaStatsExpiry = informationSchemaStatsExpiry;
            InnodbBufferPoolInstances = innodbBufferPoolInstances;
            InnodbBufferPoolSize = innodbBufferPoolSize;
            InnodbFtEnableStopword = innodbFtEnableStopword;
            InnodbFtMaxTokenSize = innodbFtMaxTokenSize;
            InnodbFtMinTokenSize = innodbFtMinTokenSize;
            InnodbFtNumWordOptimize = innodbFtNumWordOptimize;
            InnodbFtResultCacheLimit = innodbFtResultCacheLimit;
            InnodbFtServerStopwordTable = innodbFtServerStopwordTable;
            InnodbLockWaitTimeout = innodbLockWaitTimeout;
            InnodbMaxPurgeLag = innodbMaxPurgeLag;
            InnodbMaxPurgeLagDelay = innodbMaxPurgeLagDelay;
            LocalInfile = localInfile;
            MandatoryRoles = mandatoryRoles;
            MaxConnections = maxConnections;
            MaxExecutionTime = maxExecutionTime;
            MaxPreparedStmtCount = maxPreparedStmtCount;
            MysqlFirewallMode = mysqlFirewallMode;
            MysqlZstdDefaultCompressionLevel = mysqlZstdDefaultCompressionLevel;
            MysqlxConnectTimeout = mysqlxConnectTimeout;
            MysqlxDeflateDefaultCompressionLevel = mysqlxDeflateDefaultCompressionLevel;
            MysqlxDeflateMaxClientCompressionLevel = mysqlxDeflateMaxClientCompressionLevel;
            MysqlxDocumentIdUniquePrefix = mysqlxDocumentIdUniquePrefix;
            MysqlxEnableHelloNotice = mysqlxEnableHelloNotice;
            MysqlxIdleWorkerThreadTimeout = mysqlxIdleWorkerThreadTimeout;
            MysqlxInteractiveTimeout = mysqlxInteractiveTimeout;
            MysqlxLz4defaultCompressionLevel = mysqlxLz4defaultCompressionLevel;
            MysqlxLz4maxClientCompressionLevel = mysqlxLz4maxClientCompressionLevel;
            MysqlxMaxAllowedPacket = mysqlxMaxAllowedPacket;
            MysqlxMinWorkerThreads = mysqlxMinWorkerThreads;
            MysqlxReadTimeout = mysqlxReadTimeout;
            MysqlxWaitTimeout = mysqlxWaitTimeout;
            MysqlxWriteTimeout = mysqlxWriteTimeout;
            MysqlxZstdDefaultCompressionLevel = mysqlxZstdDefaultCompressionLevel;
            MysqlxZstdMaxClientCompressionLevel = mysqlxZstdMaxClientCompressionLevel;
            ParserMaxMemSize = parserMaxMemSize;
            QueryAllocBlockSize = queryAllocBlockSize;
            QueryPreallocSize = queryPreallocSize;
            SqlMode = sqlMode;
            SqlRequirePrimaryKey = sqlRequirePrimaryKey;
            SqlWarnings = sqlWarnings;
            TransactionIsolation = transactionIsolation;
        }
    }
}
