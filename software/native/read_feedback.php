<?php
/** Bounded read-only candidate adapter. Inclusion performs no IO. PHP 8.2+, 64-bit. */
declare(strict_types=1);
namespace WssNative;

const TRANSPORT_VERSION = 'wss-native-read-1.1';
const EVENT_NAME = '\\mod_feedback\\event\\response_submitted';
const MAX_INPUT_BYTES = 65536;
const MAX_BLOB_BYTES = 262144;
const MAX_BLOB_TOTAL = 4194304;
const MAX_BLOBS = 128;
const MAX_TRANSPORT_BYTES = 8388608;
const CANDIDATE_LIMIT = 17; // 16 plus an overflow sentinel; never choose a winner.
const MAX_SNAPSHOTS = 32;

final class ContractError extends \RuntimeException {}

/** Strict JSON: duplicate keys, floats, nonfinite numbers and oversized integers fail. */
final class StrictJson {
    private int $pos = 0;
    public function __construct(private readonly string $raw) {
        if (strlen($raw) > MAX_INPUT_BYTES) { throw new ContractError('INPUT_LIMIT'); }
    }
    public function decode(): mixed {
        $value = $this->value(0);
        $this->space();
        if ($this->pos !== strlen($this->raw)) { throw new ContractError('JSON_TRAILING'); }
        return $value;
    }
    private function space(): void {
        while (isset($this->raw[$this->pos]) && str_contains(" \t\n\r", $this->raw[$this->pos])) { ++$this->pos; }
    }
    private function value(int $depth): mixed {
        if ($depth > 16) { throw new ContractError('JSON_DEPTH'); }
        $this->space();
        $c = $this->raw[$this->pos] ?? '';
        if ($c === '"') { return $this->string(); }
        if ($c === '{' || $c === '[') {
            ++$this->pos;
            $object = $c === '{';
            $end = $object ? '}' : ']';
            $result = [];
            $this->space();
            if (($this->raw[$this->pos] ?? '') === $end) {
                ++$this->pos;
                return $object ? (object)$result : $result;
            }
            for ($count = 0; $count < 256; ++$count) {
                $this->space();
                if ($object) {
                    $key = $this->string();
                    if (array_key_exists($key, $result)) { throw new ContractError('JSON_DUPLICATE_KEY'); }
                    $this->space();
                    if (($this->raw[$this->pos++] ?? '') !== ':') { throw new ContractError('JSON_COLON'); }
                    $result[$key] = $this->value($depth + 1);
                } else { $result[] = $this->value($depth + 1); }
                $this->space();
                $next = $this->raw[$this->pos++] ?? '';
                if ($next === $end) { return $object ? (object)$result : $result; }
                if ($next !== ',') { throw new ContractError('JSON_DELIMITER'); }
            }
            throw new ContractError('JSON_ITEMS_LIMIT');
        }
        foreach (['true' => true, 'false' => false, 'null' => null] as $token => $literal) {
            if (substr($this->raw, $this->pos, strlen($token)) === $token) {
                $this->pos += strlen($token);
                return $literal;
            }
        }
        if (preg_match('/\G-?(?:0|[1-9][0-9]*)/A', $this->raw, $match, 0, $this->pos) === 1) {
            $this->pos += strlen($match[0]);
            $number = json_decode($match[0], false, 2, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            if (!is_int($number)) { throw new ContractError('JSON_INTEGER_RANGE'); }
            return $number;
        }
        throw new ContractError('JSON_TOKEN');
    }
    private function string(): string {
        if (($this->raw[$this->pos] ?? '') !== '"') { throw new ContractError('JSON_STRING'); }
        $start = $this->pos++;
        $escaped = false;
        while (isset($this->raw[$this->pos])) {
            $c = $this->raw[$this->pos++];
            if ($escaped) { $escaped = false; continue; }
            if ($c === '\\') { $escaped = true; continue; }
            if ($c === '"') {
                $decoded = json_decode(substr($this->raw, $start, $this->pos - $start), false, 2, JSON_THROW_ON_ERROR);
                if (!is_string($decoded)) { throw new ContractError('JSON_STRING'); }
                return $decoded;
            }
        }
        throw new ContractError('JSON_STRING_END');
    }
}

function closed_object(mixed $value, array $keys): array {
    if (!$value instanceof \stdClass) { throw new ContractError('OBJECT_REQUIRED'); }
    $data = get_object_vars($value);
    $actual = array_keys($data);
    sort($actual); sort($keys);
    if ($actual !== $keys) { throw new ContractError('OBJECT_KEYS'); }
    return $data;
}
function identifier(mixed $value): string {
    if (!is_string($value) || strlen($value) > 256 || $value === '' || trim($value) !== $value
        || preg_match('/[\p{Cc}\p{Cf}\p{Cs}]/u', $value) !== 0) {
        throw new ContractError('IDENTIFIER_INVALID');
    }
    return $value;
}
function integer(mixed $value, int $minimum = 0): int {
    if (!is_int($value) || $value < $minimum) { throw new ContractError('INTEGER_INVALID'); }
    return $value;
}
function digest(mixed $value): string {
    if (!is_string($value) || preg_match('/\Asha256:[0-9a-f]{64}\z/D', $value) !== 1) {
        throw new ContractError('DIGEST_INVALID');
    }
    return $value;
}

/** No environment reads or backend access. Every supplied reference is a declaration. */
function parse_inputs(string $operatorJson, string $requestJson): array {
    if (PHP_INT_SIZE !== 8 || PHP_VERSION_ID < 80200) { throw new ContractError('REQUIRES_64_BIT_PHP_82'); }
    $op = closed_object((new StrictJson($operatorJson))->decode(), [
        'source', 'target', 'actor', 'table_prefix', 'backend', 'other_encoding',
        'read_context_ref', 'transaction_ref', 'connection_ref',
        'target_window_before_ref', 'target_window_after_ref',
        'clean_interval_evidence_ref', 'prior_operations_evidence_ref',
        'sole_writer_evidence_ref', 'native_result_known', 'schema_policy_ref',
        'read_scope_ref', 'readonly_principal_ref', 'consistent_engine_policy_ref',
    ]);
    $op['source'] = closed_object($op['source'], [
        'source_epoch_ref', 'instance_ref', 'source_version_ref', 'runtime_version_ref',
    ]);
    foreach ($op['source'] as $ref) { identifier($ref); }
    $op['actor'] = closed_object($op['actor'], ['actor_ref', 'registry_ref', 'expected_userid']);
    identifier($op['actor']['actor_ref']); identifier($op['actor']['registry_ref']);
    integer($op['actor']['expected_userid'], 1);
    $op['target'] = closed_object($op['target'], [
        'target_ref', 'source_epoch_ref', 'courseid', 'feedback_route', 'response_scope_courseid', 'cmid', 'feedback_id', 'item_id',
        'contextid', 'contextlevel', 'eventname', 'objecttable', 'item_type',
        'item_digest', 'item_presentation_digest', 'controlled_value_digest',
    ]);
    foreach (['target_ref', 'source_epoch_ref', 'item_type'] as $key) { identifier($op['target'][$key]); }
    foreach (['courseid', 'cmid', 'feedback_id', 'item_id', 'contextid'] as $key) { integer($op['target'][$key], 1); }
    // Context course IDs remain positive. Only the distinct response scope is 0.
    integer($op['target']['response_scope_courseid'], 0);
    if ($op['target']['feedback_route'] !== 'ordinary_course'
        || $op['target']['response_scope_courseid'] !== 0) { throw new ContractError('UNSUPPORTED_FEEDBACK_SCOPE'); }
    foreach (['item_digest', 'item_presentation_digest', 'controlled_value_digest'] as $key) { digest($op['target'][$key]); }
    if ($op['target']['source_epoch_ref'] !== $op['source']['source_epoch_ref']
        || $op['target']['contextlevel'] !== 70 || $op['target']['eventname'] !== EVENT_NAME
        || $op['target']['objecttable'] !== 'feedback_completed') { throw new ContractError('TARGET_POLICY'); }
    if (!is_string($op['table_prefix']) || preg_match('/\A[A-Za-z][A-Za-z0-9_]{0,49}\z/D', $op['table_prefix']) !== 1
        || !in_array($op['backend'], ['mysql8', 'mariadb10'], true)
        || !in_array($op['other_encoding'], ['json_object', 'php_array_scalars'], true)) {
        throw new ContractError('BACKEND_POLICY');
    }
    foreach ([
        'read_context_ref', 'transaction_ref', 'connection_ref',
        'target_window_before_ref', 'target_window_after_ref', 'sole_writer_evidence_ref',
        'schema_policy_ref', 'read_scope_ref', 'readonly_principal_ref', 'consistent_engine_policy_ref',
    ] as $key) { identifier($op[$key]); }
    foreach (['clean_interval_evidence_ref', 'prior_operations_evidence_ref'] as $key) {
        if ($op[$key] !== null) { identifier($op[$key]); }
    }
    if ($op['clean_interval_evidence_ref'] === null && $op['prior_operations_evidence_ref'] === null) {
        throw new ContractError('CLEAN_OR_PRIOR_DECLARATION_REQUIRED');
    }
    if (!is_bool($op['native_result_known'])) { throw new ContractError('BOOLEAN_REQUIRED'); }
    $request = closed_object((new StrictJson($requestJson))->decode(), [
        'observation_ref', 'operation_ref', 'observer_sequence', 'log_watermark',
    ]);
    identifier($request['observation_ref']); identifier($request['operation_ref']);
    integer($request['observer_sequence']); integer($request['log_watermark']);
    return ['operator' => $op, 'request' => $request];
}

/** Narrow fake seam for offline tests. A provider is not a source/authenticity oracle. */
interface QueryProvider {
    public function begin(): void;
    public function rows(string $queryName, string $sql, array $params, int $limit): array;
    public function rollback(): void;
}

final class PdoProvider implements QueryProvider {
    private function __construct(private readonly \PDO $pdo) {}
    /** Explicit LIVE-ONLY factory. Not invoked on inclusion, help or input parsing. */
    public static function fromEnvironment(): self {
        if (!extension_loaded('pdo_mysql') || PHP_INT_SIZE !== 8) { throw new ContractError('DRIVER_UNSUPPORTED'); }
        $values = [];
        foreach (['HOST', 'PORT', 'NAME', 'USER', 'PASSWORD', 'TLS_CA'] as $name) {
            $value = getenv('WSS_DB_' . $name);
            if ($value === false || $value === '') { throw new ContractError('CREDENTIAL_CONFIGURATION_REQUIRED'); }
            $values[$name] = $value;
        }
        if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9.\-]{0,252}\z/D', $values['HOST']) !== 1
            || preg_match('/\A[A-Za-z0-9_]{1,64}\z/D', $values['NAME']) !== 1
            || preg_match('/\A[0-9]{1,5}\z/D', $values['PORT']) !== 1
            || (int)$values['PORT'] < 1 || (int)$values['PORT'] > 65535
            || !is_file($values['TLS_CA']) || !is_readable($values['TLS_CA'])) {
            throw new ContractError('CREDENTIAL_CONFIGURATION_INVALID');
        }
        foreach (['PDO::MYSQL_ATTR_MULTI_STATEMENTS', 'PDO::MYSQL_ATTR_SSL_CA', 'PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT'] as $attribute) {
            if (!defined($attribute)) { throw new ContractError('STRICT_DRIVER_ATTRIBUTES_UNAVAILABLE'); }
        }
        $options = [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_STRINGIFY_FETCHES => false,
            \PDO::ATTR_PERSISTENT => false,
            \PDO::ATTR_TIMEOUT => 5,
            constant('PDO::MYSQL_ATTR_MULTI_STATEMENTS') => false,
            constant('PDO::MYSQL_ATTR_SSL_CA') => $values['TLS_CA'],
            constant('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT') => true,
        ];
        // No DSN passthrough, socket/localhost fallback or init commands.
        if (strtolower($values['HOST']) === 'localhost') { throw new ContractError('EXPLICIT_TCP_HOST_REQUIRED'); }
        $dsn = 'mysql:host=' . $values['HOST'] . ';port=' . $values['PORT'] . ';dbname=' . $values['NAME'] . ';charset=utf8mb4';
        try { return new self(new \PDO($dsn, $values['USER'], $values['PASSWORD'], $options)); }
        catch (\Throwable $error) { throw new ContractError('CONNECTION_UNAVAILABLE'); }
    }
    public function begin(): void {
        // Fixed connection-local statements. No global state or data mutation.
        $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        $this->pdo->exec('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
    }
    public function rows(string $queryName, string $sql, array $params, int $limit): array {
        if (!str_starts_with($sql, 'SELECT ')) { throw new ContractError('SELECT_ONLY'); }
        $statement = $this->pdo->prepare($sql);
        foreach ($params as $key => $value) {
            $statement->bindValue(':' . $key, $value, is_int($value) ? \PDO::PARAM_INT : \PDO::PARAM_STR);
        }
        $statement->execute();
        $rows = [];
        while (($row = $statement->fetch()) !== false) {
            $rows[] = $row;
            if (count($rows) > $limit) { throw new ContractError('QUERY_ROW_BOUND'); }
        }
        $statement->closeCursor();
        return $rows;
    }
    public function rollback(): void { $this->pdo->exec('ROLLBACK'); }
}

/** Safe subset of PHP serialized arrays: string keys, scalar null/bool/int/string values. */
final class ScalarArrayDecoder {
    private int $pos = 0;
    public function __construct(private readonly string $raw) {
        if (strlen($raw) > MAX_BLOB_BYTES) { throw new ContractError('OTHER_LIMIT'); }
    }
    private function take(string $literal): void {
        if (substr($this->raw, $this->pos, strlen($literal)) !== $literal) { throw new ContractError('OTHER_ENCODING'); }
        $this->pos += strlen($literal);
    }
    private function decimal(string $delimiter): int {
        $end = strpos($this->raw, $delimiter, $this->pos);
        if ($end === false) { throw new ContractError('OTHER_ENCODING'); }
        $token = substr($this->raw, $this->pos, $end - $this->pos);
        if (preg_match('/\A(?:0|[1-9][0-9]*)\z/D', $token) !== 1 || strlen($token) > 9) {
            throw new ContractError('OTHER_LENGTH');
        }
        $this->pos = $end + strlen($delimiter);
        return (int)$token;
    }
    private function string(): string {
        $this->take('s:'); $length = $this->decimal(':'); $this->take('"');
        if ($length > MAX_BLOB_BYTES || $this->pos + $length > strlen($this->raw)) { throw new ContractError('OTHER_LENGTH'); }
        $result = substr($this->raw, $this->pos, $length); $this->pos += $length; $this->take('";');
        return $result;
    }
    private function scalar(): mixed {
        if (substr($this->raw, $this->pos, 2) === 's:') { return $this->string(); }
        if (substr($this->raw, $this->pos, 2) === 'N;') { $this->pos += 2; return null; }
        if (substr($this->raw, $this->pos, 2) === 'b:') {
            $this->pos += 2; $value = $this->raw[$this->pos++] ?? ''; $this->take(';');
            if ($value !== '0' && $value !== '1') { throw new ContractError('OTHER_BOOL'); }
            return $value === '1';
        }
        if (substr($this->raw, $this->pos, 2) === 'i:') {
            $this->pos += 2; $end = strpos($this->raw, ';', $this->pos);
            if ($end === false) { throw new ContractError('OTHER_INTEGER'); }
            $token = substr($this->raw, $this->pos, $end - $this->pos);
            if (preg_match('/\A-?(?:0|[1-9][0-9]*)\z/D', $token) !== 1) { throw new ContractError('OTHER_INTEGER'); }
            $value = json_decode($token, false, 2, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            if (!is_int($value)) { throw new ContractError('OTHER_INTEGER'); }
            $this->pos = $end + 1; return $value;
        }
        throw new ContractError('OTHER_SCALAR_ONLY');
    }
    public function decode(): array {
        $this->take('a:'); $count = $this->decimal(':'); $this->take('{');
        if ($count > 16) { throw new ContractError('OTHER_KEYS_LIMIT'); }
        $result = [];
        for ($i = 0; $i < $count; ++$i) {
            $key = $this->string();
            if (array_key_exists($key, $result)) { throw new ContractError('OTHER_DUPLICATE_KEY'); }
            $result[$key] = $this->scalar();
        }
        $this->take('}');
        if ($this->pos !== strlen($this->raw)) { throw new ContractError('OTHER_TRAILING'); }
        return $result;
    }
}

final class BlobBag {
    private array $blobs = [];
    private int $total = 0;
    public function add(string $bytes): array {
        $hex = hash('sha256', $bytes); $ref = 'blob:' . $hex;
        if (isset($this->blobs[$ref])) { return [$ref, 'sha256:' . $hex]; }
        if (strlen($bytes) > MAX_BLOB_BYTES || count($this->blobs) >= MAX_BLOBS
            || $this->total + strlen($bytes) > MAX_BLOB_TOTAL) { throw new ContractError('BLOB_CAPACITY'); }
        $this->blobs[$ref] = ['ref' => $ref, 'sha256' => 'sha256:' . $hex,
            'byte_length' => strlen($bytes), 'data_base64' => base64_encode($bytes)];
        $this->total += strlen($bytes);
        return [$ref, 'sha256:' . $hex];
    }
    public function all(): array { return array_values($this->blobs); }
}
function source_int(mixed $value): ?int {
    if (is_int($value)) { return $value >= 0 ? $value : null; }
    if (!is_string($value) || preg_match('/\A(?:0|[1-9][0-9]*)\z/D', $value) !== 1) { return null; }
    $decoded = json_decode($value, false, 2, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
    return is_int($decoded) ? $decoded : null;
}
function unix_time(mixed $value): ?string {
    $seconds = source_int($value);
    // Explicit supported source interval 1970..9999. Zero remains epoch, not observer time.
    return $seconds !== null && $seconds <= 253402300799 ? gmdate('Y-m-d\TH:i:s\Z', $seconds) : null;
}
function source_flag(mixed $value, bool $feedbackEnum = false): ?bool {
    $number = source_int($value);
    if ($feedbackEnum) { return $number === 1 ? true : ($number === 2 ? false : null); }
    return $number === 1 ? true : ($number === 0 ? false : null);
}
function add_diagnostic(array &$receipt, string $code): void {
    if (!in_array($code, $receipt['diagnostics'], true)) { $receipt['diagnostics'][] = $code; }
}
function compare_source(array &$receipt, mixed $actual, mixed $expected, string $code): void {
    if ($actual === null) { add_diagnostic($receipt, $code . '_UNRESOLVED'); }
    elseif ($actual !== $expected) { add_diagnostic($receipt, $code . '_CONFLICT'); }
}
function capture_column(BlobBag $bag, array $row, string $field, array &$receipt): array {
    if (!array_key_exists($field, $row) || !is_string($row[$field])) {
        add_diagnostic($receipt, strtoupper($field) . '_UNAVAILABLE_OR_BYTE_LIMIT'); return [null, null];
    }
    try { return $bag->add($row[$field]); }
    catch (ContractError $error) { add_diagnostic($receipt, 'BLOB_CAPACITY'); return [null, null]; }
}
function capture_metadata(BlobBag $bag, array $metadata, array &$receipt): void {
    try { $bag->add(json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)); }
    catch (\Throwable $error) { add_diagnostic($receipt, 'SOURCE_METADATA_UNAVAILABLE'); }
}
function source_text(BlobBag $bag, mixed $value, string $field, array &$receipt): array {
    $rawRef = null;
    if (is_string($value)) {
        try { [$rawRef] = $bag->add($value); }
        catch (ContractError $error) { add_diagnostic($receipt, 'BLOB_CAPACITY'); }
    }
    if (!is_string($value) || $value === '' || preg_match('//u', $value) !== 1) {
        add_diagnostic($receipt, strtoupper($field) . '_TEXT_UNRESOLVED'); return [null, $rawRef];
    }
    return [$value, $rawRef];
}
function bounded_column(string $column, string $alias): string {
    return 'CASE WHEN OCTET_LENGTH(' . $column . ') <= ' . MAX_BLOB_BYTES . ' THEN ' . $column . ' ELSE NULL END AS ' . $alias;
}
function other_fields(?string $raw, string $encoding): array {
    if ($raw === null) { throw new ContractError('OTHER_UNAVAILABLE'); }
    if ($encoding === 'json_object') {
        $decoded = (new StrictJson($raw))->decode();
        if (!$decoded instanceof \stdClass) { throw new ContractError('OTHER_OBJECT_REQUIRED'); }
        $values = get_object_vars($decoded);
        foreach ($values as $value) {
            if (!is_null($value) && !is_bool($value) && !is_int($value) && !is_string($value)) {
                throw new ContractError('OTHER_SCALAR_ONLY');
            }
        }
        return $values;
    }
    return (new ScalarArrayDecoder($raw))->decode();
}

function empty_receipt(array $op, array $request): array {
    return [
        'observation_ref' => $request['observation_ref'], 'operation_ref' => $request['operation_ref'],
        'status' => 'READ_UNAVAILABLE', 'observer_time' => gmdate('Y-m-d\TH:i:s\Z'),
        'observer_sequence' => $request['observer_sequence'], 'source' => $op['source'],
        'target' => $op['target'], 'actor' => $op['actor'], 'occurrences' => [], 'snapshots' => [],
        'read_context_ref' => $op['read_context_ref'], 'transaction_ref' => $op['transaction_ref'],
        'connection_ref' => $op['connection_ref'], 'consistent_snapshot_observed' => false,
        'target_course_category' => null,
        'target_window_before_ref' => $op['target_window_before_ref'],
        'target_window_after_ref' => $op['target_window_after_ref'],
        'log_watermark' => $request['log_watermark'], 'cursor_end' => null,
        'clean_interval_evidence_ref' => $op['clean_interval_evidence_ref'],
        'prior_operations_evidence_ref' => $op['prior_operations_evidence_ref'],
        'sole_writer_evidence_ref' => $op['sole_writer_evidence_ref'],
        'native_result_known' => $op['native_result_known'], 'diagnostics' => [], 'native_lira_event_id' => null,
    ];
}

/** One bounded read. No polling, ingestion, persistence, allocation or acknowledgment. */
function read_once(QueryProvider $provider, array $inputs, string $evidenceClass): array {
    if (!in_array($evidenceClass, ['REPORTED_NATIVE_READ', 'SYNTHETIC_OFFLINE_FIXTURE'], true)) {
        throw new ContractError('EVIDENCE_CLASS');
    }
    // Defend direct library callers as well as CLI parsing.
    $inputs = parse_inputs(json_encode($inputs['operator'] ?? null, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION),
        json_encode($inputs['request'] ?? null, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION));
    $op = $inputs['operator']; $req = $inputs['request']; $target = $op['target']; $actor = $op['actor'];
    $receipt = empty_receipt($op, $req); $bag = new BlobBag(); $begun = false;
    $prefix = $op['table_prefix'];
    $table = static fn(string $name): string => '`' . $prefix . $name . '`';
    try {
        $provider->begin(); $begun = true;
        $versionRows = $provider->rows('server_version', 'SELECT VERSION() AS server_version', [], 1);
        $version = $versionRows[0]['server_version'] ?? null;
        if (!is_string($version) || ($op['backend'] === 'mysql8'
            ? preg_match('/\A8\.[0-9]+\.[0-9]+/', $version) !== 1 || stripos($version, 'mariadb') !== false
            : preg_match('/\A(?:5\.5\.5-)?10\.[0-9]+\.[0-9]+.*MariaDB/i', $version) !== 1)) {
            throw new ContractError('BACKEND_VERSION_UNSUPPORTED');
        }
        $tlsTable = $op['backend'] === 'mysql8' ? 'performance_schema.session_status' : 'INFORMATION_SCHEMA.SESSION_STATUS';
        $tlsRows = $provider->rows('tls_status', "SELECT VARIABLE_VALUE AS tls_cipher FROM " . $tlsTable
            . " WHERE VARIABLE_NAME = 'Ssl_cipher' LIMIT 2", [], 2);
        if (count($tlsRows) !== 1 || !is_string($tlsRows[0]['tls_cipher'] ?? null) || $tlsRows[0]['tls_cipher'] === '') {
            throw new ContractError('TLS_SESSION_UNVERIFIED');
        }
        $names = ['course', 'course_modules', 'modules', 'context', 'feedback', 'feedback_item', 'feedback_completed', 'feedback_value', 'logstore_standard_log'];
        $params = []; $holders = [];
        foreach ($names as $index => $name) { $params['t' . $index] = $prefix . $name; $holders[] = ':t' . $index; }
        $engines = $provider->rows('engines', 'SELECT TABLE_NAME, ENGINE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (' . implode(',', $holders) . ') LIMIT 10', $params, 10);
        $observed = [];
        foreach ($engines as $row) {
            if (!isset($row['TABLE_NAME'], $row['ENGINE']) || strtolower((string)$row['ENGINE']) !== 'innodb'
                || isset($observed[$row['TABLE_NAME']])) { throw new ContractError('CONSISTENT_ENGINE_POLICY'); }
            $observed[$row['TABLE_NAME']] = true;
        }
        foreach ($params as $name) { if (!isset($observed[$name])) { throw new ContractError('ENGINE_OR_TABLE_UNAVAILABLE'); } }
        $receipt['consistent_snapshot_observed'] = true;
        $targetSql = 'SELECT cm.id AS cmid, cm.course AS courseid, c.category AS course_category, cm.instance AS feedback_id, m.name AS module_name, '
            . 'ctx.id AS contextid, ctx.contextlevel, ctx.instanceid AS contextinstanceid, f.course AS feedback_course, f.anonymous AS feedback_anonymous, '
            . 'i.id AS item_id, i.feedback AS item_feedback_id, i.typ AS item_type FROM ' . $table('course_modules') . ' cm '
            . 'LEFT JOIN ' . $table('course') . ' c ON c.id = cm.course '
            . 'LEFT JOIN ' . $table('modules') . ' m ON m.id = cm.module '
            . 'LEFT JOIN ' . $table('context') . ' ctx ON ctx.instanceid = cm.id AND ctx.contextlevel = 70 '
            . 'LEFT JOIN ' . $table('feedback') . ' f ON f.id = cm.instance '
            . 'LEFT JOIN ' . $table('feedback_item') . ' i ON i.id = :itemid WHERE cm.id = :cmid LIMIT 2';
        $targetParams = ['itemid' => $target['item_id'], 'cmid' => $target['cmid']];
        $before = $provider->rows('target_before', $targetSql, $targetParams, 2);
        $receipt['target_course_category'] = count($before) === 1 ? source_int($before[0]['course_category'] ?? null) : null;
        $beforeValid = check_target($before, $target, $receipt);
        capture_metadata($bag, ['target_window_ref' => $op['target_window_before_ref'], 'native_target_rows' => $before], $receipt);
        if (!$beforeValid) {
            $receipt['status'] = !$op['native_result_known'] ? 'NATIVE_RESULT_UNRESOLVED' : 'SOURCE_CONFLICT';
            $provider->rollback(); $begun = false;
            return finish_envelope($receipt, $bag, $evidenceClass);
        }
        $windowWhere = 'courseid = :course AND contextinstanceid = :cmid AND contextlevel = 70 AND eventname = :event '
            . 'AND (userid = :initiator OR relateduserid = :owner)';
        $windowParams = ['course' => $target['courseid'], 'cmid' => $target['cmid'], 'event' => EVENT_NAME,
            'initiator' => $actor['expected_userid'], 'owner' => $actor['expected_userid']];
        $endRows = $provider->rows('cursor_end', 'SELECT MAX(id) AS cursor_end FROM ' . $table('logstore_standard_log') . ' WHERE ' . $windowWhere, $windowParams, 1);
        $endRaw = $endRows[0]['cursor_end'] ?? null;
        $end = $endRaw === null ? 0 : source_int($endRaw);
        if ($end === null) { throw new ContractError('CURSOR_ENCODING'); }
        $receipt['cursor_end'] = $end;
        if ($end < $req['log_watermark']) { add_diagnostic($receipt, 'CURSOR_RESET_OR_CONFLICT'); }
        $logParams = $windowParams + ['watermark' => $req['log_watermark'], 'cursorend' => $end];
        $logs = $provider->rows('candidates', 'SELECT id, eventname, objecttable, objectid, contextid, contextlevel, contextinstanceid, '
            . 'courseid, userid, relateduserid, realuserid, origin, anonymous, timecreated, OCTET_LENGTH(other) AS other_byte_length, ' . bounded_column('other', 'other_raw')
            . ' FROM ' . $table('logstore_standard_log') . ' WHERE ' . $windowWhere . ' AND id > :watermark AND id <= :cursorend ORDER BY id ASC LIMIT 17', $logParams, CANDIDATE_LIMIT);
        if (count($logs) >= CANDIDATE_LIMIT) { add_diagnostic($receipt, 'CANDIDATE_OVERFLOW'); }
        foreach ($logs as $log) { capture_event($provider, $table, $log, $op, $receipt, $bag); }
        $after = $provider->rows('target_after', $targetSql, $targetParams, 2);
        check_target($after, $target, $receipt);
        capture_metadata($bag, ['target_window_ref' => $op['target_window_after_ref'], 'native_target_rows' => $after], $receipt);
        if ($before !== $after) { add_diagnostic($receipt, 'TARGET_WINDOW_CONFLICT'); }
        $provider->rollback(); $begun = false;
        if (!$op['native_result_known']) { $receipt['status'] = 'NATIVE_RESULT_UNRESOLVED'; }
        elseif ($receipt['diagnostics'] !== []) { $receipt['status'] = 'SOURCE_CONFLICT'; }
        elseif (count($receipt['occurrences']) > 1) { $receipt['status'] = 'MULTIPLE_MATCH'; }
        elseif (count($receipt['occurrences']) === 0) { $receipt['status'] = 'NO_MATCH'; }
        elseif (count($receipt['snapshots']) !== 1) { $receipt['status'] = 'SOURCE_CONFLICT'; add_diagnostic($receipt, 'SOURCE_SNAPSHOT_CARDINALITY'); }
        else { $receipt['status'] = 'MATCH_OBSERVED'; }
    } catch (\Throwable $error) {
        // Deliberately do not serialize exceptions, SQLSTATE, SQL, DSN or raw rows.
        $receipt['status'] = 'READ_UNAVAILABLE'; add_diagnostic($receipt, 'READ_FAILED_SANITIZED');
        if ($begun) {
            try { $provider->rollback(); } catch (\Throwable $rollbackError) { add_diagnostic($receipt, 'READ_CLOSE_UNCONFIRMED'); }
        }
    }
    return finish_envelope($receipt, $bag, $evidenceClass);
}
function finish_envelope(array $receipt, BlobBag $bag, string $evidenceClass): array {
    $receipt['observer_time'] = gmdate('Y-m-d\TH:i:s\Z');
    $envelope = ['transport_version' => TRANSPORT_VERSION, 'evidence_class' => $evidenceClass,
        'receipt' => $receipt, 'blobs' => $bag->all()];
    if (strlen(json_encode($envelope, JSON_THROW_ON_ERROR)) > MAX_TRANSPORT_BYTES) {
        throw new ContractError('TRANSPORT_CAPACITY');
    }
    return $envelope;
}

function check_target(array $rows, array $target, array &$receipt): bool {
    if (count($rows) !== 1) { add_diagnostic($receipt, 'TARGET_MAPPING_CARDINALITY'); return false; }
    $row = $rows[0]; $check = ['diagnostics' => []];
    foreach (['cmid', 'courseid', 'feedback_id', 'contextid', 'contextlevel', 'item_id', 'item_type'] as $field) {
        $value = $field === 'item_type' ? ($row[$field] ?? null) : source_int($row[$field] ?? null);
        compare_source($check, $value, $target[$field], 'TARGET_' . strtoupper($field));
    }
    compare_source($check, $row['module_name'] ?? null, 'feedback', 'TARGET_MODULE');
    compare_source($check, source_int($row['feedback_course'] ?? null), $target['courseid'], 'TARGET_FEEDBACK_COURSE');
    $category = source_int($row['course_category'] ?? null);
    if ($category === null) { add_diagnostic($check, 'TARGET_COURSE_CATEGORY_UNRESOLVED'); }
    elseif ($category === 0) { add_diagnostic($check, 'UNSUPPORTED_SITE_FEEDBACK'); }
    compare_source($check, source_int($row['item_feedback_id'] ?? null), $target['feedback_id'], 'TARGET_ITEM_PARENT');
    compare_source($check, source_int($row['contextinstanceid'] ?? null), $target['cmid'], 'TARGET_CONTEXT_INSTANCE');
    compare_source($check, source_flag($row['feedback_anonymous'] ?? null, true), false, 'TARGET_ANONYMITY');
    foreach ($check['diagnostics'] as $code) { add_diagnostic($receipt, $code); }
    return $check['diagnostics'] === [];
}

function capture_event(QueryProvider $provider, callable $table, array $log, array $op, array &$receipt, BlobBag $bag): void {
    $target = $op['target']; $actor = $op['actor'];
    [$otherRef] = capture_column($bag, $log, 'other_raw', $receipt);
    $other = []; $otherUsable = true;
    try { $other = other_fields(is_string($log['other_raw'] ?? null) ? $log['other_raw'] : null, $op['other_encoding']); }
    catch (\Throwable $error) { $otherUsable = false; add_diagnostic($receipt, 'OTHER_DECODE_UNAVAILABLE'); }
    if (array_diff(array_keys($other), ['cmid', 'instanceid', 'anonymous']) !== []) {
        $otherUsable = false; add_diagnostic($receipt, 'OTHER_UNKNOWN_FIELDS');
    }
    $rawTextRefs = []; $textFields = [];
    foreach (['eventname', 'objecttable', 'origin'] as $field) {
        [$textFields[$field], $rawTextRefs[$field]] = source_text($bag, $log[$field] ?? null, $field, $receipt);
    }
    $event = [
        'standard_log_record_id' => source_int($log['id'] ?? null), 'eventname' => $textFields['eventname'],
        'objecttable' => $textFields['objecttable'], 'objectid' => source_int($log['objectid'] ?? null),
        'contextid' => source_int($log['contextid'] ?? null), 'contextlevel' => source_int($log['contextlevel'] ?? null),
        'contextinstanceid' => source_int($log['contextinstanceid'] ?? null), 'courseid' => source_int($log['courseid'] ?? null),
        'userid' => source_int($log['userid'] ?? null), 'relateduserid' => source_int($log['relateduserid'] ?? null),
        'realuserid' => source_int($log['realuserid'] ?? null), 'realuserid_observed' => array_key_exists('realuserid', $log),
        'origin' => $textFields['origin'], 'other_cmid' => source_int($other['cmid'] ?? null),
        'other_instanceid' => source_int($other['instanceid'] ?? null),
        'anonymous' => source_flag($log['anonymous'] ?? null),
        'other_anonymous' => source_flag($other['anonymous'] ?? null, true),
        'native_time' => unix_time($log['timecreated'] ?? null),
    ];
    $receipt['occurrences'][] = $event;
    try {
        $bag->add(json_encode(['native_occurrence' => $event, 'raw_other_ref' => $otherRef, 'raw_text_column_refs' => $rawTextRefs,
            'raw_other_byte_length' => source_int($log['other_byte_length'] ?? null)],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    } catch (\Throwable $error) { add_diagnostic($receipt, 'EVENT_METADATA_UNAVAILABLE'); }
    $eventCheck = ['diagnostics' => []];
    foreach ([
        'eventname' => EVENT_NAME, 'objecttable' => 'feedback_completed',
        'contextid' => $target['contextid'], 'contextlevel' => 70, 'contextinstanceid' => $target['cmid'],
        'courseid' => $target['courseid'], 'userid' => $actor['expected_userid'], 'relateduserid' => $actor['expected_userid'],
        'other_cmid' => $target['cmid'], 'other_instanceid' => $target['feedback_id'], 'anonymous' => false, 'other_anonymous' => false,
    ] as $field => $expected) { compare_source($eventCheck, $event[$field], $expected, 'EVENT_' . strtoupper($field)); }
    if ($event['realuserid_observed'] !== true || ($log['realuserid'] ?? null) !== null) { add_diagnostic($eventCheck, 'NO_IMPERSONATION_UNVERIFIED'); }
    if ($event['native_time'] === null || $event['origin'] === null) { add_diagnostic($eventCheck, 'EVENT_METADATA_UNRESOLVED'); }
    if (($event['standard_log_record_id'] ?? 0) <= 0 || ($event['objectid'] ?? 0) <= 0) {
        add_diagnostic($eventCheck, 'NATIVE_ID_UNRESOLVED');
    }
    if (!$otherUsable || $otherRef === null || in_array(null, $rawTextRefs, true)) {
        add_diagnostic($eventCheck, 'EVENT_ANCHOR_SOURCE_UNRESOLVED');
    }
    if ($event['standard_log_record_id'] !== null
        && ($event['standard_log_record_id'] <= $receipt['log_watermark']
            || $event['standard_log_record_id'] > $receipt['cursor_end'])) {
        add_diagnostic($eventCheck, 'EVENT_CURSOR_WINDOW_CONFLICT');
    }
    foreach ($eventCheck['diagnostics'] as $code) { add_diagnostic($receipt, $code); }
    if ($eventCheck['diagnostics'] !== []) { return; }
    $completed = $provider->rows('completed', 'SELECT id, feedback, userid, anonymous_response, courseid, timemodified FROM '
        . $table('feedback_completed') . ' WHERE id = :completed LIMIT 2', ['completed' => $event['objectid']], 2);
    if (count($completed) !== 1) { add_diagnostic($receipt, 'COMPLETED_CARDINALITY'); return; }
    $row = $completed[0];
    $base = [
        'snapshot_ref' => null, 'completed_id' => source_int($row['id'] ?? null),
        'completed_feedback_id' => source_int($row['feedback'] ?? null), 'completed_userid' => source_int($row['userid'] ?? null),
        'completed_anonymous' => source_flag($row['anonymous_response'] ?? null, true),
        'completed_courseid' => source_int($row['courseid'] ?? null), 'completed_modified_time' => unix_time($row['timemodified'] ?? null),
        'item_id' => null, 'item_feedback_id' => null, 'item_type' => null, 'item_text_ref' => null, 'item_digest' => null,
        'item_presentation_ref' => null, 'item_presentation_digest' => null, 'value_id' => null,
        'value_completed_id' => null, 'value_item_id' => null, 'value_courseid' => null,
        'value_bytes_ref' => null, 'value_digest' => null,
    ];
    if ($base['completed_modified_time'] === null) { add_diagnostic($receipt, 'COMPLETED_TIME_UNRESOLVED'); }
    compare_source($receipt, $base['completed_id'], $event['objectid'], 'COMPLETED_ID');
    compare_source($receipt, $base['completed_userid'], $actor['expected_userid'], 'COMPLETED_OWNER');
    compare_source($receipt, $base['completed_feedback_id'], $target['feedback_id'], 'COMPLETED_FEEDBACK');
    compare_source($receipt, $base['completed_courseid'], $target['response_scope_courseid'], 'COMPLETED_RESPONSE_SCOPE');
    compare_source($receipt, $base['completed_anonymous'], false, 'COMPLETED_ANONYMITY');
    capture_metadata($bag, ['native_log_id' => $event['standard_log_record_id'], 'native_completed_snapshot' => $base], $receipt);
    // Never expose answer bytes from a different/unknown owner or context.
    if ($base['completed_id'] !== $event['objectid'] || $base['completed_modified_time'] === null
        || $base['completed_userid'] !== $actor['expected_userid'] || $base['completed_feedback_id'] !== $target['feedback_id']
        || $base['completed_courseid'] !== $target['response_scope_courseid'] || $base['completed_anonymous'] !== false) {
        finish_snapshot($base, $event, $otherRef, $receipt, $bag); return;
    }
    $valueSql = 'SELECT v.id AS value_id, v.completed AS value_completed_id, v.item AS value_item_id, '
        . 'v.course_id AS value_courseid, v.tmp_completed, i.id AS item_id, i.feedback AS item_feedback_id, i.typ AS item_type, '
        . bounded_column('v.value', 'value_raw') . ', ' . bounded_column('i.name', 'item_raw') . ', '
        . bounded_column('i.presentation', 'presentation_raw') . ', OCTET_LENGTH(v.value) AS value_byte_length, '
        . 'OCTET_LENGTH(i.name) AS item_byte_length, OCTET_LENGTH(i.presentation) AS presentation_byte_length FROM ' . $table('feedback_value') . ' v '
        . 'LEFT JOIN ' . $table('feedback_item') . ' i ON i.id = v.item '
        . 'WHERE v.completed = :completed AND v.item = :expecteditem ORDER BY v.id ASC LIMIT 17';
    $values = $provider->rows('values', $valueSql, ['completed' => $event['objectid'], 'expecteditem' => $target['item_id']], CANDIDATE_LIMIT);
    if (count($values) >= CANDIDATE_LIMIT) { add_diagnostic($receipt, 'VALUE_ROWS_OVERFLOW'); }
    if ($values === []) { add_diagnostic($receipt, 'VALUE_MISSING'); finish_snapshot($base, $event, $otherRef, $receipt, $bag); }
    foreach ($values as $value) {
        $snapshot = $base;
        foreach (['value_id', 'value_completed_id', 'value_item_id', 'value_courseid', 'item_id', 'item_feedback_id'] as $field) {
            $snapshot[$field] = source_int($value[$field] ?? null);
        }
        [$snapshot['item_type'], $itemTypeRawRef] = source_text($bag, $value['item_type'] ?? null, 'item_type', $receipt);
        [$snapshot['item_text_ref'], $snapshot['item_digest']] = capture_column($bag, $value, 'item_raw', $receipt);
        [$snapshot['item_presentation_ref'], $snapshot['item_presentation_digest']] = capture_column($bag, $value, 'presentation_raw', $receipt);
        [$snapshot['value_bytes_ref'], $snapshot['value_digest']] = capture_column($bag, $value, 'value_raw', $receipt);
        foreach ([
            'item_id' => $target['item_id'], 'item_feedback_id' => $target['feedback_id'], 'item_type' => $target['item_type'],
            'value_completed_id' => $event['objectid'], 'value_item_id' => $target['item_id'], 'value_courseid' => $target['response_scope_courseid'],
            'item_digest' => $target['item_digest'], 'item_presentation_digest' => $target['item_presentation_digest'],
            'value_digest' => $target['controlled_value_digest'],
        ] as $field => $expected) { compare_source($receipt, $snapshot[$field], $expected, 'SOURCE_' . strtoupper($field)); }
        compare_source($receipt, source_int($value['tmp_completed'] ?? null), 0, 'VALUE_TEMP_COMPLETED');
        if (($snapshot['value_id'] ?? 0) <= 0) { add_diagnostic($receipt, 'VALUE_ID_UNRESOLVED'); }
        finish_snapshot($snapshot, $event, $otherRef, $receipt, $bag, [
            'tmp_completed' => source_int($value['tmp_completed'] ?? null), 'raw_item_type_ref' => $itemTypeRawRef,
            'item_byte_length' => source_int($value['item_byte_length'] ?? null),
            'presentation_byte_length' => source_int($value['presentation_byte_length'] ?? null),
            'value_byte_length' => source_int($value['value_byte_length'] ?? null),
        ]);
    }
}
function finish_snapshot(array $snapshot, array $event, ?string $otherRef, array &$receipt, BlobBag $bag, array $details = []): void {
    if (count($receipt['snapshots']) >= MAX_SNAPSHOTS) { add_diagnostic($receipt, 'SNAPSHOT_ROWS_OVERFLOW'); return; }
    // Content addressing is local byte storage only, never a native occurrence identity.
    $metadata = ['standard_log_record_id' => $event['standard_log_record_id'], 'raw_other_ref' => $otherRef,
        'native_snapshot_fields' => $snapshot, 'source_projection_details' => $details];
    try { [$snapshot['snapshot_ref']] = $bag->add(json_encode($metadata, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)); }
    catch (\Throwable $error) { add_diagnostic($receipt, 'SNAPSHOT_METADATA_UNAVAILABLE'); }
    $receipt['snapshots'][] = $snapshot;
}

function read_small_file(string $path): string {
    if (is_link($path) || !is_file($path)) { throw new ContractError('INPUT_FILE_REQUIRED'); }
    $handle = fopen($path, 'rb');
    if ($handle === false) { throw new ContractError('INPUT_FILE_UNAVAILABLE'); }
    try { $raw = stream_get_contents($handle, MAX_INPUT_BYTES + 1); }
    finally { fclose($handle); }
    if (!is_string($raw) || strlen($raw) > MAX_INPUT_BYTES) { throw new ContractError('INPUT_FILE_LIMIT'); }
    return $raw;
}
function cli(array $args): int {
    if ($args === [] || $args === ['--help']) {
        fwrite(STDOUT, "WSS native read candidate: explicit --execute-read --operator FILE --request FILE required.\n");
        return 0;
    }
    if (count($args) !== 5 || $args[0] !== '--execute-read' || $args[1] !== '--operator' || $args[3] !== '--request') {
        fwrite(STDERR, "WSS_INPUT_REJECTED\n"); return 2;
    }
    // Warnings/errors are not emitted with private file paths or driver detail.
    set_error_handler(static function(int $severity, string $message, string $file, int $line): never {
        throw new ContractError('IO_OR_RUNTIME_UNAVAILABLE');
    });
    $inputs = null;
    try {
        $inputs = parse_inputs(read_small_file($args[2]), read_small_file($args[4]));
        $provider = PdoProvider::fromEnvironment();
        $envelope = read_once($provider, $inputs, 'REPORTED_NATIVE_READ');
        fwrite(STDOUT, json_encode($envelope, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
        return $envelope['receipt']['status'] === 'READ_UNAVAILABLE' ? 3 : 0;
    } catch (\Throwable $error) {
        if (is_array($inputs)) {
            $receipt = empty_receipt($inputs['operator'], $inputs['request']);
            add_diagnostic($receipt, 'READ_FAILED_BEFORE_PROVIDER');
            fwrite(STDOUT, json_encode(['transport_version' => TRANSPORT_VERSION,
                'evidence_class' => 'REPORTED_NATIVE_READ', 'receipt' => $receipt, 'blobs' => []],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
        } else { fwrite(STDERR, "WSS_READ_UNAVAILABLE_SANITIZED\n"); }
        return 3;
    }
    finally { restore_error_handler(); }
}

// Inclusion is inert, including in the separate offline self-test source.
if (PHP_SAPI === 'cli' && is_string($_SERVER['SCRIPT_FILENAME'] ?? null)
    && $_SERVER['SCRIPT_FILENAME'] !== ''
    && (get_included_files()[0] ?? null) === __FILE__) {
    exit(cli(array_slice($argv, 1)));
}
