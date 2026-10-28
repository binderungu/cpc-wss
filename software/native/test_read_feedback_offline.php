<?php
/** Source-only offline fake-provider tests. No PDO, env, Moodle or network access. */
declare(strict_types=1);
namespace WssNativeOfflineTest;
require_once __DIR__ . '/read_feedback.php';

use WssNative\ContractError;
use WssNative\QueryProvider;

final class FakeProvider implements QueryProvider {
    public array $calls = [];
    public array $queryInputs = [];
    public bool $begun = false;
    public bool $closed = false;
    public function __construct(public array $script, public ?string $failAt = null, public bool $closeFails = false) {}
    public function begin(): void { $this->begun = true; }
    public function rows(string $queryName, string $sql, array $params, int $limit): array {
        if (!$this->begun || $this->closed || !str_starts_with($sql, 'SELECT ') || $limit > 17) {
            throw new \RuntimeException('FAKE_QUERY_CONTRACT');
        }
        $this->calls[] = $queryName;
        $this->queryInputs[$queryName] = ['sql' => $sql, 'params' => $params];
        if ($this->failAt === $queryName) { throw new \RuntimeException('secret_password_private_dsn_query'); }
        if (!array_key_exists($queryName, $this->script)) { throw new \RuntimeException('UNSCRIPTED_QUERY'); }
        return $this->script[$queryName];
    }
    public function rollback(): void {
        if ($this->closeFails) { throw new \RuntimeException('private_rollback_detail'); }
        $this->closed = true;
    }
}
function check(bool $condition, string $name): void {
    if (!$condition) { throw new \RuntimeException('ASSERTION:' . $name); }
}
function rejected(callable $operation): void {
    try { $operation(); } catch (\Throwable $error) { return; }
    throw new \RuntimeException('EXPECTED_REJECTION');
}
function fixture(): array {
    $operator = [
        'source' => ['source_epoch_ref' => 'fixture:epoch', 'instance_ref' => 'fixture:instance',
            'source_version_ref' => 'fixture:source-version', 'runtime_version_ref' => 'fixture:runtime-version'],
        'target' => ['target_ref' => 'fixture:target', 'source_epoch_ref' => 'fixture:epoch',
            'courseid' => 7, 'feedback_route' => 'ordinary_course', 'response_scope_courseid' => 0, 'cmid' => 8, 'feedback_id' => 9, 'item_id' => 10,
            'contextid' => 11, 'contextlevel' => 70, 'eventname' => \WssNative\EVENT_NAME,
            'objecttable' => 'feedback_completed', 'item_type' => 'textarea',
            'item_digest' => 'sha256:' . hash('sha256', 'Question'),
            'item_presentation_digest' => 'sha256:' . hash('sha256', '40|5'),
            'controlled_value_digest' => 'sha256:' . hash('sha256', 'synthetic response')],
        'actor' => ['actor_ref' => 'fixture:actor', 'registry_ref' => 'fixture:actors', 'expected_userid' => 12],
        'table_prefix' => 'fixture_', 'backend' => 'mysql8', 'other_encoding' => 'json_object',
        'read_context_ref' => 'fixture:read', 'transaction_ref' => 'fixture:transaction',
        'connection_ref' => 'fixture:connection', 'target_window_before_ref' => 'fixture:before',
        'target_window_after_ref' => 'fixture:after', 'clean_interval_evidence_ref' => 'fixture:clean',
        'prior_operations_evidence_ref' => null, 'sole_writer_evidence_ref' => 'fixture:sole-writer',
        'native_result_known' => true, 'schema_policy_ref' => 'fixture:schema',
        'read_scope_ref' => 'fixture:scope', 'readonly_principal_ref' => 'fixture:principal',
        'consistent_engine_policy_ref' => 'fixture:engines',
    ];
    $request = ['observation_ref' => 'fixture:observation', 'operation_ref' => 'fixture:operation',
        'observer_sequence' => 0, 'log_watermark' => 100];
    $targetRow = ['cmid' => 8, 'courseid' => 7, 'course_category' => 1, 'feedback_id' => 9, 'module_name' => 'feedback',
        'contextid' => 11, 'contextlevel' => 70, 'contextinstanceid' => 8,
        'feedback_course' => 7, 'feedback_anonymous' => 2, 'item_id' => 10,
        'item_feedback_id' => 9, 'item_type' => 'textarea'];
    $other = '{"cmid":8,"instanceid":9,"anonymous":2}';
    $log = ['id' => 101, 'eventname' => \WssNative\EVENT_NAME, 'objecttable' => 'feedback_completed',
        'objectid' => 1000, 'contextid' => 11, 'contextlevel' => 70, 'contextinstanceid' => 8,
        'courseid' => 7, 'userid' => 12, 'relateduserid' => 12, 'realuserid' => null,
        'origin' => 'web', 'anonymous' => 0, 'timecreated' => 1792195200,
        'other_raw' => $other, 'other_byte_length' => strlen($other)];
    $engines = [];
    foreach (['course', 'course_modules', 'modules', 'context', 'feedback', 'feedback_item', 'feedback_completed', 'feedback_value', 'logstore_standard_log'] as $name) {
        $engines[] = ['TABLE_NAME' => 'fixture_' . $name, 'ENGINE' => 'InnoDB'];
    }
    $script = [
        'server_version' => [['server_version' => '8.0.36']], 'tls_status' => [['tls_cipher' => 'TLS_AES_256_GCM_SHA384']], 'engines' => $engines,
        'target_before' => [$targetRow], 'target_after' => [$targetRow],
        'cursor_end' => [['cursor_end' => 101]], 'candidates' => [$log],
        'completed' => [['id' => 1000, 'feedback' => 9, 'userid' => 12,
            'anonymous_response' => 2, 'courseid' => 0, 'timemodified' => 1792195200]],
        'values' => [['value_id' => 2000, 'value_completed_id' => 1000, 'value_item_id' => 10,
            'value_courseid' => 0, 'tmp_completed' => 0, 'item_id' => 10,
            'item_feedback_id' => 9, 'item_type' => 'textarea', 'item_raw' => 'Question',
            'presentation_raw' => '40|5', 'value_raw' => 'synthetic response',
            'item_byte_length' => 8, 'presentation_byte_length' => 4, 'value_byte_length' => 18]],
    ];
    return [$operator, $request, $script];
}
function read_fixture(array $operator, array $request, array $script, ?FakeProvider $provider = null): array {
    return \WssNative\read_once($provider ?? new FakeProvider($script), ['operator' => $operator, 'request' => $request], 'SYNTHETIC_OFFLINE_FIXTURE');
}
function run(): int {
    $tests = [];
    $tests['strict_json_duplicate_and_float_rejection'] = static function(): void {
        foreach (['{"a":1,"a":2}', '{"a":1.5}', '{"a":1e2}', '{"a":9223372036854775808}', '{"a":"\\uD800"}'] as $raw) {
            rejected(static fn() => (new \WssNative\StrictJson($raw))->decode());
        }
    };
    $tests['closed_inputs_and_exact_types'] = static function(): void {
        [$op, $req] = fixture(); $op['unknown'] = 1;
        rejected(static fn() => read_fixture($op, $req, []));
        [$op, $req] = fixture(); $req['log_watermark'] = true;
        rejected(static fn() => read_fixture($op, $req, []));
        [$op, $req] = fixture(); $op['target']['contextlevel'] = 50;
        rejected(static fn() => read_fixture($op, $req, []));
    };
    $tests['php_scalar_array_decoder'] = static function(): void {
        $raw = 'a:3:{s:4:"cmid";i:8;s:10:"instanceid";i:9;s:9:"anonymous";i:2;}';
        check((new \WssNative\ScalarArrayDecoder($raw))->decode() === ['cmid' => 8, 'instanceid' => 9, 'anonymous' => 2], 'scalar-array');
        foreach (['O:8:"stdClass":0:{}', 'a:1:{s:1:"x";R:1;}', 'a:1:{s:1:"x";a:0:{}}', 'a:2:{s:1:"x";i:1;s:1:"x";i:2;}', 'a:1:{s:1:"x";d:1.2;}'] as $bad) {
            rejected(static fn() => (new \WssNative\ScalarArrayDecoder($bad))->decode());
        }
    };
    $tests['positive_transport_and_exact_source_bytes'] = static function(): void {
        [$op, $req, $script] = fixture(); $provider = new FakeProvider($script);
        $result = read_fixture($op, $req, $script, $provider);
        check(array_keys($result) === ['transport_version', 'evidence_class', 'receipt', 'blobs'], 'four-keys');
        check($provider->closed && $result['receipt']['status'] === 'MATCH_OBSERVED', 'match-and-close');
        check($result['receipt']['snapshots'][0]['value_id'] === 2000, 'native-value-id');
        check(($provider->queryInputs['values']['params']['expecteditem'] ?? null) === 10
            && str_contains($provider->queryInputs['values']['sql'], 'v.item = :expecteditem'), 'narrow-expected-item');
        check($result['receipt']['occurrences'][0]['other_anonymous'] === false, 'moodle-enum-two');
        foreach ($result['blobs'] as $blob) {
            $raw = base64_decode($blob['data_base64'], true);
            check(is_string($raw) && strlen($raw) === $blob['byte_length'], 'blob-length');
            check($blob['sha256'] === 'sha256:' . hash('sha256', $raw) && $blob['ref'] === 'blob:' . hash('sha256', $raw), 'blob-digest');
        }
    };
    $tests['serialized_other_positive'] = static function(): void {
        [$op, $req, $script] = fixture(); $op['other_encoding'] = 'php_array_scalars';
        $script['candidates'][0]['other_raw'] = 'a:3:{s:4:"cmid";i:8;s:10:"instanceid";i:9;s:9:"anonymous";i:2;}';
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'MATCH_OBSERVED', 'serialized-match');
    };
    $tests['unknown_and_malformed_other_hold'] = static function(): void {
        foreach (['{"cmid":8,"instanceid":9,"anonymous":2,"unknown":1}', '{"cmid":8,"cmid":8}', 'O:8:"stdClass":0:{}'] as $raw) {
            [$op, $req, $script] = fixture(); $script['candidates'][0]['other_raw'] = $raw;
            $result = read_fixture($op, $req, $script);
            check($result['receipt']['status'] === 'SOURCE_CONFLICT' && count($result['receipt']['occurrences']) === 1, 'other-hold');
        }
    };
    $tests['multiple_events_same_completed_retained'] = static function(): void {
        [$op, $req, $script] = fixture(); $second = $script['candidates'][0]; $second['id'] = 102;
        $script['candidates'][] = $second; $script['cursor_end'][0]['cursor_end'] = 102;
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'MULTIPLE_MATCH' && count($result['receipt']['occurrences']) === 2
            && count($result['receipt']['snapshots']) === 2, 'multiplicity');
    };
    $tests['wrong_owner_hides_answer_bytes'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['completed'][0]['userid'] = 99;
        $provider = new FakeProvider($script); $result = read_fixture($op, $req, $script, $provider);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT' && !in_array('values', $provider->calls, true), 'no-value-query');
        check($result['receipt']['snapshots'][0]['value_bytes_ref'] === null, 'no-answer-bytes');
    };
    $tests['wrong_value_course_item_temporary_retained'] = static function(): void {
        [$op, $req, $script] = fixture();
        $script['values'][0]['value_courseid'] = 999; $script['values'][0]['tmp_completed'] = 3;
        $script['values'][0]['value_item_id'] = 999;
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && $result['receipt']['snapshots'][0]['value_courseid'] === 999, 'wrong-binding-retained');
    };
    $tests['zero_native_identity_not_fabricated'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['candidates'][0]['id'] = 0;
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && $result['receipt']['occurrences'][0]['standard_log_record_id'] === 0, 'zero-retained');
    };
    $tests['no_match_and_unresolved_native_result'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['candidates'] = []; $script['cursor_end'][0]['cursor_end'] = 100;
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'NO_MATCH', 'no-match');
        $op['native_result_known'] = false;
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'NATIVE_RESULT_UNRESOLVED', 'not-native-success');
    };
    $tests['cursor_reset_hold'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['candidates'] = []; $script['cursor_end'][0]['cursor_end'] = 99;
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'SOURCE_CONFLICT', 'cursor-reset');
    };
    $tests['byte_limit_not_substituted_with_controlled_input'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['values'][0]['value_raw'] = null;
        $script['values'][0]['value_byte_length'] = \WssNative\MAX_BLOB_BYTES + 1;
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && $result['receipt']['snapshots'][0]['value_digest'] === null, 'no-substitute');
    };
    $tests['candidate_overflow_is_explicit'] = static function(): void {
        [$op, $req, $script] = fixture(); $first = $script['candidates'][0]; $script['candidates'] = [];
        for ($i = 0; $i < 17; ++$i) { $row = $first; $row['id'] = 101 + $i; $script['candidates'][] = $row; }
        $script['cursor_end'][0]['cursor_end'] = 117;
        $result = read_fixture($op, $req, $script);
        check(count($result['receipt']['occurrences']) === 17 && in_array('CANDIDATE_OVERFLOW', $result['receipt']['diagnostics'], true)
            && $result['receipt']['status'] !== 'MATCH_OBSERVED', 'overflow-hold');
    };
    $tests['target_conflict_and_window_change_hold'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['target_after'][0]['contextid'] = 999;
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && in_array('TARGET_WINDOW_CONFLICT', $result['receipt']['diagnostics'], true), 'target-change');
    };
    $tests['unsupported_engine_and_backend_fail_closed'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['engines'][0]['ENGINE'] = 'MyISAM';
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'READ_UNAVAILABLE', 'engine');
        [$op, $req, $script] = fixture(); $script['server_version'][0]['server_version'] = '5.7.44';
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'READ_UNAVAILABLE', 'version');
    };
    $tests['failure_sanitized_partial_receipts_retained'] = static function(): void {
        [$op, $req, $script] = fixture(); $provider = new FakeProvider($script, 'values');
        $result = read_fixture($op, $req, $script, $provider);
        check($result['receipt']['status'] === 'READ_UNAVAILABLE' && count($result['receipt']['occurrences']) === 1 && $provider->closed, 'partial-close');
        check(!str_contains(json_encode($result, JSON_THROW_ON_ERROR), 'secret_password'), 'error-sanitized');
    };
    $tests['rollback_failure_is_hold'] = static function(): void {
        [$op, $req, $script] = fixture(); $provider = new FakeProvider($script, null, true);
        $result = read_fixture($op, $req, $script, $provider);
        check($result['receipt']['status'] === 'READ_UNAVAILABLE'
            && in_array('READ_CLOSE_UNCONFIRMED', $result['receipt']['diagnostics'], true), 'close-unknown');
    };
    $tests['missing_tls_cipher_fails_before_target_reads'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['tls_status'] = [['tls_cipher' => '']];
        $provider = new FakeProvider($script); $result = read_fixture($op, $req, $script, $provider);
        check($result['receipt']['status'] === 'READ_UNAVAILABLE' && !in_array('target_before', $provider->calls, true), 'tls-hold');
    };
    $tests['empty_source_text_retains_bytes_and_null_receipt'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['candidates'][0]['origin'] = '';
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && $result['receipt']['occurrences'][0]['origin'] === null
            && $result['receipt']['snapshots'] === [], 'empty-origin-no-source-read');
        [$op, $req, $script] = fixture(); $script['values'][0]['item_type'] = '';
        $result = read_fixture($op, $req, $script);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT'
            && $result['receipt']['snapshots'][0]['item_type'] === null, 'empty-item-type-not-unparseable');
        $foundEmpty = false; foreach ($result['blobs'] as $blob) { if ($blob['byte_length'] === 0) { $foundEmpty = true; } }
        check($foundEmpty, 'raw-empty-blob-retained');
    };
    $tests['invalid_before_target_stops_before_native_answer_queries'] = static function(): void {
        [$op, $req, $script] = fixture(); $script['target_before'][0]['module_name'] = 'quiz';
        $provider = new FakeProvider($script); $result = read_fixture($op, $req, $script, $provider);
        check($result['receipt']['status'] === 'SOURCE_CONFLICT' && $provider->closed
            && !in_array('candidates', $provider->calls, true)
            && !in_array('completed', $provider->calls, true)
            && !in_array('values', $provider->calls, true), 'invalid-target-no-source-answers');
        $op['native_result_known'] = false;
        check(read_fixture($op, $req, $script)['receipt']['status'] === 'NATIVE_RESULT_UNRESOLVED', 'unknown-result-precedence');
    };
    $tests['invalid_event_anchor_stops_before_completed_or_values'] = static function(): void {
        foreach (['objecttable' => 'quiz_attempts', 'userid' => 99, 'relateduserid' => 99, 'realuserid' => 999] as $field => $bad) {
            [$op, $req, $script] = fixture(); $script['candidates'][0][$field] = $bad;
            $provider = new FakeProvider($script); $result = read_fixture($op, $req, $script, $provider);
            check($result['receipt']['status'] === 'SOURCE_CONFLICT' && count($result['receipt']['occurrences']) === 1
                && !in_array('completed', $provider->calls, true)
                && !in_array('values', $provider->calls, true), 'invalid-anchor-no-completed-answers');
        }
    };
    $tests['blob_capacity_and_exact_deduplication'] = static function(): void {
        $bag = new \WssNative\BlobBag();
        $first = $bag->add("\0exact\r\n"); $second = $bag->add("\0exact\r\n");
        check($first === $second && count($bag->all()) === 1, 'byte-dedup-only');
        rejected(static fn() => $bag->add(str_repeat('x', \WssNative\MAX_BLOB_BYTES + 1)));
    };
    $failed = 0;
    foreach ($tests as $name => $test) {
        try { $test(); fwrite(STDOUT, 'OK ' . $name . "\n"); }
        catch (\Throwable $error) { ++$failed; fwrite(STDERR, 'FAIL ' . $name . "\n"); }
    }
    fwrite(STDOUT, json_encode(['test_methods' => count($tests), 'failed' => $failed,
        'evidence_class' => 'SYNTHETIC_OFFLINE_FIXTURE'], JSON_THROW_ON_ERROR) . "\n");
    return $failed === 0 ? 0 : 1;
}
if (PHP_SAPI === 'cli' && (get_included_files()[0] ?? null) === __FILE__) {
    exit(run());
}
