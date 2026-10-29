<?php
/** SC01 regressions over a fake SQL provider only. No PDO/Moodle/LIRA/network. */
declare(strict_types=1);
namespace WssSc01OfflineTest;
require_once __DIR__ . '/test_read_feedback_offline.php';
use WssNativeOfflineTest\FakeProvider;
function check(bool $ok, string $why): void { if (!$ok) { throw new \RuntimeException($why); } }
function contract_rejected(callable $fn): void {
    try { $fn(); } catch (\WssNative\ContractError $e) { return; }
    throw new \RuntimeException('Expected specifically ContractError');
}
function run(): int {
    $tests = [];
    $tests['context_positive_and_scope_zero_match_without_rewrite'] = static function(): void {
        [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$p=new FakeProvider($rows);
        $r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
        check($r['status']==='MATCH_OBSERVED' && $r['diagnostics']===[], 'positive');
        check($r['target']['courseid']===7 && $r['occurrences'][0]['courseid']===7, 'context-positive');
        check($r['snapshots'][0]['completed_courseid']===0 && $r['snapshots'][0]['value_courseid']===0, 'scopes-zero');
        check($r['target_course_category']===1, 'category-observed');
        check(count($p->queryInputs['engines']['params'])===9, 'nine-InnoDB-tables');
        check(str_contains($p->queryInputs['target_before']['sql'],'`fixture_course` c ON c.id = cm.course'), 'category-source-join');
    };
    $tests['mariadb10_scope_zero_uses_session_tls_metadata'] = static function(): void {
        [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$op['backend']='mariadb10';
        $rows['server_version'][0]['server_version']='10.11.19-MariaDB';
        $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
        check($r['status']==='MATCH_OBSERVED' && $r['snapshots'][0]['value_courseid']===0,'mariadb-zero-positive');
        check(str_contains($p->queryInputs['tls_status']['sql'],'INFORMATION_SCHEMA.SESSION_STATUS'),'mariadb-tls-branch');
    };
    $tests['scope_declaration_is_explicit_exact_zero'] = static function(): void {
        foreach ([null,true,false,'0',0.0,-1,7] as $bad) {
            [$op,$req]=\WssNativeOfflineTest\fixture();$op['target']['response_scope_courseid']=$bad;
            contract_rejected(static fn()=>\WssNativeOfflineTest\read_fixture($op,$req,[]));
        }
        foreach (['feedback_route','response_scope_courseid'] as $key) {
            [$op,$req]=\WssNativeOfflineTest\fixture();unset($op['target'][$key]);
            contract_rejected(static fn()=>\WssNativeOfflineTest\read_fixture($op,$req,[]));
        }
    };
    $tests['site_route_declaration_and_zero_context_not_allowed'] = static function(): void {
        foreach (['site_feedback',null,''] as $bad) {
            [$op,$req]=\WssNativeOfflineTest\fixture();$op['target']['feedback_route']=$bad;
            contract_rejected(static fn()=>\WssNativeOfflineTest\read_fixture($op,$req,[]));
        }
        [$op,$req]=\WssNativeOfflineTest\fixture();$op['target']['courseid']=0;
        contract_rejected(static fn()=>\WssNativeOfflineTest\read_fixture($op,$req,[]));
    };
    $tests['completed_wrong_or_missing_scope_stops_answer_query'] = static function(): void {
        foreach ([7,1,null] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['completed'][0]['courseid']=$bad;
            $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && !in_array('values',$p->calls,true), 'failed-scope-no-answer');
            check($r['snapshots'][0]['completed_courseid']===$bad && $r['snapshots'][0]['value_bytes_ref']===null,'retained-not-replaced');
        }
    };
    $tests['completed_wrong_missing_zero_id_stops_answer_query'] = static function(): void {
        foreach ([999,null,0] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['completed'][0]['id']=$bad;
            $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && !in_array('values',$p->calls,true),'completed-id-no-answer');
            check($r['snapshots'][0]['completed_id']===$bad && $r['snapshots'][0]['value_bytes_ref']===null,'bad-id-preserved');
        }
    };
    $tests['completed_missing_time_stops_answer_query'] = static function(): void {
        [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['completed'][0]['timemodified']=null;
        $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
        check($r['status']==='SOURCE_CONFLICT' && !in_array('values',$p->calls,true),'missing-time-no-answer');
        check($r['snapshots'][0]['completed_modified_time']===null,'missing-time-preserved');
    };
    $tests['value_nonzero_or_missing_scope_is_retained_conflict'] = static function(): void {
        foreach ([7,1,null] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['values'][0]['value_courseid']=$bad;
            $r=\WssNativeOfflineTest\read_fixture($op,$req,$rows)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && $r['snapshots'][0]['value_courseid']===$bad,'scope-fact-retained');
        }
    };
    $tests['site_course_category_zero_stops_before_anchors_answers'] = static function(): void {
        [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['target_before'][0]['course_category']=0;
        $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
        check($r['status']==='SOURCE_CONFLICT' && in_array('UNSUPPORTED_SITE_FEEDBACK',$r['diagnostics'],true),'site-hold');
        check($r['target_course_category']===0 && !in_array('candidates',$p->calls,true) && !in_array('values',$p->calls,true),'site-no-answer');
    };
    $tests['category_missing_bool_or_negative_is_unresolved'] = static function(): void {
        foreach ([null,true,-1] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['target_before'][0]['course_category']=$bad;
            $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && $r['target_course_category']===null,'category-unresolved');
            check(!in_array('candidates',$p->calls,true),'category-no-event-read');
        }
    };
    $tests['after_window_category_change_remains_conflict'] = static function(): void {
        foreach ([0,2] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['target_after'][0]['course_category']=$bad;
            $r=\WssNativeOfflineTest\read_fixture($op,$req,$rows)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && $r['target_course_category']===1,'before-fact-not-rewritten');
            check(in_array('TARGET_WINDOW_CONFLICT',$r['diagnostics'],true),'window-change');
        }
    };
    $tests['new_course_table_missing_or_noninnodb_fails_read_closed'] = static function(): void {
        foreach (['missing','MyISAM'] as $bad) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();
            if ($bad==='missing') { array_shift($rows['engines']); } else {$rows['engines'][0]['ENGINE']=$bad;}
            $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
            check($r['status']==='READ_UNAVAILABLE' && !in_array('values',$p->calls,true),'course-engine-gate');
        }
    };
    $tests['context_course_and_actor_guards_survive_scope_zero'] = static function(): void {
        foreach (['courseid','feedback_course','contextinstanceid'] as $field) {
            [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['target_before'][0][$field]=999;
            $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
            check($r['status']==='SOURCE_CONFLICT' && !in_array('values',$p->calls,true),'context-not-relaxed');
        }
        [$op,$req,$rows]=\WssNativeOfflineTest\fixture();$rows['completed'][0]['userid']=99;
        $p=new FakeProvider($rows);$r=\WssNativeOfflineTest\read_fixture($op,$req,$rows,$p)['receipt'];
        check($r['status']==='SOURCE_CONFLICT' && !in_array('values',$p->calls,true),'owner-not-relaxed');
    };
    $failed=0;
    foreach ($tests as $name=>$test) {
        try {$test();fwrite(STDOUT,'OK '.$name."\n");}
        catch (\Throwable $e) {++$failed;fwrite(STDERR,'FAIL '.$name.': '.$e->getMessage()."\n");}
    }
    fwrite(STDOUT,json_encode(['test_methods'=>count($tests),'failed'=>$failed,'evidence_class'=>'SYNTHETIC_OFFLINE_FIXTURE'],JSON_THROW_ON_ERROR)."\n");
    return $failed ? 1 : 0;
}
if (PHP_SAPI==='cli' && (get_included_files()[0]??null)===__FILE__) {exit(run());}
