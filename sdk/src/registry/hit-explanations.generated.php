<?php
/**
 * GENERATED FILE. DO NOT EDIT.
 *
 * Source of truth: pkg/hitexplain in the WebDecoy/app repository (#443).
 * Regenerate with
 *   go run ./cmd/export-hit-explanations -php
 * from that repository's pkg/ directory. The plain-language sentence for
 * each kind of decoy hit, shared with the WordPress digest email.
 */

declare(strict_types=1);

return [
    'metadata_key' => 'trap_kind',
    'hidden_link_prefix' => '/__wd/',
    'max_path_runes' => 80,
    'source_tripwire' => 'sdk_tripwire',
    'source_decoy_link' => 'decoy_link',
    'source_decoy_endpoint' => 'endpoint',
    'trap_kinds' => ['hidden_link', 'fake_plugin', 'author_lookup', 'user_list', 'probe_path', 'trap_path'],
    'templates' => [
        'hidden_link' => [
            'with_path' => 'A visitor requested {path}, the address of a hidden link on your pages. People can\'t see or click that link.',
            'without_path' => 'A visitor requested the address of a hidden link on your pages. People can\'t see or click that link.',
        ],
        'fake_plugin' => [
            'with_path' => 'A visitor requested {path}. That plugin is not installed on your site, so the path exists only as a trap.',
            'without_path' => 'A visitor requested a path inside a plugin that is not installed on your site. The path exists only as a trap.',
        ],
        'author_lookup' => [
            'with_path' => 'A visitor asked your site for the user name behind an author number, without logging in.',
            'without_path' => 'A visitor asked your site for the user name behind an author number, without logging in.',
        ],
        'user_list' => [
            'with_path' => 'A visitor asked your site\'s API for its list of users, without logging in.',
            'without_path' => 'A visitor asked your site\'s API for its list of users, without logging in.',
        ],
        'probe_path' => [
            'with_path' => 'A visitor requested {path}, a path that scanners commonly try. It is set up as a trap on your site.',
            'without_path' => 'A visitor requested a path that scanners commonly try. It is set up as a trap on your site.',
        ],
        'trap_path' => [
            'with_path' => 'A visitor requested {path}, a path set up as a trap on your site.',
            'without_path' => 'A visitor requested a path set up as a trap on your site. The path was not recorded.',
        ],
        'decoy_url' => [
            'with_path' => 'A visitor opened {path}, a decoy URL that exists only as a trap.',
            'without_path' => 'A visitor opened a decoy URL that exists only as a trap. The path was not recorded.',
        ],
        'decoy_endpoint' => [
            'with_path' => 'A visitor called {path}, a decoy API address that exists only as a trap.',
            'without_path' => 'A visitor called a decoy API address that exists only as a trap. The path was not recorded.',
        ],
    ],
];
