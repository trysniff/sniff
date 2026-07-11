use super::*;

#[test]
fn feature_flag_and_session_cache_boundaries_are_treated_as_intentional_surfaces() {
    let feature_flags = FileRecord {
        file_path: "ui/src/lib/feature-flags.ts".to_string(),
        source: "export class FeatureFlags { static isEnabled(flag: string) { return true; } }\n"
            .to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    };
    let password_cache = FileRecord {
        file_path: "ui/src/lib/password-session-cache.ts".to_string(),
        source: "export const getSessionPassword = async () => null;\nexport const setSessionPassword = async () => {};\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "normalizeBrandId".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 1,
                end_line: 3,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizePassword".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 4,
                end_line: 6,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "toCacheEntry".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 7,
                end_line: 9,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getPasswordFromEntry".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 10,
                end_line: 12,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "pruneExpiredMemoryEntries".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 13,
                end_line: 15,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "hydrateLegacySessionCacheOnce".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 0,
                start_line: 16,
                end_line: 18,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "clearExpiredSessionPasswords".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 0,
                start_line: 19,
                end_line: 21,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getSessionPassword".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 22,
                end_line: 24,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "setSessionPassword".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 25,
                end_line: 27,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "clearSessionPassword".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 28,
                end_line: 30,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "clearAllSessionPasswords".to_string(),
                file_path: "ui/src/lib/password-session-cache.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 0,
                start_line: 31,
                end_line: 33,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_support_boundary_module(&feature_flags));
    assert!(is_intentional_surface_record(&feature_flags));
    assert!(is_support_boundary_module(&password_cache));
    assert!(is_intentional_surface_record(&password_cache));
}

#[test]
fn data_catalog_modules_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "ui/src/data/platforms.ts".to_string(),
        source: "export type Platform = { id: string };\n\
                 const RAW_PLATFORMS: Record<string, Platform> = Object.fromEntries([]);\n\
                 export const PLATFORMS = RAW_PLATFORMS;\n\
                 export function getPlatformClaimMode(platformId: string) { return 'assisted'; }\n\
                 export function isPlatformCacheEligible(platformId: string) { return false; }\n\
                 export function getPlatformSetupObjective(platformId: string) { return 'create_account'; }\n\
                 export function getPlatformSetupLabel(platformId: string) { return 'Create Account'; }\n\
                 export function getPlatformSetupTasks(platformId: string) { return []; }\n\
                 export function isStrictFillPlatform(platformId: string) { return false; }\n\
                 export function getPlatformDisplayName(platformId: string) { return platformId; }\n"
            .to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "getPlatformClaimMode".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 4,
                end_line: 4,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "isPlatformCacheEligible".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 5,
                end_line: 5,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getPlatformSetupObjective".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 6,
                end_line: 6,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getPlatformSetupLabel".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 7,
                end_line: 7,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getPlatformSetupTasks".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 8,
                end_line: 8,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "isStrictFillPlatform".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 9,
                end_line: 9,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getPlatformDisplayName".to_string(),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 1,
                start_line: 10,
                end_line: 10,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_data_catalog_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn real_brandset_platform_catalog_is_treated_as_intentional_surface() {
    let file =
        crate::parser::parse_file(r"C:\Users\User\Brandset\Brandset\ui\src\data\platforms.ts");

    assert!(
        is_data_catalog_module(&file),
        "parsed file did not match data catalog heuristics: methods={}, source_has_record={}, source_has_from_entries={}, path={}",
        file.methods.len(),
        file.source.to_lowercase().contains("record<string,"),
        file.source.to_lowercase().contains("object.fromentries("),
        file.file_path
    );
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn pure_contract_type_modules_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "ui/background/core/session-runtime-contracts.ts".to_string(),
        source: "export type LoggerMethod = (...args: unknown[]) => void;\n\
                 export type SessionPolicy = 'aggressive_clean' | 'preserve_login';\n\
                 export interface PlatformConfig {\n\
                   signupUrl?: string;\n\
                   checkUrl?: string;\n\
                 }\n"
        .to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    };

    assert!(is_contract_type_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn real_brandset_contract_type_module_is_treated_as_intentional_surface() {
    let file = crate::parser::parse_file(
        r"C:\Users\User\Brandset\Brandset\ui\background\core\session-runtime-contracts.ts",
    );

    assert!(is_contract_type_module(&file));
    assert!(is_intentional_surface_record(&file));
}
