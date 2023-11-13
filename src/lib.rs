// XXX: Enable this after this feature lands in stable.
//#![feature(lint_reasons)]
//#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]

// XXX: Move this list to Cargo.toml after 1.74 release: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#lints

// Enable some restriction lints.
#![warn(
    clippy::absolute_paths,
    clippy::as_conversions,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::deref_by_slicing,
    clippy::disallowed_script_idents,
    clippy::else_if_without_else,
    clippy::empty_structs_with_brackets,
    clippy::error_impl_error,
    clippy::exit,
    clippy::expect_used,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::format_push_string,
    clippy::get_unwrap,
    clippy::if_then_some_else_none,
    clippy::impl_trait_in_params,
    clippy::indexing_slicing,
    clippy::inline_asm_x86_att_syntax,
    clippy::inline_asm_x86_intel_syntax,
    clippy::integer_division,
    clippy::large_include_file,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::mixed_read_write_in_expression,
    clippy::mod_module_files,
    clippy::modulo_arithmetic,
    clippy::multiple_inherent_impl,
    clippy::mutex_atomic,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::partial_pub_fields,
    clippy::pub_without_shorthand,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::redundant_type_annotations,
    clippy::ref_patterns,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_name_method,
    clippy::semicolon_inside_block,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_lit_chars_any,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::suspicious_xor_used_as_pow,
    clippy::tests_outside_test_module,
    clippy::todo,
    clippy::try_err,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unnecessary_self_imports,
    clippy::unneeded_field_pattern,
    clippy::unseparated_literal_suffix,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm
)]
//
// Enable all pedantic lints.
#![warn(clippy::pedantic)]
// Disable some pedantic lints.
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::if_not_else
)]
//
// Enable all nursery lints.
#![warn(clippy::nursery)]

mod config;
mod diff;
mod filter;
mod gitleaks_config;
mod report;

pub mod cli;

use std::{fs::read_dir, path};

use anyhow::Context as _;

fn collect_dir<B, F>(path: &path::Path, mut f: F) -> anyhow::Result<Vec<B>>
where
    F: FnMut(Vec<B>, path::PathBuf) -> anyhow::Result<Vec<B>>,
{
    read_dir(path)
        .with_context(|| format!("Failed to read path: {path:?}"))?
        .try_fold(Vec::new(), |acc, entry| {
            let entry =
                entry.with_context(|| format!("Failed to read dir entry in {}", path.display()))?;
            f(acc, entry.path())
        })
}
