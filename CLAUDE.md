Work in small, reviewable steps:
- One logical change per commit. Stop after each commit and wait for me.
- Do not rename anything unless I asked for that specific rename.
- Do not add, remove or reword comments unless I ask.
- Do not reformat or touch lines unrelated to the change.
- Do not start parallel or background tasks or subagents.
- If a change would touch more than ~3 files, or you're unsure about scope, ask first.
- Before editing, tell me in one or two sentences what you will change.

Code style (match the surrounding code; this is what module/, quirks/ and code_ref/ do):
- Indent with tabs, one tab per level, tab width 8. Never indent with spaces.
- Function definitions: opening brace on its own line. if/while/for/else: brace on the same line, `} else {`.
- A single-statement body gets no braces and sits on its own line, indented one level. This holds even when that statement spans lines: a nested for/if stacks without braces. An if/else with multi-line branches gets braces on both (see mac() in code_ref and memmove() in quirks).
- Space after if/while/for, no space before the parentheses of a call. The pointer star binds to the name: `unsigned char *p`.
- Plain arithmetic has spaces around operators (`1 << height`, `leaves - 1`). Address and index arithmetic and array sizes are tight (`blocks+blen*leaves`, `32*(HEIGHT_MAX+1)`).
- snake_case for functions and variables, UPPER_CASE for macros. K and N (uppercase) are the erasure code parameters.
- Comments are `/* */`, short, lowercase, and rare. The only `//` comments are the LaTeX formulas in code_ref/cauchy_prime_field_erasure_coding.hh. Every file starts with a `/* */` header: a title line, a blank line, the copyright line. Leave headers alone.
- Validate arguments at the top of a function: one `if` per check, each with an early `return`.
- Return 0 on success. On error, merkle.c returns 1 and hydra.c and cme.cc return -1.
- Exported functions and variables get `__attribute__((visibility("default")))` on the line before.
- cme.cc wraps its exports in `extern "C" {`, with a blank line after the opening and before the closing brace, and no extra indent inside.
- module/merkle.c is built with -std=c89: declarations only at the top of a block, no `//` comments, no declarations in `for`. hydra.c is C99, cme.cc is C++11.
- code_ref/ holds C++ headers copied from the author's aicodix/code repository. They use `namespace CODE {` (blank line after the opening and before the closing brace, no extra indent), `struct Name` with the brace on its own line, and `template <typename PF>` on its own line above the struct or function. Types are CamelCase, template parameters are ALL_CAPS, members are snake_case, and operators are written `operator + (...)`. Member functions are defined inside the struct.
- Headers use `#pragma once`.
- Do not wrap or re-wrap lines. The longest existing lines are about 95 columns in module/ and quirks/, and 145 in code_ref/ (template specializations), with tab = 8.
- Keep each file's ending as it is. Most files end with one blank line after the last line; quirks/string.c and code_ref/prime_field.hh do not.

Commit messages (match the existing history):
- A short lowercase subject, no trailing period, under about 60 characters, saying what changed. Example: `moved block count computation out of encode function`.
- No body unless the reason is not obvious from the diff.
- No Co-Authored-By, Claude-Session or other trailers, and no links.
