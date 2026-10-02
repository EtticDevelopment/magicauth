Local run, 2026-10-01 (not the CI job): Plugin Check 2.1.0 (WPCS 3.4.1, PHPCS 3.13.6) in WordPress Playground
(`@wp-playground/cli run-blueprint --wp=7.1 --php=8.3`, WordPress 7.1.2) on the release tree of
`tools/build-release.sh`, with the CI job's arguments (`wp plugin check magicauth --format=json --ignore-warnings
--exclude-directories=build,tests,_dev,tools --exclude-files=...`). WP-CLI was started from a `runPHP` step without a
STDIN constant: under Playground's own `wp-cli` step PHPCS dies on `fopen( 'php://stdin' )`.

- `includes/ThirdParty/Passkeys`: 0 ERROR, 0 WARNING (also without `--ignore-warnings`). Before patch 0008 the same
  run reported 91 `WordPress.Security.EscapeOutput.ExceptionNotEscaped` and 2
  `WordPress.WP.AlternativeFunctions.parse_url_parse_url` ERRORs here.
- Whole plugin: 1 ERROR, `readme.txt` `outdated_tested_upto_header` ("Tested up to: 7.0 < 7.1"), present since 1.0.5
  and outside this directory. With that header at 7.1 in a scratch copy the run printed
  `Success: Checks complete. No errors found.`

CI-PENDING: SPEC 4.9 accepts build step 7 only after the CI `plugin-check` job has run on a branch that contains this
tree and printed 0 ERROR. Record that output here, then rerun `vendor.sh` (it copies this file into `VENDORED.md`).
