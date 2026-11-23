# Privacy / secret hygiene

If you fork this repo, PLEASE do **not** commit:

- `/userconfig/upstream.conf`
- `/userconfig/last_lease`
- `/userconfig/lease_ok`
- `repeater_boot.log` or any `verify_repeater.out`

`.gitignore` covers the common runtime files, but check `git status` before
pushing.
