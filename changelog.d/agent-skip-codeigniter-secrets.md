### Changed

- Application scans no longer report CodeIgniter credentials files the agent may not read as unreadable application files: `database.php`, `email.php`, `mail.php`, their variants (`database.production.php`) and `*.local.php` overrides directly in `application/config` or `app/Config`. Like `wp-config.php` and `.env`, hardening rightly keeps them from other users and they hold nothing the scan reads. Other config files there (`routes.php`) and the same names elsewhere are still reported.
