### Fixed

- **`threat_check` finds a threat by a word of its name.** Asking for "Brotli" found nothing: a threat matched only its id, its full name or an alias. It now also matches its short name, and a word of only one threat's name or short name, so "Brotli" or "Roller" works. A word several threats share, such as "Drupal", still lists the threats to choose from.
