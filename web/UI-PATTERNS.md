# Dashboard page structure

Written for anyone changing a page in `web/src`. The reader we design for is semi-technical: they run the servers or own the product, but they don't know Stackurity's terms. Every page must make sense to them without opening Help.

## Rules

1. **Every card says what it is for.** Give `Card` a `title` and a one-sentence `description`: what this area controls, in plain words, and why someone would change it. A data card ("Open issues by priority") needs a description only when its title doesn't say it all.
2. **One setting per row.** Inside a settings card, put each setting in a `SettingRow`. Its `title` names the setting, its `description` says what changing it does, and its control goes in the children. On wide screens the text sits on the left and the control on the right. On phones they stack. Rows are separated by a line.
3. **An option's meaning goes under its name, never on the same line.** For pick-one choices, use `ChoiceCards` with `{ value, label, description, badge?, disabled? }`. For a checkbox that needs explaining, use `CheckCard`. Plain `.check` pills are only for short filter-like lists that need no explanation (days of the week, event names that explain themselves).
4. **Group related fields.** A run of number or text inputs ("Severity critical", "Severity high", …) goes in a `FieldGroup` with a heading and a line saying what the numbers mean. Don't leave ten unlabelled inputs in one grid.
5. **Status and Save at the bottom.** End a settings card with `CardFooter`: `status` says what the current choice means for people right now ("3 members will be asked to set up a second factor"), and the card's Save and Cancel go in its children. A page with one form across several cards keeps the sticky `SaveBar` instead.
6. **Side notes are separate.** Caveats that don't change a setting (SSO users are exempt; API tokens are not affected) go in a `GoodToKnow` box, not in the hint text under a control.
7. **Paid features.** Put a plan badge next to the `SettingRow` title (`badge`), and the `ProNotice` inside the row it belongs to, not floating between rows.
8. **Main thing first.** Put what people come to the page for (the list of users, the open fixes) above its configuration. Rarely used settings go lower, or into a `<details>`.
9. **Words.** Use British spelling, short sentences, and no internal names (`STACKURITY_*`, table names, job kinds) in the description lines. An environment variable can appear in a hint for the self-hosting operator, but say what it's for first. Never change a label that docs, help articles or tests quote (`grep -rn` the label first) unless you update them too.

## Components (src/components/ui.tsx)

| Component | Use |
|---|---|
| `Card` (`title`, `description`, `actions`) | Any boxed area. |
| `SettingRow` (`title`, `description`, `badge`) | One setting inside a card. |
| `FieldGroup` (`title`, `description`) | A titled set of related inputs. |
| `ChoiceCards` (`name`, `legend`, `options`, `value`, `onChange`, `columns`) | Pick one, with explanations. |
| `CheckCard` (`label`, `description`, `checked`, `onChange`) | A checkbox with an explanation. |
| `OptionBadge` | "Recommended" / "Default" next to an option. |
| `CardFooter` (`status`) | What the setting means now, plus Save. |
| `GoodToKnow` | Side notes. |

The reference example is `RequireMfaCard` in `src/pages/TwoFactor.tsx` (People → Users → Two-factor sign-in).
