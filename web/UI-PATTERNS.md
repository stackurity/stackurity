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

## Lists and tables

The list pages (Assets, Components, Incidents, Audit) are the reference.

| Component | Use |
|---|---|
| `Table` (`components/Table.tsx`) | Every data table. Row spacing follows the viewer's choice (below); Default is the table as it always was. |
| `TableToolbar` (`components/FilterChips.tsx`) | The line between a list's filters and its table: the filters on, and the row-spacing control. |
| `DensityControl` (`components/Density.tsx`) | Comfortable / Default / Compact. Remembered per viewer in this browser (`tableDensity.ts`); changes row padding and text size only. `TableToolbar` already includes it. |
| `FilterChips` | Each filter on as a chip with × to remove it, plus Clear all. Describe the page's query parameters once as `FilterDef`s and build the chips with `activeFilters()` (`filterChips.ts`); `withoutFilter()` / `withoutFilters()` give the URL after removing one or all, back on the first page. Give ids a readable value (`format`: a team id to its name). Don't add a second "Clear filters" link in the form. |
| `TableSkeleton`, `CardSkeleton` (`components/Skeleton.tsx`) | While a table or a list of cards loads, instead of `Loading`. Pass a `label` ("Loading assets…") and roughly the real number of columns. Keep `Loading` for forms and single values. The shimmer stops under prefers-reduced-motion. |
| `TruncatedName` (`components/Truncate.tsx`) | A long asset name or package identifier in a cell. The start gives way to an ellipsis; the end that tells rows apart (a version, a file name) stays (`truncate.ts`). The full value is the hover title, shows whole on keyboard focus, and has a copy button. |

## Colour, badges and buttons

**Red is for real urgency or a destructive action, nothing else.**

- Badge tones (`components/Badge.tsx`). `crit` (solid red): known exploited, SOS, regressed, fix overdue, a security release. `bad` (red outline): high severity, failures and stale data that need someone now (failed, stale, stopped reporting, end of life, withdrawn). `warn` (amber): needs a look but is not on fire (medium severity, New, To do, partial, exposed, pending). `info` (grey): neutral facts and work in progress. `good` (green): done, fixed, confirmed. `muted` (hollow dot): low, off, ended, not applicable. Priority has its own P1 to P4 tokens; severity uses `SeverityBadge`.
- Use the badge components (`Badge`, `SeverityBadge`, `PriorityBadge`, `FindingStateBadge`, …), never a hand-written `badge badge-…` span. The text always says the state; colour is a second cue.
- A workflow state is not urgency: New is amber, not red. Urgency comes from priority, SOS and missed deadlines.
- Buttons: `btn btn-primary` for the one main action of a card or page; plain `btn` for every other action (secondary); `btn btn-link` for low-weight actions such as Clear all. Destructive: `btn-link-danger` for a remove, revoke or disconnect in a row or list (ask first with `confirmAction` when it cannot be undone); solid `btn-danger` only for the final button of a confirmation (`ConfirmDialog` with `destructive`, or the submit of a delete form). Never a solid red button in a table row.
- Secondary text (`.muted`, `.small`, table headers) uses `--muted` or `--text-2`, which are at least 4.5:1 on every surface in both themes (`contrast.test.ts` checks it). Don't dim text with `opacity`: it drops below 4.5:1. Use `--text-2` or `--muted` instead.

## Empty states

An `EmptyState` always offers the next useful thing to do. With filters on, that is Clear filters (an `onClick` action). With nothing yet, it is the page that fills the list (Add server, Go to assets), shown only to someone whose role can use it, with `otherwise` saying who can. The copy lives in `emptyCopy.ts`.

## Feedback after an action

There is no toast. Say what happened next to where it happened:

- Success: `Notice kind="success"` above the list or form the action changed, in one sentence that names the thing ("Request #12 decided.", "Rule #4 ended: 3 issues back to new."). It is a `role="status"` region, so screen readers announce it. The reference is the Approvals page.
- Failure: `ErrorBox` with a `title` that says what failed ("Could not decide"). It explains the error in plain words and keeps the code for support.
- Settings: `SaveBar` says "You have unsaved changes." and then "Saved.".
- Copy: the button's own text says "Copied" for two seconds (`CopyBox`, `CopyValue`).
