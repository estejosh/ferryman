# Ferryman dashboard design QA

Final result: **passed** — no open P0, P1, or P2 findings.

## Evidence

- Viewport: 1440 x 1024 CSS pixels in the selected in-app browser.
- Home source: `C:\Users\oshha\.codex\generated_images\01a029f0-296f-7843-96c6-716bdea2f3f5\exec-32e0f14a-a9b3-4eed-ac94-e977abccd6bd.png` (1487 x 1058).
- Home implementation: `C:\Users\oshha\.codex\visualizations\2026\08\22\01a029f0-296f-7843-96c6-716bdea2f3f5\ferryman-dashboard-build-home-final2.png` (1425 x 1013 captured content).
- Install source: `C:\Users\oshha\.codex\generated_images\01a029f0-296f-7843-96c6-716bdea2f3f5\exec-97ca860c-7b80-487d-bc96-54b04d207ad9.png` (1487 x 1058).
- Install implementation: `C:\Users\oshha\.codex\visualizations\2026\08\22\01a029f0-296f-7843-96c6-716bdea2f3f5\ferryman-dashboard-build-install-final2.png` (1425 x 1013 captured content).
- Normalized full-view comparisons: `qa-home-side-by-side-final.png` and `qa-install-side-by-side-final.png` in the same visualization directory. Both sides were resampled to 1440 x 1024 only for comparison; the browser itself remained at 1440 x 1024.
- State: `?demo=team`, Home and Install permanent business agent.

## Comparison

The implementation preserves the selected direction's dark navy shell, slim persistent navigation, compact top bar, strong blue action state, human-team-first hierarchy, distinct AI-agent section, shared-work/activity split, and dense install/review layout. The implementation intentionally moves the source's selected-task conversation pane to the dedicated Tasks view so the Home view remains scannable for novice operators.

Focused inspection covered:

- Human teammates versus AI agents: separate headings, different card treatments, explicit ownership copy, and access management actions.
- Personal-agent access: the owner is named; view, message, assignment, and handoff permissions are individually scoped; one-task, temporary, long-term, and permanent durations are available; repository and secret access are excluded.
- Business-agent install: business ownership, lifecycle, audience, install machine, runtime, least-privilege defaults, sensitive-access boundary, audit requirement, and review summary are visible before the primary action.
- Typography and spacing: headings, metadata, status labels, button hierarchy, card padding, and section rhythm remain readable without collisions at the target viewport.
- Color and surfaces: navy layers, subtle borders, blue focus/selection, yellow review attention, green allowed states, and red never-shared state retain semantic meaning and sufficient contrast.
- Assets and icons: the existing Ferryman logo asset is reused. The implementation does not introduce fake illustration assets or custom SVG substitutes.

## Responsive and accessibility checks

- At 700 x 900, document width was 685 pixels with no horizontal overflow; navigation and content stack vertically.
- Controls use semantic buttons, inputs, labels, checkboxes, select elements, headings, and a live status region.
- Core actions are keyboard-reachable and retain visible browser focus treatment.
- Text wrapping remained stable, with no overlap or clipped primary action at desktop or narrow width.
- The permanent business-agent action is visible at the 1024-pixel desktop fold (bottom 996.6 pixels after the final spacing pass).

## Interaction checks

- Navigation, task selection, task filters/search, agent access drawer, permission selection, duration selection, access request, install form, draft behavior, and demo installation were exercised.
- An access request for John's agent produced an explicitly non-mutating confirmation.
- A permanent business agent could be installed in demo state and appeared in the Agents view.
- Task review remained selected across the 10-second refresh interval after the final fix, and approval produced the expected demo-only confirmation.
- Browser console and warning logs were empty.

## Iteration history

1. Initial install layout placed the final action bar below the 1024-pixel viewport.
2. Lifecycle and audience choices were compacted into three-column groups and vertical margins tightened.
3. Post-fix comparison confirmed that the action bar is visible without weakening the review hierarchy.
4. Interaction QA found that periodic refresh cleared an open task detail. The renderer now reopens the selected task after refresh; an 11-second browser test confirmed the review action remained available.

## Residual product boundary

The interface is an honest policy preview. Signed ownership grants, business-agent installation, and runtime authorization enforcement are not implemented by this branch; production controls save or explain drafts instead of claiming authority changed. That backend contract is documented in `docs/DASHBOARD_TEAM_ACCESS_MODEL.md` and must be implemented before these controls become authoritative.
