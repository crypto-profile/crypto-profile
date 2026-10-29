# 0006: Report profile entries excluded by the module line

Date: 2026-10-29. Status: accepted.

The 2026-10-29 amendment to round 2 replaces its refusal of the first unavailable profile entry to prevent silent loss. The amended rule is: apply Options first, intersect the published profile set with module-line availability, and report every unavailable entry in `Selection::excluded` and `Resolved::excluded`. Preserve versions, suites, groups, schemes, keys order and each family's preference order. Options-only removals are not line exclusions. Approval does not filter resolution.

Any empty family is still refused with `EmptyProfile`, naming the first empty family in that order. Direct primitive and provider operations retain `Unavailable`. A resolved profile describes the published set intersected with availability; it changes neither the governing edition nor the meaning of module approval. Callers can inspect exclusions and impose a stricter policy.

On 4.x every profile entry is available, so all successful results have empty exclusions and unchanged lists. On 3.x `unrestricted`, `preferred` and `fips1403` exclude exactly `Scheme(MlDsa87)` then `Signature(MlDsa87)`. `cnsa2` is refused because its signature-scheme family empties. The three pre-existing post-quantum-option empty-group refusals remain. Independent golden expectations exercise all fourteen profile/Options cases on each line and linkage.

The public struct-literal contract adds `excluded: Vec<Algorithm>` to both selection and resolved values. Applications should log it alongside the profile and Options. Changing public fields makes the caller responsible for the resulting policy and its recorded provenance.
