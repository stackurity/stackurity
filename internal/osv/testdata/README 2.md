# Test data

`cvss4_vectors.txt`: one CVSS v4.0 vector and its expected score per line, as
computed by the official FIRST calculator
(https://github.com/FIRSTdotorg/cvss-v4-calculator, commit c5b0d409,
BSD-2-Clause). The `.js` files of that repository were loaded into a Node `vm`
context and each vector scored with
`cvss_score(selected, cvssLookup_global, maxSeverity, macroVector(selected))`,
where `selected` holds every metric with "X" for the absent optional ones.

The vectors are a seeded random sample of about 400 out of 404,976 that were
compared in full when the scorer was written: all 104,976 Base-only vectors
plus 300,000 random vectors with Threat, Environmental and Supplemental
metrics. All of them matched.
