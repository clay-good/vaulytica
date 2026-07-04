# rule-accuracy — delta

## ADDED Requirements

### Requirement: FIN-001 honors magnitude suffixes

FIN-001 SHALL apply the magnitude suffix it matches (`k`, `m`, `mm`, `b`,
`bn`, case-insensitive) to the numeral before comparing it to the spelled-out
amount.

#### Scenario: Consistent shorthand amount

- **WHEN** a document contains "one million dollars ($1M)"
- **THEN** FIN-001 does not fire

#### Scenario: Genuine mismatch with a suffix

- **WHEN** a document contains "one million dollars ($2M)"
- **THEN** FIN-001 fires with both values reported at their suffix-applied
  magnitudes

### Requirement: IPDATA-001 requires an IP assignment object

IPDATA-001 SHALL treat an assignment clause as satisfying the IP-ownership
presence check only when the assigned object is intellectual property (or an
equivalent term: inventions, works, work product, deliverables, copyrights,
patents, trademarks, trade secrets).

#### Scenario: Receivables assignment does not satisfy the check

- **WHEN** a document's only assignment language is "Consultant hereby assigns
  to a factor all accounts receivable" and no IP-ownership clause exists
- **THEN** IPDATA-001 fires

#### Scenario: IP assignment still satisfies the check

- **WHEN** a document contains "Contractor hereby assigns all right, title and
  interest in the work product"
- **THEN** IPDATA-001 does not fire

### Requirement: PERS-009 binds duration to the non-solicit language

PERS-009 SHALL attribute a duration to the non-solicit obligation only when
the duration appears in the same sentence as, or within a bounded token window
of, the non-solicit language — not merely the same paragraph.

#### Scenario: Unrelated duration in the same paragraph

- **WHEN** a paragraph states a 24-month support commitment and separately a
  non-solicit with no stated duration
- **THEN** PERS-009 does not attribute the 24 months to the non-solicit

#### Scenario: True over-long non-solicit still fires

- **WHEN** a clause states "shall not solicit ... for a period of twenty-four
  (24) months"
- **THEN** PERS-009 fires quoting that duration

### Requirement: TEMP-003 is auto-renewal aware and clause-scoped

TEMP-003 SHALL NOT flag a notice period exceeding the stated term when the
term clause carries auto-renewal language, and SHALL prefer a term/notice pair
drawn from the same paragraph over independent document-wide matches.

#### Scenario: Month-to-month auto-renewing agreement

- **WHEN** a document states "an initial term of 1 month, renewing
  automatically ... unless either party provides 60 days prior written notice
  of non-renewal"
- **THEN** TEMP-003 does not fire

#### Scenario: Fixed term with an impossible notice still fires

- **WHEN** a document states a fixed non-renewing 30-day term and separately
  requires 60 days' notice to terminate
- **THEN** TEMP-003 fires

### Requirement: Detection fixes ship with two-sided fixtures

Every rule-detection fix SHALL land with the reproducing document as a
regression fixture and at least one counter-fixture proving the rule still
fires on its true-positive pattern.

#### Scenario: A fix silently disables a rule

- **WHEN** a detection change causes a rule's true-positive fixture to stop
  firing
- **THEN** the suite fails naming the rule and fixture
