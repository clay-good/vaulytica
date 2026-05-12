/**
 * v3 PHI / personal-data category detector — placeholder.
 *
 * Spec: spec-v3.md §19.
 *
 * Will detect category schedules in known locations (Annex I to EU SCCs, BAA recitals,
 * inline enumeration) and map detected categories to a controlled vocabulary covering:
 *   - HIPAA's 18 individual identifiers.
 *   - GDPR Article 9 special categories.
 *   - GDPR Article 10 (criminal convictions).
 *   - CCPA "sensitive personal information."
 *   - A residual "other" bucket.
 *
 * Rules can then assert, for example, "if special categories are processed, the DPA must
 * require encryption at rest by name." Implementation lands in spec-v3.md Step 30.
 */
export {};
