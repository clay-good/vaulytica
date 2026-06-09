import { describe, expect, it } from "vitest";
import { isHttpUrl } from "./url-safety.js";

describe("isHttpUrl (shared URL-safety policy)", () => {
  it("accepts http and https absolute URLs", () => {
    expect(isHttpUrl("https://www.govinfo.gov/app/details/CFR-2024")).toBe(true);
    expect(isHttpUrl("http://www.nationalarchives.gov.uk/doc/open-government-licence/")).toBe(true);
    expect(isHttpUrl("HTTPS://EUR-LEX.EUROPA.EU/eli/reg/2016/679")).toBe(true);
  });

  it("rejects dangerous and non-web schemes", () => {
    expect(isHttpUrl("javascript:alert(1)")).toBe(false);
    expect(isHttpUrl("data:text/html,<script>alert(1)</script>")).toBe(false);
    expect(isHttpUrl("file:///etc/passwd")).toBe(false);
    expect(isHttpUrl("ftp://example.com/x")).toBe(false);
    expect(isHttpUrl("mailto:a@b.com")).toBe(false);
  });

  it("rejects relative / unparseable / empty values without throwing", () => {
    expect(isHttpUrl("/relative/path")).toBe(false);
    expect(isHttpUrl("//protocol-relative.example.com")).toBe(false);
    expect(isHttpUrl("not a url")).toBe(false);
    expect(isHttpUrl("")).toBe(false);
  });
});
