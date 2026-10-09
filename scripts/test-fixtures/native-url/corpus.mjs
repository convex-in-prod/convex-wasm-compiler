import { readFileSync } from "node:fs";

// Shared by bytecode and compiled-runtime boundary checks.
export function renderUrlCorpus() {
  const vendor = new URL("../../vendor/ada-4.0.0/", import.meta.url);
  const parsing = JSON.parse(readFileSync(new URL("urltestdata.json", vendor), "utf8"))
    .filter((entry) => typeof entry === "object" && entry !== null);
  const setters = JSON.parse(readFileSync(new URL("setters_tests.json", vendor), "utf8"));
  return `(() => {
      const parsing = ${JSON.stringify(parsing)};
      const setters = ${JSON.stringify(setters)};
      function check(value, label) { if (!value) throw new Error("URL corpus: " + label); }
      const fields = ["href", "origin", "protocol", "username", "password", "host",
                      "hostname", "port", "pathname", "search", "hash"];
      let id = 0;
      for (const entry of parsing) {
        const base = entry.base === null ? undefined : entry.base;
        let url;
        try { url = new URL(entry.input, base); }
        catch (error) {
          if (!(error instanceof TypeError)) throw error;
          check(entry.failure === true, id + " unexpected rejection");
        }
        check(URL.canParse(entry.input, base) === !entry.failure, id + " predicate");
        check((URL.parse(entry.input, base) !== null) === !entry.failure, id + " parse");
        if (!entry.failure) {
          for (const field of fields) {
            if (Object.hasOwn(entry, field)) check(url[field] === entry[field], id + " " + field);
          }
        } else check(url === undefined, id + " invalid accepted");
        ++id;
      }
      for (const [field, entries] of Object.entries(setters)) {
        if (field === "comment") continue;
        for (const entry of entries) {
          const url = new URL(entry.href);
          url[field] = entry.new_value;
          for (const [key, value] of Object.entries(entry.expected)) {
            check(url[key] === value, id + " " + field + " " + key);
          }
          ++id;
        }
      }
      if (id !== 1169) throw new Error("URL corpus count changed: " + id);
    })();`;
}
