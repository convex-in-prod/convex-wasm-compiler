// Reference service for JS wrapper/hardening tests only. The native boundary
// suite executes the real JSI implementation and its memory accounting.
const NativeURL = globalThis.URL;
const fields = ["href", "origin", "protocol", "username", "password", "host", "hostname", "port", "pathname", "search", "hash"];

export function nodeUrlService() {
  return Object.freeze({
    parse: Object.freeze((input, base) => {
      try {
        return new NativeURL(input, base);
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
        return null;
      }
    }),
    get: Object.freeze((handle, field) => handle[fields[field]]),
    set: Object.freeze((handle, field, value) => {
      try {
        handle[fields[field]] = value;
        return true;
      } catch (error) {
        if (!(error instanceof TypeError) || field !== 0) throw error;
        return false;
      }
    }),
  });
}
