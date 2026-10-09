(() => {
  function check(value, label) {
    if (!value) throw new Error("URL boundary: " + label);
  }
  function typeError(operation, label) {
    let caught = false;
    try { operation(); } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      caught = true;
    }
    check(caught, label);
  }
  check(!Object.hasOwn(globalThis, "__convexWasmNativeUrl"), "bootstrap removed");
  check(Object.isFrozen(URL) && Object.isFrozen(URL.prototype), "URL hardened");
  check(Object.isFrozen(URLSearchParams.prototype), "params hardened");
  typeError(() => new URL(), "required argument");
  typeError(() => new URL(Symbol()), "symbol input");
  typeError(() => new URL("https://example.test", Symbol()), "symbol base");
  typeError(() => new URL("https://example.test", "invalid"), "invalid absolute base");
  typeError(() => URL.prototype.toString.call({}), "method brand");
  const href = Object.getOwnPropertyDescriptor(URL.prototype, "href");
  typeError(() => href.get.call({}), "getter brand");
  let coercions = 0;
  typeError(() => href.set.call({}, {toString() { ++coercions; return ""; }}), "setter brand");
  check(coercions === 0, "brand precedes coercion");
  const order = [];
  const url = new URL(
    {toString() { order.push("url"); collectForUrlTest(); return "../next?x=1&x=2"; }},
    {toString() { order.push("base"); collectForUrlTest(); return "https://example.test/dir/a"; }});
  check(order.join() === "url,base", "constructor conversion order");
  const params = url.searchParams;
  check(url.href === "https://example.test/next?x=1&x=2", "relative construction");
  check(params === url.searchParams && params.getAll("x").join() === "1,2", "stable duplicates");
  params.append("q", "a b~");
  check(url.search === "?x=1&x=2&q=a+b%7E", "params update URL");
  url.search = "?b=2&a=1&b=3";
  check(params === url.searchParams && params.size === 3 && params.get("b") === "2", "URL updates params");
  params.sort();
  check(url.search === "?a=1&b=2&b=3", "stable sorting");
  const iterator = params.entries();
  check(iterator.next().value.join() === "a,1", "iterator starts");
  url.search = "?x=8&y=9";
  check(iterator.next().value.join() === "y,9", "iterator observes replacement");
  url.href = "https://example.test/new?k=1";
  check(params.get("k") === "1" && params === url.searchParams, "href keeps params identity");
  const original = url.href;
  typeError(() => { url.href = "invalid"; }, "invalid href throws");
  check(url.href === original && params.get("k") === "1", "invalid href preserves state");
  url.hostname = "[invalid";
  check(url.href === original, "invalid hostname ignored");
  url.search = "?";
  check(url.href.endsWith("?") && url.search === "" && params.size === 0, "empty query delimiter");
  params.delete("absent");
  check(!url.href.endsWith("?"), "empty params removes delimiter");
  url.hash = "#";
  check(url.href.endsWith("#") && url.hash === "", "empty fragment delimiter");
  url.pathname = {toString() { collectForUrlTest(); return "/\ud800"; }};
  check(url.pathname === "/%EF%BF%BD", "USVString setter with GC");
  typeError(() => { url.search = Symbol(); }, "symbol setter");
  class ChildURL extends URL { extra() { return this.hostname; } }
  const child = new ChildURL("https://example.test");
  check(child instanceof ChildURL && child instanceof URL && child.extra() === "example.test", "subclass");
  const parsed = URL.parse("/parse", "https://example.test");
  check(parsed instanceof URL && parsed.href === "https://example.test/parse", "parse returns wrapper");
  check(URL.parse("invalid") === null && !URL.canParse("invalid"), "invalid static parse");
  typeError(() => URL.parse(Symbol()), "static conversion throws");
  const opaque = new URL("data:a   ?q");
  opaque.searchParams.delete("q");
  check(opaque.href === "data:a  %20", "opaque path preserves encoded trailing space");
  url.search = "?x=a\nb\rc\td";
  check(url.searchParams.get("x") === "abcd", "params use parsed query");
  const seen = [];
  const mutable = new URL("https://example.test/?a=1&b=2");
  mutable.searchParams.forEach((v, k) => {
    seen.push(k);
    if (k === "a") mutable.searchParams.append("c", "3");
    collectForUrlTest();
  });
  check(seen.join() === "a,b,c", "iteration during mutation and GC");
  check(JSON.stringify(url) === JSON.stringify(url.href), "serialization");
})();
