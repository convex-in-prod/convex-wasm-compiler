module.exports.experimental_reuseContext = true;

// CommonJS entry modules execute inside an ordinary wrapper, whose arguments object is retained
// with module state rather than being an invocation-local database-UDF value.
arguments.cached = true;
