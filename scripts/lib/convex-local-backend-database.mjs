const SUPPORTED_DATABASE_NAME = /^[A-Za-z0-9_]+$/u;

function fail(message) {
  throw new Error(`Local Convex database identity: ${message}`);
}

export function deriveConvexMysqlDatabaseName(instanceName) {
  if (
    typeof instanceName !== "string" ||
    instanceName.length === 0 ||
    instanceName.includes("\u0000") ||
    instanceName.includes("\r") ||
    instanceName.includes("\n")
  ) {
    fail("backend instance name must be one nonempty line");
  }
  const database = instanceName.replaceAll("-", "_");
  if (!SUPPORTED_DATABASE_NAME.test(database)) {
    fail(
      `backend instance ${JSON.stringify(instanceName)} resolves to an unsupported database name`
    );
  }
  return database;
}

export function databaseIdentityFromDockerInspection(container) {
  if (typeof container !== "object" || container === null || Array.isArray(container)) {
    fail("backend container inspection must be an object");
  }
  const environment = container.Config?.Env;
  if (!Array.isArray(environment)) {
    fail("backend container inspection has no environment");
  }
  const instanceNames = environment
    .filter((entry) => typeof entry === "string" && entry.startsWith("INSTANCE_NAME="))
    .map((entry) => entry.slice("INSTANCE_NAME=".length));
  if (instanceNames.length !== 1) {
    fail(`backend container must define INSTANCE_NAME exactly once, found ${instanceNames.length}`);
  }
  const instanceName = instanceNames[0];
  return {
    database: deriveConvexMysqlDatabaseName(instanceName),
    instanceName,
  };
}

export function validateConvexMysqlDatabaseIdentity(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("backend database identity must be an object");
  }
  const database = deriveConvexMysqlDatabaseName(value.instanceName);
  if (value.database !== database) {
    fail(
      `backend instance ${JSON.stringify(value.instanceName)} resolves to ${database}, not ${JSON.stringify(value.database)}`
    );
  }
  return { database, instanceName: value.instanceName };
}
