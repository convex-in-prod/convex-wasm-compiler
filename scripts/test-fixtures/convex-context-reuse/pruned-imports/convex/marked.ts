import DefaultSchema from "default-schema";
import * as SchemaNamespace from "namespace-schema";
import { type ExplicitNamedType, NamedSchema } from "named-schema";
import { OriginalSchema as AliasedSchema } from "aliased-schema";
import type ExplicitTypeSchema from "type-schema";

export const experimental_reuseContext = true;

export type DefaultSchemaType = DefaultSchema;
export type NamespaceSchemaType = SchemaNamespace.Schema;
export type NamedSchemaType = NamedSchema;
export type AliasedSchemaType = AliasedSchema;
export type ExplicitNamedSchemaType = ExplicitNamedType;
export type ExplicitSchemaType = ExplicitTypeSchema;

const require = (specifier: string): string => specifier;
export const localRequireResult = require("./not-a-runtime-import");
