export async function requiredDocument(ctx, table, id) {
  const document = await ctx.db.get(table, id);
  if (!document) throw new Error(`Document not found in ${table}: ${id}`);
  return document;
}
