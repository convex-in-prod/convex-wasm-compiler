const name=process.argv[2];
if(!['smoke','probe','contracts','dates','bindings','construction','locales','ranges','date-ranges', 'collator', 'bootstrap', 'hardening'].includes(name))throw new Error('Unknown probe');
process.env.TZ = 'UTC';
const {default:createModule}=await import(new URL(name+'.mjs',process.env.INTL_EXPERIMENT_URL));
await createModule();
