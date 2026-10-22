/** Wrangler bundles .txt files as text modules. */
declare module "*.txt" {
  const text: string;
  export default text;
}
