import docusSitemap from "docus/server/routes/sitemap.xml";
import { inferSiteURL } from "docus/utils/meta";

/** Pages outside `content/` that the Docus sitemap cannot see. Keep in step with `app/pages/`. */
const PAGES = ["/playground"];

/** Appends the Vue pages Docus can't see. h3's handler, since Docus reads the event as h3's. */
export default defineEventHandler(async (event) => {
  const xml = String(await docusSitemap(event));
  const siteUrl = inferSiteURL() ?? "";
  const entries = PAGES.map((path) => `  <url>\n    <loc>${siteUrl}${path}</loc>\n  </url>`).join("\n");
  return xml.replace("</urlset>", `${entries}\n</urlset>`);
});
