import * as fs from "fs";
import * as path from "path";

export async function configureTraefik(yaml: string) {
  fs.writeFileSync(path.join(__dirname, ".http.yml"), yaml);

  // Wait some time for traefik to reload the config
  await new Promise(r => setTimeout(r, 2000));
}
