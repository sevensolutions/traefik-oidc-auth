import * as fs from "fs";
import * as path from "path";

export async function configureTraefik(yaml: string) {
  const filePath = path.join(__dirname, ".http.yml");

  let existing: string = "";

  if (fs.existsSync(filePath))
    existing = fs.readFileSync(filePath).toString();

  if (existing !== yaml) {
    fs.writeFileSync(filePath, yaml);

    // Wait some time for traefik to reload the config
    // Note: Traefik has a throttle duration of 2s.
    await new Promise(r => setTimeout(r, 2500));
  }
}
