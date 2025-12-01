import { Command, ValidationError } from "@cliffy/command";
import * as yaml from "yaml";

import { convert, merge, type Options } from "./libs/utils.ts";

export async function convertAction(
  options: Options & { output?: string },
  ...input: string[]
) {
  const clashConfigInputs: object[] = [];
  const singboxConfigInputs: object[] = [];

  await Promise.all(
    input.map(async (i) => {
      const content = /^https?:\/\//.test(i)
        ? await (await fetch(i, { headers: { "User-Agent": "ClashMeta" } }))
          .text()
        : Deno.readTextFileSync(i);

      try {
        const jsonContent = JSON.parse(content);
        if (
          jsonContent && typeof jsonContent === "object" &&
          ("log" in jsonContent || "dns" in jsonContent ||
            "inbounds" in jsonContent || "outbounds" in jsonContent ||
            "route" in jsonContent)
        ) {
          singboxConfigInputs.push(jsonContent);
          return;
        }
        // If it's valid JSON but not a sing-box config, treat it as Clash (JSON is a subset of YAML)
        clashConfigInputs.push(jsonContent);
      } catch (_e) {
        // Not JSON, assume YAML and try to parse.
        clashConfigInputs.push(yaml.parse(content) as object);
      }
    }),
  );

  const mergedClash = merge(...clashConfigInputs);
  const mergedSingbox = merge(...singboxConfigInputs);

  const finalConfigJson = convert(mergedClash, mergedSingbox, options);

  if (
    options.output === undefined || options.output === "-" ||
    options.output === "stdout"
  ) {
    console.log(finalConfigJson);
  } else {
    Deno.writeTextFileSync(options.output, finalConfigJson);
  }
}

await new Command()
  .name("clash2sing-box")
  .description("Clash to sing-box configuration converter")
  .command("convert <input...:string>", "Convert configuration")
  .option("-o, --output <string>", "Output file path")
  .option(
    "--outbound.domainresolver.tag <string:string>",
    "The name of the domain resolver, required for setting resolver strategy",
  )
  .option(
    "--outbound.selector.default <integer:integer>",
    "Use the n-th outbound as the default in the selector outbound",
  )
  .option(
    "--outbound.selector.tag <string:string[]>",
    "The name(s) of the selector outbound(s)",
  )
  .action(convertAction)
  .parse(Deno.args);
